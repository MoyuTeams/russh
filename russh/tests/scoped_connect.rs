#![allow(clippy::unwrap_used)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::scoped::*;
use russh::{client, server};

#[derive(Clone)]
struct Scope(Arc<AtomicUsize>, Option<&'static str>);
struct Grant {
    bytes: usize,
    live: Arc<AtomicUsize>,
    completed: Option<Arc<AtomicUsize>>,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.live.fetch_sub(self.bytes, Ordering::SeqCst);
        if let Some(completed) = &self.completed {
            completed.fetch_add(1, Ordering::SeqCst);
        }
    }
}
impl AdmissionScope for Scope {
    type Reservation = Grant;
    fn try_reserve(&self, request: ResourceRequest) -> Result<Grant, ScopedFault> {
        let bytes = request.bytes()?;
        if self
            .1
            .is_some_and(|site| site == "*" || site == request.site)
        {
            return Err(ScopedFault {
                kind: FaultKind::ByteBudget,
                site: request.site,
                requested: bytes,
                available: Some(0),
            });
        }
        self.0.fetch_add(bytes, Ordering::SeqCst);
        Ok(Grant {
            bytes,
            live: self.0.clone(),
            completed: None,
        })
    }
}

struct Clock(Scope);
struct Sleep(Rooted<Instant, Grant>);
impl Future for Sleep {
    type Output = Result<(), ScopedFault>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= *self.0.get() {
            Poll::Ready(Ok(()))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
impl ScopedClock for Clock {
    type Sleep = Sleep;
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep_until(&self, deadline: Instant) -> Result<Sleep, ScopedFault> {
        Rooted::try_new(&self.0, ResourceClass::Control, "fixture.sleep", || {
            deadline
        })
        .map(Sleep)
    }
    fn reset(&self, sleep: Pin<&mut Sleep>, deadline: Instant) -> Result<(), ScopedFault> {
        *sleep.get_mut().0.get_mut() = deadline;
        Ok(())
    }
}
struct Budget(AtomicUsize);
impl Cooperative for Budget {
    fn begin_poll(&self) {
        self.0.store(32, Ordering::SeqCst);
    }
    fn poll_budget(&self, cx: &mut Context<'_>, units: usize) -> Poll<()> {
        let mut remaining = self.0.load(Ordering::SeqCst);
        loop {
            let Some(next) = remaining.checked_sub(units) else {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            };
            match self
                .0
                .compare_exchange_weak(remaining, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Poll::Ready(()),
                Err(actual) => remaining = actual,
            }
        }
    }
}

// 测试调度器由 join poll 驱动真实 F；客户端线程没有 Tokio runtime。
struct Spawner;
struct Task<T> {
    future: Option<RootedFuture<T, Grant>>,
    cancelled: AtomicBool,
}
impl<T> Future for Task<T> {
    type Output = Result<T, ScopedFault>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cancelled.load(Ordering::SeqCst) {
            self.future.take();
            return Poll::Ready(Err(ScopedFault {
                kind: FaultKind::Cancelled,
                site: "fixture.task",
                requested: 0,
                available: None,
            }));
        }
        match Pin::new(self.future.as_mut().unwrap()).poll(cx) {
            Poll::Ready(value) => {
                self.future.take();
                Poll::Ready(Ok(value))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl<T> ScopedTask for Task<T> {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}
impl<S: AdmissionScope<Reservation = Grant>> ScopedSpawner<S> for Spawner {
    type Task<T: Send + 'static> = Task<T>;
    fn try_spawn<F>(&self, scope: &S, future: F) -> Result<Task<F::Output>, ScopedFault>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let future = Rooted::try_new(scope, ResourceClass::Runtime, "fixture.task", || future)?
            .into_future();
        Ok(Task {
            future: Some(future),
            cancelled: AtomicBool::new(false),
        })
    }
}

struct Client(PublicKey);

struct PendingDisconnectClient {
    key: PublicKey,
    operation_error: bool,
    exchanges: usize,
    entered: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    late_error: Arc<std::sync::Mutex<Option<ResourceRoot<Grant>>>>,
}

struct CallbackDrop(Arc<AtomicUsize>);
impl Drop for CallbackDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl client::Handler for PendingDisconnectClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(key == &self.key)
    }
    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        _: &russh::Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.exchanges += 1;
        if self.operation_error && self.exchanges > 1 {
            Err(russh::Error::SendError)
        } else {
            Ok(())
        }
    }
}
impl client::ScopedHandler<Scope, Clock, Budget> for PendingDisconnectClient {
    async fn disconnected_scoped(
        &mut self,
        reason: client::ScopedDisconnectReason<'_, Self::Error, Grant>,
    ) -> Result<(), ScopedError<Self::Error>> {
        match reason {
            client::ScopedDisconnectReason::Error(error) => {
                assert!(matches!(error.get(), russh::Error::SendError));
                *self.late_error.lock().unwrap() =
                    Some(error.root().try_clone().map_err(ScopedError::Resource)?);
            }
            client::ScopedDisconnectReason::ReceivedDisconnect(info) => {
                assert_eq!(info.message, "fixture-disconnect")
            }
        }
        let guard = CallbackDrop(self.dropped.clone());
        self.entered.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
        drop(guard);
        Ok(())
    }
}

#[test]
fn shutdown_cancels_pending_disconnected_and_preserves_primary_error_root() {
    for operation_error in [false, true] {
        let (ready, established) = tokio::sync::oneshot::channel();
        let (stream, handler, server) = fixture(IncomingServer(Some(ready)));
        let live = Arc::new(AtomicUsize::new(0));
        let scope = Scope(live.clone(), None);
        let entered = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let late_error = Arc::new(std::sync::Mutex::new(None));
        assert!(tokio::runtime::Handle::try_current().is_err());
        let completed = futures::executor::block_on(async {
            let mut client = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                stream,
                PendingDisconnectClient {
                    key: handler.0,
                    operation_error,
                    exchanges: 0,
                    entered: entered.clone(),
                    dropped: dropped.clone(),
                    late_error: late_error.clone(),
                },
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            let late_handle = client.root().try_clone().unwrap();
            assert!(client.authenticate_none("fixture").await.unwrap().success());
            let remote = established.await.unwrap();
            if operation_error {
                client.rekey_soon().await.unwrap();
            } else {
                remote
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        "fixture-disconnect".into(),
                        String::new(),
                    )
                    .await
                    .unwrap();
            }
            std::future::poll_fn(|cx| {
                assert!(Pin::new(&mut client).poll(cx).is_pending());
                if entered.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            let mut shutdown = std::pin::pin!(client.shutdown());
            let result = shutdown
                .as_mut()
                .poll(&mut Context::from_waker(std::task::Waker::noop()));
            if let Poll::Ready(result) = result {
                if operation_error {
                    assert!(
                        matches!(result, Err(ScopedError::Operation(ref error)) if matches!(error.get(), russh::Error::SendError))
                    );
                } else {
                    result.unwrap();
                }
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
                assert!(live.load(Ordering::SeqCst) > 0);
                drop(late_handle);
                true
            } else {
                drop(late_handle);
                false
            }
        });
        let server_result = server.join().unwrap();
        assert!(
            server_result.is_ok()
                || matches!(server_result,
            Err(russh::Error::IO(ref error)) if matches!(error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe))
        );
        if operation_error {
            assert!(live.load(Ordering::SeqCst) > 0);
        }
        drop(late_error.lock().unwrap().take());
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert!(completed, "shutdown 不能等待 disconnected 回调就绪");
    }
}
impl<S, C, B> client::ScopedHandler<S, C, B> for Client
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
}
impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(key == &self.0)
    }
}

struct ObservedClient {
    client: Client,
    exchanges: Arc<AtomicUsize>,
}
impl<S, C, B> client::ScopedHandler<S, C, B> for ObservedClient
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
}
impl client::Handler for ObservedClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        self.client.check_server_key(key).await
    }
    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        _: &russh::Names,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct Server;
impl server::Handler for Server {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

struct AuthServer {
    rounds: usize,
    ping: Option<tokio::sync::oneshot::Receiver<()>>,
}
impl server::Handler for AuthServer {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        _: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if password == "scoped-password-fixture" {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        session.send_ping(sender)?;
        self.ping = Some(receiver);
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: russh::ChannelId,
        term: &str,
        columns: u32,
        rows: u32,
        _: u32,
        _: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.ping.take().unwrap().try_recv().unwrap();
        assert_eq!(term, "终端-fixture");
        assert_eq!((columns, rows), (80, 24));
        assert_eq!(modes, &[(russh::Pty::ECHO, 1)]);
        session.data(channel, b"before-pty-success".as_slice())?;
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: russh::ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn window_change_request(
        &mut self,
        _: russh::ChannelId,
        columns: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        assert_eq!((columns, rows), (120, 40));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())
    }

    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.exit_status_request(channel, 17)?;
        session.eof(channel)?;
        session.close(channel)
    }
    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _: &str,
        _: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<server::Auth, Self::Error> {
        use std::borrow::Cow;
        if let Some(mut response) = response {
            if response.next().as_deref() != Some(b"scoped-answer-fixture".as_slice())
                || response.next().is_some()
            {
                return Ok(server::Auth::reject());
            }
            self.rounds += 1;
            if self.rounds == 2 {
                return Ok(server::Auth::Accept);
            }
        }
        Ok(server::Auth::Partial {
            name: Cow::Borrowed("认证"),
            instructions: Cow::Borrowed("合成提示"),
            prompts: Cow::Owned(vec![(Cow::Borrowed("口令"), false)]),
        })
    }
}

fn auth_fixture() -> (
    tokio::io::DuplexStream,
    Client,
    std::thread::JoinHandle<Result<(), russh::Error>>,
) {
    fixture(AuthServer {
        rounds: 0,
        ping: None,
    })
}

fn fixture<H: server::Handler<Error = russh::Error> + Send + 'static>(
    handler: H,
) -> (
    tokio::io::DuplexStream,
    Client,
    std::thread::JoinHandle<Result<(), russh::Error>>,
) {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let client = Client(key.public_key().clone());
    let config = Arc::new(server::Config {
        keys: vec![key],
        window_size: 1024,
        maximum_packet_size: 512,
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    let server = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                tokio::time::timeout(Duration::from_secs(15), async {
                    server::run_stream(config, server_stream, handler)
                        .await
                        .unwrap()
                        .await
                })
                .await
                .unwrap()
            })
    });
    (client_stream, client, server)
}

#[test]
fn scoped_password_and_multiround_keyboard_without_client_tokio() {
    for keyboard in [false, true] {
        let (stream, handler, server) = auth_fixture();
        let live = Arc::new(AtomicUsize::new(0));
        let scope = Scope(live.clone(), None);
        assert!(tokio::runtime::Handle::try_current().is_err());
        futures::executor::block_on(async {
            let mut client = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                stream,
                handler,
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            if keyboard {
                let result = client
                    .authenticate_keyboard_interactive_start("fixture", None)
                    .await
                    .unwrap();
                let client::ScopedKeyboardInteractiveResponse::InfoRequest(info) = result else {
                    panic!("expected prompts")
                };
                assert_eq!(info.name(), "认证");
                assert_eq!(info.instructions(), "合成提示");
                let mut prompts = info.prompts();
                let prompt = prompts.next().unwrap();
                assert_eq!(prompt.prompt, "口令");
                assert!(!prompt.echo);
                assert!(prompts.next().is_none());
                let late_prompt = info.root().try_clone().unwrap();
                drop(info);
                assert!(matches!(
                    client
                        .authenticate_keyboard_interactive_respond(&["scoped-answer-fixture"])
                        .await
                        .unwrap(),
                    client::ScopedKeyboardInteractiveResponse::InfoRequest(_)
                ));
                assert!(matches!(
                    client
                        .authenticate_keyboard_interactive_respond(&["scoped-answer-fixture"])
                        .await
                        .unwrap(),
                    client::ScopedKeyboardInteractiveResponse::Success
                ));
                client.shutdown().await.unwrap();
                assert!(live.load(Ordering::SeqCst) > 0);
                drop(late_prompt);
            } else {
                assert!(
                    !client
                        .authenticate_password("fixture", "wrong-password-fixture")
                        .await
                        .unwrap()
                        .success()
                );
                assert!(
                    client
                        .authenticate_password("fixture", "scoped-password-fixture")
                        .await
                        .unwrap()
                        .success()
                );
                client.shutdown().await.unwrap();
            }
        });
        assert!(server.join().unwrap().is_ok());
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn scoped_auth_queue_and_packet_budget_failures_are_not_auth_rejections() {
    for site in [
        "client.auth.payload",
        "client.command.node",
        "client.packet.seal",
        "client.packet.read",
    ] {
        let (stream, handler, server) = auth_fixture();
        let live = Arc::new(AtomicUsize::new(0));
        let scope = Scope(live.clone(), Some(site));
        futures::executor::block_on(async {
            let connection = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                stream,
                handler,
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await;
            let error = if site == "client.packet.read" {
                match connection {
                    Err(error) => error,
                    Ok(_) => panic!("read must require admission"),
                }
            } else {
                let mut client = connection.unwrap();
                client
                    .authenticate_password("fixture", "scoped-password-fixture")
                    .await
                    .unwrap_err()
            };
            assert!(
                matches!(error, ScopedError::Resource(ScopedFault { kind: FaultKind::ByteBudget, site: failed, .. }) if failed == site)
            );
        });
        let outcome = server.join().unwrap();
        assert!(matches!(outcome, Ok(()) | Err(russh::Error::IO(_))));
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn scoped_pty_shell_flow_window_resize_exit_and_late_data_root() {
    for keyboard in [false, true] {
        let (stream, handler, server) = auth_fixture();
        let live = Arc::new(AtomicUsize::new(0));
        let scope = Scope(live.clone(), None);
        let exchanges = Arc::new(AtomicUsize::new(0));
        let handler = ObservedClient {
            client: handler,
            exchanges: exchanges.clone(),
        };
        assert!(tokio::runtime::Handle::try_current().is_err());
        futures::executor::block_on(async {
            let config = Arc::new(client::Config {
                window_size: 1024,
                maximum_packet_size: 512,
                ..client::Config::default()
            });
            let mut client = client::connect_stream_scoped(
                config,
                stream,
                handler,
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            if keyboard {
                assert!(matches!(
                    client
                        .authenticate_keyboard_interactive_start("fixture", None)
                        .await
                        .unwrap(),
                    client::ScopedKeyboardInteractiveResponse::InfoRequest(_)
                ));
                assert!(matches!(
                    client
                        .authenticate_keyboard_interactive_respond(&["scoped-answer-fixture"])
                        .await
                        .unwrap(),
                    client::ScopedKeyboardInteractiveResponse::InfoRequest(_)
                ));
                assert!(matches!(
                    client
                        .authenticate_keyboard_interactive_respond(&["scoped-answer-fixture"])
                        .await
                        .unwrap(),
                    client::ScopedKeyboardInteractiveResponse::Success
                ));
            } else {
                assert!(
                    client
                        .authenticate_password("fixture", "scoped-password-fixture")
                        .await
                        .unwrap()
                        .success()
                );
            }
            let (bad_stream, bad_handler, bad_server) = auth_fixture();
            let bad_scope = Scope(live.clone(), Some("client.command.node"));
            let mut bad = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                bad_stream,
                bad_handler,
                bad_scope.clone(),
                Spawner,
                Clock(bad_scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            assert!(matches!(
                bad.authenticate_password("fixture", "scoped-password-fixture")
                    .await,
                Err(ScopedError::Resource(ScopedFault {
                    kind: FaultKind::ByteBudget,
                    ..
                }))
            ));
            drop(bad);
            assert!(matches!(
                bad_server.join().unwrap(),
                Ok(()) | Err(russh::Error::IO(_))
            ));
            let mut channel = client.channel_open_session().await.unwrap();
            client.rekey_soon().await.unwrap();
            let mut late_data = None;
            {
                let run = async {
                    use client::ScopedChannelMsg as Event;
                    channel
                        .request_pty(
                            true,
                            "终端-fixture",
                            80,
                            24,
                            0,
                            0,
                            &[(russh::Pty::TTY_OP_END, 0), (russh::Pty::ECHO, 1)],
                        )
                        .await
                        .unwrap();
                    match channel.wait().await.unwrap().unwrap() {
                        Event::Data(data) => {
                            assert_eq!(data.as_slice(), b"before-pty-success");
                            late_data = Some(data.root().try_clone().unwrap());
                        }
                        _ => panic!("data must precede PTY success"),
                    }
                    assert!(matches!(
                        channel.wait().await.unwrap(),
                        Some(Event::Success)
                    ));
                    channel.request_shell(true).await.unwrap();
                    assert!(matches!(
                        channel.wait().await.unwrap(),
                        Some(Event::Success)
                    ));
                    channel.window_change(120, 40, 0, 0).await.unwrap();
                    let bytes = vec![0x5a; 8192];
                    channel.data(&bytes).await.unwrap();
                    let mut received = 0;
                    while received < bytes.len() {
                        match channel.wait().await.unwrap().unwrap() {
                            Event::Data(data) => {
                                assert!(data.as_slice().iter().all(|byte| *byte == 0x5a));
                                received += data.len();
                            }
                            _ => panic!("expected echoed data"),
                        }
                    }
                    assert_eq!(received, bytes.len());
                    channel.eof().await.unwrap();
                    assert!(matches!(
                        channel.wait().await.unwrap(),
                        Some(Event::ExitStatus(17))
                    ));
                    assert!(matches!(channel.wait().await.unwrap(), Some(Event::Eof)));
                    assert!(matches!(channel.wait().await.unwrap(), Some(Event::Close)));
                };
                let run = std::pin::pin!(run);
                match futures::future::select(run, &mut client).await {
                    futures::future::Either::Left(_) => (),
                    futures::future::Either::Right((result, _)) => {
                        panic!("connection ended before terminal: {result:?}")
                    }
                }
            }
            drop(channel);
            assert!(exchanges.load(Ordering::SeqCst) >= 2);
            client.shutdown().await.unwrap();
            assert!(live.load(Ordering::SeqCst) > 0);
            drop(late_data);
        });
        assert!(server.join().unwrap().is_ok());
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

struct GateScope {
    base: Scope,
    sealed: Arc<AtomicUsize>,
    blocked: Arc<AtomicBool>,
}
impl AdmissionScope for GateScope {
    type Reservation = Grant;
    fn try_reserve(&self, request: ResourceRequest) -> Result<Grant, ScopedFault> {
        let grant = self.base.try_reserve(request)?;
        if request.site == "client.packet.seal" && self.sealed.fetch_add(1, Ordering::SeqCst) == 1 {
            self.blocked.store(true, Ordering::SeqCst);
        }
        Ok(grant)
    }
}

struct GateStream {
    stream: tokio::io::DuplexStream,
    blocked: Arc<AtomicBool>,
    pending_writes: Option<Arc<AtomicUsize>>,
}
impl tokio::io::AsyncRead for GateStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl tokio::io::AsyncWrite for GateStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.blocked.load(Ordering::SeqCst) {
            if let Some(count) = &self.pending_writes {
                count.fetch_add(1, Ordering::SeqCst);
            }
            Poll::Pending
        } else {
            Pin::new(&mut self.stream).poll_write(cx, bytes)
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[test]
fn cancelled_auth_finishes_while_encrypted_write_stays_pending() {
    let (stream, handler, server) = auth_fixture();
    let live = Arc::new(AtomicUsize::new(0));
    let base = Scope(live.clone(), None);
    let blocked = Arc::new(AtomicBool::new(false));
    let scope = GateScope {
        base: base.clone(),
        sealed: Arc::new(AtomicUsize::new(0)),
        blocked: blocked.clone(),
    };
    futures::executor::block_on(async {
        let stream = GateStream {
            stream,
            blocked: blocked.clone(),
            pending_writes: None,
        };
        let mut client = client::connect_stream_scoped(
            Arc::new(client::Config::default()),
            stream,
            handler,
            scope,
            Spawner,
            Clock(base),
            Budget(AtomicUsize::new(0)),
        )
        .await
        .unwrap();
        {
            let auth = client.authenticate_password("fixture", "scoped-password-fixture");
            let mut auth = std::pin::pin!(auth);
            std::future::poll_fn(|cx| {
                assert!(auth.as_mut().poll(cx).is_pending());
                if blocked.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        let late = client.root().try_clone().unwrap();
        assert!(matches!(
            (&mut client).await,
            Err(ScopedError::Resource(ScopedFault {
                kind: FaultKind::Cancelled,
                ..
            }))
        ));
        assert!(blocked.load(Ordering::SeqCst));
        drop(client);
        assert!(live.load(Ordering::SeqCst) > 0);
        drop(late);
    });
    assert!(matches!(
        server.join().unwrap(),
        Ok(()) | Err(russh::Error::IO(_))
    ));
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn scoped_connect_authenticate_shutdown_without_client_tokio_runtime() {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let expected = key.public_key().clone();
    let server_config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::ZERO,
        ..server::Config::default()
    });
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    let server_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            tokio::time::timeout(Duration::from_secs(15), async {
                server::run_stream(server_config, server_stream, Server)
                    .await
                    .unwrap()
                    .await
            })
            .await
            .unwrap()
        })
    });
    assert!(tokio::runtime::Handle::try_current().is_err());
    let live = Arc::new(AtomicUsize::new(0));
    let scope = Scope(live.clone(), None);
    futures::executor::block_on(async {
        let mut client = client::connect_stream_scoped(
            Arc::new(client::Config::default()),
            client_stream,
            Client(expected),
            scope.clone(),
            Spawner,
            Clock(scope),
            Budget(AtomicUsize::new(0)),
        )
        .await
        .unwrap();
        assert!(client.authenticate_none("fixture").await.unwrap().success());
        client.best_supported_rsa_hash().await.unwrap();
        client.send_keepalive(false).await.unwrap();
        let late = client.root().try_clone().unwrap();
        client.shutdown().await.unwrap();
        assert!(live.load(Ordering::SeqCst) > 0);
        drop(late);
    });
    // 对端可能在客户端已关闭读取后写最后一个 keepalive 回复。
    match server_thread.join().unwrap() {
        Ok(()) => (),
        Err(russh::Error::IO(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => (),
        result => panic!("unexpected server outcome: {result:?}"),
    }
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

struct ProbeStream {
    bytes: &'static [u8],
    writes: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

#[derive(Default)]
struct IncomingMailbox {
    open: Option<client::ScopedChannelOpen<Scope, Clock, Budget>>,
    metadata: Option<ResourceRoot<Grant>>,
    called: usize,
}
struct IncomingClient {
    key: PublicKey,
    mailbox: Arc<std::sync::Mutex<IncomingMailbox>>,
    mode: usize,
}
impl client::Handler for IncomingClient {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(key == &self.key)
    }
}
impl client::ScopedHandler<Scope, Clock, Budget> for IncomingClient {
    async fn server_channel_open_scoped(
        &mut self,
        open: client::ScopedChannelOpen<Scope, Clock, Budget>,
    ) -> Result<(), ScopedError<Self::Error>> {
        assert_eq!(
            open.info().kind(),
            client::ScopedChannelType::ForwardedTcpIp
        );
        assert_eq!(open.info().address(), Some(("接入-fixture", 41)));
        assert_eq!(open.info().originator(), Some(("来源-fixture", 42)));
        {
            let mut mailbox = self.mailbox.lock().unwrap();
            mailbox.called += 1;
            mailbox.metadata = Some(
                open.info()
                    .root()
                    .try_clone()
                    .map_err(ScopedError::Resource)?,
            );
        }
        if self.mode == 5 {
            std::future::pending::<()>().await;
        }
        match self.mode {
            0 => self.mailbox.lock().unwrap().open = Some(open),
            1 => open.reject(1),
            _ => drop(open),
        }
        Ok(())
    }
}
struct IncomingServer(Option<tokio::sync::oneshot::Sender<server::Handle>>);
impl server::Handler for IncomingServer {
    type Error = russh::Error;
    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    async fn auth_succeeded(&mut self, session: &mut server::Session) -> Result<(), Self::Error> {
        self.0.take().unwrap().send(session.handle()).unwrap();
        Ok(())
    }
}

#[test]
fn scoped_incoming_channel_accept_reject_drop_and_prehandler_quota() {
    for mode in 0..6 {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let expected = key.public_key().clone();
        let config = Arc::new(server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            ..server::Config::default()
        });
        let (stream, remote) = tokio::io::duplex(4096);
        let (ready, established) = tokio::sync::oneshot::channel();
        let (start, started) = tokio::sync::oneshot::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let server_completed = completed.clone();
        let server = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    tokio::time::timeout(Duration::from_secs(15), async move {
                        let connection =
                            server::run_stream(config, remote, IncomingServer(Some(ready)))
                                .await
                                .unwrap();
                        let drive = async move {
                            let handle = established.await.unwrap();
                            started.await.unwrap();
                            let opened = handle
                                .channel_open_forwarded_tcpip(
                                    "接入-fixture",
                                    41,
                                    "来源-fixture",
                                    42,
                                )
                                .await;
                            match mode {
                                0 => {
                                    let mut channel = opened.unwrap();
                                    channel
                                        .data(b"server-channel-data".as_slice())
                                        .await
                                        .unwrap();
                                    loop {
                                        match channel.wait().await.unwrap() {
                                            russh::ChannelMsg::Data { data } => {
                                                assert_eq!(data.as_ref(), b"client-channel-data");
                                                break;
                                            }
                                            russh::ChannelMsg::WindowAdjusted { .. } => (),
                                            event => panic!(
                                                "unexpected incoming-channel event: {event:?}"
                                            ),
                                        }
                                    }
                                    channel.eof().await.unwrap();
                                    loop {
                                        match channel.wait().await.unwrap() {
                                            russh::ChannelMsg::Close => break,
                                            russh::ChannelMsg::WindowAdjusted { .. } => (),
                                            event => panic!("unexpected close event: {event:?}"),
                                        }
                                    }
                                }
                                1 | 2 => assert!(matches!(
                                    opened,
                                    Err(russh::Error::ChannelOpenFailure(
                                        russh::ChannelOpenFailure::AdministrativelyProhibited
                                    ))
                                )),
                                _ => assert!(opened.is_err()),
                            }
                            server_completed.store(true, Ordering::SeqCst);
                        };
                        let (result, ()) = tokio::join!(connection, drive);
                        result
                    })
                    .await
                    .unwrap()
                })
        });
        let live = Arc::new(AtomicUsize::new(0));
        let denied = match mode {
            3 => Some("client.channel.open.info"),
            4 => Some("client.channel.open.decision"),
            _ => None,
        };
        let scope = Scope(live.clone(), denied);
        let mailbox = Arc::new(std::sync::Mutex::new(IncomingMailbox::default()));
        futures::executor::block_on(async {
            let mut client = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                stream,
                IncomingClient {
                    key: expected,
                    mailbox: mailbox.clone(),
                    mode,
                },
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            assert!(client.authenticate_none("fixture").await.unwrap().success());
            start.send(()).unwrap();
            if let Some(site) = denied {
                assert!(
                    matches!((&mut client).await, Err(ScopedError::Resource(ScopedFault { kind: FaultKind::ByteBudget, site: failed, .. })) if site == failed)
                );
                assert_eq!(mailbox.lock().unwrap().called, 0);
                return;
            }
            std::future::poll_fn(|cx| {
                assert!(Pin::new(&mut client).poll(cx).is_pending());
                if mailbox.lock().unwrap().called != 0 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            if mode == 5 {
                client.shutdown().await.unwrap();
                return;
            }
            if mode == 0 {
                let open = mailbox.lock().unwrap().open.take().unwrap();
                assert_eq!(open.info().address().unwrap().0, "接入-fixture");
                let mut channel = open.accept().unwrap();
                let run = async {
                    let Some(client::ScopedChannelMsg::Data(data)) = channel.wait().await.unwrap()
                    else {
                        panic!("expected actual channel data")
                    };
                    assert_eq!(data.as_slice(), b"server-channel-data");
                    channel.data(b"client-channel-data").await.unwrap();
                    assert!(matches!(
                        channel.wait().await.unwrap(),
                        Some(client::ScopedChannelMsg::Eof)
                    ));
                    channel.close().await.unwrap();
                    assert!(matches!(
                        channel.wait().await.unwrap(),
                        Some(client::ScopedChannelMsg::Close)
                    ));
                };
                let mut run = std::pin::pin!(run);
                match futures::future::select(&mut run, &mut client).await {
                    futures::future::Either::Left(_) => (),
                    _ => panic!("connection ended before incoming channel exchange"),
                }
            }
            std::future::poll_fn(|cx| {
                assert!(Pin::new(&mut client).poll(cx).is_pending());
                if completed.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            client.shutdown().await.unwrap();
        });
        let result = server.join().unwrap();
        if denied.is_none() && mode != 5 {
            result.unwrap();
        } else {
            assert!(matches!(result, Ok(()) | Err(russh::Error::IO(_))));
        }
        drop(mailbox.lock().unwrap().metadata.take());
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "ring")]
struct KeyServer {
    public: PublicKey,
    certificate: Option<ssh_key::Certificate>,
}
#[cfg(feature = "ring")]
impl server::Handler for KeyServer {
    type Error = russh::Error;
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if user == "fixture" && key == &self.public {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        self.auth_publickey_offered(user, key).await
    }
    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &ssh_key::Certificate,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "fixture" && self.certificate.as_ref() == Some(certificate) {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
}

#[cfg(feature = "ring")]
struct KeySigner {
    key: Rooted<ring::signature::Ed25519KeyPair, Grant>,
    late: Option<ResourceRoot<Grant>>,
    calls: usize,
    fail_operation: bool,
}
#[cfg(feature = "ring")]
impl client::ScopedSigner<Scope> for KeySigner {
    type Error = russh::Error;
    async fn sign(
        &mut self,
        scope: &Scope,
        request: &client::ScopedSignRequest<Grant>,
        _: Option<ssh_key::HashAlg>,
    ) -> Result<ScopedBuffer<Grant>, ScopedError<Shared<Self::Error, Grant>>> {
        if self.fail_operation {
            let error =
                Rooted::try_new(scope, ResourceClass::Control, "fixture.sign.error", || {
                    russh::Error::SendError
                })
                .map_err(ScopedError::Resource)?
                .into_shared();
            return Err(ScopedError::Operation(error));
        }
        let mut output = ScopedBuffer::try_with_capacity(
            scope,
            ResourceClass::Secret,
            "fixture.sign.signature",
            4 + 11 + 4 + 64,
        )
        .map_err(ScopedError::Resource)?;
        self.late = Some(request.root().try_clone().map_err(ScopedError::Resource)?);
        self.calls += 1;
        assert!(!request.public_key_blob().is_empty());
        assert!(request.algorithm().starts_with("ssh-ed25519"));
        let mut yielded = false;
        std::future::poll_fn(|cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        let signature = self.key.get().sign(request.data());
        output
            .try_extend_from_slice(scope, &11u32.to_be_bytes())
            .map_err(ScopedError::Resource)?;
        output
            .try_extend_from_slice(scope, b"ssh-ed25519")
            .map_err(ScopedError::Resource)?;
        output
            .try_extend_from_slice(scope, &64u32.to_be_bytes())
            .map_err(ScopedError::Resource)?;
        output
            .try_extend_from_slice(scope, signature.as_ref())
            .map_err(ScopedError::Resource)?;
        Ok(output)
    }
}

#[test]
#[cfg(feature = "ring")]
fn scoped_external_signer_publickey_and_certificate_authenticate_without_tokio() {
    for certificate in [false, true] {
        let user_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let cert = certificate.then(|| {
            let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
            let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
                &mut rand::rng(),
                user_key.public_key(),
                0,
                u64::MAX,
            )
            .unwrap();
            builder
                .cert_type(ssh_key::certificate::CertType::User)
                .unwrap();
            builder.valid_principal("fixture").unwrap();
            builder.sign(&ca).unwrap()
        });
        let blob = match &cert {
            Some(cert) => cert.to_bytes().unwrap(),
            None => user_key.public_key().to_bytes().unwrap(),
        };
        let (stream, handler, server) = fixture(KeyServer {
            public: user_key.public_key().clone(),
            certificate: cert,
        });
        let live = Arc::new(AtomicUsize::new(0));
        let scope = Scope(live.clone(), None);
        let key = Rooted::try_new(&scope, ResourceClass::Secret, "fixture.sign.key", || {
            ring::signature::Ed25519KeyPair::from_seed_unchecked(
                user_key.key_data().ed25519().unwrap().private.as_ref(),
            )
            .unwrap()
        })
        .unwrap();
        let mut signer = KeySigner {
            key,
            late: None,
            calls: 0,
            fail_operation: false,
        };
        assert!(tokio::runtime::Handle::try_current().is_err());
        futures::executor::block_on(async {
            let mut client = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                stream,
                handler,
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            let result = if certificate {
                client
                    .authenticate_certificate_with("fixture", &blob, None, &mut signer)
                    .await
            } else {
                client
                    .authenticate_publickey_with("fixture", &blob, None, &mut signer)
                    .await
            }
            .unwrap();
            assert!(result.success());
            assert_eq!(signer.calls, 1);
            client.shutdown().await.unwrap();
        });
        server.join().unwrap().unwrap();
        assert!(live.load(Ordering::SeqCst) > 0);
        drop(signer);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

struct ControlScope {
    base: Scope,
    created: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
}
impl AdmissionScope for ControlScope {
    type Reservation = Grant;
    fn try_reserve(&self, request: ResourceRequest) -> Result<Grant, ScopedFault> {
        let site = request.site;
        let mut grant = self.base.try_reserve(request)?;
        if site == "client.control.reply.node" {
            self.created.fetch_add(1, Ordering::SeqCst);
            grant.completed = Some(self.completed.clone());
        }
        Ok(grant)
    }
}

#[test]
fn keepalive_reply_is_received_before_control_root_is_released() {
    let (stream, handler, server) = auth_fixture();
    let live = Arc::new(AtomicUsize::new(0));
    let base = Scope(live.clone(), None);
    let created = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    futures::executor::block_on(async {
        let mut client = client::connect_stream_scoped(
            Arc::new(client::Config::default()),
            stream,
            handler,
            ControlScope {
                base: base.clone(),
                created: created.clone(),
                completed: completed.clone(),
            },
            Spawner,
            Clock(base),
            Budget(AtomicUsize::new(0)),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_password("fixture", "scoped-password-fixture")
                .await
                .unwrap()
                .success()
        );
        client.send_keepalive(true).await.unwrap();
        std::future::poll_fn(|cx| {
            assert!(Pin::new(&mut client).poll(cx).is_pending());
            if completed.load(Ordering::SeqCst) == 1 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert_eq!(created.load(Ordering::SeqCst), 1);
        client.send_keepalive(false).await.unwrap();
        let channel = client.channel_open_session().await.unwrap();
        assert_eq!(created.load(Ordering::SeqCst), 1);
        drop(channel);
        client.shutdown().await.unwrap();
    });
    server.join().unwrap().unwrap();
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn scoped_keepalive_queue_and_reply_quota_failures_are_terminal_resource_faults() {
    for site in ["client.control.node", "client.control.reply.node"] {
        let (stream, handler, server) = auth_fixture();
        let live = Arc::new(AtomicUsize::new(0));
        let scope = Scope(live.clone(), Some(site));
        futures::executor::block_on(async {
            let mut client = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                stream,
                handler,
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            assert!(
                client
                    .authenticate_password("fixture", "scoped-password-fixture")
                    .await
                    .unwrap()
                    .success()
            );
            client.send_keepalive(true).await.unwrap();
            let Err(ScopedError::Resource(fault)) = (&mut client).await else {
                panic!("control quota must remain a resource fault")
            };
            assert_eq!(fault.kind, FaultKind::ByteBudget);
            assert_eq!(fault.site, site);
            assert!(fault.requested > 0);
            assert_eq!(fault.available, Some(0));
        });
        assert!(matches!(
            server.join().unwrap(),
            Ok(()) | Err(russh::Error::IO(_))
        ));
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

#[derive(Clone)]
struct ClosingScope {
    base: Scope,
    exhausted: Arc<AtomicBool>,
    reservations: Arc<AtomicUsize>,
}

impl AdmissionScope for ClosingScope {
    type Reservation = Grant;
    fn try_reserve(&self, request: ResourceRequest) -> Result<Grant, ScopedFault> {
        self.reservations.fetch_add(1, Ordering::SeqCst);
        if self.exhausted.load(Ordering::SeqCst) {
            return Err(ScopedFault {
                kind: FaultKind::ByteBudget,
                site: request.site,
                requested: request.bytes()?,
                available: Some(0),
            });
        }
        self.base.try_reserve(request)
    }
}

#[test]
fn shutdown_needs_no_new_grant_even_when_write_is_pending() {
    for mode in 0..3 {
        let pending = mode != 0;
        let (stream, handler, server) = auth_fixture();
        let live = Arc::new(AtomicUsize::new(0));
        let scope = ClosingScope {
            base: Scope(live.clone(), None),
            exhausted: Arc::new(AtomicBool::new(false)),
            reservations: Arc::new(AtomicUsize::new(0)),
        };
        let blocked = Arc::new(AtomicBool::new(false));
        let pending_writes = Arc::new(AtomicUsize::new(0));
        futures::executor::block_on(async {
            let mut client = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                GateStream {
                    stream,
                    blocked: blocked.clone(),
                    pending_writes: Some(pending_writes.clone()),
                },
                handler,
                scope.clone(),
                Spawner,
                Clock(scope.base.clone()),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            assert!(
                client
                    .authenticate_password("fixture", "scoped-password-fixture")
                    .await
                    .unwrap()
                    .success()
            );
            let late = client.root().try_clone().unwrap();
            blocked.store(pending, Ordering::SeqCst);
            if mode == 2 {
                client.rekey_soon().await.unwrap();
                std::future::poll_fn(|cx| {
                    assert!(Pin::new(&mut client).poll(cx).is_pending());
                    if pending_writes.load(Ordering::SeqCst) != 0 {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
            scope.exhausted.store(true, Ordering::SeqCst);
            let before = scope.reservations.load(Ordering::SeqCst);
            let mut shutdown = std::pin::pin!(client.shutdown());
            let result = std::future::poll_fn(|cx| {
                // 新连接没有待处理应用消息，关闭不得等待网络或新准入。
                match shutdown.as_mut().poll(cx) {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => panic!("shutdown waited for a blocked transport"),
                }
            })
            .await;
            result.unwrap();
            assert_eq!(scope.reservations.load(Ordering::SeqCst), before);
            assert!(live.load(Ordering::SeqCst) > 0);
            drop(late);
        });
        let result = server.join().unwrap();
        if pending {
            assert!(
                matches!(result, Err(russh::Error::IO(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
            );
        } else {
            result.unwrap();
        }
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}
impl Drop for ProbeStream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
#[test]
#[cfg(feature = "ring")]
fn scoped_signer_and_signed_packet_failures_keep_the_original_terminal_error() {
    for denied in [
        None,
        Some("fixture.sign.signature"),
        Some("client.auth.signed"),
    ] {
        let user_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let blob = user_key.public_key().to_bytes().unwrap();
        let (stream, handler, server) = fixture(KeyServer {
            public: user_key.public_key().clone(),
            certificate: None,
        });
        let live = Arc::new(AtomicUsize::new(0));
        let scope = Scope(live.clone(), denied);
        let key = Rooted::try_new(&scope, ResourceClass::Secret, "fixture.sign.key", || {
            ring::signature::Ed25519KeyPair::from_seed_unchecked(
                user_key.key_data().ed25519().unwrap().private.as_ref(),
            )
            .unwrap()
        })
        .unwrap();
        let mut signer = KeySigner {
            key,
            late: None,
            calls: 0,
            fail_operation: denied.is_none(),
        };
        futures::executor::block_on(async {
            let mut client = client::connect_stream_scoped(
                Arc::new(client::Config::default()),
                stream,
                handler,
                scope.clone(),
                Spawner,
                Clock(scope),
                Budget(AtomicUsize::new(0)),
            )
            .await
            .unwrap();
            let error = client
                .authenticate_publickey_with("fixture", &blob, None, &mut signer)
                .await
                .unwrap_err();
            let terminal = (&mut client).await.unwrap_err();
            for error in [&error, &terminal] {
                match (denied, error) {
                    (None, ScopedError::Operation(error)) => {
                        assert!(matches!(error.get(), russh::Error::SendError))
                    }
                    (
                        Some(expected),
                        ScopedError::Resource(ScopedFault {
                            kind: FaultKind::ByteBudget,
                            site,
                            ..
                        }),
                    ) => assert_eq!(*site, expected),
                    _ => panic!("signing failure changed category"),
                }
            }
        });
        assert!(matches!(
            server.join().unwrap(),
            Ok(()) | Err(russh::Error::IO(_))
        ));
        drop(signer);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}

impl tokio::io::AsyncRead for ProbeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let n = self.bytes.len().min(buffer.remaining());
        buffer.put_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Poll::Ready(Ok(()))
    }
}
impl tokio::io::AsyncWrite for ProbeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
struct RejectClient;
impl<S, C, B> client::ScopedHandler<S, C, B> for RejectClient
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
}
impl client::Handler for RejectClient {
    type Error = russh::Error;
}

#[test]
fn scoped_rejected_host_key_remains_the_primary_operation_error() {
    let (stream, _, server) = auth_fixture();
    let live = Arc::new(AtomicUsize::new(0));
    let scope = Scope(live.clone(), None);
    let result = futures::executor::block_on(client::connect_stream_scoped(
        Arc::new(client::Config::default()),
        stream,
        RejectClient,
        scope.clone(),
        Spawner,
        Clock(scope),
        Budget(AtomicUsize::new(0)),
    ));
    let Err(ScopedError::Operation(error)) = result else {
        panic!("host key rejection must remain an operation error")
    };
    assert!(matches!(error.get(), russh::Error::UnknownKey));
    assert!(live.load(Ordering::SeqCst) > 0);
    drop(error);
    assert!(matches!(
        server.join().unwrap(),
        Ok(()) | Err(russh::Error::IO(_))
    ));
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn connect_and_spawn_quota_failures_remain_typed_and_release_captures() {
    for site in ["*", "client.control.cleanup", "fixture.task"] {
        let live = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let scope = Scope(live.clone(), Some(site));
        let result = futures::executor::block_on(client::connect_stream_scoped(
            Arc::new(client::Config::default()),
            ProbeStream {
                bytes: b"SSH-2.0-fixture\r\n",
                writes: writes.clone(),
                dropped: dropped.clone(),
            },
            RejectClient,
            scope.clone(),
            Spawner,
            Clock(scope),
            Budget(AtomicUsize::new(0)),
        ));
        assert!(matches!(
            result,
            Err(ScopedError::Resource(ScopedFault {
                kind: FaultKind::ByteBudget,
                ..
            }))
        ));
        if site != "fixture.task" {
            assert_eq!(writes.load(Ordering::SeqCst), 0);
        }
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }
}
