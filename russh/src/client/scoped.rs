use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::task::AtomicWaker;
use ssh_key::{Algorithm, HashAlg};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

use super::runtime::{RunError, Runtime};
use super::{Config, Handler, ReplySender, Session};
use crate::scoped::{AdmissionScope, Cooperative, FaultKind, ResourceClass, queue};
use crate::scoped::{ResourceRoot, RootSlot, Rooted, ScopedClock, ScopedError, ScopedFault};
use crate::scoped::{ScopedSpawner, ScopedTask, Shared};
use crate::session::CommonSession;
use crate::ssh_read::SshRead;
use crate::sshbuffer::PacketWriter;
use crate::{Disconnect, Error, MethodKind, SshId};

pub(super) mod auth;
pub(super) mod channel;
pub(super) mod control;
mod incoming;
mod packet;
mod sign;
mod source;
pub use auth::{ScopedAuthInfo, ScopedKeyboardInteractiveResponse, ScopedPrompt, ScopedPrompts};
pub use channel::{ScopedChannel, ScopedChannelMsg};
pub use incoming::{
    ScopedChannelOpen, ScopedChannelType, ScopedDisconnectReason, ScopedHandler, ScopedOpenInfo,
};
pub use sign::{ScopedSignRequest, ScopedSigner};

type Outcome<E, R> = Result<(), ScopedError<Shared<E, R>>>;
type ClientResult<T, E, R> = Result<T, ScopedError<Shared<E, R>>>;
type ErrorSlot<E, R> = ClientResult<RootSlot<E, R>, E, R>;

#[derive(Debug)]
pub(super) struct WritePacket {
    bytes: crate::scoped::ErasedBuffer,
    offset: usize,
}

pub(super) fn poll_write<W: AsyncWrite + Unpin>(
    packet: &mut Option<WritePacket>,
    stream: &mut W,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<()>> {
    let Some(pending) = packet.as_mut() else {
        return Poll::Pending;
    };
    let remaining = pending.bytes.as_slice().split_at(pending.offset).1;
    if !remaining.is_empty() {
        match Pin::new(&mut *stream).poll_write(cx, remaining) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(0)) => return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
            Poll::Ready(Ok(count)) => {
                pending.offset += count;
                return Poll::Ready(Ok(()));
            }
        }
    }
    match Pin::new(stream).poll_flush(cx) {
        Poll::Ready(Ok(())) => {
            packet.take();
            Poll::Ready(Ok(()))
        }
        result => result,
    }
}

#[derive(Debug)]
pub(super) enum Command {
    Authenticate(auth::Request),
    Open(crate::scoped::ErasedRooted<channel::State>),
    Channel { id: u32, pending: channel::Pending },
    Consumed { id: u32, bytes: u32 },
    Keepalive { want_reply: bool },
    Rekey,
}

/// 认证状态不把可变容量的 MethodSet backing 裸传出 scope。
#[derive(Debug)]
pub enum ScopedAuthResult {
    Success,
    Failure {
        remaining_methods: [Option<MethodKind>; 5],
        partial_success: bool,
    },
}

impl ScopedAuthResult {
    pub fn success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

struct Services<S, C, B> {
    scope: S,
    commands: queue::Sender<Command>,
    clock: C,
    cooperative: B,
    rsa: AtomicU8,
    rsa_waiter: AtomicWaker,
    closing: AtomicU32,
    cause: std::sync::Mutex<Option<ScopedFault>>,
    control: AtomicWaker,
    channel_cleanup: AtomicBool,
    window_size: u32,
    maximum_packet_size: u32,
}

impl<S, C, B> Services<S, C, B> {
    fn fail(&self, fault: ScopedFault) {
        {
            let mut cause = self.cause.lock().unwrap_or_else(|error| error.into_inner());
            if cause.is_none() {
                *cause = Some(fault);
            }
        }
        self.control.wake();
    }

    fn failure(&self) -> Option<ScopedFault> {
        *self.cause.lock().unwrap_or_else(|error| error.into_inner())
    }
}

async fn notify_disconnected<S, C, B, H>(
    services: &Shared<Services<S, C, B>, S::Reservation>,
    handler: &mut H,
    reason: ScopedDisconnectReason<'_, H::Error, S::Reservation>,
) -> Result<(), ScopedError<H::Error>>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
    H: ScopedHandler<S, C, B>,
    H::Error: Sync,
{
    if let Some(fault) = services.get().failure() {
        return Err(ScopedError::Resource(fault));
    }
    if services.get().closing.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let callback = handler.disconnected_scoped(reason);
    let mut callback = std::pin::pin!(callback);
    std::future::poll_fn(|cx| {
        let services = services.get();
        services.control.register(cx.waker());
        if let Some(fault) = services.failure() {
            return Poll::Ready(Err(ScopedError::Resource(fault)));
        }
        if services.closing.load(Ordering::Acquire) != 0 {
            return Poll::Ready(Ok(()));
        }
        callback.as_mut().poll(cx)
    })
    .await
}

struct AuthWait<
    S: AdmissionScope + Send + Sync + 'static,
    C: Send + Sync + 'static,
    B: Send + Sync + 'static,
> {
    services: Shared<Services<S, C, B>, S::Reservation>,
    armed: bool,
}

impl<S: AdmissionScope + Send + Sync + 'static, C: Send + Sync + 'static, B: Send + Sync + 'static>
    Drop for AuthWait<S, C, B>
{
    fn drop(&mut self) {
        if self.armed {
            self.services.get().fail(ScopedFault {
                kind: FaultKind::Cancelled,
                site: "client.auth.cancelled",
                requested: 0,
                available: None,
            });
        }
    }
}

impl<S, C, B> Runtime for Shared<Services<S, C, B>, S::Reservation>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
    type Fault = ScopedFault;
    type Sleep = C::Sleep;

    fn register_poll(&self, cx: &Context<'_>) {
        self.get().control.register(cx.waker());
    }

    fn check(&self) -> Result<(), ScopedFault> {
        self.get().failure().map_or(Ok(()), Err)
    }

    fn sleep(&self, duration: Duration) -> Result<Self::Sleep, ScopedFault> {
        let clock = &self.get().clock;
        let deadline = clock
            .now()
            .checked_add(duration)
            .ok_or_else(|| ScopedFault::overflow("client.clock.deadline"))?;
        clock.sleep_until(deadline)
    }

    fn reset(&self, sleep: Pin<&mut Self::Sleep>, duration: Duration) -> Result<(), ScopedFault> {
        let clock = &self.get().clock;
        let deadline = clock
            .now()
            .checked_add(duration)
            .ok_or_else(|| ScopedFault::overflow("client.clock.deadline"))?;
        clock.reset(sleep, deadline)
    }

    fn begin_poll(&self) {
        self.get().cooperative.begin_poll();
    }

    fn poll_budget(&self, cx: &mut Context<'_>, units: usize) -> Poll<()> {
        self.get().cooperative.poll_budget(cx, units)
    }

    fn observe_server_sig_algs(&self, algorithms: Option<&[Algorithm]>) {
        let Some(algorithms) = algorithms else { return };
        let mut bits = 1;
        for algorithm in algorithms {
            bits |= match algorithm {
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                } => 8,
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                } => 4,
                Algorithm::Rsa { hash: None } => 2,
                _ => 0,
            };
        }
        if self.get().rsa.swap(bits, Ordering::AcqRel) != bits {
            self.get().rsa_waiter.wake();
        }
    }

    fn poll_control(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.get().control.register(cx.waker());
        if self.get().failure().is_some()
            || self.get().closing.load(Ordering::Acquire) != 0
            || self.get().channel_cleanup.swap(false, Ordering::AcqRel)
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn is_closing(&self) -> bool {
        self.get().closing.load(Ordering::Acquire) != 0
    }

    fn scoped_io(&self) -> bool {
        true
    }

    fn keepalive(
        &self,
        session: &mut Session,
        want_reply: bool,
    ) -> Result<(), RunError<Error, ScopedFault>> {
        control::keepalive(&self.get().scope, session, want_reply)
    }

    async fn control<W: AsyncWrite + Unpin + Send>(
        &self,
        session: &mut Session,
        stream: &mut W,
    ) -> Result<bool, RunError<Error, ScopedFault>> {
        let reason = self.get().closing.load(Ordering::Acquire);
        if reason == 0 {
            return Ok(false);
        }
        control::close(&self.get().scope, session, stream, reason).await?;
        Ok(true)
    }

    fn command(
        &self,
        session: &mut Session,
        command: Command,
    ) -> Result<(), RunError<Error, ScopedFault>> {
        match command {
            Command::Keepalive { want_reply } => self.keepalive(session, want_reply),
            Command::Rekey => session.initiate_rekey().map_err(RunError::Operation),
            Command::Authenticate(request) => {
                let state = session.scoped_auth.as_mut().ok_or(Error::Inconsistent)?;
                if request.continuation && (state.id != request.id || state.sent) {
                    return Err(Error::Inconsistent.into());
                }
                state.id = request.id;
                state.kind = request.kind;
                state.probe_pending =
                    request.kind == auth::Kind::PublicKey && !request.continuation;
                if !request.continuation {
                    state.probe.take();
                }
                state.pending = Some(request.packet);
                state.sent = false;
                Ok(())
            }
            command => channel::command(&self.get().scope, session, command),
        }
    }

    async fn read<R: AsyncRead + Unpin + Send>(
        &self,
        mut stream: R,
        mut buffer: crate::sshbuffer::SSHBuffer,
        mut cipher: Box<dyn crate::cipher::OpeningKey + Send>,
    ) -> Result<
        (
            usize,
            R,
            crate::sshbuffer::SSHBuffer,
            Box<dyn crate::cipher::OpeningKey + Send>,
        ),
        RunError<Error, ScopedFault>,
    > {
        let read =
            crate::cipher::read_scoped(&self.get().scope, &mut stream, &mut buffer, &mut *cipher)
                .await;
        match read {
            Ok(n) => Ok((n, stream, buffer, cipher)),
            Err(ScopedError::Resource(fault)) => Err(RunError::Runtime(fault)),
            Err(ScopedError::Operation(error)) => Err(RunError::Operation(error)),
        }
    }

    fn packet(
        &self,
        session: &mut Session,
        buffer: &crate::sshbuffer::SSHBuffer,
    ) -> Result<super::runtime::PacketOwner, RunError<Error, ScopedFault>> {
        if session
            .common
            .encrypted
            .as_ref()
            .is_some_and(|enc| !matches!(enc.decompress, crate::compression::Decompress::None))
        {
            return Err(RunError::Runtime(ScopedFault {
                kind: FaultKind::PolicyUnavailable,
                site: "client.packet.decompression",
                requested: 0,
                available: None,
            }));
        }
        let bytes = buffer
            .packet_bytes()
            .get(5..)
            .ok_or(Error::IndexOutOfBounds)?;
        let scope = &self.get().scope;
        let site = "client.packet.decode";
        let slot = Rooted::<crate::sshbuffer::IncomingSshPacket, _>::try_allocate_with_source(
            scope,
            ResourceClass::Runtime,
            site,
            bytes.len(),
        )
        .map_err(RunError::Runtime)?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            RunError::Runtime(ScopedFault {
                kind: FaultKind::AllocationFailed,
                site,
                requested: bytes.len(),
                available: None,
            })
        })?;
        owned.extend_from_slice(bytes);
        Ok(super::runtime::PacketOwner::Scoped(
            slot.initialize(|| crate::sshbuffer::IncomingSshPacket {
                buffer: owned,
                seqn: buffer.seqn,
            })
            .erase(),
        ))
    }

    async fn flush<W: AsyncWrite + Unpin + Send>(
        &self,
        session: &mut Session,
        _: &mut W,
    ) -> Result<(), RunError<Error, ScopedFault>> {
        if let Some(fault) = self.get().failure() {
            return Err(RunError::Runtime(fault));
        }
        if session.kex.active() {
            return Ok(());
        }
        control::flush(&self.get().scope, session)?;
        if session.scoped_write.is_some() {
            return Ok(());
        }
        auth::flush(&self.get().scope, session)?;
        if session.scoped_write.is_some() {
            return Ok(());
        }
        channel::flush(&self.get().scope, &self.get().cooperative, session).await
    }
}

impl<S, C, B, H> super::runtime::PacketHandler<H> for Shared<Services<S, C, B>, S::Reservation>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
    H: ScopedHandler<S, C, B>,
{
    async fn process(
        &self,
        session: &mut Session,
        handler: &mut H,
        bytes: &[u8],
    ) -> Result<bool, RunError<H::Error, ScopedFault>> {
        if incoming::process(self, session, handler, bytes).await? {
            return Ok(true);
        }
        if control::process(&self.get().scope, session, bytes)
            .map_err(|error| error.map_operation(Into::into))?
        {
            return Ok(true);
        }
        if auth::process(&self.get().scope, session, handler, bytes).await? {
            return Ok(true);
        }
        channel::process(&self.get().scope, session, bytes)
            .map_err(|error| error.map_operation(Into::into))
    }
}

struct HandleState<H, S, P, C, B>
where
    H: Handler,
    H::Error: Send + Sync + 'static,
    S: AdmissionScope,
    P: ScopedSpawner<S>,
{
    commands: queue::Sender<Command>,
    auth_replies: queue::Receiver<auth::Reply>,
    auth_sequence: u64,
    keyboard_attempt: Option<u64>,
    task: P::Task<Outcome<H::Error, S::Reservation>>,
    terminal: Option<Outcome<H::Error, S::Reservation>>,
    primary_failure: Option<ScopedError<Shared<H::Error, S::Reservation>>>,
    // 队列句柄和 task 先释放，Session backing 的最后根随后释放。
    _session: ResourceRoot<S::Reservation>,
    services: Shared<Services<S, C, B>, S::Reservation>,
}

struct Captures<H: Handler, T, S: AdmissionScope, C, B> {
    read: SshRead<tokio::io::ReadHalf<T>>,
    write: tokio::io::WriteHalf<T>,
    handler: H,
    signal: Option<oneshot::Sender<()>>,
    services: Shared<Services<S, C, B>, S::Reservation>,
    error: RootSlot<H::Error, S::Reservation>,
    // 分配前准入的外置 split／signal 在其计费根之前析构，包括未 poll 就取消。
    session: SessionOwner<S::Reservation>,
}

struct SessionOwner<R>(Rooted<Session, R>);
impl<R> SessionOwner<R> {
    fn get_mut(&mut self) -> &mut Session {
        self.0.get_mut()
    }
}
impl<R> Drop for SessionOwner<R> {
    fn drop(&mut self) {
        self.get_mut().scoped_receiver.take();
        self.get_mut().scoped_auth.take();
        self.get_mut().scoped_write.take();
        self.get_mut().scoped_control.take();
        channel::cleanup(self.get_mut());
    }
}

/// 显式 scoped task 的连接句柄；不持有或调用 Legacy Handle。
/// 仅用于实验性 scoped 入口，不代表连接总活图或秘密全链已经获证。
pub struct ScopedHandle<H, S, P, C, B>
where
    H: Handler,
    H::Error: Send + Sync + 'static,
    S: AdmissionScope,
    P: ScopedSpawner<S>,
{
    state: Rooted<HandleState<H, S, P, C, B>, S::Reservation>,
}

impl<H, S, P, C, B> Drop for ScopedHandle<H, S, P, C, B>
where
    H: Handler,
    H::Error: Send + Sync + 'static,
    S: AdmissionScope,
    P: ScopedSpawner<S>,
{
    fn drop(&mut self) {
        // 不把取消当作 backing 已释放；Task 的最后持有者仍持其原预约。
        self.state.get().task.cancel();
    }
}

fn poll_task<T, E, R>(
    task: &mut T,
    terminal: &mut Option<Outcome<E, R>>,
    primary: &mut Option<ScopedError<Shared<E, R>>>,
    cx: &mut Context<'_>,
) where
    T: Future<Output = Result<Outcome<E, R>, ScopedFault>> + Unpin,
{
    if terminal.is_none() {
        if let Poll::Ready(result) = Pin::new(task).poll(cx) {
            let outcome = match result {
                Ok(outcome) => outcome,
                Err(fault) => Err(ScopedError::Resource(fault)),
            };
            *terminal = Some(match primary.take() {
                Some(error) => Err(error),
                None => outcome,
            });
        }
    }
}

fn copy_error<E: Send + Sync + 'static, R: Send + Sync + 'static>(
    error: &ScopedError<Shared<E, R>>,
) -> ScopedError<Shared<E, R>> {
    match error {
        ScopedError::Resource(fault) => ScopedError::Resource(*fault),
        ScopedError::Operation(error) => match error.try_clone() {
            Ok(error) => ScopedError::Operation(error),
            Err(fault) => ScopedError::Resource(fault),
        },
    }
}

fn operation_error<E: Send + Sync + 'static, R: Send + Sync + 'static>(
    slot: RootSlot<E, R>,
    error: E,
) -> ScopedError<Shared<E, R>> {
    ScopedError::Operation(slot.initialize(|| error).into_shared())
}

enum Wait<T> {
    Ready(T),
    Terminal,
}

struct RsaRegistration<'a>(&'a AtomicWaker);

impl Drop for RsaRegistration<'_> {
    fn drop(&mut self) {
        self.0.take();
    }
}

impl<H, S, P, C, B> ScopedHandle<H, S, P, C, B>
where
    H: Handler + 'static,
    H::Error: Send + Sync + 'static,
    S: AdmissionScope + Send + Sync + 'static,
    P: ScopedSpawner<S> + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
    pub fn root(&self) -> &ResourceRoot<S::Reservation> {
        self.state.root()
    }

    pub fn is_closed(&self) -> bool {
        self.state.get().terminal.is_some() || self.state.get().commands.is_closed()
    }

    fn error_slot(&self) -> ErrorSlot<H::Error, S::Reservation> {
        if let Some(Err(error)) = self.state.get().terminal.as_ref() {
            return Err(copy_error(error));
        }
        if let Some(error) = self.state.get().primary_failure.as_ref() {
            return Err(copy_error(error));
        }
        if let Some(fault) = self.state.get().services.get().failure() {
            return Err(ScopedError::Resource(fault));
        }
        Rooted::try_allocate(
            &self.state.get().services.get().scope,
            ResourceClass::Control,
            "client.operation.error",
        )
        .map_err(ScopedError::Resource)
    }

    fn closed_error(
        &self,
        slot: RootSlot<H::Error, S::Reservation>,
    ) -> ScopedError<Shared<H::Error, S::Reservation>> {
        match self.state.get().terminal.as_ref() {
            Some(Err(error)) => copy_error(error),
            _ => operation_error(slot, Error::Disconnect.into()),
        }
    }

    fn send_control(&self, command: Command) -> ClientResult<(), H::Error, S::Reservation> {
        if let Some(Err(error)) = &self.state.get().terminal {
            return Err(copy_error(error));
        }
        let services = self.state.get().services.get();
        if let Some(fault) = services.failure() {
            return Err(ScopedError::Resource(fault));
        }
        self.state
            .get()
            .commands
            .try_send(&services.scope, "client.command.node", command)
            .map_err(|fault| {
                services.fail(fault);
                ScopedError::Resource(fault)
            })
    }

    pub async fn authenticate_none(
        &mut self,
        user: &str,
    ) -> ClientResult<ScopedAuthResult, H::Error, S::Reservation> {
        self.authenticate(auth::InitialKind::None, user, "").await
    }

    pub async fn authenticate_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> ClientResult<ScopedAuthResult, H::Error, S::Reservation> {
        self.authenticate(auth::InitialKind::Password, user, password)
            .await
    }

    fn next_auth(&mut self) -> Result<u64, ScopedFault> {
        let state = self.state.get_mut();
        state.auth_sequence = state.auth_sequence.checked_add(1).ok_or(ScopedFault {
            kind: FaultKind::CountBudget,
            site: "client.auth.attempt",
            requested: 1,
            available: Some(0),
        })?;
        Ok(state.auth_sequence)
    }

    async fn authenticate(
        &mut self,
        kind: auth::InitialKind,
        user: &str,
        secret: &str,
    ) -> ClientResult<ScopedAuthResult, H::Error, S::Reservation> {
        let error = self.error_slot()?;
        if self.state.get().keyboard_attempt.is_some() {
            return Err(operation_error(error, Error::Inconsistent.into()));
        }
        let id = self.next_auth().map_err(ScopedError::Resource)?;
        let request = auth::request(
            &self.state.get().services.get().scope,
            id,
            kind,
            user,
            secret,
        )
        .map_err(ScopedError::Resource)?;
        match self.auth_exchange(request, error).await? {
            auth::Reply::Result { result, .. } => Ok(result),
            auth::Reply::Info { .. } | auth::Reply::Sign { .. } => {
                let error = self.error_slot()?;
                Err(operation_error(error, Error::Inconsistent.into()))
            }
        }
    }

    fn runtime_error(
        &self,
        error: RunError<Error, ScopedFault>,
    ) -> ScopedError<Shared<H::Error, S::Reservation>> {
        match error {
            RunError::Runtime(fault) => ScopedError::Resource(fault),
            RunError::Operation(error) => match self.error_slot() {
                Ok(slot) => operation_error(slot, error.into()),
                Err(error) => error,
            },
            RunError::Disconnected => match self.error_slot() {
                Ok(slot) => operation_error(slot, Error::Disconnect.into()),
                Err(error) => error,
            },
        }
    }

    fn sign_failure(
        &mut self,
        error: ScopedError<Shared<H::Error, S::Reservation>>,
    ) -> ScopedError<Shared<H::Error, S::Reservation>> {
        let returned = copy_error(&error);
        let cause = match &error {
            ScopedError::Resource(fault) => *fault,
            ScopedError::Operation(_) => ScopedFault {
                kind: FaultKind::Cancelled,
                site: "client.auth.sign.failed",
                requested: 0,
                available: None,
            },
        };
        let state = self.state.get_mut();
        state.primary_failure = Some(error);
        state.services.get().fail(cause);
        returned
    }

    /// key_blob 是调用者原操作根持有的 SSH 公钥编码，借用期间不复制成普通 Vec。
    pub async fn authenticate_publickey_with<K: ScopedSigner<S, Error = H::Error>>(
        &mut self,
        user: &str,
        key_blob: &[u8],
        hash_alg: Option<HashAlg>,
        signer: &mut K,
    ) -> ClientResult<ScopedAuthResult, H::Error, S::Reservation> {
        self.authenticate_signed(user, key_blob, hash_alg, false, signer)
            .await
    }

    /// certificate_blob 是已加载证书的 SSH 编码；签名服务仍持有原私钥／agent。
    pub async fn authenticate_certificate_with<K: ScopedSigner<S, Error = H::Error>>(
        &mut self,
        user: &str,
        certificate_blob: &[u8],
        hash_alg: Option<HashAlg>,
        signer: &mut K,
    ) -> ClientResult<ScopedAuthResult, H::Error, S::Reservation> {
        self.authenticate_signed(user, certificate_blob, hash_alg, true, signer)
            .await
    }

    async fn authenticate_signed<K: ScopedSigner<S, Error = H::Error>>(
        &mut self,
        user: &str,
        key_blob: &[u8],
        hash_alg: Option<HashAlg>,
        certificate: bool,
        signer: &mut K,
    ) -> ClientResult<ScopedAuthResult, H::Error, S::Reservation> {
        let error = self.error_slot()?;
        if self.state.get().keyboard_attempt.is_some() {
            return Err(operation_error(error, Error::Inconsistent.into()));
        }
        let algorithm = match sign::algorithm(key_blob, hash_alg, certificate) {
            Ok(algorithm) => algorithm,
            Err(fault) => return Err(operation_error(error, fault.into())),
        };
        let id = self.next_auth().map_err(ScopedError::Resource)?;
        let probe = sign::probe(
            &self.state.get().services.get().scope,
            id,
            user,
            algorithm,
            key_blob,
        )
        .map_err(ScopedError::Resource)?;
        let (bytes, request_offset) = match self.auth_exchange(probe, error).await? {
            auth::Reply::Result { result, .. } => return Ok(result),
            auth::Reply::Sign {
                bytes,
                request_offset,
                ..
            } => (bytes, request_offset),
            _ => return Err(self.runtime_error(Error::Inconsistent.into())),
        };
        let request = ScopedSignRequest::from_reply(bytes, request_offset)
            .map_err(|fault| self.sign_failure(ScopedError::Resource(fault)))?;
        let mut guard = AuthWait {
            services: self
                .state
                .get()
                .services
                .try_clone()
                .map_err(ScopedError::Resource)?,
            armed: true,
        };
        let signature = {
            let operation = signer.sign(&guard.services.get().scope, &request, hash_alg);
            let mut operation = std::pin::pin!(operation);
            let state = self.state.get_mut();
            std::future::poll_fn(|cx| {
                poll_task(
                    &mut state.task,
                    &mut state.terminal,
                    &mut state.primary_failure,
                    cx,
                );
                if state.terminal.is_some() {
                    return Poll::Ready(Wait::Terminal);
                }
                operation.as_mut().poll(cx).map(Wait::Ready)
            })
            .await
        };
        let signature = match signature {
            Wait::Ready(Ok(signature)) => signature,
            Wait::Ready(Err(error)) => {
                guard.armed = false;
                return Err(self.sign_failure(error));
            }
            Wait::Terminal => return Err(self.runtime_error(Error::Disconnect.into())),
        };
        let signed = request
            .signed(&guard.services.get().scope, id, signature)
            .map_err(|error| {
                let error = self.runtime_error(error);
                self.sign_failure(error)
            })?;
        let error = self
            .error_slot()
            .map_err(|error| self.sign_failure(error))?;
        let result = self.auth_exchange(signed, error).await;
        guard.armed = false;
        let reply = result.map_err(|error| self.sign_failure(error))?;
        match reply {
            auth::Reply::Result { result, .. } => Ok(result),
            _ => Err(self.runtime_error(Error::Inconsistent.into())),
        }
    }

    async fn auth_exchange(
        &mut self,
        request: auth::Request,
        error: RootSlot<H::Error, S::Reservation>,
    ) -> ClientResult<auth::Reply, H::Error, S::Reservation> {
        let id = request.id;
        let mut guard = AuthWait {
            services: self
                .state
                .get()
                .services
                .try_clone()
                .map_err(ScopedError::Resource)?,
            armed: false,
        };
        self.state
            .get()
            .commands
            .try_send(
                &guard.services.get().scope,
                "client.command.node",
                Command::Authenticate(request),
            )
            .map_err(ScopedError::Resource)?;
        guard.armed = true;
        loop {
            let result = {
                let state = self.state.get_mut();
                std::future::poll_fn(|cx| {
                    poll_task(
                        &mut state.task,
                        &mut state.terminal,
                        &mut state.primary_failure,
                        cx,
                    );
                    if state.terminal.is_some() {
                        return Poll::Ready(Wait::Terminal);
                    }
                    state.auth_replies.poll_recv(cx).map(Wait::Ready)
                })
                .await
            };
            match result {
                Wait::Ready(Some(reply)) if reply.id() == id => {
                    guard.armed = false;
                    return Ok(reply);
                }
                Wait::Ready(Some(_)) => (),
                _ => return Err(self.closed_error(error)),
            }
        }
    }

    pub async fn authenticate_keyboard_interactive_start(
        &mut self,
        user: &str,
        submethods: Option<&str>,
    ) -> ClientResult<ScopedKeyboardInteractiveResponse<S::Reservation>, H::Error, S::Reservation>
    {
        let error = self.error_slot()?;
        if self.state.get().keyboard_attempt.is_some() {
            return Err(operation_error(error, Error::Inconsistent.into()));
        }
        let id = self.next_auth().map_err(ScopedError::Resource)?;
        let request = auth::request(
            &self.state.get().services.get().scope,
            id,
            auth::InitialKind::Keyboard,
            user,
            submethods.unwrap_or(""),
        )
        .map_err(ScopedError::Resource)?;
        let reply = self
            .auth_exchange(request, error)
            .await?
            .keyboard()
            .map_err(|error| self.runtime_error(error))?;
        self.state.get_mut().keyboard_attempt =
            if matches!(reply, ScopedKeyboardInteractiveResponse::InfoRequest(_)) {
                Some(id)
            } else {
                None
            };
        Ok(reply)
    }

    pub async fn authenticate_keyboard_interactive_respond(
        &mut self,
        responses: &[&str],
    ) -> ClientResult<ScopedKeyboardInteractiveResponse<S::Reservation>, H::Error, S::Reservation>
    {
        let error = self.error_slot()?;
        let Some(id) = self.state.get().keyboard_attempt else {
            return Err(operation_error(error, Error::Inconsistent.into()));
        };
        let request = auth::responses(&self.state.get().services.get().scope, id, responses)
            .map_err(ScopedError::Resource)?;
        let reply = self
            .auth_exchange(request, error)
            .await?
            .keyboard()
            .map_err(|error| self.runtime_error(error))?;
        if !matches!(reply, ScopedKeyboardInteractiveResponse::InfoRequest(_)) {
            self.state.get_mut().keyboard_attempt = None;
        }
        Ok(reply)
    }

    pub async fn best_supported_rsa_hash(
        &mut self,
    ) -> ClientResult<Option<Option<HashAlg>>, H::Error, S::Reservation> {
        let error = self.error_slot()?;
        if self.state.get().services.get().rsa.load(Ordering::Acquire) == 0 {
            let services = self
                .state
                .get()
                .services
                .try_clone()
                .map_err(ScopedError::Resource)?;
            let _registration = RsaRegistration(&services.get().rsa_waiter);
            let sleep = self
                .state
                .get()
                .services
                .sleep(Duration::from_secs(1))
                .map_err(ScopedError::Resource)?;
            let mut sleep = std::pin::pin!(sleep);
            let result = {
                let state = self.state.get_mut();
                std::future::poll_fn(|cx| {
                    poll_task(
                        &mut state.task,
                        &mut state.terminal,
                        &mut state.primary_failure,
                        cx,
                    );
                    if state.terminal.is_some() {
                        return Poll::Ready(Wait::Terminal);
                    }
                    state.services.get().rsa_waiter.register(cx.waker());
                    if state.services.get().rsa.load(Ordering::Acquire) != 0 {
                        return Poll::Ready(Wait::Ready(Ok(())));
                    }
                    sleep.as_mut().poll(cx).map(Wait::Ready)
                })
                .await
            };
            match result {
                Wait::Ready(result) => result.map_err(ScopedError::Resource)?,
                Wait::Terminal => return Err(self.closed_error(error)),
            }
        }
        let bits = self.state.get().services.get().rsa.load(Ordering::Acquire);
        Ok(if bits & 8 != 0 {
            Some(Some(HashAlg::Sha512))
        } else if bits & 4 != 0 {
            Some(Some(HashAlg::Sha256))
        } else if bits & 2 != 0 {
            Some(None)
        } else {
            None
        })
    }

    pub async fn channel_open_session(
        &mut self,
    ) -> ClientResult<ScopedChannel<S, C, B>, H::Error, S::Reservation> {
        let error = self.error_slot()?;
        let services = self
            .state
            .get()
            .services
            .try_clone()
            .map_err(ScopedError::Resource)?;
        let window = services.get().window_size;
        let maximum = services.get().maximum_packet_size;
        let commands = self
            .state
            .get()
            .commands
            .try_clone()
            .map_err(ScopedError::Resource)?;
        let (mut channel, node) = ScopedChannel::new(services, commands, window, maximum)
            .map_err(ScopedError::Resource)?;
        let mut guard = AuthWait {
            services: self
                .state
                .get()
                .services
                .try_clone()
                .map_err(ScopedError::Resource)?,
            armed: false,
        };
        self.state
            .get()
            .commands
            .try_send(
                &guard.services.get().scope,
                "client.command.node",
                Command::Open(node),
            )
            .map_err(ScopedError::Resource)?;
        guard.armed = true;
        let result = {
            let state = self.state.get_mut();
            std::future::poll_fn(|cx| {
                poll_task(
                    &mut state.task,
                    &mut state.terminal,
                    &mut state.primary_failure,
                    cx,
                );
                if state.terminal.is_some() {
                    return Poll::Ready(Wait::Terminal);
                }
                channel.poll_open(cx).map(Wait::Ready)
            })
            .await
        };
        match result {
            Wait::Ready(Some(channel::Event::Open { id, remote })) => {
                guard.armed = false;
                channel.opened(id, remote);
                Ok(channel)
            }
            Wait::Ready(Some(channel::Event::OpenFailure(code))) => {
                guard.armed = false;
                let reason = match code {
                    1 => crate::ChannelOpenFailure::AdministrativelyProhibited,
                    2 => crate::ChannelOpenFailure::ConnectFailed,
                    3 => crate::ChannelOpenFailure::UnknownChannelType,
                    4 => crate::ChannelOpenFailure::ResourceShortage,
                    code => crate::ChannelOpenFailure::Other {
                        code,
                        reason: String::new(),
                    },
                };
                Err(operation_error(
                    error,
                    Error::ChannelOpenFailure(reason).into(),
                ))
            }
            _ => Err(self.closed_error(error)),
        }
    }

    pub async fn send_keepalive(
        &mut self,
        want_reply: bool,
    ) -> ClientResult<(), H::Error, S::Reservation> {
        self.send_control(Command::Keepalive { want_reply })
    }

    pub async fn rekey_soon(&mut self) -> ClientResult<(), H::Error, S::Reservation> {
        self.send_control(Command::Rekey)
    }

    /// 请求本地关闭；使用已预留 backing 尝试发送 disconnect，不等待阻塞的写端。
    /// 不再准入新资源。对端是否收到通知不影响本地 task 的资源清理。
    pub async fn disconnect(
        &mut self,
        reason: Disconnect,
    ) -> ClientResult<(), H::Error, S::Reservation> {
        let services = self.state.get().services.get();
        let _ = services.closing.compare_exchange(
            0,
            reason as u32,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        services.control.wake();
        Ok(())
    }

    pub async fn shutdown(mut self) -> ClientResult<(), H::Error, S::Reservation> {
        self.disconnect(Disconnect::ByApplication).await?;
        self.await
    }
}

impl<H, S, P, C, B> Future for ScopedHandle<H, S, P, C, B>
where
    H: Handler + 'static,
    H::Error: Send + Sync + 'static,
    S: AdmissionScope + Send + Sync + 'static,
    P: ScopedSpawner<S> + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
    type Output = ClientResult<(), H::Error, S::Reservation>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = self.get_mut().state.get_mut();
        poll_task(
            &mut state.task,
            &mut state.terminal,
            &mut state.primary_failure,
            cx,
        );
        match state.terminal.as_ref() {
            Some(Ok(())) => Poll::Ready(Ok(())),
            Some(Err(error)) => Poll::Ready(Err(copy_error(error))),
            None => Poll::Pending,
        }
    }
}

/// 由调用者的 stream、spawn、clock 与 cooperative 服务执行 SSH 连接。
/// 输入对象已有的外置资源须由调用者原 scope 持有；本入口不安装 ambient runtime。
///
/// # 实验性入口
///
/// 只有显式调用此函数并提供 scoped 服务时才进入候选路径；旧 constructors、
/// `connect` 和 `connect_stream` 不调用它。当前 KEX、派生分配、压缩与 SDK 图
/// 尚未完整闭合，因此不能用此入口承诺连接总活图上限或秘密 backing 全链保护。
/// 应用正常网络接入须等待完整闭包与宿主验收；本入口不是已获证的替代路径。
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub async fn connect_stream_scoped<H, T, S, P, C, B>(
    config: Arc<Config>,
    mut stream: T,
    handler: H,
    scope: S,
    spawner: P,
    clock: C,
    cooperative: B,
) -> ClientResult<ScopedHandle<H, S, P, C, B>, H::Error, S::Reservation>
where
    H: ScopedHandler<S, C, B> + Send + 'static,
    H::Error: Send + Sync + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AdmissionScope + Send + Sync + 'static,
    P: ScopedSpawner<S> + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
    let services = Rooted::<Services<S, C, B>, _>::try_allocate(
        &scope,
        ResourceClass::Control,
        "client.services",
    )
    .map_err(ScopedError::Resource)?;
    let (commands, command_receiver) =
        queue::channel(&scope, "client.command.queue").map_err(ScopedError::Resource)?;
    let service_commands = commands.try_clone().map_err(ScopedError::Resource)?;
    let services = services
        .initialize(|| Services {
            scope,
            commands: service_commands,
            clock,
            cooperative,
            rsa: AtomicU8::new(0),
            rsa_waiter: AtomicWaker::new(),
            closing: AtomicU32::new(0),
            cause: std::sync::Mutex::new(None),
            control: AtomicWaker::new(),
            channel_cleanup: AtomicBool::new(false),
            window_size: config.window_size,
            maximum_packet_size: config.maximum_packet_size,
        })
        .into_shared();
    let scope = &services.get().scope;
    let connection_error =
        Rooted::<H::Error, _>::try_allocate(scope, ResourceClass::Control, "client.connect.error")
            .map_err(ScopedError::Resource)?;
    let task_error =
        Rooted::<H::Error, _>::try_allocate(scope, ResourceClass::Control, "client.task.error")
            .map_err(ScopedError::Resource)?;
    let handle_slot = Rooted::<HandleState<H, S, P, C, B>, _>::try_allocate(
        scope,
        ResourceClass::Control,
        "client.handle",
    )
    .map_err(ScopedError::Resource)?;
    let source = source::initial::<T>().map_err(ScopedError::Resource)?;
    let session_slot = Rooted::<Session, _>::try_allocate_with_source(
        scope,
        ResourceClass::Runtime,
        "client.session",
        source,
    )
    .map_err(ScopedError::Resource)?;

    let control = control::State::new(scope).map_err(ScopedError::Resource)?;
    let identification = match &config.client_id {
        SshId::Standard(id) => match stream.write_all(id.as_bytes()).await {
            Ok(()) => stream.write_all(b"\r\n").await,
            Err(error) => Err(error),
        },
        SshId::Raw(id) => stream.write_all(id.as_bytes()).await,
    };
    if let Err(error) = identification {
        return Err(operation_error(connection_error, Error::from(error).into()));
    }
    let mut stream = SshRead::new(stream);
    let peer_id = match stream.read_ssh_id().await {
        Ok(id) => id,
        Err(error) => return Err(operation_error(connection_error, error.into())),
    };
    let (auth_sender, auth_replies) =
        queue::channel(scope, "client.auth.reply.queue").map_err(ScopedError::Resource)?;
    let session = session_slot.initialize(|| {
        let mut session = Session::new(
            config.window_size,
            CommonSession {
                packet_writer: PacketWriter::clear(),
                auth_user: String::new(),
                auth_attempts: 0,
                auth_method: None,
                remote_to_local: Box::new(crate::cipher::clear::Key),
                encrypted: None,
                config,
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
                remote_sshid: peer_id.to_vec(),
            },
            super::LegacyReceiver::default(),
            ReplySender::Scoped,
        );
        session.scoped_receiver = Some(command_receiver);
        session.scoped_control = Some(control);
        session.scoped_auth = Some(auth::State {
            id: 0,
            kind: auth::Kind::None,
            pending: None,
            sent: false,
            service_sent: false,
            service_accepted: false,
            probe: None,
            probe_pending: false,
            replies: auth_sender,
        });
        session
    });
    let session_root = session.root().try_clone().map_err(ScopedError::Resource)?;
    let task_services = services.try_clone().map_err(ScopedError::Resource)?;
    let (signal, established) = oneshot::channel();
    let mut established = (
        established,
        session_root.try_clone().map_err(ScopedError::Resource)?,
    );
    let (read, write) = stream.split();
    let captures = Captures {
        read,
        write,
        handler,
        signal: Some(signal),
        services: task_services,
        error: task_error,
        session: SessionOwner(session),
    };
    let task = spawner
        .try_spawn(scope, async move {
            let mut captures = captures;
            if let Err(error) = captures.session.get_mut().begin_rekey() {
                return Err(operation_error(captures.error, error.into()));
            }
            let result = captures
                .session
                .get_mut()
                .run_inner_with(
                    captures.read,
                    &mut captures.write,
                    &mut captures.handler,
                    &mut captures.signal,
                    &captures.services,
                )
                .await;
            captures.session.get_mut().receiver.close();
            captures.session.get_mut().inbound_channel_receiver.close();
            if let Some(receiver) = captures.session.get_mut().scoped_receiver.as_mut() {
                receiver.close();
            }
            match result {
                Err(RunError::Runtime(fault)) => {
                    captures.services.get().fail(fault);
                    Err(ScopedError::Resource(fault))
                }
                Err(RunError::Operation(error)) => {
                    let error = captures.error.initialize(|| error).into_shared();
                    if captures.signal.is_none() {
                        // 回调或取消产生的次级结果不覆盖已拥有的主操作错误。
                        let _ = notify_disconnected(
                            &captures.services,
                            &mut captures.handler,
                            ScopedDisconnectReason::Error(&error),
                        )
                        .await;
                    }
                    Err(ScopedError::Operation(error))
                }
                Err(RunError::Disconnected)
                    if captures.services.get().closing.load(Ordering::Acquire) == 0 =>
                {
                    Err(operation_error(captures.error, Error::Disconnect.into()))
                }
                normal => {
                    if let Ok(info) = normal {
                        if let Err(error) = notify_disconnected(
                            &captures.services,
                            &mut captures.handler,
                            ScopedDisconnectReason::ReceivedDisconnect(&info),
                        )
                        .await
                        {
                            return Err(match error {
                                ScopedError::Resource(fault) => {
                                    captures.services.get().fail(fault);
                                    ScopedError::Resource(fault)
                                }
                                ScopedError::Operation(error) => {
                                    operation_error(captures.error, error)
                                }
                            });
                        }
                    }
                    let shutdown = std::future::poll_fn(|cx| {
                        match Pin::new(&mut captures.write).poll_shutdown(cx) {
                            Poll::Pending => Poll::Ready(Ok(())),
                            Poll::Ready(result) => Poll::Ready(result),
                        }
                    })
                    .await;
                    match shutdown {
                        Ok(()) => Ok(()),
                        Err(error) => {
                            Err(operation_error(captures.error, Error::from(error).into()))
                        }
                    }
                }
            }
        })
        .map_err(ScopedError::Resource)?;
    let state = handle_slot.initialize(|| HandleState {
        commands,
        auth_replies,
        auth_sequence: 0,
        keyboard_attempt: None,
        task,
        terminal: None,
        primary_failure: None,
        _session: session_root,
        services,
    });
    let mut handle = ScopedHandle { state };
    let established = std::future::poll_fn(|cx| {
        let state = handle.state.get_mut();
        poll_task(
            &mut state.task,
            &mut state.terminal,
            &mut state.primary_failure,
            cx,
        );
        if state.terminal.is_some() {
            return Poll::Ready(false);
        }
        match Pin::new(&mut established.0).poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(true),
            Poll::Ready(Err(_)) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    })
    .await;
    if established {
        Ok(handle)
    } else {
        Err(handle.closed_error(connection_error))
    }
}
