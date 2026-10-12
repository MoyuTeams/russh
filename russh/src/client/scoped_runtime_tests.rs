// 断言与故障注入仅属于测试夹具。
#![allow(clippy::unwrap_used)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::runtime::{RunError, timeout};
use super::{Config, Handler, Session};
use crate::scoped::{AdmissionScope, Cooperative, FaultKind, ResourceClass, ResourceRequest};
use crate::scoped::{Rooted, ScopedClock, ScopedFault};
use crate::session::CommonSession;
use crate::ssh_read::SshRead;
use crate::sshbuffer::PacketWriter;

#[derive(Default)]
struct Counts {
    held: AtomicUsize,
    dropped: AtomicUsize,
    resets: AtomicUsize,
    polls: AtomicUsize,
    yields: AtomicUsize,
    remaining: AtomicUsize,
}

struct Grant {
    counts: Arc<Counts>,
    bytes: usize,
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.counts.held.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

struct Clock {
    counts: Arc<Counts>,
    fail_create: bool,
    fail_reset: bool,
}

impl AdmissionScope for Clock {
    type Reservation = Grant;

    fn try_reserve(&self, request: ResourceRequest) -> Result<Grant, ScopedFault> {
        let bytes = request.bytes()?;
        if self.fail_create {
            return Err(ScopedFault {
                kind: FaultKind::ByteBudget,
                site: request.site,
                requested: bytes,
                available: Some(0),
            });
        }
        self.counts.held.fetch_add(bytes, Ordering::SeqCst);
        Ok(Grant {
            counts: self.counts.clone(),
            bytes,
        })
    }
}

struct SleepState(Arc<Counts>);

impl Drop for SleepState {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

struct Sleep(Rooted<SleepState, Grant>);

impl Future for Sleep {
    type Output = Result<(), ScopedFault>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let _ = self.0.get();
        Poll::Ready(Ok(()))
    }
}

impl ScopedClock for Clock {
    type Sleep = Sleep;

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, _: Instant) -> Result<Self::Sleep, ScopedFault> {
        Rooted::try_new(self, ResourceClass::Control, "test.timer", || {
            SleepState(self.counts.clone())
        })
        .map(Sleep)
    }

    fn reset(&self, _: Pin<&mut Self::Sleep>, _: Instant) -> Result<(), ScopedFault> {
        self.counts.resets.fetch_add(1, Ordering::SeqCst);
        if self.fail_reset {
            return Err(ScopedFault {
                kind: FaultKind::InflightBudget,
                site: "test.timer.reset",
                requested: 1,
                available: Some(0),
            });
        }
        Ok(())
    }
}

struct Budget(Arc<Counts>);

impl Cooperative for Budget {
    fn begin_poll(&self) {
        self.0.polls.fetch_add(1, Ordering::SeqCst);
        self.0.remaining.store(2, Ordering::SeqCst);
    }

    fn poll_budget(&self, cx: &mut Context<'_>, units: usize) -> Poll<()> {
        let available = self.0.remaining.load(Ordering::SeqCst);
        if units <= available {
            self.0.remaining.store(available - units, Ordering::SeqCst);
            Poll::Ready(())
        } else {
            self.0.yields.fetch_add(1, Ordering::SeqCst);
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct Stream;

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Client;

impl Handler for Client {
    type Error = crate::Error;
}

fn session(inactivity: bool) -> (Session, tokio::sync::mpsc::Sender<super::Msg>) {
    let config = Arc::new(Config {
        keepalive_interval: Some(Duration::from_secs(1)),
        inactivity_timeout: inactivity.then_some(Duration::from_secs(2)),
        ..Config::default()
    });
    let (sender, receiver) = tokio::sync::mpsc::channel(10);
    let (replies, _) = tokio::sync::mpsc::unbounded_channel();
    let session = Session::new(
        config.window_size,
        CommonSession {
            auth_user: String::new(),
            remote_sshid: Vec::new(),
            config,
            encrypted: None,
            auth_method: None,
            auth_attempts: 0,
            packet_writer: PacketWriter::clear(),
            remote_to_local: Box::new(crate::cipher::clear::Key),
            wants_reply: false,
            disconnected: false,
            buffer: Vec::new(),
            strict_kex: false,
            alive_timeouts: 0,
            received_data: false,
        },
        receiver,
        replies,
    );
    (session, sender)
}

#[test]
fn scoped_clock_drives_session_timers_without_tokio_driver() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let counts = Arc::new(Counts::default());
    let runtime = (
        Clock {
            counts: counts.clone(),
            fail_create: false,
            fail_reset: false,
        },
        Budget(counts.clone()),
    );
    let (mut session, _sender) = session(true);
    let (read, mut write) = SshRead::new(Stream).split();
    let result = futures::executor::block_on(session.run_inner_with(
        read,
        &mut write,
        &mut Client,
        &mut None,
        &runtime,
    ));
    assert!(matches!(
        result,
        Err(RunError::Operation(crate::Error::InactivityTimeout))
    ));
    assert_eq!(counts.resets.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 2);
    assert_eq!(counts.held.load(Ordering::SeqCst), 0);
}

#[test]
fn scoped_timer_admission_remains_typed_in_session() {
    let counts = Arc::new(Counts::default());
    let runtime = (
        Clock {
            counts: counts.clone(),
            fail_create: true,
            fail_reset: false,
        },
        Budget(counts.clone()),
    );
    let (mut session, _sender) = session(false);
    let (read, mut write) = SshRead::new(Stream).split();
    let result = futures::executor::block_on(session.run_inner_with(
        read,
        &mut write,
        &mut Client,
        &mut None,
        &runtime,
    ));
    assert!(matches!(
        result,
        Err(RunError::Runtime(ScopedFault {
            kind: FaultKind::ByteBudget,
            ..
        }))
    ));
    assert_eq!(counts.held.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn scoped_timer_reset_failure_keeps_resource_error() {
    let counts = Arc::new(Counts::default());
    let runtime = (
        Clock {
            counts: counts.clone(),
            fail_create: false,
            fail_reset: true,
        },
        Budget(counts.clone()),
    );
    let (mut session, _sender) = session(true);
    let (read, mut write) = SshRead::new(Stream).split();
    let result = futures::executor::block_on(session.run_inner_with(
        read,
        &mut write,
        &mut Client,
        &mut None,
        &runtime,
    ));
    assert!(matches!(
        result,
        Err(RunError::Runtime(ScopedFault {
            kind: FaultKind::InflightBudget,
            ..
        }))
    ));
    assert_eq!(counts.held.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 2);
}

#[test]
fn ready_timer_yields_at_poll_budget_and_cancellation_releases_it() {
    let counts = Arc::new(Counts::default());
    let runtime = (
        Clock {
            counts: counts.clone(),
            fail_create: false,
            fail_reset: false,
        },
        Budget(counts.clone()),
    );
    let (mut session, _sender) = session(false);
    let (read, mut write) = SshRead::new(Stream).split();
    {
        let mut client = Client;
        let mut signal = None;
        let run = session.run_inner_with(read, &mut write, &mut client, &mut signal, &runtime);
        let mut run = std::pin::pin!(run);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(run.as_mut().poll(&mut cx).is_pending());
        assert_eq!(counts.polls.load(Ordering::SeqCst), 1);
        assert_eq!(counts.yields.load(Ordering::SeqCst), 1);
        assert!(counts.held.load(Ordering::SeqCst) > 0);
        assert!(run.as_mut().poll(&mut cx).is_pending());
        assert_eq!(counts.polls.load(Ordering::SeqCst), 2);
    }
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(counts.held.load(Ordering::SeqCst), 0);
}

#[test]
fn outbound_drain_consumes_the_explicit_poll_budget() {
    let counts = Arc::new(Counts::default());
    let runtime = (
        Clock {
            counts: counts.clone(),
            fail_create: false,
            fail_reset: false,
        },
        Budget(counts.clone()),
    );
    let (mut session, sender) = session(false);
    session.common.config = Arc::new(Config::default());
    for _ in 0..10 {
        sender
            .try_send(super::Msg::AuthInfoResponse {
                responses: Vec::new(),
            })
            .unwrap();
    }
    let (read, mut write) = SshRead::new(Stream).split();
    {
        let mut client = Client;
        let mut signal = None;
        let run = session.run_inner_with(read, &mut write, &mut client, &mut signal, &runtime);
        let mut run = std::pin::pin!(run);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(run.as_mut().poll(&mut cx).is_pending());
        assert_eq!(counts.yields.load(Ordering::SeqCst), 1);
    }
    assert_eq!(session.receiver.len(), 8);
}

#[test]
fn extension_wait_timeout_uses_rooted_clock() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let counts = Arc::new(Counts::default());
    let runtime = (
        Clock {
            counts: counts.clone(),
            fail_create: false,
            fail_reset: false,
        },
        Budget(counts.clone()),
    );
    let result = futures::executor::block_on(timeout(
        &runtime,
        Duration::from_secs(1),
        std::future::pending::<()>(),
    ));
    assert_eq!(result, Ok(None));
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(counts.held.load(Ordering::SeqCst), 0);
}
