use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::cipher::OpeningKey;
use crate::scoped::{Cooperative, ScopedClock, ScopedFault};
use crate::sshbuffer::{IncomingSshPacket, SSHBuffer};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) enum Event<R, F> {
    Read(R),
    Keepalive(Result<(), F>),
    Inactivity(Result<(), F>),
    Outbound(Option<super::Msg>),
    Inbound(Option<super::Msg>),
    Scoped(Option<super::scoped::Command>),
    Control,
    Write(std::io::Result<()>),
}

pub(super) enum RunError<E, F> {
    Disconnected,
    Operation(E),
    Runtime(F),
}

pub(super) type ReadResult<R, F> =
    Result<(usize, R, SSHBuffer, Box<dyn OpeningKey + Send>), RunError<crate::Error, F>>;

impl<E, F> RunError<E, F> {
    pub(super) fn map_operation<T>(self, map: impl FnOnce(E) -> T) -> RunError<T, F> {
        match self {
            Self::Disconnected => RunError::Disconnected,
            Self::Operation(error) => RunError::Operation(map(error)),
            Self::Runtime(fault) => RunError::Runtime(fault),
        }
    }
}

pub(super) enum PacketOwner {
    Legacy(IncomingSshPacket),
    Scoped(crate::scoped::ErasedRooted<IncomingSshPacket>),
}

impl PacketOwner {
    pub(super) fn get_mut(&mut self) -> &mut IncomingSshPacket {
        match self {
            Self::Legacy(packet) => packet,
            Self::Scoped(packet) => packet.get_mut(),
        }
    }
}

impl<E: From<crate::Error>, F> From<crate::Error> for RunError<E, F> {
    fn from(error: crate::Error) -> Self {
        Self::Operation(error.into())
    }
}

pub(super) trait Runtime: Sync {
    fn register_poll(&self, _: &Context<'_>) {}
    type Fault: Send;
    type Sleep: Future<Output = Result<(), Self::Fault>> + Send;

    fn sleep(&self, duration: Duration) -> Result<Self::Sleep, Self::Fault>;
    fn reset(&self, sleep: Pin<&mut Self::Sleep>, duration: Duration) -> Result<(), Self::Fault>;
    fn begin_poll(&self);
    fn poll_budget(&self, cx: &mut Context<'_>, units: usize) -> Poll<()>;
    fn observe_server_sig_algs(&self, _: Option<&[ssh_key::Algorithm]>) {}
    fn check(&self) -> Result<(), Self::Fault> {
        Ok(())
    }

    fn poll_control(&self, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }

    fn is_closing(&self) -> bool {
        false
    }

    fn scoped_io(&self) -> bool {
        false
    }

    fn keepalive(
        &self,
        session: &mut super::Session,
        want_reply: bool,
    ) -> Result<(), RunError<crate::Error, Self::Fault>> {
        session
            .send_keepalive(want_reply)
            .map_err(RunError::Operation)
    }

    fn control<W: AsyncWrite + Unpin + Send>(
        &self,
        _: &mut super::Session,
        _: &mut W,
    ) -> impl Future<Output = Result<bool, RunError<crate::Error, Self::Fault>>> + Send {
        async { Ok(false) }
    }

    fn command(
        &self,
        _: &mut super::Session,
        _: super::scoped::Command,
    ) -> Result<(), RunError<crate::Error, Self::Fault>> {
        Err(RunError::Operation(crate::Error::Inconsistent))
    }

    fn read<R: AsyncRead + Unpin + Send>(
        &self,
        stream: R,
        buffer: SSHBuffer,
        cipher: Box<dyn OpeningKey + Send>,
    ) -> impl Future<Output = ReadResult<R, Self::Fault>> + Send {
        async {
            super::start_reading(stream, buffer, cipher)
                .await
                .map_err(RunError::Operation)
        }
    }

    fn packet(
        &self,
        session: &mut super::Session,
        buffer: &SSHBuffer,
    ) -> Result<PacketOwner, RunError<crate::Error, Self::Fault>> {
        session
            .maybe_decompress(buffer)
            .map(PacketOwner::Legacy)
            .map_err(RunError::Operation)
    }

    fn flush<W: AsyncWrite + Unpin + Send>(
        &self,
        _: &mut super::Session,
        _: &mut W,
    ) -> impl Future<Output = Result<(), RunError<crate::Error, Self::Fault>>> + Send {
        async { Ok(()) }
    }
}

pub(super) struct Legacy;

pub(super) trait PacketHandler<H: super::Handler>: Runtime {
    fn process(
        &self,
        _: &mut super::Session,
        _: &mut H,
        _: &[u8],
    ) -> impl Future<Output = Result<bool, RunError<H::Error, Self::Fault>>> + Send {
        async { Ok(false) }
    }
}

impl<H: super::Handler> PacketHandler<H> for Legacy {}
impl<H: super::Handler, C: ScopedClock + Sync, B: Cooperative + Sync> PacketHandler<H> for (C, B) {}

pub(super) struct LegacySleep(tokio::time::Sleep);

impl Future for LegacySleep {
    type Output = Result<(), Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // 包装不移动内部 Sleep，且没有独立的析构或投影出口。
        unsafe { self.map_unchecked_mut(|sleep| &mut sleep.0) }
            .poll(cx)
            .map(Ok)
    }
}

impl Runtime for Legacy {
    type Fault = Infallible;
    type Sleep = LegacySleep;

    fn sleep(&self, duration: Duration) -> Result<Self::Sleep, Infallible> {
        Ok(LegacySleep(tokio::time::sleep(duration)))
    }

    fn reset(&self, sleep: Pin<&mut Self::Sleep>, duration: Duration) -> Result<(), Infallible> {
        unsafe { sleep.map_unchecked_mut(|sleep| &mut sleep.0) }
            .reset(tokio::time::Instant::now() + duration);
        Ok(())
    }

    fn begin_poll(&self) {}

    fn poll_budget(&self, cx: &mut Context<'_>, _: usize) -> Poll<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let budget = std::pin::pin!(tokio::task::consume_budget());
            budget.poll(cx)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = cx;
            Poll::Ready(())
        }
    }
}

impl<C: ScopedClock + Sync, B: Cooperative + Sync> Runtime for (C, B) {
    type Fault = ScopedFault;
    type Sleep = C::Sleep;

    fn sleep(&self, duration: Duration) -> Result<Self::Sleep, ScopedFault> {
        let deadline = self
            .0
            .now()
            .checked_add(duration)
            .ok_or_else(|| ScopedFault::overflow("client.clock.deadline"))?;
        self.0.sleep_until(deadline)
    }

    fn reset(&self, sleep: Pin<&mut Self::Sleep>, duration: Duration) -> Result<(), ScopedFault> {
        let deadline = self
            .0
            .now()
            .checked_add(duration)
            .ok_or_else(|| ScopedFault::overflow("client.clock.deadline"))?;
        self.0.reset(sleep, deadline)
    }

    fn begin_poll(&self) {
        self.1.begin_poll();
    }

    fn poll_budget(&self, cx: &mut Context<'_>, units: usize) -> Poll<()> {
        self.1.poll_budget(cx, units)
    }
}

pub(super) struct Timer<F> {
    sleep: Option<F>,
}

impl<F> Timer<F> {
    pub fn new<R: Runtime<Sleep = F>>(
        runtime: &R,
        duration: Option<Duration>,
    ) -> Result<Self, R::Fault> {
        Ok(Self {
            sleep: duration
                .map(|duration| runtime.sleep(duration))
                .transpose()?,
        })
    }

    pub fn reset<R: Runtime<Sleep = F>>(
        self: Pin<&mut Self>,
        runtime: &R,
        duration: Option<Duration>,
    ) -> Result<(), R::Fault> {
        // Option 的存在性不变，reset 只投影到已固定的 Sleep。
        let sleep = unsafe { self.map_unchecked_mut(|timer| &mut timer.sleep) };
        if let (Some(sleep), Some(duration)) = (sleep.as_pin_mut(), duration) {
            runtime.reset(sleep, duration)?;
        }
        Ok(())
    }
}

impl<F: Future> Future for Timer<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let sleep = unsafe { self.map_unchecked_mut(|timer| &mut timer.sleep) };
        match sleep.as_pin_mut() {
            Some(sleep) => sleep.poll(cx),
            None => Poll::Pending,
        }
    }
}

pub(super) async fn timeout<R: Runtime, F: Future>(
    runtime: &R,
    duration: Duration,
    future: F,
) -> Result<Option<F::Output>, R::Fault> {
    let sleep = runtime.sleep(duration)?;
    let sleep = std::pin::pin!(sleep);
    let future = std::pin::pin!(future);
    match futures::future::select(future, sleep).await {
        futures::future::Either::Left((output, _)) => Ok(Some(output)),
        futures::future::Either::Right((result, _)) => {
            result?;
            Ok(None)
        }
    }
}
