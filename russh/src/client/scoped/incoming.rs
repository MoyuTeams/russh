use std::ops::Range;
use std::sync::Mutex;

use super::{Services, auth::Cursor, channel::ScopedChannel};
use crate::client::{Handler, Session, runtime::RunError};
use crate::scoped::{
    AdmissionScope, Cooperative, ResourceClass, ResourceRoot, Rooted, ScopedBuffer, ScopedClock,
    ScopedError, ScopedFault, Shared,
};
use crate::{Error, msg};

/// scoped 被动 channel 回调使用具体宿主类型，允许在 callback 返回后持有 channel。
/// 旧 Handler 回调签名不变；本 trait 只用于 connect_stream_scoped。
pub trait ScopedHandler<S, C, B>: Handler
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
    /// 收尾只借用原因；主操作错误仍由连接的 Shared 根拥有。
    /// 关闭或资源终结可取消尚未就绪的回调，旧 Handler::disconnected 不受影响。
    fn disconnected_scoped(
        &mut self,
        _reason: ScopedDisconnectReason<'_, Self::Error, S::Reservation>,
    ) -> impl std::future::Future<Output = Result<(), ScopedError<Self::Error>>> + Send
    where
        Self::Error: Sync,
    {
        async { Ok(()) }
    }

    fn server_channel_open_scoped(
        &mut self,
        request: ScopedChannelOpen<S, C, B>,
    ) -> impl std::future::Future<Output = Result<(), ScopedError<Self::Error>>> + Send {
        async move {
            if request.info().kind() == ScopedChannelType::Unknown {
                request.reject(3);
            } else {
                drop(request.accept().map_err(ScopedError::Resource)?);
            }
            Ok(())
        }
    }
}

pub enum ScopedDisconnectReason<'a, E, R> {
    ReceivedDisconnect(&'a crate::client::RemoteDisconnectInfo),
    Error(&'a Shared<E, R>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopedChannelType {
    Session,
    DirectTcpIp,
    ForwardedTcpIp,
    DirectStreamLocal,
    ForwardedStreamLocal,
    X11,
    AgentForward,
    Unknown,
}

/// 字符串 getter 借用同一已验证 packet，不复制成 String 或 Bytes。
pub struct ScopedOpenInfo<R> {
    bytes: ScopedBuffer<R>,
    kind: ScopedChannelType,
    name: Range<usize>,
    address: Option<(Range<usize>, u32)>,
    originator: Option<(Range<usize>, u32)>,
    socket: Option<Range<usize>>,
    parameters: usize,
}

impl<R: Send + Sync + 'static> ScopedOpenInfo<R> {
    pub fn root(&self) -> &ResourceRoot<R> {
        self.bytes.root()
    }
    pub fn kind(&self) -> ScopedChannelType {
        self.kind
    }
    pub fn name(&self) -> &str {
        self.text(&self.name)
    }
    pub fn address(&self) -> Option<(&str, u32)> {
        self.address
            .as_ref()
            .map(|(name, port)| (self.text(name), *port))
    }
    pub fn originator(&self) -> Option<(&str, u32)> {
        self.originator
            .as_ref()
            .map(|(name, port)| (self.text(name), *port))
    }
    pub fn socket_path(&self) -> Option<&str> {
        self.socket.as_ref().map(|name| self.text(name))
    }
    pub fn parameters(&self) -> &[u8] {
        self.bytes.as_slice().split_at(self.parameters).1
    }
    fn text(&self, range: &Range<usize>) -> &str {
        let bytes = self
            .bytes
            .as_slice()
            .split_at(range.start)
            .1
            .split_at(range.len())
            .0;
        // 构造时逐字段验证范围及 UTF-8，随后没有可变 payload 出口。
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Decision {
    Pending,
    Accept,
    Reject(u32),
}

pub struct ScopedChannelOpen<S, C, B>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: Send + Sync + 'static,
    B: Send + Sync + 'static,
{
    info: ScopedOpenInfo<S::Reservation>,
    channel: Option<ScopedChannel<S, C, B>>,
    decision: Shared<Mutex<Decision>, S::Reservation>,
    services: Shared<Services<S, C, B>, S::Reservation>,
}

impl<S, C, B> ScopedChannelOpen<S, C, B>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
    pub fn info(&self) -> &ScopedOpenInfo<S::Reservation> {
        &self.info
    }

    pub fn accept(mut self) -> Result<ScopedChannel<S, C, B>, ScopedFault> {
        if let Some(fault) = self.services.get().failure() {
            return Err(fault);
        }
        if self
            .services
            .get()
            .closing
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
            || self.services.get().commands.is_closed()
        {
            return Err(ScopedFault {
                kind: crate::scoped::FaultKind::Cancelled,
                site: "client.channel.open.cancelled",
                requested: 0,
                available: None,
            });
        }
        *self
            .decision
            .get()
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Decision::Accept;
        self.services
            .get()
            .channel_cleanup
            .store(true, std::sync::atomic::Ordering::Release);
        self.services.get().control.wake();
        self.channel.take().ok_or(ScopedFault {
            kind: crate::scoped::FaultKind::Cancelled,
            site: "client.channel.open.closed",
            requested: 0,
            available: None,
        })
    }

    pub fn reject(self, reason: u32) {
        *self
            .decision
            .get()
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Decision::Reject(reason);
        self.services
            .get()
            .channel_cleanup
            .store(true, std::sync::atomic::Ordering::Release);
        self.services.get().control.wake();
    }
}

impl<S, C, B> Drop for ScopedChannelOpen<S, C, B>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: Send + Sync + 'static,
    B: Send + Sync + 'static,
{
    fn drop(&mut self) {
        {
            let mut decision = self
                .decision
                .get()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if matches!(*decision, Decision::Pending) {
                *decision = Decision::Reject(1);
            }
        }
        self.services
            .get()
            .channel_cleanup
            .store(true, std::sync::atomic::Ordering::Release);
        self.services.get().control.wake();
    }
}

fn text_span(cursor: &mut Cursor<'_>) -> Result<Range<usize>, Error> {
    let len = cursor.word()? as usize;
    let start = cursor.position();
    std::str::from_utf8(cursor.take(len)?).map_err(|_| Error::Inconsistent)?;
    Ok(start..start + len)
}

pub(super) async fn process<S, C, B, H>(
    services: &Shared<Services<S, C, B>, S::Reservation>,
    session: &mut Session,
    handler: &mut H,
    bytes: &[u8],
) -> Result<bool, RunError<H::Error, ScopedFault>>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
    H: ScopedHandler<S, C, B> + Send,
{
    if bytes.first() != Some(&msg::CHANNEL_OPEN) {
        return Ok(false);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.byte()?;
    let name = text_span(&mut cursor)?;
    let remote = cursor.word()?;
    let window = cursor.word()?;
    let maximum_packet = cursor.word()?;
    let parameters = cursor.position();
    if maximum_packet == 0 {
        return Err(Error::Inconsistent.into());
    }
    let mut address = None;
    let mut originator = None;
    let mut socket = None;
    let kind = match bytes.get(name.clone()).ok_or(Error::Inconsistent)? {
        b"session" => ScopedChannelType::Session,
        b"direct-tcpip" | b"forwarded-tcpip" => {
            address = Some((text_span(&mut cursor)?, cursor.word()?));
            originator = Some((text_span(&mut cursor)?, cursor.word()?));
            if bytes.get(name.clone()) == Some(b"direct-tcpip") {
                ScopedChannelType::DirectTcpIp
            } else {
                ScopedChannelType::ForwardedTcpIp
            }
        }
        b"direct-streamlocal@openssh.com" => {
            socket = Some(text_span(&mut cursor)?);
            cursor.string()?;
            cursor.word()?;
            ScopedChannelType::DirectStreamLocal
        }
        b"forwarded-streamlocal@openssh.com" => {
            socket = Some(text_span(&mut cursor)?);
            cursor.string()?;
            ScopedChannelType::ForwardedStreamLocal
        }
        b"x11" => {
            originator = Some((text_span(&mut cursor)?, cursor.word()?));
            ScopedChannelType::X11
        }
        b"auth-agent@openssh.com" => ScopedChannelType::AgentForward,
        _ => ScopedChannelType::Unknown,
    };
    if kind != ScopedChannelType::Unknown {
        cursor.finish()?;
    }
    let id = super::channel::next_id(session).map_err(|error| error.map_operation(Into::into))?;
    let scope = &services.get().scope;
    let mut owned = ScopedBuffer::try_with_capacity(
        scope,
        ResourceClass::Secret,
        "client.channel.open.info",
        bytes.len(),
    )
    .map_err(RunError::Runtime)?;
    owned
        .try_extend_from_slice(scope, bytes)
        .map_err(RunError::Runtime)?;
    let decision = Rooted::try_new(
        scope,
        ResourceClass::Control,
        "client.channel.open.decision",
        || Mutex::new(Decision::Pending),
    )
    .map_err(RunError::Runtime)?
    .into_shared();
    let (mut channel, mut actor) = ScopedChannel::new(
        services.try_clone().map_err(RunError::Runtime)?,
        services
            .get()
            .commands
            .try_clone()
            .map_err(RunError::Runtime)?,
        services.get().window_size,
        services.get().maximum_packet_size,
    )
    .map_err(RunError::Runtime)?;
    channel.opened(id, remote);
    actor.get_mut().incoming(
        id,
        remote,
        window,
        maximum_packet,
        decision.try_clone().map_err(RunError::Runtime)?.erase(),
    );
    super::channel::insert(session, actor);
    let open = ScopedChannelOpen {
        info: ScopedOpenInfo {
            bytes: owned,
            kind,
            name,
            address,
            originator,
            socket,
            parameters,
        },
        channel: Some(channel),
        decision,
        services: services.try_clone().map_err(RunError::Runtime)?,
    };
    handler
        .server_channel_open_scoped(open)
        .await
        .map_err(|error| match error {
            ScopedError::Resource(fault) => RunError::Runtime(fault),
            ScopedError::Operation(error) => RunError::Operation(error),
        })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::scoped::tests::{Scope, assert_no_allocations, assert_secret_release};
    use futures::task::AtomicWaker;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

    struct Clock;
    impl ScopedClock for Clock {
        type Sleep = std::future::Ready<Result<(), ScopedFault>>;
        fn now(&self) -> std::time::Instant {
            std::time::Instant::now()
        }
        fn sleep_until(&self, _: std::time::Instant) -> Result<Self::Sleep, ScopedFault> {
            Ok(std::future::ready(Ok(())))
        }
        fn reset(
            &self,
            _: std::pin::Pin<&mut Self::Sleep>,
            _: std::time::Instant,
        ) -> Result<(), ScopedFault> {
            Ok(())
        }
    }
    struct Budget;
    impl Cooperative for Budget {
        fn begin_poll(&self) {}
        fn poll_budget(&self, _: &mut std::task::Context<'_>, _: usize) -> std::task::Poll<()> {
            std::task::Poll::Ready(())
        }
    }

    #[test]
    fn dropped_open_token_rejects_without_allocation_and_wipes_metadata() {
        for watch_wipe in [false, true] {
            let scope = Scope::new(usize::MAX);
            let (commands, receiver) =
                crate::scoped::queue::channel(&scope, "test.incoming.commands").unwrap();
            let services = Rooted::try_new(
                &scope,
                ResourceClass::Control,
                "test.incoming.services",
                || Services {
                    scope: scope.clone(),
                    commands,
                    clock: Clock,
                    cooperative: Budget,
                    rsa: AtomicU8::new(0),
                    rsa_waiter: AtomicWaker::new(),
                    closing: AtomicU32::new(0),
                    cause: Mutex::new(None),
                    control: AtomicWaker::new(),
                    channel_cleanup: AtomicBool::new(false),
                    window_size: 1024,
                    maximum_packet_size: 512,
                },
            )
            .unwrap()
            .into_shared();
            let decision = Rooted::try_new(
                &scope,
                ResourceClass::Control,
                "test.incoming.decision",
                || Mutex::new(Decision::Pending),
            )
            .unwrap()
            .into_shared();
            let (channel, actor) = ScopedChannel::new(
                services.try_clone().unwrap(),
                services.get().commands.try_clone().unwrap(),
                1024,
                512,
            )
            .unwrap();
            let token_services = services.try_clone().unwrap();
            let token_decision = decision.try_clone().unwrap();
            let mut bytes = ScopedBuffer::try_with_capacity(
                &scope,
                ResourceClass::Secret,
                "test.incoming.metadata",
                37,
            )
            .unwrap();
            bytes.try_extend_from_slice(&scope, &[0xA7; 37]).unwrap();
            scope.freeze();
            let release = |bytes: ScopedBuffer<_>| {
                let late = bytes.root().try_clone().unwrap();
                let token = ScopedChannelOpen {
                    info: ScopedOpenInfo {
                        bytes,
                        kind: ScopedChannelType::Unknown,
                        name: 0..0,
                        address: None,
                        originator: None,
                        socket: None,
                        parameters: 0,
                    },
                    channel: Some(channel),
                    decision: token_decision,
                    services: token_services,
                };
                drop(token);
                assert!(matches!(
                    *decision.get().lock().unwrap(),
                    Decision::Reject(1)
                ));
                assert!(services.get().channel_cleanup.load(Ordering::Acquire));
                drop(late);
            };
            if watch_wipe {
                assert_secret_release(&scope, bytes, release);
            } else {
                assert_no_allocations(|| release(bytes));
            }
            drop((actor, decision, services, receiver));
            assert_eq!(scope.held(), 0);
        }
    }
}
