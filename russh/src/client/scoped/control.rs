use std::pin::Pin;
use std::task::Poll;

use tokio::io::AsyncWrite;

use super::super::runtime::RunError;
use super::{Session, WritePacket};
use crate::scoped::{
    AdmissionScope, ErasedBuffer, ResourceClass, ScopedBuffer, ScopedFault, queue,
};
use crate::{Error, msg};

// SSH padding_length 是 u8；本库现有 MAC 的最大输出为 SHA-512 的 64 bytes。
// disconnect 固定为 message + reason + 两个空 string，容量不依赖用户输入。
const CLEANUP_CAPACITY: usize = 4 + 1 + 13 + u8::MAX as usize + 64;

enum Pending {
    Keepalive(bool),
    Reply(bool),
}

pub(crate) struct State {
    pending_tx: queue::Sender<Pending>,
    pending_rx: queue::Receiver<Pending>,
    replies_tx: queue::Sender<usize>,
    replies_rx: queue::Receiver<usize>,
    reply: Option<usize>,
    legacy_tracked: usize,
    cleanup: Option<ErasedBuffer>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").finish_non_exhaustive()
    }
}

impl State {
    pub(super) fn new<S: AdmissionScope>(scope: &S) -> Result<Self, ScopedFault> {
        let (pending_tx, pending_rx) = queue::channel(scope, "client.control.queue")?;
        let (replies_tx, replies_rx) = queue::channel(scope, "client.control.replies")?;
        let cleanup = ScopedBuffer::try_with_capacity(
            scope,
            ResourceClass::Secret,
            "client.control.cleanup",
            CLEANUP_CAPACITY,
        )?;
        Ok(Self {
            pending_tx,
            pending_rx,
            replies_tx,
            replies_rx,
            reply: None,
            legacy_tracked: 0,
            cleanup: Some(cleanup.erase()),
        })
    }
}

pub(super) fn keepalive<S: AdmissionScope>(
    scope: &S,
    session: &Session,
    want_reply: bool,
) -> Result<(), RunError<Error, ScopedFault>> {
    session
        .scoped_control
        .as_ref()
        .ok_or(Error::Inconsistent)?
        .pending_tx
        .try_send(scope, "client.control.node", Pending::Keepalive(want_reply))
        .map_err(RunError::Runtime)
}

pub(super) fn process<S: AdmissionScope>(
    scope: &S,
    session: &mut Session,
    bytes: &[u8],
) -> Result<bool, RunError<Error, ScopedFault>> {
    if bytes.first() != Some(&msg::GLOBAL_REQUEST) || session.common.encrypted.is_none() {
        return response(session, bytes).map_err(RunError::Operation);
    }
    let mut cursor = super::auth::Cursor::new(bytes);
    cursor.byte()?;
    let name = cursor.text()?;
    let want_reply = cursor.byte()?;
    if name == "hostkeys-00@openssh.com" {
        return Ok(false);
    }
    let success = name.starts_with("keepalive");
    if success {
        cursor.finish()?;
        if want_reply != 1 {
            return Ok(true);
        }
    }
    session
        .scoped_control
        .as_ref()
        .ok_or(Error::Inconsistent)?
        .pending_tx
        .try_send(scope, "client.control.node", Pending::Reply(success))
        .map_err(RunError::Runtime)?;
    Ok(true)
}

pub(super) fn response(session: &mut Session, bytes: &[u8]) -> Result<bool, Error> {
    if !matches!(
        bytes.first(),
        Some(&msg::REQUEST_SUCCESS | &msg::REQUEST_FAILURE)
    ) {
        return Ok(false);
    }
    let state = session.scoped_control.as_mut().ok_or(Error::Inconsistent)?;
    if state.reply.is_none() {
        state.reply = state.replies_rx.try_recv();
    }
    let Some(before) = state.reply.as_mut() else {
        return Ok(false);
    };
    if *before != 0 {
        *before -= 1;
        state.legacy_tracked -= 1;
        return Ok(false);
    }
    // keepalive 的成功和失败都没有结果 payload；回复只消费对应的有根队列项。
    if bytes.len() != 1 {
        return Err(Error::Inconsistent);
    }
    state.reply.take();
    Ok(true)
}

pub(super) fn flush<S: AdmissionScope>(
    scope: &S,
    session: &mut Session,
) -> Result<(), RunError<Error, ScopedFault>> {
    let state = session.scoped_control.as_mut().ok_or(Error::Inconsistent)?;
    let Some(pending) = state.pending_rx.try_recv() else {
        return Ok(());
    };
    const NAME: &[u8] = b"keepalive@openssh.com";
    let mut payload = [0u8; 6 + NAME.len()];
    let (len, want_reply) = match pending {
        Pending::Keepalive(want_reply) => {
            payload[0] = msg::GLOBAL_REQUEST;
            payload[1..5].copy_from_slice(&(NAME.len() as u32).to_be_bytes());
            let (name, flag) = payload[5..].split_at_mut(NAME.len());
            name.copy_from_slice(NAME);
            *flag.first_mut().ok_or(Error::Inconsistent)? = u8::from(want_reply);
            (payload.len(), want_reply)
        }
        Pending::Reply(success) => {
            payload[0] = if success {
                msg::REQUEST_SUCCESS
            } else {
                msg::REQUEST_FAILURE
            };
            (1, false)
        }
    };
    // 在 seal 改变序号前准入回复项，拒额时不会留下已经发送的孤立请求。
    if want_reply {
        let legacy = session.open_global_requests.len();
        let before = legacy
            .checked_sub(state.legacy_tracked)
            .ok_or(Error::Inconsistent)?;
        state
            .replies_tx
            .try_send(scope, "client.control.reply.node", before)
            .map_err(RunError::Runtime)?;
        state.legacy_tracked = legacy;
    }
    let bytes = session
        .common
        .packet_writer
        .scoped_packet(scope, payload.get(..len).ok_or(Error::Inconsistent)?)
        .map_err(RunError::Runtime)?;
    session.scoped_write = Some(WritePacket {
        bytes: bytes.erase(),
        offset: 0,
    });
    Ok(())
}

pub(super) async fn close<S: AdmissionScope, W: AsyncWrite + Unpin>(
    scope: &S,
    session: &mut Session,
    stream: &mut W,
    reason: u32,
) -> Result<(), RunError<Error, ScopedFault>> {
    // 已有半包不能被 disconnect 插入；只尝试一次推进，Pending 时直接本地关闭。
    let ready = std::future::poll_fn(|cx| {
        if let Some(pending) = session.scoped_write.as_mut() {
            let remaining = pending.bytes.as_slice().split_at(pending.offset).1;
            if !remaining.is_empty() {
                match Pin::new(&mut *stream).poll_write(cx, remaining) {
                    Poll::Ready(Ok(n)) if n == remaining.len() => (),
                    _ => return Poll::Ready(false),
                }
            }
        }
        Poll::Ready(true)
    })
    .await;
    session.scoped_write.take();
    if !ready || !session.common.packet_writer.buffer().buffer.is_empty() {
        return Ok(());
    }
    let mut payload = [0u8; 13];
    payload[0] = msg::DISCONNECT;
    payload[1..5].copy_from_slice(&reason.to_be_bytes());
    let state = session.scoped_control.as_mut().ok_or(Error::Inconsistent)?;
    let buffer = state
        .cleanup
        .take()
        .ok_or(Error::Inconsistent)?
        .into_typed::<S::Reservation>()
        .map_err(RunError::Runtime)?;
    let required = session
        .common
        .packet_writer
        .scoped_packet_size(&payload)
        .map_err(RunError::Runtime)?;
    if required > buffer.capacity() {
        return Err(RunError::Runtime(ScopedFault::overflow(
            "client.control.cleanup",
        )));
    }
    let bytes = session
        .common
        .packet_writer
        .scoped_packet_into(scope, &payload, buffer)
        .map_err(RunError::Runtime)?;
    std::future::poll_fn(|cx| {
        if let Poll::Ready(Ok(n)) = Pin::new(&mut *stream).poll_write(cx, bytes.as_slice()) {
            if n == bytes.len() {
                let _ = Pin::new(&mut *stream).poll_flush(cx);
            }
        }
        Poll::Ready(())
    })
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoped::tests::{Scope, assert_no_allocations, assert_secret_release};

    #[test]
    #[allow(clippy::unwrap_used)]
    fn cleanup_uses_reserved_backing_after_budget_exhaustion_and_wipes_capacity() {
        let scope = Scope::new(usize::MAX);
        let mut control = State::new(&scope).unwrap();
        let cleanup = control.cleanup.take().unwrap().into_typed().unwrap();
        let mut writer = crate::sshbuffer::PacketWriter::clear();
        let mut payload = [0u8; 13];
        payload[0] = msg::DISCONNECT;
        payload[1..5].copy_from_slice(&(crate::Disconnect::ByApplication as u32).to_be_bytes());
        scope.freeze();
        let output = assert_no_allocations(|| {
            writer
                .scoped_packet_into(&scope, &payload, cleanup)
                .unwrap()
        });
        assert_eq!(&output.as_slice()[5..18], &payload);
        assert_secret_release(&scope, output, drop);
        drop(control);
        assert_eq!(scope.held(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn control_node_denial_does_not_call_allocator() {
        let scope = Scope::new(usize::MAX);
        let control = State::new(&scope).unwrap();
        scope.freeze();
        let error = assert_no_allocations(|| {
            control
                .pending_tx
                .try_send(&scope, "client.control.node", Pending::Keepalive(true))
        })
        .unwrap_err();
        assert_eq!(error.kind, crate::scoped::FaultKind::ByteBudget);
        assert!(error.requested > 0);
        assert_eq!(error.available, Some(0));
        let error = assert_no_allocations(|| {
            control
                .replies_tx
                .try_send(&scope, "client.control.reply.node", 0)
        })
        .unwrap_err();
        assert_eq!(error.kind, crate::scoped::FaultKind::ByteBudget);
        assert!(error.requested > 0);
        drop(control);
        assert_eq!(scope.held(), 0);
    }
}
