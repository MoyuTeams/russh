use std::ops::Range;

use super::{ScopedAuthResult, packet};
use crate::client::runtime::RunError;
use crate::client::{Handler, Session};
use crate::scoped::{
    AdmissionScope, ErasedBuffer, ResourceClass, ScopedBuffer, ScopedFault, queue,
};
use crate::session::EncryptedState;
use crate::{Error, MethodKind, msg};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::client) enum Kind {
    None,
    Password,
    Keyboard,
    PublicKey,
}

#[derive(Clone, Copy)]
pub(super) enum InitialKind {
    None,
    Password,
    Keyboard,
}

#[derive(Debug)]
pub(in crate::client) struct Request {
    pub id: u64,
    pub kind: Kind,
    pub packet: ErasedBuffer,
    pub continuation: bool,
}

pub(in crate::client) struct State {
    pub id: u64,
    pub kind: Kind,
    pub pending: Option<ErasedBuffer>,
    pub sent: bool,
    pub service_sent: bool,
    pub service_accepted: bool,
    pub probe: Option<ErasedBuffer>,
    pub probe_pending: bool,
    pub replies: queue::Sender<Reply>,
}

pub(in crate::client) enum Reply {
    Sign {
        id: u64,
        bytes: ErasedBuffer,
        request_offset: usize,
    },
    Result {
        id: u64,
        result: ScopedAuthResult,
    },
    Info {
        id: u64,
        bytes: ErasedBuffer,
        name: Range<usize>,
        instructions: Range<usize>,
        prompts: usize,
        count: u32,
    },
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedAuthState")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// 提示文本保留原 packet 的实际根；getter 不创建 String 或 Vec。
pub struct ScopedAuthInfo<R> {
    bytes: ScopedBuffer<R>,
    name: Range<usize>,
    instructions: Range<usize>,
    prompts: usize,
    count: u32,
}

pub enum ScopedKeyboardInteractiveResponse<R> {
    Success,
    Failure {
        remaining_methods: [Option<MethodKind>; 5],
        partial_success: bool,
    },
    InfoRequest(ScopedAuthInfo<R>),
}

impl<R> std::fmt::Debug for ScopedKeyboardInteractiveResponse<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("Success"),
            Self::Failure { .. } => f.write_str("Failure"),
            Self::InfoRequest(_) => f.write_str("InfoRequest"),
        }
    }
}

pub struct ScopedPrompt<'a> {
    pub prompt: &'a str,
    pub echo: bool,
}
pub struct ScopedPrompts<'a> {
    cursor: Cursor<'a>,
    count: u32,
}

impl<'a> Iterator for ScopedPrompts<'a> {
    type Item = ScopedPrompt<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        let prompt = self.cursor.text().ok()?;
        let echo = self.cursor.byte().ok()? != 0;
        Some(ScopedPrompt { prompt, echo })
    }
}

impl<R: Send + Sync + 'static> ScopedAuthInfo<R> {
    pub fn name(&self) -> &str {
        self.text(&self.name)
    }
    pub fn instructions(&self) -> &str {
        self.text(&self.instructions)
    }
    pub fn root(&self) -> &crate::scoped::ResourceRoot<R> {
        self.bytes.root()
    }
    pub fn prompts(&self) -> ScopedPrompts<'_> {
        ScopedPrompts {
            cursor: Cursor {
                bytes: self.bytes.as_slice(),
                position: self.prompts,
            },
            count: self.count,
        }
    }
    fn text(&self, range: &Range<usize>) -> &str {
        let (_, bytes) = self.bytes.as_slice().split_at(range.start);
        let (bytes, _) = bytes.split_at(range.len());
        // 构造前已逐字段验证 UTF-8，且此类型不暴露可变 backing。
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }
}

impl Reply {
    pub(super) fn id(&self) -> u64 {
        match self {
            Self::Result { id, .. } | Self::Info { id, .. } | Self::Sign { id, .. } => *id,
        }
    }
    pub(super) fn keyboard<R: Send + Sync + 'static>(
        self,
    ) -> Result<ScopedKeyboardInteractiveResponse<R>, RunError<Error, ScopedFault>> {
        Ok(match self {
            Self::Result {
                result: ScopedAuthResult::Success,
                ..
            } => ScopedKeyboardInteractiveResponse::Success,
            Self::Result {
                result:
                    ScopedAuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    },
                ..
            } => ScopedKeyboardInteractiveResponse::Failure {
                remaining_methods,
                partial_success,
            },
            Self::Info {
                bytes,
                name,
                instructions,
                prompts,
                count,
                ..
            } => ScopedKeyboardInteractiveResponse::InfoRequest(ScopedAuthInfo {
                bytes: bytes.into_typed().map_err(RunError::Runtime)?,
                name,
                instructions,
                prompts,
                count,
            }),
            Self::Sign { .. } => return Err(Error::Inconsistent.into()),
        })
    }
}

pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    pub(super) fn position(&self) -> usize {
        self.position
    }
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error::IndexOutOfBounds)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::IndexOutOfBounds)?;
        self.position = end;
        Ok(bytes)
    }
    pub(super) fn byte(&mut self) -> Result<u8, Error> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(Error::IndexOutOfBounds)
    }
    pub(super) fn word(&mut self) -> Result<u32, Error> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| Error::IndexOutOfBounds)?;
        Ok(u32::from_be_bytes(bytes))
    }
    pub(super) fn string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.word()? as usize;
        self.take(len)
    }
    pub(super) fn text(&mut self) -> Result<&'a str, Error> {
        std::str::from_utf8(self.string()?).map_err(|_| Error::Inconsistent)
    }
    fn span(&mut self) -> Result<Range<usize>, Error> {
        let len = self.word()? as usize;
        let start = self.position;
        std::str::from_utf8(self.take(len)?).map_err(|_| Error::Inconsistent)?;
        Ok(start..self.position)
    }
    pub(super) fn finish(&self) -> Result<(), Error> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Inconsistent)
        }
    }
}

pub(super) fn request<S: AdmissionScope>(
    scope: &S,
    id: u64,
    initial: InitialKind,
    user: &str,
    secret_or_submethods: &str,
) -> Result<Request, ScopedFault> {
    let site = "client.auth.payload";
    let (kind, method, tail): (_, &[u8], _) = match initial {
        InitialKind::None => (Kind::None, b"none", 0),
        InitialKind::Password => (Kind::Password, b"password", 5),
        InitialKind::Keyboard => (Kind::Keyboard, b"keyboard-interactive", 8),
    };
    let len = packet::length(
        site,
        &[
            1,
            4,
            user.len(),
            4,
            b"ssh-connection".len(),
            4,
            method.len(),
            tail,
            secret_or_submethods.len(),
        ],
    )?;
    let mut packet = packet::Packet::new(scope, site, len)?;
    packet.byte(scope, msg::USERAUTH_REQUEST)?;
    packet.string(scope, user.as_bytes())?;
    packet.string(scope, b"ssh-connection")?;
    packet.string(scope, method)?;
    match initial {
        InitialKind::None => (),
        InitialKind::Password => {
            packet.byte(scope, 0)?;
            packet.string(scope, secret_or_submethods.as_bytes())?;
        }
        InitialKind::Keyboard => {
            packet.string(scope, b"")?;
            packet.string(scope, secret_or_submethods.as_bytes())?;
        }
    }
    Ok(Request {
        id,
        kind,
        packet: packet.finish().erase(),
        continuation: false,
    })
}

pub(super) fn responses<S: AdmissionScope>(
    scope: &S,
    id: u64,
    responses: &[&str],
) -> Result<Request, ScopedFault> {
    let site = "client.auth.responses";
    let count = u32::try_from(responses.len()).map_err(|_| ScopedFault::overflow(site))?;
    let mut len = 5;
    for response in responses {
        len = packet::length(site, &[len, 4, response.len()])?;
    }
    let mut packet = packet::Packet::new(scope, site, len)?;
    packet.byte(scope, msg::USERAUTH_INFO_RESPONSE)?;
    packet.word(scope, count)?;
    for response in responses {
        packet.string(scope, response.as_bytes())?;
    }
    Ok(Request {
        id,
        kind: Kind::Keyboard,
        packet: packet.finish().erase(),
        continuation: true,
    })
}

pub(super) async fn process<S: AdmissionScope, H: Handler + Send>(
    scope: &S,
    session: &mut Session,
    handler: &mut H,
    bytes: &[u8],
) -> Result<bool, RunError<H::Error, ScopedFault>> {
    if session.common.encrypted.is_none() {
        return Ok(false);
    }
    let Some(state) = session.scoped_auth.as_ref() else {
        return Ok(false);
    };
    let mut cursor = Cursor::new(bytes);
    let message = cursor.byte()?;
    if message == msg::SERVICE_ACCEPT {
        if !state.service_sent {
            return Err(Error::Inconsistent.into());
        }
        if cursor.text()? != "ssh-userauth" {
            return Err(Error::Inconsistent.into());
        }
        cursor.finish()?;
        if let Some(state) = session.scoped_auth.as_mut() {
            state.service_accepted = true;
        }
        return Ok(true);
    }
    if state.id == 0 {
        return Ok(false);
    }
    let id = state.id;
    match message {
        msg::USERAUTH_PK_OK if state.kind == Kind::PublicKey => {
            let algorithm = cursor.string()?;
            let key = cursor.string()?;
            cursor.finish()?;
            if !state.sent {
                return Err(Error::Inconsistent.into());
            }
            let probe = state.probe.as_ref().ok_or(Error::Inconsistent)?;
            let (flag, expected_algorithm, expected_key) = super::sign::ranges(probe.as_slice())?;
            if probe.as_slice().get(expected_algorithm) != Some(algorithm)
                || probe.as_slice().get(expected_key) != Some(key)
            {
                return Err(Error::Inconsistent.into());
            }
            let session_id = session
                .common
                .encrypted
                .as_ref()
                .ok_or(Error::Inconsistent)?
                .session_id
                .as_ref();
            let site = "client.auth.sign";
            let offset = packet::length(site, &[4, session_id.len()]).map_err(RunError::Runtime)?;
            let len = packet::length(site, &[offset, probe.as_slice().len()])
                .map_err(RunError::Runtime)?;
            let mut bytes =
                ScopedBuffer::try_with_capacity(scope, ResourceClass::Secret, site, len)
                    .map_err(RunError::Runtime)?;
            let session_len = u32::try_from(session_id.len())
                .map_err(|_| RunError::Runtime(ScopedFault::overflow(site)))?;
            bytes
                .try_extend_from_slice(scope, &session_len.to_be_bytes())
                .map_err(RunError::Runtime)?;
            bytes
                .try_extend_from_slice(scope, session_id)
                .map_err(RunError::Runtime)?;
            bytes
                .try_extend_from_slice(scope, probe.as_slice())
                .map_err(RunError::Runtime)?;
            *bytes
                .as_mut_slice()
                .get_mut(offset + flag)
                .ok_or(Error::Inconsistent)? = 1;
            if let Some(state) = session.scoped_auth.as_mut() {
                state.probe.take();
                state.sent = false;
                state
                    .replies
                    .try_send(
                        scope,
                        "client.auth.reply.node",
                        Reply::Sign {
                            id,
                            bytes: bytes.erase(),
                            request_offset: offset,
                        },
                    )
                    .map_err(RunError::Runtime)?;
            }
        }
        msg::USERAUTH_SUCCESS => {
            cursor.finish()?;
            if !state.sent {
                return Err(Error::Inconsistent.into());
            }
            if let Some(enc) = session.common.encrypted.as_mut() {
                if !matches!(
                    enc.client_compression,
                    crate::compression::Compression::None
                ) || !matches!(
                    enc.server_compression,
                    crate::compression::Compression::None
                ) {
                    return Err(RunError::Runtime(ScopedFault {
                        kind: crate::scoped::FaultKind::PolicyUnavailable,
                        site: "client.compression.init",
                        requested: 0,
                        available: None,
                    }));
                }
                enc.state = EncryptedState::InitCompression;
            }
            if let Some(state) = session.scoped_auth.as_mut() {
                state.id = 0;
                state.probe.take();
                state
                    .replies
                    .try_send(
                        scope,
                        "client.auth.reply.node",
                        Reply::Result {
                            id,
                            result: ScopedAuthResult::Success,
                        },
                    )
                    .map_err(RunError::Runtime)?;
            }
        }
        msg::USERAUTH_FAILURE => {
            if !state.sent {
                return Err(Error::Inconsistent.into());
            }
            let methods = cursor.text()?;
            let partial_success = cursor.byte()? != 0;
            cursor.finish()?;
            let mut remaining_methods = [None; 5];
            let mut index = 0;
            for name in methods.split(',') {
                if let Ok(method) = name.parse::<MethodKind>() {
                    if !remaining_methods.contains(&Some(method)) {
                        if let Some(slot) = remaining_methods.get_mut(index) {
                            *slot = Some(method);
                            index += 1;
                        }
                    }
                }
            }
            if let Some(state) = session.scoped_auth.as_mut() {
                state.id = 0;
                state.probe.take();
                state
                    .replies
                    .try_send(
                        scope,
                        "client.auth.reply.node",
                        Reply::Result {
                            id,
                            result: ScopedAuthResult::Failure {
                                remaining_methods,
                                partial_success,
                            },
                        },
                    )
                    .map_err(RunError::Runtime)?;
            }
        }
        msg::USERAUTH_INFO_REQUEST if state.kind == Kind::Keyboard => {
            if !state.sent {
                return Err(Error::Inconsistent.into());
            }
            let name = cursor.span()?;
            let instructions = cursor.span()?;
            cursor.text()?;
            let count = cursor.word()?;
            let prompts = cursor.position;
            if count as usize > bytes.len().saturating_sub(prompts) / 5 {
                return Err(Error::Inconsistent.into());
            }
            for _ in 0..count {
                cursor.text()?;
                cursor.byte()?;
            }
            cursor.finish()?;
            let mut owned = ScopedBuffer::try_with_capacity(
                scope,
                ResourceClass::Secret,
                "client.auth.prompts",
                bytes.len(),
            )
            .map_err(RunError::Runtime)?;
            owned
                .try_extend_from_slice(scope, bytes)
                .map_err(RunError::Runtime)?;
            if let Some(state) = session.scoped_auth.as_mut() {
                state.sent = false;
                state
                    .replies
                    .try_send(
                        scope,
                        "client.auth.reply.node",
                        Reply::Info {
                            id,
                            bytes: owned.erase(),
                            name,
                            instructions,
                            prompts,
                            count,
                        },
                    )
                    .map_err(RunError::Runtime)?;
            }
        }
        msg::USERAUTH_BANNER => {
            let banner = cursor.text()?;
            cursor.text()?;
            cursor.finish()?;
            handler
                .auth_banner(banner, session)
                .await
                .map_err(RunError::Operation)?;
        }
        msg::USERAUTH_INFO_REQUEST => return Err(Error::Inconsistent.into()),
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn flush<S: AdmissionScope>(
    scope: &S,
    session: &mut Session,
) -> Result<(), RunError<Error, ScopedFault>> {
    let Some(state) = session.scoped_auth.as_mut() else {
        return Ok(());
    };
    if state.pending.is_none() {
        return Ok(());
    }
    if !state.service_accepted {
        if !state.service_sent {
            let mut request =
                packet::Packet::new(scope, "client.auth.service", 17).map_err(RunError::Runtime)?;
            request
                .byte(scope, msg::SERVICE_REQUEST)
                .map_err(RunError::Runtime)?;
            request
                .string(scope, b"ssh-userauth")
                .map_err(RunError::Runtime)?;
            let output = session
                .common
                .packet_writer
                .scoped_packet(scope, request.finish().as_slice())
                .map_err(RunError::Runtime)?;
            session.scoped_write = Some(super::WritePacket {
                bytes: output.erase(),
                offset: 0,
            });
            state.service_sent = true;
        }
        return Ok(());
    }
    if let Some(input) = state.pending.take() {
        let output = session
            .common
            .packet_writer
            .scoped_packet(scope, input.as_slice())
            .map_err(RunError::Runtime)?;
        session.scoped_write = Some(super::WritePacket {
            bytes: output.erase(),
            offset: 0,
        });
        state.sent = true;
        if state.probe_pending {
            state.probe = Some(input);
            state.probe_pending = false;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoped::tests::{Scope, assert_secret_release};

    #[test]
    #[allow(clippy::unwrap_used)]
    fn first_owned_password_and_answers_wipe_after_queue_cancel_and_late_root() {
        for keyboard in [false, true] {
            let scope = Scope::new(usize::MAX);
            let request = if keyboard {
                responses(&scope, 1, &["first-answer", "second-answer"])
            } else {
                request(
                    &scope,
                    1,
                    InitialKind::Password,
                    "fixture",
                    "first-owned-password",
                )
            }
            .unwrap();
            let bytes = request.packet.into_typed().unwrap();
            let needle: &[u8] = if keyboard {
                b"second-answer"
            } else {
                b"first-owned-password"
            };
            assert!(
                bytes
                    .as_slice()
                    .windows(needle.len())
                    .any(|part| part == needle)
            );
            assert_secret_release(&scope, bytes, |bytes| {
                let late = bytes.root().try_clone().unwrap();
                let (sender, receiver) = queue::channel(&scope, "test.auth.queue").unwrap();
                sender
                    .try_send(&scope, "test.auth.node", bytes.erase())
                    .unwrap();
                drop(receiver);
                drop(sender);
                assert!(scope.held() > 0);
                drop(late);
            });
            assert_eq!(scope.held(), 0);
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn plaintext_packet_capacity_wipes_when_write_is_cancelled() {
        let scope = Scope::new(usize::MAX);
        let request = request(
            &scope,
            1,
            InitialKind::Password,
            "fixture",
            "packet-password",
        )
        .unwrap();
        let mut writer = crate::sshbuffer::PacketWriter::clear();
        let output = writer
            .scoped_packet(&scope, request.packet.as_slice())
            .unwrap();
        assert!(
            output
                .as_slice()
                .windows(b"packet-password".len())
                .any(|part| part == b"packet-password")
        );
        assert_secret_release(&scope, output, |mut output| {
            output.clear();
            let pending = crate::client::scoped::WritePacket {
                bytes: output.erase(),
                offset: 0,
            };
            drop(pending);
        });
        drop(request);
        assert_eq!(scope.held(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn packet_denial_precedes_every_allocator_call() {
        let scope = Scope::new(0);
        let mut writer = crate::sshbuffer::PacketWriter::clear();
        crate::scoped::tests::assert_no_allocations(|| {
            assert_eq!(
                writer
                    .scoped_packet(&scope, b"secret-payload")
                    .unwrap_err()
                    .kind,
                crate::scoped::FaultKind::ByteBudget
            );
        });
        assert_eq!(scope.held(), 0);
    }
}
