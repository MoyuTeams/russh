use std::sync::atomic::Ordering;

use super::{Command, Services, auth::Cursor, packet};
use crate::client::{Session, runtime::RunError};
use crate::scoped::{
    AdmissionScope, Cooperative, ErasedBuffer, ErasedRooted, ResourceClass, Rooted, ScopedBuffer,
    ScopedClock, ScopedFault, Shared, queue,
};
use crate::{Error, Pty, msg};

#[derive(Debug)]
pub(in crate::client) enum Pending {
    Data { bytes: ErasedBuffer, offset: usize },
    Packet { bytes: ErasedBuffer, close: bool },
}

pub(super) enum Event {
    Open {
        id: u32,
        remote: u32,
    },
    OpenFailure(u32),
    Data {
        bytes: ErasedBuffer,
        extended: Option<u32>,
    },
    Success,
    Failure,
    Eof,
    Close,
    ExitStatus(u32),
    ExitSignal(ErasedBuffer),
}

/// 数据和信号字段由实际 backing 根持有；不会返回脱离准入的 Vec。
pub enum ScopedChannelMsg<R> {
    Data(ScopedBuffer<R>),
    ExtendedData { data: ScopedBuffer<R>, ext: u32 },
    Success,
    Failure,
    Eof,
    Close,
    ExitStatus(u32),
    ExitSignal(ScopedBuffer<R>),
}

pub(in crate::client) struct State {
    id: u32,
    remote: u32,
    open_sent: bool,
    confirmed: bool,
    remote_window: u32,
    remote_packet: u32,
    local_window: u32,
    local_packet: u32,
    credit: u32,
    received_close: bool,
    sent_close: bool,
    failed: bool,
    events: queue::Sender<Event>,
    pending_sender: queue::Sender<Pending>,
    pending: queue::Receiver<Pending>,
    current: Option<Pending>,
    next: Option<ErasedRooted<State>>,
    incoming: Option<crate::scoped::ErasedShared<std::sync::Mutex<super::incoming::Decision>>>,
}

impl State {
    pub(super) fn incoming(
        &mut self,
        id: u32,
        remote: u32,
        window: u32,
        maximum_packet: u32,
        decision: crate::scoped::ErasedShared<std::sync::Mutex<super::incoming::Decision>>,
    ) {
        self.id = id;
        self.remote = remote;
        self.remote_window = window;
        self.remote_packet = maximum_packet;
        self.incoming = Some(decision);
    }
}

struct Handle<S: AdmissionScope, C, B> {
    id: u32,
    remote: u32,
    commands: queue::Sender<Command>,
    events: queue::Receiver<Event>,
    services: Shared<Services<S, C, B>, S::Reservation>,
}

pub struct ScopedChannel<S, C, B>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: Send + Sync + 'static,
    B: Send + Sync + 'static,
{
    state: Rooted<Handle<S, C, B>, S::Reservation>,
}

impl<S, C, B> Drop for ScopedChannel<S, C, B>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: Send + Sync + 'static,
    B: Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.state.get_mut().events.close();
        let services = self.state.get().services.get();
        services.channel_cleanup.store(true, Ordering::Release);
        services.control.wake();
    }
}

impl<S, C, B> ScopedChannel<S, C, B>
where
    S: AdmissionScope + Send + Sync + 'static,
    C: ScopedClock + Send + Sync + 'static,
    B: Cooperative + Send + Sync + 'static,
{
    pub(super) fn new(
        services: Shared<Services<S, C, B>, S::Reservation>,
        commands: queue::Sender<Command>,
        window: u32,
        maximum_packet: u32,
    ) -> Result<(Self, ErasedRooted<State>), ScopedFault> {
        let scope = &services.get().scope;
        let slot = Rooted::<Handle<S, C, B>, _>::try_allocate(
            scope,
            ResourceClass::Control,
            "client.channel.handle",
        )?;
        let (events, receiver) = queue::channel(scope, "client.channel.events")?;
        let (pending_sender, pending) = queue::channel(scope, "client.channel.pending")?;
        let state = Rooted::try_new(
            scope,
            ResourceClass::Runtime,
            "client.channel.state",
            || State {
                id: 0,
                remote: 0,
                open_sent: false,
                confirmed: false,
                remote_window: 0,
                remote_packet: 0,
                local_window: window,
                local_packet: maximum_packet,
                credit: 0,
                received_close: false,
                sent_close: false,
                failed: false,
                events,
                pending_sender,
                pending,
                current: None,
                next: None,
                incoming: None,
            },
        )?
        .erase();
        let state_handle = slot.initialize(|| Handle {
            id: 0,
            remote: 0,
            commands,
            events: receiver,
            services,
        });
        Ok((
            Self {
                state: state_handle,
            },
            state,
        ))
    }

    pub(super) fn poll_open(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Event>> {
        self.state.get_mut().events.poll_recv(cx)
    }

    pub(super) fn opened(&mut self, id: u32, remote: u32) {
        self.state.get_mut().id = id;
        self.state.get_mut().remote = remote;
    }
    pub fn id(&self) -> crate::ChannelId {
        crate::ChannelId(self.state.get().id)
    }
    pub fn root(&self) -> &crate::scoped::ResourceRoot<S::Reservation> {
        self.state.root()
    }

    fn send(&self, pending: Pending) -> Result<(), ScopedFault> {
        let state = self.state.get();
        if let Some(fault) = state.services.get().failure() {
            return Err(fault);
        }
        state.commands.try_send(
            &state.services.get().scope,
            "client.command.node",
            Command::Channel {
                id: state.id,
                pending,
            },
        )
    }

    fn request(
        &self,
        name: &[u8],
        want_reply: bool,
        tail: usize,
    ) -> Result<packet::Packet<S::Reservation>, ScopedFault> {
        let state = self.state.get();
        let scope = &state.services.get().scope;
        let size = packet::length("client.channel.request", &[1, 4, 4, name.len(), 1, tail])?;
        let mut packet = packet::Packet::new(scope, "client.channel.request", size)?;
        packet.byte(scope, msg::CHANNEL_REQUEST)?;
        packet.word(scope, state.remote)?;
        packet.string(scope, name)?;
        packet.byte(scope, u8::from(want_reply))?;
        Ok(packet)
    }

    // 保持 PTY 协议字段与旧 channel 接口一致。
    #[allow(clippy::too_many_arguments)]
    pub async fn request_pty(
        &self,
        want_reply: bool,
        term: &str,
        columns: u32,
        rows: u32,
        pixel_width: u32,
        pixel_height: u32,
        modes: &[(Pty, u32)],
    ) -> Result<(), ScopedFault> {
        let scope = &self.state.get().services.get().scope;
        let count = modes
            .iter()
            .filter(|(code, _)| *code != Pty::TTY_OP_END)
            .count();
        let mode_bytes = count
            .checked_mul(5)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| ScopedFault::overflow("client.channel.pty"))?;
        let tail = packet::length("client.channel.pty", &[4, term.len(), 16, 4, mode_bytes])?;
        let mut packet = self.request(b"pty-req", want_reply, tail)?;
        packet.string(scope, term.as_bytes())?;
        for value in [columns, rows, pixel_width, pixel_height] {
            packet.word(scope, value)?;
        }
        packet.word(
            scope,
            u32::try_from(mode_bytes).map_err(|_| ScopedFault::overflow("client.channel.pty"))?,
        )?;
        for &(code, value) in modes {
            if code != Pty::TTY_OP_END {
                packet.byte(scope, code as u8)?;
                packet.word(scope, value)?;
            }
        }
        packet.byte(scope, Pty::TTY_OP_END as u8)?;
        self.send(Pending::Packet {
            bytes: packet.finish().erase(),
            close: false,
        })
    }

    pub async fn request_shell(&self, want_reply: bool) -> Result<(), ScopedFault> {
        self.send(Pending::Packet {
            bytes: self.request(b"shell", want_reply, 0)?.finish().erase(),
            close: false,
        })
    }

    pub async fn window_change(
        &self,
        columns: u32,
        rows: u32,
        pixel_width: u32,
        pixel_height: u32,
    ) -> Result<(), ScopedFault> {
        let scope = &self.state.get().services.get().scope;
        let mut packet = self.request(b"window-change", false, 16)?;
        for value in [columns, rows, pixel_width, pixel_height] {
            packet.word(scope, value)?;
        }
        self.send(Pending::Packet {
            bytes: packet.finish().erase(),
            close: false,
        })
    }

    pub async fn data(&self, bytes: &[u8]) -> Result<(), ScopedFault> {
        if bytes.is_empty() {
            return Ok(());
        }
        let scope = &self.state.get().services.get().scope;
        let mut owned = ScopedBuffer::try_with_capacity(
            scope,
            ResourceClass::Secret,
            "client.channel.data",
            bytes.len(),
        )?;
        owned.try_extend_from_slice(scope, bytes)?;
        self.send(Pending::Data {
            bytes: owned.erase(),
            offset: 0,
        })
    }

    async fn simple(&self, message: u8) -> Result<(), ScopedFault> {
        let state = self.state.get();
        let scope = &state.services.get().scope;
        let mut packet = packet::Packet::new(scope, "client.channel.control", 5)?;
        packet.byte(scope, message)?;
        packet.word(scope, state.remote)?;
        self.send(Pending::Packet {
            bytes: packet.finish().erase(),
            close: message == msg::CHANNEL_CLOSE,
        })
    }
    pub async fn eof(&self) -> Result<(), ScopedFault> {
        self.simple(msg::CHANNEL_EOF).await
    }
    pub async fn close(&self) -> Result<(), ScopedFault> {
        self.simple(msg::CHANNEL_CLOSE).await
    }

    /// 返回的数据根继续计费；连接的操作错误由 ScopedHandle 交付。
    pub async fn wait(&mut self) -> Result<Option<ScopedChannelMsg<S::Reservation>>, ScopedFault> {
        if let Some(fault) = self.state.get().services.get().failure() {
            return Err(fault);
        }
        let event = self.state.get_mut().events.recv().await;
        if let Some(fault) = self.state.get().services.get().failure() {
            return Err(fault);
        }
        Ok(match event {
            Some(Event::Data { bytes, extended }) => {
                let state = self.state.get();
                let count = u32::try_from(bytes.as_slice().len())
                    .map_err(|_| ScopedFault::overflow("client.channel.consumed"))?;
                if let Err(fault) = state.commands.try_send(
                    &state.services.get().scope,
                    "client.channel.credit.node",
                    Command::Consumed {
                        id: state.id,
                        bytes: count,
                    },
                ) {
                    state.services.get().fail(fault);
                    return Err(fault);
                }
                let data = bytes.into_typed()?;
                Some(match extended {
                    Some(ext) => ScopedChannelMsg::ExtendedData { data, ext },
                    None => ScopedChannelMsg::Data(data),
                })
            }
            Some(Event::Success) => Some(ScopedChannelMsg::Success),
            Some(Event::Failure) => Some(ScopedChannelMsg::Failure),
            Some(Event::Eof) => Some(ScopedChannelMsg::Eof),
            Some(Event::Close) => Some(ScopedChannelMsg::Close),
            Some(Event::ExitStatus(status)) => Some(ScopedChannelMsg::ExitStatus(status)),
            Some(Event::ExitSignal(bytes)) => {
                Some(ScopedChannelMsg::ExitSignal(bytes.into_typed()?))
            }
            Some(Event::Open { .. } | Event::OpenFailure(_)) | None => None,
        })
    }
}

fn find(session: &mut Session, id: u32) -> Option<&mut State> {
    let mut link = session.scoped_channels.as_mut();
    while let Some(node) = link {
        let state = node.get_mut();
        if state.id == id {
            return Some(state);
        }
        link = state.next.as_mut();
    }
    None
}

pub(super) fn next_id(session: &mut Session) -> Result<u32, RunError<Error, ScopedFault>> {
    let enc = session
        .common
        .encrypted
        .as_mut()
        .ok_or(Error::Inconsistent)?;
    if !matches!(
        enc.state,
        crate::session::EncryptedState::Authenticated
            | crate::session::EncryptedState::InitCompression
    ) {
        return Err(Error::NotAuthenticated.into());
    }
    enc.last_channel_id
        .0
        .checked_add(1)
        .ok_or_else(|| RunError::Runtime(ScopedFault::overflow("client.channel.id")))?;
    Ok(enc.new_channel_id().0)
}

pub(super) fn insert(session: &mut Session, mut node: ErasedRooted<State>) {
    node.get_mut().next = session.scoped_channels.take();
    session.scoped_channels = Some(node);
}

pub(super) fn command<S: AdmissionScope>(
    scope: &S,
    session: &mut Session,
    command: Command,
) -> Result<(), RunError<Error, ScopedFault>> {
    match command {
        Command::Open(mut node) => {
            node.get_mut().id = next_id(session)?;
            insert(session, node);
        }
        Command::Channel { id, pending } => {
            let state = find(session, id).ok_or(Error::WrongChannel)?;
            if !state.received_close && !state.sent_close {
                state
                    .pending_sender
                    .try_send(scope, "client.channel.pending.node", pending)
                    .map_err(RunError::Runtime)?;
            }
        }
        Command::Consumed { id, bytes } => {
            if let Some(state) = find(session, id) {
                state.credit = state.credit.checked_add(bytes).ok_or(Error::Inconsistent)?;
            }
        }
        Command::Authenticate(_) | Command::Keepalive { .. } | Command::Rekey => {
            return Err(Error::Inconsistent.into());
        }
    }
    Ok(())
}

pub(super) fn process<S: AdmissionScope>(
    scope: &S,
    session: &mut Session,
    bytes: &[u8],
) -> Result<bool, RunError<Error, ScopedFault>> {
    let Some(&message) = bytes.first() else {
        return Ok(false);
    };
    if !(msg::CHANNEL_OPEN_CONFIRMATION..=msg::CHANNEL_FAILURE).contains(&message) {
        return Ok(false);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.byte()?;
    let id = cursor.word()?;
    let Some(state) = find(session, id) else {
        return Ok(false);
    };
    let event = match message {
        msg::CHANNEL_OPEN_CONFIRMATION => {
            if state.confirmed || !state.open_sent {
                return Err(Error::Inconsistent.into());
            }
            state.remote = cursor.word()?;
            state.remote_window = cursor.word()?;
            state.remote_packet = cursor.word()?;
            if state.remote_packet == 0 {
                return Err(Error::Inconsistent.into());
            }
            state.confirmed = true;
            Event::Open {
                id,
                remote: state.remote,
            }
        }
        msg::CHANNEL_OPEN_FAILURE => {
            let reason = cursor.word()?;
            cursor.text()?;
            cursor.text()?;
            state.failed = true;
            Event::OpenFailure(reason)
        }
        msg::CHANNEL_WINDOW_ADJUST => {
            state.remote_window = state
                .remote_window
                .checked_add(cursor.word()?)
                .ok_or(Error::Inconsistent)?;
            cursor.finish()?;
            return Ok(true);
        }
        msg::CHANNEL_DATA | msg::CHANNEL_EXTENDED_DATA => {
            let extended = if message == msg::CHANNEL_EXTENDED_DATA {
                Some(cursor.word()?)
            } else {
                None
            };
            let data = cursor.string()?;
            cursor.finish()?;
            let len = u32::try_from(data.len()).map_err(|_| Error::Inconsistent)?;
            if !state.confirmed || len > state.local_packet {
                return Err(Error::Inconsistent.into());
            }
            state.local_window = state
                .local_window
                .checked_sub(len)
                .ok_or(Error::Inconsistent)?;
            if state.events.is_closed() {
                return Ok(true);
            }
            let mut owned = ScopedBuffer::try_with_capacity(
                scope,
                ResourceClass::Secret,
                "client.channel.incoming",
                data.len(),
            )
            .map_err(RunError::Runtime)?;
            owned
                .try_extend_from_slice(scope, data)
                .map_err(RunError::Runtime)?;
            Event::Data {
                bytes: owned.erase(),
                extended,
            }
        }
        msg::CHANNEL_SUCCESS => Event::Success,
        msg::CHANNEL_FAILURE => Event::Failure,
        msg::CHANNEL_EOF => Event::Eof,
        msg::CHANNEL_CLOSE => {
            state.received_close = true;
            Event::Close
        }
        msg::CHANNEL_REQUEST => {
            let name = cursor.text()?;
            let want_reply = cursor.byte()? != 0;
            let event = match name {
                "exit-status" => Event::ExitStatus(cursor.word()?),
                "exit-signal" => {
                    cursor.text()?;
                    cursor.byte()?;
                    cursor.text()?;
                    cursor.text()?;
                    let mut owned = ScopedBuffer::try_with_capacity(
                        scope,
                        ResourceClass::Secret,
                        "client.channel.exit",
                        bytes.len(),
                    )
                    .map_err(RunError::Runtime)?;
                    owned
                        .try_extend_from_slice(scope, bytes)
                        .map_err(RunError::Runtime)?;
                    Event::ExitSignal(owned.erase())
                }
                _ => {
                    if want_reply {
                        queue_reply(scope, state, msg::CHANNEL_FAILURE)?;
                    }
                    return Ok(true);
                }
            };
            if want_reply {
                queue_reply(scope, state, msg::CHANNEL_SUCCESS)?;
            }
            event
        }
        _ => return Ok(false),
    };
    cursor.finish()?;
    if !state.events.is_closed() {
        state
            .events
            .try_send(scope, "client.channel.event.node", event)
            .map_err(RunError::Runtime)?;
    }
    Ok(true)
}

fn queue_reply<S: AdmissionScope>(
    scope: &S,
    state: &State,
    message: u8,
) -> Result<(), RunError<Error, ScopedFault>> {
    let mut packet =
        packet::Packet::new(scope, "client.channel.reply", 5).map_err(RunError::Runtime)?;
    packet.byte(scope, message).map_err(RunError::Runtime)?;
    packet
        .word(scope, state.remote)
        .map_err(RunError::Runtime)?;
    state
        .pending_sender
        .try_send(
            scope,
            "client.channel.pending.node",
            Pending::Packet {
                bytes: packet.finish().erase(),
                close: false,
            },
        )
        .map_err(RunError::Runtime)
}

fn write<S: AdmissionScope>(
    scope: &S,
    writer: &mut crate::sshbuffer::PacketWriter,
    pending: &mut Option<super::WritePacket>,
    bytes: &[u8],
    scheduled: &mut u32,
    id: u32,
) -> Result<(), RunError<Error, ScopedFault>> {
    let output = writer
        .scoped_packet(scope, bytes)
        .map_err(RunError::Runtime)?;
    *pending = Some(super::WritePacket {
        bytes: output.erase(),
        offset: 0,
    });
    *scheduled = id;
    Ok(())
}

pub(super) async fn flush<S, B>(
    scope: &S,
    budget: &B,
    session: &mut Session,
) -> Result<(), RunError<Error, ScopedFault>>
where
    S: AdmissionScope,
    B: Cooperative,
{
    let mut link = &mut session.scoped_channels;
    while let Some(node) = link.as_ref() {
        std::future::poll_fn(|cx| budget.poll_budget(cx, 1)).await;
        let state = node.get();
        if state.failed || state.received_close && state.sent_close {
            let mut node = link.take().ok_or(Error::Inconsistent)?;
            node.get_mut().events.close();
            *link = node.get_mut().next.take();
        } else {
            link = &mut link.as_mut().ok_or(Error::Inconsistent)?.get_mut().next;
        }
    }
    let writer = &mut session.common.packet_writer;
    let output = &mut session.scoped_write;
    let scheduled = &mut session.scoped_last_channel;
    let pivot = *scheduled;
    for pass in 0..2 {
        let mut link = &mut session.scoped_channels;
        while let Some(node) = link {
            std::future::poll_fn(|cx| budget.poll_budget(cx, 1)).await;
            let state = node.get_mut();
            if (pass == 0 && state.id >= pivot) || (pass == 1 && state.id < pivot) {
                link = &mut node.get_mut().next;
                continue;
            }
            if !state.open_sent {
                if let Some(decision) = state.incoming.as_ref() {
                    let decision = *decision
                        .get()
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let reason = match decision {
                        super::incoming::Decision::Pending => {
                            link = &mut node.get_mut().next;
                            continue;
                        }
                        super::incoming::Decision::Accept => None,
                        super::incoming::Decision::Reject(reason) => Some(reason),
                    };
                    let mut packet = packet::Packet::new(scope, "client.channel.open.reply", 17)
                        .map_err(RunError::Runtime)?;
                    packet
                        .byte(
                            scope,
                            if reason.is_some() {
                                msg::CHANNEL_OPEN_FAILURE
                            } else {
                                msg::CHANNEL_OPEN_CONFIRMATION
                            },
                        )
                        .map_err(RunError::Runtime)?;
                    packet
                        .word(scope, state.remote)
                        .map_err(RunError::Runtime)?;
                    if let Some(reason) = reason {
                        packet.word(scope, reason).map_err(RunError::Runtime)?;
                        packet.string(scope, b"").map_err(RunError::Runtime)?;
                        packet.string(scope, b"").map_err(RunError::Runtime)?;
                    } else {
                        for word in [state.id, state.local_window, state.local_packet] {
                            packet.word(scope, word).map_err(RunError::Runtime)?;
                        }
                    }
                    write(
                        scope,
                        writer,
                        output,
                        packet.finish().as_slice(),
                        scheduled,
                        state.id,
                    )?;
                    state.open_sent = true;
                    state.confirmed = reason.is_none();
                    state.failed = reason.is_some();
                    state.incoming.take();
                    return Ok(());
                }
                let mut packet = packet::Packet::new(scope, "client.channel.open", 24)
                    .map_err(RunError::Runtime)?;
                packet
                    .byte(scope, msg::CHANNEL_OPEN)
                    .map_err(RunError::Runtime)?;
                packet
                    .string(scope, b"session")
                    .map_err(RunError::Runtime)?;
                for word in [state.id, state.local_window, state.local_packet] {
                    packet.word(scope, word).map_err(RunError::Runtime)?;
                }
                write(
                    scope,
                    writer,
                    output,
                    packet.finish().as_slice(),
                    scheduled,
                    state.id,
                )?;
                state.open_sent = true;
                return Ok(());
            }
            if state.confirmed {
                if (state.received_close || state.events.is_closed()) && !state.sent_close {
                    let mut packet = packet::Packet::new(scope, "client.channel.close", 5)
                        .map_err(RunError::Runtime)?;
                    packet
                        .byte(scope, msg::CHANNEL_CLOSE)
                        .map_err(RunError::Runtime)?;
                    packet
                        .word(scope, state.remote)
                        .map_err(RunError::Runtime)?;
                    write(
                        scope,
                        writer,
                        output,
                        packet.finish().as_slice(),
                        scheduled,
                        state.id,
                    )?;
                    state.sent_close = true;
                    state.current.take();
                    while state.pending.try_recv().is_some() {}
                    return Ok(());
                }
                if !state.sent_close && state.credit != 0 {
                    let mut packet = packet::Packet::new(scope, "client.channel.window", 9)
                        .map_err(RunError::Runtime)?;
                    packet
                        .byte(scope, msg::CHANNEL_WINDOW_ADJUST)
                        .map_err(RunError::Runtime)?;
                    packet
                        .word(scope, state.remote)
                        .map_err(RunError::Runtime)?;
                    packet
                        .word(scope, state.credit)
                        .map_err(RunError::Runtime)?;
                    write(
                        scope,
                        writer,
                        output,
                        packet.finish().as_slice(),
                        scheduled,
                        state.id,
                    )?;
                    state.local_window = state
                        .local_window
                        .checked_add(state.credit)
                        .ok_or(Error::Inconsistent)?;
                    state.credit = 0;
                    return Ok(());
                }
                if !state.sent_close && !state.received_close {
                    std::future::poll_fn(|cx| budget.poll_budget(cx, 1)).await;
                    if state.current.is_none() {
                        state.current = state.pending.try_recv();
                    }
                    if let Some(pending) = state.current.take() {
                        match pending {
                            Pending::Packet { bytes, close } => {
                                write(
                                    scope,
                                    writer,
                                    output,
                                    bytes.as_slice(),
                                    scheduled,
                                    state.id,
                                )?;
                                state.sent_close = close;
                            }
                            Pending::Data { bytes, mut offset } => {
                                let remaining =
                                    bytes.as_slice().get(offset..).ok_or(Error::Inconsistent)?;
                                let count = remaining
                                    .len()
                                    .min(state.remote_window as usize)
                                    .min(state.remote_packet as usize);
                                if count == 0 {
                                    state.current = Some(Pending::Data { bytes, offset });
                                    link = &mut node.get_mut().next;
                                    continue;
                                }
                                let size = packet::length("client.channel.output", &[9, count])
                                    .map_err(RunError::Runtime)?;
                                let mut packet =
                                    packet::Packet::new(scope, "client.channel.output", size)
                                        .map_err(RunError::Runtime)?;
                                packet
                                    .byte(scope, msg::CHANNEL_DATA)
                                    .map_err(RunError::Runtime)?;
                                packet
                                    .word(scope, state.remote)
                                    .map_err(RunError::Runtime)?;
                                let (chunk, _) = remaining.split_at(count);
                                packet.string(scope, chunk).map_err(RunError::Runtime)?;
                                write(
                                    scope,
                                    writer,
                                    output,
                                    packet.finish().as_slice(),
                                    scheduled,
                                    state.id,
                                )?;
                                state.remote_window -= count as u32;
                                offset += count;
                                if offset < bytes.as_slice().len() {
                                    state.current = Some(Pending::Data { bytes, offset });
                                }
                            }
                        }
                        return Ok(());
                    }
                }
            }
            if state.failed || state.received_close && state.sent_close {
                state.events.close();
            }
            link = &mut node.get_mut().next;
        }
    }
    Ok(())
}

pub(super) fn cleanup(session: &mut Session) {
    while let Some(mut node) = session.scoped_channels.take() {
        session.scoped_channels = node.get_mut().next.take();
        node.get_mut().events.close();
    }
}
