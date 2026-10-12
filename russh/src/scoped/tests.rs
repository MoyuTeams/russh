// 测试中的 unwrap 将意外错误直接转为断言失败。
#![allow(clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[test]
fn algorithm_selection_preserves_protocol_names_without_allocating() {
    assert_no_allocations(|| {
        for name in crate::cipher::ALL_CIPHERS {
            assert_eq!(
                crate::cipher::Name::try_from(name.as_ref()).unwrap(),
                **name
            );
            assert!(crate::cipher::CIPHERS.get(name).is_some());
        }
        for name in crate::mac::ALL_MAC_ALGORITHMS {
            assert_eq!(crate::mac::Name::try_from(name.as_ref()).unwrap(), **name);
            assert!(crate::mac::MACS.get(name).is_some());
        }
        for name in crate::kex::ALL_KEX_ALGORITHMS {
            assert_eq!(crate::kex::Name::try_from(name.as_ref()).unwrap(), **name);
            assert!(crate::kex::KEXES.get(name).is_some());
        }
        assert!(crate::cipher::Name::try_from("not-an-ssh-cipher").is_err());
        assert!(crate::mac::Name::try_from("not-an-ssh-mac").is_err());
        assert!(crate::kex::Name::try_from("not-an-ssh-kex").is_err());
    });
}

#[test]
fn erased_future_releases_captures_without_refunding_late_header() {
    struct Capture(Arc<AtomicUsize>);
    impl Drop for Capture {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let scope = Scope::new(usize::MAX);
    let dropped = Arc::new(AtomicUsize::new(0));
    let capture = Capture(dropped.clone());
    let mut future = Rooted::try_new(
        &scope,
        ResourceClass::Runtime,
        "future.erased",
        || async move {
            std::future::pending::<()>().await;
            drop(capture);
        },
    )
    .unwrap()
    .into_future();
    let late = future.root().try_clone().unwrap();
    let held = scope.held();
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    assert!(std::future::Future::poll(std::pin::Pin::new(&mut future), &mut cx).is_pending());
    drop(future);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(scope.held(), held);
    drop(late);
    assert_eq!(scope.held(), 0);
}

#[derive(Clone, Copy, Default)]
struct Observation {
    size: usize,
    align: usize,
    attempts: usize,
    fail: bool,
    address: usize,
    wipe_offset: usize,
    wipe_len: usize,
    freed: bool,
    zero_at_free: bool,
    refund_after_free: Option<bool>,
    reservation_id: usize,
    all_allocations: bool,
}

#[test]
fn future_drop_allows_concurrent_late_header_read_and_clone() {
    struct Capture {
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Capture {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            self.entered.wait();
            self.release.wait();
        }
    }
    let scope = Scope::new(usize::MAX);
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let dropped = Arc::new(AtomicUsize::new(0));
    let capture = Capture {
        entered: entered.clone(),
        release: release.clone(),
        dropped: dropped.clone(),
    };
    let future = Rooted::try_new(
        &scope,
        ResourceClass::Runtime,
        "future.concurrent",
        || async move {
            std::future::pending::<()>().await;
            drop(capture);
        },
    )
    .unwrap()
    .into_future();
    let late = future.root().try_clone().unwrap();
    let reader = late.try_clone().unwrap();
    let layout = late.layout();
    let offset = late.payload_offset();
    let held = scope.held();
    let thread = std::thread::spawn(move || {
        entered.wait();
        for _ in 0..1024 {
            assert_eq!(reader.layout(), layout);
            assert_eq!(reader.payload_offset(), offset);
            let cloned = reader.try_clone().unwrap();
            assert!(cloned.holder_count() >= 3);
            drop(cloned);
        }
        release.wait();
        reader
    });
    drop(future);
    let reader = thread.join().unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(scope.held(), held);
    drop(reader);
    assert_eq!(scope.held(), held);
    drop(late);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(scope.held(), 0);
}

thread_local! {
    static OBSERVATION: Cell<Observation> = const { Cell::new(Observation {
        size: 0, align: 0, attempts: 0, fail: false, address: 0,
        wipe_offset: 0, wipe_len: 0, freed: false, zero_at_free: false,
        refund_after_free: None,
        reservation_id: 1,
        all_allocations: false,
    }) };
}

struct Recorder;

#[global_allocator]
static ALLOCATOR: Recorder = Recorder;

impl Recorder {
    fn fail(layout: Layout) -> bool {
        OBSERVATION
            .try_with(|cell| {
                let mut observation = cell.get();
                if !observation.all_allocations
                    && (layout.size() != observation.size || layout.align() != observation.align)
                {
                    return false;
                }
                observation.attempts += 1;
                let fail = observation.fail;
                observation.fail = false;
                cell.set(observation);
                fail
            })
            .unwrap_or(false)
    }

    fn record(pointer: *mut u8, layout: Layout) {
        let _ = OBSERVATION.try_with(|cell| {
            let mut observation = cell.get();
            if layout.size() == observation.size
                && layout.align() == observation.align
                && observation.address == 0
            {
                observation.address = pointer as usize;
                cell.set(observation);
            }
        });
    }
}

unsafe impl GlobalAlloc for Recorder {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if Self::fail(layout) {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        Self::record(pointer, layout);
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if Self::fail(layout) {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc_zeroed(layout) };
        Self::record(pointer, layout);
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = OBSERVATION.try_with(|cell| {
            let mut observation = cell.get();
            if pointer as usize == observation.address && observation.address != 0 {
                observation.zero_at_free = (0..observation.wipe_len).all(|offset| unsafe {
                    pointer.add(observation.wipe_offset + offset).read() == 0
                });
                observation.freed = true;
                cell.set(observation);
            }
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[derive(Default)]
struct State {
    held: AtomicUsize,
    peak: AtomicUsize,
    requests: AtomicUsize,
    refunds: AtomicUsize,
    limit: AtomicUsize,
}

#[derive(Clone)]
pub(crate) struct Scope(Arc<State>);

impl Scope {
    pub(crate) fn new(limit: usize) -> Self {
        Self(Arc::new(State {
            limit: AtomicUsize::new(limit),
            ..State::default()
        }))
    }

    pub(crate) fn held(&self) -> usize {
        self.0.held.load(Ordering::SeqCst)
    }

    pub(crate) fn freeze(&self) {
        self.0.limit.store(self.held(), Ordering::SeqCst);
    }
}

pub(crate) struct Reservation {
    state: Arc<State>,
    bytes: usize,
    id: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.state.held.fetch_sub(self.bytes, Ordering::SeqCst);
        self.state.refunds.fetch_add(1, Ordering::SeqCst);
        let _ = OBSERVATION.try_with(|cell| {
            let mut observation = cell.get();
            if self.id != observation.reservation_id {
                return;
            }
            observation.refund_after_free = Some(observation.freed);
            cell.set(observation);
        });
    }
}

impl AdmissionScope for Scope {
    type Reservation = Reservation;

    fn try_reserve(&self, request: ResourceRequest) -> Result<Reservation, ScopedFault> {
        let id = self.0.requests.fetch_add(1, Ordering::SeqCst) + 1;
        let bytes = request.bytes()?;
        let limit = self.0.limit.load(Ordering::SeqCst);
        let mut held = self.held();
        loop {
            let next = held
                .checked_add(bytes)
                .filter(|&next| next <= limit)
                .ok_or(ScopedFault {
                    kind: FaultKind::ByteBudget,
                    site: request.site,
                    requested: bytes,
                    available: Some(limit.saturating_sub(held)),
                })?;
            match self
                .0
                .held
                .compare_exchange_weak(held, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    self.0.peak.fetch_max(next, Ordering::SeqCst);
                    return Ok(Reservation {
                        state: self.0.clone(),
                        bytes,
                        id,
                    });
                }
                Err(current) => held = current,
            }
        }
    }
}

fn watch(payload: Layout, fail: bool) -> Layout {
    let (layout, offset) = ResourceRoot::<Reservation>::allocation_layout(payload, "test").unwrap();
    OBSERVATION.set(Observation {
        size: layout.size(),
        align: layout.align(),
        fail,
        wipe_offset: offset,
        wipe_len: payload.size(),
        reservation_id: 1,
        ..Observation::default()
    });
    layout
}

fn finish_watch() -> Observation {
    OBSERVATION.replace(Observation::default())
}

pub(crate) fn assert_no_allocations<T>(action: impl FnOnce() -> T) -> T {
    OBSERVATION.set(Observation {
        all_allocations: true,
        ..Observation::default()
    });
    let result = action();
    assert_eq!(finish_watch().attempts, 0);
    result
}

pub(crate) fn assert_secret_release(
    scope: &Scope,
    bytes: ScopedBuffer<Reservation>,
    release: impl FnOnce(ScopedBuffer<Reservation>),
) {
    let offset = bytes.root().payload_offset();
    OBSERVATION.set(Observation {
        size: bytes.root().layout().size(),
        align: bytes.root().layout().align(),
        address: bytes.as_slice().as_ptr() as usize - offset,
        wipe_offset: offset,
        wipe_len: bytes.capacity(),
        reservation_id: scope.0.requests.load(Ordering::SeqCst),
        ..Observation::default()
    });
    release(bytes);
    let observation = finish_watch();
    assert!(observation.freed);
    assert!(observation.zero_at_free);
    assert_eq!(observation.refund_after_free, Some(true));
}

#[test]
fn quota_denial_precedes_allocator_and_initialization() {
    let scope = Scope::new(0);
    watch(Layout::new::<[u8; 317]>(), false);
    let initialized = Cell::new(false);
    let result = Rooted::try_new(&scope, ResourceClass::Runtime, "test", || {
        initialized.set(true);
        [0u8; 317]
    });
    let observation = finish_watch();
    assert_eq!(result.unwrap_err().kind, FaultKind::ByteBudget);
    assert!(!initialized.get());
    assert_eq!(observation.attempts, 0);
    assert_eq!(scope.held(), 0);
}

#[test]
fn allocator_null_refunds_without_initializing() {
    let scope = Scope::new(usize::MAX);
    watch(Layout::new::<[u8; 317]>(), true);
    let initialized = Cell::new(false);
    let result = Rooted::try_new(&scope, ResourceClass::Runtime, "test", || {
        initialized.set(true);
        [0u8; 317]
    });
    let observation = finish_watch();
    assert_eq!(result.unwrap_err().kind, FaultKind::AllocationFailed);
    assert_eq!(observation.attempts, 1);
    assert!(!initialized.get());
    assert_eq!(scope.held(), 0);
    assert_eq!(scope.0.refunds.load(Ordering::SeqCst), 1);
}

#[test]
fn final_holder_frees_header_before_refund() {
    let scope = Scope::new(usize::MAX);
    let layout = watch(Layout::new::<[u8; 317]>(), false);
    let value = Rooted::try_new(&scope, ResourceClass::Runtime, "test", || [42u8; 317]).unwrap();
    let late = value.root().try_clone().unwrap();
    assert_eq!(late.layout(), layout);
    drop(value);
    assert_eq!(scope.held(), layout.size());
    assert!(!OBSERVATION.get().freed);
    drop(late);
    let observation = finish_watch();
    assert!(observation.freed);
    assert_eq!(observation.refund_after_free, Some(true));
    assert_eq!(scope.held(), 0);
}

#[test]
fn secret_capacity_is_wiped_after_truncate_and_last_holder() {
    let scope = Scope::new(usize::MAX);
    watch(Layout::array::<u8>(317).unwrap(), false);
    let mut bytes =
        ScopedBuffer::try_with_capacity(&scope, ResourceClass::Secret, "test", 317).unwrap();
    bytes.try_extend_from_slice(&scope, &[0x93; 317]).unwrap();
    bytes.truncate(1);
    bytes.clear();
    let late = bytes.root().try_clone().unwrap();
    drop(bytes);
    assert!(!OBSERVATION.get().freed);
    drop(late);
    let observation = finish_watch();
    assert!(observation.zero_at_free);
    assert_eq!(observation.refund_after_free, Some(true));
}

#[test]
fn growth_charges_overlap_and_wipes_old_capacity() {
    let scope = Scope::new(usize::MAX);
    let old_layout = watch(Layout::array::<u8>(317).unwrap(), false);
    let mut bytes =
        ScopedBuffer::try_with_capacity(&scope, ResourceClass::Secret, "test", 317).unwrap();
    bytes.try_extend_from_slice(&scope, &[0x93; 317]).unwrap();
    bytes.try_extend_from_slice(&scope, &[0x42; 211]).unwrap();
    let observation = finish_watch();
    let new_size = bytes.root().layout().size();
    assert_eq!(
        scope.0.peak.load(Ordering::SeqCst),
        old_layout.size() + new_size
    );
    assert!(observation.zero_at_free);
    assert_eq!(observation.refund_after_free, Some(true));
    assert_eq!(bytes.capacity(), 528);
    assert_eq!(bytes.as_slice().get(..317).unwrap(), &[0x93; 317]);
    assert_eq!(bytes.as_slice().get(317..).unwrap(), &[0x42; 211]);
    assert_eq!(scope.held(), new_size);
    drop(bytes);
    assert_eq!(scope.held(), 0);
}

#[test]
fn rejected_growth_preserves_old_root_and_bytes() {
    let scope = Scope::new(usize::MAX);
    let mut bytes =
        ScopedBuffer::try_with_capacity(&scope, ResourceClass::Secret, "test", 317).unwrap();
    bytes.try_extend_from_slice(&scope, &[0x93; 317]).unwrap();
    let old_pointer = bytes.as_slice().as_ptr();
    let old_held = scope.held();
    scope.0.limit.store(old_held, Ordering::SeqCst);
    watch(Layout::array::<u8>(318).unwrap(), false);
    let result = bytes.try_extend_from_slice(&scope, &[1]);
    let observation = finish_watch();
    assert_eq!(result.unwrap_err().kind, FaultKind::ByteBudget);
    assert_eq!(observation.attempts, 0);
    assert_eq!(bytes.as_slice().as_ptr(), old_pointer);
    assert_eq!(bytes.as_slice(), &[0x93; 317]);
    assert_eq!(scope.held(), old_held);
}

#[test]
fn allocation_failure_on_growth_preserves_old_root() {
    let scope = Scope::new(usize::MAX);
    let mut bytes =
        ScopedBuffer::try_with_capacity(&scope, ResourceClass::Secret, "test", 317).unwrap();
    bytes.try_extend_from_slice(&scope, &[0x93; 317]).unwrap();
    let old_pointer = bytes.as_slice().as_ptr();
    let old_held = scope.held();
    watch(Layout::array::<u8>(318).unwrap(), true);
    let result = bytes.try_extend_from_slice(&scope, &[1]);
    let observation = finish_watch();
    assert_eq!(result.unwrap_err().kind, FaultKind::AllocationFailed);
    assert_eq!(observation.attempts, 1);
    assert_eq!(bytes.as_slice().as_ptr(), old_pointer);
    assert_eq!(bytes.as_slice(), &[0x93; 317]);
    assert_eq!(scope.held(), old_held);
}

#[test]
fn layout_overflow_precedes_admission() {
    let scope = Scope::new(usize::MAX);
    let result =
        ScopedBuffer::try_with_capacity(&scope, ResourceClass::Runtime, "test", usize::MAX);
    assert_eq!(result.unwrap_err().kind, FaultKind::LayoutOverflow);
    assert_eq!(scope.0.requests.load(Ordering::SeqCst), 0);
}

#[test]
#[allow(clippy::panic)] // 故障注入：验证初始化 unwind 的资源释放。
fn initialization_unwind_releases_uninitialized_backing() {
    let scope = Scope::new(usize::MAX);
    watch(Layout::new::<[u8; 317]>(), false);
    let result = std::panic::catch_unwind(|| {
        let _ = Rooted::<[u8; 317], _>::try_new(&scope, ResourceClass::Secret, "test", || {
            panic!("受控初始化中断")
        });
    });
    let observation = finish_watch();
    assert!(result.is_err());
    assert!(observation.freed);
    assert!(observation.zero_at_free);
    assert_eq!(observation.refund_after_free, Some(true));
    assert_eq!(scope.held(), 0);
}

#[test]
#[allow(clippy::panic)] // 故障注入：验证 payload 析构 unwind 的资源释放。
fn payload_unwind_still_wipes_and_frees_before_refund() {
    struct Payload([u8; 317]);
    impl Drop for Payload {
        fn drop(&mut self) {
            assert_eq!(self.0[0], 0x93);
            panic!("受控析构中断");
        }
    }
    let scope = Scope::new(usize::MAX);
    watch(Layout::new::<Payload>(), false);
    let owner = Rooted::try_new(&scope, ResourceClass::Secret, "test", || {
        Payload([0x93; 317])
    })
    .unwrap();
    let result = std::panic::catch_unwind(|| drop(owner));
    let observation = finish_watch();
    assert!(result.is_err());
    assert!(observation.zero_at_free);
    assert_eq!(observation.refund_after_free, Some(true));
    assert_eq!(scope.held(), 0);
}

#[test]
fn over_aligned_payload_and_zero_sized_payload() {
    #[repr(align(256))]
    struct Aligned(u8);
    let scope = Scope::new(usize::MAX);
    let mut value =
        Rooted::try_new(&scope, ResourceClass::Runtime, "test", || Aligned(42)).unwrap();
    assert_eq!(value.get() as *const Aligned as usize % 256, 0);
    assert_eq!(value.root().layout().align(), 256);
    value.get_mut().0 = 12;
    assert_eq!(value.get().0, 12);
    let empty = Rooted::try_new(&scope, ResourceClass::Control, "test", || ()).unwrap();
    assert!(empty.root().layout().size() > 0);
    drop((value, empty));
    assert_eq!(scope.held(), 0);
}

#[test]
fn rooted_future_ready_does_not_release_late_waker_root() {
    struct WakeRoot(ResourceRoot<Reservation>);
    impl std::task::Wake for WakeRoot {
        fn wake(self: Arc<Self>) {
            let _ = self.0.holder_count();
        }
    }
    let scope = Scope::new(usize::MAX);
    let payload =
        ScopedBuffer::try_with_capacity(&scope, ResourceClass::Secret, "capture", 32).unwrap();
    let future = async move {
        drop(payload);
        42
    };
    let expected =
        ResourceRoot::<Reservation>::allocation_layout(Layout::for_value(&future), "future")
            .unwrap();
    let mut owner = Rooted::try_new(&scope, ResourceClass::Runtime, "future", || future).unwrap();
    assert_eq!(owner.root().layout(), expected.0);
    let waker = std::task::Waker::from(Arc::new(WakeRoot(owner.root().try_clone().unwrap())));
    let mut context = Context::from_waker(&waker);
    assert_eq!(owner.as_pin_mut().poll(&mut context), Poll::Ready(42));
    assert_eq!(scope.held(), expected.0.size());
    drop(owner);
    assert_eq!(scope.held(), expected.0.size());
    drop(waker);
    assert_eq!(scope.held(), 0);
}

#[test]
fn last_holder_on_another_thread_drops_payload_once() {
    struct Payload(Arc<AtomicUsize>);
    impl Drop for Payload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let scope = Scope::new(usize::MAX);
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Rooted::try_new(&scope, ResourceClass::Runtime, "test", || {
        Payload(drops.clone())
    })
    .unwrap();
    let late = owner.root().try_clone().unwrap();
    drop(owner);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    std::thread::spawn(move || drop(late)).join().unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(scope.held(), 0);
}
