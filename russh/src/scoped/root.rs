use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, compiler_fence, fence};
use std::task::{Context, Poll};

use super::{AdmissionScope, FaultKind, ResourceClass, ResourceRequest, ScopedFault};

struct Header<R> {
    holders: AtomicUsize,
    layout: Layout,
    payload_offset: usize,
    payload_size: usize,
    initialized: AtomicBool,
    wipe: bool,
    drop_payload: unsafe fn(*mut u8),
    reservation: ManuallyDrop<R>,
}

/// 唯一跨库分配根。每个副本持有同一真实 header，不产生新分配。
///
/// 根自身不暴露 payload；`Rooted` 是唯一可访问 payload 的所有者。
/// 保留根只能延长生命期，不能取得数据引用或提前退还预约。
pub struct ResourceRoot<R> {
    header: NonNull<Header<R>>,
}

// payload 只通过带类型的唯一 Rooted 访问，且构造时要求 Send。
unsafe impl<R: Send + Sync> Send for ResourceRoot<R> {}
unsafe impl<R: Send + Sync> Sync for ResourceRoot<R> {}

impl<R> fmt::Debug for ResourceRoot<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceRoot")
            .field("layout", &self.layout())
            .finish_non_exhaustive()
    }
}

impl<R> ResourceRoot<R> {
    fn header(&self) -> &Header<R> {
        // 每个有效 ResourceRoot 都持有一个计数，header 不会提前释放。
        unsafe { self.header.as_ref() }
    }

    pub fn layout(&self) -> Layout {
        self.header().layout
    }

    pub fn payload_offset(&self) -> usize {
        self.header().payload_offset
    }

    pub fn holder_count(&self) -> usize {
        self.header().holders.load(Ordering::Acquire)
    }

    /// 可失败的显式持根。不作为 raw Waker 的不可失败 clone 实现。
    pub fn try_clone(&self) -> Result<Self, ScopedFault> {
        let holders = &self.header().holders;
        let mut count = holders.load(Ordering::Relaxed);
        loop {
            let next = count.checked_add(1).ok_or(ScopedFault {
                kind: FaultKind::CountBudget,
                site: "scoped.root.holders",
                requested: 1,
                available: Some(0),
            })?;
            match holders.compare_exchange_weak(count, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => {
                    return Ok(Self {
                        header: self.header,
                    });
                }
                Err(current) => count = current,
            }
        }
    }

    fn payload(&self) -> *mut u8 {
        // Layout::extend 已证明该 offset 位于同一 allocation 中。
        unsafe { self.header.as_ptr().cast::<u8>().add(self.payload_offset()) }
    }

    fn allocate<S: AdmissionScope<Reservation = R>>(
        scope: &S,
        class: ResourceClass,
        site: &'static str,
        payload: Layout,
        out_of_line_upper: usize,
        wipe: bool,
        drop_payload: unsafe fn(*mut u8),
    ) -> Result<Self, ScopedFault> {
        let (layout, payload_offset) = Self::allocation_layout(payload, site)?;
        let request = ResourceRequest {
            class,
            site,
            layout,
            out_of_line_upper,
            slots: 1,
        };
        request.bytes()?;
        let reservation = scope.try_reserve(request)?;
        // header 非空，layout 已检查；NULL 不触发 handle_alloc_error。
        let allocation = unsafe { alloc_zeroed(layout) };
        let Some(header) = NonNull::new(allocation.cast::<Header<R>>()) else {
            return Err(ScopedFault {
                kind: FaultKind::AllocationFailed,
                site,
                requested: layout.size(),
                available: None,
            });
        };
        unsafe {
            header.as_ptr().write(Header {
                holders: AtomicUsize::new(1),
                layout,
                payload_offset,
                payload_size: payload.size(),
                initialized: AtomicBool::new(false),
                wipe,
                drop_payload,
                reservation: ManuallyDrop::new(reservation),
            });
        }
        Ok(Self { header })
    }

    /// App 可在构造捕获图前互核实际 header + payload 布局。
    pub fn allocation_layout(
        payload: Layout,
        site: &'static str,
    ) -> Result<(Layout, usize), ScopedFault> {
        Layout::new::<Header<R>>()
            .extend(payload)
            .map(|(layout, offset)| (layout.pad_to_align(), offset))
            .map_err(|_| ScopedFault::overflow(site))
    }
}

// 析构 payload 即使 unwind，也必须先释放 backing，再退预约。
struct FinalRelease<R> {
    header: NonNull<Header<R>>,
}

impl<R> Drop for FinalRelease<R> {
    fn drop(&mut self) {
        unsafe {
            let header = self.header.as_ptr();
            let layout = (*header).layout;
            if (*header).wipe {
                let payload = header.cast::<u8>().add((*header).payload_offset);
                for offset in 0..(*header).payload_size {
                    ptr::write_volatile(payload.add(offset), 0);
                }
                compiler_fence(Ordering::SeqCst);
            }
            // grant 必须先移到栈；dealloc 后不再读取 header。
            let reservation = ManuallyDrop::take(&mut (*header).reservation);
            dealloc(header.cast::<u8>(), layout);
            drop(reservation);
        }
    }
}

impl<R> Drop for ResourceRoot<R> {
    fn drop(&mut self) {
        if self.header().holders.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        let _release = FinalRelease {
            header: self.header,
        };
        if self.header().initialized.swap(false, Ordering::AcqRel) {
            unsafe { (self.header().drop_payload)(self.payload()) };
        }
    }
}

unsafe fn drop_value<T>(payload: *mut u8) {
    unsafe { ptr::drop_in_place(payload.cast::<T>()) };
}

unsafe fn drop_bytes(_: *mut u8) {}

/// 单一 typed owner；移动此对象不会移动已分配的 T。
///
/// 不提供 Clone、into_inner 或裸指针逃逸；附加根仅延长生命期。
pub struct Rooted<T, R> {
    root: ResourceRoot<R>,
    value: PhantomData<T>,
}

// 移动句柄不会移动堆上的 payload；可变访问仍由 T: Unpin 或 Pin 投影约束。
impl<T, R> Unpin for Rooted<T, R> {}

pub(crate) struct ErasedRooted<T> {
    payload: NonNull<T>,
    header: NonNull<()>,
    release: unsafe fn(NonNull<()>),
}

// 唯一 typed owner 仅擦除 Reservation 类型，不改变 payload 或 header 的所有权。
unsafe impl<T: Send> Send for ErasedRooted<T> {}
unsafe impl<T: Sync> Sync for ErasedRooted<T> {}

impl<T> ErasedRooted<T> {
    pub(crate) fn get(&self) -> &T {
        unsafe { self.payload.as_ref() }
    }

    pub(crate) fn get_mut(&mut self) -> &mut T
    where
        T: Unpin,
    {
        unsafe { self.payload.as_mut() }
    }
}

pub(crate) struct ErasedShared<T> {
    payload: NonNull<T>,
    header: NonNull<()>,
    retain: unsafe fn(NonNull<()>) -> Result<NonNull<()>, ScopedFault>,
    release: unsafe fn(NonNull<()>),
}

unsafe impl<T: Send + Sync> Send for ErasedShared<T> {}
unsafe impl<T: Send + Sync> Sync for ErasedShared<T> {}

impl<T> ErasedShared<T> {
    pub(crate) fn get(&self) -> &T {
        unsafe { self.payload.as_ref() }
    }

    pub(crate) fn try_clone(&self) -> Result<Self, ScopedFault> {
        Ok(Self {
            payload: self.payload,
            header: unsafe { (self.retain)(self.header)? },
            retain: self.retain,
            release: self.release,
        })
    }
}

impl<T> Drop for ErasedShared<T> {
    fn drop(&mut self) {
        unsafe { (self.release)(self.header) };
    }
}

unsafe fn retain_erased<R>(header: NonNull<()>) -> Result<NonNull<()>, ScopedFault> {
    let root = ManuallyDrop::new(ResourceRoot::<R> {
        header: header.cast(),
    });
    let retained = ManuallyDrop::new(root.try_clone()?);
    Ok(retained.header.cast())
}

impl<T> fmt::Debug for ErasedRooted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rooted").finish_non_exhaustive()
    }
}

impl<T> Drop for ErasedRooted<T> {
    fn drop(&mut self) {
        unsafe { (self.release)(self.header) };
    }
}

unsafe fn release_erased<R>(header: NonNull<()>) {
    drop(ResourceRoot::<R> {
        header: header.cast(),
    });
}

/// 在真实 F 的布局已准入后擦除 poll 类型，不再分配 Box 或另一个 header。
pub struct RootedFuture<T, R> {
    root: ResourceRoot<R>,
    poll: unsafe fn(*mut u8, &mut Context<'_>) -> Poll<T>,
}

impl<T, R> Unpin for RootedFuture<T, R> {}

impl<T, R> Drop for RootedFuture<T, R> {
    fn drop(&mut self) {
        // 唯一 poll owner 先释放捕获图，打断内部 waker 引用环；header 与预约仍保留至最后根。
        let header = self.root.header();
        // late root 可并发借用 header；仅原子更新初始化位，不创建整个 Header 的独占引用。
        if header.initialized.swap(false, Ordering::AcqRel) {
            unsafe { (header.drop_payload)(self.root.payload()) };
        }
    }
}

impl<T, R> RootedFuture<T, R> {
    pub fn root(&self) -> &ResourceRoot<R> {
        &self.root
    }
}

impl<T, R> Future for RootedFuture<T, R> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = self.get_mut();
        unsafe { (this.poll)(this.root.payload(), cx) }
    }
}

unsafe fn poll_erased<F: Future>(payload: *mut u8, cx: &mut Context<'_>) -> Poll<F::Output> {
    unsafe { Pin::new_unchecked(&mut *payload.cast::<F>()) }.poll(cx)
}

/// 已准入并已分配、尚未构造 payload 的槽。取消构造仍先 free 再退额。
pub struct RootSlot<T, R> {
    root: ResourceRoot<R>,
    value: PhantomData<T>,
}

impl<T: Send + 'static, R: Send + Sync + 'static> RootSlot<T, R> {
    pub fn initialize(self, initialize: impl FnOnce() -> T) -> Rooted<T, R> {
        unsafe {
            self.root.payload().cast::<T>().write(initialize());
        }
        self.root
            .header()
            .initialized
            .store(true, Ordering::Release);
        Rooted {
            root: self.root,
            value: PhantomData,
        }
    }
}

/// 只读共享 payload；每个 holder 都持有同一真实 ResourceRoot。
pub struct Shared<T, R> {
    root: ResourceRoot<R>,
    value: PhantomData<T>,
}

impl<T, R> Unpin for Shared<T, R> {}

impl<T: Send + Sync + 'static, R: Send + Sync + 'static> Shared<T, R> {
    pub(crate) fn erase(self) -> ErasedShared<T> {
        let payload = unsafe { NonNull::new_unchecked(self.root.payload().cast::<T>()) };
        let root = ManuallyDrop::new(self.root);
        ErasedShared {
            payload,
            header: root.header.cast(),
            retain: retain_erased::<R>,
            release: release_erased::<R>,
        }
    }
    pub fn try_clone(&self) -> Result<Self, ScopedFault> {
        Ok(Self {
            root: self.root.try_clone()?,
            value: PhantomData,
        })
    }

    pub fn get(&self) -> &T {
        unsafe { &*self.root.payload().cast::<T>() }
    }

    pub fn root(&self) -> &ResourceRoot<R> {
        &self.root
    }
}

impl<T: Send + 'static, R: Send + Sync + 'static> Rooted<T, R> {
    /// `initialize` 在准入及 backing 分配之后执行。
    /// 捕获或初始化中的外置分配必须已有各自的真实根。
    pub fn try_new<S: AdmissionScope<Reservation = R>>(
        scope: &S,
        class: ResourceClass,
        site: &'static str,
        initialize: impl FnOnce() -> T,
    ) -> Result<Self, ScopedFault> {
        Ok(Self::try_allocate(scope, class, site)?.initialize(initialize))
    }

    pub fn try_allocate<S: AdmissionScope<Reservation = R>>(
        scope: &S,
        class: ResourceClass,
        site: &'static str,
    ) -> Result<RootSlot<T, R>, ScopedFault> {
        Self::try_allocate_with_source(scope, class, site, 0)
    }

    pub(crate) fn try_allocate_with_source<S: AdmissionScope<Reservation = R>>(
        scope: &S,
        class: ResourceClass,
        site: &'static str,
        out_of_line_upper: usize,
    ) -> Result<RootSlot<T, R>, ScopedFault> {
        let root = ResourceRoot::allocate(
            scope,
            class,
            site,
            Layout::new::<T>(),
            out_of_line_upper,
            class == ResourceClass::Secret,
            drop_value::<T>,
        )?;
        Ok(RootSlot {
            root,
            value: PhantomData,
        })
    }

    pub fn into_shared(self) -> Shared<T, R>
    where
        T: Sync,
    {
        Shared {
            root: self.root,
            value: PhantomData,
        }
    }

    pub(crate) fn erase(self) -> ErasedRooted<T> {
        let payload = unsafe { NonNull::new_unchecked(self.root.payload().cast::<T>()) };
        let root = ManuallyDrop::new(self.root);
        ErasedRooted {
            payload,
            header: root.header.cast(),
            release: release_erased::<R>,
        }
    }

    pub fn into_future(self) -> RootedFuture<T::Output, R>
    where
        T: Future,
    {
        RootedFuture {
            root: self.root,
            poll: poll_erased::<T>,
        }
    }
}

impl<T, R> Rooted<T, R> {
    pub fn root(&self) -> &ResourceRoot<R> {
        &self.root
    }

    pub fn get(&self) -> &T {
        unsafe { &*self.root.payload().cast::<T>() }
    }

    pub fn get_mut(&mut self) -> &mut T
    where
        T: Unpin,
    {
        unsafe { &mut *self.root.payload().cast::<T>() }
    }

    pub fn as_pin_mut(&mut self) -> Pin<&mut T> {
        // 唯一 typed owner，payload 不会移动；最后根负责原位析构。
        unsafe { Pin::new_unchecked(&mut *self.root.payload().cast::<T>()) }
    }
}

impl<T, R> fmt::Debug for Shared<T, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl<T, R> fmt::Debug for Rooted<T, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rooted").field("root", &self.root).finish()
    }
}

/// 精确容量的字节 backing。增长先预约并分配新块，旧块仍持额。
///
/// Secret 块全部 capacity 在最终 free 前 volatile 清零；clear/truncate
/// 不归还容量，也不以逻辑长度代替需要擦除的完整区域。
pub struct ScopedBuffer<R> {
    root: ResourceRoot<R>,
    len: usize,
    capacity: usize,
    class: ResourceClass,
    site: &'static str,
}

pub(crate) struct ErasedBuffer {
    payload: NonNull<u8>,
    header: NonNull<()>,
    release: unsafe fn(NonNull<()>),
    len: usize,
    capacity: usize,
    class: ResourceClass,
    site: &'static str,
    reservation: std::any::TypeId,
}

unsafe impl Send for ErasedBuffer {}
unsafe impl Sync for ErasedBuffer {}

impl ErasedBuffer {
    pub(crate) fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.payload.as_ptr(), self.len) }
    }

    pub(crate) fn into_typed<R: Send + Sync + 'static>(
        self,
    ) -> Result<ScopedBuffer<R>, ScopedFault> {
        if self.reservation != std::any::TypeId::of::<R>() {
            return Err(ScopedFault {
                kind: super::FaultKind::PolicyUnavailable,
                site: "buffer.reservation_type",
                requested: 0,
                available: None,
            });
        }
        let this = ManuallyDrop::new(self);
        Ok(ScopedBuffer {
            root: ResourceRoot {
                header: this.header.cast(),
            },
            len: this.len,
            capacity: this.capacity,
            class: this.class,
            site: this.site,
        })
    }
}

impl fmt::Debug for ErasedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedBuffer")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Drop for ErasedBuffer {
    fn drop(&mut self) {
        unsafe { (self.release)(self.header) };
    }
}

impl<R: Send + Sync + 'static> ScopedBuffer<R> {
    pub(crate) fn erase(self) -> ErasedBuffer {
        let payload = unsafe { NonNull::new_unchecked(self.root.payload()) };
        let root = ManuallyDrop::new(self.root);
        ErasedBuffer {
            payload,
            header: root.header.cast(),
            release: release_erased::<R>,
            len: self.len,
            capacity: self.capacity,
            class: self.class,
            site: self.site,
            reservation: std::any::TypeId::of::<R>(),
        }
    }

    pub fn try_resize<S: AdmissionScope<Reservation = R>>(
        &mut self,
        scope: &S,
        len: usize,
        value: u8,
    ) -> Result<(), ScopedFault> {
        if len > self.len {
            self.try_reserve(scope, len - self.len)?;
            unsafe {
                std::slice::from_raw_parts_mut(self.root.payload().add(self.len), len - self.len)
            }
            .fill(value);
        }
        self.len = len;
        Ok(())
    }
    pub fn try_with_capacity<S: AdmissionScope<Reservation = R>>(
        scope: &S,
        class: ResourceClass,
        site: &'static str,
        capacity: usize,
    ) -> Result<Self, ScopedFault> {
        let layout = Layout::array::<u8>(capacity).map_err(|_| ScopedFault::overflow(site))?;
        let root = ResourceRoot::allocate(
            scope,
            class,
            site,
            layout,
            0,
            class == ResourceClass::Secret,
            drop_bytes,
        )?;
        Ok(Self {
            root,
            len: 0,
            capacity,
            class,
            site,
        })
    }

    pub fn root(&self) -> &ResourceRoot<R> {
        &self.root
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.root.payload(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.root.payload(), self.len) }
    }

    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn try_reserve<S: AdmissionScope<Reservation = R>>(
        &mut self,
        scope: &S,
        additional: usize,
    ) -> Result<(), ScopedFault> {
        let capacity = self
            .len
            .checked_add(additional)
            .ok_or_else(|| ScopedFault::overflow(self.site))?;
        if capacity <= self.capacity {
            return Ok(());
        }
        let mut next = Self::try_with_capacity(scope, self.class, self.site, capacity)?;
        unsafe {
            ptr::copy_nonoverlapping(self.root.payload(), next.root.payload(), self.len);
        }
        next.len = self.len;
        *self = next;
        Ok(())
    }

    pub fn try_extend_from_slice<S: AdmissionScope<Reservation = R>>(
        &mut self,
        scope: &S,
        bytes: &[u8],
    ) -> Result<(), ScopedFault> {
        self.try_reserve(scope, bytes.len())?;
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.root.payload().add(self.len),
                bytes.len(),
            );
        }
        self.len += bytes.len();
        Ok(())
    }
}

impl<R> fmt::Debug for ScopedBuffer<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedBuffer")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}
