//! 显式资源准入与真实分配根。
//!
//! 预约随 backing 转移，在最后持有者释放 backing 和 header 后归还。
//! 这些类型不安装线程局部 runtime，也不改变 legacy 客户端的执行方式。
//!
//! `client::connect_stream_scoped` 是显式实验接口；本模块的实际分配根保证
//! 不等于整条 SSH 连接的累计活图、第三方分配或秘密全链已获证。

use std::alloc::Layout;
use std::future::Future;
use std::task::{Context, Poll};
use std::time::Instant;

mod root;
pub(crate) use root::{ErasedBuffer, ErasedRooted, ErasedShared};
pub(crate) mod queue;
pub use root::{ResourceRoot, RootSlot, Rooted, RootedFuture, ScopedBuffer, Shared};

/// 应用将用途映射到同一进程账本，不另建独立配额。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceClass {
    Runtime,
    Secret,
    Control,
    Persistent,
    Source,
}

/// `layout` 包含真实 header、对齐和 padding；外置容量不得重复计费。
#[derive(Clone, Copy, Debug)]
pub struct ResourceRequest {
    pub class: ResourceClass,
    pub site: &'static str,
    pub layout: Layout,
    pub out_of_line_upper: usize,
    pub slots: usize,
}

impl ResourceRequest {
    pub fn bytes(self) -> Result<usize, ScopedFault> {
        self.layout
            .size()
            .checked_add(self.out_of_line_upper)
            .ok_or_else(|| ScopedFault::overflow(self.site))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultKind {
    ByteBudget,
    CountBudget,
    InflightBudget,
    AllocationFailed,
    LayoutOverflow,
    Cancelled,
    PolicyUnavailable,
}

/// 固定字段错误不持有认证载荷或动态诊断字符串。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedFault {
    pub kind: FaultKind,
    pub site: &'static str,
    pub requested: usize,
    pub available: Option<usize>,
}

impl ScopedFault {
    pub(crate) fn overflow(site: &'static str) -> Self {
        Self {
            kind: FaultKind::LayoutOverflow,
            site,
            requested: usize::MAX,
            available: None,
        }
    }
}

impl std::fmt::Display for ScopedFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at {}", self.kind, self.site)
    }
}

impl std::error::Error for ScopedFault {}

/// 不经旧认证错误映射的独立错误通道。
#[derive(Debug)]
pub enum ScopedError<E> {
    Resource(ScopedFault),
    Operation(E),
}

pub type ScopedResult<T, E> = Result<T, ScopedError<E>>;

/// Reservation 是 move-only 预约；其 Drop 必须不 unwind。
///
/// 实现必须先在原账本预约完整请求，再返回成功。失效只禁止新预约，
/// 不撤销现存 Reservation。共享元数据应传递已有根，不重复预约。
pub trait AdmissionScope {
    type Reservation: Send + Sync + 'static;

    fn try_reserve(&self, request: ResourceRequest) -> Result<Self::Reservation, ScopedFault>;
}

/// 接收尚未装箱的真实 future；实现负责计算自身 task header 与 F 的布局。
///
/// F 的捕获图在构造前须已预约。Task ready/join 不可提前退还 task 的预约；
/// late waker、取消句柄及结果持有的 backing 必须释放后才归还对应额度。
pub trait ScopedSpawner<S: AdmissionScope> {
    type Task<T: Send + 'static>: ScopedTask<Output = Result<T, ScopedFault>> + Send + Unpin;

    fn try_spawn<F>(&self, scope: &S, future: F) -> Result<Self::Task<F::Output>, ScopedFault>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

/// cancel 只撤销后续执行；task/waker/completion 的实际根仍由最后持有者释放。
pub trait ScopedTask: Future {
    fn cancel(&self);
}

/// Sleep 的 registration 由实际持有者保留预约；Drop 撤销交付资格。
/// 已排队的回调仍须持根，reset 必须在增长前预约且失败时保留原根。
pub trait ScopedClock {
    type Sleep: Future<Output = Result<(), ScopedFault>> + Send;

    fn now(&self) -> Instant;
    fn sleep_until(&self, deadline: Instant) -> Result<Self::Sleep, ScopedFault>;
    fn reset(
        &self,
        sleep: std::pin::Pin<&mut Self::Sleep>,
        deadline: Instant,
    ) -> Result<(), ScopedFault>;
}

/// 每轮 task poll 重置预算；Pending 必须登记一次无分配 wake。
pub trait Cooperative {
    fn begin_poll(&self);
    fn poll_budget(&self, cx: &mut Context<'_>, work_units: usize) -> Poll<()>;
}

#[cfg(test)]
pub(crate) mod tests;
