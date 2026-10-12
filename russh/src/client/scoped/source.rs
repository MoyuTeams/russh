use std::alloc::Layout;
use std::mem::MaybeUninit;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::task::Waker;

use crate::scoped::ScopedFault;

const SITE: &str = "client.initial.source";

fn add(left: usize, right: usize) -> Result<usize, ScopedFault> {
    left.checked_add(right)
        .ok_or_else(|| ScopedFault::overflow(SITE))
}

// 对字段重排也成立的布局上界：各字段自身尺寸、各字段前最大 padding、尾 padding。
fn fields(layouts: &[Layout]) -> Result<usize, ScopedFault> {
    let mut total = 0;
    let mut alignment = 1;
    for layout in layouts {
        total = add(total, add(layout.size(), layout.align() - 1)?)?;
        alignment = alignment.max(layout.align());
    }
    add(total, alignment - 1)
}

fn arc(data: Layout) -> Result<usize, ScopedFault> {
    fields(&[
        Layout::new::<AtomicUsize>(),
        Layout::new::<AtomicUsize>(),
        data,
    ])
}

pub(super) fn initial<T>() -> Result<usize, ScopedFault> {
    let mut bytes = 0;
    let signal = fields(&[
        Layout::new::<AtomicUsize>(),
        Layout::new::<Option<()>>(),
        Layout::new::<MaybeUninit<Waker>>(),
        Layout::new::<MaybeUninit<Waker>>(),
    ])?;
    bytes = add(
        bytes,
        arc(
            Layout::from_size_align(signal, Layout::new::<Waker>().align())
                .map_err(|_| ScopedFault::overflow(SITE))?,
        )?,
    )?;
    let split = fields(&[Layout::new::<Mutex<T>>(), Layout::new::<bool>()])?;
    bytes = add(
        bytes,
        arc(
            Layout::from_size_align(split, Layout::new::<Mutex<T>>().align())
                .map_err(|_| ScopedFault::overflow(SITE))?,
        )?,
    )?;
    // SSH identification 的协议行长上限；读取暂存内联在 SshRead 中。
    add(bytes, 255)
}
