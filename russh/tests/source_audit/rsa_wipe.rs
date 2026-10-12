//! 独立依赖审计：检查合成 RSA 密钥的 CRT 素数 backing 在 dealloc 前是否擦除。
//! 用当前锁依赖构建的 rsa/rand rlib 编译运行；失败表示秘密闭包门槛未满足。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rsa::traits::{PrivateKeyParts, PublicKeyParts};

static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static LENGTH: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicBool = AtomicBool::new(false);
static WIPED: AtomicBool = AtomicBool::new(false);

struct Recorder;
#[global_allocator]
static ALLOCATOR: Recorder = Recorder;

unsafe impl GlobalAlloc for Recorder {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if pointer as usize == ADDRESS.load(Ordering::SeqCst)
            && layout.size() == LENGTH.load(Ordering::SeqCst)
        {
            let zero = (0..layout.size()).all(|index| unsafe { pointer.add(index).read() == 0 });
            WIPED.store(zero, Ordering::SeqCst);
            FREED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}

fn main() -> std::process::ExitCode {
    let generated = rsa::RsaPrivateKey::new(&mut rand::rng(), 2048).expect("合成密钥");
    let key = rsa::RsaPrivateKey::from_components(
        generated.n().as_ref().clone(),
        generated.e().clone(),
        generated.d().clone(),
        generated.primes().to_vec(),
    )
    .expect("加载密钥组件");
    drop(generated);
    let limbs = key
        .p_params()
        .expect("CRT 参数")
        .modulus()
        .as_ref()
        .as_limbs();
    ADDRESS.store(limbs.as_ptr() as usize, Ordering::SeqCst);
    LENGTH.store(std::mem::size_of_val(limbs), Ordering::SeqCst);
    drop(key);
    ADDRESS.store(0, Ordering::SeqCst);
    let freed = FREED.load(Ordering::SeqCst);
    let wiped = WIPED.load(Ordering::SeqCst);
    println!("observed_deallocation={freed}; zero_before_deallocation={wiped}");
    if freed && wiped {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
