// src/hooks.rs
use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

// ==========================================
// 全局析构支持 (__cxa_atexit / __cxa_finalize)
// ==========================================

struct GlobalAtExitEntry {
    func: extern "C" fn(*mut c_void),
    arg: *mut c_void,
    dso_handle: *mut c_void,
}

// 必须标记为 Send，因为这些回调可能在任何线程（通常是主线程或最后退出的线程）被调用
unsafe impl Send for GlobalAtExitEntry {}
unsafe impl Sync for GlobalAtExitEntry {}

static GLOBAL_HANDLERS: OnceLock<Mutex<Vec<GlobalAtExitEntry>>> = OnceLock::new();

fn get_global_handlers() -> &'static Mutex<Vec<GlobalAtExitEntry>> {
    GLOBAL_HANDLERS.get_or_init(|| Mutex::new(Vec::new()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn custom___cxa_atexit(
    func: extern "C" fn(*mut c_void),
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> i32 {
    let handlers = get_global_handlers();
    if let Ok(mut guard) = handlers.lock() {
        guard.push(GlobalAtExitEntry { func, arg, dso_handle });
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn custom___cxa_finalize(dso_handle: *mut c_void) {
    let handlers = get_global_handlers();
    if let Ok(mut guard) = handlers.lock() {
        // 从后往前遍历 (LIFO)
        let mut i = guard.len();
        while i > 0 {
            i -= 1;
            let entry = &guard[i];
            if dso_handle.is_null() || entry.dso_handle == dso_handle {
                (entry.func)(entry.arg);
                guard.remove(i);
            }
        }
    }
}

// ==========================================
// 线程局部析构支持 (__cxa_thread_atexit_impl)
// ==========================================

struct ThreadAtExitEntry {
    func: extern "C" fn(*mut c_void),
    arg: *mut c_void,
    // dso_handle 在线程局部析构中通常用于匹配卸载，
    // 但这里主要关注线程退出时的自动调用。
    #[allow(dead_code)] 
    dso_handle: *mut c_void,
}

/// 管理器：利用 Rust 的 Drop 机制在线程退出时触发回调
#[derive(Default)]
struct ThreadDtorManager {
    handlers: Vec<ThreadAtExitEntry>,
}

impl Drop for ThreadDtorManager {
    fn drop(&mut self) {
        // 线程退出时，Rust 会 Drop 这个 thread_local 变量
        // 我们利用这个时机调用注册的 C++ 析构函数
        // 顺序：LIFO (后注册的先析构)
        while let Some(entry) = self.handlers.pop() {
            (entry.func)(entry.arg);
        }
    }
}

thread_local! {
    // 每个线程都有自己独立的 DtorManager
    // RefCell 用于内部可变性，允许我们 push 新的 handler
    static TLS_DTORS: RefCell<ThreadDtorManager> = RefCell::new(ThreadDtorManager::default());
}

/// 真正的线程局部析构 Hook
/// 当 C++ 代码中有 thread_local 对象（且有非平凡析构函数）时会调用此函数
#[unsafe(no_mangle)]
pub unsafe extern "C" fn custom___cxa_thread_atexit_impl(
    func: extern "C" fn(*mut c_void),
    arg: *mut c_void,
    dso_handle: *mut c_void,
) {
    TLS_DTORS.with(|manager| {
        manager.borrow_mut().handlers.push(ThreadAtExitEntry {
            func,
            arg,
            dso_handle,
        });
    });
}