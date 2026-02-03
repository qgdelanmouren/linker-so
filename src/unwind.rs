//! dl_iterate_phdr hook 支持
//! 
//! 为自定义加载的模块提供 program header 遍历支持，
//! 这对于 C++ 异常处理和栈回溯是必需的。

use std::ffi::{c_void, CString};
use std::mem;
use std::ptr;
use libc::{c_char, c_int, size_t};

use crate::context::LinkerContext;
use crate::elf::{Elf_Phdr, Elf_Addr};

// ==========================================
// 平台适配类型
// ==========================================

#[cfg(target_pointer_width = "64")]
type Elf_Half = u16;

#[cfg(target_pointer_width = "32")]
type Elf_Half = u16;  // Elf32_Half 也是 u16

// RTLD_NEXT 定义
const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;

// ==========================================
// DlPhdrInfo 结构体 (平台自适应)
// ==========================================

/// dl_phdr_info 结构体
/// 根据目标平台自动选择正确的字段大小
#[repr(C)]
pub struct DlPhdrInfo {
    /// 模块加载基址
    pub dlpi_addr: Elf_Addr,
    /// 模块名称
    pub dlpi_name: *const c_char,
    /// Program header 数组指针
    pub dlpi_phdr: *const Elf_Phdr,
    /// Program header 数量
    pub dlpi_phnum: Elf_Half,
    /// 添加计数 (可选，用于兼容性)
    #[cfg(target_pointer_width = "64")]
    pub dlpi_adds: u64,
    #[cfg(target_pointer_width = "32")]
    pub dlpi_adds: u32,
    /// 移除计数 (可选)
    #[cfg(target_pointer_width = "64")]
    pub dlpi_subs: u64,
    #[cfg(target_pointer_width = "32")]
    pub dlpi_subs: u32,
    /// TLS 模块 ID
    pub dlpi_tls_modid: size_t,
    /// TLS 数据指针
    pub dlpi_tls_data: *mut c_void,
}

// ==========================================
// 全局上下文
// ==========================================

static mut GLOBAL_CONTEXT: *const LinkerContext = ptr::null();

/// 初始化 unwind 支持
/// 
/// # Safety
/// 必须在单线程环境下调用
pub unsafe fn init_unwind(ctx: &LinkerContext) {
    unsafe {
        GLOBAL_CONTEXT = ctx;
    }
}

// ==========================================
// dl_iterate_phdr Hook
// ==========================================

type DlIteratePhdrCallback = extern "C" fn(info: *mut DlPhdrInfo, size: size_t, data: *mut c_void) -> c_int;
type DlIteratePhdrFn = extern "C" fn(callback: DlIteratePhdrCallback, data: *mut c_void) -> c_int;

/// 自定义 dl_iterate_phdr 实现
/// 
/// 先调用系统的 dl_iterate_phdr，然后遍历自定义加载的模块
#[unsafe(no_mangle)]
pub unsafe extern "C" fn custom_dl_iterate_phdr(
    callback: DlIteratePhdrCallback,
    data: *mut c_void
) -> c_int {
    unsafe {
        // 1. 先调用系统原本的 dl_iterate_phdr
        let sys_func_addr = libc::dlsym(RTLD_NEXT, "dl_iterate_phdr\0".as_ptr() as *const c_char);
        if !sys_func_addr.is_null() {
            let sys_func: DlIteratePhdrFn = mem::transmute(sys_func_addr);
            let ret = sys_func(callback, data);
            if ret != 0 {
                return ret;
            }
        }

        // 2. 遍历我们自定义加载的模块
        let ctx_ptr = GLOBAL_CONTEXT;
        if ctx_ptr.is_null() {
            return 0;
        }

        let ctx = &*ctx_ptr;
        
        for (name, loader_rc) in ctx.snapshot_modules() {
            if let Ok(loader) = loader_rc.try_borrow() {
                let phdrs = loader.get_phdrs();
                // 使用我们自己的 Elf_Phdr，已经是平台适配的
                let phdrs_ptr = phdrs.as_ptr();
                
                let c_name = CString::new(name).unwrap(); 
                
                let mut info = DlPhdrInfo {
                    dlpi_addr: loader.get_load_bias() as Elf_Addr,
                    dlpi_name: c_name.as_ptr(),
                    dlpi_phdr: phdrs_ptr,
                    dlpi_phnum: phdrs.len() as Elf_Half,
                    dlpi_adds: 0,
                    dlpi_subs: 0,
                    dlpi_tls_modid: loader.get_tls_module_id(),
                    dlpi_tls_data: ptr::null_mut(),
                };

                let size = mem::size_of::<DlPhdrInfo>();
                
                let ret = callback(&mut info, size, data);
                if ret != 0 {
                    return ret;
                }
            }
        }
    }

    0
}