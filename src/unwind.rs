use std::ffi::{c_void, CString};
use std::mem;
use std::ptr;
use libc::{c_char, c_int, size_t, Elf64_Phdr, Elf64_Addr, Elf64_Half};

use crate::context::LinkerContext;

// 手动定义 RTLD_NEXT
const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;

#[repr(C)]
pub struct DlPhdrInfo {
    pub dlpi_addr: Elf64_Addr,
    pub dlpi_name: *const c_char,
    pub dlpi_phdr: *const Elf64_Phdr,
    pub dlpi_phnum: Elf64_Half,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: size_t,
    pub dlpi_tls_data: *mut c_void,
}

static mut GLOBAL_CONTEXT: *const LinkerContext = ptr::null();

pub unsafe fn init_unwind(ctx: &LinkerContext) {
    unsafe {
        GLOBAL_CONTEXT = ctx;
    }
}

type DlIteratePhdrCallback = extern "C" fn(info: *mut DlPhdrInfo, size: size_t, data: *mut c_void) -> c_int;
type DlIteratePhdrFn = extern "C" fn(callback: DlIteratePhdrCallback, data: *mut c_void) -> c_int;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn custom_dl_iterate_phdr(
    callback: DlIteratePhdrCallback,
    data: *mut c_void
) -> c_int {
    unsafe {
        // 1. 先調用系統原本的 dl_iterate_phdr
        let sys_func_addr = libc::dlsym(RTLD_NEXT, "dl_iterate_phdr\0".as_ptr() as *const c_char);
        if !sys_func_addr.is_null() {
            let sys_func: DlIteratePhdrFn = mem::transmute(sys_func_addr);
            let ret = sys_func(callback, data);
            if ret != 0 {
                return ret;
            }
        }

        // 2. 遍歷我們自定義加載的模塊
        let ctx_ptr = GLOBAL_CONTEXT;
        if ctx_ptr.is_null() {
            return 0;
        }

        let ctx = &*ctx_ptr;
        
        for (name, loader_rc) in &ctx.modules {
            if let Ok(loader) = loader_rc.try_borrow() {
                // 類型轉換：從 crate::elf::Elf64_Phdr 到 libc::Elf64_Phdr
                let phdrs = loader.get_phdrs();
                let phdrs_ptr = phdrs.as_ptr() as *const libc::Elf64_Phdr;
                
                let c_name = CString::new(name.clone()).unwrap(); 
                
                let mut info = DlPhdrInfo {
                    dlpi_addr: loader.get_load_bias() as u64,
                    dlpi_name: c_name.as_ptr(),
                    dlpi_phdr: phdrs_ptr,
                    dlpi_phnum: phdrs.len() as u16,
                    dlpi_adds: 0,
                    dlpi_subs: 0,
                    dlpi_tls_modid: 0,
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