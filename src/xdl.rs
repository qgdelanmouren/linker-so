// src/xdl.rs
use libc::{c_char, c_int, c_void, size_t};

// Constants from xdl.h
pub const XDL_DEFAULT: c_int = 0x00;
pub const XDL_TRY_FORCE_LOAD: c_int = 0x01;
pub const XDL_ALWAYS_FORCE_LOAD: c_int = 0x02;

#[link(name = "xdl", kind = "static")]
unsafe extern "C" { // <--- 关键修改：增加了 unsafe 关键字
    /// Enhanced dlopen()
    pub fn xdl_open(filename: *const c_char, flags: c_int) -> *mut c_void;

    /// Enhanced dlclose()
    pub fn xdl_close(handle: *mut c_void) -> *mut c_void;

    /// Enhanced dlsym()
    pub fn xdl_sym(handle: *mut c_void, symbol: *const c_char, symbol_size: *mut size_t) -> *mut c_void;

    /// Enhanced dlsym() (Dynamic Symbol Lookup)
    pub fn xdl_dsym(handle: *mut c_void, symbol: *const c_char, symbol_size: *mut size_t) -> *mut c_void;
}