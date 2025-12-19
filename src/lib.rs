#[cfg(target_os = "android")]
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        log::info!($($arg)*);
    }};
}

#[cfg(not(target_os = "android"))]
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        ::std::println!($($arg)*);
    }};
}

pub mod elf;
pub mod loader;
pub mod utils;
pub mod xdl;
pub mod context;
pub mod hooks;
pub mod tls;
pub mod unwind;

mod embedded_libs {
    include!(concat!(env!("OUT_DIR"), "/embedded_libs.rs"));
}

pub use embedded_libs::embedded_lib_bytes;
pub use embedded_libs::MAIN_LIB_NAME;

use std::collections::HashSet;
use std::rc::Rc;
use std::cell::RefCell;
use crate::context::LinkerContext;
use crate::loader::ElfLoader;

// Wrapper to allow raw pointers in static (compilation fix for !Sync types)
struct SyncPtr<T>(*const T);
unsafe impl<T> Sync for SyncPtr<T> {}
unsafe impl<T> Send for SyncPtr<T> {} // Just in case

// Global storage using raw pointers to avoid lifetime/Sync issues
static mut GLOBAL_LOADER: SyncPtr<RefCell<ElfLoader>> = SyncPtr(std::ptr::null());
static mut GLOBAL_CONTEXT: SyncPtr<RefCell<LinkerContext>> = SyncPtr(std::ptr::null());

// Define the init function to run when the library is loaded
#[unsafe(link_section = ".init_array")]
#[used] // Ensure it's kept by the linker
pub static INITIALIZE: extern "C" fn() = init_library;

extern "C" fn init_library() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("custom-linker")
                .with_max_level(log::LevelFilter::Info),
        );
    }

    println!("[Linker] init_array called - loading embedded library...");

    // Initialize global context
    let ctx = LinkerContext::new();

    // Initialize unwind support
    unsafe {
        unwind::init_unwind(&ctx.borrow());
    }

    // Load the embedded library
    let lib_bytes = match embedded_lib_bytes(MAIN_LIB_NAME) {
        Some(b) => b,
        None => {
            println!("[Linker] Failed to locate embedded main library for this architecture: {}", MAIN_LIB_NAME);
            return;
        }
    };

    match LinkerContext::load_library_from_memory(ctx.clone(), MAIN_LIB_NAME, lib_bytes) {
        Ok(loader) => {
            println!("[Linker] Embedded library loaded successfully during init");
            
            // Store in global variables
            // We use Rc::into_raw to leak the Rc and get a raw pointer, ensuring the objects stay alive
            unsafe {
                GLOBAL_CONTEXT = SyncPtr(Rc::into_raw(ctx));
                GLOBAL_LOADER = SyncPtr(Rc::into_raw(loader));
            }
        },
        Err(e) => {
            println!("[Linker] Failed to load embedded library during init: {}", e);
        }
    }
}

fn should_call_all_jni_onload() -> bool {
    if cfg!(feature = "jni_onload_all") {
        return true;
    }
    match std::env::var("CUSTOM_LINKER_JNI_ONLOAD_ALL") {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn collect_modules_postorder(
    ctx: &LinkerContext,
    name: &str,
    visited: &mut HashSet<String>,
    out: &mut Vec<String>,
) {
    if !visited.insert(name.to_string()) {
        return;
    }
    let Some(loader) = ctx.get_module(name) else {
        return;
    };
    let needed = loader.borrow().get_needed_libs().to_vec();
    for dep in needed {
        if ctx.get_module(&dep).is_some() {
            collect_modules_postorder(ctx, &dep, visited, out);
        }
    }
    out.push(name.to_string());
}

#[unsafe(no_mangle)]
pub extern "C" fn JNI_OnLoad(vm: *mut libc::c_void, reserved: *mut libc::c_void) -> libc::c_int {
    println!("[Linker] JNI_OnLoad called");

    unsafe {
        let call_all = should_call_all_jni_onload();
        if call_all {
            let ctx_ptr = GLOBAL_CONTEXT.0;
            if !ctx_ptr.is_null() {
                let calls: Vec<(String, usize)> = {
                    let ctx_ref = &*ctx_ptr;
                    let ctx_borrow = ctx_ref.borrow();
                    let mut visited: HashSet<String> = HashSet::new();
                    let mut order: Vec<String> = Vec::new();
                    collect_modules_postorder(&ctx_borrow, MAIN_LIB_NAME, &mut visited, &mut order);

                    let mut calls: Vec<(String, usize)> = Vec::new();
                    for name in order {
                        let Some(loader) = ctx_borrow.get_module(&name) else {
                            continue;
                        };
                        if let Some(addr) = loader.borrow().get_export_symbol("JNI_OnLoad") {
                            calls.push((name, addr));
                        }
                    }
                    calls
                };

                let mut main_result: Option<libc::c_int> = None;
                for (name, addr) in calls {
                    println!("[Linker] Calling JNI_OnLoad for {} at 0x{:x}", name, addr);
                    let target_jni_onload: extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> libc::c_int =
                        std::mem::transmute(addr);
                    let result = target_jni_onload(vm, reserved);
                    println!("[Linker] JNI_OnLoad for {} returned {}", name, result);

                    if name == MAIN_LIB_NAME {
                        main_result = Some(result);
                    }
                    if result < 0 {
                        return -1;
                    }
                }

                if let Some(r) = main_result {
                    return r;
                }
            }
        }

        let loader_ptr = GLOBAL_LOADER.0;
        
        if !loader_ptr.is_null() {
            // Reconstruct reference from raw pointer
            // Note: We don't turn it back into Rc to avoid dropping it at end of scope
            let loader_ref = &*loader_ptr; 
            
            // Resolve JNI_OnLoad from the loaded library
            let addr = loader_ref.borrow().get_export_symbol("JNI_OnLoad");

            if let Some(addr) = addr {
                println!("[Linker] Found JNI_OnLoad at 0x{:x}", addr);

                let target_jni_onload: extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> libc::c_int =
                    std::mem::transmute(addr);

                // Call the target JNI_OnLoad
                let result = target_jni_onload(vm, reserved);
                println!("[Linker] Target JNI_OnLoad returned {}", result);

                return result;
            } else {
                println!("[Linker] Error: JNI_OnLoad not found in embedded library");
                return -1;
            }
        } else {
            println!("[Linker] Error: Library was not initialized properly in .init_array");
            return -1;
        }
    }
}