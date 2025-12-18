use std::env;
use std::ffi::CString;
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashSet;
use linker::context::LinkerContext;
use linker::loader::ElfLoader;
use linker::unwind; // [New] 引入異常處理模塊



// Signal handler for crash diagnostics
extern "C" fn crash_handler(sig: libc::c_int, info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
    unsafe {
        // Use write() directly to avoid allocation
        let msg = match sig {
            libc::SIGSEGV => "\n[CRASH] SIGSEGV (Segmentation fault)\n",
            libc::SIGBUS => "\n[CRASH] SIGBUS (Bus error)\n", 
            libc::SIGABRT => "\n[CRASH] SIGABRT (Abort)\n",
            libc::SIGFPE => "\n[CRASH] SIGFPE (Floating point exception)\n",
            _ => "\n[CRASH] Unknown signal\n",
        };
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        
        // Print fault address (platform-specific access)
        if !info.is_null() {
            // Access si_addr - on Android/Linux it's in the union
            let si_addr_ptr = (info as *const u8).add(16) as *const *mut libc::c_void;
            let si_addr = *si_addr_ptr;
            if !si_addr.is_null() {
                let addr_msg = format!("[CRASH] Fault address: 0x{:x}\n", si_addr as usize);
                libc::write(2, addr_msg.as_ptr() as *const libc::c_void, addr_msg.len());
            }
        }
        
        // Exit
        libc::_exit(128 + sig);
    }
}

fn setup_crash_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = crash_handler as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        
        libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGFPE, &sa, std::ptr::null_mut());
    }
}

fn main() {
    // Setup crash handler first
    setup_crash_handler();
    
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <path_to_so>", args[0]);
        return;
    }
    let target_so_path = &args[1];

    println!("[*] RustLinker V25 (C++ Exception & OpenMP Support) starting...");

    let ctx = LinkerContext::new();

    // 1. [New] 初始化異常支持 (注入全局 Context)
    unsafe {
        unwind::init_unwind(&ctx.borrow());
    }



    // 4. 加載目標 SO (遞歸處理依賴)
    let path = std::path::Path::new(target_so_path);
    let target_name = path.file_name().unwrap().to_str().unwrap();
    
    match LinkerContext::load_library(ctx.clone(), target_name, Some(path)) {
        Ok(loader) => {
            println!("[+] Target loaded successfully!\n");
            
            // 打印依賴樹
            println!("Dependency Tree for {}:", target_name);
            let mut visited = HashSet::new();
            visited.insert(target_name.to_string());
            print_dependency_tree(&ctx, loader.clone(), 0, &mut visited);
            println!("\n==========================================\n");
            if target_name.contains("libtls_test"){
                let loader_ref = loader.borrow();
                if let Some(addr) = loader_ref.get_export_symbol("test") {
                    println!("[Test] Found test at 0x{:x}", addr);

                    let func: extern "C" fn() -> libc::c_void = unsafe { std::mem::transmute(addr) };
                    func();
                }
            }
            // 針對 libmem.so 的特定測試 (如果需要)
            if target_so_path.contains("libmem") {
                // 先测试系统的 opendir 是否正常
                println!("[Debug] Testing system opendir directly...");
                unsafe {
                    let proc_path = CString::new("/proc").unwrap();
                    let dir = libc::opendir(proc_path.as_ptr());
                    if dir.is_null() {
                        println!("[Debug] System opendir(\"/proc\") returned NULL!");
                    } else {
                        println!("[Debug] System opendir(\"/proc\") succeeded: {:p}", dir);
                        // 读取几个条目
                        for i in 0..3 {
                            let entry = libc::readdir(dir);
                            if !entry.is_null() {
                                let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr());
                                println!("[Debug]   Entry {}: {:?}", i, name);
                            }
                        }
                        libc::closedir(dir);
                    }
                    
                    // 测试系统 strlen 和 strcmp
                    let test_str = CString::new("bin.mt.plus.canary").unwrap();
                    let len = libc::strlen(test_str.as_ptr());
                    println!("[Debug] System strlen(\"bin.mt.plus.canary\") = {}", len);
                    
                    let cmp_result = libc::strcmp(test_str.as_ptr(), test_str.as_ptr());
                    println!("[Debug] System strcmp(same, same) = {}", cmp_result);
                }
                
                // 测试：比较不同方式获取的 strlen 地址
                {
                    println!("\n[Debug] === Comparing strlen addresses ===");
                    
                    // 方法1: Rust 的 libc 绑定（肯定正确）
                    let rust_strlen = libc::strlen as usize;
                    println!("[Debug] 1. Rust libc::strlen = 0x{:x}", rust_strlen);
                    
                    // 方法2: dlsym(RTLD_DEFAULT)
                    let dlsym_strlen = unsafe {
                        let name = CString::new("strlen").unwrap();
                        libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) as usize
                    };
                    println!("[Debug] 2. dlsym(RTLD_DEFAULT) = 0x{:x}", dlsym_strlen);
                    
                    // 方法3: 我们的 context.resolve_symbol
                    let ctx_ref = ctx.borrow();
                    let ctx_strlen = ctx_ref.resolve_symbol("strlen").unwrap_or(0);
                    println!("[Debug] 3. context.resolve_symbol = 0x{:x}", ctx_strlen);
                    
                    // 检查差异
                    if rust_strlen != dlsym_strlen {
                        println!("[Debug] ⚠ Rust libc != dlsym!");
                    }
                    if dlsym_strlen != ctx_strlen {
                        println!("[Debug] ⚠ dlsym != context! Difference: {} bytes", 
                                 (ctx_strlen as i64 - dlsym_strlen as i64).abs());
                    }
                    
                    // 只用 Rust 的地址测试（这个肯定能工作）
                    let test_str = CString::new("bin.mt.plus.canary").unwrap();
                    println!("[Debug] Testing Rust libc::strlen directly...");
                    let result = unsafe { libc::strlen(test_str.as_ptr()) };
                    println!("[Debug] Rust libc::strlen result = {} (expected 18)", result);
                    
                    // 如果 dlsym 地址不同，用它测试
                    if dlsym_strlen != 0 && dlsym_strlen != rust_strlen {
                        println!("[Debug] Testing dlsym strlen...");
                        let dlsym_fn: extern "C" fn(*const libc::c_char) -> usize = 
                            unsafe { std::mem::transmute(dlsym_strlen) };
                        let result2 = dlsym_fn(test_str.as_ptr());
                        println!("[Debug] dlsym strlen result = {}", result2);
                    }
                    
                    println!("[Debug] === End comparison ===\n");
                }
                
                let loader_ref = loader.borrow();
                if let Some(addr) = loader_ref.get_export_symbol("getPid") {
                    println!("[Test] Found getPid at 0x{:x}", addr);
                    println!("[Test] SO base_addr: 0x{:x}, load_bias: 0x{:x}", 
                             loader_ref.get_base_addr(), loader_ref.get_load_bias());
                    
                    let pkg_name = CString::new("bin.mt.plus.canary").unwrap();
                    println!("[Test] Calling getPid(\"{}\") at 0x{:x}...", "bin.mt.plus.canary", addr);
                    let func: extern "C" fn(*const libc::c_char) -> libc::c_int = unsafe { std::mem::transmute(addr) };
                    let pid = func(pkg_name.as_ptr());
                    println!("[Test] getPid result: {}", pid);
                    
                    // 如果返回 -1，尝试用不同的包名测试
                    if pid == -1 {
                        println!("[Debug] getPid returned -1, trying with 'init' (should exist)...");
                        let init_name = CString::new("init").unwrap();
                        let pid2 = func(init_name.as_ptr());
                        println!("[Debug] getPid(\"init\") result: {}", pid2);
                        
                        // 也尝试找 zygote64
                        println!("[Debug] Trying 'zygote64'...");
                        let zygote_name = CString::new("zygote64").unwrap();
                        let pid3 = func(zygote_name.as_ptr());
                        println!("[Debug] getPid(\"zygote64\") result: {}", pid3);
                    }
                }
            }

            // [Critical Fix] 防止 Drop 導致的 Segfault
            // 我們故意泄漏 ctx 和 loader，讓它們在進程生命週期內一直有效。
            // 這樣 C++ 的靜態析構函數運行時，內存依然存在。
            std::mem::forget(loader);
            std::mem::forget(ctx);
            while true {
                
            };
            println!("[*] Main finished. Keeping loader alive via leak.");
        },
        Err(e) => println!("[-] Fatal Error: {}", e),
    }
}

// 輔助函數：遞歸打印依賴樹
fn print_dependency_tree(
    ctx: &Rc<RefCell<LinkerContext>>, 
    loader: Rc<RefCell<ElfLoader>>, 
    depth: usize, 
    visited: &mut HashSet<String>
) {
    let loader = loader.borrow();
    let libs = loader.get_needed_libs();

    if libs.is_empty() {
        return;
    }

    for (i, lib) in libs.iter().enumerate() {
        let is_last = i == libs.len() - 1;
        let prefix = "  ".repeat(depth);
        let branch = if is_last { "└──" } else { "├──" };
        
        if visited.contains(lib) {
            println!("{}{} {} (Circular/Loaded)", prefix, branch, lib);
        } else {
            println!("{}{} {}", prefix, branch, lib);
            visited.insert(lib.clone());

            if let Some(dep_loader) = ctx.borrow().get_module(lib) {
                print_dependency_tree(ctx, dep_loader, depth + 1, visited);
            } else {
                println!("{}    └── [System Library]", "  ".repeat(depth + 1));
            }
        }
    }
}