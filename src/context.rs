use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;
use std::ffi::CString;
use libc::{c_void, RTLD_NOW, RTLD_GLOBAL};

use crate::loader::ElfLoader;
use crate::xdl;
use crate::unwind::custom_dl_iterate_phdr; // [New] 引入 Hook 函數
use crate::hooks; // [New] 引入 Hooks

pub struct LinkerContext {
    // [Fix] 改為 pub(crate) 讓 unwind.rs 可以遍歷模塊
    pub(crate) modules: HashMap<String, Rc<RefCell<ElfLoader>>>,
    
    system_handles: HashMap<String, *mut c_void>,
    fallback_handle: *mut c_void,
}

impl LinkerContext {
    pub fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            modules: HashMap::new(),
            system_handles: HashMap::new(),
            fallback_handle: std::ptr::null_mut(),
        }))
    }

    pub fn set_fallback_handle(&mut self, handle: *mut c_void) {
        self.fallback_handle = handle;
    }

    // ==========================================
    // 內存加載入口
    // ==========================================
    pub fn load_library_from_memory(
        ctx: Rc<RefCell<Self>>,
        name: &str,
        data: &'static [u8]
    ) -> Result<Rc<RefCell<ElfLoader>>, String> {
        if let Some(loader) = ctx.borrow().modules.get(name) {
            return Ok(loader.clone());
        }

        println!("[Context] Loading memory library: {}", name);
        let loader = Rc::new(RefCell::new(ElfLoader::new_memory(name, data)));
        
        ctx.borrow_mut().modules.insert(name.to_string(), loader.clone());

        loader.borrow_mut().map()?;
        
        // 遞歸加載依賴
        let needed_libs = loader.borrow_mut().parse_needed()?;
        for dep_name in needed_libs {
            if Self::is_system_lib(&dep_name) {
                ctx.borrow_mut().load_system_lib(&dep_name);
            } else {
                // 內存庫的依賴如果是其他的內存庫，這裡需要額外邏輯處理
                // 目前假設內存庫只依賴系統庫
                println!("[Context] Warning: Memory lib {} depends on {}, skipping recursion for now.", name, dep_name);
            }
        }

        loader.borrow_mut().relocate(ctx.clone())?;
        loader.borrow_mut().call_constructors();

        Ok(loader)
    }

    // ==========================================
    // 文件加載入口
    // ==========================================
    pub fn load_library(
        ctx: Rc<RefCell<Self>>, 
        name: &str, 
        parent_path: Option<&Path>
    ) -> Result<Rc<RefCell<ElfLoader>>, String> {
        if let Some(loader) = ctx.borrow().modules.get(name) {
            return Ok(loader.clone());
        }

        // 路徑推導
        let mut target_path = None;
        if let Some(parent) = parent_path {
            if let Some(parent_dir) = parent.parent() {
                let candidate = parent_dir.join(name);
                if candidate.exists() { target_path = Some(candidate); }
            }
        }
        if target_path.is_none() {
            let candidate = Path::new("/data/local/tmp").join(name);
            if candidate.exists() { target_path = Some(candidate); }
        }

        if let Some(path) = target_path {
            let path_str = path.to_str().unwrap().to_string();
            println!("[Context] Loading user library: {} from {:?}", name, path);

            let loader = Rc::new(RefCell::new(ElfLoader::new_file(name, &path_str)));
            ctx.borrow_mut().modules.insert(name.to_string(), loader.clone());

            loader.borrow_mut().map()?;
            let needed_libs = loader.borrow_mut().parse_needed()?;
            
            // 遞歸加載
            for dep_name in needed_libs {
                if Self::is_system_lib(&dep_name) {
                    ctx.borrow_mut().load_system_lib(&dep_name);
                } else {
                    let _ = Self::load_library(ctx.clone(), &dep_name, Some(&path));
                }
            }
            
            // Try to load libc++_shared.so if not already loaded
            // Many C++ libraries need it even if not explicitly declared as dependency
            // But skip if SO has its own static C++ runtime
            {
                let loader_ref = loader.borrow();
                ctx.borrow_mut().try_load_cxx_runtime(&loader_ref);
            }

            loader.borrow_mut().relocate(ctx.clone())?;
            loader.borrow_mut().call_constructors();

            Ok(loader)
        } else {
            return Err(format!("Library not found: {}", name));
        }
    }

    fn load_system_lib(&mut self, name: &str) {
        if self.system_handles.contains_key(name) { return; }
        
        println!("[Context] Try loading system lib: {}", name);
        
        let c_name = CString::new(name).unwrap();
        unsafe {
            // 優先嘗試 xdl (繞過限制)
            let handle = xdl::xdl_open(c_name.as_ptr(), xdl::XDL_TRY_FORCE_LOAD);
            if !handle.is_null() {
                println!("[Context]   Success (xdl): {}", name);
                self.system_handles.insert(name.to_string(), handle);
            } else {
                // 回退到 dlopen
                let handle2 = libc::dlopen(c_name.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
                if !handle2.is_null() {
                    println!("[Context]   Success (dlopen): {}", name);
                    self.system_handles.insert(name.to_string(), handle2);
                } else {
                    println!("[Context]   FAILED to load: {}", name);
                }
            }
        }
    }
    
    fn try_load_cxx_runtime(&mut self, loader: &crate::loader::ElfLoader) {
        // Check if the SO has its own C++ runtime (statically linked)
        // Detection methods:
        // 1. SO exports C++ runtime symbols (like __cxa_throw)
        // 2. SO does NOT depend on libc++_shared.so or libc++.so (meaning it statically linked C++)
        
        let exports_cxx_symbols = loader.get_export_symbol("__cxa_throw").is_some() ||
                                   loader.get_export_symbol("__cxa_begin_catch").is_some() ||
                                   loader.get_export_symbol("__gxx_personality_v0").is_some() ||
                                   loader.get_export_symbol("__cxa_allocate_exception").is_some();
        
        // Check if SO depends on any C++ runtime library
        let needed_libs = loader.get_needed_libs();
        let depends_on_cxx_runtime = needed_libs.iter().any(|lib| {
            lib.contains("libc++") || lib.contains("libstdc++")
        });
        
        // If SO exports C++ symbols OR doesn't depend on any C++ runtime,
        // it likely has statically linked C++ - don't load system C++ runtime
        if exports_cxx_symbols {
            println!("[Context] SO exports C++ runtime symbols, skipping system libc++ to avoid conflicts");
            return;
        }
        
        if !depends_on_cxx_runtime {
            // SO doesn't depend on C++ runtime library
            // If it uses C++, it must have statically linked it
            // We should NOT load system C++ runtime to avoid conflicts
            println!("[Context] SO doesn't depend on C++ runtime lib, assuming static linkage - skipping system libc++");
            return;
        }
        
        // Only load system C++ runtime if SO explicitly depends on it
        println!("[Context] SO depends on C++ runtime, will use system library");
        
        // Try to load C++ runtime libraries
        let cxx_libs = [
            "libc++_shared.so",
            "libc++.so",
        ];
        
        for lib in &cxx_libs {
            if self.system_handles.contains_key(*lib) {
                continue;
            }
            
            let c_name = CString::new(*lib).unwrap();
            unsafe {
                let handle = xdl::xdl_open(c_name.as_ptr(), xdl::XDL_TRY_FORCE_LOAD);
                if !handle.is_null() {
                    println!("[Context] Auto-loaded C++ runtime: {}", lib);
                    self.system_handles.insert(lib.to_string(), handle);
                    break;
                } else {
                    let handle2 = libc::dlopen(c_name.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
                    if !handle2.is_null() {
                        println!("[Context] Auto-loaded C++ runtime: {}", lib);
                        self.system_handles.insert(lib.to_string(), handle2);
                        break;
                    }
                }
            }
        }
    }

    fn is_system_lib(name: &str) -> bool {
        name.starts_with("libc.so") || 
        name.starts_with("libm.so") || 
        name.starts_with("libdl.so") || 
        name.starts_with("liblog.so") ||
        name.starts_with("libstdc++") || 
        name.starts_with("libc++") ||  // C++ standard library
        name.starts_with("libz.so") ||
        name.starts_with("libjnigraphics.so") ||
        name.starts_with("libandroid.so") ||
        name.starts_with("libEGL.so") ||
        name.starts_with("libGLES") ||
        name.starts_with("libOpenSLES.so") ||
        name.starts_with("libvulkan.so") ||
        name.starts_with("libmediandk.so") ||
        name.starts_with("libcamera2ndk.so") ||
        name.starts_with("libnativewindow.so") ||
        name.starts_with("libaaudio.so") ||
        name.starts_with("libamidi.so")
    }

    // ==========================================
    // 符號解析 (包含 Hook)
    // ==========================================
    
    /// 符号解析的核心逻辑
    /// 
    /// 解析优先级（商业级兼容性设计）：
    /// 1. 特殊 Hook 符号（如 dl_iterate_phdr）
    /// 2. 用户自定义模块导出的符号（尊重用户自己的实现）
    /// 3. dlsym(RTLD_DEFAULT) - 正确处理 IFUNC，查找所有已加载库的公开符号
    /// 4. xdl_sym 查找私有符号（fallback）
    /// 
    /// 注意：不再硬编码"必须从系统解析"的函数列表
    /// 如果用户的 SO 导出了 open/malloc 等函数，应该优先使用用户的实现
    pub fn resolve_symbol(&self, symbol_name: &str) -> Option<usize> {
        
        // 1. [Hook] 特殊符号劫持
        if symbol_name == "dl_iterate_phdr" {
            return Some(custom_dl_iterate_phdr as usize);
        }
        if symbol_name == "__cxa_atexit" {
            return Some(hooks::custom___cxa_atexit as usize);
        }
        if symbol_name == "__cxa_finalize" {
            return Some(hooks::custom___cxa_finalize as usize);
        }
        if symbol_name == "__cxa_thread_atexit_impl" {
            return Some(hooks::custom___cxa_thread_atexit_impl as usize);
        }

        // 2. [Priority 1] 查自定义模块导出的符号
        // 尊重用户自己的实现：如果用户 SO 导出了某个符号，优先使用它
        // 这样用户可以自己实现 open/malloc 等函数而不会被系统版本覆盖
        for loader in self.modules.values() {
            if let Ok(l) = loader.try_borrow() {
                if let Some(addr) = l.get_export_symbol(symbol_name) {
                    return Some(addr);
                }
            }
        }

        let c_name = CString::new(symbol_name).unwrap();

        // 3. [Priority 2] dlsym(RTLD_DEFAULT) - 推荐方式
        // 优点：
        // - 正确处理 IFUNC（间接函数）解析
        // - 能找到所有已加载库的公开符号
        // - 跨 Android 版本兼容性好
        unsafe {
            let addr = libc::dlsym(libc::RTLD_DEFAULT, c_name.as_ptr());
            if !addr.is_null() { 
                return Some(addr as usize); 
            }
        }

        // 4. [Priority 3] xdl_sym 查找显式加载的库
        // 用于查找某些私有符号（dlsym 可能找不到）
        for handle in self.system_handles.values() {
            unsafe {
                let addr = xdl::xdl_sym(*handle, c_name.as_ptr(), std::ptr::null_mut());
                if !addr.is_null() { 
                    return Some(addr as usize); 
                }
            }
        }

        // 5. [Priority 4] Fallback 句柄
        if !self.fallback_handle.is_null() {
            unsafe {
                let addr = libc::dlsym(self.fallback_handle, c_name.as_ptr());
                if !addr.is_null() { 
                    return Some(addr as usize); 
                }
            }
        }

        None
    }
    

    
    pub fn get_module(&self, name: &str) -> Option<Rc<RefCell<ElfLoader>>> {
        self.modules.get(name).cloned()
    }
}