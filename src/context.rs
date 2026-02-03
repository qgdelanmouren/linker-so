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
use crate::tls; // [New] TLS Support

pub struct LinkerNamespace {
    modules: HashMap<String, Rc<RefCell<ElfLoader>>>,
    search_paths: Vec<String>,
    linked_namespaces: Vec<String>,
}

impl LinkerNamespace {
    fn new(search_paths: Vec<String>) -> Self {
        Self {
            modules: HashMap::new(),
            search_paths,
            linked_namespaces: Vec::new(),
        }
    }
}

pub struct LinkerContext {
    namespaces: HashMap<String, LinkerNamespace>,
    system_handles: HashMap<String, *mut c_void>,
    fallback_handle: *mut c_void,
}

impl LinkerContext {
    pub fn new() -> Rc<RefCell<Self>> {
        let mut namespaces: HashMap<String, LinkerNamespace> = HashMap::new();
        namespaces.insert(
            "default".to_string(),
            LinkerNamespace::new(vec!["/data/local/tmp".to_string()]),
        );
        Rc::new(RefCell::new(Self {
            namespaces,
            system_handles: HashMap::new(),
            fallback_handle: std::ptr::null_mut(),
        }))
    }

    pub fn create_namespace(&mut self, name: &str, search_paths: Vec<String>) {
        self.namespaces
            .entry(name.to_string())
            .or_insert_with(|| LinkerNamespace::new(search_paths));
    }

    pub fn link_namespaces(&mut self, from: &str, to: &str) {
        if let Some(ns) = self.namespaces.get_mut(from) {
            if !ns.linked_namespaces.iter().any(|n| n == to) {
                ns.linked_namespaces.push(to.to_string());
            }
        }
    }

    pub(crate) fn snapshot_modules(&self) -> Vec<(String, Rc<RefCell<ElfLoader>>)> {
        let mut out: Vec<(String, Rc<RefCell<ElfLoader>>)> = Vec::new();
        for ns in self.namespaces.values() {
            for (name, loader) in &ns.modules {
                out.push((name.clone(), loader.clone()));
            }
        }
        out
    }

     pub(crate) fn snapshot_modules_in_namespace(
         &self,
         namespace: &str,
     ) -> Vec<Rc<RefCell<ElfLoader>>> {
         let mut out: Vec<Rc<RefCell<ElfLoader>>> = Vec::new();

         let Some(ns) = self.namespaces.get(namespace) else {
             return out;
         };

         for loader in ns.modules.values() {
             out.push(loader.clone());
         }
         for linked in &ns.linked_namespaces {
             if let Some(ns2) = self.namespaces.get(linked) {
                 for loader in ns2.modules.values() {
                     out.push(loader.clone());
                 }
             }
         }

         out
     }

    pub fn set_fallback_handle(&mut self, handle: *mut c_void) {
        self.fallback_handle = handle;
    }

    // ==========================================
    // 內存加載入口 (处理加密的 SO)
    // ==========================================
    pub fn load_library_from_memory(
        ctx: Rc<RefCell<Self>>,
        name: &str,
        encrypted_data: &'static [u8]
    ) -> Result<Rc<RefCell<ElfLoader>>, String> {
        Self::load_library_from_memory_in_namespace(ctx, "default", name, encrypted_data)
    }

    pub fn load_library_from_memory_in_namespace(
        ctx: Rc<RefCell<Self>>,
        namespace: &str,
        name: &str,
        encrypted_data: &'static [u8],
    ) -> Result<Rc<RefCell<ElfLoader>>, String> {
        let existing = {
            let ctx_borrow = ctx.borrow();
            ctx_borrow
                .namespaces
                .get(namespace)
                .and_then(|ns| ns.modules.get(name).cloned())
        };
        if let Some(loader) = existing {
            return Ok(loader);
        }

        println!("[Context] Loading memory library: {}", name);
        
        // 解密 SO 数据
        let decrypted = crate::crypto::decrypt_so(encrypted_data)?;
        
        // 将解密后的数据转换为 'static 生命周期
        // 注意: 这会泄漏内存，但 SO 通常在整个进程生命周期内都需要
        let static_data: &'static [u8] = Box::leak(decrypted.into_boxed_slice());
        
        let loader = Rc::new(RefCell::new(ElfLoader::new_memory(name, static_data, namespace)));

        {
            let mut ctx_mut = ctx.borrow_mut();
            ctx_mut
                .namespaces
                .entry(namespace.to_string())
                .or_insert_with(|| LinkerNamespace::new(vec!["/data/local/tmp".to_string()]))
                .modules
                .insert(name.to_string(), loader.clone());
        }

        loader.borrow_mut().map()?;

        let needed_libs = loader.borrow_mut().parse_needed()?;
        for dep_name in needed_libs {
            if Self::is_system_lib(&dep_name) {
                ctx.borrow_mut().load_system_lib(&dep_name);
            } else {
                if let Some(dep_bytes) = crate::embedded_lib_bytes(&dep_name) {
                    let _ = Self::load_library_from_memory_in_namespace(
                        ctx.clone(),
                        namespace,
                        &dep_name,
                        dep_bytes,
                    )?;
                } else {
                    return Err(format!(
                        "Missing embedded dependency: {} (needed by {})",
                        dep_name, name
                    ));
                }
            }
        }

        {
            let loader_ref = loader.borrow();
            ctx.borrow_mut().try_load_cxx_runtime(&loader_ref);
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
        Self::load_library_in_namespace(ctx, "default", name, parent_path)
    }

    pub fn load_library_in_namespace(
        ctx: Rc<RefCell<Self>>,
        namespace: &str,
        name: &str,
        parent_path: Option<&Path>,
    ) -> Result<Rc<RefCell<ElfLoader>>, String> {
        let existing = {
            let ctx_borrow = ctx.borrow();
            ctx_borrow
                .namespaces
                .get(namespace)
                .and_then(|ns| ns.modules.get(name).cloned())
        };
        if let Some(loader) = existing {
            return Ok(loader);
        }

        let ns_search_paths: Vec<String> = {
            let ctx_borrow = ctx.borrow();
            ctx_borrow
                .namespaces
                .get(namespace)
                .map(|ns| ns.search_paths.clone())
                .unwrap_or_else(|| vec!["/data/local/tmp".to_string()])
        };

        let mut target_path = None;
        if let Some(parent) = parent_path {
            if let Some(parent_dir) = parent.parent() {
                let candidate = parent_dir.join(name);
                if candidate.exists() {
                    target_path = Some(candidate);
                }
            }
        }
        if target_path.is_none() {
            for p in &ns_search_paths {
                let candidate = Path::new(p).join(name);
                if candidate.exists() {
                    target_path = Some(candidate);
                    break;
                }
            }
        }

        if let Some(path) = target_path {
            let path_str = path.to_str().unwrap().to_string();
            println!("[Context] Loading user library: {} from {:?}", name, path);

            let loader = Rc::new(RefCell::new(ElfLoader::new_file(name, &path_str, namespace)));
            {
                let mut ctx_mut = ctx.borrow_mut();
                ctx_mut
                    .namespaces
                    .entry(namespace.to_string())
                    .or_insert_with(|| LinkerNamespace::new(vec!["/data/local/tmp".to_string()]))
                    .modules
                    .insert(name.to_string(), loader.clone());
            }

            loader.borrow_mut().map()?;
            let needed_libs = loader.borrow_mut().parse_needed()?;

            for dep_name in needed_libs {
                if Self::is_system_lib(&dep_name) {
                    ctx.borrow_mut().load_system_lib(&dep_name);
                } else {
                    let _ = Self::load_library_in_namespace(ctx.clone(), namespace, &dep_name, Some(&path));
                }
            }

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
        let exports_cxx_symbols = loader.get_export_symbol("__cxa_throw").is_some() ||
                                   loader.get_export_symbol("__cxa_begin_catch").is_some() ||
                                   loader.get_export_symbol("__gxx_personality_v0").is_some() ||
                                   loader.get_export_symbol("__cxa_allocate_exception").is_some();
        
        let needed_libs = loader.get_needed_libs();
        let depends_on_cxx_runtime = needed_libs.iter().any(|lib| {
            lib.contains("libc++") || lib.contains("libstdc++")
        });
        
        if exports_cxx_symbols {
            println!("[Context] SO exports C++ runtime symbols, skipping system libc++ to avoid conflicts");
            return;
        }
        
        if !depends_on_cxx_runtime {
            println!("[Context] SO doesn't depend on C++ runtime lib, assuming static linkage - skipping system libc++");
            return;
        }
        
        println!("[Context] SO depends on C++ runtime, will use system library");
        
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
        self.resolve_symbol_in_namespace("default", symbol_name)
    }

    pub fn resolve_symbol_in_namespace(&self, namespace: &str, symbol_name: &str) -> Option<usize> {
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
        if symbol_name == "__tls_get_addr" {
            return Some(tls::__tls_get_addr as usize);
        }
        if symbol_name == "__emutls_get_address" {
            return Some(tls::__emutls_get_address as usize);
        }

        if let Some(ns) = self.namespaces.get(namespace) {
            for loader in ns.modules.values() {
                if let Ok(l) = loader.try_borrow() {
                    if let Some(addr) = l.get_export_symbol(symbol_name) {
                        return Some(addr);
                    }
                }
            }
            for linked in &ns.linked_namespaces {
                if let Some(ns2) = self.namespaces.get(linked) {
                    for loader in ns2.modules.values() {
                        if let Ok(l) = loader.try_borrow() {
                            if let Some(addr) = l.get_export_symbol(symbol_name) {
                                return Some(addr);
                            }
                        }
                    }
                }
            }
        }

        let c_name = CString::new(symbol_name).unwrap();

        unsafe {
            let addr = libc::dlsym(libc::RTLD_DEFAULT, c_name.as_ptr());
            if !addr.is_null() {
                return Some(addr as usize);
            }
        }

        for handle in self.system_handles.values() {
            unsafe {
                let addr = xdl::xdl_sym(*handle, c_name.as_ptr(), std::ptr::null_mut());
                if !addr.is_null() {
                    return Some(addr as usize);
                }
            }
        }

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
        self.namespaces
            .get("default")
            .and_then(|ns| ns.modules.get(name).cloned())
    }
}