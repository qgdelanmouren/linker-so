use libc::{
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE, c_char, c_void, mmap,
    mprotect,
};

#[cfg(not(target_arch = "arm"))]
 unsafe extern "C" {
    unsafe fn __register_frame(begin: *const u8);
    unsafe fn __deregister_frame(begin: *const u8);
}
use std::cell::RefCell;
use std::ffi::CString;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::mem;
use std::ptr;
use std::rc::Rc;
use std::slice;

use crate::context::LinkerContext;
use crate::elf::*;
use crate::tls;
use crate::utils::{get_page_size, page_end, page_start};
use crate::xdl;

// 移除这个常量定义，直接在 match 中使用字面量，避免 pattern matching 歧义
// const DT_GNU_HASH: usize = 0x6ffffef5;

pub trait ElfRead: Read + Seek {}
impl<T: Read + Seek> ElfRead for T {}

enum LoaderSource {
    File(String),
    Memory(&'static [u8]),
}

pub struct ElfLoader {
    namespace: String,
    source_type: LoaderSource,
    base_addr: usize,
    load_size: usize,
    load_bias: usize,
    phdrs: Vec<Elf_Phdr>,

    dynamic: *const Elf_Dyn,
    strtab: *const c_char,
    strtab_size: usize,
    symtab: *const Elf_Sym,
    sym_count: usize,

    // RELA relocations (with addend)
    rela: *const Elf_Rela,
    rela_count: usize,
    
    // REL relocations (without addend) 
    rel: *const Elf_Rel,
    rel_count: usize,
    
    // PLT relocations
    jmp_rel: *const u8,  // Can be either Elf_Rela or Elf_Rel
    plt_rel_count: usize,
    plt_rel_is_rela: bool,  // true = RELA, false = REL
    
    // RELR packed relative relocations
    relr: *const Elf_Addr,
    relr_count: usize,
    
    // Android packed relocations
    android_rela: *const u8,
    android_rela_size: usize,

    needed_libs: Vec<String>,
    library_handles: Vec<*mut c_void>,

    init_func: Option<extern "C" fn()>,
    init_array: *const extern "C" fn(),
    init_array_count: usize,
    
    // IFUNC resolvers to call after all relocations
    ifunc_relocations: Vec<(usize, usize)>,  // (reloc_addr, resolver_addr)

    fallback_resolvers: Vec<Rc<RefCell<ElfLoader>>>,
    
    eh_frame_addr: *const u8,
    
    // TLS support
    tls_module_id: usize,
    tlsdesc_args: Vec<Box<[usize; 2]>>,
    
    // Symbol versioning support
    versym: *const u16,           // .gnu.version - 每个符号的版本索引
    verdef: *const u8,            // .gnu.version_d - 版本定义
    verdef_num: usize,            // 版本定义数量
    verneed: *const u8,           // .gnu.version_r - 版本需求
    verneed_num: usize,           // 版本需求数量
}

impl ElfLoader {
    pub fn new_file(_name: &str, path: &str, namespace: &str) -> Self {
        Self::new_internal(LoaderSource::File(path.to_string()), namespace)
    }

    pub fn new_memory(_name: &str, data: &'static [u8], namespace: &str) -> Self {
        Self::new_internal(LoaderSource::Memory(data), namespace)
    }

    fn new_internal(source: LoaderSource, namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
            source_type: source,
            base_addr: 0,
            load_size: 0,
            load_bias: 0,
            phdrs: Vec::new(),
            dynamic: ptr::null(),
            strtab: ptr::null(),
            strtab_size: 0,
            symtab: ptr::null(),
            sym_count: 0,
            rela: ptr::null(),
            rela_count: 0,
            rel: ptr::null(),
            rel_count: 0,
            jmp_rel: ptr::null(),
            plt_rel_count: 0,
            plt_rel_is_rela: true,
            relr: ptr::null(),
            relr_count: 0,
            android_rela: ptr::null(),
            android_rela_size: 0,
            needed_libs: Vec::new(),
            library_handles: Vec::new(),
            init_func: None,
            init_array: ptr::null(),
            init_array_count: 0,
            ifunc_relocations: Vec::new(),
            fallback_resolvers: Vec::new(),
            eh_frame_addr: ptr::null(),
            tls_module_id: 0,
            tlsdesc_args: Vec::new(),
            // Symbol versioning
            versym: ptr::null(),
            verdef: ptr::null(),
            verdef_num: 0,
            verneed: ptr::null(),
            verneed_num: 0,
        }
    }

    pub fn add_fallback_loader(&mut self, loader: Rc<RefCell<ElfLoader>>) {
        self.fallback_resolvers.push(loader);
    }

    pub fn get_needed_libs(&self) -> &[String] {
        &self.needed_libs
    }

    pub fn map(&mut self) -> Result<(), String> {
        let page_size = get_page_size();
        println!("[Loader] Starting map process...");

        let mut source: Box<dyn ElfRead> = match &self.source_type {
            LoaderSource::File(path) => {
                let f = File::open(path).map_err(|e| e.to_string())?;
                Box::new(f)
            }
            LoaderSource::Memory(data) => Box::new(Cursor::new(*data)),
        };

        let mut header: Elf_Ehdr = unsafe { mem::zeroed() };
        let header_slice = unsafe {
            slice::from_raw_parts_mut(&mut header as *mut _ as *mut u8, mem::size_of::<Elf_Ehdr>())
        };
        source.read_exact(header_slice).map_err(|e| e.to_string())?;

        if header.e_ident[0..4] != ELFMAG {
            return Err("Invalid ELF Magic".to_string());
        }

        let ph_off = header.e_phoff as u64;
        let ph_num = header.e_phnum as usize;
        // println!("[Loader] Header OK. Phdrs: {}, Offset: {}", ph_num, ph_off);

        source
            .seek(SeekFrom::Start(ph_off))
            .map_err(|e| e.to_string())?;
        self.phdrs = vec![unsafe { mem::zeroed() }; ph_num];
        let ph_slice = unsafe {
            slice::from_raw_parts_mut(
                self.phdrs.as_mut_ptr() as *mut u8,
                ph_num * mem::size_of::<Elf_Phdr>(),
            )
        };
        source.read_exact(ph_slice).map_err(|e| e.to_string())?;

        self.reserve_address_space()?;
        self.map_segments(&mut source, page_size)?;
        self.process_tls_segment();
        self.register_eh_frame();
        self.find_dynamic_section()?;
        println!("[Loader] Mapped & Parsed. SymCount: {}", self.sym_count);

        Ok(())
    }

    fn process_tls_segment(&mut self) {
        for ph in &self.phdrs {
            if ph.p_type == PT_TLS {
                let image_ptr = (self.load_bias + ph.p_vaddr as usize) as *const u8;
                let image_size = ph.p_filesz as usize;
                let mem_size = ph.p_memsz as usize;
                let align = ph.p_align as usize;
                
                // Register TLS module
                self.tls_module_id = tls::register_tls_module(image_ptr, image_size, mem_size, align);
                println!("[Loader] Registered TLS module id={} size={}/{} align={}", 
                         self.tls_module_id, image_size, mem_size, align);
                break;
            }
        }
    }

    pub fn get_export_tls_symbol(&self, name: &str) -> Option<usize> {
        if self.symtab.is_null() || self.strtab.is_null() {
            return None;
        }

        let count = if self.sym_count > 0 {
            self.sym_count
        } else {
            30000
        };

        for i in 0..count {
            unsafe {
                let sym_ptr = self.symtab.add(i);
                if !self.is_valid_ptr(sym_ptr as usize) {
                    break;
                }

                let sym = &*sym_ptr;
                if sym.st_name == 0 {
                    continue;
                }
                
                // Check if it's a TLS symbol
                if (sym.st_info & 0xf) != STT_TLS {
                    continue;
                }

                if let Some(s) = self.get_safe_string(sym.st_name as usize) {
                    if s == name {
                        // Return the offset (st_value)
                        return Some(sym.st_value as usize);
                    }
                }
            }
        }
        None
    }

    pub fn get_tls_module_id(&self) -> usize {
        self.tls_module_id
    }

    fn get_safe_string(&self, offset: usize) -> Option<String> {
        if self.strtab.is_null() {
            return None;
        }
        if self.strtab_size > 0 && offset >= self.strtab_size {
            return None;
        }

        let start_addr = unsafe { self.strtab.add(offset) as usize };
        if !self.is_valid_ptr(start_addr) {
            return None;
        }

        let mut bytes = Vec::new();
        let mut curr_addr = start_addr;

        loop {
            if !self.is_valid_ptr(curr_addr) {
                break;
            }
            let c = unsafe { *(curr_addr as *const u8) };
            if c == 0 {
                break;
            }
            bytes.push(c);
            curr_addr += 1;
            if bytes.len() > 4096 {
                break;
            }
        }

        String::from_utf8(bytes).ok()
    }
    // 在 impl ElfLoader 中添加：

    pub fn get_load_bias(&self) -> usize {
        self.load_bias
    }

    pub fn get_base_addr(&self) -> usize {
        self.base_addr
    }

    pub fn get_phdrs(&self) -> &[Elf_Phdr] {
        &self.phdrs
    }
    pub fn parse_needed(&mut self) -> Result<Vec<String>, String> {
        let mut needed = Vec::new();
        if !self.dynamic.is_null() && !self.strtab.is_null() {
            unsafe {
                let mut i = 0;
                loop {
                    let dyn_entry = &*self.dynamic.add(i);
                    if dyn_entry.d_tag == 0 {
                        break;
                    }
                    if dyn_entry.d_tag as usize == DT_NEEDED {
                        let name_offset = dyn_entry.d_val as usize;
                        if let Some(s) = self.get_safe_string(name_offset) {
                            needed.push(s);
                        }
                    }
                    i += 1;
                }
            }
        }
        self.needed_libs = needed.clone();
        Ok(needed)
    }

    pub fn load_system_dependencies(&mut self) -> Result<(), String> {
        for lib_name in &self.needed_libs {
            let c_name = CString::new(lib_name.as_str()).unwrap();
            unsafe {
                let handle = xdl::xdl_open(c_name.as_ptr(), xdl::XDL_TRY_FORCE_LOAD);
                if !handle.is_null() {
                    self.library_handles.push(handle);
                }
            }
        }
        Ok(())
    }

    pub fn relocate(&mut self, ctx: Rc<RefCell<LinkerContext>>) -> Result<(), String> {
        let mut failed = 0;

        // Process RELR (packed relative relocations) first
        if !self.relr.is_null() && self.relr_count > 0 {
            println!("[Reloc] Processing RELR: {} entries", self.relr_count);
            self.process_relr_relocations()?;
            println!("[Reloc] RELR done");
        }

        // Process RELA relocations
        if !self.rela.is_null() && self.rela_count > 0 {
            println!("[Reloc] Processing RELA: {} entries", self.rela_count);
            for i in 0..self.rela_count {
                let rela = unsafe { &*self.rela.add(i) };
                if !self.process_rela_relocation(rela, &ctx)? {
                    failed += 1;
                }
            }
            println!("[Reloc] RELA done");
        }
        
        // Process REL relocations (without addend)
        if !self.rel.is_null() && self.rel_count > 0 {
            println!("[Reloc] Processing REL: {} entries", self.rel_count);
            for i in 0..self.rel_count {
                let rel = unsafe { &*self.rel.add(i) };
                if !self.process_rel_relocation(rel, &ctx)? {
                    failed += 1;
                }
            }
            println!("[Reloc] REL done");
        }
        
        // Process PLT relocations
        if !self.jmp_rel.is_null() && self.plt_rel_count > 0 {
            println!("[Reloc] Processing PLT ({}): {} entries", 
                if self.plt_rel_is_rela { "RELA" } else { "REL" }, 
                self.plt_rel_count);
            if self.plt_rel_is_rela {
                let rela_ptr = self.jmp_rel as *const Elf_Rela;
                for i in 0..self.plt_rel_count {
                    let rela = unsafe { &*rela_ptr.add(i) };
                    if !self.process_rela_relocation(rela, &ctx)? {
                        failed += 1;
                    }
                }
            } else {
                let rel_ptr = self.jmp_rel as *const Elf_Rel;
                for i in 0..self.plt_rel_count {
                    let rel = unsafe { &*rel_ptr.add(i) };
                    if !self.process_rel_relocation(rel, &ctx)? {
                        failed += 1;
                    }
                }
            }
            println!("[Reloc] PLT done");
        }
        
        // Process Android packed relocations
        if !self.android_rela.is_null() && self.android_rela_size > 0 {
            println!("[Reloc] Processing Android packed: {} bytes", self.android_rela_size);
            self.process_android_relocations(&ctx)?;
        }
        
        // Now resolve IFUNC relocations (must be done after all other relocations)
        if !self.ifunc_relocations.is_empty() {
            println!("[Reloc] Resolving {} IFUNC relocations", self.ifunc_relocations.len());
        self.resolve_ifunc_relocations();
        }

        if failed > 0 {
            println!(
                "[Loader] Warning: {} relocations failed (Check logs)",
                failed
            );
        }

        // Memory barrier to ensure all GOT writes are visible
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        // Debug: Verify GOT entries for critical string functions after all relocations
        println!("[Reloc] Verifying critical GOT entries...");
        self.verify_got_entries();

        println!("[Reloc] All relocations completed");
        Ok(())
    }
    
    /// Verify GOT entries for critical functions after relocation
    fn verify_got_entries(&self) {
        // Walk through PLT relocations and check GOT values
        if self.jmp_rel.is_null() || self.plt_rel_count == 0 || !self.plt_rel_is_rela {
            return;
        }
        
        let rela_ptr = self.jmp_rel as *const Elf_Rela;
        for i in 0..self.plt_rel_count {
            let rela = unsafe { &*rela_ptr.add(i) };
            
            #[cfg(target_pointer_width = "64")]
            let r_info = rela.r_info as u64;
            #[cfg(target_pointer_width = "32")]
            let r_info = rela.r_info as u32;
            
            let r_sym = elf_r_sym(r_info);
            
            if let Some(name) = self.get_sym_name(r_sym) {
                // Only check critical string functions
                if name == "strlen" || name == "strcmp" || name == "memcpy" {
                    let got_addr = self.load_bias + rela.r_offset as usize;
                    unsafe {
                        let got_value = ptr::read_volatile(got_addr as *const usize);
                        println!("[Verify] {} GOT @ 0x{:x} = 0x{:x}", name, got_addr, got_value);
                    }
                }
            }
        }
    }

    fn process_rela_relocation(
        &mut self,
        rela: &Elf_Rela,
        ctx: &Rc<RefCell<LinkerContext>>,
    ) -> Result<bool, String> {
        #[cfg(target_pointer_width = "64")]
        let r_info = rela.r_info as u64;
        #[cfg(target_pointer_width = "32")]
        let r_info = rela.r_info as u32;
        
        let r_type = elf_r_type(r_info);
        let r_sym = elf_r_sym(r_info);
        let reloc_addr = (self.load_bias + rela.r_offset as usize) as *mut usize;

        if !self.is_valid_ptr(reloc_addr as usize) {
            return Ok(true);
        }

        self.do_relocation(r_type, r_sym, reloc_addr, rela.r_addend as i64, ctx)
    }
    
    fn process_rel_relocation(
        &mut self,
        rel: &Elf_Rel,
        ctx: &Rc<RefCell<LinkerContext>>,
    ) -> Result<bool, String> {
        #[cfg(target_pointer_width = "64")]
        let r_info = rel.r_info as u64;
        #[cfg(target_pointer_width = "32")]
        let r_info = rel.r_info as u32;
        
        let r_type = elf_r_type(r_info);
        let r_sym = elf_r_sym(r_info);
        let reloc_addr = (self.load_bias + rel.r_offset as usize) as *mut usize;

        if !self.is_valid_ptr(reloc_addr as usize) {
            return Ok(true);
        }

        // For REL, the addend is implicit (read from memory)
        let addend = unsafe { *reloc_addr as i64 };
        self.do_relocation(r_type, r_sym, reloc_addr, addend, ctx)
    }
    
    fn do_relocation(
        &mut self,
        r_type: u32,
        r_sym: u32,
        reloc_addr: *mut usize,
        addend: i64,
        ctx: &Rc<RefCell<LinkerContext>>,
    ) -> Result<bool, String> {
        match r_type {
            // =========================================================
            // AArch64 Relocations
            // =========================================================
            #[cfg(target_arch = "aarch64")]
            R_AARCH64_NONE => Ok(true),
            
            #[cfg(target_arch = "aarch64")]
            R_AARCH64_RELATIVE => {
                let val = (self.load_bias as i64 + addend) as usize;
                unsafe { *reloc_addr = val; }
                Ok(true)
            }
            
            #[cfg(target_arch = "aarch64")]
            R_AARCH64_IRELATIVE => {
                let resolver_addr = (self.load_bias as i64 + addend) as usize;
                self.ifunc_relocations.push((reloc_addr as usize, resolver_addr));
                Ok(true)
            }
            
            #[cfg(target_arch = "aarch64")]
            R_AARCH64_COPY => {
                self.process_copy_reloc(r_sym, reloc_addr, ctx)
            }
            
            #[cfg(target_arch = "aarch64")]
            R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT | R_AARCH64_ABS64 => {
                self.process_global_reloc(r_sym, reloc_addr, addend, ctx, "AArch64")
            }
            
            #[cfg(target_arch = "aarch64")]
            R_AARCH64_TLS_DTPMOD64 => {
                self.process_tls_dtpmod(r_sym, reloc_addr, ctx)
            }

            #[cfg(target_arch = "aarch64")]
            R_AARCH64_TLS_DTPREL64 => {
                self.process_tls_dtprel(r_sym, reloc_addr, addend, ctx)
            }

            #[cfg(target_arch = "aarch64")]
            R_AARCH64_TLS_TPREL64 => {
                println!("[Reloc] Error: R_AARCH64_TLS_TPREL64 (Static TLS) not supported!");
                Ok(false)
            }

            #[cfg(target_arch = "aarch64")]
            R_AARCH64_TLSDESC => {
                self.process_tls_desc(r_sym, reloc_addr, addend, ctx)
            }

            // =========================================================
            // x86_64 Relocations
            // =========================================================
            #[cfg(target_arch = "x86_64")]
            R_X86_64_RELATIVE => {
                let val = (self.load_bias as i64 + addend) as usize;
                unsafe { *reloc_addr = val; }
                Ok(true)
            }

            #[cfg(target_arch = "x86_64")]
            R_X86_64_64 => { // Similar to ABS64, but for 64-bit
                 // If r_sym is 0, it behaves like RELATIVE
                 if r_sym == 0 {
                     let val = (self.load_bias as i64 + addend) as usize;
                     unsafe { *reloc_addr = val; }
                     Ok(true)
                 } else {
                     self.process_global_reloc(r_sym, reloc_addr, addend, ctx, "x86_64")
                 }
            }

            #[cfg(target_arch = "x86_64")]
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                self.process_global_reloc(r_sym, reloc_addr, addend, ctx, "x86_64")
            }

            #[cfg(target_arch = "x86_64")]
            R_X86_64_COPY => {
                self.process_copy_reloc(r_sym, reloc_addr, ctx)
            }

            #[cfg(target_arch = "x86_64")]
            R_X86_64_IRELATIVE => {
                // On x86_64, IRELATIVE usually doesn't have an addend in RELA for the resolver?
                // Actually it does.
                let resolver_addr = (self.load_bias as i64 + addend) as usize;
                self.ifunc_relocations.push((reloc_addr as usize, resolver_addr));
                Ok(true)
            }

            #[cfg(target_arch = "x86_64")]
            R_X86_64_DTPMOD64 => {
                self.process_tls_dtpmod(r_sym, reloc_addr, ctx)
            }

            #[cfg(target_arch = "x86_64")]
            R_X86_64_DTPOFF64 => {
                 self.process_tls_dtprel(r_sym, reloc_addr, addend, ctx)
            }

            #[cfg(target_arch = "x86_64")]
            R_X86_64_TLSDESC => {
                 self.process_tls_desc(r_sym, reloc_addr, addend, ctx)
            }

            // =========================================================
            // ARM (32-bit) Relocations
            // =========================================================
            #[cfg(target_arch = "arm")]
            R_ARM_RELATIVE => {
                // ARM RELATIVE: *addr += load_bias
                // Note: For REL (no addend param), addend is read from *addr. 
                // But our do_relocation receives 'addend' which is either explicit (RELA) or read from *reloc_addr (REL).
                let val = (self.load_bias as i64 + addend) as usize;
                unsafe { *reloc_addr = val; }
                Ok(true)
            }

            #[cfg(target_arch = "arm")]
            R_ARM_ABS32 => {
                 if r_sym == 0 {
                     let val = (self.load_bias as i64 + addend) as usize;
                     unsafe { *reloc_addr = val; }
                     Ok(true)
                 } else {
                     self.process_global_reloc(r_sym, reloc_addr, addend, ctx, "ARM")
                 }
            }

            #[cfg(target_arch = "arm")]
            R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT => {
                self.process_global_reloc(r_sym, reloc_addr, addend, ctx, "ARM")
            }

            #[cfg(target_arch = "arm")]
            R_ARM_TLS_DTPMOD32 => {
                self.process_tls_dtpmod(r_sym, reloc_addr, ctx)
            }

            #[cfg(target_arch = "arm")]
            R_ARM_TLS_DTPOFF32 => {
                self.process_tls_dtprel(r_sym, reloc_addr, addend, ctx)
            }
            
            #[cfg(target_arch = "arm")]
            R_ARM_TLS_DESC => {
                self.process_tls_desc(r_sym, reloc_addr, addend, ctx)
            }

             // =========================================================
            // x86 (32-bit) Relocations
            // =========================================================
            #[cfg(target_arch = "x86")]
            R_386_RELATIVE => {
                let val = (self.load_bias as i64 + addend) as usize;
                unsafe { *reloc_addr = val; }
                Ok(true)
            }

            #[cfg(target_arch = "x86")]
            R_386_32 => {
                 if r_sym == 0 {
                     let val = (self.load_bias as i64 + addend) as usize;
                     unsafe { *reloc_addr = val; }
                     Ok(true)
                 } else {
                     self.process_global_reloc(r_sym, reloc_addr, addend, ctx, "x86")
                 }
            }

            #[cfg(target_arch = "x86")]
            R_386_GLOB_DAT | R_386_JMP_SLOT => {
                self.process_global_reloc(r_sym, reloc_addr, addend, ctx, "x86")
            }

             #[cfg(target_arch = "x86")]
            R_386_TLS_DTPMOD32 => {
                self.process_tls_dtpmod(r_sym, reloc_addr, ctx)
            }

            #[cfg(target_arch = "x86")]
            R_386_TLS_DTPOFF32 => {
                self.process_tls_dtprel(r_sym, reloc_addr, addend, ctx)
            }
            
            #[cfg(target_arch = "x86")]
            R_386_TLS_DESC => {
                self.process_tls_desc(r_sym, reloc_addr, addend, ctx)
            }
            
            _ => {
                // Unknown relocation type - log it but don't fail
                println!("[Reloc] Warning: Unknown relocation type: {}", r_type);
                Ok(true)
            }
        }
    }

    // Helper to process COPY relocations
    #[allow(dead_code)]
    fn process_copy_reloc(&self, r_sym: u32, reloc_addr: *mut usize, ctx: &Rc<RefCell<LinkerContext>>) -> Result<bool, String> {
        if let Some(name) = self.get_sym_name(r_sym) {
            if let Some(sym_addr) = self.resolve_symbol_for_reloc(&name, ctx) {
                let sym_size = self.get_sym_size(r_sym).unwrap_or(0);
                if sym_size > 0 && self.is_valid_ptr(sym_addr) {
                    unsafe {
                        ptr::copy_nonoverlapping(
                            sym_addr as *const u8,
                            reloc_addr as *mut u8,
                            sym_size,
                        );
                    }
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    // Helper to process standard global relocations (GLOB_DAT, JUMP_SLOT, ABS)
    fn process_global_reloc(
        &self, 
        r_sym: u32, 
        reloc_addr: *mut usize, 
        addend: i64, 
        ctx: &Rc<RefCell<LinkerContext>>,
        _arch: &str
    ) -> Result<bool, String> {
        if r_sym == 0 {
             let val = (self.load_bias as i64 + addend) as usize;
             unsafe { *reloc_addr = val; }
             return Ok(true);
        }

        if let Some(name) = self.get_sym_name(r_sym) {
            if let Some(sym_addr) = self.resolve_symbol_for_reloc(&name, ctx) {
                let val = (sym_addr as i64 + addend) as usize;
                unsafe { ptr::write_volatile(reloc_addr, val); }
                Ok(true)
            } else {
                if self.is_weak_symbol(r_sym) {
                    unsafe { *reloc_addr = 0; }
                    Ok(true)
                } else {
                     println!("[Reloc] Error: Unresolved symbol: {}", name);
                     unsafe { *reloc_addr = 0; }
                     Ok(true) // Don't crash, just warn
                }
            }
        } else {
            Ok(true)
        }
    }

    // Helper for TLS DTPMOD
    fn process_tls_dtpmod(&self, r_sym: u32, reloc_addr: *mut usize, ctx: &Rc<RefCell<LinkerContext>>) -> Result<bool, String> {
        if r_sym == 0 {
            if self.tls_module_id == 0 {
                println!("[Reloc] Warning: TLS_DTPMOD for local symbol but no PT_TLS");
            }
            unsafe { *reloc_addr = self.tls_module_id; }
        } else {
            if let Some(name) = self.get_sym_name(r_sym) {
                if let Some((mod_id, _)) = self.resolve_tls_symbol(&name, ctx) {
                     unsafe { *reloc_addr = mod_id; }
                } else {
                     println!("[Reloc] Error: Could not resolve TLS symbol: {}", name);
                }
            }
        }
        Ok(true)
    }

    // Helper for TLS DTPREL (Offset)
    fn process_tls_dtprel(&self, r_sym: u32, reloc_addr: *mut usize, addend: i64, ctx: &Rc<RefCell<LinkerContext>>) -> Result<bool, String> {
        if r_sym == 0 {
            unsafe { *reloc_addr = addend as usize; }
        } else {
            if let Some(name) = self.get_sym_name(r_sym) {
                if let Some((_, offset)) = self.resolve_tls_symbol(&name, ctx) {
                     unsafe { *reloc_addr = (offset as i64 + addend) as usize; }
                } else {
                     println!("[Reloc] Error: Could not resolve TLS symbol: {}", name);
                }
            }
        }
        Ok(true)
    }

    // Helper for TLSDESC
    fn process_tls_desc(&mut self, r_sym: u32, reloc_addr: *mut usize, addend: i64, ctx: &Rc<RefCell<LinkerContext>>) -> Result<bool, String> {
        let mut mod_id = self.tls_module_id;
        let mut offset = 0;
        
        if r_sym != 0 {
            if let Some(name) = self.get_sym_name(r_sym) {
                if let Some((id, off)) = self.resolve_tls_symbol(&name, ctx) {
                    mod_id = id;
                    offset = off;
                } else {
                     if self.is_weak_symbol(r_sym) {
                         mod_id = 0;
                         offset = 0;
                     } else {
                        println!("[Reloc] Error: Could not resolve TLS symbol: {}", name);
                     }
                }
            }
        } else {
            offset = 0; 
        }
        
        offset = (offset as i64 + addend) as usize;

        let arg = Box::new([mod_id, offset]);
        let arg_ptr = arg.as_ptr();
        self.tlsdesc_args.push(arg);
        
        unsafe {
            *reloc_addr = tls::tlsdesc_resolver_trampoline as usize;
            *(reloc_addr.add(1)) = arg_ptr as usize;
        }
        
        Ok(true)
    }
    
    fn resolve_tls_symbol(&self, name: &str, ctx: &Rc<RefCell<LinkerContext>>) -> Option<(usize, usize)> {
        // 1. Try local module
        if let Some(offset) = self.get_export_tls_symbol(name) {
            return Some((self.tls_module_id, offset));
        }

        // 2. Try other modules in context
        let visible = { ctx.borrow().snapshot_modules_in_namespace(&self.namespace) };
        for loader in visible {
            if let Ok(l) = loader.try_borrow() {
                if let Some(offset) = l.get_export_tls_symbol(name) {
                    return Some((l.get_tls_module_id(), offset));
                }
            }
        }
        
        None
    }

    fn resolve_symbol_for_reloc(&self, name: &str, ctx: &Rc<RefCell<LinkerContext>>) -> Option<usize> {
        // Special handling for __dso_handle - each SO needs its own
        // __dso_handle is used by __cxa_atexit to identify which DSO registered an atexit handler
        if name == "__dso_handle" {
            // Return the base address of this SO as its __dso_handle
            // This is what the system linker does
            return Some(self.base_addr);
        }

        // Emulated TLS entrypoint used by clang (__emutls_*). Some builds import
        // __emutls_get_address without a backing runtime; we provide a compatible implementation.
        if name == "__emutls_get_address" || name.starts_with("__emutls_get_address@") {
            return Some(tls::__emutls_get_address as usize);
        }
        
        // For C++ runtime symbols, prefer local (SO's own) implementation first
        // This is critical for SOs with statically linked C++ runtime
        if Self::prefer_local_symbol(name) {
            if let Some(addr) = self.get_export_symbol(name) {
                if Self::is_important_symbol(name) {
                    println!("[Sym] {} -> 0x{:x} (from local)", name, addr);
                }
                return Some(addr);
            }
        }
        
        // Try context (namespace-aware symbols)
        if let Some(addr) = ctx.borrow().resolve_symbol_in_namespace(&self.namespace, name) {
            if addr != 0 {
                // Log important symbol resolutions for debugging
                if Self::is_important_symbol(name) {
                    println!("[Sym] {} -> 0x{:x} (from context)", name, addr);
                }
                return Some(addr);
            }
        }

        // Then try local exports (for other symbols defined in this SO)
        if let Some(addr) = self.get_export_symbol(name) {
            if Self::is_important_symbol(name) {
                println!("[Sym] {} -> 0x{:x} (from local)", name, addr);
            }
            return Some(addr);
        }

        // Finally try fallback resolvers
        for loader_ref in &self.fallback_resolvers {
            if let Ok(loader) = loader_ref.try_borrow() {
                if let Some(addr) = loader.get_export_symbol(name) {
                    if Self::is_important_symbol(name) {
                        println!("[Sym] {} -> 0x{:x} (from fallback)", name, addr);
                    }
                    return Some(addr);
                }
            }
        }

        None
    }
    
    /// 判断符号是否应该优先使用 SO 自己的实现
    /// 
    /// 这里只硬编码 **C++ ABI 标准前缀**，而不是具体的函数名。
    /// 原因：C++ ABI 前缀是跨平台标准化的，不会因系统/内核不同而变化。
    /// 
    /// 注意：我们不在这里硬编码具体的 libc 函数名（如 strlen, open）
    /// 因为用户可能自己实现了这些函数（如用 svc 直接调用内核）
    fn prefer_local_symbol(name: &str) -> bool {
        // C++ ABI 标准符号 - 如果 SO 静态链接了 C++ runtime，应该用自己的版本
        // 这些前缀是 Itanium C++ ABI 标准定义的，跨平台兼容
        name.starts_with("__cxa_") ||      // C++ ABI: __cxa_throw, __cxa_begin_catch, etc.
        name.starts_with("__gxx_") ||      // GCC C++ ABI: __gxx_personality_v0
        name == "__gxx_personality_v0" ||
        // GCC TLS 仿真 - 如果 SO 自己实现了 TLS，应该用自己的
        name.starts_with("__emutls") ||
        // C++ 异常展开 ABI - 必须与 C++ runtime 一致
        name.starts_with("_Unwind_") ||
        // C++ 标准库内部符号（名称修饰）
        (name.starts_with("_ZN") && name.contains("std")) ||
        name.starts_with("_ZSt") ||
        // C++ RTTI (类型信息) - 必须保持地址一致性
        name.starts_with("_ZTI") ||  // typeinfo
        name.starts_with("_ZTS")     // typeinfo name
    }
    
    /// Check if a symbol is important enough to log
    fn is_important_symbol(name: &str) -> bool {
        // Only log key symbols to reduce noise
        // Skip __cxa_pure_virtual as it appears many times
        if name == "__cxa_pure_virtual" {
            return false;
        }
        
        // Log key C++ runtime symbols
        name == "__cxa_atexit" ||
        name == "__cxa_finalize" ||
        name == "__cxa_throw" ||
        name == "__cxa_begin_catch" ||
        name == "__gxx_personality_v0" ||
        // Threading
        name == "pthread_create" ||
        name == "pthread_join" ||
        // TLS
        name.starts_with("__emutls") ||
        // File operations (for debugging getPid issue)
        name == "opendir" ||
        name == "readdir" ||
        name == "closedir" ||
        name == "fopen" ||
        name == "fread" ||
        name == "fclose" ||
        name == "strcmp" ||
        name == "snprintf" ||
        // String functions - critical for debugging
        name == "strlen" ||
        name == "strncmp" ||
        name == "strcpy" ||
        name == "strncpy" ||
        name == "memcpy" ||
        name == "memset" ||
        name == "memmove"
    }
    
    fn resolve_ifunc_relocations(&self) {
        for (reloc_addr, resolver_addr) in &self.ifunc_relocations {
            if self.is_valid_ptr(*resolver_addr) {
                let resolver: extern "C" fn() -> usize = unsafe { mem::transmute(*resolver_addr) };
                let result = resolver();
                unsafe {
                    *(*reloc_addr as *mut usize) = result;
                }
            }
        }
    }
    
    fn process_relr_relocations(&self) -> Result<(), String> {
        if self.relr.is_null() || self.relr_count == 0 {
            return Ok(());
        }
        
        let mut base_addr: usize = 0;
        let word_size = mem::size_of::<usize>();
        // Number of bits in a word minus 1 (63 on 64-bit, 31 on 32-bit)
        let bits_per_word = word_size * 8 - 1;
        
        for i in 0..self.relr_count {
            let entry = unsafe { *self.relr.add(i) } as usize;
            
            if (entry & 1) == 0 {
                // Even entry: this is a location (offset from load_bias)
                let reloc_addr = self.load_bias + entry;
                if self.is_valid_ptr(reloc_addr) {
                    unsafe {
                        let ptr = reloc_addr as *mut usize;
                        *ptr = (*ptr).wrapping_add(self.load_bias);
                    }
                }
                // Set base for next bitmap entries
                base_addr = reloc_addr + word_size;
            } else {
                // Odd entry: this is a bitmap
                // Each bit represents whether to relocate at base_addr + bit_index * word_size
                let bitmap = entry >> 1;
                for bit in 0..bits_per_word {
                    if (bitmap & (1usize << bit)) != 0 {
                        let reloc_addr = base_addr + bit * word_size;
                        if self.is_valid_ptr(reloc_addr) {
                        unsafe {
                            let ptr = reloc_addr as *mut usize;
                            *ptr = (*ptr).wrapping_add(self.load_bias);
                        }
                    }
                }
                }
                // After processing bitmap, advance base by the full bitmap coverage
                base_addr += bits_per_word * word_size;
            }
        }
        
        Ok(())
    }
    
    fn process_android_relocations(&mut self, ctx: &Rc<RefCell<LinkerContext>>) -> Result<(), String> {
        // Android packed relocations use SLEB128/LEB128 encoding
        // Format: "APS2" magic + SLEB128 encoded relocation groups
        
        if self.android_rela.is_null() || self.android_rela_size < 4 {
            return Ok(());
        }
        
        let data = unsafe { slice::from_raw_parts(self.android_rela, self.android_rela_size) };
        
        // Check magic: "APS2" for RELA, "APS1" for REL (we currently only support RELA)
        if data.len() < 4 || &data[0..4] != b"APS2" {
            // Check for "APS1" (REL format) or other formats
            if data.len() >= 4 && &data[0..4] == b"APS1" {
                println!("[Reloc] Warning: Android REL (APS1) format not fully supported");
                return Ok(());
            }
            println!("[Reloc] Warning: Unknown Android relocation format");
            return Ok(());
        }
        
        let mut pos = 4; // Skip magic
        
        // Read relocation count
        let (reloc_count, bytes_read) = self.read_sleb128(&data[pos..]);
        if bytes_read == 0 {
            return Err("Failed to read Android reloc count".to_string());
        }
        pos += bytes_read;
        
        // Read base offset
        let (base_offset, bytes_read) = self.read_sleb128(&data[pos..]);
        pos += bytes_read;
        
        let mut offset = (self.load_bias as i64 + base_offset) as usize;
        let mut processed = 0;
        
        while processed < reloc_count as usize && pos < data.len() {
            // Read group header
            let (group_size, bytes_read) = self.read_sleb128(&data[pos..]);
            if bytes_read == 0 { break; }
            pos += bytes_read;
            
            let (group_flags, bytes_read) = self.read_sleb128(&data[pos..]);
            if bytes_read == 0 { break; }
            pos += bytes_read;
            
            let group_flags = group_flags as u64;
            
            // Parse flags
            let grouped_by_info = (group_flags & 1) != 0;
            let grouped_by_offset_delta = (group_flags & 2) != 0;
            let grouped_by_addend = (group_flags & 4) != 0;
            let use_addend = (group_flags & 8) != 0;
            
            // Read group values based on flags
            let mut group_r_offset_delta: i64 = 0;
            let mut group_r_info: u64 = 0;
            let mut group_r_addend: i64 = 0;
            
            if grouped_by_offset_delta {
                let (val, bytes_read) = self.read_sleb128(&data[pos..]);
                pos += bytes_read;
                group_r_offset_delta = val;
            }
            
            if grouped_by_info {
                let (val, bytes_read) = self.read_sleb128(&data[pos..]);
                pos += bytes_read;
                group_r_info = val as u64;
            }
            
            if grouped_by_addend && use_addend {
                let (val, bytes_read) = self.read_sleb128(&data[pos..]);
                pos += bytes_read;
                group_r_addend = val;
            }
            
            // Process each relocation in the group
            for _ in 0..group_size {
                if pos >= data.len() { break; }
                
                let r_offset_delta: i64;
                let r_info: u64;
                let r_addend: i64;
                
                if grouped_by_offset_delta {
                    r_offset_delta = group_r_offset_delta;
                } else {
                    let (val, bytes_read) = self.read_sleb128(&data[pos..]);
                    pos += bytes_read;
                    r_offset_delta = val;
                }
                
                if grouped_by_info {
                    r_info = group_r_info;
                } else {
                    let (val, bytes_read) = self.read_sleb128(&data[pos..]);
                    pos += bytes_read;
                    r_info = val as u64;
                }
                
                if use_addend {
                    if grouped_by_addend {
                        r_addend = group_r_addend;
                    } else {
                        let (val, bytes_read) = self.read_sleb128(&data[pos..]);
                        pos += bytes_read;
                        r_addend = val;
                    }
                } else {
                    r_addend = 0;
                }
                
                offset = (offset as i64 + r_offset_delta) as usize;
                
                #[cfg(target_pointer_width = "64")]
                let r_type = elf_r_type(r_info);
                #[cfg(target_pointer_width = "64")]
                let r_sym = elf_r_sym(r_info);
                
                #[cfg(target_pointer_width = "32")]
                let r_type = elf_r_type(r_info as u32);
                #[cfg(target_pointer_width = "32")]
                let r_sym = elf_r_sym(r_info as u32);
                
                if self.is_valid_ptr(offset) {
                    let reloc_addr = offset as *mut usize;
                    let _ = self.do_relocation(r_type, r_sym, reloc_addr, r_addend, ctx);
                }
                
                processed += 1;
            }
        }
        
        println!("[Reloc] Processed {} Android packed relocations", processed);
        Ok(())
    }
    
    fn read_sleb128(&self, data: &[u8]) -> (i64, usize) {
        let mut result: i64 = 0;
        let mut shift = 0;
        let mut pos = 0;
        
        loop {
            if pos >= data.len() {
                return (0, 0);
            }
            
            let byte = data[pos];
            pos += 1;
            
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            
            if (byte & 0x80) == 0 {
                // Sign extend if needed
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= !0i64 << shift;
                }
                break;
            }
        }
        
        (result, pos)
    }
    
    #[allow(dead_code)]
    fn get_sym_size(&self, sym_idx: u32) -> Option<usize> {
        if self.symtab.is_null() {
            return None;
        }
        unsafe {
            let sym_ptr = self.symtab.add(sym_idx as usize);
            if !self.is_valid_ptr(sym_ptr as usize) {
                return None;
            }
            let sym = &*sym_ptr;
            Some(sym.st_size as usize)
        }
    }
    
    fn is_weak_symbol(&self, sym_idx: u32) -> bool {
        if self.symtab.is_null() {
            return false;
        }
        unsafe {
            let sym_ptr = self.symtab.add(sym_idx as usize);
            if !self.is_valid_ptr(sym_ptr as usize) {
                return false;
            }
            let sym = &*sym_ptr;
            // STB_WEAK = 2, binding is in upper 4 bits of st_info
            (sym.st_info >> 4) == 2
        }
    }

    pub fn call_constructors(&self) {
        println!("[Init] Calling constructors...");
        if let Some(func) = self.init_func {
            println!("[Init] Calling DT_INIT at 0x{:x}", func as usize);
            func();
            println!("[Init] DT_INIT returned");
        }
        if !self.init_array.is_null() && self.init_array_count > 0 {
            println!("[Init] Calling {} init_array functions", self.init_array_count);
            let arrays = unsafe { slice::from_raw_parts(self.init_array, self.init_array_count) };
            for (i, func) in arrays.iter().enumerate() {
                let func_addr = *func as usize;
                // Skip invalid function pointers (0 or -1)
                if func_addr == 0 || func_addr == usize::MAX {
                    println!("[Init]   [{}/{}] Skipping invalid function pointer: 0x{:x}", 
                        i + 1, self.init_array_count, func_addr);
                    continue;
                }
                println!("[Init]   [{}/{}] Calling 0x{:x}", i + 1, self.init_array_count, func_addr);
                func();
            }
            println!("[Init] init_array done");
        }
        
        // Verify GOT entries are still intact after constructors
        println!("[Init] Verifying GOT entries after constructors...");
        self.verify_got_entries();
        
        println!("[Init] Constructors completed");
    }

    pub fn get_export_symbol(&self, name: &str) -> Option<usize> {
        if self.symtab.is_null() || self.strtab.is_null() {
            return None;
        }

        let count = if self.sym_count > 0 {
            self.sym_count
        } else {
            30000
        };

        for i in 0..count {
            unsafe {
                let sym_ptr = self.symtab.add(i);
                if !self.is_valid_ptr(sym_ptr as usize) {
                    break;
                }

                let sym = &*sym_ptr;
                if sym.st_name == 0 || sym.st_value == 0 {
                    continue;
                }

                if let Some(s) = self.get_safe_string(sym.st_name as usize) {
                    if s == name {
                        return Some(self.load_bias + sym.st_value as usize);
                    }
                }
            }
        }
        None
    }

    fn get_sym_name(&self, sym_idx: u32) -> Option<String> {
        if self.symtab.is_null() || self.strtab.is_null() {
            return None;
        }
        unsafe {
            let sym_ptr = self.symtab.add(sym_idx as usize);
            if !self.is_valid_ptr(sym_ptr as usize) {
                return None;
            }
            let sym = &*sym_ptr;
            self.get_safe_string(sym.st_name as usize)
        }
    }
    
    /// 获取符号的版本索引
    fn get_sym_version_index(&self, sym_idx: usize) -> Option<u16> {
        if self.versym.is_null() {
            return None;
        }
        unsafe {
            let versym_ptr = self.versym.add(sym_idx);
            if !self.is_valid_ptr(versym_ptr as usize) {
                return None;
            }
            Some(*versym_ptr)
        }
    }
    
    /// 获取版本定义的名称
    /// 根据版本索引从 verdef 中查找版本名称
    pub fn get_verdef_name(&self, ver_ndx: u16) -> Option<String> {
        use crate::elf::{Elf_Verdef, Elf_Verdaux, VER_NDX_LOCAL, VER_NDX_GLOBAL, VERSYM_VERSION};
        
        if self.verdef.is_null() || self.verdef_num == 0 {
            return None;
        }
        
        let ver_idx = ver_ndx & VERSYM_VERSION;
        if ver_idx == VER_NDX_LOCAL || ver_idx == VER_NDX_GLOBAL {
            return None; // 本地或全局基础版本，无特定名称
        }
        
        unsafe {
            let mut verdef_ptr = self.verdef;
            for _ in 0..self.verdef_num {
                if !self.is_valid_ptr(verdef_ptr as usize) {
                    break;
                }
                
                let verdef = &*(verdef_ptr as *const Elf_Verdef);
                
                if verdef.vd_ndx == ver_idx {
                    // 找到了，获取第一个 Verdaux 的名称
                    let verdaux_ptr = verdef_ptr.add(verdef.vd_aux as usize) as *const Elf_Verdaux;
                    if self.is_valid_ptr(verdaux_ptr as usize) {
                        let verdaux = &*verdaux_ptr;
                        return self.get_safe_string(verdaux.vda_name as usize);
                    }
                }
                
                if verdef.vd_next == 0 {
                    break;
                }
                verdef_ptr = verdef_ptr.add(verdef.vd_next as usize);
            }
        }
        
        None
    }
    
    /// 带版本的符号查找
    /// 如果请求的符号有版本要求（如 "malloc@GLIBC_2.17"），会匹配版本
    pub fn get_export_symbol_versioned(&self, name: &str, required_version: Option<&str>) -> Option<usize> {
        use crate::elf::{VER_NDX_LOCAL, VERSYM_HIDDEN, VERSYM_VERSION};
        
        if self.symtab.is_null() || self.strtab.is_null() {
            return None;
        }

        let count = if self.sym_count > 0 {
            self.sym_count
        } else {
            30000
        };

        for i in 0..count {
            unsafe {
                let sym_ptr = self.symtab.add(i);
                if !self.is_valid_ptr(sym_ptr as usize) {
                    break;
                }

                let sym = &*sym_ptr;
                if sym.st_name == 0 || sym.st_value == 0 {
                    continue;
                }

                if let Some(s) = self.get_safe_string(sym.st_name as usize) {
                    if s == name {
                        // 检查版本
                        if let Some(ver_idx) = self.get_sym_version_index(i) {
                            // 跳过隐藏的符号（除非明确请求）
                            if (ver_idx & VERSYM_HIDDEN) != 0 && required_version.is_none() {
                                continue;
                            }
                            
                            // 跳过本地符号
                            let ver_ndx = ver_idx & VERSYM_VERSION;
                            if ver_ndx == VER_NDX_LOCAL {
                                continue;
                            }
                            
                            // 如果有版本要求，检查是否匹配
                            if let Some(req_ver) = required_version {
                                if let Some(sym_ver) = self.get_verdef_name(ver_idx) {
                                    if sym_ver != req_ver {
                                        continue; // 版本不匹配
                                    }
                                }
                            }
                        }
                        
                        return Some(self.load_bias + sym.st_value as usize);
                    }
                }
            }
        }
        None
    }

    fn reserve_address_space(&mut self) -> Result<(), String> {
        let mut min_vaddr = Elf_Addr::MAX;
        let mut max_vaddr = 0;
        for ph in &self.phdrs {
            if ph.p_type == PT_LOAD {
                if ph.p_vaddr < min_vaddr {
                    min_vaddr = ph.p_vaddr;
                }
                if ph.p_vaddr + ph.p_memsz > max_vaddr {
                    max_vaddr = ph.p_vaddr + ph.p_memsz;
                }
            }
        }
        if min_vaddr == Elf_Addr::MAX {
            return Err("No PT_LOAD found".to_string());
        }
        let page_size = get_page_size();
        let min_vaddr_aligned = page_start(min_vaddr as usize, page_size);
        let max_vaddr_aligned = page_end(max_vaddr as usize, page_size);
        self.load_size = max_vaddr_aligned - min_vaddr_aligned;
        let addr = unsafe {
            mmap(
                ptr::null_mut(),
                self.load_size,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err("mmap failed".to_string());
        }
        self.base_addr = addr as usize;
        self.load_bias = self.base_addr - min_vaddr_aligned;
        Ok(())
    }

    fn map_segments(&self, source: &mut Box<dyn ElfRead>, page_size: usize) -> Result<(), String> {
        for ph in &self.phdrs {
            if ph.p_type != PT_LOAD {
                continue;
            }
            let seg_start = (ph.p_vaddr as usize) + self.load_bias;
            let seg_end = seg_start + (ph.p_memsz as usize);
            let seg_page_start = page_start(seg_start, page_size);
            let seg_page_end = page_end(seg_end, page_size);
            let file_start = ph.p_offset as u64;
            let file_len = ph.p_filesz as usize;
            let mem_len = ph.p_memsz as usize;

            let ret = unsafe {
                mprotect(
                    seg_page_start as *mut c_void,
                    seg_page_end - seg_page_start,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                )
            };
            if ret != 0 {
                return Err(format!(
                    "mprotect failed for segment 0x{:x}",
                    seg_page_start
                ));
            }

            if file_len > 0 {
                source
                    .seek(SeekFrom::Start(file_start))
                    .map_err(|e| e.to_string())?;
                let dst_slice =
                    unsafe { slice::from_raw_parts_mut(seg_start as *mut u8, file_len) };
                source.read_exact(dst_slice).map_err(|e| e.to_string())?;
            }
            
            // Zero out BSS section (mem_len > file_len means there's uninitialized data)
            if mem_len > file_len {
                let bss_start = seg_start + file_len;
                let bss_len = mem_len - file_len;
                unsafe {
                    ptr::write_bytes(bss_start as *mut u8, 0, bss_len);
                }
            }
        }
        Ok(())
    }

    fn is_valid_ptr(&self, ptr: usize) -> bool {
        ptr >= self.base_addr && ptr < self.base_addr + self.load_size
    }

    fn find_dynamic_section(&mut self) -> Result<(), String> {
        let mut dyn_vaddr = 0;
        let mut dyn_size = 0;
        for ph in &self.phdrs {
            if ph.p_type == PT_DYNAMIC {
                dyn_vaddr = ph.p_vaddr as usize;
                dyn_size = ph.p_memsz as usize;
                break;
            }
        }
        if dyn_vaddr == 0 {
            return Ok(());
        }

        let dyn_addr = self.load_bias + dyn_vaddr;
        if !self.is_valid_ptr(dyn_addr) || !self.is_valid_ptr(dyn_addr + dyn_size - 1) {
            return Err("Fatal: PT_DYNAMIC out of bounds".to_string());
        }

        self.dynamic = dyn_addr as *const Elf_Dyn;

        let mut init_off = 0;
        let mut init_array_off = 0;
        let mut init_array_sz = 0;
        let mut hash_off = 0;
        let mut strtab_off = 0;
        let mut symtab_off = 0;
        
        // RELA
        let mut rela_off = 0;
        let mut rela_sz = 0;
        
        // REL (without addend)
        let mut rel_off = 0;
        let mut rel_sz = 0;
        
        // PLT
        let mut jmprel_off = 0;
        let mut jmprel_sz = 0;
        let mut pltrel_type = 0usize;  // DT_RELA or DT_REL
        
        // RELR
        let mut relr_off = 0;
        let mut relr_sz = 0;
        
        // Android packed
        let mut android_rela_off = 0;
        let mut android_rela_sz = 0;
        
        // Symbol versioning
        let mut versym_off = 0;
        let mut verdef_off = 0;
        let mut verdef_num = 0;
        let mut verneed_off = 0;
        let mut verneed_num = 0;

        unsafe {
            let mut i = 0;
            loop {
                if i > 10000 {
                    return Err("Infinite loop in dynamic".to_string());
                }
                let dyn_entry = &*self.dynamic.add(i);
                if dyn_entry.d_tag == DT_NULL as _ {
                    break;
                }

                match dyn_entry.d_tag as usize {
                    DT_STRTAB => strtab_off = dyn_entry.d_val as usize,
                    DT_STRSZ => self.strtab_size = dyn_entry.d_val as usize,
                    DT_SYMTAB => symtab_off = dyn_entry.d_val as usize,
                    
                    // RELA
                    DT_RELA => rela_off = dyn_entry.d_val as usize,
                    DT_RELASZ => rela_sz = dyn_entry.d_val as usize,
                    
                    // REL
                    DT_REL => rel_off = dyn_entry.d_val as usize,
                    DT_RELSZ => rel_sz = dyn_entry.d_val as usize,
                    
                    // PLT
                    DT_JMPREL => jmprel_off = dyn_entry.d_val as usize,
                    DT_PLTRELSZ => jmprel_sz = dyn_entry.d_val as usize,
                    DT_PLTREL => pltrel_type = dyn_entry.d_val as usize,
                    
                    // RELR (packed relative relocations)
                    DT_RELR | DT_ANDROID_RELR => relr_off = dyn_entry.d_val as usize,
                    DT_RELRSZ | DT_ANDROID_RELRSZ => relr_sz = dyn_entry.d_val as usize,
                    
                    // Android packed
                    DT_ANDROID_RELA => android_rela_off = dyn_entry.d_val as usize,
                    DT_ANDROID_RELASZ => android_rela_sz = dyn_entry.d_val as usize,
                    DT_ANDROID_REL => {
                        if android_rela_off == 0 {
                            android_rela_off = dyn_entry.d_val as usize;
                        }
                    }
                    DT_ANDROID_RELSZ => {
                        if android_rela_sz == 0 {
                            android_rela_sz = dyn_entry.d_val as usize;
                        }
                    }
                    
                    DT_INIT => init_off = dyn_entry.d_val as usize,
                    DT_INIT_ARRAY => init_array_off = dyn_entry.d_val as usize,
                    DT_INIT_ARRAYSZ => init_array_sz = dyn_entry.d_val as usize,
                    DT_HASH => hash_off = dyn_entry.d_val as usize,
                    
                    // DT_GNU_HASH
                    DT_GNU_HASH => {
                        let gnu_hash_addr = self.load_bias + dyn_entry.d_val as usize;
                        if self.is_valid_ptr(gnu_hash_addr) {
                            let ptr = gnu_hash_addr as *const u32;
                            let nbuckets = *ptr;
                            let symndx = *ptr.add(1);
                            let maskwords = *ptr.add(2);
                            let bloom_size = if mem::size_of::<usize>() == 8 { 8 } else { 4 };
                            let buckets_ptr = ptr.add(4 + maskwords as usize * (bloom_size / 4));
                            let chain_ptr = buckets_ptr.add(nbuckets as usize);

                            let mut max_sym = symndx;
                            for bi in 0..nbuckets {
                                let sym_idx = *buckets_ptr.add(bi as usize);
                                if sym_idx != 0 && sym_idx > max_sym {
                                    max_sym = sym_idx;
                                }
                            }

                            if max_sym >= symndx {
                                let mut chain_idx = (max_sym - symndx) as usize;
                                loop {
                                    if !self.is_valid_ptr(chain_ptr.add(chain_idx) as usize) {
                                        break;
                                    }
                                    let hash = *chain_ptr.add(chain_idx);
                                    chain_idx += 1;
                                    if (hash & 1) != 0 {
                                        break;
                                    }
                                }
                                self.sym_count = symndx as usize + chain_idx;
                            } else {
                                self.sym_count = symndx as usize;
                            }
                        }
                    }
                    
                    // Symbol versioning
                    DT_VERSYM => versym_off = dyn_entry.d_val as usize,
                    DT_VERDEF => verdef_off = dyn_entry.d_val as usize,
                    DT_VERDEFNUM => verdef_num = dyn_entry.d_val as usize,
                    DT_VERNEED => verneed_off = dyn_entry.d_val as usize,
                    DT_VERNEEDNUM => verneed_num = dyn_entry.d_val as usize,
                    
                    _ => {}
                }
                i += 1;
            }
        }

        if strtab_off != 0 {
            let p = self.load_bias + strtab_off;
            if self.is_valid_ptr(p) {
                self.strtab = p as *const c_char;
            }
        }
        if symtab_off != 0 {
            let p = self.load_bias + symtab_off;
            if self.is_valid_ptr(p) {
                self.symtab = p as *const Elf_Sym;
            }
        }
        
        // RELA
        if rela_off != 0 {
            let p = self.load_bias + rela_off;
            if self.is_valid_ptr(p) {
                self.rela = p as *const Elf_Rela;
                self.rela_count = rela_sz / mem::size_of::<Elf_Rela>();
                println!("[DYN] Found RELA: {} entries at 0x{:x}", self.rela_count, p);
            }
        }
        
        // REL
        if rel_off != 0 {
            let p = self.load_bias + rel_off;
            if self.is_valid_ptr(p) {
                self.rel = p as *const Elf_Rel;
                self.rel_count = rel_sz / mem::size_of::<Elf_Rel>();
                println!("[DYN] Found REL: {} entries at 0x{:x}", self.rel_count, p);
            }
        }
        
        // PLT relocations - check DT_PLTREL to determine if it's REL or RELA
        if jmprel_off != 0 {
            let p = self.load_bias + jmprel_off;
            if self.is_valid_ptr(p) {
                self.jmp_rel = p as *const u8;
                // Default to RELA for AArch64 if DT_PLTREL is not specified
                self.plt_rel_is_rela = pltrel_type == DT_RELA || (pltrel_type == 0);
                
                if self.plt_rel_is_rela {
                    self.plt_rel_count = jmprel_sz / mem::size_of::<Elf_Rela>();
                } else {
                    self.plt_rel_count = jmprel_sz / mem::size_of::<Elf_Rel>();
                }
                println!("[DYN] Found PLT ({}): {} entries at 0x{:x}", 
                    if self.plt_rel_is_rela { "RELA" } else { "REL" }, 
                    self.plt_rel_count, p);
            }
        }
        
        // RELR
        if relr_off != 0 {
            let p = self.load_bias + relr_off;
            if self.is_valid_ptr(p) {
                self.relr = p as *const Elf_Addr;
                self.relr_count = relr_sz / mem::size_of::<Elf_Addr>();
                println!("[DYN] Found RELR: {} entries at 0x{:x}", self.relr_count, p);
            }
        }
        
        // Android packed
        if android_rela_off != 0 {
            let p = self.load_bias + android_rela_off;
            if self.is_valid_ptr(p) {
                self.android_rela = p as *const u8;
                self.android_rela_size = android_rela_sz;
                println!("[DYN] Found Android packed relocs: {} bytes at 0x{:x}", android_rela_sz, p);
            }
        }
        
        if init_off != 0 {
            let p = self.load_bias + init_off;
            if self.is_valid_ptr(p) {
                self.init_func = Some(unsafe { mem::transmute(p) });
            }
        }
        if init_array_off != 0 {
            let p = self.load_bias + init_array_off;
            if self.is_valid_ptr(p) {
                self.init_array = p as *const extern "C" fn();
                self.init_array_count = init_array_sz / mem::size_of::<usize>();
            }
        }

        if hash_off != 0 && self.sym_count == 0 {
            let p = self.load_bias + hash_off;
            if self.is_valid_ptr(p) {
                let ptr = p as *const u32;
                unsafe {
                    if self.is_valid_ptr(p + 4) {
                        self.sym_count = *ptr.add(1) as usize;
                    }
                }
            }
        }
        
        // Symbol versioning
        if versym_off != 0 {
            let p = self.load_bias + versym_off;
            if self.is_valid_ptr(p) {
                self.versym = p as *const u16;
            }
        }
        if verdef_off != 0 {
            let p = self.load_bias + verdef_off;
            if self.is_valid_ptr(p) {
                self.verdef = p as *const u8;
                self.verdef_num = verdef_num;
            }
        }
        if verneed_off != 0 {
            let p = self.load_bias + verneed_off;
            if self.is_valid_ptr(p) {
                self.verneed = p as *const u8;
                self.verneed_num = verneed_num;
            }
        }
        
        // Log versioning info if present
        if !self.versym.is_null() || !self.verdef.is_null() || !self.verneed.is_null() {
            println!("[DYN] Symbol versioning: versym={} verdef={} verneed={}",
                !self.versym.is_null(),
                self.verdef_num,
                self.verneed_num);
        }

        Ok(())
    }

    fn register_eh_frame(&mut self) {
        for ph in &self.phdrs {
            if ph.p_type == PT_GNU_EH_FRAME {
                let eh_frame_hdr = (self.load_bias + ph.p_vaddr as usize) as *const u8;
                if !self.is_valid_ptr(eh_frame_hdr as usize) {
                    continue;
                }
                
                // Parse .eh_frame_hdr to find the actual .eh_frame section
                // .eh_frame_hdr structure:
                //   version (1 byte)
                //   eh_frame_ptr_enc (1 byte)
                //   fde_count_enc (1 byte) 
                //   table_enc (1 byte)
                //   eh_frame_ptr (encoded, typically 4 bytes for DW_EH_PE_pcrel|DW_EH_PE_sdata4)
                unsafe {
                    let version = *eh_frame_hdr;
                    if version != 1 {
                        println!("[EH] Warning: Unsupported eh_frame_hdr version: {}", version);
                        continue;
                    }
                    
                    let eh_frame_ptr_enc = *eh_frame_hdr.add(1);
                    
                    // Decode the eh_frame pointer based on encoding
                    let eh_frame_addr = match eh_frame_ptr_enc {
                        // DW_EH_PE_pcrel | DW_EH_PE_sdata4 (0x1b)
                        0x1b => {
                            let ptr_loc = eh_frame_hdr.add(4) as *const i32;
                            let offset = *ptr_loc;
                            (ptr_loc as isize + offset as isize) as usize
                        }
                        // DW_EH_PE_absptr (0x00)
                        0x00 => {
                            let ptr_loc = eh_frame_hdr.add(4) as *const usize;
                            *ptr_loc
                        }
                        // DW_EH_PE_pcrel | DW_EH_PE_sdata8 (0x1c) - 64-bit
                        0x1c => {
                            let ptr_loc = eh_frame_hdr.add(4) as *const i64;
                            let offset = *ptr_loc;
                            (ptr_loc as isize + offset as isize) as usize
                        }
                        // For other encodings, try using eh_frame_hdr directly
                        _ => {
                            println!("[EH] Warning: Unknown eh_frame_ptr encoding: 0x{:x}, using hdr directly", eh_frame_ptr_enc);
                            eh_frame_hdr as usize
                        }
                    };
                    
                    if self.is_valid_ptr(eh_frame_addr) {
                        #[cfg(not(target_arch = "arm"))]
                        {
                            __register_frame(eh_frame_addr as *const u8);
                            self.eh_frame_addr = eh_frame_addr as *const u8;
                            println!("[EH] Registered exception frame at 0x{:x}", eh_frame_addr);
                        }
                    }
                }
                break;
            }
        }
    }
}

impl Drop for ElfLoader {
    fn drop(&mut self) {
        if !self.eh_frame_addr.is_null() {
            #[cfg(not(target_arch = "arm"))]
            unsafe {
                __deregister_frame(self.eh_frame_addr);
            }
        }
    }
}
