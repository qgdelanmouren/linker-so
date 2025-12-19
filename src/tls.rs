use std::alloc::{alloc, Layout};
use std::cell::RefCell;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use libc::c_void;

// =========================================================================
// TLS Registry (Global)
// =========================================================================

#[derive(Clone, Debug)]
pub struct TlsModuleInfo {
    pub id: usize,          // Module ID (1-based)
    pub image: *const u8,   // Start of .tdata in memory
    pub image_size: usize,  // Size of .tdata
    pub mem_size: usize,    // Size of full TLS block (.tdata + .tbss)
    pub align: usize,       // Alignment requirement
}

// Global registry of TLS modules
// We use a simple static Mutex for thread safety
static mut TLS_REGISTRY_PTR: *mut Mutex<Vec<TlsModuleInfo>> = ptr::null_mut();
static TLS_REGISTRY_INIT: std::sync::Once = std::sync::Once::new();

fn get_registry() -> &'static Mutex<Vec<TlsModuleInfo>> {
    unsafe {
        TLS_REGISTRY_INIT.call_once(|| {
            let registry = Box::new(Mutex::new(Vec::new()));
            TLS_REGISTRY_PTR = Box::into_raw(registry);
        });
        &*TLS_REGISTRY_PTR
    }
}

/// Register a new TLS module and return its ID (1-based)
pub fn register_tls_module(image: *const u8, image_size: usize, mem_size: usize, align: usize) -> usize {
    let registry = get_registry();
    let mut modules = registry.lock().unwrap();
    
    let id = modules.len() + 1;
    modules.push(TlsModuleInfo {
        id,
        image,
        image_size,
        mem_size,
        align,
    });
    
    // println!("[TLS] Registered module id={} size={}/{} align={}", id, image_size, mem_size, align);
    id
}

fn get_module_info(id: usize) -> Option<TlsModuleInfo> {
    let registry = get_registry();
    let modules = registry.lock().unwrap();
    // id is 1-based
    if id > 0 && id <= modules.len() {
        Some(modules[id - 1].clone())
    } else {
        None
    }
}

// =========================================================================
// Per-Thread DTV (Dynamic Thread Vector)
// =========================================================================

// We use Rust's thread_local to manage our "DTV"
// This maps module_id -> pointer to thread-local instance
thread_local! {
    static DTV: RefCell<Vec<*mut u8>> = RefCell::new(Vec::new());
}

thread_local! {
    static EMUTLS_DTV: RefCell<Vec<*mut u8>> = RefCell::new(Vec::new());
}

static EMUTLS_NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);

#[repr(C)]
pub struct EmutlsControl {
    pub size: usize,
    pub align: usize,
    pub index: usize,
    pub value: *const u8,
}

// =========================================================================
// Core Implementation
// =========================================================================

/// The core logic to get TLS address for (module_id, offset)
/// Allocates the TLS block if it doesn't exist for this thread.
unsafe fn get_tls_addr_inner(module_id: usize, offset: usize) -> *mut u8 {
    if module_id == 0 {
        return ptr::null_mut();
    }

    DTV.with(|dtv_cell| {
        let mut dtv = dtv_cell.borrow_mut();
        
        // Ensure DTV is large enough
        if dtv.len() < module_id {
            dtv.resize(module_id, ptr::null_mut());
        }
        
        // Check if block is allocated (index is module_id - 1)
        let idx = module_id - 1;
        if dtv[idx].is_null() {
            // Need to allocate
            if let Some(info) = get_module_info(module_id) {
                // Layout must have non-zero size
                let size = if info.mem_size > 0 { info.mem_size } else { 1 };
                let align = if info.align > 0 { info.align } else { 1 };
                
                let layout = Layout::from_size_align(size, align).unwrap();
                let ptr = unsafe { alloc(layout) };
                
                if ptr.is_null() {
                    eprintln!("[TLS] Fatal: OOM allocating TLS block for module {}", module_id);
                    std::process::abort();
                }
                
                // Initialize: Copy .tdata
                if info.image_size > 0 && !info.image.is_null() {
                    unsafe {
                        ptr::copy_nonoverlapping(info.image, ptr, info.image_size);
                    }
                }
                
                // Zero .tbss
                if info.mem_size > info.image_size {
                    unsafe {
                        ptr::write_bytes(ptr.add(info.image_size), 0, info.mem_size - info.image_size);
                    }
                }
                
                dtv[idx] = ptr;
                // println!("[TLS] Thread {:?} allocated block for module {} at {:p}", std::thread::current().id(), module_id, ptr);
            } else {
                eprintln!("[TLS] Fatal: Request for unknown TLS module ID {}", module_id);
                // Return a dummy safe pointer to avoid immediate crash, or abort
                // std::process::abort();
            }
        }
        
        let block_start = dtv[idx];
        if block_start.is_null() {
            ptr::null_mut()
        } else {
            unsafe { block_start.add(offset) }
        }
    })
}

// =========================================================================
// Public Entry Points (ABI)
// =========================================================================

/// __tls_get_addr
/// ABI: Passed a pointer to struct { size_t module_id; size_t offset; }
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tls_get_addr(arg: *const usize) -> *mut c_void {
    if arg.is_null() { return ptr::null_mut(); }
    let module_id = unsafe { *arg };
    let offset = unsafe { *arg.add(1) };
    
    // println!("[TLS] __tls_get_addr(mod={}, off={})", module_id, offset);
    
    let ptr = unsafe { get_tls_addr_inner(module_id, offset) };
    ptr as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __emutls_get_address(control: *mut EmutlsControl) -> *mut c_void {
    if control.is_null() {
        return ptr::null_mut();
    }

    let ctl = unsafe { &mut *control };
    if ctl.index == 0 {
        let idx = EMUTLS_NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
        ctl.index = idx;
    }

    let slot = ctl.index.saturating_sub(1);
    EMUTLS_DTV.with(|dtv_cell| {
        let mut dtv = dtv_cell.borrow_mut();
        if dtv.len() <= slot {
            dtv.resize(slot + 1, ptr::null_mut());
        }

        if dtv[slot].is_null() {
            let size = if ctl.size > 0 { ctl.size } else { 1 };
            let mut align = if ctl.align > 0 { ctl.align } else { 1 };
            if !align.is_power_of_two() {
                align = align.next_power_of_two();
            }

            let layout = Layout::from_size_align(size, align).unwrap();
            let p = unsafe { alloc(layout) };
            if p.is_null() {
                eprintln!("[TLS] Fatal: OOM allocating EMUTLS block size={} align={}", size, align);
                std::process::abort();
            }

            if ctl.value.is_null() {
                unsafe { ptr::write_bytes(p, 0, size) };
            } else {
                if ctl.size > 0 {
                    unsafe { ptr::copy_nonoverlapping(ctl.value, p, ctl.size) };
                }
            }

            dtv[slot] = p;
        }

        dtv[slot] as *mut c_void
    })
}

// =========================================================================
// TLSDESC Support
// =========================================================================

// Helpers to read Thread Pointer

// AArch64: TP in tpidr_el0
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn get_tp() -> usize {
    let tp: usize;
    unsafe { std::arch::asm!("mrs {}, tpidr_el0", out(reg) tp) };
    tp
}

// x86_64: TP is fs_base. In Linux/Android, fs:0 points to the TCB (which starts with self-pointer).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn get_tp() -> usize {
    let tp: usize;
    unsafe { std::arch::asm!("mov {}, fs:[0]", out(reg) tp) };
    tp
}

// x86 (32-bit): TP is gs_base. gs:0 points to self.
#[cfg(target_arch = "x86")]
#[inline(always)]
unsafe fn get_tp() -> usize {
    let tp: usize;
    unsafe { std::arch::asm!("mov {}, gs:[0]", out(reg) tp) };
    tp
}

// ARM (32-bit): TP in CP15 c13
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn get_tp() -> usize {
    let tp: usize;
    unsafe { std::arch::asm!("mrc p15, 0, {}, c13, c0, 3", out(reg) tp) };
    tp
}

// Fallback for others
#[cfg(not(any(
    target_arch = "aarch64", 
    target_arch = "x86_64", 
    target_arch = "x86", 
    target_arch = "arm"
)))]
unsafe fn get_tp() -> usize {
    0 
}

/// The Rust implementation of the TLSDESC resolver.
/// Arguments:
///   ptr: The pointer to the TLSDESC entry (GOT entry).
///        Entry[0] = resolver address (this function's trampoline)
///        Entry[1] = argument (we store pointer to TlsDescArg here)
/// Returns:
///   The offset from TP to the TLS variable (TP_OFFSET).
///   i.e. Addr = TP + TP_OFFSET  =>  TP_OFFSET = Addr - TP
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tlsdesc_resolver_impl(entry_ptr: *const usize) -> usize {
    if entry_ptr.is_null() { return 0; }
    let arg_ptr = unsafe { *entry_ptr.add(1) as *const usize };
    if arg_ptr.is_null() {
        return 0;
    }
    
    let module_id = unsafe { *arg_ptr };
    let offset = unsafe { *arg_ptr.add(1) };
    
    // 1. Get absolute address
    let abs_addr = unsafe { get_tls_addr_inner(module_id, offset) as usize };
    if abs_addr == 0 { return 0; }
    
    // 2. Get TP
    let tp = unsafe { get_tp() };
    
    // 3. Return delta (Abs - TP)
    // Note: wrapping_sub handles the negative case correctly (usize is unsigned, but 2's complement works)
    abs_addr.wrapping_sub(tp)
}

// Trampoline for TLSDESC
#[cfg(target_arch = "aarch64")]
use std::arch::global_asm;

#[cfg(target_arch = "aarch64")]
global_asm!(
    ".global tlsdesc_resolver_trampoline",
    "tlsdesc_resolver_trampoline:",
    // Save x1-x18
    "stp x1, x2, [sp, #-16]!",
    "stp x3, x4, [sp, #-16]!",
    "stp x5, x6, [sp, #-16]!",
    "stp x7, x8, [sp, #-16]!",
    "stp x9, x10, [sp, #-16]!",
    "stp x11, x12, [sp, #-16]!",
    "stp x13, x14, [sp, #-16]!",
    "stp x15, x16, [sp, #-16]!",
    "stp x17, x18, [sp, #-16]!",
    // Save x29(fp), x30(lr)
    "stp x29, x30, [sp, #-16]!",
    
    // Save NZCV (Flags)
    // We use x1 as scratch because x1 is already saved on stack
    "mrs x1, nzcv",
    "sub sp, sp, #16",  // Keep stack aligned
    "str x1, [sp]",

    // Save FP/SIMD registers q0-q31
    // This is a lot of stack space (32 * 16 = 512 bytes)
    "sub sp, sp, #512",
    "stp q0, q1, [sp, #0]",
    "stp q2, q3, [sp, #32]",
    "stp q4, q5, [sp, #64]",
    "stp q6, q7, [sp, #96]",
    "stp q8, q9, [sp, #128]",
    "stp q10, q11, [sp, #160]",
    "stp q12, q13, [sp, #192]",
    "stp q14, q15, [sp, #224]",
    "stp q16, q17, [sp, #256]",
    "stp q18, q19, [sp, #288]",
    "stp q20, q21, [sp, #320]",
    "stp q22, q23, [sp, #352]",
    "stp q24, q25, [sp, #384]",
    "stp q26, q27, [sp, #416]",
    "stp q28, q29, [sp, #448]",
    "stp q30, q31, [sp, #480]",
    
    // Call implementation
    // x0 is already the argument (descriptor ptr)
    "bl tlsdesc_resolver_impl",
    
    // Restore FP/SIMD
    "ldp q0, q1, [sp, #0]",
    "ldp q2, q3, [sp, #32]",
    "ldp q4, q5, [sp, #64]",
    "ldp q6, q7, [sp, #96]",
    "ldp q8, q9, [sp, #128]",
    "ldp q10, q11, [sp, #160]",
    "ldp q12, q13, [sp, #192]",
    "ldp q14, q15, [sp, #224]",
    "ldp q16, q17, [sp, #256]",
    "ldp q18, q19, [sp, #288]",
    "ldp q20, q21, [sp, #320]",
    "ldp q22, q23, [sp, #352]",
    "ldp q24, q25, [sp, #384]",
    "ldp q26, q27, [sp, #416]",
    "ldp q28, q29, [sp, #448]",
    "ldp q30, q31, [sp, #480]",
    "add sp, sp, #512",
    
    // Restore NZCV
    "ldr x1, [sp]",
    "msr nzcv, x1",
    "add sp, sp, #16",

    // Restore GPRs
    "ldp x29, x30, [sp], #16",
    "ldp x17, x18, [sp], #16",
    "ldp x15, x16, [sp], #16",
    "ldp x13, x14, [sp], #16",
    "ldp x11, x12, [sp], #16",
    "ldp x9, x10, [sp], #16",
    "ldp x7, x8, [sp], #16",
    "ldp x5, x6, [sp], #16",
    "ldp x3, x4, [sp], #16",
    "ldp x1, x2, [sp], #16",
    
    "ret"
);

// x86_64 Trampoline
#[cfg(target_arch = "x86_64")]
use std::arch::global_asm;

#[cfg(target_arch = "x86_64")]
global_asm!(
    // ".intel_syntax noprefix", // Intel syntax is default, removing to avoid warning
    ".global tlsdesc_resolver_trampoline",
    "tlsdesc_resolver_trampoline:",
    // Argument in RAX (pointer to GOT entry)
    // We need to call tlsdesc_resolver_impl(RAX)
    // And preserve registers: RCX, RDX, RSI, RDI, R8-R11
    // And Flags.

    "pushfq", // Save Flags (x86_64 uses pushfq, not pushf usually, but pushf might assemble to pushfq in 64-bit)
    
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push r8",
    "push r9",
    "push r10",
    "push r11",

    // Move RAX to RDI (Argument 1 for C ABI)
    "mov rdi, rax",
    
    // Call
    "call tlsdesc_resolver_impl",
    
    // Restore
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    
    "popfq",
    "ret"
);

// ARM Trampoline
#[cfg(target_arch = "arm")]
use std::arch::global_asm;

#[cfg(target_arch = "arm")]
global_asm!(
    ".global tlsdesc_resolver_trampoline",
    "tlsdesc_resolver_trampoline:",
    // Arg in R0. Result in R0.
    // Preserve R1-R3, R12, LR, CPSR.
    // Also save D0-D7? For safety let's save what we can.
    
    // Escape braces for format string!
    "push {{r1-r3, r12, lr}}", // Save GPRs
    "vpush {{d0-d7}}",         // Save VFP (if available, assume yes for v7a)
    "mrs r1, cpsr",          // Save CPSR
    "push {{r1}}",

    // Call
    "bl tlsdesc_resolver_impl",
    
    // Restore
    "pop {{r1}}",
    "msr cpsr_f, r1",        // Restore flags
    "vpop {{d0-d7}}",
    "pop {{r1-r3, r12, pc}}"   // Return by popping LR into PC
);

// x86 Trampoline
#[cfg(target_arch = "x86")]
use std::arch::global_asm;

#[cfg(target_arch = "x86")]
global_asm!(
    ".intel_syntax noprefix",
    ".global tlsdesc_resolver_trampoline",
    "tlsdesc_resolver_trampoline:",
    // Arg in EAX. Result in EAX.
    
    // Stack alignment might be needed (16-byte).
    "push ebp",
    "mov ebp, esp",
    
    // Preserve caller-saved registers that C function might clobber
    // TLSDESC resolver must preserve all registers except EAX (return val) and EFLAGS
    // Entry ESP is misaligned by 4 (ret addr).
    // push ebp -> misaligned by 8
    "push ecx", // misaligned by 12
    "push edx", // aligned (0 mod 16)
    
    // We need to pass 1 argument (EAX).
    // Stack must be 16-byte aligned *before* the call instruction.
    // If we just push eax, esp becomes misaligned by 4.
    // So we pad 12 bytes first.
    "sub esp, 12",
    "push eax", // ESP is now aligned (0 mod 16)
    
    "call tlsdesc_resolver_impl@PLT",
    
    // Cleanup stack (pop argument + padding)
    "add esp, 16",
    
    // Restore registers
    "pop edx",
    "pop ecx",
    
    "pop ebp",
    "ret"
);

unsafe extern "C" {
    pub fn tlsdesc_resolver_trampoline();
}

#[cfg(not(any(
    target_arch = "aarch64", 
    target_arch = "x86_64", 
    target_arch = "x86", 
    target_arch = "arm"
)))]
pub unsafe extern "C" fn tlsdesc_resolver_trampoline() {
    panic!("TLSDESC not supported on this architecture");
}
