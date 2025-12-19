#![allow(non_camel_case_types)]
#![allow(dead_code)]

// ==========================================
// 基础类型
// ==========================================
pub type Elf64_Addr = u64;
pub type Elf64_Off = u64;
pub type Elf64_Half = u16;
pub type Elf64_Word = u32;
pub type Elf64_Sword = i32;
pub type Elf64_Xword = u64;
pub type Elf64_Sxword = i64;

pub type Elf32_Addr = u32;
pub type Elf32_Off = u32;
pub type Elf32_Half = u16;
pub type Elf32_Word = u32;
pub type Elf32_Sword = i32;

// ==========================================
// 常量定义
// ==========================================
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];

// Segment Types
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474E550;
pub const PT_GNU_RELRO: u32 = 0x6474E552;

// Dynamic Array Tags (d_tag)
pub const DT_NULL: usize = 0;
pub const DT_NEEDED: usize = 1;
pub const DT_PLTRELSZ: usize = 2;
pub const DT_PLTGOT: usize = 3;
pub const DT_HASH: usize = 4;
pub const DT_STRTAB: usize = 5;
pub const DT_SYMTAB: usize = 6;
pub const DT_RELA: usize = 7;
pub const DT_RELASZ: usize = 8;
pub const DT_RELAENT: usize = 9;
pub const DT_STRSZ: usize = 10;
pub const DT_SYMENT: usize = 11;
pub const DT_INIT: usize = 12;
pub const DT_FINI: usize = 13;
pub const DT_SONAME: usize = 14;
pub const DT_RPATH: usize = 15;
pub const DT_SYMBOLIC: usize = 16;
pub const DT_REL: usize = 17;
pub const DT_RELSZ: usize = 18;
pub const DT_RELENT: usize = 19;
pub const DT_PLTREL: usize = 20;
pub const DT_DEBUG: usize = 21;
pub const DT_TEXTREL: usize = 22;
pub const DT_JMPREL: usize = 23;
pub const DT_BIND_NOW: usize = 24;
pub const DT_INIT_ARRAY: usize = 25;
pub const DT_FINI_ARRAY: usize = 26;
pub const DT_INIT_ARRAYSZ: usize = 27;
pub const DT_FINI_ARRAYSZ: usize = 28;
pub const DT_RUNPATH: usize = 29;
pub const DT_FLAGS: usize = 30;
pub const DT_PREINIT_ARRAY: usize = 32;
pub const DT_PREINIT_ARRAYSZ: usize = 33;

// GNU Extensions
pub const DT_GNU_HASH: usize = 0x6ffffef5;
pub const DT_RELACOUNT: usize = 0x6ffffff9;
pub const DT_RELCOUNT: usize = 0x6ffffffa;
pub const DT_FLAGS_1: usize = 0x6ffffffb;
pub const DT_VERSYM: usize = 0x6ffffff0;
pub const DT_VERDEF: usize = 0x6ffffffc;
pub const DT_VERDEFNUM: usize = 0x6ffffffd;
pub const DT_VERNEED: usize = 0x6ffffffe;
pub const DT_VERNEEDNUM: usize = 0x6fffffff;

// RELR (relative relocations packed)
pub const DT_RELR: usize = 36;
pub const DT_RELRSZ: usize = 35;
pub const DT_RELRENT: usize = 37;

// Android packed relocations
pub const DT_ANDROID_REL: usize = 0x6000000f;
pub const DT_ANDROID_RELSZ: usize = 0x60000010;
pub const DT_ANDROID_RELA: usize = 0x60000011;
pub const DT_ANDROID_RELASZ: usize = 0x60000012;
pub const DT_ANDROID_RELR: usize = 0x6fffe000;
pub const DT_ANDROID_RELRSZ: usize = 0x6fffe001;
pub const DT_ANDROID_RELRENT: usize = 0x6fffe003;

// Symbol Types (st_info & 0xf)
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;

// Symbol Bindings (st_info >> 4)
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

// Relocation Types (AArch64)
pub const R_AARCH64_NONE: u32 = 0;
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_ABS32: u32 = 258;
pub const R_AARCH64_ABS16: u32 = 259;
pub const R_AARCH64_PREL64: u32 = 260;
pub const R_AARCH64_PREL32: u32 = 261;
pub const R_AARCH64_PREL16: u32 = 262;
pub const R_AARCH64_COPY: u32 = 1024;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_TLS_DTPMOD64: u32 = 1028;
pub const R_AARCH64_TLS_DTPREL64: u32 = 1029;
pub const R_AARCH64_TLS_TPREL64: u32 = 1030;
pub const R_AARCH64_TLSDESC: u32 = 1031;
pub const R_AARCH64_IRELATIVE: u32 = 1032;

// Relocation Types (ARM 32-bit)
pub const R_ARM_ABS32: u32 = 2;
pub const R_ARM_REL32: u32 = 3;
pub const R_ARM_GLOB_DAT: u32 = 21;
pub const R_ARM_JUMP_SLOT: u32 = 22;
pub const R_ARM_RELATIVE: u32 = 23;
pub const R_ARM_TLS_DTPMOD32: u32 = 17;
pub const R_ARM_TLS_DTPOFF32: u32 = 18;
pub const R_ARM_TLS_TPOFF32: u32 = 19;
pub const R_ARM_TLS_DESC: u32 = 13; // Check specific value for ARM TLSDESC
pub const R_ARM_IRELATIVE: u32 = 160;

// Relocation Types (x86_64)
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_TLSDESC: u32 = 36;
pub const R_X86_64_IRELATIVE: u32 = 37;

// Relocation Types (x86 i386)
pub const R_386_32: u32 = 1;
pub const R_386_PC32: u32 = 2;
pub const R_386_GOT32: u32 = 3;
pub const R_386_PLT32: u32 = 4;
pub const R_386_COPY: u32 = 5;
pub const R_386_GLOB_DAT: u32 = 6;
pub const R_386_JMP_SLOT: u32 = 7;
pub const R_386_RELATIVE: u32 = 8;
pub const R_386_GOTOFF: u32 = 9;
pub const R_386_GOTPC: u32 = 10;
pub const R_386_TLS_TPOFF: u32 = 14;
pub const R_386_TLS_DTPMOD32: u32 = 35;
pub const R_386_TLS_DTPOFF32: u32 = 36;
pub const R_386_TLS_DESC: u32 = 41;
pub const R_386_IRELATIVE: u32 = 42;

// ==========================================
// 32-bit 结构体
// ==========================================
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf32_Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: Elf32_Half,
    pub e_machine: Elf32_Half,
    pub e_version: Elf32_Word,
    pub e_entry: Elf32_Addr,
    pub e_phoff: Elf32_Off,
    pub e_shoff: Elf32_Off,
    pub e_flags: Elf32_Word,
    pub e_ehsize: Elf32_Half,
    pub e_phentsize: Elf32_Half,
    pub e_phnum: Elf32_Half,
    pub e_shentsize: Elf32_Half,
    pub e_shnum: Elf32_Half,
    pub e_shstrndx: Elf32_Half,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf32_Phdr {
    pub p_type: Elf32_Word,
    pub p_offset: Elf32_Off,
    pub p_vaddr: Elf32_Addr,
    pub p_paddr: Elf32_Addr,
    pub p_filesz: Elf32_Word,
    pub p_memsz: Elf32_Word,
    pub p_flags: Elf32_Word,
    pub p_align: Elf32_Word,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf32_Dyn {
    pub d_tag: Elf32_Sword,
    pub d_val: Elf32_Word, // union d_un
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf32_Sym {
    pub st_name: Elf32_Word,
    pub st_value: Elf32_Addr,
    pub st_size: Elf32_Word,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: Elf32_Half,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf32_Rel {
    pub r_offset: Elf32_Addr,
    pub r_info: Elf32_Word,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf32_Rela {
    pub r_offset: Elf32_Addr,
    pub r_info: Elf32_Word,
    pub r_addend: Elf32_Sword,
}

// ==========================================
// 64-bit 结构体
// ==========================================
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64_Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: Elf64_Half,
    pub e_machine: Elf64_Half,
    pub e_version: Elf64_Word,
    pub e_entry: Elf64_Addr,
    pub e_phoff: Elf64_Off,
    pub e_shoff: Elf64_Off,
    pub e_flags: Elf64_Word,
    pub e_ehsize: Elf64_Half,
    pub e_phentsize: Elf64_Half,
    pub e_phnum: Elf64_Half,
    pub e_shentsize: Elf64_Half,
    pub e_shnum: Elf64_Half,
    pub e_shstrndx: Elf64_Half,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64_Phdr {
    pub p_type: Elf64_Word,
    pub p_flags: Elf64_Word,
    pub p_offset: Elf64_Off,
    pub p_vaddr: Elf64_Addr,
    pub p_paddr: Elf64_Addr,
    pub p_filesz: Elf64_Xword,
    pub p_memsz: Elf64_Xword,
    pub p_align: Elf64_Xword,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64_Dyn {
    pub d_tag: Elf64_Sxword,
    pub d_val: Elf64_Xword, // union d_un
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64_Sym {
    pub st_name: Elf64_Word,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: Elf64_Half,
    pub st_value: Elf64_Addr,
    pub st_size: Elf64_Xword,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64_Rela {
    pub r_offset: Elf64_Addr,
    pub r_info: Elf64_Xword,
    pub r_addend: Elf64_Sxword,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64_Rel {
    pub r_offset: Elf64_Addr,
    pub r_info: Elf64_Xword,
}


// ==========================================
// 自动适配层
// ==========================================

#[cfg(target_pointer_width = "64")]
pub type Elf_Ehdr = Elf64_Ehdr;
#[cfg(target_pointer_width = "64")]
pub type Elf_Phdr = Elf64_Phdr;
#[cfg(target_pointer_width = "64")]
pub type Elf_Dyn = Elf64_Dyn;
#[cfg(target_pointer_width = "64")]
pub type Elf_Sym = Elf64_Sym;
#[cfg(target_pointer_width = "64")]
pub type Elf_Rela = Elf64_Rela;
#[cfg(target_pointer_width = "64")]
pub type Elf_Rel = Elf64_Rel;
#[cfg(target_pointer_width = "64")]
pub type Elf_Addr = Elf64_Addr;
#[cfg(target_pointer_width = "64")]
pub type Elf_Word = Elf64_Word;
#[cfg(target_pointer_width = "64")]
pub type Elf_Sxword = Elf64_Sxword;

#[cfg(target_pointer_width = "32")]
pub type Elf_Ehdr = Elf32_Ehdr;
#[cfg(target_pointer_width = "32")]
pub type Elf_Phdr = Elf32_Phdr;
#[cfg(target_pointer_width = "32")]
pub type Elf_Dyn = Elf32_Dyn;
#[cfg(target_pointer_width = "32")]
pub type Elf_Sym = Elf32_Sym;
#[cfg(target_pointer_width = "32")]
pub type Elf_Rela = Elf32_Rela; // 注意：ARM32通常使用REL而非RELA，但为了统一接口先定义
#[cfg(target_pointer_width = "32")]
pub type Elf_Rel = Elf32_Rel;
#[cfg(target_pointer_width = "32")]
pub type Elf_Addr = Elf32_Addr;
#[cfg(target_pointer_width = "32")]
pub type Elf_Word = Elf32_Word;
#[cfg(target_pointer_width = "32")]
pub type Elf_Sxword = Elf32_Sword;

// 辅助函数：从 r_info 获取 type 和 symbol index
#[inline(always)]
#[cfg(target_pointer_width = "64")]
pub fn elf_r_type(info: u64) -> u32 {
    (info & 0xffffffff) as u32
}

#[inline(always)]
#[cfg(target_pointer_width = "64")]
pub fn elf_r_sym(info: u64) -> u32 {
    (info >> 32) as u32
}

#[inline(always)]
#[cfg(target_pointer_width = "32")]
pub fn elf_r_type(info: u32) -> u32 {
    info & 0xff
}

#[inline(always)]
#[cfg(target_pointer_width = "32")]
pub fn elf_r_sym(info: u32) -> u32 {
    info >> 8
}