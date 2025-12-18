use libc::{sysconf, _SC_PAGESIZE};

pub fn get_page_size() -> usize {
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// 向下对齐到页边界 (用于 mmap 起始地址)
pub fn page_start(addr: usize, page_size: usize) -> usize {
    addr & !(page_size - 1)
}

/// 向上对齐到页边界 (用于计算内存大小)
pub fn page_end(addr: usize, page_size: usize) -> usize {
    (addr + page_size - 1) & !(page_size - 1)
}

/// 计算偏移量
pub fn page_offset(addr: usize, page_size: usize) -> usize {
    addr & (page_size - 1)
}