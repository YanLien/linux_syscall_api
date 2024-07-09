use axhal::mem::VirtAddr;
use axprocess::{current_process, futex::FutexKey};

use crate::{SyscallError, SyscallResult};

use super::flags::FLAGS_SHARED;

pub fn futex_get_value_locked(vaddr: VirtAddr) -> SyscallResult {
    let process = current_process();
    if process.manual_alloc_for_lazy(vaddr).is_ok() {
        let real_futex_val = unsafe { (vaddr.as_usize() as *const u32).read_volatile() };
        Ok(real_futex_val as isize)
    }
    else {
        Err(SyscallError::EFAULT)
    }
}

pub fn get_futex_key(uaddr: VirtAddr, flags: i32) -> FutexKey {
    if flags & FLAGS_SHARED != 0 {
        /* Todo: after implementing inode 
        let inode = uaddr.get_inode();
        let page_index = uaddr.get_page_index();
        let offset = uaddr.get_offset();
        FutexKey::new(inode, page_index, offset)
        */
        //error!("[linux_syscall_api::get_futex_key] shared futex is not supported yet");
        let pid = current_process().pid();
        let aligned = uaddr.align_down_4k().as_usize();
        let offset = uaddr.align_offset_4k() as u32;
        return FutexKey::new(pid, aligned, offset);
    }
    else {
        let pid = current_process().pid();
        let aligned = uaddr.align_down_4k().as_usize();
        let offset = uaddr.align_offset_4k() as u32;
        return FutexKey::new(pid, aligned, offset);
    } 
}