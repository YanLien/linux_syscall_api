//! 支持 futex 相关的 syscall

extern crate alloc;

use core::time::Duration;

use axlog::{error, warn};
use axprocess::{
    current_process, current_task,
    futex::FutexRobustList}
;

use crate::{syscall_task::imp::futex::waitwake::futex_requeue, RobustList, SyscallError, SyscallResult, TimeSecs};

use super::{flags::{
    futex_op_to_flag, FLAGS_CLOCKRT, FLAGS_SHARED, FUTEX_BITSET_MATCH_ANY, FUTEX_CMD_MASK, FUTEX_CMP_REQUEUE, FUTEX_REQUEUE, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET, FUTEX_WAKE_OP
}, waitwake::{futex_wait, futex_wake, futex_wake_bitset}};

/// prepare to replace syscall_futex
pub fn syscall_futex(args: [usize; 6]) -> SyscallResult {
    let uaddr = args[0];
    let futex_op = args[1] as i32;
    let val = args[2] as u32;
    /* arg[3] is time_out_val or val2 depends on futex_op */
    let val2 = args[3];
    let uaddr2 = args[4];
    let mut val3 = args[5] as u32;

    let process = current_process();


    let flags: i32 = futex_op_to_flag(futex_op);
    // cmd determines the operation of futex
    let cmd: i32 = futex_op & FUTEX_CMD_MASK;
    // TODO: shared futex and real time clock 
    // It's Ok for ananonymous mmap to use private futex
    if (flags & FLAGS_SHARED) != 0 {
        warn!("shared futex is not supported, but it's ok for anonymous mmap to use private futex");
    }
    if (flags & FLAGS_CLOCKRT) != 0 {
        panic!("FUTEX_CLOCK_REALTIME is not supported");
    }
    match cmd {
        FUTEX_WAIT => {
            val3 = FUTEX_BITSET_MATCH_ANY;
            // convert `TimeSecs` struct to `timeout` nanoseconds
            let timeout = if val2 != 0 && process.manual_alloc_for_lazy(val2.into()).is_ok()
            {
                let time_sepc: TimeSecs = unsafe { *(val2 as *const TimeSecs) };
                time_sepc.turn_to_nanos()
            } else {
                // usize::MAX
                0
            };
            let deadline: Option<Duration> = if timeout != 0 {
                Some(Duration::from_nanos(timeout as u64))
            } else {
                None
            };
            futex_wait(uaddr.into(), flags, val, deadline, val3)?;
        }
        FUTEX_WAIT_BITSET => {
            // convert `TimeSecs` struct to `timeout` nanoseconds
            let timeout = if val2 != 0 && process.manual_alloc_for_lazy(val2.into()).is_ok()
            {
                let time_sepc: TimeSecs = unsafe { *(val2 as *const TimeSecs) };
                time_sepc.turn_to_nanos()
            } else {
                // usize::MAX
                0
            };
            // convert absolute timeout to relative timeout
            let deadline = if timeout != 0 {
                Some(Duration::from_nanos(timeout as u64) - axhal::time::current_time())
            } else {
                None
            };
            futex_wait(uaddr.into(), flags, val, deadline, val3)?;   
        }
        FUTEX_WAKE => {
            futex_wake(uaddr.into(), flags, val)?;
        }
        FUTEX_WAKE_BITSET => {
            futex_wake_bitset(uaddr.into(), flags, val, val3)?;
        }
        FUTEX_REQUEUE => {
            futex_requeue(uaddr.into(), flags, val, uaddr2.into(), val2 as u32)?;
        }
        FUTEX_CMP_REQUEUE => {
            // futex_requeue(uaddr, flags, uaddr2, flags, val, val2, &val3, 0)
            error!("[linux_syscall_api] futex: unsupported futex operation: FUTEX_CMP_REQUEUE");
            return Err(SyscallError::ENOSYS);
        }
        FUTEX_WAKE_OP => {
            // futex_wake(uaddr, flags, uaddr2, val, val2, val3)
            error!("[linux_syscall_api] futex: unsupported futex operation: FUTEX_WAKE_OP", );
            return Err(SyscallError::ENOSYS);
        }
        // TODO: priority-inheritance futex 
        _ => {
            error!("[linux_syscall_api] futex: unsupported futex operation: {}", cmd);
            return Err(SyscallError::ENOSYS);
        }
    }
    // success anyway and reach here
    Ok(0)
} 

/* 
/// # Arguments
/// * vaddr: usize
/// * futex_op: i32
/// * futex_val: u32
/// * time_out_val: usize
/// * vaddr2: usize
/// * val3: u32
pub fn syscall_futex(args: [usize; 6]) -> SyscallResult {
    let vaddr = args[0];
    let futex_op = args[1] as i32;
    let futex_val = args[2] as u32;
    let time_out_val = args[3];
    let vaddr2 = args[4];
    let val3 = args[5] as u32;
    let process = current_process();
    let timeout = if time_out_val != 0 && process.manual_alloc_for_lazy(time_out_val.into()).is_ok()
    {
        let time_sepc: TimeSecs = unsafe { *(time_out_val as *const TimeSecs) };
        time_sepc.turn_to_nanos()
    } else {
        // usize::MAX
        0
    };
    // 释放锁，防止任务无法被调度
    match futex(
        vaddr.into(),
        futex_op,
        futex_val,
        timeout,
        vaddr2.into(),
        time_out_val,
        val3,
    ) {
        Ok(ans) => Ok(ans as isize),
        Err(errno) => Err(errno),
    }
}
*/

/// 内核只发挥存储的作用
/// 但要保证head对应的地址已经被分配
/// # Arguments
/// * head: usize
/// * len: usize
pub fn syscall_set_robust_list(args: [usize; 6]) -> SyscallResult {
    let head = args[0];
    let len = args[1];
    let process = current_process();
    if len != core::mem::size_of::<RobustList>() {
        return Err(SyscallError::EINVAL);
    }
    let curr_id = current_task().id().as_u64();
    if process.manual_alloc_for_lazy(head.into()).is_ok() {
        let mut robust_list = process.robust_list.lock();
        robust_list.insert(curr_id, FutexRobustList::new(head, len));
        Ok(0)
    } else {
        Err(SyscallError::EINVAL)
    }
}

/// 取出对应线程的robust list
/// # Arguments
/// * pid: i32
/// * head: *mut usize
/// * len: *mut usize
pub fn syscall_get_robust_list(args: [usize; 6]) -> SyscallResult {
    let pid = args[0] as i32;
    let head = args[1] as *mut usize;
    let len = args[2] as *mut usize;

    if pid == 0 {
        let process = current_process();
        let curr_id = current_task().id().as_u64();
        if process
            .manual_alloc_for_lazy((head as usize).into())
            .is_ok()
        {
            let robust_list = process.robust_list.lock();
            if robust_list.contains_key(&curr_id) {
                let list = robust_list.get(&curr_id).unwrap();
                unsafe {
                    *head = list.head;
                    *len = list.len;
                }
            } else {
                return Err(SyscallError::EPERM);
            }
            return Ok(0);
        }
        return Err(SyscallError::EPERM);
    }
    Err(SyscallError::EPERM)
}
