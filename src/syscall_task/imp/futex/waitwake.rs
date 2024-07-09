
use alloc::collections::VecDeque;
use axhal::mem::VirtAddr;
use axlog::info;
use core::time::Duration;
use axprocess::{current_task, futex::{FutexQ, FUTEX_WAIT_TASK, WAIT_FOR_FUTEX}, signal::current_have_signals, yield_now_task};
//use axtask::schedule;

use crate::{syscall_task::imp::futex::core::{futex_get_value_locked, get_futex_key}, SyscallError, SyscallResult};



/// val3 is bitset
pub fn futex_wait(vaddr: VirtAddr, flags: i32, expected_val: u32, deadline: Option<Duration>, bitset: u32) -> SyscallResult {
    info!("[futex_wait] vaddr: {:?}, flags: {:?}, val: {:?}, deadline: {:?}", vaddr, flags, expected_val, deadline);
    let mut is_tiemout = false;
    // we may be victim of spurious wakeups, so we need to loop
    loop {
        let key = get_futex_key(vaddr, flags);
        let real_futex_val = futex_get_value_locked(vaddr)?;
        if expected_val != real_futex_val as u32 {
            return Err(SyscallError::EAGAIN);
        }
        let cur_futexq = FutexQ::new(key, current_task().as_task_ref().clone(), bitset); 
        // 比较后相等，放入等待队列
        let mut futex_wait_task = FUTEX_WAIT_TASK.lock();
        let wait_list = futex_wait_task.get_mut(&key);

        // if the futex is not in the queue, add it to the queue
        // if the futex is in the queue, add the task to the tail of queue
        if let Some(wait_list) = wait_list {
            wait_list.push_back(cur_futexq);
        }
        else {
            // init the futex wait list
            let mut new_wait_list = VecDeque::new();
            new_wait_list.push_back(cur_futexq);
            futex_wait_task.insert(key, new_wait_list);
        }

        // drop lock to avoid deadlock
        drop(futex_wait_task);

        if let Some(deadline) = deadline {
            is_tiemout = WAIT_FOR_FUTEX.wait_timeout(deadline);
        }
        else {
            // If timeout is NULL, the operation can block indefinitely.
            yield_now_task();
        }

        // If we were woken (and unqueued), we succeeded, whatever. 
        // We doesn't care about the reason of wakeup if we were unqueued.
        let mut futex_wait_task = FUTEX_WAIT_TASK.lock();
        let wait_list = futex_wait_task.get_mut(&key); 
        if let Some(wait_list) = wait_list {
            let current_task = current_task().as_task_ref().clone();
            let cur_futexq_id = current_task.id();
            if let Some(idx) = wait_list.iter().position(|futex_q| futex_q.task.id() == cur_futexq_id){
                // the task is still in the wait list 
                let futex_q = wait_list.remove(idx).unwrap();
                info!("the task {:?} is still in the wait list, and remove it", futex_q.task.id());
                // if the queue is empty, remove the futex queue
                if wait_list.is_empty() {
                    futex_wait_task.remove(&key);
                }
                // if timeout is not null, check the timeout
                if is_tiemout {
                    return Err(SyscallError::ETIMEDOUT);
                }
                if current_have_signals() {
                    return Err(SyscallError::EINTR);
                }
            }
            else {
                // the task is woken up anyway
                return Ok(0);
            }
        }
        else {
            // the futex queue is removed
            return Ok(0);
        }
    }
}


// no need to check the bitset, faster than futex_wake_bitset
pub fn futex_wake(vaddr: VirtAddr, flags: i32, nr_waken: u32) -> SyscallResult {
    info!("[linux_syscall_api::syscall_task::futex_wake] vaddr: {:?}, flags: {:?}, nr_waken: {:?}", vaddr, flags, nr_waken);
    let mut ret = 0;
    let key = get_futex_key(vaddr, flags);
    let mut futex_wait_task = FUTEX_WAIT_TASK.lock();
    if futex_wait_task.contains_key(&key) {
        let wait_list = futex_wait_task.get_mut(&key).unwrap();
        while let Some(futex_q) = wait_list.pop_front() {
            // wakeup corresponding task both in the `FUTEX_WAIT_TASK` and `WAlT_FOR_FUTEX`
            info!("wake up the task {:?} in the futex queue", futex_q.task.id());
            WAIT_FOR_FUTEX.notify_task(&futex_q.task);
            ret += 1;
            if ret == nr_waken {
                break;
            }
        }
    }
    info!("wake up {} tasks", ret);
    drop(futex_wait_task);
    yield_now_task();
    Ok(ret as isize)
}

pub fn futex_wake_bitset(vaddr: VirtAddr, flags: i32, nr_waken: u32, bitset: u32) -> SyscallResult {
    if bitset == 0 {
        return Err(SyscallError::EINVAL);
    }
    let mut ret = 0;
    let key = get_futex_key(vaddr, flags);
    let mut futex_wait_task = FUTEX_WAIT_TASK.lock();
    if futex_wait_task.contains_key(&key) {
        let wait_list = futex_wait_task.get_mut(&key).unwrap();
        while let Some(futex_q) = wait_list.pop_front() {
            if (futex_q.bitset & bitset) != 0 {
                // wakeup corresponding task both in the `FUTEX_WAIT_TASK` and `WAlT_FOR_FUTEX`
                WAIT_FOR_FUTEX.notify_task(&futex_q.task);
                ret += 1;
                if ret == nr_waken {
                    break;
                }
            }
        }
    }
    Ok(ret as isize)
}


pub fn futex_requeue(uaddr: VirtAddr, flags: i32, nr_waken: u32, uaddr2: VirtAddr, nr_requeue: u32) -> SyscallResult {
    let mut ret = 0;
    let mut requeued = 0;
    let key = get_futex_key(uaddr, flags);
    let req_key = get_futex_key(uaddr2, flags);
    let mut futex_wait_task = FUTEX_WAIT_TASK.lock();
    if futex_wait_task.contains_key(&key) {
        let wait_list = futex_wait_task.get_mut(&key).unwrap();
        // wake up at most `nr_waken` tasks
        while let Some(futex_q) = wait_list.pop_front() {
            WAIT_FOR_FUTEX.notify_task(&futex_q.task);
            ret += 1;
            if ret == nr_waken {
                break;
            }
        }
        if wait_list.is_empty() {
            futex_wait_task.remove(&key);
            return Ok(ret as isize);
        }
        // requeue the rest of the waiters
        // let req_list = futex_wait_task.entry(req_key).or_default(); 
        let mut req_list = VecDeque::new();
        while let Some(futex_q) = wait_list.pop_front() {
            req_list.push_back(futex_q);
            requeued += 1;
            if requeued == nr_requeue {
                break;
            }
        }
        if requeued != 0 {
            // if the req_key is not in the futex_wait_task, insert it, or append the req_list to the prev req_key
            futex_wait_task.entry(req_key).or_default().append(&mut req_list);
        }
    }
    Ok(ret as isize)
}