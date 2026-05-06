//! Process management syscalls
use crate::task::{
    current_user_token, mmap, munmap, get_syscall_count,
    exit_current_and_run_next, suspend_current_and_run_next, change_program_brk,
};
use crate::mm::{translated_byte_buffer, PageTable, PTEFlags, VirtAddr};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
      let token = current_user_token();
      let len = core::mem::size_of::<TimeVal>();
      let buffers = translated_byte_buffer(token, ts as *const u8, len);
      let us = get_time_us();
      let time_val = TimeVal { sec: us / 1_000_000, usec: us % 1_000_000 };
      let src = unsafe {
          core::slice::from_raw_parts(&time_val as *const TimeVal as *const u8, len)
      };
      let mut offset = 0;
      for buffer in buffers {
          let n = buffer.len();
          buffer.copy_from_slice(&src[offset..offset + n]);
          offset += n;
      }
      0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
      let token = current_user_token();
      match trace_request {
          0 => {
              let page_table = PageTable::from_token(token);
              let vpn = VirtAddr::from(id).floor();
              match page_table.translate(vpn) {
                  Some(pte) => {
                    let flags = pte.flags();
                    if !pte.is_valid() || !flags.contains(PTEFlags::U) || !flags.contains(PTEFlags::R) {
                          return -1;
                    }
                    let offset = VirtAddr::from(id).page_offset();
                    pte.ppn().get_bytes_array()[offset] as isize
                  }
                  None => -1,
              }
          }
          1 => {
              let page_table = PageTable::from_token(token);
              let vpn = VirtAddr::from(id).floor();
              match page_table.translate(vpn) {
                  Some(pte) => {
                    let flags = pte.flags();
                    if !pte.is_valid() || !flags.contains(PTEFlags::U) || !flags.contains(PTEFlags::W) {
                          return -1;
                    }
                    let offset = VirtAddr::from(id).page_offset();
                    pte.ppn().get_bytes_array()[offset] = (data & 0xFF) as u8;
                      0
                  }
                  None => -1,
              }
          }
          2 => get_syscall_count(id) as isize,
          _ => -1,
      }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
      mmap(start, len, port)
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
      munmap(start, len)
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
