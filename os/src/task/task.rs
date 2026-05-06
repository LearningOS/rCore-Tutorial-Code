//! Types related to task management
use super::TaskContext;
use crate::config::TRAP_CONTEXT_BASE;
use crate::config::MAX_SYSCALL_NUM;
use crate::mm::{
    kernel_stack_position, MapPermission, MemorySet, PhysPageNum, VirtAddr, KERNEL_SPACE,
};
use crate::mm::address::StepByOne;
use crate::trap::{trap_handler, TrapContext};
use crate::config::PAGE_SIZE;

/// The task control block (TCB) of a task.
pub struct TaskControlBlock {
    /// Save task context
    pub task_cx: TaskContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,

    /// Application address space
    pub memory_set: MemorySet,

    /// The phys page number of trap context
    pub trap_cx_ppn: PhysPageNum,

    /// The size(top addr) of program which is loaded from elf file
    pub base_size: usize,

    /// Heap bottom
    pub heap_bottom: usize,

    /// Program break
    pub program_brk: usize,

    pub syscall_count: [usize; MAX_SYSCALL_NUM],
}

impl TaskControlBlock {
    /// get the trap context
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }
    /// get the user token
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    /// Based on the elf info in program, build the contents of task in a new address space
    pub fn new(elf_data: &[u8], app_id: usize) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();
        let task_status = TaskStatus::Ready;
        // map a kernel-stack in kernel space
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(app_id);
        KERNEL_SPACE.exclusive_access().insert_framed_area(
            kernel_stack_bottom.into(),
            kernel_stack_top.into(),
            MapPermission::R | MapPermission::W,
        );
        let task_control_block = Self {
            task_status,
            task_cx: TaskContext::goto_trap_return(kernel_stack_top),
            memory_set,
            trap_cx_ppn,
            base_size: user_sp,
            heap_bottom: user_sp,
            program_brk: user_sp,
            syscall_count: [0; MAX_SYSCALL_NUM],
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }
    /// change the location of the program break. return None if failed.
    pub fn change_program_brk(&mut self, size: i32) -> Option<usize> {
        let old_break = self.program_brk;
        let new_brk = self.program_brk as isize + size as isize;
        if new_brk < self.heap_bottom as isize {
            return None;
        }
        let result = if size < 0 {
            self.memory_set
                .shrink_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        } else {
            self.memory_set
                .append_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        };
        if result {
            self.program_brk = new_brk as usize;
            Some(old_break)
        } else {
            None
        }
    }
    pub fn increment_syscall_count(&mut self, num: usize) {
        if num < MAX_SYSCALL_NUM {
            self.syscall_count[num] += 1;
        }
    }

    pub fn get_syscall_count(&self, num: usize) -> usize {
        if num < MAX_SYSCALL_NUM {
            self.syscall_count[num]
        } else {
            0
        }
    }
    pub fn mmap(&mut self, start: usize, len: usize, prot: usize) -> isize {
      if start % PAGE_SIZE != 0 { return -1; }
      if prot & !0x7 != 0 { return -1; }
      if prot & 0x7 == 0 { return -1; }
      let mut perm = MapPermission::U;
      if prot & 0x1 != 0 { perm |= MapPermission::R; }
      if prot & 0x2 != 0 { perm |= MapPermission::W; }
      if prot & 0x4 != 0 { perm |= MapPermission::X; }
      let len = if len == 0 { 0 } else { (len - 1) / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE };
      if len == 0 { return 0; }
      let start_vpn = VirtAddr::from(start).floor();
      let end_vpn = VirtAddr::from(start + len).ceil();
      let mut cur = start_vpn;
      while cur < end_vpn {
          if let Some(pte) = self.memory_set.translate(cur) {
              if pte.is_valid() { return -1; }
          }
          cur.step();
      }
      self.memory_set.insert_framed_area(start.into(), (start + len).into(), perm);
      0
    }

    pub fn munmap(&mut self, start: usize, len: usize) -> isize {
        if start % PAGE_SIZE != 0 { return -1; }
        let len = if len == 0 { 0 } else { (len - 1) / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE };
        if len == 0 { return 0; }
        let start_vpn = VirtAddr::from(start).floor();
        let end_vpn = VirtAddr::from(start + len).ceil();
        // 检查全部已映射
        let mut cur = start_vpn;
        while cur < end_vpn {
            match self.memory_set.translate(cur) {
                Some(pte) if pte.is_valid() => {}
                _ => { return -1; }
            }
            cur.step();
        }
        self.memory_set.unmap_framed_area(start.into(), (start + len).into());
        let mut cur = start_vpn;
        while cur < end_vpn {
            self.memory_set.page_table.unmap(cur);
            for area in &mut self.memory_set.areas {
                if area.vpn_range.get_start() <= cur && cur < area.vpn_range.get_end() {
                    area.unmap_one(&mut self.memory_set.page_table, cur);
                    break;
                }
            }
            cur.step();
        }
        0
    }
}

#[derive(Copy, Clone, PartialEq)]
/// task status: UnInit, Ready, Running, Exited
pub enum TaskStatus {
    /// uninitialized
    UnInit,
    /// ready to run
    Ready,
    /// running
    Running,
    /// exited
    Exited,
}
