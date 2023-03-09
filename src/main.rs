use std::{
    cmp::Ordering,
    ops::Range,
    os::unix::process::CommandExt,
    process::{Child, Command},
};

use humansize::{make_format, BINARY};
use nix::{
    sys::{
        ptrace::{self},
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use owo_colors::OwoColorize;
use rangemap::RangeMap;

type MemMap = RangeMap<usize, ()>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new("../mem-hog/target/release/mem-hog");
    unsafe {
        cmd.pre_exec(|| {
            ptrace::traceme()?;
            Ok(())
        });
    }

    let child = cmd.spawn()?;
    let mut tracee = Tracee::new(child)?;
    tracee.run()
}

struct Tracee {
    pid: Pid,
    mem_map: MemMap,
    heap_range: Option<Range<usize>>,
}

impl Tracee {
    fn new(child: Child) -> Result<Self, Box<dyn std::error::Error>> {
        let pid = Pid::from_raw(child.id() as _);
        waitpid(pid, None)?;

        Ok(Self {
            pid,
            mem_map: Default::default(),
            heap_range: None,
        })
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            self.syscall_step()?;
            self.syscall_step()?;
            self.on_sys_exit()?;
        }
    }

    fn syscall_step(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            ptrace::syscall(self.pid, None)?;

            match waitpid(self.pid, None)? {
                WaitStatus::Stopped(_, Signal::SIGTRAP) => break Ok(()),
                WaitStatus::Exited(_, status) => {
                    eprintln!("Child exited with status {status}");
                    std::process::exit(status);
                }
                _ => continue,
            }
        }
    }

    fn on_sys_exit(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let regs = ptrace::getregs(self.pid)?;
        let syscall = regs.orig_rax as i64;
        let ret = regs.rax as usize;

        match syscall {
            libc::SYS_mmap if regs.r8 == (-1_i32 as u32) as _ => {
                let len = regs.rsi as usize;
                self.mem_map.mutate("mmap", ret, |mem| {
                    mem.insert(ret..ret + len, ());
                })
            }
            libc::SYS_munmap => {
                let addr = regs.rdi as usize;
                let len = regs.rsi as usize;
                self.mem_map.mutate("munmap", addr, |mem| {
                    mem.remove(addr..(addr + len));
                });
            }
            libc::SYS_brk => {
                // just a query? initialize the range if needed
                if regs.rdi == 0 {
                    if self.heap_range.is_none() {
                        self.heap_range = Some(ret..ret);
                    }
                } else {
                    // updating the range?
                    let Some(heap_range) = self.heap_range.as_mut() else { return Ok(()) };

                    if ret > heap_range.end {
                        self.mem_map.mutate("brk", heap_range.end, |mem| {
                            mem.insert(heap_range.end..ret, ());
                        });
                    }
                    if ret < heap_range.end {
                        self.mem_map.mutate("brk", ret, |mem| {
                            mem.remove(ret..heap_range.end);
                        });
                    }

                    heap_range.end = ret;
                }
            }
            _other => {
                // let's ignore that for now
            }
        }

        Ok(())
    }
}

trait Total {
    fn total(&self) -> usize;
    fn mutate(&mut self, syscall: &str, addr: usize, f: impl FnOnce(&mut Self));
}

impl<V: Eq + Clone> Total for RangeMap<usize, V> {
    fn total(&self) -> usize {
        self.iter().map(|(range, _)| range.end - range.start).sum()
    }

    fn mutate(&mut self, syscall: &str, addr: usize, f: impl FnOnce(&mut Self)) {
        let total_before = self.total();
        f(self);
        let total_after = self.total();

        let formatter = make_format(BINARY);

        let print_usage = match total_after.cmp(&total_before) {
            Ordering::Less => {
                eprintln!(
                    "{:#x} {} removed ({})",
                    addr.blue(),
                    formatter(total_before - total_after).red(),
                    syscall,
                );
                true
            }
            Ordering::Equal => false,
            Ordering::Greater => {
                eprintln!(
                    "{:#x} {} added ({})",
                    addr.blue(),
                    formatter(total_after - total_before).green(),
                    syscall,
                );
                true
            }
        };
        if print_usage {
            eprintln!("Total usage: {}", formatter(self.total()).yellow());
        }
    }
}
