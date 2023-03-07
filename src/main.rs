use std::{
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
    anon_ranges: RangeMap<usize, ()>,
    heap_range: Option<Range<usize>>,
}

impl Tracee {
    fn new(child: Child) -> Result<Self, Box<dyn std::error::Error>> {
        let pid = Pid::from_raw(child.id() as _);
        waitpid(pid, None)?;

        Ok(Self {
            pid,
            anon_ranges: Default::default(),
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
        let formatter = make_format(BINARY);

        let regs = ptrace::getregs(self.pid)?;
        let syscall = regs.orig_rax as i64;
        let ret = regs.rax as usize;

        match syscall {
            libc::SYS_mmap if regs.r8 == (-1_i32 as u32) as _ => {
                let len = regs.rsi as usize;
                eprintln!("{:#x} {} added (mmap)", ret.blue(), formatter(len).green(),);
                self.anon_ranges.insert(ret..ret + len, ());
            }
            libc::SYS_munmap => {
                let addr = regs.rdi as usize;
                let len = regs.rsi as usize;

                let total_a = self.anon_ranges.total();
                self.anon_ranges.remove(addr..(addr + len));
                let total_b = self.anon_ranges.total();

                if let Some(diff) = total_a.checked_sub(total_b) {
                    eprintln!(
                        "{:#x} {} removed (munmap)",
                        addr.blue(),
                        formatter(diff).red(),
                    );
                }
            }
            libc::SYS_brk => {
                // just a query? initialize the range if needed
                if regs.rdi == 0 {
                    if self.heap_range.is_none() {
                        self.heap_range = Some(ret..ret);
                    }
                } else {
                    // updating the range?
                    if let Some(heap_range) = self.heap_range.as_mut() {
                        #[allow(clippy::comparison_chain)]
                        if ret > heap_range.end {
                            self.anon_ranges.insert(heap_range.end..ret, ());
                            let diff = ret - heap_range.end;
                            heap_range.end = ret;
                            eprintln!(
                                "{:#x} {} added (brk)",
                                heap_range.end.blue(),
                                formatter(diff).green(),
                            );
                        } else if ret < heap_range.end {
                            self.anon_ranges.remove(ret..heap_range.end);
                            let diff = heap_range.end - ret;
                            heap_range.end = ret;
                            eprintln!("{:#x} {} removed (brk)", ret.blue(), formatter(diff).red(),);
                        }
                    }
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
}

impl<V: Eq + Clone> Total for RangeMap<usize, V> {
    fn total(&self) -> usize {
        self.iter().map(|(range, _)| range.end - range.start).sum()
    }
}
