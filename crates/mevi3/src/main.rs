use std::{
    cmp::Ordering,
    ops::Range,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{net::UnixListener, process::CommandExt},
    },
    process::{Child, Command},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use humansize::{make_format, BINARY};
use libc::user_regs_struct;
use nix::{
    sys::{
        ptrace::{self},
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::{sysconf, Pid, SysconfVar},
};
use owo_colors::OwoColorize;
use passfd::FdPassingExt;
use rangemap::RangeMap;
use userfaultfd::Uffd;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Paged {
    In,
    Out,
}
type MemMap = RangeMap<usize, Paged>;
type UffdSlot = Arc<Mutex<Option<Uffd>>>;

const SOCK_PATH: &str = "/tmp/mevi.sock";

struct SysExitGuard {
    pid: Pid,
}

impl Drop for SysExitGuard {
    fn drop(&mut self) {
        ptrace::syscall(self.pid, None).unwrap();
    }
}

enum TraceeEvent {
    Map {
        range: Range<usize>,
        paged: Paged,
        _guard: SysExitGuard,
    },
    Connected {
        uffd: &'static Uffd,
    },
    PageIn {
        range: Range<usize>,
    },
    PageOut {
        range: Range<usize>,
    },
    Unmap {
        range: Range<usize>,
    },
    Remap {
        old_range: Range<usize>,
        new_range: Range<usize>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::remove_file(SOCK_PATH).ok();
    let listener = UnixListener::bind(SOCK_PATH).unwrap();
    let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;

    let (tx, rx) = std::sync::mpsc::channel::<TraceeEvent>();

    std::thread::spawn({
        let tx = tx.clone();
        move || {
            let (stream, _) = listener.accept().unwrap();
            let uffd = unsafe { Uffd::from_raw_fd(stream.recv_fd().unwrap()) };
            let uffd: &'static Uffd = Box::leak(Box::new(uffd));
            tx.send(TraceeEvent::Connected { uffd }).unwrap();

            loop {
                let event = uffd.read_event().unwrap().unwrap();
                match event {
                    userfaultfd::Event::Pagefault { addr, .. } => {
                        unsafe {
                            uffd.zeropage(addr, page_size, true).unwrap();
                        }
                        let addr = addr as usize;
                        tx.send(TraceeEvent::PageIn {
                            range: addr..addr + page_size,
                        })
                        .unwrap();
                    }
                    userfaultfd::Event::Remap { from, to, len } => {
                        let from = from as usize;
                        let to = to as usize;
                        tx.send(TraceeEvent::Remap {
                            old_range: from..from + len,
                            new_range: to..to + len,
                        })
                        .unwrap();
                    }
                    userfaultfd::Event::Remove { start, end } => {
                        let start = start as usize;
                        let end = end as usize;
                        tx.send(TraceeEvent::PageOut { range: start..end }).unwrap();
                    }
                    userfaultfd::Event::Unmap { start, end } => {
                        let start = start as usize;
                        let end = end as usize;
                        tx.send(TraceeEvent::Unmap { range: start..end }).unwrap();
                    }
                    _ => {
                        eprintln!("Unexpected event: {:?}", event);
                    }
                }
            }
        }
    });

    let mut args = std::env::args();
    // skip our own name
    args.next().unwrap();

    let mut cmd = Command::new(args.next().unwrap());
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env("LD_PRELOAD", "target/release/libmevi_payload.so");
    unsafe {
        cmd.pre_exec(|| {
            ptrace::traceme()?;
            Ok(())
        });
    }

    std::thread::spawn(move || {
        let child = cmd.spawn().unwrap();
        eprintln!("Child's PID is {}", child.id().green());

        // wait for initial attach
        let pid = Pid::from_raw(child.id() as _);
        waitpid(pid, None).unwrap();

        // then loop waiting for syscalls
        let wait_for_sys_boundary = || {
            loop {
                let wait_status = waitpid(pid, None)?;
                // eprintln!("wait_status: {:?}", wait_status.yellow());
                match wait_status {
                    WaitStatus::Stopped(_, Signal::SIGTRAP) => break Ok(()),
                    WaitStatus::Stopped(_, _) => {
                        // stopped by another signal? resume until syscall
                        ptrace::syscall(pid, None)?;
                    }
                    WaitStatus::Exited(_, status) => {
                        eprintln!("Child exited with status {status}");
                        std::process::exit(status);
                    }
                    _ => continue,
                }
            }
        };

        loop {
            wait_for_sys_boundary().unwrap();
            wait_for_sys_boundary().unwrap();
            tx.send(TraceeEvent::SyscallExit {
                regs: ptrace::getregs(pid).unwrap(),
            })
            .unwrap();
        }
    });

    Ok(())
}

struct Tracee {
    pid: Pid,
    mem_map: MemMap,
    heap_range: Option<Range<usize>>,
    uffd_slot: Arc<Mutex<Option<Uffd>>>,
}

impl Tracee {
    fn new(child: Child, uffd_slot: UffdSlot) -> Result<Self, Box<dyn std::error::Error>> {
        let pid = Pid::from_raw(child.id() as _);
        waitpid(pid, None)?;

        Ok(Self {
            pid,
            mem_map: Default::default(),
            heap_range: None,
            uffd_slot,
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

            let wait_status = waitpid(self.pid, None)?;
            // eprintln!("wait_status: {:?}", wait_status.yellow());
            match wait_status {
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
            libc::SYS_mmap => {
                let fd = regs.r8 as i32;
                let flags = regs.r10;
                let addr = regs.rdi;
                let len = regs.rsi as usize;
                let prot = regs.rdx;
                let off = regs.r9;

                if fd != -1 {
                    // don't care about file mappings
                    return Ok(());
                }
                if addr != 0 {
                    // don't care about fixed mappings
                    return Ok(());
                }
                eprintln!(
                    "mmap(addr={addr:#x}, len={len:#x}, prot={prot:#x}, flags={flags:#x}, fd={fd}, off={off})"
                );

                self.mem_map.mutate("mmap", ret, |mem| {
                    mem.insert(ret..ret + len, Paged::Out);
                });
                {
                    let uffd_slot = self.uffd_slot.lock().unwrap();
                    if let Some(uffd) = uffd_slot.as_ref() {
                        uffd.register(ret as _, len).unwrap();
                    }
                }
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
                            mem.insert(heap_range.end..ret, Paged::In);
                        });
                        {
                            let uffd_slot = self.uffd_slot.lock().unwrap();
                            if let Some(uffd) = uffd_slot.as_ref() {
                                uffd.register(heap_range.end as _, ret - heap_range.end)
                                    .unwrap();
                            }
                        }
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
        f(self)

        // let total_before = self.total();
        // f(self);
        // let total_after = self.total();

        // let formatter = make_format(BINARY);

        // let print_usage = match total_after.cmp(&total_before) {
        //     Ordering::Less => {
        //         eprintln!(
        //             "{:#x} {} removed ({})",
        //             addr.blue(),
        //             formatter(total_before - total_after).red(),
        //             syscall,
        //         );
        //         true
        //     }
        //     Ordering::Equal => false,
        //     Ordering::Greater => {
        //         eprintln!(
        //             "{:#x} {} added ({})",
        //             addr.blue(),
        //             formatter(total_after - total_before).green(),
        //             syscall,
        //         );
        //         true
        //     }
        // };
        // if print_usage {
        //     eprintln!("Total usage: {}", formatter(self.total()).yellow());
        // }
    }
}
