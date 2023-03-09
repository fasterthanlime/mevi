#![allow(unused_imports)]

use std::{
    cmp::Ordering,
    ops::Range,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{net::UnixListener, process::CommandExt},
    },
    process::{Child, Command},
    sync::{mpsc, Arc, Mutex},
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Resident {
    Yes,
    No,
}

#[allow(dead_code)]
type MemMap = RangeMap<usize, Resident>;
#[allow(dead_code)]
type UffdSlot = Arc<Mutex<Option<Uffd>>>;

const SOCK_PATH: &str = "/tmp/mevi.sock";

#[derive(Debug)]
#[allow(dead_code)]
enum TraceeEvent {
    Map {
        range: Range<usize>,
        resident: Resident,
        _guard: mpsc::Sender<()>,
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

    let (tx, rx) = mpsc::channel::<TraceeEvent>();
    let tx2 = tx.clone();

    std::thread::spawn(move || userfault_thread(tx, listener));
    std::thread::spawn(move || tracer_thread(tx2));

    loop {
        let ev = rx.recv().unwrap();
        eprintln!("{:?}", ev.blue());
    }
}

fn tracer_thread(tx: mpsc::Sender<TraceeEvent>) {
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

    let child = cmd.spawn().unwrap();
    let mut tracee = Tracee::new(tx, child).unwrap();
    tracee.run().unwrap();
}

fn userfault_thread(tx: mpsc::Sender<TraceeEvent>, listener: UnixListener) {
    let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;

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

struct Tracee {
    tx: mpsc::Sender<TraceeEvent>,
    pid: Pid,
    heap_range: Option<Range<usize>>,
}

enum SysExitOutcome {
    Map {
        range: Range<usize>,
        resident: Resident,
    },
    Other,
}

impl Tracee {
    fn new(
        tx: mpsc::Sender<TraceeEvent>,
        child: Child,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pid = Pid::from_raw(child.id() as _);
        std::mem::forget(child);

        let res = waitpid(pid, None)?;
        eprintln!("first waitpid: {res:?}");

        Ok(Self {
            tx,
            pid,
            heap_range: None,
        })
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            eprintln!("stepping until next syscall");
            ptrace::syscall(self.pid, None)?;
            self.syscall_wait()?;

            eprintln!("stepping until next syscall");
            ptrace::syscall(self.pid, None)?;
            self.syscall_wait()?;

            match self.on_sys_exit()? {
                SysExitOutcome::Other => {
                    // cool
                }
                SysExitOutcome::Map { range, resident } => {
                    let (tx, rx) = mpsc::channel();
                    let ev = TraceeEvent::Map {
                        range,
                        resident,
                        _guard: tx,
                    };
                    self.tx.send(ev).unwrap();

                    // this will fail, because it's been dropped. but it'll
                    // wait until it's dropped, which is what we want
                    _ = rx.recv();
                }
            }
        }
    }

    fn syscall_wait(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            eprintln!("waiting for sys_enter / sys_exit");
            let wait_status = waitpid(self.pid, None)?;
            eprintln!("wait_status: {:?}", wait_status.yellow());
            match wait_status {
                WaitStatus::Stopped(_, Signal::SIGTRAP) => break Ok(()),
                WaitStatus::Stopped(_, _other_sig) => {
                    eprintln!("caught other sig: {_other_sig}");
                    ptrace::syscall(self.pid, None)?;
                    continue;
                }
                WaitStatus::Exited(_, status) => {
                    eprintln!("Child exited with status {status}");
                    std::process::exit(status);
                }
                _ => continue,
            }
        }
    }

    fn on_sys_exit(&mut self) -> Result<SysExitOutcome, Box<dyn std::error::Error>> {
        let regs = ptrace::getregs(self.pid)?;
        eprintln!("{regs:?}");
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

                if fd == -1 && addr == 0 {
                    eprintln!(
                        "mmap(addr={addr:#x}, len={len:#x}, prot={prot:#x}, flags={flags:#x}, fd={fd}, off={off})"
                    );
                    return Ok(SysExitOutcome::Map {
                        range: ret..ret + len,
                        resident: Resident::No,
                    });
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
                        let old_top = heap_range.end;
                        heap_range.end = ret;

                        if heap_range.end > old_top {
                            return Ok(SysExitOutcome::Map {
                                range: old_top..heap_range.end,
                                resident: Resident::Yes,
                            });
                        }
                    }
                }
            }
            _ => {
                // let's ignore those
            }
        }

        Ok(SysExitOutcome::Other)
    }
}
