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
enum PageStatus {
    In,
    Out,
}
type MemMap = RangeMap<usize, PageStatus>;
type UffdSlot = Arc<Mutex<Option<Uffd>>>;

const SOCK_PATH: &str = "/tmp/mevi.sock";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::remove_file(SOCK_PATH).ok();
    let listener = UnixListener::bind(SOCK_PATH).unwrap();
    let uffd_slot: UffdSlot = Default::default();

    std::thread::spawn({
        let uffd_slot = uffd_slot.clone();
        move || {
            eprintln!("Accepting UDS connection from child");
            let (stream, _) = listener.accept().unwrap();
            eprintln!("Receiving uffd from child...");
            let uffd = unsafe { Uffd::from_raw_fd(stream.recv_fd().unwrap()) };

            eprintln!("Received uffd from child!");
            let uffd_clone = unsafe { Uffd::from_raw_fd(uffd.as_raw_fd()) };
            uffd_slot.lock().unwrap().replace(uffd_clone);

            let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;
            let mut counter: usize = 0;
            let mut last_print = Instant::now();
            let interval = Duration::from_millis(500);
            let formatter = make_format(BINARY);

            loop {
                let event = uffd.read_event().unwrap().unwrap();
                match event {
                    userfaultfd::Event::Pagefault { addr, .. } => unsafe {
                        let n = uffd.zeropage(addr, page_size, true).unwrap();
                        counter += n;
                        let elapsed = last_print.elapsed();
                        if elapsed > interval {
                            eprintln!(
                                "Paged in {} in the last {elapsed:?}",
                                formatter(counter as u64).green()
                            );
                            last_print = Instant::now();
                            counter = 0;
                        }

                        // eprintln!(
                        //     "{:#x} zeroed {n:#x} bytes ({page_size:#x} pages)",
                        //     (addr as usize).blue()
                        // );
                    },
                    ev => {
                        eprintln!("Unexpected event: {:?}", ev);
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

    let child = cmd.spawn()?;
    eprintln!("Child's PID is {}", child.id().green());
    let mut tracee = Tracee::new(child, uffd_slot)?;
    tracee.run()
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
                    mem.insert(ret..ret + len, PageStatus::Out);
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
                            mem.insert(heap_range.end..ret, PageStatus::In);
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
