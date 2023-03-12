use std::{
    borrow::Cow, collections::HashMap, ops::Range, os::unix::process::CommandExt, process::Command,
    sync::mpsc,
};

use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use owo_colors::OwoColorize;
use tracing::{debug, info, trace};

use crate::{MapGuard, MemState, MeviEvent, TraceeId, TraceePayload};

pub(crate) fn run(tx: mpsc::SyncSender<MeviEvent>) {
    Tracer::new(tx).unwrap().run().unwrap();
}

struct Tracer {
    tx: mpsc::SyncSender<MeviEvent>,
    tracees: HashMap<TraceeId, Tracee>,
}

struct Mapped {
    range: Range<usize>,
    resident: MemState,
}

impl Tracer {
    fn new(tx: mpsc::SyncSender<MeviEvent>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut args = std::env::args();
        // skip our own name
        args.next().unwrap();

        let mut cmd = Command::new(args.next().unwrap());
        for arg in args {
            cmd.arg(arg);
        }
        cmd.env("LD_PRELOAD", "target/release/libmevi_preload.so");
        unsafe {
            cmd.pre_exec(|| {
                ptrace::traceme()?;
                Ok(())
            });
        }

        let child = cmd.spawn().unwrap();

        let pid = Pid::from_raw(child.id() as _);
        std::mem::forget(child);

        let res = waitpid(pid, None)?;
        trace!("first waitpid: {res:?}");

        ptrace::setoptions(
            pid,
            ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK,
        )?;
        ptrace::syscall(pid, None)?;

        Ok(Self {
            tx,
            tracees: Default::default(),
        })
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let wait_status = match waitpid(None, None) {
                Ok(s) => s,
                Err(e) => {
                    if e == nix::errno::Errno::ECHILD {
                        info!("no more children, exiting");
                        std::process::exit(0);
                    } else {
                        panic!("waitpid failed: {}", e);
                    }
                }
            };

            trace!("wait_status: {:?}", wait_status.yellow());
            match wait_status {
                WaitStatus::Stopped(pid, sig) => {
                    debug!("{pid} caught sig {sig}");
                    if sig == Signal::SIGTRAP {
                        // probably ptrace stuff?
                        ptrace::syscall(pid, None)?;
                    } else {
                        // probably not ptrace stuff, forward the signal?
                        ptrace::syscall(pid, sig)?;
                    }
                    continue;
                }
                WaitStatus::Exited(pid, status) => {
                    info!("{pid} exited with status {status}");
                    let ev = MeviEvent::TraceeEvent(pid.into(), TraceePayload::Exit);
                    self.tx.send(ev).unwrap();
                }
                WaitStatus::PtraceSyscall(pid) => {
                    debug!("{pid} in sys_enter / sys_exit");
                    let tid: TraceeId = pid.into();
                    let tracee = self.tracees.entry(tid).or_insert_with(|| Tracee {
                        was_in_syscall: false,
                        tid,
                        heap_range: None,
                    });
                    if tracee.was_in_syscall {
                        tracee.was_in_syscall = false;
                        if let Some(Mapped { range, resident }) = tracee.on_sys_exit()? {
                            let (tx, rx) = mpsc::channel();
                            let ev = MeviEvent::TraceeEvent(
                                tid,
                                TraceePayload::Map {
                                    range,
                                    state: resident,
                                    _guard: MapGuard { _inner: Some(tx) },
                                },
                            );
                            self.tx.send(ev).unwrap();

                            // this will fail, because it's been dropped. but it'll
                            // wait until it's dropped, which is what we want
                            _ = rx.recv();
                        }
                        ptrace::syscall(pid, None)?;
                    } else {
                        tracee.was_in_syscall = true;
                        ptrace::syscall(pid, None)?;
                    }
                }
                WaitStatus::PtraceEvent(pid, sig, event) => {
                    let event_name: Cow<'static, str> = match event {
                        libc::PTRACE_EVENT_CLONE => "clone".into(),
                        libc::PTRACE_EVENT_FORK => "fork".into(),
                        libc::PTRACE_EVENT_VFORK => "vfork".into(),
                        other => format!("unknown event {}", other).into(),
                    };
                    debug!("{pid} got event {event_name} with sig {sig}");
                    ptrace::syscall(pid, None)?;
                }
                WaitStatus::Signaled(pid, signal, core_dump) => {
                    info!("{pid} was terminated with signal {signal} with, WCOREDUMP({core_dump})");
                }
                other => {
                    panic!("unexpected wait status: {:?}", other);
                }
            }
        }
    }
}

struct Tracee {
    was_in_syscall: bool,
    tid: TraceeId,
    heap_range: Option<Range<usize>>,
}

impl Tracee {
    fn on_sys_exit(&mut self) -> Result<Option<Mapped>, Box<dyn std::error::Error>> {
        let regs = ptrace::getregs(self.tid.into())?;
        trace!("on sys_exit: {regs:?}");
        let ret = regs.rax as usize;

        match regs.orig_rax as i64 {
            libc::SYS_mmap => {
                let fd = regs.r8 as i32;
                let addr_in = regs.rdi;
                let len = regs.rsi as usize;

                if fd == -1 && addr_in == 0 {
                    return Ok(Some(Mapped {
                        range: ret..ret + len,
                        resident: MemState::NotResident,
                    }));
                }
            }
            libc::SYS_brk => {
                if regs.rdi == 0 {
                    // just a query: remember the top of the heap
                    if self.heap_range.is_none() {
                        self.heap_range = Some(ret..ret);
                    }
                } else if let Some(heap_range) = self.heap_range.as_mut() {
                    // either growing or shrinking the heap,
                    // and we know the previous top
                    let old_top = heap_range.end;
                    heap_range.end = ret;

                    if heap_range.end > old_top {
                        // heap just grew - shrinking will be handled by
                        // userfaultfd
                        return Ok(Some(Mapped {
                            range: old_top..heap_range.end,
                            resident: MemState::Resident,
                        }));
                    }
                }
            }
            _ => {
                // let's ignore those
            }
        }

        Ok(None)
    }
}
