use std::{ops::Range, os::unix::process::CommandExt, process::Command, sync::mpsc};

use libc::user_regs_struct;
use nix::{
    sys::{
        ptrace::{self},
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use owo_colors::OwoColorize;
use tracing::{info, trace, warn};

use crate::{IsResident, TraceeEvent};

pub(crate) fn run(tx: mpsc::SyncSender<TraceeEvent>) {
    Tracee::new(tx).unwrap().run().unwrap();
}

struct Tracee {
    tx: mpsc::SyncSender<TraceeEvent>,
    heap_range: Option<Range<usize>>,
}

struct Mapped {
    range: Range<usize>,
    resident: IsResident,
}

impl Tracee {
    fn new(tx: mpsc::SyncSender<TraceeEvent>) -> Result<Self, Box<dyn std::error::Error>> {
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
            ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACESYSGOOD,
        )
        .unwrap();

        ptrace::syscall(pid, None)?;

        Ok(Self {
            tx,
            heap_range: None,
        })
    }

    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let (pid, _regs) = self.syscall_step()?;
            ptrace::syscall(pid, None)?;

            let (pid, regs) = self.syscall_step()?;
            if let Some(Mapped { range, resident }) = self.on_sys_exit(pid, regs)? {
                let (tx, rx) = mpsc::channel();
                self.tx
                    .send(TraceeEvent::Map {
                        range,
                        resident,
                        _tx: Some(tx),
                    })
                    .unwrap();

                // this will fail, because it's been dropped. but it'll
                // wait until it's dropped, which is what we want
                _ = rx.recv();
            }
            ptrace::syscall(pid, None)?;
        }
    }

    fn syscall_step(&mut self) -> Result<(Pid, user_regs_struct), Box<dyn std::error::Error>> {
        loop {
            let wait_status = waitpid(None, None)?;
            trace!("wait_status: {:?}", wait_status.yellow());
            match wait_status {
                WaitStatus::Stopped(pid, sig) => {
                    warn!("caught other sig: {sig}");
                    ptrace::syscall(pid, sig)?;
                    continue;
                }
                WaitStatus::Exited(_, status) => {
                    info!("Child exited with status {status}");
                    std::process::exit(status);
                }
                WaitStatus::PtraceEvent(pid, signal, x) => {
                    let msg = ptrace::getevent(pid)?;
                    trace!(%pid, %signal, %x, %msg, "ptrace event");
                    ptrace::syscall(pid, signal)?;
                    continue;
                }
                WaitStatus::PtraceSyscall(pid) => {
                    let regs = ptrace::getregs(pid)?;
                    break Ok((pid, regs));
                }
                other => {
                    panic!("Unexpected wait status: {other:?}");
                }
            }
        }
    }

    fn on_sys_exit(
        &mut self,
        pid: Pid,
        regs: user_regs_struct,
    ) -> Result<Option<Mapped>, Box<dyn std::error::Error>> {
        trace!("[{pid}] on sys_exit: {regs:?}");
        let ret = regs.rax as usize;

        match regs.orig_rax as i64 {
            libc::SYS_mmap => {
                let fd = regs.r8 as i32;
                let addr_in = regs.rdi;
                let len = regs.rsi as usize;

                if fd == -1 && addr_in == 0 {
                    return Ok(Some(Mapped {
                        range: ret..ret + len,
                        resident: IsResident::No,
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
                            resident: IsResident::Yes,
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
