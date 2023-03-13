use std::{
    borrow::Cow,
    collections::HashMap,
    ops::Range,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::Command,
    sync::mpsc,
};

use color_eyre::Result;
use libc::{sockaddr_un, user_regs_struct};
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use owo_colors::OwoColorize;
use tracing::{debug, info, trace, warn};
use userfaultfd::{raw, FeatureFlags, IoctlFlags};

use crate::{
    ConnectSource, MapGuard, MemState, MeviEvent, PendingUffdsHandle, TraceeId, TraceePayload,
};

pub(crate) fn run(puh: PendingUffdsHandle, tx: mpsc::SyncSender<MeviEvent>) {
    Tracer::new(puh, tx).unwrap().run().unwrap();
}

struct Tracer {
    puh: PendingUffdsHandle,
    tx: mpsc::SyncSender<MeviEvent>,
    tracees: HashMap<TraceeId, Tracee>,
    next_parent: Option<TraceeId>,
}

struct Mapped {
    range: Range<usize>,
    resident: MemState,
}

impl Tracer {
    fn new(puh: PendingUffdsHandle, tx: mpsc::SyncSender<MeviEvent>) -> Result<Self> {
        let mut args = std::env::args();
        // skip our own name
        args.next().unwrap();

        let mut cmd = Command::new(args.next().unwrap());
        for arg in args {
            cmd.arg(arg);
        }

        // let exe_path = std::fs::canonicalize(std::env::current_exe()?)?;
        // debug!("exe_path = {}", exe_path.display());
        // let exe_dir_path = exe_path.parent().unwrap();
        // debug!("exe_dir_path = {}", exe_dir_path.display());
        // let preload_path = exe_dir_path.join("libmevi_preload.so");
        // debug!("Setting LD_PRELOAD to {}", preload_path.display());

        // cmd.env("LD_PRELOAD", preload_path);
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
            puh,
            tx,
            tracees: Default::default(),
            next_parent: None,
        })
    }

    fn run(&mut self) -> Result<()> {
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
                    let tid: TraceeId = pid.into();
                    debug!("{tid} caught sig {sig}");
                    match sig {
                        Signal::SIGTRAP => {
                            // probably ptrace stuff?
                            ptrace::syscall(pid, None)?;
                        }
                        Signal::SIGSTOP => {
                            // probably a new thread after clone?
                            info!("{tid} is that a new thread? (just got SIGSTOP)");

                            if let Some(ptid) = self.next_parent.take() {
                                info!("{tid} might be a child of {ptid}, methinks");

                                if let Some(uffd) = self
                                    .puh
                                    .lock()
                                    .unwrap()
                                    .get_mut(&ptid)
                                    .and_then(|q| q.pop_front())
                                {
                                    info!(
                                        "{tid}<={ptid} well we got uffd {} for this",
                                        uffd.as_raw_fd()
                                    );
                                    self.tx
                                        .send(MeviEvent::TraceeEvent(
                                            tid,
                                            TraceePayload::Connected {
                                                source: ConnectSource::Fork,
                                                uffd: uffd.as_raw_fd(),
                                            },
                                        ))
                                        .unwrap();
                                    info!(
                                        "{tid}<={ptid} well we got uffd {} for this... and sent!",
                                        uffd.as_raw_fd()
                                    );
                                    std::thread::sleep(std::time::Duration::from_millis(10));
                                } else {
                                    info!("{tid}<={ptid} well we don't have a uffd for this");
                                }
                            }

                            ptrace::syscall(pid, None)?;
                        }
                        _ => {
                            // probably not ptrace stuff, forward the signal?
                            ptrace::syscall(pid, sig)?;
                        }
                    }
                    continue;
                }
                WaitStatus::Exited(pid, status) => {
                    if status == 0 {
                        debug!("{pid} exited with status {status}");
                    } else {
                        warn!("{pid} exited with non-zero status {status}");
                    }
                    let ev = MeviEvent::TraceeEvent(pid.into(), TraceePayload::Exit);
                    self.tx.send(ev).unwrap();
                }
                WaitStatus::PtraceSyscall(pid) => {
                    let tid: TraceeId = pid.into();
                    debug!("{tid} in sys_enter / sys_exit");
                    let tracee = self.tracees.entry(tid).or_insert_with(|| Tracee {
                        was_in_syscall: false,
                        tid,
                        heap_range: None,
                        uffd: None,
                    });
                    if tracee.was_in_syscall {
                        tracee.was_in_syscall = false;
                        if let Some(Mapped { range, resident }) =
                            tracee.on_sys_exit(&mut self.tx)?
                        {
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
                        if let Err(e) = ptrace::syscall(pid, None) {
                            if e == nix::errno::Errno::ESRCH {
                                // the process has exited, we don't care
                                info!(
                                    "{pid} exited while we were spying on its syscalls, that's ok"
                                );
                            }
                        }
                    } else {
                        tracee.was_in_syscall = true;
                        match ptrace::syscall(pid, None) {
                            Ok(_) => {}
                            Err(e) => {
                                if e == nix::errno::Errno::ESRCH {
                                    // the process has exited, we don't care
                                    info!(
                                        "{tid} exited while we were spying on its syscalls, that's ok"
                                    );
                                } else {
                                    panic!("{tid} ptrace::syscall failed: {e}");
                                }
                            }
                        }
                    }
                }
                WaitStatus::PtraceEvent(pid, sig, event) => {
                    let tid: TraceeId = pid.into();
                    if event == libc::PTRACE_EVENT_FORK {
                        self.next_parent = Some(tid);
                    }

                    let event_name: Cow<'static, str> = match event {
                        libc::PTRACE_EVENT_CLONE => "clone".into(),
                        libc::PTRACE_EVENT_FORK => "fork".into(),
                        libc::PTRACE_EVENT_VFORK => "vfork".into(),
                        other => format!("unknown event {}", other).into(),
                    };

                    info!("{tid} got event {event_name} with sig {sig}");
                    ptrace::syscall(pid, None)?;
                }
                WaitStatus::Signaled(pid, signal, core_dump) => {
                    let tid: TraceeId = pid.into();
                    info!("{tid} was terminated with signal {signal} with, WCOREDUMP({core_dump})");
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
    uffd: Option<()>,
}

impl Tracee {
    fn on_sys_exit(&mut self, tx: &mut mpsc::SyncSender<MeviEvent>) -> Result<Option<Mapped>> {
        let regs = ptrace::getregs(self.tid.into())?;
        trace!("on sys_exit: {regs:?}");
        let ret = regs.rax as usize;

        match regs.orig_rax as i64 {
            libc::SYS_execve | libc::SYS_execveat => {
                info!("{} is about to execve, getting rid of heap_range", self.tid);

                self.heap_range = None;
                tx.send(MeviEvent::TraceeEvent(self.tid, TraceePayload::Execve))
                    .unwrap();

                return Ok(None);
            }
            libc::SYS_mmap => {
                let fd = regs.r8 as i32;
                let addr_in = regs.rdi;
                let len = regs.rsi as usize;

                if fd == -1 && addr_in == 0 {
                    if self.uffd.is_none() {
                        self.make_uffd(regs, ret)?;
                    }

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
                        info!("{} initial heap_range: {:x?}", self.tid, self.heap_range);
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

    /// `staging_area` is area that was _just_ mmap'd, and that we can write
    /// to, so we can pass pointers-to-structs to the kernel
    #[allow(clippy::useless_transmute)]
    fn make_uffd(&mut self, saved_regs: user_regs_struct, staging_area: usize) -> Result<()> {
        let pid: Pid = self.tid.into();

        const WORD_SIZE: usize = 8;
        assert_eq!(
            std::mem::size_of::<usize>(),
            WORD_SIZE,
            "this is all 64-bit only"
        );

        let sys_step = || {
            ptrace::syscall(pid, None)?;
            let waitres = waitpid(pid, None)?;
            match waitres {
                WaitStatus::PtraceSyscall(_) => {
                    // good.
                }
                other => {
                    panic!("unexpected wait status: {:?}", other);
                }
            }

            Ok::<_, color_eyre::Report>(())
        };

        let invoke = |nr: i64, args: &[u64]| -> Result<u64> {
            let mut call_regs = saved_regs;
            call_regs.rax = nr as _;
            call_regs.rip -= 2;

            for (i, arg) in args.iter().enumerate() {
                match i {
                    0 => call_regs.rdi = *arg,
                    1 => call_regs.rsi = *arg,
                    2 => call_regs.rdx = *arg,
                    3 => call_regs.r10 = *arg,
                    4 => call_regs.r8 = *arg,
                    5 => call_regs.r9 = *arg,
                    _ => panic!("too many args"),
                }
            }

            ptrace::setregs(pid, call_regs)?;

            sys_step()?;
            sys_step()?;

            Ok(ptrace::getregs(pid)?.rax)
        };

        let write_to_staging = |addr: *const u64, addr_size: usize| -> Result<()> {
            let num_words = addr_size / WORD_SIZE;
            for i in 0..num_words {
                let word = unsafe { addr.add(i) };
                let word = unsafe { *word };
                info!("api word {i}: {:016x}", word);
                unsafe { ptrace::write(pid, (staging_area + i * WORD_SIZE) as _, word as _)? };
            }
            Ok(())
        };

        let read_from_staging = |addr: *mut u64, addr_size: usize| -> Result<()> {
            let num_words = addr_size / WORD_SIZE;
            for i in 0..num_words {
                let word_dst = unsafe { addr.add(i) };
                let word = ptrace::read(pid, (staging_area + i * WORD_SIZE) as _)?;
                info!("api word {i}: {:016x}", word);
                unsafe { *word_dst = word as _ };
            }
            Ok(())
        };

        info!("making userfaultfd sycall");
        let raw_uffd = invoke(libc::SYS_userfaultfd, &[])? as i32;
        if raw_uffd < 0 {
            panic!("userfaultfd failed with {}", Errno::from_i32(raw_uffd));
        }
        info!("making userfaultfd sycall.. done! got fd {raw_uffd}");

        let req_features =
            FeatureFlags::EVENT_REMAP | FeatureFlags::EVENT_REMOVE | FeatureFlags::EVENT_UNMAP;
        let mut api = raw::uffdio_api {
            api: raw::UFFD_API,
            features: req_features.bits(),
            ioctls: 0,
        };

        // write the api struct to the staging area
        write_to_staging(
            unsafe { std::mem::transmute(&api) },
            std::mem::size_of_val(&api),
        )?;

        let ret = invoke(
            libc::SYS_ioctl,
            &[raw_uffd as _, raw::UFFDIO_API as _, staging_area as _],
        )?;
        info!("ioctl returned {ret}");

        // read the api struct back from the staging area
        read_from_staging(
            unsafe { std::mem::transmute(&mut api) },
            std::mem::size_of_val(&api),
        )?;

        let supported = IoctlFlags::from_bits(api.ioctls).unwrap();
        info!("supported ioctls: {supported:?}");

        let sock_fd = invoke(
            libc::SYS_socket,
            &[
                libc::AF_UNIX as _,
                (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as _,
                0,
            ],
        )? as i32;
        if sock_fd < 0 {
            panic!("socket failed with {}", Errno::from_i32(sock_fd));
        }
        info!("socket fd: {sock_fd}");

        let mut addr_un = sockaddr_un {
            sun_family: libc::AF_UNIX as _,
            sun_path: [0; 108],
        };
        let sock_path = b"/tmp/mevi.sock\0";
        addr_un.sun_path[0..sock_path.len()]
            .copy_from_slice(unsafe { std::mem::transmute(&sock_path[..]) });
        let addr_len = 2 + sock_path.len();
        info!("addr_len = {addr_len}");

        write_to_staging(
            unsafe { std::mem::transmute(&addr_un) },
            std::mem::size_of_val(&addr_un),
        )?;

        let ret = invoke(
            libc::SYS_connect,
            &[sock_fd as _, staging_area as _, addr_len as _],
        )? as i32;
        if ret < 0 {
            panic!("connect failed with {}", Errno::from_i32(ret));
        }
        info!("connect returned {ret}");

        // now let's write the pid
        unsafe {
            ptrace::write(pid, staging_area as _, pid.as_raw() as u64 as _)?;
        }
        let ret = invoke(libc::SYS_write, &[sock_fd as _, staging_area as _, 8 as _])? as i32;
        if ret < 0 {
            panic!("write failed with {}", Errno::from_i32(ret));
        }
        info!("write returned {ret}");

        // this is the big one: sendmsg.
        let mut msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 24,
            msg_flags: 0,
        };

        // here's our data layout.
        //
        // staging_area
        // [ msghdr ] [ payload ] [  iovec  ] [ cmsghdr | cmsg_data ]
        // 0x0        0x100       0x200       0x300
        //

        // write payload
        unsafe {
            ptrace::write(pid, (staging_area + 0x100) as _, 0x0 as _)?;
        }

        // write iovec
        let iovec = libc::iovec {
            iov_base: (staging_area + 0x100) as _,
            iov_len: 4,
        };
        unsafe {
            #[allow(clippy::identity_op)]
            ptrace::write(pid, (staging_area + 0x200 + 0) as _, iovec.iov_base)?;
            ptrace::write(pid, (staging_area + 0x200 + 8) as _, iovec.iov_len as _)?;
        }

        msghdr.msg_iov = (staging_area + 0x200) as _;
        msghdr.msg_iovlen = 1;

        // write cmsghdr
        let cmsghdr = libc::cmsghdr {
            cmsg_len: 20,
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
        };
        unsafe {
            #[allow(clippy::identity_op)]
            ptrace::write(pid, (staging_area + 0x300 + 0) as _, cmsghdr.cmsg_len as _)?;

            let cmsg_level_ptr: *const u64 = std::mem::transmute(&cmsghdr.cmsg_level);
            ptrace::write(pid, (staging_area + 0x300 + 8) as _, *cmsg_level_ptr as _)?;

            ptrace::write(pid, (staging_area + 0x300 + 16) as _, raw_uffd as _)?;
        }

        msghdr.msg_control = (staging_area + 0x300) as _;
        msghdr.msg_controllen = 24;

        write_to_staging(
            unsafe { std::mem::transmute(&msghdr) },
            std::mem::size_of_val(&msghdr),
        )?;

        let ret = invoke(libc::SYS_sendmsg, &[sock_fd as _, staging_area as _, 0])? as i32;
        if ret < 0 {
            panic!("sendmsg failed with {}", Errno::from_i32(ret));
        }
        info!("sendmsg returned {ret}");

        let ret = invoke(libc::SYS_close, &[sock_fd as _])?;
        info!("close returned {ret}");

        self.uffd = Some(());

        ptrace::setregs(pid, saved_regs)?;
        Ok(())
    }
}
