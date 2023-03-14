use std::{
    borrow::Cow, collections::HashMap, ops::Range, os::unix::process::CommandExt, process::Command,
    sync::mpsc,
};

use color_eyre::Result;
use humansize::{make_format, BINARY};
use libc::{sockaddr_un, user_regs_struct};
use mevi_common::{MapGuard, MemState, MeviEvent, TraceeId, TraceePayload};
use nix::{
    errno::Errno,
    sys::{
        mman::{MapFlags, ProtFlags},
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use owo_colors::OwoColorize;
use tracing::{debug, info, trace, warn};
use userfaultfd::{raw, FeatureFlags, IoctlFlags};

pub(crate) fn run(tx: mpsc::SyncSender<MeviEvent>) {
    Tracer::new(tx).unwrap().run().unwrap();
}

struct Tracer {
    tx: mpsc::SyncSender<MeviEvent>,
    tracees: HashMap<TraceeId, Tracee>,
}

struct MemoryEvent {
    for_tid: TraceeId,
    change: MemoryChange,
}

enum MemoryChange {
    Map {
        range: Range<u64>,
        state: MemState,
    },
    Remap {
        old_range: Range<u64>,
        new_range: Range<u64>,
    },
    Unmap {
        range: Range<u64>,
    },
    PageOut {
        range: Range<u64>,
    },
}

impl Tracer {
    fn new(tx: mpsc::SyncSender<MeviEvent>) -> Result<Self> {
        let mut args = std::env::args();
        // skip our own name
        args.next().unwrap();

        let mut cmd = Command::new(args.next().unwrap());
        for arg in args {
            cmd.arg(arg);
        }

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
                            debug!("{tid} is that a new thread? (just got SIGSTOP)");
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
                        kind: TraceeKind::Unknown,
                    });

                    if tracee.was_in_syscall {
                        tracee.was_in_syscall = false;

                        if let Some(MemoryEvent { for_tid, change }) =
                            tracee.on_sys_exit(&mut self.tx)?
                        {
                            if matches!(tracee.kind, TraceeKind::Unknown) {
                                warn!(
                                    "{} unknown tracee kind, and Mapped, assuming process",
                                    tracee.tid
                                );
                            }

                            match change {
                                MemoryChange::Map { range, state } => {
                                    let (tx, rx) = mpsc::channel();
                                    let ev = MeviEvent::TraceeEvent(
                                        for_tid,
                                        TraceePayload::Map {
                                            range,
                                            state,
                                            _guard: MapGuard { _inner: Some(tx) },
                                        },
                                    );
                                    self.tx.send(ev).unwrap();
                                    _ = rx.recv(); // wait for event to be processed
                                }
                                MemoryChange::Remap {
                                    old_range,
                                    new_range,
                                } => {
                                    let (tx, rx) = mpsc::channel();
                                    let ev = MeviEvent::TraceeEvent(
                                        for_tid,
                                        TraceePayload::Remap {
                                            old_range,
                                            new_range,
                                            _guard: MapGuard { _inner: Some(tx) },
                                        },
                                    );
                                    self.tx.send(ev).unwrap();
                                    _ = rx.recv(); // wait for event to be processed
                                }
                                MemoryChange::Unmap { range } => {
                                    let ev = MeviEvent::TraceeEvent(
                                        for_tid,
                                        TraceePayload::Unmap { range },
                                    );
                                    self.tx.send(ev).unwrap();
                                }
                                MemoryChange::PageOut { range } => {
                                    let ev = MeviEvent::TraceeEvent(
                                        for_tid,
                                        TraceePayload::PageOut { range },
                                    );
                                    self.tx.send(ev).unwrap();
                                }
                            }
                        }
                        if let Err(e) = ptrace::syscall(pid, None) {
                            if e == nix::errno::Errno::ESRCH {
                                // the process has exited, we don't care
                                info!("{pid} exited while we spied");
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
                    let ev = MeviEvent::TraceeEvent(tid, TraceePayload::Exit);
                    self.tx.send(ev).unwrap();
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
    kind: TraceeKind,
}

enum TraceeKind {
    Unknown,

    // we got an uffd for it
    Process { heap_range: Range<u64> },

    // it's a thread of something we have an uffd for
    ThreadOf { pid: TraceeId },
}

impl Tracee {
    fn on_sys_exit(&mut self, tx: &mut mpsc::SyncSender<MeviEvent>) -> Result<Option<MemoryEvent>> {
        let regs = ptrace::getregs(self.tid.into())?;
        trace!("on sys_exit: {regs:?}");
        let ret = regs.rax;

        if matches!(self.kind, TraceeKind::Unknown) {
            match regs.orig_rax as _ {
                libc::SYS_rseq | libc::SYS_set_robust_list | libc::SYS_rt_sigprocmask => {
                    // these all happen super early, seems lke a bad idea? idk
                }
                libc::SYS_execve => {
                    // bad idea, we're about to replace all memory mappings anyway
                }
                syscall_nr => {
                    info!(
                        "{} connecting as syscall {syscall_nr} is returning",
                        self.tid
                    );
                    self.connect(regs)?;
                }
            }
        }

        let for_tid = match &self.kind {
            TraceeKind::ThreadOf { pid } => *pid,
            TraceeKind::Unknown => self.tid,
            TraceeKind::Process { .. } => self.tid,
        };

        match regs.orig_rax as i64 {
            libc::SYS_execve | libc::SYS_execveat => {
                info!("{} will execve, resetting", self.tid);

                // TODO: remember that we execv'd, at this point
                self.kind = TraceeKind::Unknown;
                tx.send(MeviEvent::TraceeEvent(for_tid, TraceePayload::Execve))
                    .unwrap();

                return Ok(None);
            }
            libc::SYS_mmap => {
                let addr_in = regs.rdi;
                let len = regs.rsi;
                let prot = regs.rdx;
                let flags = regs.r10;
                let fd = regs.r8 as i32;
                let map_flags = MapFlags::from_bits(flags as _).unwrap();
                let prot_flags = ProtFlags::from_bits(prot as _).unwrap();
                let _ = (map_flags, prot_flags);

                if fd == -1
                    && addr_in == 0
                    && prot_flags.contains(ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
                    && map_flags.contains(MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS)
                {
                    info!("{} thread of {for_tid} just did mmap addr_in={addr_in:x?} len={len:x?} prot=({prot_flags:?}) flags=({map_flags:?}) fd={fd}", self.tid);
                    return Ok(Some(MemoryEvent {
                        for_tid,
                        change: MemoryChange::Map {
                            range: ret..ret + len,
                            state: if map_flags.contains(MapFlags::MAP_POPULATE) {
                                MemState::Resident
                            } else {
                                MemState::NotResident
                            },
                        },
                    }));
                }
            }
            libc::SYS_mremap => {
                let addr = regs.rdi;
                let old_len = regs.rsi;
                let new_len = regs.rdx;
                let flags = regs.r10;
                let new_addr = ret;

                {
                    let formatter = make_format(BINARY);
                    let old_len = formatter(old_len);
                    let new_len = formatter(new_len);
                    info!("{} thread of {for_tid} just did mremap addr={addr:x?} old_len={old_len} new_len={new_len} flags={flags:x?} new_addr={new_addr:x?}", self.tid);
                }

                return Ok(Some(MemoryEvent {
                    for_tid,
                    change: MemoryChange::Remap {
                        old_range: addr..addr + old_len,
                        new_range: new_addr..new_addr + new_len,
                    },
                }));
            }
            libc::SYS_munmap => {
                let addr = regs.rdi;
                let len = regs.rsi;

                {
                    let formatter = make_format(BINARY);
                    let len = formatter(len);
                    info!(
                        "{} thread of {for_tid} just did munmap addr={addr:x?} len={len}",
                        self.tid
                    );
                }

                return Ok(Some(MemoryEvent {
                    for_tid,
                    change: MemoryChange::Unmap {
                        range: addr..addr + len,
                    },
                }));
            }
            libc::SYS_madvise => {
                let addr = regs.rdi;
                let len = regs.rsi;
                let advice = regs.rdx as i32;

                match advice {
                    libc::MADV_DONTNEED | libc::MADV_REMOVE => {
                        {
                            let formatter = make_format(BINARY);
                            let len = formatter(len);
                            info!("{} thread of {for_tid} just did madvise-dontneed/remove addr={addr:x?} len={len} advice={advice}", self.tid);
                        }

                        return Ok(Some(MemoryEvent {
                            for_tid,
                            change: MemoryChange::PageOut {
                                range: addr..addr + len,
                            },
                        }));
                    }
                    _ => {
                        // ignore
                    }
                }
            }
            libc::SYS_brk => {
                // FIXME: calling brk from a thread should mutate the heap of
                // the whole process
                if let TraceeKind::Process { heap_range } = &mut self.kind {
                    if regs.rdi == 0 {
                        // just a query: ignore
                    } else {
                        // either growing or shrinking the heap,
                        // and we know the previous top
                        let old_top = heap_range.end;
                        heap_range.end = ret;

                        if heap_range.end > old_top {
                            // heap just grew
                            info!("heap grew from {old_top:x?} to {:x?}", heap_range.end);
                            return Ok(Some(MemoryEvent {
                                for_tid,
                                change: MemoryChange::Map {
                                    range: old_top..heap_range.end,
                                    state: MemState::Resident,
                                },
                            }));
                        }
                        if heap_range.end < old_top {
                            // heap just shrunk
                            info!("heap shrunk from {old_top:x?} to {:x?}", heap_range.end);
                            return Ok(Some(MemoryEvent {
                                for_tid,
                                change: MemoryChange::Unmap {
                                    range: heap_range.end..old_top,
                                },
                            }));
                        }
                    }
                } else {
                    warn!("a thread is changing the brk for the process, we should handle that");
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
    fn connect(&mut self, saved_regs: user_regs_struct) -> Result<()> {
        let tid = self.tid;
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
                    panic!(
                        "{} in make_uffd, unexpected wait status: {:?}",
                        self.tid, other
                    );
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

        let real_pid = TraceeId(invoke(libc::SYS_getpid, &[])?);

        if real_pid != tid {
            info!("{tid} is a thread of {real_pid}");
            self.kind = TraceeKind::ThreadOf { pid: real_pid };
            ptrace::setregs(pid, saved_regs)?;
            return Ok(());
        }

        debug!("allocate staging area");
        let staging_area = invoke(
            libc::SYS_mmap,
            &[
                0,
                0x1000,
                (libc::PROT_READ | libc::PROT_WRITE) as _,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as _,
                (-1_i32) as u64,
                0,
            ],
        )? as usize;
        if staging_area == libc::MAP_FAILED as usize {
            panic!("failed to allocate staging area: returned MAP_FAILED");
        }

        let write_to_staging = |addr: *const u64, addr_size: usize| -> Result<()> {
            let num_words = addr_size / WORD_SIZE;
            for i in 0..num_words {
                let word = unsafe { addr.add(i) };
                let word = unsafe { *word };
                // info!("api word {i}: {:016x}", word);
                unsafe { ptrace::write(pid, (staging_area + i * WORD_SIZE) as _, word as _)? };
            }
            Ok(())
        };

        let read_from_staging = |addr: *mut u64, addr_size: usize| -> Result<()> {
            let num_words = addr_size / WORD_SIZE;
            for i in 0..num_words {
                let word_dst = unsafe { addr.add(i) };
                let word = ptrace::read(pid, (staging_area + i * WORD_SIZE) as _)?;
                // info!("api word {i}: {:016x}", word);
                unsafe { *word_dst = word as _ };
            }
            Ok(())
        };

        debug!("making userfaultfd sycall");
        let ret = invoke(libc::SYS_userfaultfd, &[0])? as i32;
        if ret < 0 {
            panic!("userfaultfd failed with {}", Errno::from_i32(-ret));
        }
        let raw_uffd = ret;
        debug!("making userfaultfd sycall.. done! got fd {raw_uffd}");

        let req_features = FeatureFlags::EVENT_REMAP
            | FeatureFlags::EVENT_REMOVE
            | FeatureFlags::EVENT_UNMAP
            | FeatureFlags::THREAD_ID;
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
        )? as i32;
        if ret < 0 {
            panic!("ioctl failed with {ret} / {}", Errno::from_i32(-ret));
        }
        debug!("ioctl returned {ret}");

        // read the api struct back from the staging area
        read_from_staging(
            unsafe { std::mem::transmute(&mut api) },
            std::mem::size_of_val(&api),
        )?;

        let supported = IoctlFlags::from_bits(api.ioctls).unwrap();
        debug!("supported ioctls: {supported:?}");

        let ret = invoke(
            libc::SYS_socket,
            &[
                libc::AF_UNIX as _,
                (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as _,
                0,
            ],
        )? as i32;
        if ret < 0 {
            panic!("socket failed with {ret} / {}", Errno::from_i32(-ret));
        }
        let sock_fd = ret;
        debug!("socket fd: {sock_fd}");

        let mut addr_un = sockaddr_un {
            sun_family: libc::AF_UNIX as _,
            sun_path: [0; 108],
        };
        let sock_path = b"/tmp/mevi.sock\0";
        addr_un.sun_path[0..sock_path.len()]
            .copy_from_slice(unsafe { std::mem::transmute(&sock_path[..]) });
        let addr_len = 2 + sock_path.len();
        debug!("addr_len = {addr_len}");

        write_to_staging(
            unsafe { std::mem::transmute(&addr_un) },
            std::mem::size_of_val(&addr_un),
        )?;

        let ret = invoke(
            libc::SYS_connect,
            &[sock_fd as _, staging_area as _, addr_len as _],
        )? as i32;
        if ret < 0 {
            panic!("connect failed with {ret} / {}", Errno::from_i32(-ret));
        }
        debug!("connect returned {ret}");

        // now let's write the pid
        unsafe {
            ptrace::write(pid, staging_area as _, pid.as_raw() as u64 as _)?;
        }
        let ret = invoke(libc::SYS_write, &[sock_fd as _, staging_area as _, 8 as _])? as i32;
        if ret < 0 {
            panic!("write failed with {ret} / {}", Errno::from_i32(-ret));
        }
        debug!("write returned {ret}");

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
            panic!("sendmsg failed with {}", Errno::from_i32(-ret));
        }
        debug!("sendmsg returned {ret}");

        // now close the socket
        let ret = invoke(libc::SYS_close, &[sock_fd as _])?;
        debug!("close(sock_fd) returned {ret}");

        // now close the uffd
        let ret = invoke(libc::SYS_close, &[raw_uffd as _])?;
        debug!("close(uffd) returned {ret}");

        // now free the staging area
        let ret = invoke(libc::SYS_munmap, &[staging_area as _, 0x1000])?;
        debug!("munmap(staging_area) returned {ret}");

        // TODO: get break start from `/proc/:pid/stat` field 47 instead?
        // cf. https://man7.org/linux/man-pages/man5/proc.5.html
        let ret = invoke(libc::SYS_brk, &[0])?;
        debug!("brk(0) returned {ret}");

        self.kind = TraceeKind::Process {
            heap_range: ret..ret,
        };
        ptrace::setregs(pid, saved_regs)?;

        // info!("{tid} now let's query proc maps");
        // let maps = proc_maps::get_process_maps(tid.0 as _)?;
        // for map in maps {
        //     if map.filename().is_none() && map.is_read() && map.is_write() {
        //         info!(
        //             "- {:x?}..{:x?} R={}, W={} {map:?}",
        //             map.start(),
        //             map.start() + map.size(),
        //             map.is_read(),
        //             map.is_write()
        //         );
        //         tx.send(MeviEvent::TraceeEvent(
        //             tid,
        //             TraceePayload::Map {
        //                 range: map.start()..map.start() + map.size(),
        //                 state: MemState::NotResident,
        //                 _guard: MapGuard { _inner: None },
        //             },
        //         ))
        //         .unwrap();
        //         info!("Let's hope that's not a race condition");
        //     }
        // }

        Ok(())
    }
}
