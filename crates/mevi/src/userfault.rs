use std::{
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixListener,
    },
    sync::mpsc,
};

use nix::unistd::{sysconf, SysconfVar};
use passfd::FdPassingExt;
use tracing::{debug, info, warn};
use userfaultfd::Uffd;

use crate::{MeviEvent, TraceeId, TraceePayload};

pub(crate) fn run(tx: mpsc::SyncSender<MeviEvent>, listener: UnixListener) {
    loop {
        let (mut stream, _) = listener.accept().unwrap();

        let mut pid_bytes = [0u8; 8];
        stream.read_exact(&mut pid_bytes).unwrap();

        let tid = TraceeId(u64::from_be_bytes(pid_bytes));

        let uffd = unsafe { Uffd::from_raw_fd(stream.recv_fd().unwrap()) };
        debug!("From {tid:?}, got uffd {}", uffd.as_raw_fd());
        let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", tid.0))
            .unwrap()
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .collect();
        info!("cmdline for {tid:?} is {cmdline:?}");

        tx.send(MeviEvent::TraceeEvent(
            tid,
            TraceePayload::Connected {
                uffd: uffd.as_raw_fd(),
                cmdline,
            },
        ))
        .unwrap();

        std::thread::spawn({
            let tx = tx.clone();
            move || handle(tx, tid, uffd)
        });
    }
}

fn handle(tx: mpsc::SyncSender<MeviEvent>, tid: TraceeId, uffd: Uffd) {
    let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;

    let send_ev = |payload: TraceePayload| {
        tx.send(MeviEvent::TraceeEvent(tid, payload)).unwrap();
    };

    loop {
        let event = uffd.read_event().unwrap().unwrap();
        match event {
            userfaultfd::Event::Pagefault { addr, .. } => {
                unsafe {
                    loop {
                        match uffd.zeropage(addr, page_size, true) {
                            Ok(_) => {
                                // cool!
                                break;
                            }
                            Err(e) => match e {
                                userfaultfd::Error::ZeropageFailed(errno) => match errno as i32 {
                                    libc::EAGAIN => {
                                        // this is actually fine, just try it again
                                        continue;
                                    }
                                    _ => {
                                        panic!("{e}");
                                    }
                                },
                                _ => unreachable!(),
                            },
                        }
                    }
                }
                let addr = addr as usize;
                send_ev(TraceePayload::PageIn {
                    range: addr..addr + page_size,
                });
            }
            userfaultfd::Event::Remap { from, to, len } => {
                let from = from as usize;
                let to = to as usize;
                send_ev(TraceePayload::Remap {
                    old_range: from..from + len,
                    new_range: to..to + len,
                });
            }
            userfaultfd::Event::Remove { start, end } => {
                let start = start as usize;
                let end = end as usize;
                send_ev(TraceePayload::PageOut { range: start..end });
            }
            userfaultfd::Event::Unmap { start, end } => {
                let start = start as usize;
                let end = end as usize;
                send_ev(TraceePayload::Unmap { range: start..end });
            }
            _ => {
                warn!("Unexpected event: {:?}", event);
            }
        }
    }
}
