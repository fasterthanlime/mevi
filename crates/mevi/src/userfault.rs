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

use crate::{ConnectSource, MeviEvent, TraceeId, TraceePayload};

pub(crate) fn run(tx: mpsc::SyncSender<MeviEvent>, listener: UnixListener) {
    loop {
        let (mut stream, addr) = listener.accept().unwrap();
        debug!("accepted unix stream from {addr:?}!");

        // TODO: SO_PEERCRED can be used here instead of sending the PID in-band
        // https://stackoverflow.com/questions/8104904/identify-program-that-connects-to-a-unix-domain-socket
        //
        // but it's also a huge PITA, and this isn't security-sensitive, so.
        let mut pid_bytes = [0u8; 8];
        stream.read_exact(&mut pid_bytes).unwrap();

        let tid = TraceeId(u64::from_le_bytes(pid_bytes));

        let uffd = unsafe { Uffd::from_raw_fd(stream.recv_fd().unwrap()) };
        info!("{tid} received uffd {}", uffd.as_raw_fd());

        tx.send(MeviEvent::TraceeEvent(
            tid,
            TraceePayload::Connected {
                source: ConnectSource::Uds,
                uffd: uffd.as_raw_fd() as _,
            },
        ))
        .unwrap();

        std::thread::spawn({
            let mut tx = tx.clone();
            move || {
                handle(&mut tx, tid, uffd);
                tx.send(MeviEvent::TraceeEvent(tid, TraceePayload::Exit))
            }
        });
    }
}

fn handle(tx: &mut mpsc::SyncSender<MeviEvent>, tid: TraceeId, uffd: Uffd) {
    let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;

    let send_ev = |payload: TraceePayload| {
        tx.send(MeviEvent::TraceeEvent(tid, payload)).unwrap();
    };

    loop {
        let event = match uffd.read_event() {
            Ok(event) => event.unwrap(),
            Err(userfaultfd::Error::SystemError(nix::Error::EBADF)) => {
                warn!("uffd {} died! (got EBADF)", uffd.as_raw_fd());
                return;
            }
            Err(e) => {
                panic!("uffd.read_event failed: {e}");
            }
        };
        tracing::debug!("{tid} got {event:?}");
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
                                    libc::EBADF => {
                                        warn!("uffd {} died! (got EBADF)", uffd.as_raw_fd());
                                        return;
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
            other => {
                warn!("unhandled uffd event: {:?}", other);
            }
        }
    }
}
