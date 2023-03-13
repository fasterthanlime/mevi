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
use tracing::{info, warn};
use userfaultfd::{raw, FeatureFlags, IoctlFlags, Uffd};

use crate::{ConnectSource, MeviEvent, PendingUffdsHandle, TraceeId, TraceePayload};

pub(crate) fn run(
    puh: PendingUffdsHandle,
    tx: mpsc::SyncSender<MeviEvent>,
    listener: UnixListener,
) {
    loop {
        let (mut stream, _) = listener.accept().unwrap();

        let mut pid_bytes = [0u8; 8];
        stream.read_exact(&mut pid_bytes).unwrap();

        let tid = TraceeId(u64::from_be_bytes(pid_bytes));

        let uffd = unsafe { Uffd::from_raw_fd(stream.recv_fd().unwrap()) };
        info!("{tid} received uffd {}", uffd.as_raw_fd());

        tx.send(MeviEvent::TraceeEvent(
            tid,
            TraceePayload::Connected {
                source: ConnectSource::LdPreload,
                uffd: uffd.as_raw_fd(),
            },
        ))
        .unwrap();

        std::thread::spawn({
            let tx = tx.clone();
            let puh = puh.clone();
            move || handle(puh, tx, tid, uffd)
        });
    }
}

fn handle(puh: PendingUffdsHandle, tx: mpsc::SyncSender<MeviEvent>, tid: TraceeId, uffd: Uffd) {
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
            userfaultfd::Event::Fork { uffd } => {
                info!("{tid} uffd fork notif! the child uffd is {:?}", uffd);

                // FIXME: turns out the API handshake is already done by
                // the time the fd is dup'd? I'm very confused.
                //
                // info!("{tid} performing API handshake with child uffd");
                // let req_features = FeatureFlags::EVENT_REMAP
                //     | FeatureFlags::EVENT_REMOVE
                //     | FeatureFlags::EVENT_UNMAP
                //     | FeatureFlags::EVENT_FORK;
                // let mut api = raw::uffdio_api {
                //     api: raw::UFFD_API,
                //     features: req_features.bits(),
                //     ioctls: 0,
                // };
                // unsafe {
                //     raw::api(uffd.as_raw_fd(), &mut api as *mut raw::uffdio_api).unwrap();
                // }
                // let supported = IoctlFlags::from_bits(api.ioctls)
                //     .expect("unknown ioctl flags returned by kernel");
                // info!("{tid} supported ioctls: {supported:?}");

                {
                    let mut puh = puh.lock().unwrap();
                    puh.entry(tid).or_default().push_back(uffd);
                }
            }
        }
    }
}
