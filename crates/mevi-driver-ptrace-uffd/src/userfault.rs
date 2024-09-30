use std::{os::fd::AsRawFd, sync::mpsc};

use humansize::{make_format, BINARY};
use mevi_common::{MemState, MeviEvent, TraceeId, TraceePayload};
use nix::unistd::{sysconf, SysconfVar};
use tracing::{debug, warn};
use userfaultfd::Uffd;

pub(crate) fn handle(tx: &mut mpsc::SyncSender<MeviEvent>, tid: TraceeId, uffd: Uffd) {
    let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as u64;

    let send_ev = |payload: TraceePayload| {
        tx.send(MeviEvent::TraceeEvent(tid, payload)).unwrap();
    };

    loop {
        let event = match uffd.read_event() {
            Ok(event) => event.unwrap(),
            Err(userfaultfd::Error::SystemError(nix::Error::EBADF)) => {
                warn!("{tid} uffd {} died! (got EBADF)", uffd.as_raw_fd());
                let ev = MeviEvent::TraceeEvent(tid, TraceePayload::Exit);
                tx.send(ev).unwrap();
                return;
            }
            Err(e) => {
                panic!("uffd.read_event failed: {e:?}");
            }
        };
        tracing::debug!("{tid} got {event:?}");
        match event {
            userfaultfd::Event::Pagefault { addr, .. } => {
                let res = unsafe { uffd.zeropage(addr, page_size as _, true) };
                if let Err(e) = res {
                    let errno = match e {
                        userfaultfd::Error::ZeropageFailed(errno) => errno,
                        _ => unreachable!(),
                    };

                    match errno as i32 {
                        libc::EAGAIN => {
                            // retrying often doesn't work, BUT this means the
                            // thread wasn't awakened, so we need to do it by
                            // hand. worst case scenario, we get another event
                            // from the same range.
                            debug!("zeropage({addr:p}, {page_size:x?}) = EAGAIN, breaking");
                            uffd.wake(addr, page_size as _).unwrap();
                        }
                        libc::EBADF => {
                            warn!("{tid} uffd {} died! (got EBADF)", uffd.as_raw_fd());
                            return;
                        }
                        libc::ENOENT => {
                            // not sure if this is fine but let's not panic?
                            warn!("{tid} ENOENT while zeropaging {addr:?}");
                            continue;
                        }
                        _ => {
                            panic!("while doing zeropage: {e:?}");
                        }
                    }
                }
                let addr = addr as u64;
                send_ev(TraceePayload::MemStateChange {
                    range: addr..addr + page_size,
                    state: MemState::Resident,
                });
            }
            userfaultfd::Event::Remap { from, to, len } => {
                let from = from as usize;
                let to = to as usize;

                debug!(
                    "{} got uffd remap event {:x?}.. => {:x?}, len = {}",
                    tid,
                    from,
                    to,
                    make_format(BINARY)(len),
                );
            }
            userfaultfd::Event::Remove { start, end } => {
                let start = start as usize;
                let end = end as usize;

                debug!(
                    "{} got uffd remove event {:x?}, len = {}",
                    tid,
                    start..end,
                    make_format(BINARY)(end - start),
                );
            }
            userfaultfd::Event::Unmap { start, end } => {
                let start = start as usize;
                let end = end as usize;

                debug!(
                    "{} got uffd unmap event {:x?}, len = {}",
                    tid,
                    start..end,
                    make_format(BINARY)(end - start),
                );
            }
            other => {
                warn!("unhandled uffd event: {:?}", other);
            }
        }
    }
}
