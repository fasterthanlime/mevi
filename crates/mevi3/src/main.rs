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
use tracing::{debug, info, trace, warn};
use tracing_subscriber::EnvFilter;
use userfaultfd::Uffd;

mod tracer;
mod userfault;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IsResident {
    Yes,
    No,
}

type MemMap = RangeMap<usize, IsResident>;

const SOCK_PATH: &str = "/tmp/mevi.sock";

#[derive(Debug)]
#[allow(dead_code)]
enum TraceeEvent {
    Map {
        range: Range<usize>,
        resident: IsResident,
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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::try_from("info").unwrap()),
        )
        .init();

    std::fs::remove_file(SOCK_PATH).ok();
    let listener = UnixListener::bind(SOCK_PATH).unwrap();

    let (tx, rx) = mpsc::sync_channel::<TraceeEvent>(2048);
    let tx2 = tx.clone();

    std::thread::spawn(move || userfault::run(tx, listener));
    std::thread::spawn(move || tracer::run(tx2));

    let mut child_uffd: Option<&'static Uffd> = None;

    let mut map: MemMap = Default::default();

    let mut last_print = Instant::now();
    let interval = Duration::from_millis(250);

    let formatter = make_format(BINARY);

    loop {
        let mut first = true;
        let ev = loop {
            if last_print.elapsed() > interval {
                last_print = Instant::now();
                let mut total = 0;
                let mut resident = 0;
                for (range, is_resident) in map.iter() {
                    total += range.end - range.start;
                    if *is_resident == IsResident::Yes {
                        resident += range.end - range.start;
                    }
                }
                let format = make_format(BINARY);
                info!("VIRT: {}, RSS: {}", format(total), format(resident));
            }

            if first {
                match rx.recv_timeout(interval) {
                    Ok(ev) => break ev,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        first = false;
                        continue;
                    }
                    _ => unreachable!(),
                };
            } else {
                break rx.recv().unwrap();
            }
        };
        debug!("{:?}", ev.blue());
        match ev {
            TraceeEvent::Map {
                range,
                resident,
                _guard,
            } => {
                let size = range.end - range.start;
                if size > 0x1000 * 128 {
                    warn!("Map {} {:?}", formatter(size), resident);
                }

                if let Some(uffd) = child_uffd {
                    uffd.register(range.start as _, range.end - range.start)
                        .unwrap();
                }
                map.insert(range, resident);
            }
            TraceeEvent::Connected { uffd } => {
                child_uffd = Some(uffd);
            }
            TraceeEvent::PageIn { range } => {
                map.insert(range, IsResident::Yes);
            }
            TraceeEvent::PageOut { range } => {
                map.insert(range, IsResident::No);
            }
            TraceeEvent::Unmap { range } => {
                warn!("Unmap {}", formatter(range.end - range.start));
                map.remove(range);
            }
            TraceeEvent::Remap {
                old_range,
                new_range,
            } => {
                warn!("Remap: {old_range:?} => {new_range:?}");
                // FIXME: that's not right - we should retain the resident state
                map.remove(old_range);
                map.insert(new_range, IsResident::Yes);
            }
        }
    }
}
