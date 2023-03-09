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
enum Resident {
    Yes,
    No,
}

#[allow(dead_code)]
type MemMap = RangeMap<usize, Resident>;
#[allow(dead_code)]
type UffdSlot = Arc<Mutex<Option<Uffd>>>;

const SOCK_PATH: &str = "/tmp/mevi.sock";

#[derive(Debug)]
#[allow(dead_code)]
enum TraceeEvent {
    Map {
        range: Range<usize>,
        resident: Resident,
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

    let (tx, rx) = mpsc::channel::<TraceeEvent>();
    let tx2 = tx.clone();

    std::thread::spawn(move || userfault::run(tx, listener));
    std::thread::spawn(move || tracer::run(tx2));

    loop {
        let ev = rx.recv().unwrap();
        info!("{:?}", ev.blue());
    }
}
