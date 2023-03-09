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

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
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
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::EnvFilter;
use userfaultfd::Uffd;

mod tracer;
mod userfault;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let (w_tx, w_rx) = watch::channel(MemMap::default());

    let router = axum::Router::new()
        .route("/ws", axum::routing::get(ws))
        .with_state(w_rx);
    let addr = "127.0.0.1:5001".parse().unwrap();
    let server = axum::Server::bind(&addr).serve(router.into_make_service());

    std::thread::spawn(move || relay(rx, w_tx));

    server.await.unwrap();
    Ok(())
}

fn relay(rx: mpsc::Receiver<TraceeEvent>, w_tx: watch::Sender<MemMap>) {
    let mut child_uffd: Option<&'static Uffd> = None;

    let mut map: MemMap = Default::default();

    let mut last_print = Instant::now();
    let interval = Duration::from_millis(250);

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
        w_tx.send(map.clone()).unwrap();
    }
}

async fn ws(
    State(rx): State<watch::Receiver<MemMap>>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(|ws| handle_ws(rx, ws))
}

async fn handle_ws(mut rx: watch::Receiver<MemMap>, mut ws: WebSocket) {
    loop {
        rx.changed().await.unwrap();
        let payload = bincode::serialize(&*rx.borrow()).unwrap();
        ws.send(Message::Binary(payload)).await.unwrap();
    }
}
