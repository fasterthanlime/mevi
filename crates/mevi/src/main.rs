use std::{
    collections::HashMap,
    ops::Range,
    os::{
        fd::{FromRawFd, RawFd},
        unix::net::UnixListener,
    },
    sync::mpsc,
    time::Duration,
};

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use nix::unistd::Pid;
// use humansize::{make_format, BINARY};
use owo_colors::OwoColorize;
use postage::{broadcast, sink::Sink, stream::Stream};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use tracing_subscriber::EnvFilter;
use userfaultfd::Uffd;

mod tracer;
mod userfault;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum MemState {
    Resident,
    NotResident,
    Unmapped,
}

type MemMap = RangeMap<usize, MemState>;

const SOCK_PATH: &str = "/tmp/mevi.sock";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
struct TraceePid(u64);

impl From<Pid> for TraceePid {
    fn from(pid: Pid) -> Self {
        Self(pid.as_raw() as _)
    }
}

#[derive(Debug, Serialize)]
struct TraceeEvent {
    pid: TraceePid,
    payload: TraceePayload,
}

#[derive(Debug, Serialize)]
struct MapGuard {
    #[serde(skip)]
    _inner: Option<mpsc::Sender<()>>,
}

impl Clone for MapGuard {
    fn clone(&self) -> Self {
        Self { _inner: None }
    }
}

#[derive(Debug, Clone, Serialize)]
enum TraceePayload {
    Map {
        range: Range<usize>,
        resident: MemState,
        _guard: MapGuard,
    },
    Connected {
        uffd: RawFd,
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
    Batch {
        batch: MemMap,
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

    let (tx, rx) = mpsc::sync_channel::<TraceeEvent>(16);
    let tx2 = tx.clone();

    std::thread::spawn(move || userfault::run(tx, listener));
    std::thread::spawn(move || tracer::run(tx2));

    let (w_tx, _) = broadcast::channel(16);

    let router = axum::Router::new()
        .route("/ws", axum::routing::get(ws))
        .with_state(w_tx.clone());
    let addr = "127.0.0.1:5001".parse().unwrap();
    let server = axum::Server::bind(&addr).serve(router.into_make_service());

    std::thread::spawn(move || relay(rx, w_tx));

    server.await.unwrap();
    Ok(())
}

struct TraceeState {
    pid: TraceePid,
    map: MemMap,
    batch: MemMap,
    batch_size: usize,
    uffd: Option<Uffd>,
    w_tx: broadcast::Sender<Vec<u8>>,
}

impl TraceeState {
    fn send_ev(&mut self, payload: TraceePayload) {
        let ev = TraceeEvent {
            pid: self.pid,
            payload,
        };
        let payload = bincode::serialize(&ev).unwrap();
        _ = self.w_tx.blocking_send(payload);
    }

    fn flush(&mut self) {
        if self.batch_size == 0 {
            return;
        }

        self.batch_size = 0;
        self.send_ev(TraceePayload::Batch {
            batch: std::mem::take(&mut self.batch),
        });
    }

    fn accumulate(&mut self, range: Range<usize>, state: MemState) {
        if self.batch_size > 128 {
            self.flush();
        }

        self.batch.insert(range, state);
    }

    fn register(&mut self, range: &Range<usize>) {
        if let Some(uffd) = &self.uffd {
            let _ = uffd.register(range.start as _, range.end - range.start);
        }
    }
}

fn relay(rx: mpsc::Receiver<TraceeEvent>, mut w_tx: broadcast::Sender<Vec<u8>>) {
    let mut tracees: HashMap<TraceePid, TraceeState> = Default::default();
    let interval = Duration::from_millis(150);

    loop {
        let mut first = true;
        let ev = loop {
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
                // didn't get an event in `interval`, block until we get one,
                // but first, flush all batches
                for tracee in tracees.values_mut() {
                    tracee.flush();
                }
                break rx.recv().unwrap();
            }
        };
        debug!("{:?}", ev.blue());

        const COALESCE_THRESHOLD: usize = 128;

        let tracee = tracees.entry(ev.pid).or_insert_with(|| TraceeState {
            pid: ev.pid,
            map: Default::default(),
            batch: Default::default(),
            batch_size: 0,
            uffd: None,
            w_tx: w_tx.clone(),
        });

        match &ev.payload {
            TraceePayload::PageIn { range } => tracee.accumulate(range.clone(), MemState::Resident),
            TraceePayload::PageOut { range } => {
                tracee.accumulate(range.clone(), MemState::NotResident)
            }
            other => {
                tracee.flush();
                tracee.send_ev(ev.payload);
            }
        };

        match ev.payload {
            TraceePayload::Map {
                range, resident, ..
            } => {
                tracee.register(&range);
                tracee.map.insert(range, resident);
            }
            TraceePayload::Connected { uffd } => {
                tracee.uffd.replace(unsafe { Uffd::from_raw_fd(uffd) });
            }
            TraceePayload::PageIn { range } => {
                tracee.map.insert(range, MemState::Resident);
            }
            TraceePayload::PageOut { range } => {
                tracee.map.insert(range, MemState::NotResident);
            }
            TraceePayload::Unmap { range } => {
                tracee.map.remove(range);
            }
            TraceePayload::Remap {
                old_range,
                new_range,
            } => {
                warn!("Remap: {old_range:?} => {new_range:?}");

                // FIXME: that's not right - we should retain the memory state
                tracee.map.remove(old_range);
                tracee.map.insert(new_range, MemState::Resident);
            }
            _ => {
                unreachable!()
            }
        }
    }
}

async fn ws(
    State(tx): State<broadcast::Sender<Vec<u8>>>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |ws| handle_ws(tx.subscribe(), ws))
}

async fn handle_ws(mut rx: broadcast::Receiver<Vec<u8>>, mut ws: WebSocket) {
    loop {
        let payload = rx.recv().await.unwrap();
        ws.send(Message::Binary(payload)).await.unwrap();
    }
}
