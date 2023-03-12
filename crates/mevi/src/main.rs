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
struct TraceeId(u64);

impl From<Pid> for TraceeId {
    fn from(pid: Pid) -> Self {
        Self(pid.as_raw() as _)
    }
}

impl From<TraceeId> for Pid {
    fn from(id: TraceeId) -> Self {
        Self::from_raw(id.0 as _)
    }
}

#[derive(Debug, Serialize)]
enum MeviEvent {
    Snapshot(Vec<TraceeSnapshot>),
    TraceeEvent(TraceeId, TraceePayload),
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
struct TraceeSnapshot {
    tid: TraceeId,
    cmdline: Vec<String>,
    map: MemMap,
}

#[derive(Debug, Clone, Serialize)]
enum TraceePayload {
    Map {
        range: Range<usize>,
        state: MemState,
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
    Start {
        cmdline: Vec<String>,
    },
    Exit,
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

    let (tx, rx) = mpsc::sync_channel::<MeviEvent>(16);
    let tx2 = tx.clone();
    let tx3 = tx.clone();

    std::thread::spawn(move || userfault::run(tx, listener));
    std::thread::spawn(move || tracer::run(tx2));

    let (payload_tx, _) = broadcast::channel(16);

    let rs = RouterState {
        payload_tx: payload_tx.clone(),
        ev_tx: tx3.clone(),
    };
    let router = axum::Router::new()
        .route("/stream", axum::routing::get(stream))
        .with_state(rs);
    let addr = "127.0.0.1:5001".parse().unwrap();
    let server = axum::Server::bind(&addr).serve(router.into_make_service());

    std::thread::spawn(move || relay(rx, payload_tx));

    server.await.unwrap();
    Ok(())
}

struct TraceeState {
    tid: TraceeId,
    cmdline: Vec<String>,
    map: MemMap,
    batch: MemMap,
    batch_size: usize,
    uffd: Option<Uffd>,
    w_tx: broadcast::Sender<Vec<u8>>,
}

impl TraceeState {
    fn send_ev(&mut self, payload: TraceePayload) {
        let ev = MeviEvent::TraceeEvent(self.tid, payload);
        let payload = bincode::serialize(&ev).unwrap();
        _ = self.w_tx.blocking_send(payload);
    }

    fn flush(&mut self) {
        if self.batch_size == 0 {
            return;
        }

        self.batch_size = 0;
        let batch = std::mem::take(&mut self.batch);
        self.send_ev(TraceePayload::Batch { batch });
    }

    const BATCH_SIZE: usize = 512;
    // const BATCH_SIZE: usize = 128;
    // const BATCH_SIZE: usize = 16;

    fn accumulate(&mut self, range: Range<usize>, state: MemState) {
        if self.batch_size > Self::BATCH_SIZE {
            self.flush();
        }

        self.batch.insert(range, state);
        self.batch_size += 1;
    }

    fn register(&mut self, range: &Range<usize>) {
        if let Some(uffd) = &self.uffd {
            let _ = uffd.register(range.start as _, range.end - range.start);
        }
    }
}

fn relay(ev_rx: mpsc::Receiver<MeviEvent>, mut payload_tx: broadcast::Sender<Vec<u8>>) {
    let mut tracees: HashMap<TraceeId, TraceeState> = Default::default();
    let interval = Duration::from_millis(16 * 3);

    loop {
        let mut first = true;
        let ev = loop {
            if first {
                match ev_rx.recv_timeout(interval) {
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
                break ev_rx.recv().unwrap();
            }
        };
        debug!("{:?}", ev.blue());

        let (tid, payload) = match ev {
            MeviEvent::Snapshot(mut snap_tracees) => {
                for tracee in tracees.values_mut() {
                    tracee.flush();
                    snap_tracees.push(TraceeSnapshot {
                        tid: tracee.tid,
                        cmdline: tracee.cmdline.clone(),
                        map: tracee.map.clone(),
                    });
                }
                _ = payload_tx
                    .blocking_send(bincode::serialize(&MeviEvent::Snapshot(snap_tracees)).unwrap());
                continue;
            }
            MeviEvent::TraceeEvent(tid, ev) => (tid, ev),
        };

        let tracee = tracees.entry(tid).or_insert_with(|| {
            let cmdline: Vec<String> = std::fs::read_to_string(format!("/proc/{}/cmdline", tid.0))
                .unwrap_or_default()
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned())
                .collect();

            let ev = MeviEvent::TraceeEvent(
                tid,
                TraceePayload::Start {
                    cmdline: cmdline.clone(),
                },
            );
            _ = payload_tx.blocking_send(bincode::serialize(&ev).unwrap());

            TraceeState {
                tid,
                cmdline,
                map: Default::default(),
                batch: Default::default(),
                batch_size: 0,
                uffd: None,
                w_tx: payload_tx.clone(),
            }
        });

        match &payload {
            TraceePayload::PageIn { range } => tracee.accumulate(range.clone(), MemState::Resident),
            TraceePayload::PageOut { range } => {
                tracee.accumulate(range.clone(), MemState::NotResident)
            }
            payload => {
                tracee.flush();
                tracee.send_ev(payload.clone());
            }
        };

        match payload {
            TraceePayload::Map { range, state, .. } => {
                tracee.register(&range);
                tracee.map.insert(range, state);
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
            TraceePayload::Batch { .. } => {
                unreachable!()
            }
            TraceePayload::Start { .. } => {
                unreachable!()
            }
            TraceePayload::Exit => {
                tracees.remove(&tid);
            }
        }
    }
}

#[derive(Clone)]
struct RouterState {
    payload_tx: broadcast::Sender<Vec<u8>>,
    ev_tx: mpsc::SyncSender<MeviEvent>,
}

async fn stream(State(rs): State<RouterState>, upgrade: WebSocketUpgrade) -> impl IntoResponse {
    upgrade.on_upgrade(move |ws| {
        let payload_rx = rs.payload_tx.subscribe();
        _ = rs.ev_tx.send(MeviEvent::Snapshot(vec![]));
        handle_ws(payload_rx, ws)
    })
}

async fn handle_ws(mut payload_rx: broadcast::Receiver<Vec<u8>>, mut ws: WebSocket) {
    loop {
        let payload = payload_rx.recv().await.unwrap();
        ws.send(Message::Binary(payload)).await.unwrap();
    }
}
