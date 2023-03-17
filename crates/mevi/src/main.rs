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
use color_eyre::Result;
use humansize::{make_format, BINARY};
use mevi_common::{MemMap, MemState, MeviEvent, TraceeId, TraceePayload, TraceeSnapshot};
use owo_colors::OwoColorize;
use postage::{broadcast, sink::Sink, stream::Stream};
use tokio::time::Instant;
use tracing::{debug, warn};
use tracing_subscriber::EnvFilter;
use userfaultfd::Uffd;

mod tracer;
mod userfault;

const SOCK_PATH: &str = "/tmp/mevi.sock";

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

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
    uffd: Option<Uffd>,
    w_tx: broadcast::Sender<MeviEvent>,
    printed_uffd_warning: bool,
}

impl TraceeState {
    fn send_ev(&mut self, payload: TraceePayload) {
        let ev = MeviEvent::TraceeEvent(self.tid, payload);
        _ = self.w_tx.blocking_send(ev);
    }

    fn register(&mut self, range: &Range<u64>, state: MemState) {
        let mut could_register = false;

        if let Some(uffd) = &self.uffd {
            if let Err(e) = uffd.register(range.start as _, (range.end - range.start) as _) {
                warn!(
                    "{} failed to register range {range:x?} {state:?}: {e}",
                    self.tid
                );
            } else {
                could_register = true;
            }
        }

        if could_register {
            self.map.insert(range.clone(), state);
        } else {
            if !self.printed_uffd_warning {
                self.printed_uffd_warning = true;
                warn!(
                    "{} no uffd, can't register range {range:x?} {state:?}",
                    self.tid
                );
            }

            self.map.insert(range.clone(), MemState::Untracked);
            self.send_ev(TraceePayload::MemStateChange {
                range: range.clone(),
                state: MemState::Untracked,
            });
        }
    }
}

fn relay(ev_rx: mpsc::Receiver<MeviEvent>, mut payload_tx: broadcast::Sender<MeviEvent>) {
    let mut tracees: HashMap<TraceeId, TraceeState> = Default::default();

    loop {
        let ev = ev_rx.recv().unwrap();
        debug!("{:?}", ev.blue());

        let (tid, payload) = match ev {
            MeviEvent::Snapshot(mut snap_tracees) => {
                for tracee in tracees.values_mut() {
                    snap_tracees.push(TraceeSnapshot {
                        tid: tracee.tid,
                        cmdline: tracee.cmdline.clone(),
                        map: tracee.map.clone(),
                    });
                }
                _ = payload_tx.blocking_send(MeviEvent::Snapshot(snap_tracees));
                continue;
            }
            MeviEvent::TraceeEvent(tid, ev) => (tid, ev),
        };

        let tracee = tracees.entry(tid).or_insert_with(|| {
            let cmdline = get_cmdline(tid);
            let ev = MeviEvent::TraceeEvent(
                tid,
                TraceePayload::CmdLineChange {
                    cmdline: cmdline.clone(),
                },
            );
            _ = payload_tx.blocking_send(ev);

            TraceeState {
                tid,
                cmdline,
                map: Default::default(),
                uffd: None,
                w_tx: payload_tx.clone(),
                printed_uffd_warning: false,
            }
        });

        payload.apply_to_memmap(&mut tracee.map);
        tracee.send_ev(payload.clone());

        match payload {
            TraceePayload::Map { range, state, .. } => {
                tracee.register(&range, state);
            }
            TraceePayload::Connected { source, uffd } => {
                if let Some(prev_uffd) = tracee.uffd.as_ref() {
                    warn!(
                        "{} already has uffd {:?}, not using {:?} from {source:?}",
                        tracee.tid, prev_uffd, uffd
                    );
                } else {
                    tracee.uffd = Some(unsafe { Uffd::from_raw_fd(uffd as RawFd) });
                    debug!(
                        "{} connected to uffd {:?} from {source:?}",
                        tracee.tid, uffd
                    );
                }
            }
            TraceePayload::Exec => {
                debug!("{} just execve'd, clearing uffd", tracee.tid);
                tracee.uffd = None;
                // map is cleared by apply_to_memmap

                // update cmdline while we're at it
                let cmdline = get_cmdline(tracee.tid);
                tracee.cmdline = cmdline.clone();
                tracee.send_ev(TraceePayload::CmdLineChange { cmdline });
            }
            TraceePayload::Remap {
                old_range,
                new_range,
                _guard,
            } => {
                let formatter = make_format(BINARY);
                debug!(
                    "remap: ({}) {old_range:x?} => ({}) {new_range:x?}",
                    formatter(old_range.end - old_range.start),
                    formatter(new_range.end - new_range.start),
                );
            }
            TraceePayload::CmdLineChange { .. } => {
                unreachable!()
            }
            TraceePayload::Exit => {
                tracees.remove(&tid);
            }
            _ => {
                // ignore
            }
        }
    }
}

#[derive(Clone)]
struct RouterState {
    payload_tx: broadcast::Sender<MeviEvent>,
    ev_tx: mpsc::SyncSender<MeviEvent>,
}

async fn stream(State(rs): State<RouterState>, upgrade: WebSocketUpgrade) -> impl IntoResponse {
    upgrade.on_upgrade(move |ws| {
        let payload_rx = rs.payload_tx.subscribe();
        _ = rs.ev_tx.send(MeviEvent::Snapshot(vec![]));
        handle_ws(payload_rx, ws)
    })
}

async fn handle_ws(mut payload_rx: broadcast::Receiver<MeviEvent>, mut ws: WebSocket) {
    // let interval = Duration::from_millis(16);
    let interval = Duration::from_millis(32);
    let mut next_flush = Instant::now() + interval;
    let mut queue = vec![];

    loop {
        match tokio::time::timeout_at(next_flush, payload_rx.recv()).await {
            Ok(ev) => {
                let ev = ev.unwrap();
                queue.push(ev);
            }
            Err(_elapsed) => {
                if !queue.is_empty() {
                    ws.send(Message::Binary(
                        mevi_common::serialize_many(&queue[..]).unwrap(),
                    ))
                    .await
                    .unwrap();
                    queue.clear();
                }
                next_flush += interval;
            }
        };
    }
}

pub(crate) fn get_cmdline(tid: TraceeId) -> Vec<String> {
    std::fs::read_to_string(format!("/proc/{}/cmdline", tid.0))
        .unwrap_or_default()
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .collect()
}
