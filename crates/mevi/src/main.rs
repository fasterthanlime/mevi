use std::{collections::HashMap, os::unix::net::UnixListener, sync::mpsc, time::Duration};

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
use postage::{broadcast, sink::Sink, stream::Stream};
use tokio::time::Instant;
use tracer::Tracer;
use tracing::debug;
use tracing_subscriber::EnvFilter;

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

    std::thread::spawn(move || Tracer::new(tx2, listener).unwrap().run().unwrap());

    let (payload_tx, _) = broadcast::channel(16);

    let rs = RouterState {
        payload_tx: payload_tx.clone(),
        ev_tx: tx.clone(),
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
    w_tx: broadcast::Sender<MeviEvent>,
}

impl TraceeState {
    fn send_ev(&mut self, payload: TraceePayload) {
        let ev = MeviEvent::TraceeEvent(self.tid, payload);
        _ = self.w_tx.blocking_send(ev);
    }
}

fn relay(ev_rx: mpsc::Receiver<MeviEvent>, mut payload_tx: broadcast::Sender<MeviEvent>) {
    let mut tracees: HashMap<TraceeId, TraceeState> = Default::default();

    loop {
        let ev = ev_rx.recv().unwrap();
        debug!("{:?}", ev);

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

        let tracee = tracees.entry(tid).or_insert_with(|| TraceeState {
            tid,
            cmdline: Default::default(),
            map: Default::default(),
            w_tx: payload_tx.clone(),
        });

        payload.apply_to_memmap(&mut tracee.map);
        tracee.send_ev(payload.clone());

        match payload {
            TraceePayload::Exit => {
                if let Some(tracee) = tracees.get(&tid) {
                    let mut total_vsz = 0;
                    let mut total_rss = 0;
                    for (range, state) in tracee.map.iter() {
                        let size = range.end - range.start;
                        total_vsz += size;
                        if let MemState::Resident = state {
                            total_rss += size;
                        }
                    }
                    let formatter = make_format(BINARY);
                    tracing::warn!(
                        "{tid} exiting with {} vsz, {} rss, cmdline was {:?}",
                        formatter(total_vsz),
                        formatter(total_rss),
                        tracee.cmdline,
                    );
                }

                tracees.remove(&tid);
            }
            TraceePayload::CmdLineChange { cmdline } => {
                tracee.cmdline = cmdline;
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
