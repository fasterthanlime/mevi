use std::{
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
enum IsResident {
    Yes,
    No,
    Unmapped,
}

type MemMap = RangeMap<usize, IsResident>;

const SOCK_PATH: &str = "/tmp/mevi.sock";

enum Acc {
    PageIn { range_map: MemMap, count: usize },
    PageOut { range_map: MemMap, count: usize },
}

#[derive(Debug, Serialize, Deserialize)]
enum TraceeEvent {
    Map {
        range: Range<usize>,
        resident: IsResident,
        #[serde(skip)]
        _tx: Option<mpsc::Sender<()>>,
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
    PageInAcc {
        range_map: MemMap,
    },
    PageOutAcc {
        range_map: MemMap,
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

fn relay(rx: mpsc::Receiver<TraceeEvent>, mut w_tx: broadcast::Sender<Vec<u8>>) {
    let mut child_uffd: Option<Uffd> = None;

    let mut map: MemMap = Default::default();
    let mut acc: Option<Acc> = None;

    let interval = Duration::from_millis(150);

    let send_ev = |w_tx: &mut broadcast::Sender<Vec<u8>>, ev: &TraceeEvent| {
        let payload = bincode::serialize(&ev).unwrap();
        _ = w_tx.blocking_send(payload);
    };

    let flush_acc = |w_tx: &mut broadcast::Sender<Vec<u8>>, acc: &mut Option<Acc>| {
        if let Some(acc) = acc.take() {
            send_ev(
                w_tx,
                &match acc {
                    Acc::PageIn { range_map, .. } => TraceeEvent::PageInAcc { range_map },
                    Acc::PageOut { range_map, .. } => TraceeEvent::PageOutAcc { range_map },
                },
            )
        }
    };

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
                flush_acc(&mut w_tx, &mut acc);
                break rx.recv().unwrap();
            }
        };
        debug!("{:?}", ev.blue());

        const COALESCE_THRESHOLD: usize = 128;

        match &ev {
            TraceeEvent::PageIn { range } => match acc.as_mut() {
                Some(Acc::PageIn { range_map, count }) if *count < COALESCE_THRESHOLD => {
                    range_map.insert(range.clone(), IsResident::Yes);
                    *count += 1;
                }
                _ => {
                    flush_acc(&mut w_tx, &mut acc);
                    acc = Some(Acc::PageIn {
                        range_map: {
                            let mut range_map = MemMap::default();
                            range_map.insert(range.clone(), IsResident::Yes);
                            range_map
                        },
                        count: 1,
                    });
                }
            },
            TraceeEvent::PageOut { range } => match acc.as_mut() {
                Some(Acc::PageOut { range_map, count }) if *count < COALESCE_THRESHOLD => {
                    range_map.insert(range.clone(), IsResident::No);
                    *count += 1;
                }
                _ => {
                    flush_acc(&mut w_tx, &mut acc);
                    acc = Some(Acc::PageOut {
                        range_map: {
                            let mut range_map = MemMap::default();
                            range_map.insert(range.clone(), IsResident::No);
                            range_map
                        },
                        count: 1,
                    });
                }
            },
            _ => {
                flush_acc(&mut w_tx, &mut acc);
                send_ev(&mut w_tx, &ev);
            }
        };

        match ev {
            TraceeEvent::Map {
                range, resident, ..
            } => {
                if let Some(uffd) = child_uffd.as_ref() {
                    uffd.register(range.start as _, range.end - range.start)
                        .unwrap();
                }
                map.insert(range, resident);
            }
            TraceeEvent::Connected { uffd } => {
                child_uffd.replace(unsafe { Uffd::from_raw_fd(uffd) });
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
