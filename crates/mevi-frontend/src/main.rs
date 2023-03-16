use std::{collections::HashMap, ops::Range};

use futures_util::StreamExt;
use gloo_net::websocket::{futures::WebSocket, Message};
use humansize::{make_format, BINARY};
use instant::{Duration, Instant};
use itertools::Itertools;
use mevi_common::{MemMap, MemState, MeviEvent, TraceeId, TraceePayload};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

struct Group {
    start: u64,
    size: u64,
    ranges: Vec<(Range<u64>, MemState)>,
}

#[derive(Clone)]
struct TraceeState {
    tid: TraceeId,
    map: MemMap,
    cmdline: Vec<String>,
}

impl TraceeState {
    fn total_rss(&self) -> u64 {
        self.map
            .iter()
            .map(|(range, state)| {
                if state == &MemState::Resident {
                    range.end - range.start
                } else {
                    0
                }
            })
            .sum()
    }
}

async fn connect_to_ws() -> WebSocket {
    let addr = "ws://localhost:5001/stream";
    gloo_console::log!("Connecting to", addr);
    let mut ws = WebSocket::open(addr).unwrap();

    let mut counter = 0;
    loop {
        counter += 1;
        gloo_timers::future::sleep(std::time::Duration::from_millis(100)).await;
        match ws.state() {
            gloo_net::websocket::State::Connecting => {
                if counter > 20 {
                    ws.close(None, None).unwrap();
                    ws = WebSocket::open(addr).unwrap();
                    counter = 0;
                }
            }
            gloo_net::websocket::State::Open => {
                gloo_console::log!("Connected!");
                break;
            }
            gloo_net::websocket::State::Closing => {
                gloo_console::log!("Closing...");
                panic!("Closing");
            }
            gloo_net::websocket::State::Closed => {
                gloo_timers::future::sleep(std::time::Duration::from_secs(1)).await;
                ws = WebSocket::open(addr).unwrap();
                counter = 0;
            }
        }
    }

    ws
}

#[function_component(App)]
fn app() -> Html {
    let live = use_state(|| false);
    let tracees = use_state(|| -> HashMap<TraceeId, TraceeState> { Default::default() });

    {
        let tracees = tracees.clone();
        let live = live.clone();
        use_effect_with_deps(
            move |_| {
                let mut tracees_acc = HashMap::new();

                spawn_local(async move {
                    let mut last_flush = Instant::now();
                    let mut batch_size = 0;
                    let flush_every = Duration::from_millis(16);

                    let (mut _write, mut read) = connect_to_ws().await.split();
                    live.set(true);

                    while let Some(msg) = read.next().await {
                        let msg = match msg {
                            Ok(msg) => msg,
                            Err(e) => {
                                gloo_console::log!("Websocket error:", e.to_string());
                                live.set(false);

                                gloo_console::log!("Reconnecting...");
                                (_write, read) = connect_to_ws().await.split();
                                tracees_acc.clear();
                                tracees.set(tracees_acc.clone());
                                live.set(true);
                                continue;
                            }
                        };
                        live.set(true);
                        match msg {
                            Message::Text(t) => {
                                gloo_console::log!(format!("text message: {t}"));
                                if t == "flush" {
                                    tracees.set(tracees_acc.clone());
                                    last_flush = Instant::now();
                                    batch_size = 0;
                                }
                            }
                            Message::Bytes(b) => {
                                let ev: MeviEvent = bincode::deserialize(&b).unwrap();
                                // gloo_console::log!(format!("{:?}", ev));

                                apply_ev(&mut tracees_acc, ev);
                                batch_size += 1;
                                if last_flush.elapsed() > flush_every {
                                    gloo_console::log!(format!("flushing {} events", batch_size));
                                    tracees.set(tracees_acc.clone());
                                    last_flush = Instant::now();
                                    batch_size = 0;
                                }
                            }
                        }
                    }
                    gloo_console::log!("WebSocket Closed")
                })
            },
            (),
        );
    }

    let mut total_virt: u64 = 0;
    let mut total_res: u64 = 0;
    for (range, mem_state) in tracees.values().flat_map(|v| v.map.iter()) {
        total_virt += range.end - range.start;

        if *mem_state == MemState::Resident {
            total_res += range.end - range.start;
        }
    }

    let formatter = make_format(BINARY);
    html! {
        <>
            <div class="mem-stats-container">
                <span class="brand"><span>{"me"}</span><span class="brand-rest">{"vi"}</span></span>
                <span class="mem-stats rss"><span class="mem-square"></span><span class="name">{"RSS"}</span>{format!("{}", formatter(total_res))}</span>
                <span class="mem-stats virt"><span class="mem-square"></span><span class="name">{"VSZ"}</span>{format!("{}", formatter(total_virt))}</span>
                <span class={ if *live { "live-indicator live" } else { "live-indicator offline" } }>{ if *live { "LIVE" } else { "OFFLINE" } }</span>
            </div>
            {{
                tracees.values().sorted_by_key(|p| std::cmp::Reverse(p.total_rss())).map(|tracee| {
                    html! {
                        <>
                            <div class="process">
                                <div class="process-info">
                                    <span class="pid">{"PID "}{tracee.tid.0}</span>
                                    {{
                                        // collect virt/rss stats for process
                                        let mut virt: u64 = 0;
                                        let mut res: u64 = 0;
                                        for (range, mem_state) in tracee.map.iter() {
                                                virt += range.end - range.start;

                                            if *mem_state == MemState::Resident {
                                                res += range.end - range.start;
                                            }
                                        }
                                        html! {
                                            <>
                                                <span class="mem-stats rss"><span class="mem-square"></span><span>{format!("{}", formatter(res))}</span></span>
                                                <span class="mem-stats virt"><span class="mem-square"></span><span>{format!("{}", formatter(virt))}</span></span>
                                            </>
                                        }
                                    }}
                                    {
                                        tracee.cmdline.iter().map(|arg| {
                                            html! {
                                                <span class="arg">{arg}</span>
                                            }
                                        }).collect::<Html>()
                                    }
                                </div>
                                {{
                                    let map = &tracee.map;
                                    // let has_any_memory_resident = map.iter().any(|(_, state)| *state == MemState::Resident);
                                    let has_any_memory_resident = true;
                                    if !has_any_memory_resident {
                                        return html!{ };
                                    }

                                    let mut groups: Vec<Group> = vec![];
                                    // let threshold_new_group = 4 * 1024 * 1024;
                                    let threshold_new_group = 128 * 1024 * 1024;
                                    for (range, state) in map.iter() {
                                        if let Some(last_group) = groups.last() {
                                            if range.start - (last_group.start + last_group.size) > threshold_new_group || last_group.size >= 30 * 1024 * 1024 {
                                                groups.push(Group {
                                                    start: range.start,
                                                    size: range.end - range.start,
                                                    ranges: vec![
                                                        (range.clone(), *state)
                                                    ],
                                                });
                                            } else {
                                                let last_group = groups.last_mut().unwrap();
                                                last_group.ranges.push((range.clone(), *state));
                                                last_group.size = range.end - last_group.start;
                                            }
                                        } else {
                                            groups.push(Group {
                                                start: range.start,
                                                size: range.end - range.start,
                                                ranges: vec![
                                                    (range.clone(), *state)
                                                ],
                                            });
                                        }
                                    }

                                    let mut groups_markup = vec![];

                                    let mut last_group_end: Option<u64> = None;
                                    for group in groups {
                                        let mut group_markup = vec![];

                                        let mut max_bytes: u64 = 16 * 1024;
                                        while max_bytes < group.size {
                                            max_bytes *= 2;
                                        }
                                        let scale_ratio = 100.0 / (max_bytes as f64);
                                        let min_size_for_print = max_bytes / 16;

                                        for (range, mem_state) in group.ranges {
                                            let size = range.end - range.start;
                                            if size < 4 * 4096 {
                                                continue;
                                            }

                                            // avoid some allocations
                                            let state_class = |ms: MemState| -> &'static str {
                                                match ms {
                                                    MemState::Resident => "r",
                                                    MemState::NotResident => "n",
                                                    MemState::Untracked => "u",
                                                }
                                            };

                                            let style = format!("width:{}%;left:{}%;", size as f64 * scale_ratio, (range.start - group.start) as f64 * scale_ratio);
                                            let h = if size >= min_size_for_print {
                                                html! {
                                                    <i class={state_class(mem_state)} title={format!("{} at {:x?}", formatter(size), range)} style={style}>{
                                                        formatter(size).to_string()
                                                    }</i>
                                                }
                                            } else {
                                                html! {
                                                    <i class={state_class(mem_state)} style={style}></i>
                                                }
                                            };
                                            group_markup.push(h)
                                        }

                                        if !group_markup.is_empty() {
                                            groups_markup.push(html! {
                                                <>
                                                    {{
                                                        let mut gap = 0;
                                                        if let Some(last_group_end) = last_group_end {
                                                            gap = group.start - last_group_end;
                                                        }
                                                        if gap > 0 {
                                                            html! {
                                                                <div class="group-gap">
                                                                    { format!("{} gap", formatter(group.start - last_group_end.unwrap_or_default())) }
                                                                </div>
                                                            }
                                                        } else {
                                                            html! {}
                                                        }
                                                    }}
                                                    <div class="group-outer">
                                                        <div class="group-header">
                                                            <span>
                                                                { format!("{:x}", group.start) }
                                                            </span>
                                                            <span class="scale">
                                                                { format!("{} scale", formatter(max_bytes)) }
                                                            </span>
                                                        </div>
                                                        <div class="group">
                                                            { group_markup }
                                                        </div>
                                                    </div>
                                                </>
                                            });
                                        }

                                        last_group_end = Some(group.start + group.size);
                                    }

                                    groups_markup
                                }}
                            </div>
                        </>
                    }
                }).collect::<Vec<_>>()
            }}
        </>
    }
}

fn apply_ev(tracees: &mut HashMap<TraceeId, TraceeState>, ev: MeviEvent) {
    let (tid, payload) = match ev {
        MeviEvent::Snapshot(snap_tracees) => {
            for snap_tracee in snap_tracees {
                let tracee = tracees
                    .entry(snap_tracee.tid)
                    .or_insert_with(|| TraceeState {
                        tid: snap_tracee.tid,
                        map: Default::default(),
                        cmdline: Default::default(),
                    });
                tracee.cmdline = snap_tracee.cmdline;
                tracee.map = snap_tracee.map;
            }
            return;
        }
        MeviEvent::TraceeEvent(tid, ev) => (tid, ev),
    };

    let tracee = tracees.entry(tid).or_insert_with(|| TraceeState {
        tid,
        map: Default::default(),
        cmdline: Default::default(),
    });

    payload.apply_to_memmap(&mut tracee.map);
    match payload {
        TraceePayload::Start { cmdline } => {
            tracee.cmdline = cmdline;
        }
        TraceePayload::Exit { .. } => {
            tracees.remove(&tid);
        }
        _ => {
            // ignore
        }
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
