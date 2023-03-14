use std::{borrow::Cow, collections::HashMap};

use futures_util::StreamExt;
use gloo_net::websocket::{futures::WebSocket, Message};
use humansize::{make_format, BINARY};
use itertools::Itertools;
use mevi_common::{MemMap, MemState, MeviEvent, TraceeId, TraceePayload};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

struct GroupInfo {
    start: u64,
    size: u64,
}

#[derive(Clone)]
struct TraceeState {
    tid: TraceeId,
    map: MemMap,
    cmdline: Vec<String>,
}

#[function_component(App)]
fn app() -> Html {
    let tracees = use_state(|| -> HashMap<TraceeId, TraceeState> { Default::default() });

    {
        let tracees = tracees.clone();
        use_effect_with_deps(
            move |_| {
                let mut tracees_acc = HashMap::new();

                gloo_console::log!("Connecting to WebSocket...");
                let ws = WebSocket::open("ws://localhost:5001/stream").unwrap();
                gloo_console::log!("Connected to WebSocket");
                let (write, mut read) = ws.split();
                drop(write);

                spawn_local(async move {
                    while let Some(msg) = read.next().await {
                        let msg = msg.unwrap();
                        match msg {
                            Message::Text(t) => {
                                gloo_console::log!(format!("text message: {t}"))
                            }
                            Message::Bytes(b) => {
                                let ev: MeviEvent = bincode::deserialize(&b).unwrap();
                                // gloo_console::log!(format!("{:?}", ev));

                                apply_ev(&mut tracees_acc, ev);
                                tracees.set(tracees_acc.clone());
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
        if *mem_state != MemState::Unmapped {
            total_virt += range.end - range.start;
        }

        if *mem_state == MemState::Resident {
            total_res += range.end - range.start;
        }
    }

    // const KEY_SHR: u64 = 40;
    // const KEY_SHR: u64 = 32;
    // const KEY_SHR: u64 = 30;
    const KEY_SHR: u64 = 24;

    let formatter = make_format(BINARY);
    html! {
        <>
            <div class="mem-stats-container">
                <span class="mem-stats virt"><span class="name">{"Virtual"}</span>{format!("{}", formatter(total_virt))}</span>
                <span class="mem-stats rss"><span class="name">{"Resident"}</span>{format!("{}", formatter(total_res))}</span>
            </div>
            {{
                tracees.values().map(|tracee| {
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
                                            if *mem_state != MemState::Unmapped {
                                                virt += range.end - range.start;
                                            }

                                            if *mem_state == MemState::Resident {
                                                res += range.end - range.start;
                                            }
                                        }
                                        html! {
                                            <>
                                                <span class="mem-stats virt"><span>{format!("{}", formatter(virt))}</span></span>
                                                <span class="mem-stats rss"><span>{format!("{}", formatter(res))}</span></span>
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

                                    let groups = map.iter().group_by(|(range, _)| (range.start >> KEY_SHR));
                                    let mut group_infos = HashMap::new();
                                    for (key, group) in groups.into_iter() {
                                        let mut group_start: Option<u64> = None;
                                        let mut group_end: Option<u64> = None;
                                        for (range, _state) in group {
                                            if group_start.is_none() {
                                                group_start = Some(range.start);
                                            }

                                            group_end = Some(range.end);
                                        }
                                        let size = group_end.unwrap() - group_start.unwrap();
                                        group_infos.insert(key, GroupInfo {
                                            start: group_start.unwrap(),
                                            size,
                                        });
                                    }

                                    let groups = map.iter().group_by(|(range, _)| (range.start >> KEY_SHR));
                                    let mut groups_markup = vec![];

                                    for (key, group) in groups.into_iter() {
                                        let mut group_markup = vec![];
                                        let mut group_start = None;
                                        let group_info = &group_infos[&key];

                                        let mut max_mb: u64 = 16 * 1024;
                                        while max_mb < group_info.size {
                                            max_mb *= 2;
                                        }
                                        let max_mb_f = max_mb as f64;

                                        for (range, mem_state) in group {
                                            if group_start.is_none() {
                                                group_start = Some(range.start);
                                            }

                                            let size = range.end - range.start;
                                            if size < 4 * 4096 {
                                                continue;
                                            }

                                            let style = format!("width: {}%; left: {}%;", size as f64 / max_mb_f * 100.0, (range.start - group_start.unwrap()) as f64 / max_mb_f * 100.0);
                                            group_markup.push(html! {
                                                <i class={format!("{:?}", mem_state)} title={formatter(size).to_string()} style={style}>{
                                                    // if size > 4 * 1024 * 1024 {
                                                    if size > 128 * 1024 {
                                                        Cow::from(formatter(size).to_string())
                                                    } else {
                                                        Cow::from("")
                                                    }
                                                }</i>
                                            })
                                        }

                                        if !group_markup.is_empty() {
                                            groups_markup.push(html! {
                                                <div class="group-outer">
                                                    <div class="group-header">
                                                        <span>
                                                            { format!("{:x}", group_infos[&key].start) }
                                                        </span>
                                                        <span class="scale">
                                                            { format!("{} scale", formatter(max_mb)) }
                                                        </span>
                                                    </div>
                                                    <div class="group">
                                                        { group_markup }
                                                    </div>
                                                </div>
                                            });
                                        }
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
