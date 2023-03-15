use std::{borrow::Cow, collections::HashMap, ops::Range};

use futures_util::StreamExt;
use gloo_net::websocket::{futures::WebSocket, Message};
use humansize::{make_format, BINARY};
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
        total_virt += range.end - range.start;

        if *mem_state == MemState::Resident {
            total_res += range.end - range.start;
        }
    }

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
                                                virt += range.end - range.start;

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

                                    let mut groups: Vec<Group> = vec![];
                                    let threshold_new_group = 4 * 1024 * 1024;
                                    for (range, state) in map.iter() {
                                        if let Some(last_group) = groups.last() {
                                            if (last_group.start + last_group.size) - range.start > threshold_new_group || last_group.size >= 30 * 1024 * 1024 {
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

                                        let mut max_mb: u64 = 16 * 1024;
                                        while max_mb < group.size {
                                            max_mb *= 2;
                                        }
                                        let max_mb_f = max_mb as f64;

                                        for (range, mem_state) in group.ranges {
                                            let size = range.end - range.start;
                                            if size < 4 * 4096 {
                                                continue;
                                            }

                                            let style = format!("width: {}%; left: {}%;", size as f64 / max_mb_f * 100.0, (range.start - group.start) as f64 / max_mb_f * 100.0);
                                            group_markup.push(html! {
                                                <i class={format!("{:?}", mem_state)} title={format!("{} at {:x?}", formatter(size), range)} style={style}>{
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
                                                                { format!("{} scale", formatter(max_mb)) }
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
