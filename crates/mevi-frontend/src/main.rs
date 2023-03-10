use std::{borrow::Cow, collections::HashMap, ops::Range};

use futures_util::StreamExt;
use gloo_net::websocket::{futures::WebSocket, Message};
use humansize::{make_format, BINARY};
use itertools::Itertools;
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

type MemMap = RangeMap<u64, IsResident>;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum IsResident {
    Yes,
    No,
    Unmapped,
}

#[derive(Debug, Serialize, Deserialize)]
enum TraceeEvent {
    Map {
        range: Range<u64>,
        resident: IsResident,
    },
    Connected {
        uffd: u64,
    },
    PageIn {
        range: Range<u64>,
    },
    PageOut {
        range: Range<u64>,
    },
    Unmap {
        range: Range<u64>,
    },
    Remap {
        old_range: Range<u64>,
        new_range: Range<u64>,
    },
    PageInAcc {
        range_map: MemMap,
    },
    PageOutAcc {
        range_map: MemMap,
    },
}

#[function_component(App)]
fn app() -> Html {
    let map = use_state(MemMap::default);
    {
        let map = map.clone();
        use_effect_with_deps(
            move |_| {
                let mut map_acc = MemMap::default();

                gloo_console::log!("Connecting to WebSocket...");
                let ws = WebSocket::open("ws://localhost:5001/ws").unwrap();
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
                                let msg: TraceeEvent = bincode::deserialize(&b).unwrap();
                                gloo_console::log!(format!("{:?}", msg));

                                match msg {
                                    TraceeEvent::Map { range, resident } => {
                                        map_acc.insert(range, resident);
                                    }
                                    TraceeEvent::Connected { .. } => {
                                        // ignore
                                    }
                                    TraceeEvent::PageIn { range } => {
                                        map_acc.insert(range, IsResident::Yes);
                                    }
                                    TraceeEvent::PageOut { range } => {
                                        map_acc.insert(range, IsResident::No);
                                    }
                                    TraceeEvent::Unmap { range } => {
                                        map_acc.insert(range, IsResident::Unmapped);
                                    }
                                    TraceeEvent::Remap {
                                        old_range,
                                        new_range,
                                    } => {
                                        map_acc.insert(old_range, IsResident::Unmapped);
                                        // FIXME: this is wrong but eh.
                                        map_acc.insert(new_range, IsResident::Yes);
                                    }
                                    TraceeEvent::PageInAcc { range_map } => {
                                        for (range, is_resident) in range_map.into_iter() {
                                            map_acc.insert(range, is_resident);
                                        }
                                    }
                                    TraceeEvent::PageOutAcc { range_map } => {
                                        for (range, is_resident) in range_map.into_iter() {
                                            map_acc.insert(range, is_resident);
                                        }
                                    }
                                }
                                map.set(map_acc.clone());
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
    for (range, is_resident) in map.iter() {
        if *is_resident != IsResident::Unmapped {
            total_virt += range.end - range.start;
        }

        if *is_resident == IsResident::Yes {
            total_res += range.end - range.start;
        }
    }

    let formatter = make_format(BINARY);
    html! {
        <>
            <div>
                <div>
                    <span class="mem-stats">{format!("VIRT: {}", formatter(total_virt))}</span>
                    <span class="mem-stats rss">{format!("RSS: {}", formatter(total_res))}</span>
                </div>
                {{
                    let groups = map.iter().group_by(|(range, _is_resident)| (range.start >> 40));
                    let mut group_sizes = HashMap::new();
                    for (key, group) in groups.into_iter() {
                        let mut group_start: Option<u64> = None;
                        let mut group_end: Option<u64> = None;
                        for (range, _is_resident) in group {
                            if group_start.is_none() {
                                group_start = Some(range.start);
                            }
                            group_end = Some(range.end);
                        }
                        let size = group_end.unwrap() - group_start.unwrap();
                        group_sizes.insert(key, size);
                    }

                    let largest_group = group_sizes.values().copied().max().unwrap_or_default();
                    let mut max_mb: u64 = 4 * 1024 * 1024;
                    while max_mb < largest_group {
                        max_mb *= 2;
                    }
                    let max_mb = max_mb as f64;

                    let groups = map.iter().group_by(|(range, _is_resident)| (range.start >> 40));
                    groups.into_iter().map(
                        |(key, group)| {
                            let mut group_markup = vec![];
                            let mut group_start = None;

                            for (range, is_resident) in group {
                                if group_start.is_none() {
                                    group_start = Some(range.start);
                                }

                                let size = range.end - range.start;
                                if size < 4 * 4096 {
                                    continue;
                                }

                                if matches!(is_resident, IsResident::Unmapped) {
                                    continue;
                                }

                                let style = format!("width: {}%; left: {}%;", size as f64 / max_mb * 100.0, (range.start - group_start.unwrap()) as f64 / max_mb * 100.0);
                                group_markup.push(html! {
                                    <i class={format!("{:?}", is_resident)} style={style}>{
                                        if matches!(is_resident, IsResident::Yes) && size > 4 * 1024 * 1024 {
                                            Cow::from(formatter(size).to_string())
                                        } else {
                                            Cow::from("")
                                        }
                                    }</i>
                                })
                            }

                            html! {
                                <>
                                    <div class="group_header" style="display: block;">
                                        { format!("{:#x}...", key) }
                                    </div>
                                    <div class="group">
                                        { group_markup }
                                    </div>
                                </>
                            }
                        }
                    ).collect::<Vec<_>>()
                }}
            </div>
        </>
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
