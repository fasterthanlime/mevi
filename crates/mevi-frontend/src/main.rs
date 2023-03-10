use std::ops::Range;

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
                                        map.set(map_acc.clone());
                                    }
                                    TraceeEvent::Connected { .. } => {
                                        // ignore
                                    }
                                    TraceeEvent::PageIn { range } => {
                                        map_acc.insert(range, IsResident::Yes);
                                        map.set(map_acc.clone());
                                    }
                                    TraceeEvent::PageOut { range } => {
                                        map_acc.insert(range, IsResident::No);
                                        map.set(map_acc.clone());
                                    }
                                    TraceeEvent::Unmap { range } => {
                                        map_acc.remove(range);
                                        map.set(map_acc.clone());
                                    }
                                    TraceeEvent::Remap {
                                        old_range,
                                        new_range,
                                    } => {
                                        map_acc.remove(old_range);
                                        // FIXME: this is wrong but eh.
                                        map_acc.insert(new_range, IsResident::Yes);
                                        map.set(map_acc.clone());
                                    }
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
    for (range, is_resident) in map.iter() {
        total_virt += range.end - range.start;
        if *is_resident == IsResident::Yes {
            total_res += range.end - range.start;
        }
    }

    let formatter = make_format(BINARY);
    html! {
        <>
            <h1>{ "Memory maps" }</h1>
            <ul style="font-family: monospace;">
                <li>
                    { format!("VIRT: {}, RSS: {}", formatter(total_virt), formatter(total_res)) }
                </li>
                {{
                    let groups = map.iter().group_by(|(range, _is_resident)| (range.start >> 24));
                    groups.into_iter().map(
                        |(key, group)| {
                            let group_markup = group.map(
                                |(range, is_resident)| {
                                    html! {
                                        <li>{
                                            format!("{:#x}..{:#x} ({}, {})", range.start, range.end, match is_resident  {
                                                IsResident::Yes => "resident",
                                                IsResident::No => "not resident",
                                            }, formatter(range.end - range.start))
                                        }</li>
                                    }
                                }
                            ).collect::<Vec<_>>();

                            html! {
                                <li>
                                    <h2>{ format!("{:#x}...", key) }</h2>
                                    <ul>
                                        { group_markup }
                                    </ul>
                                </li>
                            }
                        }
                    ).collect::<Vec<_>>()
                }}
            </ul>
        </>
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
