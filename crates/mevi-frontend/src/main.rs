use std::ops::Range;

use futures_util::StreamExt;
use gloo_net::websocket::{futures::WebSocket, Message};
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

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
    html! {
        <h1>{ "Hello World" }</h1>
    }
}

fn main() {
    yew::Renderer::<App>::new().render();

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
                    gloo_console::log!(format!("{:?}", msg))
                }
            }
        }
        gloo_console::log!("WebSocket Closed")
    })
}
