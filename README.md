# Leptos WebTransport Crate

Welcome to the `leptos_webtransport` crate! 🚀 This Rust crate provides WebTransport functionality for the leptos framework.

## Overview

WebTransport is a modern web standard that enables bidirectional communication between a client and a server over a single, multiplexed connection. This crate aims to make it easy for developers using the leptos framework to integrate and leverage WebTransport in their applications.

## Features

- **Easy Integration:** Seamlessly integrate WebTransport into your leptos-based projects.
- **Bidirectional Communication:** Leverage the power of bidirectional communication for efficient data exchange.
- **Multiplexed Connections:** Benefit from a single, multiplexed connection for improved performance.

## Getting Started

To use `leptos_webtransport` in your project, add the following to your `Cargo.toml` file:

```sh
cargo add leptos_webtransport
```

```rust
use js_sys::Uint8Array;
use leptos::{
    html::{Input, Textarea},
    *,
};
use leptos_webtransport::{WebTransportService, WebTransportStatus, WebTransportTask};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use std::sync::Arc;
use web_sys::SubmitEvent;

pub const ECHO_URL: &str = "";

#[component]
pub fn WebtransportDemo() -> impl IntoView {
    let (data, set_data) = create_signal(String::new());
    let (url, set_url) = create_signal(ECHO_URL.to_string());
    let url_input_element: NodeRef<Input> = create_node_ref();
    let (connect, set_connect) = create_signal(false);
    let (status, set_status) = create_signal(WebTransportStatus::Closed);
    let (transport, set_transport) = create_signal::<Arc<Option<WebTransportTask>>>(Arc::new(None));
    let datagrams = create_rw_signal(create_signal::<Vec<u8>>(Vec::new()).0);
    let unidirectional_streams = create_rw_signal(create_signal::<Option<_>>(None).0);
    let bidirectional_streams = create_rw_signal(create_signal::<Option<_>>(None).0);
    let (bidirectional_streams_from_client, set_bidirectional_streams_from_client) = create_signal::<Vec<u8>>(Vec::new());

    let on_submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let value = url_input_element()
            .expect("<input> to exist")
            .value();
        let connected = connect.get_untracked();
        if !connected {
            if let Ok(t) = WebTransportService::connect(&value) {
                datagrams.set(t.datagram.clone());
                unidirectional_streams.set(t.unidirectional_stream.clone());
                bidirectional_streams.set(t.bidirectional_stream.clone());
                set_status(t.status.get());
                set_transport(Arc::new(Some(t)));
            }
        } else {
            if let Some(t) = transport.get_untracked().as_ref() {
                t.close();
            }
            set_status(WebTransportStatus::Closed);
            set_transport(Arc::new(None));
        }
        set_connect(!connect.get_untracked());
        set_url(value.clone());
    };
    let text_area_element: NodeRef<Textarea> = create_node_ref();

    let send_data = move |ev: SubmitEvent| {
        ev.prevent_default();
        let value = text_area_element()
            .expect("<textarea> to exist")
            .value();
        set_data(value.clone());
        if let Some(t) = transport.get_untracked().as_ref() {
            let method = ev
                .target()
                .expect("event target")
                .unchecked_into::<web_sys::HtmlFormElement>()
                .elements()
                .named_item("method")
                .expect("method")
                .unchecked_into::<web_sys::HtmlInputElement>()
                .value();
            logging::log!("method: {}", method);

            match method.as_str() {
                "send_datagram" => {
                    WebTransportTask::send_datagram(t.transport.clone(), value.as_bytes().to_vec());
                }
                "send_undirectional_stream" => {
                    WebTransportTask::send_unidirectional_stream(t.transport.clone(), value.as_bytes().to_vec());
                }
                "send_bidirectional_stream" => {
                    WebTransportTask::send_bidirectional_stream(t.transport.clone(), value.as_bytes().to_vec(), set_bidirectional_streams_from_client.clone());
                }
                _ => {}
            }
        }
    };

    create_effect(move |_| {
        if let Some(t) = transport.get().as_ref() {
            let status = t.status.get();
            set_status(status.clone());
            match status {
                WebTransportStatus::Closed => {
                    logging::log!("WebTransportStatus Connection closed");
                }
                WebTransportStatus::Connecting => {
                    logging::log!("WebTransportStatus Connecting...");
                }
                WebTransportStatus::Opened => {
                    logging::log!("WebTransportStatus Connection opened");
                }
                WebTransportStatus::Error => {
                    logging::error!("WebTransportStatus Connection error");
                }
            }
        }
    });

    create_effect(move |_| {
        let datagram= datagrams.get().get();
        let s = String::from_utf8(datagram).unwrap();
        logging::log!("Received datagram: {}", s);
    });

    create_effect(move |_| {
        let Some(stream) = unidirectional_streams.get().get() else {
            logging::log!("No unidirectional stream");
            return;
        };
        let reader = stream.get_reader().unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        let c = Closure::new(|result: JsValue| {
            let done = js_sys::Reflect::get(&result, &JsValue::from_str("done")).unwrap().as_bool().unwrap();
            let value = js_sys::Reflect::get(&result, &JsValue::from_str("value")).unwrap().unchecked_into::<Uint8Array>();
            if done {
                logging::log!("Unidirectional stream closed");
            }
            let value = js_sys::Uint8Array::new(&value);
            let s = String::from_utf8(value.to_vec()).unwrap();
            logging::log!("Received unidirectional stream: {}", s);
        });
        let catch = Closure::new(|e: JsValue| {
            logging::error!("Error reading unidirectional stream: {:?}", e);
        });
        let _ = reader.read().then(&c).catch(&catch);
        c.forget();
        catch.forget();
    });

    view! {
        <form on:submit=on_submit>
            <input type="text" value=url node_ref=url_input_element/>
            <input
                type="submit"
                value=move || { if connect.get() { "Disconnect" } else { "Connect" } }
            />
        </form>
        <h2>{move || { format!("WebTransport Status: {:?}", status.get()) }}
        </h2>
        <form on:submit=send_data>
            <textarea value=data node_ref=text_area_element></textarea>
            <input type="submit" value="Send Data"/>
            <input type="radio" name="method" value="send_datagram" checked=true/>
            <label for="send_data">Send Datagram</label>
            <input type="radio" name="method" value="send_undirectional_stream"/>
            <label for="send_stream">Send Unidirectional Stream</label>
            <input type="radio" name="method" value="send_bidirectional_stream"/>
            <label for="send_datagram">Send Bidirectional Stream</label>
        </form>
        <div>
            <h2>Received Data</h2>
            <div>
                <textarea value=data readonly=true></textarea>
            </div>
        </div>
    }
}
```

## Contributing

We welcome contributions from the community! If you find a bug or have an idea for a new feature, please open an issue or submit a pull request.

## License

This crate is distributed under the terms of the MIT license. See the [LICENSE](LICENSE) file for details.

Happy coding! 🦀
