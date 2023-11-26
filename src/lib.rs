//! A service to connect to a server through the
//! [`WebTransport` Protocol](https://datatracker.ietf.org/doc/draft-ietf-webtrans-overview/).

/**
MIT License

Copyright (c) 2023 Security Union

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
use anyhow::{anyhow, Error};
use leptos::{create_signal, ReadSignal, SignalGet, SignalUpdate, WriteSignal};
use std::{fmt, rc::Rc};
use thiserror::Error as ThisError;
use wasm_bindgen_futures::JsFuture;

use js_sys::{Boolean, JsString, Promise, Reflect, Uint8Array};
use wasm_bindgen::{prelude::Closure, JsCast, JsValue};
use web_sys::{
    ReadableStream, ReadableStreamDefaultReader, WebTransport, WebTransportBidirectionalStream,
    WebTransportCloseInfo, WebTransportDatagramDuplexStream, WebTransportReceiveStream,
    WritableStream,
};

/// Represents formatting errors.
#[derive(Debug, ThisError)]
pub enum FormatError {
    /// Received text for a binary format, e.g. someone sending text
    /// on a WebTransport that is using a binary serialization format, like Cbor.
    #[error("received text for a binary format")]
    ReceivedTextForBinary,
    /// Received binary for a text format, e.g. someone sending binary
    /// on a WebTransport that is using a text serialization format, like Json.
    #[error("received binary for a text format")]
    ReceivedBinaryForText,
    /// Trying to encode a binary format as text", e.g., trying to
    /// store a Cbor encoded value in a String.
    #[error("trying to encode a binary format as Text")]
    CantEncodeBinaryAsText,
}

/// A representation of a value which can be stored and restored as a text.
///
/// Some formats are binary only and can't be serialized to or deserialized
/// from Text.  Attempting to do so will return an Err(FormatError).
pub type Text = Result<String, Error>;

/// A representation of a value which can be stored and restored as a binary.
pub type Binary = Result<Vec<u8>, Error>;

/// The status of a WebTransport connection. Used for status notifications.
#[derive(Clone, Debug, PartialEq)]
pub enum WebTransportStatus {
    /// Fired when a WebTransport connection has opened.
    Opened,
    /// Fired when a WebTransport connection has closed.
    Closed,
    /// Fired when a WebTransport connection has failed.
    Error,
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
/// An error encountered by a WebTransport.
pub enum WebTransportError {
    #[error("{0}")]
    /// An error encountered when creating the WebTransport.
    CreationError(String),
}

/// A handle to control the WebTransport connection. Implements `Task` and could be canceled.
#[must_use = "the connection will be closed when the task is dropped"]
#[derive(Clone)]
pub struct WebTransportTask {
    pub datagram: ReadSignal<Vec<u8>>,
    pub unidirectional_stream: ReadSignal<Option<WebTransportReceiveStream>>,
    pub bidirectional_stream: ReadSignal<Option<WebTransportBidirectionalStream>>,
    pub status: ReadSignal<WebTransportStatus>,
    transport: Rc<WebTransport>,
    #[allow(dead_code)]
    listeners: [Promise; 2],
}

impl WebTransportTask {
    fn new(
        transport: Rc<WebTransport>,
        datagram: ReadSignal<Vec<u8>>,
        unidirectional_stream: ReadSignal<Option<WebTransportReceiveStream>>,
        bidirectional_stream: ReadSignal<Option<WebTransportBidirectionalStream>>,
        status: ReadSignal<WebTransportStatus>,
        listeners: [Promise; 2],
    ) -> WebTransportTask {
        WebTransportTask {
            transport,
            datagram,
            unidirectional_stream,
            bidirectional_stream,
            status,
            listeners,
        }
    }
}

impl fmt::Debug for WebTransportTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebTransportTask")
    }
}

/// A WebTransport service attached to a user context.
#[derive(Default, Debug)]
pub struct WebTransportService {}

impl WebTransportService {
    /// Connects to a server through a WebTransport connection. Needs two closures; one is passed
    /// data, the other is passed updates about the WebTransport's status.
    pub fn connect(url: &str) -> Result<WebTransportTask, WebTransportError> {
        let (datagram, set_datagram) = create_signal(Vec::new());
        let (status, set_status) = create_signal(WebTransportStatus::Closed);
        let (unidirectional_stream, set_unidirectional_stream) =
            create_signal::<Option<WebTransportReceiveStream>>(None);
        let (bidirectional_stream, set_bidirectional_stream) =
            create_signal::<Option<WebTransportBidirectionalStream>>(None);
        let ConnectCommon(transport, listeners) = Self::connect_common(url, &set_status)?;
        let transport = Rc::new(transport);

        Self::start_listening_incoming_datagrams(
            transport.clone(),
            transport.datagrams(),
            set_datagram,
        );
        Self::start_listening_incoming_unidirectional_streams(
            transport.clone(),
            transport.incoming_unidirectional_streams(),
            set_unidirectional_stream,
        );

        Self::start_listening_incoming_bidirectional_streams(
            transport.clone(),
            transport.incoming_bidirectional_streams(),
            set_bidirectional_stream,
        );

        Ok(WebTransportTask::new(
            transport,
            datagram,
            unidirectional_stream,
            bidirectional_stream,
            status,
            listeners,
        ))
    }

    fn start_listening_incoming_unidirectional_streams(
        transport: Rc<WebTransport>,
        incoming_streams: ReadableStream,
        stream_signal: WriteSignal<Option<WebTransportReceiveStream>>,
    ) {
        println!("waiting for unidirectional streams");
        let read_result: ReadableStreamDefaultReader =
            incoming_streams.get_reader().unchecked_into();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                let read_result = JsFuture::from(read_result.read()).await;
                println!("got unidirectional stream");
                match read_result {
                    Err(e) => {
                        eprintln!("Failed to read incoming unidirectional streams {e:?}");
                        let mut reason = WebTransportCloseInfo::default();
                        reason.reason(
                            format!("Failed to read incoming unidirectional strams {e:?}").as_str(),
                        );
                        transport.close_with_close_info(&reason);
                        break;
                    }
                    Ok(result) => {
                        let done = Reflect::get(&result, &JsString::from("done"))
                            .unwrap()
                            .unchecked_into::<Boolean>();
                        if let Ok(value) = Reflect::get(&result, &JsString::from("value")) {
                            let value: WebTransportReceiveStream = value.unchecked_into();
                            stream_signal.update(|x| *x = Some(value));
                        }
                        if done.is_truthy() {
                            println!("reading is over");
                            break;
                        }
                    }
                }
            }
        });
    }

    fn start_listening_incoming_datagrams(
        transport: Rc<WebTransport>,
        datagrams: WebTransportDatagramDuplexStream,
        closure: WriteSignal<Vec<u8>>,
    ) {
        let incoming_datagrams: ReadableStreamDefaultReader =
            datagrams.readable().get_reader().unchecked_into();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                let read_result = JsFuture::from(incoming_datagrams.read()).await;
                match read_result {
                    Err(e) => {
                        let mut reason = WebTransportCloseInfo::default();
                        reason.reason(format!("Failed to read incoming datagrams {e:?}").as_str());
                        transport.close_with_close_info(&reason);
                        break;
                    }
                    Ok(result) => {
                        let done = Reflect::get(&result, &JsString::from("done"))
                            .unwrap()
                            .unchecked_into::<Boolean>();
                        if done.is_truthy() {
                            break;
                        }
                        let value: Uint8Array = Reflect::get(&result, &JsString::from("value"))
                            .unwrap()
                            .unchecked_into();
                        process_binary(&value, &closure);
                    }
                }
            }
        });
    }

    fn start_listening_incoming_bidirectional_streams(
        transport: Rc<WebTransport>,
        streams: ReadableStream,
        stream_signal: WriteSignal<Option<WebTransportBidirectionalStream>>,
    ) {
        println!("waiting for bidirectional streams");
        let read_result: ReadableStreamDefaultReader = streams.get_reader().unchecked_into();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                let read_result = JsFuture::from(read_result.read()).await;
                println!("got bidirectional stream");
                match read_result {
                    Err(e) => {
                        println!("Failed to read incoming unidirectional streams {e:?}");
                        let mut reason = WebTransportCloseInfo::default();
                        reason.reason(
                            format!("Failed to read incoming unidirectional strams {e:?}").as_str(),
                        );
                        transport.close_with_close_info(&reason);
                        break;
                    }
                    Ok(result) => {
                        println!("got result");
                        let done = Reflect::get(&result, &JsString::from("done"))
                            .unwrap()
                            .unchecked_into::<Boolean>();
                        if let Ok(value) = Reflect::get(&result, &JsString::from("value")) {
                            let value: WebTransportBidirectionalStream = value.unchecked_into();
                            stream_signal.update(|x| *x = Some(value));
                        }
                        if done.is_truthy() {
                            println!("reading is over");
                            break;
                        }
                    }
                }
            }
        });
    }

    fn connect_common(
        url: &str,
        notification: &WriteSignal<WebTransportStatus>,
    ) -> Result<ConnectCommon, WebTransportError> {
        let transport = WebTransport::new(url);
        let transport = transport.map_err(|e| {
            WebTransportError::CreationError(format!("Failed to create WebTransport: {e:?}"))
        })?;

        let notify = *notification;
        let closure = Closure::wrap(Box::new(move |_| {
            notify.update(|x| *x = WebTransportStatus::Opened);
        }) as Box<dyn FnMut(JsValue)>);
        let ready = transport.ready().then(&closure);
        closure.forget();

        let notify = *notification;
        let closed_closure = Closure::wrap(Box::new(move |e| {
            println!("WebTransport closed: {:?}", e);
            notify.update(|x| *x = WebTransportStatus::Closed);
        }) as Box<dyn FnMut(JsValue)>);
        let closed = transport.closed().then(&closed_closure);
        closed_closure.forget();

        {
            let listeners = [ready, closed];
            Ok(ConnectCommon(transport, listeners))
        }
    }
}
struct ConnectCommon(WebTransport, [Promise; 2]);

pub fn process_binary(bytes: &Uint8Array, data_signal: &WriteSignal<Vec<u8>>) {
    let data = bytes.to_vec();
    data_signal.update(|x| *x = data);
}

impl WebTransportTask {
    /// Sends data to a WebTransport connection.
    pub fn send_datagram(transport: Rc<WebTransport>, data: Vec<u8>) {
        let transport = transport;
        wasm_bindgen_futures::spawn_local(async move {
            let transport = transport.clone();
            let result: Result<(), anyhow::Error> = async move {
                let stream = transport.datagrams();
                let stream: WritableStream = stream.writable();
                let writer = stream.get_writer().map_err(|e| anyhow!("{:?}", e))?;
                let data = Uint8Array::from(data.as_slice());
                let _stream = JsFuture::from(writer.write_with_chunk(&data))
                    .await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                writer.release_lock();
                Ok(())
            }
            .await;
            if let Err(e) = result {
                let e = e.to_string();
                println!("error: {}", e);
            }
        });
    }

    pub fn send_unidirectional_stream(transport: Rc<WebTransport>, data: Vec<u8>) {
        let transport = transport;
        wasm_bindgen_futures::spawn_local(async move {
            let transport = transport.clone();
            let result: Result<(), anyhow::Error> = async move {
                let stream = JsFuture::from(transport.create_unidirectional_stream()).await;
                let stream: WritableStream =
                    stream.map_err(|e| anyhow!("{:?}", e))?.unchecked_into();
                let writer = stream.get_writer().map_err(|e| anyhow!("{:?}", e))?;
                let data = Uint8Array::from(data.as_slice());
                let _ = JsFuture::from(writer.write_with_chunk(&data))
                    .await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                writer.release_lock();
                JsFuture::from(stream.close())
                    .await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                Ok(())
            }
            .await;
            if let Err(e) = result {
                let e = e.to_string();
                println!("error: {}", e);
            }
        });
    }

    pub fn send_bidirectional_stream(
        transport: Rc<WebTransport>,
        data: Vec<u8>,
        data_signal: WriteSignal<Vec<u8>>,
    ) {
        let transport = transport;
        wasm_bindgen_futures::spawn_local(async move {
            let transport = transport.clone();
            let result: Result<(), anyhow::Error> = async move {
                let stream = JsFuture::from(transport.create_bidirectional_stream()).await;
                let stream: WebTransportBidirectionalStream =
                    stream.map_err(|e| anyhow!("{:?}", e))?.unchecked_into();
                let readable: ReadableStreamDefaultReader =
                    stream.readable().get_reader().unchecked_into();
                let (receiver, sender) = create_signal(false);
                wasm_bindgen_futures::spawn_local(async move {
                    loop {
                        let read_result = JsFuture::from(readable.read()).await;
                        match read_result {
                            Err(e) => {
                                let mut reason = WebTransportCloseInfo::default();
                                reason.reason(
                                    format!("Failed to read incoming stream {e:?}").as_str(),
                                );
                                transport.close_with_close_info(&reason);
                                break;
                            }
                            Ok(result) => {
                                let done = Reflect::get(&result, &JsString::from("done"))
                                    .unwrap()
                                    .unchecked_into::<Boolean>();
                                if done.is_truthy() {
                                    break;
                                }
                                let value: Uint8Array =
                                    Reflect::get(&result, &JsString::from("value"))
                                        .unwrap()
                                        .unchecked_into();
                                process_binary(&value, &data_signal);
                            }
                        }
                    }
                    sender.update(|x| {
                        *x = true;
                    });
                });
                let writer = stream
                    .writable()
                    .get_writer()
                    .map_err(|e| anyhow!("{:?}", e))?;

                let data = Uint8Array::from(data.as_slice());
                let _ = JsFuture::from(writer.write_with_chunk(&data))
                    .await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                JsFuture::from(writer.close())
                    .await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

                let _ = receiver.get();

                Ok(())
            }
            .await;
            if let Err(e) = result {
                let e = e.to_string();
                println!("error: {}", e);
            }
        });
    }
}

impl Drop for WebTransportTask {
    fn drop(&mut self) {
        self.transport.close();
    }
}

#[cfg(test)]
mod test {
    use js_sys::Function;
    use leptos::create_runtime;
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);
    use super::*;

    #[wasm_bindgen]
    extern "C" {
        // Define the setTimeout function from JavaScript
        fn setTimeout(closure: &Closure<dyn FnMut()>, time: u32);
    }

    #[wasm_bindgen]
    pub fn sleep(callback: Function, delay: u32) {
        let closure = Closure::wrap(Box::new(move || {
            callback.call0(&JsValue::NULL).unwrap();
        }) as Box<dyn FnMut()>);

        // Set up the setTimeout function
        setTimeout(&&closure, delay);

        // Release the closure when it's no longer needed
        closure.forget();
    }

    #[wasm_bindgen_test]
    fn test_webtransport_init() {
        let _runtime = create_runtime();
        let _transport = WebTransportService::connect("https://transport.rustlemania.com").unwrap();
    }

    #[wasm_bindgen_test]
    fn test_webtransport_connect() {
        let _runtime = create_runtime();
        let _transport = WebTransportService::connect("https://transport.rustlemania.com").unwrap();
        // TODO: how to wait until we connect?
        // let js_function = Closure::wrap(Box::new(|param: JsValue| {
        //     // This is the body of your JavaScript function
        //     // You can perform any JavaScript logic here
        //     if notification.get() == WebTransportStatus::Opened {}
        // }) as Box<dyn Fn(JsValue)>);
        // sleep(Function::new_no_args("function "), 5000);
        // assert!(notification.get() == WebTransportStatus::Opened);
    }
}
