//! An HTTP/3 client: requests multiplexed on one QUIC connection.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::Duration;

use bytes::Bytes;
use flash_http::message::{Headers, Method, Response};
use flash_quic::{Connection, ConnectionError, Dir, QuicHandler, StreamId};

use crate::frame::{self, Reader};
use crate::{Uni, code, qpack};

type Callback = Box<dyn FnOnce(Result<Response, String>) + Send>;

struct InFlight {
    r: Reader,
    resp: Option<Response>,
    cb: Option<Callback>,
}

#[derive(Default)]
struct State {
    ready: bool,
    closed: Option<String>,
    queue: VecDeque<(Vec<u8>, Callback)>,
    inflight: HashMap<StreamId, InFlight>,
}

fn lock(s: &Mutex<State>) -> MutexGuard<'_, State> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

/// An HTTP/3 connection to one server. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct H3Client {
    conn: Connection,
    st: Arc<Mutex<State>>,
    authority: String,
}

impl H3Client {
    /// Connects to `addr`, verifying it as `server_name`, with a QUIC client config offering
    /// ALPN `h3` (for example `flash_quic::client_config(roots, &[b"h3"])`). The engine needs
    /// UDP client threads. Requests sent before the handshake completes wait for it.
    pub fn connect(
        engine: &flash::Engine,
        addr: SocketAddr,
        server_name: &str,
        config: flash_quic::proto::ClientConfig,
    ) -> Result<H3Client, flash_quic::Error> {
        let st = Arc::new(Mutex::new(State::default()));
        let handler = ClientConn {
            st: st.clone(),
            uni: HashMap::new(),
            peer_ctrl: None,
        };
        let conn = flash_quic::dial(engine, addr, server_name, config, handler)?;
        let authority = if addr.port() == 443 {
            server_name.to_owned()
        } else {
            format!("{server_name}:{}", addr.port())
        };
        Ok(H3Client {
            conn,
            st,
            authority,
        })
    }

    /// The QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Sends a request; `cb` gets the response (interim 1xx responses are skipped) or why
    /// there is none. `path` is the request target (`/a?b=c`).
    pub fn request(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Vec<u8>,
        cb: impl FnOnce(Result<Response, String>) + Send + 'static,
    ) {
        let m = method.as_str().to_owned();
        let mut fields: Vec<(&str, &str)> = vec![
            (":method", &m),
            (":scheme", "https"),
            (":authority", &self.authority),
        ];
        if method != Method::Connect {
            fields.push((":path", path));
        }
        let mut hs = Headers::new();
        for (n, v) in headers.iter() {
            hs.append(n, v);
        }
        if !body.is_empty() && hs.get("content-length").is_none() {
            hs.set("content-length", body.len().to_string());
        }
        let block = crate::encode_fields(&fields, &hs);
        let mut wire = Vec::with_capacity(block.len() + body.len() + 16);
        frame::put_frame(&mut wire, frame::HEADERS, &block);
        if !body.is_empty() {
            frame::put_frame(&mut wire, frame::DATA, &body);
        }
        let mut st = lock(&self.st);
        if let Some(e) = st.closed.clone() {
            drop(st);
            return cb(Err(e));
        }
        st.queue.push_back((wire, Box::new(cb)));
        let ready = st.ready;
        drop(st);
        if ready {
            start_queued(&self.conn, &self.st);
        }
    }

    /// Sends a request and waits for its response, up to `timeout`.
    pub fn request_blocking(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Response, String> {
        let (tx, rx) = mpsc::channel();
        self.request(method, path, headers, body, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(timeout)
            .map_err(|_| "timed out".to_owned())?
    }

    /// `GET path`, blocking.
    pub fn get(&self, path: &str, timeout: Duration) -> Result<Response, String> {
        self.request_blocking(Method::Get, path, &Headers::new(), Vec::new(), timeout)
    }

    /// Closes the connection (`H3_NO_ERROR`).
    pub fn close(&self) {
        self.conn.close(code::NO_ERROR, b"");
    }
}

/// Opens streams for queued requests while the peer allows.
fn start_queued(conn: &Connection, st: &Arc<Mutex<State>>) {
    loop {
        let mut s = lock(st);
        if s.queue.is_empty() || !s.ready {
            return;
        }
        let Some(id) = conn.open_bi() else { return };
        let (wire, cb) = s.queue.pop_front().expect("non-empty");
        s.inflight.insert(
            id,
            InFlight {
                r: Reader::default(),
                resp: None,
                cb: Some(cb),
            },
        );
        drop(s);
        let _ = conn.send(id, wire);
        let _ = conn.finish(id);
    }
}

struct ClientConn {
    st: Arc<Mutex<State>>,
    uni: HashMap<StreamId, Uni>,
    peer_ctrl: Option<StreamId>,
}

fn fields_to_response(fields: qpack::Fields) -> Option<Response> {
    let mut status = None;
    let mut headers = Headers::new();
    for (n, v) in fields {
        let v = String::from_utf8(v).ok()?;
        if n == b":status" {
            status = v.parse::<u16>().ok();
        } else if n.first() == Some(&b':') {
            return None;
        } else {
            headers.append(String::from_utf8(n).ok()?, v);
        }
    }
    let mut r = Response::new(status?);
    r.headers = headers;
    Some(r)
}

impl ClientConn {
    fn fail_all(&mut self, why: String) {
        let mut st = lock(&self.st);
        st.closed = Some(why.clone());
        let mut cbs: Vec<Callback> = st.queue.drain(..).map(|(_, cb)| cb).collect();
        cbs.extend(st.inflight.drain().filter_map(|(_, f)| f.cb));
        drop(st);
        for cb in cbs {
            cb(Err(why.clone()));
        }
    }

    /// Feeds a response stream; returns the callback to run, if the response is complete.
    fn on_resp(
        &mut self,
        id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Option<(Callback, Result<Response, String>)> {
        let mut st = lock(&self.st);
        let f = st.inflight.get_mut(&id)?;
        f.r.push(data);
        let mut err = None;
        loop {
            match f.r.frame(1 << 30) {
                Err(_) => {
                    err = Some("frame too large".to_owned());
                    break;
                }
                Ok(None) => break,
                Ok(Some((frame::HEADERS, p))) => {
                    let Ok(fields) = qpack::decode(&p, 1 << 20) else {
                        err = Some("bad field section".to_owned());
                        break;
                    };
                    match f.resp.as_mut() {
                        None => match fields_to_response(fields) {
                            Some(r) if r.status < 200 => {}
                            Some(r) => f.resp = Some(r),
                            None => {
                                err = Some("malformed response".to_owned());
                                break;
                            }
                        },
                        Some(r) => {
                            let mut t = Headers::new();
                            for (n, v) in fields {
                                t.append(String::from_utf8_lossy(&n), String::from_utf8_lossy(&v));
                            }
                            r.trailers = Some(t);
                        }
                    }
                }
                Ok(Some((frame::DATA, p))) => match f.resp.as_mut() {
                    Some(r) => r.body.extend_from_slice(&p),
                    None => {
                        err = Some("DATA before HEADERS".to_owned());
                        break;
                    }
                },
                Ok(Some(_)) => {}
            }
        }
        if err.is_none() && !fin {
            return None;
        }
        let mut f = st.inflight.remove(&id)?;
        let cb = f.cb.take()?;
        let r = match (err, f.resp.take()) {
            (Some(e), _) => Err(e),
            (None, Some(r)) => Ok(r),
            (None, None) => Err("stream ended without a response".to_owned()),
        };
        Some((cb, r))
    }
}

impl QuicHandler for ClientConn {
    fn on_connected(&mut self, c: &Connection) {
        if let Some(id) = c.open_uni() {
            let _ = c.send(id, crate::control_stream_preamble(1 << 20));
        }
        lock(&self.st).ready = true;
        start_queued(c, &self.st);
    }

    fn on_stream_opened(&mut self, _c: &Connection, id: StreamId) {
        if id.dir() == Dir::Uni {
            self.uni.insert(id, Uni::Unknown(Reader::default()));
        }
    }

    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        if let Some(u) = self.uni.get_mut(&id) {
            if let Err(e) = crate::on_uni(u, &mut self.peer_ctrl, c, id, &data, fin, false) {
                c.close(e, b"");
            }
            return;
        }
        if let Some((cb, r)) = self.on_resp(id, &data, fin) {
            cb(r);
        }
    }

    fn on_stream_reset(&mut self, _c: &Connection, id: StreamId, code: u64) {
        let f = lock(&self.st).inflight.remove(&id);
        if let Some(cb) = f.and_then(|f| f.cb) {
            cb(Err(format!("stream reset (code {code:#x})")));
        }
    }

    fn on_streams_available(&mut self, c: &Connection, _dir: Dir) {
        start_queued(c, &self.st);
    }

    fn on_close(&mut self, _c: &Connection, reason: ConnectionError) {
        self.fail_all(format!("connection closed: {reason}"));
    }
}
