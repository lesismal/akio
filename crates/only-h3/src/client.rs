//! An HTTP/3 client: requests multiplexed on one QUIC connection.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::Duration;

use only_http::message::{Headers, Method, Response};
use only_quic::Bytes;
use only_quic::{Connection, ConnectionError, Dir, QuicHandler, StreamId};

use crate::frame::{self, Reader};
use crate::qpack::{self, FieldBuf};
use crate::{StreamMap, Uni, code};

type Callback = Box<dyn FnOnce(Result<Response, H3Error>) + Send>;

/// Why an HTTP/3 request got no response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H3Error {
    /// The connection is closed (why).
    Closed(String),
    /// The server reset the request stream with this HTTP/3 error code ([`code`](crate::code)).
    Reset(u64),
    /// The response broke the protocol (what was wrong).
    Protocol(&'static str),
    /// No response within the timeout of a blocking call.
    Timeout,
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Error::Closed(why) => write!(f, "connection closed: {why}"),
            H3Error::Reset(code) => write!(f, "stream reset (code {code:#x})"),
            H3Error::Protocol(what) => write!(f, "HTTP/3 protocol error: {what}"),
            H3Error::Timeout => f.write_str("timed out"),
        }
    }
}

impl std::error::Error for H3Error {}

struct InFlight {
    r: Reader,
    resp: Option<Response>,
    cb: Option<Callback>,
}

#[derive(Default)]
struct State {
    ready: bool,
    closed: Option<String>,
    queue: VecDeque<(Bytes, Callback)>,
    inflight: StreamMap<InFlight>,
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

impl std::fmt::Debug for H3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Client").finish_non_exhaustive()
    }
}

impl H3Client {
    /// Connects to `addr`, verifying it as `server_name`, with a QUIC client config offering
    /// ALPN `h3` (for example `only_quic::client_config(roots, &[b"h3"])`). The engine needs
    /// UDP client threads. Requests sent before the handshake completes wait for it, unless
    /// the connection resumes with 0-RTT (`only_quic::ClientConfig::zero_rtt`): then they go
    /// out at once, in 0-RTT packets that may be **replayed**, so make only requests that are
    /// safe to repeat on such a client (a server may answer `425 Too Early`, RFC 8470).
    pub fn dial(
        engine: &only::Engine,
        addr: SocketAddr,
        server_name: &str,
        config: only_quic::ClientConfig,
    ) -> Result<H3Client, only_quic::Error> {
        let st = Arc::new(Mutex::new(State::default()));
        let handler = ClientConn {
            st: st.clone(),
            uni: StreamMap::default(),
            peer_ctrl: None,
            fields: FieldBuf::default(),
        };
        let conn = only_quic::dial(engine, addr, server_name, config, handler)?;
        // Resuming with 0-RTT: requests go out before the handshake completes.
        if conn.early_data() == only::tls::EarlyData::Pending {
            lock(&st).ready = true;
        }
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
        cb: impl FnOnce(Result<Response, H3Error>) + Send + 'static,
    ) {
        let pseudo: [(&[u8], &[u8]); 4] = [
            (b":method", method.as_str().as_bytes()),
            (b":scheme", b"https"),
            (b":authority", self.authority.as_bytes()),
            (b":path", path.as_bytes()),
        ];
        let pseudo = if method == Method::Connect {
            &pseudo[..3]
        } else {
            &pseudo[..]
        };
        let hint = crate::head_hint(headers) + self.authority.len() + path.len() + body.len() + 64;
        let len = (!body.is_empty()).then_some(body.len() as u64);
        let encode = |wire: &mut Vec<u8>| {
            crate::put_head(wire, None, pseudo, headers, false, len);
            if !body.is_empty() {
                frame::put_frame(wire, frame::DATA, &body);
            }
        };
        let wire = if body.len() <= crate::POOLED_BODY_MAX {
            Bytes::pooled(hint, encode)
        } else {
            let mut wire = Vec::with_capacity(hint);
            encode(&mut wire);
            Bytes::from(wire)
        };
        let mut st = lock(&self.st);
        if let Some(e) = st.closed.clone() {
            drop(st);
            return cb(Err(H3Error::Closed(e)));
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
    ) -> Result<Response, H3Error> {
        let (tx, rx) = mpsc::channel();
        self.request(method, path, headers, body, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(timeout).map_err(|_| H3Error::Timeout)?
    }

    /// `GET path`, blocking.
    pub fn get(&self, path: &str, timeout: Duration) -> Result<Response, H3Error> {
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
    uni: StreamMap<Uni>,
    peer_ctrl: Option<StreamId>,
    /// Field sections are decoded here, then copied once into the response's `Headers`.
    fields: FieldBuf,
}

fn fields_to_response(fields: &FieldBuf) -> Option<Response> {
    let mut status = None;
    let mut headers = Headers::with_capacity(fields.len(), fields.bytes());
    for (n, v) in fields.strs()? {
        if n == ":status" {
            status = v.parse::<u16>().ok();
        } else if n.starts_with(':') {
            return None;
        } else {
            headers.append(n, v);
        }
    }
    let mut r = Response::new(status?);
    r.headers = headers;
    Some(r)
}

impl ClientConn {
    fn fail_all(&self, why: String) {
        let mut st = lock(&self.st);
        st.closed = Some(why.clone());
        let mut cbs: Vec<Callback> = st.queue.drain(..).map(|(_, cb)| cb).collect();
        cbs.extend(st.inflight.drain().filter_map(|(_, f)| f.cb));
        drop(st);
        for cb in cbs {
            cb(Err(H3Error::Closed(why.clone())));
        }
    }

    /// Feeds a response stream; returns the callback to run, if the response is complete.
    fn on_resp(
        &mut self,
        id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Option<(Callback, Result<Response, H3Error>)> {
        let mut st = lock(&self.st);
        let InFlight { r, resp, .. } = st.inflight.get_mut(&id)?;
        let fields = &mut self.fields;
        let fed = r.feed(
            data,
            1 << 30,
            || H3Error::Protocol("frame too large"),
            |ty, p| {
                match ty {
                    frame::HEADERS => {
                        qpack::decode_into(p, 1 << 20, fields)
                            .map_err(|_| H3Error::Protocol("bad field section"))?;
                        match resp.as_mut() {
                            None => match fields_to_response(fields) {
                                Some(r) if r.status < 200 => {}
                                Some(r) => *resp = Some(r),
                                None => return Err(H3Error::Protocol("malformed response")),
                            },
                            Some(r) => {
                                let mut t = Headers::with_capacity(fields.len(), fields.bytes());
                                for (n, v) in fields.iter() {
                                    t.append(
                                        String::from_utf8_lossy(n),
                                        String::from_utf8_lossy(v),
                                    );
                                }
                                r.trailers = Some(t);
                            }
                        }
                    }
                    frame::DATA => match resp.as_mut() {
                        Some(r) => r.body.extend_from_slice(p),
                        None => return Err(H3Error::Protocol("DATA before HEADERS")),
                    },
                    _ => {}
                }
                Ok(())
            },
        );
        let err = fed.err();
        if err.is_none() && !fin {
            return None;
        }
        let mut f = st.inflight.remove(&id)?;
        let cb = f.cb.take()?;
        let r = match (err, f.resp.take()) {
            (Some(e), _) => Err(e),
            (None, Some(r)) => Ok(r),
            (None, None) => Err(H3Error::Protocol("stream ended without a response")),
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
        if id.dir() == Dir::Uni {
            if let Some(u) = self.uni.get_mut(&id) {
                let mut stop = |id, e| {
                    let _ = c.stop(id, e);
                };
                if let Err(e) =
                    crate::on_uni(u, &mut self.peer_ctrl, &mut stop, id, &data, fin, false)
                {
                    c.close(e, b"");
                }
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
            cb(Err(H3Error::Reset(code)));
        }
    }

    fn on_streams_available(&mut self, c: &Connection, _dir: Dir) {
        start_queued(c, &self.st);
    }

    fn on_close(&mut self, _c: &Connection, reason: ConnectionError) {
        self.fail_all(reason.to_string());
    }
}
