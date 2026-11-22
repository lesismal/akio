//! A small blocking HTTP proxy for the client tests (also used by akio-ws's): `CONNECT` tunnels
//! and absolute-form requests, optional `Proxy-Authorization` check, every request head seen
//! recorded.
#![allow(dead_code)]

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

pub(crate) struct TestProxy {
    pub(crate) addr: SocketAddr,
    /// Request heads received, in order.
    pub(crate) seen: Arc<Mutex<Vec<String>>>,
}

impl TestProxy {
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub(crate) fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

/// Starts the proxy; with `auth`, requests without `Proxy-Authorization: <auth>` get 407.
pub(crate) fn start(auth: Option<&str>) -> TestProxy {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (s2, auth) = (seen.clone(), auth.map(str::to_owned));
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            let (seen, auth) = (s2.clone(), auth.clone());
            thread::spawn(move || {
                let _ = serve(c, &seen, auth.as_deref());
            });
        }
    });
    TestProxy { addr, seen }
}

/// Reads one head (through the blank line) from `s`, starting with `buf`'s bytes.
fn read_head(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i + 4]).into_owned();
            buf.drain(..i + 4);
            return Some(head);
        }
        let mut tmp = [0u8; 4096];
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn pipe(mut from: TcpStream, mut to: TcpStream) {
    let mut b = [0u8; 16384];
    loop {
        match from.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&b[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn serve(mut c: TcpStream, seen: &Mutex<Vec<String>>, auth: Option<&str>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let Some(head) = read_head(&mut c, &mut buf) else {
        return Ok(());
    };
    seen.lock().unwrap().push(head.clone());
    if let Some(a) = auth {
        if header(&head, "proxy-authorization") != Some(a) {
            c.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n",
            )?;
            return Ok(());
        }
    }
    let mut parts = head.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method == "CONNECT" {
        let Ok(up) = TcpStream::connect(target) else {
            c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")?;
            return Ok(());
        };
        c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        let (c2, u2) = (c.try_clone()?, up.try_clone()?);
        let t = thread::spawn(move || pipe(u2, c2));
        if !buf.is_empty() {
            (&up).write_all(&buf)?;
        }
        pipe(c, up);
        let _ = t.join();
        return Ok(());
    }
    // Absolute form: `GET http://host:port/path HTTP/1.1`.
    let Some(rest) = target.strip_prefix("http://") else {
        c.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")?;
        return Ok(());
    };
    let (authority, _) = rest.split_once('/').unwrap_or((rest, ""));
    let up = TcpStream::connect(authority)?;
    let (c2, u2) = (c.try_clone()?, up.try_clone()?);
    thread::spawn(move || pipe(u2, c2));
    let mut up_w = up;
    let mut head = head;
    loop {
        // Rewrite each request to origin form, without the proxy's own field.
        let mut lines = head.split("\r\n");
        let first = lines.next().unwrap_or("");
        let mut p = first.split(' ');
        let (m, t, v) = (
            p.next().unwrap_or(""),
            p.next().unwrap_or(""),
            p.next().unwrap_or(""),
        );
        let path = t
            .strip_prefix("http://")
            .and_then(|r| r.find('/').map(|i| r[i..].to_owned()))
            .unwrap_or_else(|| "/".to_owned());
        let mut out = format!("{m} {path} {v}\r\n");
        for l in lines {
            if !l.to_ascii_lowercase().starts_with("proxy-authorization:") && !l.is_empty() {
                out.push_str(l);
                out.push_str("\r\n");
            }
        }
        out.push_str("\r\n");
        up_w.write_all(out.as_bytes())?;
        let len: usize = header(&head, "content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        while buf.len() < len {
            let mut tmp = [0u8; 4096];
            let n = c.read(&mut tmp)?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        up_w.write_all(&buf[..len])?;
        buf.drain(..len);
        match read_head(&mut c, &mut buf) {
            Some(h) => {
                seen.lock().unwrap().push(h.clone());
                head = h;
            }
            None => {
                let _ = up_w.shutdown(Shutdown::Write);
                return Ok(());
            }
        }
    }
}
