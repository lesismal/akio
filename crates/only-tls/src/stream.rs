//! A blocking TLS stream over any `Read + Write` (a `TcpStream` usually), for tests, examples
//! and interop tools. **Not** a public API: `only` connections use [`Tls`](crate::Tls).

use std::io::{self, Read, Write};

use crate::proto::{Connection, Fatal};
use crate::{ClientConfig, ServerConfig};

/// A TLS connection over a blocking byte stream.
#[derive(Debug)]
pub struct Stream<S> {
    conn: Connection,
    sock: S,
    plain: Vec<u8>,
    plain_pos: usize,
    out: Vec<u8>,
    eof: bool,
}

fn err(e: Fatal) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl<S: Read + Write> Stream<S> {
    /// A client to `server_name` over `sock`.
    pub fn client(cfg: &ClientConfig, server_name: &str, sock: S) -> io::Result<Stream<S>> {
        let conn = Connection::client(cfg.inner.clone(), server_name).map_err(err)?;
        Ok(Stream::new(conn, sock))
    }

    /// A server over `sock`.
    pub fn server(cfg: &ServerConfig, sock: S) -> Stream<S> {
        Stream::new(Connection::server(cfg.inner.clone()), sock)
    }

    fn new(conn: Connection, sock: S) -> Stream<S> {
        Stream {
            conn,
            sock,
            plain: Vec::new(),
            plain_pos: 0,
            out: Vec::new(),
            eof: false,
        }
    }

    /// The connection state (negotiated parameters).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Mutable connection state.
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// The underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.sock
    }

    fn flush_out(&mut self) -> io::Result<()> {
        if !self.out.is_empty() {
            self.sock.write_all(&self.out)?;
            self.out.clear();
        }
        self.sock.flush()
    }

    /// Reads once from the socket and processes it; false at EOF.
    fn pump(&mut self) -> io::Result<bool> {
        let mut buf = vec![0u8; 16 * 1024 + 512];
        let n = self.sock.read(&mut buf)?;
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        let r = self.conn.recv(&buf[..n], &mut self.plain, &mut self.out);
        self.flush_out()?;
        r.map_err(err)?;
        Ok(true)
    }

    /// Runs the handshake to completion.
    pub fn handshake(&mut self) -> io::Result<()> {
        let r = self.conn.recv(&[], &mut self.plain, &mut self.out);
        self.flush_out()?;
        r.map_err(err)?;
        while self.conn.handshaking() {
            if !self.pump()? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF during the TLS handshake",
                ));
            }
        }
        Ok(())
    }

    /// Sends close_notify.
    pub fn close(&mut self) -> io::Result<()> {
        self.conn.close(&mut self.out);
        self.flush_out()
    }
}

impl<S: Read + Write> Read for Stream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.plain_pos < self.plain.len() {
                let n = buf.len().min(self.plain.len() - self.plain_pos);
                buf[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
                self.plain_pos += n;
                if self.plain_pos == self.plain.len() {
                    self.plain.clear();
                    self.plain_pos = 0;
                }
                return Ok(n);
            }
            if self.eof || self.conn.received_close_notify() {
                return Ok(0);
            }
            if self.conn.handshaking() {
                self.handshake()?;
                continue;
            }
            self.pump()?;
        }
    }
}

impl<S: Read + Write> Write for Stream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.conn.handshaking() {
            self.handshake()?;
        }
        self.conn.seal(buf, &mut self.out).map_err(err)?;
        self.flush_out()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_out()
    }
}
