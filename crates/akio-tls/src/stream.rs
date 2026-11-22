//! A blocking TLS stream over any `Read + Write` (a `TcpStream` usually), for tests, examples
//! and interop tools. **Not** a public API: `akio` connections use [`Tls`](crate::Tls).

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
    buf: Vec<u8>,
    /// Kernel TLS: the socket and the negotiated (version, AEAD) once offloaded.
    #[cfg(all(target_os = "linux", feature = "ktls"))]
    ktls: Option<(std::os::fd::RawFd, bool, crate::proto::suites::AeadAlg)>,
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
            buf: Vec::new(),
            #[cfg(all(target_os = "linux", feature = "ktls"))]
            ktls: None,
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
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        if self.ktls.is_some() {
            return self.pump_ktls();
        }
        self.buf.resize(16 * 1024 + 512, 0);
        let n = self.sock.read(&mut self.buf)?;
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        let mut r = self
            .conn
            .recv(&self.buf[..n], &mut self.plain, &mut self.out);
        // A server waiting for an asynchronous anti-replay answer: wait for it here.
        while r.is_ok() && self.conn.suspended() {
            self.conn.wait_resumable();
            r = self.conn.recv(&[], &mut self.plain, &mut self.out);
        }
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

    /// Before the handshake: sends `buf` as early data (0-RTT) as far as the client config and
    /// the ticket allow, and queues the rest for after the handshake. See
    /// [`Connection::early_data`] for what became of it.
    pub fn write_early(&mut self, buf: &[u8]) -> io::Result<()> {
        self.conn.seal(buf, &mut self.out).map_err(err)?;
        self.flush_out()
    }

    /// Sends close_notify.
    pub fn close(&mut self) -> io::Result<()> {
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        if let Some((fd, ..)) = self.ktls {
            if let Some(crate::proto::OffloadEvent::Send(t, d)) = self.conn.offloaded_close() {
                crate::ktls::send_all(fd, t, &d)?;
            }
            return Ok(());
        }
        self.conn.close(&mut self.out);
        self.flush_out()
    }

    /// Whether the record layer is in the kernel.
    pub fn offloaded(&self) -> bool {
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        return self.ktls.is_some();
        #[cfg(not(all(target_os = "linux", feature = "ktls")))]
        false
    }
}

#[cfg(all(target_os = "linux", feature = "ktls"))]
impl<S: Read + Write + std::os::fd::AsRawFd> Stream<S> {
    /// Asks for kernel TLS: call before the handshake, then [`offload`](Self::offload) after it.
    pub fn want_ktls(&mut self) {
        self.conn.set_keep_keys(true);
    }

    /// Moves the record layer into the kernel if it is ready and the kernel can (`Ok(false)`
    /// otherwise; the stream carries on in user space). Plaintext then flows on the socket
    /// itself, so `sendfile(2)` on `get_ref()` sends encrypted records.
    pub fn offload(&mut self) -> io::Result<bool> {
        // Application data already decrypted stays readable from `plain`.
        self.flush_out()?;
        let Some(o) = self.conn.offload_keys() else {
            return Ok(false);
        };
        let fd = self.sock.as_raw_fd();
        if !crate::ktls::install(fd, &o)? {
            self.conn.skip_offload();
            return Ok(false);
        }
        self.conn.commit_offload();
        self.ktls = Some((fd, o.tls13, o.aead));
        Ok(true)
    }
}

#[cfg(all(target_os = "linux", feature = "ktls"))]
impl<S: Read + Write> Stream<S> {
    /// Sends a TLS 1.3 KeyUpdate through the kernel (which must support rekeying, Linux 6.14
    /// and later). Only once offloaded.
    pub fn key_update(&mut self) -> io::Result<()> {
        let Some((fd, tls13, aead)) = self.ktls else {
            return Err(io::Error::other("not offloaded"));
        };
        let mut ev = Vec::new();
        self.conn.offloaded_key_update(&mut ev).map_err(err)?;
        crate::ktls::apply(fd, tls13, aead, &mut ev, |t, d| {
            crate::ktls::send_all(fd, t, d)
        })
    }

    fn pump_ktls(&mut self) -> io::Result<bool> {
        let Some((fd, tls13, aead)) = self.ktls else {
            return Ok(false);
        };
        self.buf.resize(16 * 1024 + 512, 0);
        let (typ, n) = loop {
            match akio_sys::ktls::ktls_recv(fd, &mut self.buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                r => break r?,
            }
        };
        if typ == 23 {
            if n == 0 {
                self.eof = true;
                return Ok(false);
            }
            self.plain.extend_from_slice(&self.buf[..n]);
            return Ok(true);
        }
        let mut ev = Vec::new();
        let r = self.conn.offloaded_record(typ, &self.buf[..n], &mut ev);
        crate::ktls::apply(fd, tls13, aead, &mut ev, |t, d| {
            crate::ktls::send_all(fd, t, d)
        })?;
        r.map_err(err)
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
        #[cfg(all(target_os = "linux", feature = "ktls"))]
        if self.ktls.is_some() {
            return self.sock.write(buf);
        }
        self.conn.seal(buf, &mut self.out).map_err(err)?;
        self.flush_out()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_out()
    }
}
