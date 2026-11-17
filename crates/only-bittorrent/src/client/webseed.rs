//! Web seeds (BEP 19, GetRight style): a piece is fetched from an HTTP(S) server with `Range`
//! requests on the files it covers (padding is zeros, never fetched), through the client's
//! only-http client, then checked and written like a piece from peers.
//!
//! A single-file torrent's URL names the file (a URL ending in `/` gets the file name
//! appended); a multi-file torrent's URL is a directory holding `<name>/<path...>`.

use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use only_http::client::{ClientRequest, ClientResponse};

use super::ClientInner;
use super::torrent::TorrentShared;
use crate::magnet::encode_component;
use crate::metainfo::Info;

/// Most bytes one range request asks for (bounds the HTTP client's body buffer).
pub(crate) const MAX_RANGE: u64 = 4 << 20;
/// A whole piece must arrive within this (each range request's timeout).
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Web seeds kept per torrent.
pub(crate) const MAX_WEB_SEEDS: usize = 16;

/// One HTTP range of a piece fetch.
#[derive(Debug, Clone)]
pub(crate) struct Range {
    pub(crate) url: String,
    /// Offset in the file.
    pub(crate) start: u64,
    pub(crate) len: u64,
    /// Offset in the piece buffer.
    pub(crate) pos: usize,
    /// The range is the whole file (a `200 OK` with the full body is then fine too).
    pub(crate) whole_file: bool,
}

/// A piece to fetch from a web seed (made under the torrent's lock, started after it).
#[derive(Debug, Clone)]
pub(crate) struct Fetch {
    pub(crate) seed: String,
    pub(crate) piece: u32,
    pub(crate) size: usize,
    pub(crate) ranges: Vec<Range>,
}

/// The URL of file `file` of `info` at web seed `base`.
pub(crate) fn file_url(base: &str, info: &Info, file: usize) -> String {
    let f = &info.files[file];
    if info.single_file {
        if base.ends_with('/') {
            let name = f.path.last().map_or(info.name.as_str(), String::as_str);
            return format!("{base}{}", encode_component(name));
        }
        return base.to_owned();
    }
    let mut u = base.to_owned();
    if !u.ends_with('/') {
        u.push('/');
    }
    u.push_str(&encode_component(&info.name));
    for c in &f.path {
        u.push('/');
        u.push_str(&encode_component(c));
    }
    u
}

/// The requests that fetch piece `piece` of `info` from `base`.
pub(crate) fn plan(base: &str, info: &Info, piece: u32) -> Fetch {
    let mut ranges = Vec::new();
    let mut pos = 0usize;
    for s in info.piece_segments(piece as usize) {
        let f = &info.files[s.file];
        if !f.padding {
            let url = file_url(base, info, s.file);
            let mut off = 0;
            while off < s.len {
                let len = (s.len - off).min(MAX_RANGE);
                ranges.push(Range {
                    url: url.clone(),
                    start: s.offset + off,
                    len,
                    pos: pos + off as usize,
                    whole_file: s.offset + off == 0 && len == f.length,
                });
                off += len;
            }
        }
        pos += s.len as usize;
    }
    Fetch {
        seed: base.to_owned(),
        piece,
        size: info.piece_size(piece as usize) as usize,
        ranges,
    }
}

struct Assembly {
    buf: Vec<u8>,
    left: usize,
    error: Option<String>,
}

fn check(r: &Range, resp: &ClientResponse) -> Result<(), String> {
    match resp.status {
        206 if resp.body.len() as u64 == r.len => Ok(()),
        200 if r.whole_file && resp.body.len() as u64 == r.len => Ok(()),
        206 | 200 => Err(format!(
            "{}: got {} bytes for a range of {}",
            r.url,
            resp.body.len(),
            r.len
        )),
        s => Err(format!("{}: HTTP {s}", r.url)),
    }
}

/// Starts `f`; the outcome reaches the torrent's `web_seed_done`.
pub(crate) fn start(client: &Arc<ClientInner>, t: &Arc<TorrentShared>, f: Fetch) {
    let weak: Weak<TorrentShared> = Arc::downgrade(t);
    if f.ranges.is_empty() {
        // Padding only (cannot happen with valid layouts): zeros.
        t.with(|st, cx| st.web_seed_done(&f.seed, f.piece, Ok(vec![0; f.size]), cx));
        return;
    }
    let asm = Arc::new(Mutex::new(Assembly {
        buf: vec![0; f.size],
        left: f.ranges.len(),
        error: None,
    }));
    for r in f.ranges.clone() {
        let req = ClientRequest::get(&r.url)
            .header(
                "Range",
                &format!("bytes={}-{}", r.start, r.start + r.len - 1),
            )
            .header(
                "User-Agent",
                concat!("only-bittorrent/", env!("CARGO_PKG_VERSION")),
            )
            .timeout(REQUEST_TIMEOUT);
        let asm = asm.clone();
        let weak = weak.clone();
        let seed = f.seed.clone();
        let piece = f.piece;
        client.http.request(req, move |res| {
            let done = {
                let mut a = asm.lock().unwrap_or_else(|p| p.into_inner());
                match res.map_err(|e| format!("{}: {e}", r.url)).and_then(|resp| {
                    check(&r, &resp)?;
                    Ok(resp)
                }) {
                    Ok(resp) => {
                        if a.error.is_none() {
                            a.buf[r.pos..r.pos + r.len as usize].copy_from_slice(&resp.body);
                        }
                    }
                    Err(e) => {
                        a.error.get_or_insert(e);
                    }
                }
                a.left -= 1;
                (a.left == 0).then(|| match a.error.take() {
                    Some(e) => Err(e),
                    None => Ok(std::mem::take(&mut a.buf)),
                })
            };
            if let (Some(result), Some(t)) = (done, weak.upgrade()) {
                t.with(|st, cx| st.web_seed_done(&seed, piece, result, cx));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{Builder, TorrentVersion};

    #[test]
    fn urls_and_ranges() {
        let single = Builder::new("a b.bin")
            .piece_length(16384)
            .build_bytes(&vec![1; 40000])
            .unwrap();
        assert_eq!(
            file_url("http://h/x.bin", &single.info, 0),
            "http://h/x.bin"
        );
        assert_eq!(
            file_url("http://h/d/", &single.info, 0),
            "http://h/d/a%20b.bin"
        );
        let files = vec![
            (vec!["d".to_owned(), "x".to_owned()], vec![1u8; 20000]),
            (vec!["y".to_owned()], vec![2u8; 5]),
        ];
        let multi = Builder::new("t")
            .piece_length(16384)
            .version(TorrentVersion::Hybrid)
            .build_files(&files)
            .unwrap();
        assert_eq!(file_url("http://h/s", &multi.info, 0), "http://h/s/t/d/x");
        // Piece 1: the end of x (3616 bytes) then padding; piece 2: y.
        let p1 = plan("http://h/s/", &multi.info, 1);
        assert_eq!(p1.ranges.len(), 1);
        assert_eq!(
            (p1.ranges[0].start, p1.ranges[0].len, p1.ranges[0].pos),
            (16384, 3616, 0)
        );
        let p2 = plan("http://h/s/", &multi.info, 2);
        assert_eq!(p2.ranges[0].url, "http://h/s/t/y");
        assert!(p2.ranges[0].whole_file);
    }
}
