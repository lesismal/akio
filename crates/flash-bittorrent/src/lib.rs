#![forbid(unsafe_code)]
//! BitTorrent for flash: the protocols as codecs and state machines without I/O, a UDP port
//! shared by uTP and the DHT on a flash UDP listener, trackers on flash-http and flash UDP, and
//! a [`client::Client`] that downloads and seeds with all of them, wire compatible with
//! libtorrent and aria2 (`tools/interop/bittorrent/run.sh`).
//!
//! | Module | What it is |
//! |---|---|
//! | [`bencode`] | Bencoding: a `Value` tree, strict decoding, canonical encoding, raw spans |
//! | [`metainfo`] | .torrent files (v1), info hashes, piece/file layout, a `Builder` |
//! | [`magnet`] | Magnet links (BEP 9) |
//! | [`wire`] | The peer wire protocol (BEP 3, 5, 6, 10, 9, 11) as a codec |
//! | [`mse`] | Message Stream Encryption (MSE/PE): DH-768 and RC4, both roles |
//! | [`tracker`] | HTTP and UDP trackers (BEP 3, 15, 23, 48): codecs, a client, a server |
//! | [`utp`] | uTP (BEP 29) with LEDBAT, one connection without I/O |
//! | [`dht`] | The mainline DHT (BEP 5) as a node without I/O |
//! | [`port`] | One UDP port for uTP, the DHT and more, on a flash UDP listener |
//! | [`client`] | The client: torrents and magnets, picker, choking, storage on the logical pool |
//!
//! ```no_run
//! use flash_bittorrent::client::{AddOptions, Client, ClientConfig};
//! use std::time::Duration;
//!
//! let client = Client::new(ClientConfig::default()).unwrap(); // :6881, TCP + uTP + DHT + MSE
//! let t = client.add_magnet("magnet:?xt=urn:btih:...", AddOptions::default()).unwrap();
//! t.wait_complete(Duration::from_secs(3600));
//! ```
//!
//! Guide: [BitTorrent](https://lesismal.github.io/flash/en/protocols/bittorrent.html)
//! (中文: [BitTorrent](https://lesismal.github.io/flash/zh-CN/protocols/bittorrent.html)).
#![warn(clippy::unwrap_used)]

pub mod bencode;
pub mod client;
pub mod dht;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod magnet;
pub mod metainfo;
pub mod mse;
pub mod port;
pub mod tracker;
pub mod utp;
pub mod wire;

/// Fills `b` with random bytes from the operating system (a fixed pattern if that fails).
pub(crate) fn rand_fill(b: &mut [u8]) {
    if getrandom::getrandom(b).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let mut x = t | 1;
        for v in b {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *v = x as u8;
        }
    }
}

/// A random `u32`.
pub(crate) fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    rand_fill(&mut b);
    u32::from_le_bytes(b)
}
