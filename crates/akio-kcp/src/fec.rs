//! kcp-go's forward error correction: every `data` packets are followed by `parity` shards.

use crate::rs::Rs;

pub(crate) const HEADER: usize = 6; // seqid(4) type(2)
pub(crate) const HEADER_PLUS2: usize = HEADER + 2;
pub(crate) const TYPE_DATA: u16 = 0xf1;
pub(crate) const TYPE_PARITY: u16 = 0xf2;
pub(crate) const TYPE_OOB: u16 = 0xf3;
const MAX_SETS: i64 = 3;
const ENCODE_LATENCY_MS: i64 = 500;

fn diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

pub(crate) struct Encoder {
    rs: Rs,
    paws: u32,
    next: u32,
    count: usize,
    max_size: usize,
    shards: Vec<Vec<u8>>,
    last_ms: i64,
    started: bool,
}

impl Encoder {
    pub(crate) fn new(data: usize, parity: usize) -> Option<Encoder> {
        let rs = Rs::new(data, parity)?;
        let total = (data + parity) as u32;
        Some(Encoder {
            rs,
            paws: u32::MAX / total * total,
            next: 0,
            count: 0,
            max_size: 0,
            shards: vec![Vec::new(); data + parity],
            last_ms: 0,
            started: false,
        })
    }

    /// Stamps the FEC header at the start of `pkt` (`HEADER_PLUS2` bytes reserved) and returns
    /// the parity datagrams (FEC header + shard) the packet completes.
    pub(crate) fn add(&mut self, pkt: &mut [u8], now_ms: i64) -> Vec<Vec<u8>> {
        pkt[..4].copy_from_slice(&self.next.to_le_bytes());
        pkt[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
        let size = (pkt.len() - HEADER) as u16;
        pkt[6..8].copy_from_slice(&size.to_le_bytes());
        self.next = (self.next + 1) % self.paws;
        let payload = &pkt[HEADER..];
        self.shards[self.count].clear();
        self.shards[self.count].extend_from_slice(payload);
        self.count += 1;
        self.max_size = self.max_size.max(payload.len());
        let last = self.last_ms;
        self.last_ms = now_ms;
        if self.count < self.rs.data {
            return Vec::new();
        }
        let size = self.max_size;
        self.count = 0;
        self.max_size = 0;
        if self.started && now_ms - last >= ENCODE_LATENCY_MS {
            self.next = (self.next + self.rs.parity as u32) % self.paws;
            return Vec::new();
        }
        self.started = true;
        for s in &mut self.shards {
            s.resize(size, 0);
        }
        self.rs.encode(&mut self.shards);
        let mut out = Vec::with_capacity(self.rs.parity);
        for p in 0..self.rs.parity {
            let mut b = Vec::with_capacity(HEADER + size);
            b.extend_from_slice(&self.next.to_le_bytes());
            b.extend_from_slice(&TYPE_PARITY.to_le_bytes());
            b.extend_from_slice(&self.shards[self.rs.data + p]);
            self.next = (self.next + 1) % self.paws;
            out.push(b);
        }
        out
    }
}

struct Set {
    shards: Vec<Option<Vec<u8>>>,
    have: usize,
    done: bool,
}

pub(crate) struct Decoder {
    rs: Rs,
    total: u32,
    paws: u32,
    sets: std::collections::HashMap<u32, Set>,
    newest: u32,
}

impl Decoder {
    pub(crate) fn new(data: usize, parity: usize) -> Option<Decoder> {
        let rs = Rs::new(data, parity)?;
        let total = (data + parity) as u32;
        Some(Decoder {
            rs,
            total,
            paws: u32::MAX / total * total,
            sets: Default::default(),
            newest: 0,
        })
    }

    /// Takes a datagram (FEC header first); returns the data packets it lets us recover (each
    /// with its 2-byte size prefix).
    pub(crate) fn decode(&mut self, b: &[u8]) -> Vec<Vec<u8>> {
        let seqid = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let is_data = u16::from_le_bytes([b[4], b[5]]) == TYPE_DATA;
        if seqid >= self.paws {
            return Vec::new();
        }
        let idx = (seqid % self.total) as usize;
        if (idx < self.rs.data) != is_data {
            return Vec::new();
        }
        let id = seqid / self.total;
        let t = self.total;
        if let std::collections::hash_map::Entry::Vacant(e) = self.sets.entry(id) {
            e.insert(Set {
                shards: vec![None; t as usize],
                have: 0,
                done: false,
            });
            if self.sets.len() == 1 || diff(id.wrapping_mul(t), self.newest.wrapping_mul(t)) > 0 {
                self.newest = id;
            }
            let newest = self.newest;
            self.sets.retain(|&k, _| {
                i64::from(diff(newest.wrapping_mul(t), k.wrapping_mul(t)))
                    <= MAX_SETS * i64::from(t)
            });
            if !self.sets.contains_key(&id) {
                return Vec::new();
            }
        }
        let set = self.sets.get_mut(&id).expect("present");
        if set.done || set.shards[idx].is_some() {
            return Vec::new();
        }
        set.shards[idx] = Some(b[HEADER..].to_vec());
        set.have += 1;
        if set.have < self.rs.data {
            return Vec::new();
        }
        set.done = true;
        let mut shards = std::mem::take(&mut set.shards);
        let size = shards.iter().flatten().map(Vec::len).max().unwrap_or(0);
        let lost: Vec<bool> = (0..self.rs.data).map(|i| shards[i].is_none()).collect();
        if !lost.iter().any(|l| *l) {
            return Vec::new();
        }
        for s in shards.iter_mut().flatten() {
            s.resize(size, 0);
        }
        if !self.rs.reconstruct(&mut shards, size) {
            return Vec::new();
        }
        lost.iter()
            .enumerate()
            .filter(|(_, l)| **l)
            .filter_map(|(i, _)| shards[i].take())
            .collect()
    }
}
