//! An interpreter of the eBPF subset `only`'s programs use, for unit tests and fuzzing (the
//! kernel's verifier and JIT are the real thing). Memory is a set of regions (context, stack,
//! packet, map values), each at its own 4 GiB-aligned base address; any access outside a
//! region, an unknown instruction or helper, or running too long is an error, which is what the
//! verifier would have rejected. Maps are modelled for one CPU.

use std::collections::HashMap;

use crate::ebpf::*;

/// A simulated map.
#[derive(Clone, Debug)]
pub(crate) struct SimMap {
    pub(crate) key_size: usize,
    pub(crate) value_size: usize,
    /// Most entries (the LRU evicts the oldest, an array is pre-filled).
    pub(crate) max_entries: usize,
    /// key -> value region.
    entries: HashMap<Vec<u8>, usize>,
    /// Insertion order, for LRU eviction.
    order: Vec<Vec<u8>>,
}

impl SimMap {
    pub(crate) fn hash(key_size: usize, value_size: usize, max_entries: usize) -> SimMap {
        SimMap {
            key_size,
            value_size,
            max_entries,
            entries: HashMap::new(),
            order: Vec::new(),
        }
    }
}

/// What the program did besides its return value.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Effects {
    /// The key passed to `bpf_sk_select_reuseport`, if called.
    pub(crate) selected: Option<u32>,
}

const STACK: usize = 512;
const CTX_BASE: u64 = 1 << 32;
const STACK_REGION: usize = 1;
const PKT_REGION: usize = 2;
const MAP_PTR: u64 = 0xf000_0000_0000_0000;

/// The interpreter's state: maps (by the fd the program names them with), the clock and the
/// regions of the current run.
#[derive(Debug, Default)]
pub(crate) struct Vm {
    pub(crate) maps: HashMap<i32, SimMap>,
    /// `bpf_ktime_get_ns`.
    pub(crate) now: u64,
    /// `bpf_get_smp_processor_id`.
    pub(crate) cpu: u32,
    /// Region 0 is the context (no bytes; its loads are special), 1 the stack, 2 the packet,
    /// then map values.
    regions: Vec<Vec<u8>>,
}

fn base(region: usize) -> u64 {
    (region as u64 + 1) << 32
}

impl Vm {
    pub(crate) fn new() -> Vm {
        Vm {
            regions: vec![Vec::new(), vec![0; STACK], Vec::new()],
            ..Vm::default()
        }
    }

    pub(crate) fn add_map(&mut self, fd: i32, m: SimMap) {
        self.maps.insert(fd, m);
    }

    /// Sets `key` of map `fd` to `value` (as `BPF_MAP_UPDATE_ELEM` from userspace).
    pub(crate) fn update(&mut self, fd: i32, key: &[u8], value: &[u8]) -> Result<(), String> {
        let n = self.regions.len();
        let m = self.maps.get_mut(&fd).ok_or("no such map")?;
        if key.len() != m.key_size || value.len() != m.value_size {
            return Err("bad key or value size".into());
        }
        if let Some(&r) = m.entries.get(key) {
            self.regions[r] = value.to_vec();
            return Ok(());
        }
        if m.entries.len() >= m.max_entries {
            let oldest = m.order.remove(0);
            m.entries.remove(&oldest);
        }
        m.entries.insert(key.to_vec(), n);
        m.order.push(key.to_vec());
        self.regions.push(value.to_vec());
        Ok(())
    }

    /// The value under `key` of map `fd`.
    pub(crate) fn lookup(&self, fd: i32, key: &[u8]) -> Option<&[u8]> {
        let r = *self.maps.get(&fd)?.entries.get(key)?;
        Some(&self.regions[r])
    }

    pub(crate) fn entries(&self, fd: i32) -> usize {
        self.maps.get(&fd).map_or(0, |m| m.entries.len())
    }

    fn resolve(&mut self, addr: u64, size: usize) -> Result<&mut [u8], String> {
        let region = (addr >> 32) as usize;
        let off = (addr & 0xffff_ffff) as usize;
        if region == 0 || region > self.regions.len() {
            return Err(format!("access to bad address {addr:#x}"));
        }
        let r = &mut self.regions[region - 1];
        let len = r.len();
        r.get_mut(off..off + size)
            .ok_or_else(|| format!("{size}-byte access at {off} of a {len}-byte region"))
    }

    fn read(&mut self, addr: u64, size: usize) -> Result<u64, String> {
        let b = self.resolve(addr, size)?;
        let mut v = [0u8; 8];
        #[cfg(target_endian = "little")]
        v[..size].copy_from_slice(b);
        #[cfg(target_endian = "big")]
        v[8 - size..].copy_from_slice(b);
        Ok(u64::from_ne_bytes(v))
    }

    fn write(&mut self, addr: u64, size: usize, value: u64) -> Result<(), String> {
        let v = value.to_ne_bytes();
        let b = self.resolve(addr, size)?;
        #[cfg(target_endian = "little")]
        b.copy_from_slice(&v[..size]);
        #[cfg(target_endian = "big")]
        b.copy_from_slice(&v[8 - size..]);
        Ok(())
    }

    fn bytes(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        Ok(self.resolve(addr, len)?.to_vec())
    }

    fn map_of(&self, ptr: u64) -> Result<i32, String> {
        if ptr & MAP_PTR != MAP_PTR {
            return Err("not a map".into());
        }
        Ok((ptr & 0xffff_ffff) as u32 as i32)
    }

    /// Runs `prog` on `pkt`: an XDP program sees it from the Ethernet header (context loads at
    /// 0 and 4 are `data` and `data_end`); a reuseport program reads it through
    /// `bpf_skb_load_bytes_relative` from the network header.
    pub(crate) fn run(&mut self, prog: &[Insn], pkt: &[u8]) -> Result<(u64, Effects), String> {
        self.regions[STACK_REGION] = vec![0; STACK];
        self.regions[PKT_REGION] = pkt.to_vec();
        let pkt_start = base(PKT_REGION);
        let mut r = [0u64; 11];
        r[1] = CTX_BASE;
        r[10] = base(STACK_REGION) + STACK as u64;
        let mut fx = Effects::default();
        let mut pc = 0usize;
        for _ in 0..100_000 {
            let i = *prog.get(pc).ok_or("fell off the end")?;
            pc += 1;
            let (d, s) = (i.dst() as usize, i.src() as usize);
            if d > 10 || s > 10 {
                return Err("bad register".into());
            }
            let k64 = i64::from(i.imm) as u64;
            let class = i.code & 0x07;
            match class {
                // ALU (32-bit) and ALU64.
                0x04 | 0x07 => {
                    let op = i.code & 0xf0;
                    if class == 0x04 && op == 0xd0 {
                        // BPF_END: to big endian.
                        let v = r[d];
                        r[d] = match (i.code & 0x08 != 0, i.imm) {
                            (true, 16) => u64::from((v as u16).to_be()),
                            (true, 32) => u64::from((v as u32).to_be()),
                            (true, 64) => v.to_be(),
                            _ => return Err("unsupported byte swap".into()),
                        };
                        continue;
                    }
                    let x = if i.code & 0x08 != 0 { r[s] } else { k64 };
                    if d == 10 {
                        return Err("write to r10".into());
                    }
                    let a = r[d];
                    let v = match op {
                        0x00 => a.wrapping_add(x),
                        0x10 => a.wrapping_sub(x),
                        0x20 => a.wrapping_mul(x),
                        0x40 => a | x,
                        0x50 => a & x,
                        0x60 => a.wrapping_shl(x as u32),
                        0x70 => a.wrapping_shr(x as u32),
                        0x90 if class == 0x04 => {
                            let x = x as u32;
                            if x == 0 { 0 } else { u64::from(a as u32 % x) }
                        }
                        0xa0 => a ^ x,
                        0xb0 => x,
                        _ => return Err(format!("unsupported alu {:#x}", i.code)),
                    };
                    r[d] = if class == 0x04 {
                        // 32-bit ops (shifts by the low 5 bits).
                        let (a, x) = (a as u32, x as u32);
                        u64::from(match op {
                            0x20 => a.wrapping_mul(x),
                            0x60 => a.wrapping_shl(x),
                            0x70 => a.wrapping_shr(x),
                            _ => v as u32,
                        })
                    } else {
                        v
                    };
                }
                // LDX MEM.
                0x01 => {
                    let size = [4, 2, 1, 8][usize::from((i.code >> 3) & 3)];
                    let addr = r[s].wrapping_add(i64::from(i.off) as u64);
                    r[d] = if addr >> 32 == CTX_BASE >> 32 {
                        match (addr & 0xffff_ffff, size) {
                            (0, 4) => pkt_start,
                            (4, 4) => pkt_start + pkt.len() as u64,
                            _ => return Err("unsupported context load".into()),
                        }
                    } else {
                        self.read(addr, size)?
                    };
                }
                // ST / STX MEM.
                0x02 | 0x03 => {
                    let size = [4, 2, 1, 8][usize::from((i.code >> 3) & 3)];
                    let v = if class == 0x03 { r[s] } else { k64 };
                    self.write(r[d].wrapping_add(i64::from(i.off) as u64), size, v)?;
                }
                // LD IMM64.
                0x00 if i.code == LD_IMM64 => {
                    let hi = prog.get(pc).ok_or("truncated ld_imm64")?.imm as u32;
                    pc += 1;
                    r[d] = if i.src() == PSEUDO_MAP_FD {
                        MAP_PTR | u64::from(i.imm as u32)
                    } else {
                        u64::from(i.imm as u32) | (u64::from(hi) << 32)
                    };
                }
                0x05 => match i.code {
                    CALL => r[0] = self.call(i.imm, &r, &mut fx)?,
                    EXIT => return Ok((r[0], fx)),
                    JMP_JA => pc = jump(pc, i.off)?,
                    c => {
                        let x = if c & 0x08 != 0 { r[s] } else { k64 };
                        let a = r[d];
                        let taken = match c & 0xf0 {
                            0x10 => a == x,
                            0x20 => a > x,
                            0x30 => a >= x,
                            0x50 => a != x,
                            0xa0 => a < x,
                            0xb0 => a <= x,
                            _ => return Err(format!("unsupported jump {c:#x}")),
                        };
                        if taken {
                            pc = jump(pc, i.off)?;
                        }
                    }
                },
                _ => return Err(format!("unsupported instruction {:#x}", i.code)),
            }
        }
        Err("too many instructions".into())
    }

    fn call(&mut self, f: i32, r: &[u64; 11], fx: &mut Effects) -> Result<u64, String> {
        Ok(match f {
            FN_MAP_LOOKUP_ELEM => {
                let fd = self.map_of(r[1])?;
                let ks = self.maps.get(&fd).ok_or("no such map")?.key_size;
                let key = self.bytes(r[2], ks)?;
                match self.maps[&fd].entries.get(&key) {
                    Some(&region) => base(region),
                    None => 0,
                }
            }
            FN_MAP_UPDATE_ELEM => {
                let fd = self.map_of(r[1])?;
                let m = self.maps.get(&fd).ok_or("no such map")?;
                let (ks, vs) = (m.key_size, m.value_size);
                let key = self.bytes(r[2], ks)?;
                let value = self.bytes(r[3], vs)?;
                self.update(fd, &key, &value)?;
                0
            }
            FN_KTIME_GET_NS => self.now,
            FN_GET_SMP_PROCESSOR_ID => u64::from(self.cpu),
            FN_SKB_LOAD_BYTES_RELATIVE => {
                if r[1] != CTX_BASE || r[5] != HDR_START_NET as u64 {
                    return Err("bad skb_load_bytes_relative arguments".into());
                }
                let (off, len) = (r[2] as usize, r[4] as usize);
                if len == 0 || len > STACK {
                    return Err("bad length".into());
                }
                // Check the destination even when the packet is too short.
                self.resolve(r[3], len)?;
                match self.regions[PKT_REGION].get(off..off.saturating_add(len)) {
                    Some(b) => {
                        let b = b.to_vec();
                        self.resolve(r[3], len)?.copy_from_slice(&b);
                        0
                    }
                    None => (-14i64) as u64, // -EFAULT
                }
            }
            FN_SK_SELECT_REUSEPORT => {
                if r[1] != CTX_BASE {
                    return Err("bad context".into());
                }
                self.map_of(r[2])?;
                fx.selected = Some(self.read(r[3], 4)? as u32);
                0
            }
            _ => return Err(format!("unsupported helper {f}")),
        })
    }
}

fn jump(pc: usize, off: i16) -> Result<usize, String> {
    if off < 0 {
        return Err("backward jump".into());
    }
    Ok(pc + off as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::steer::{HashKey, SLOTS, Steering, expected_index, slot_table};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const SOCKS: i32 = 3;
    const SLOT_MAP: i32 = 4;
    const SOURCES: i32 = 5;
    const COUNTERS_MAP: i32 = 6;

    /// IPv4 or IPv6 + TCP header (flags `flags`) from `src` to `dst`, from the network header.
    fn net_packet(src: SocketAddr, dst: SocketAddr, flags: u8) -> Vec<u8> {
        let mut p = Vec::new();
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                p.extend([0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
                p.extend(s.octets());
                p.extend(d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                p.extend([0x60, 0, 0, 0, 0, 20, 6, 64]);
                p.extend(s.octets());
                p.extend(d.octets());
            }
            _ => unreachable!(),
        }
        p.extend(src.port().to_be_bytes());
        p.extend(dst.port().to_be_bytes());
        p.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p
    }

    fn frame(net: &[u8]) -> Vec<u8> {
        let ethertype: u16 = if net[0] >> 4 == 6 { 0x86dd } else { 0x0800 };
        let mut f = vec![0u8; 12];
        f.extend(ethertype.to_be_bytes());
        f.extend(net);
        f
    }

    fn hash_vm(n: usize) -> Vm {
        let mut vm = Vm::new();
        vm.add_map(SOCKS, SimMap::hash(4, 8, n));
        vm.add_map(SLOT_MAP, SimMap::hash(4, 4, SLOTS));
        for (s, &i) in slot_table(n).iter().enumerate() {
            vm.update(
                SLOT_MAP,
                &(s as u32).to_ne_bytes(),
                &u32::from(i).to_ne_bytes(),
            )
            .unwrap();
        }
        vm
    }

    #[test]
    fn ebpf_hash_matches_the_classic_program_and_the_userspace_hash() {
        let local4: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let local6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        for key in [HashKey::SrcIp, HashKey::SrcIpPort] {
            let prog = reuseport_hash(SOCKS, SLOT_MAP, key);
            for n in [1usize, 2, 3, 7, 16, SLOTS] {
                let mut vm = hash_vm(n);
                let classic = crate::cbpf::program(Steering::Hash(key), n);
                for i in 0..200u32 {
                    let port = 1024 + (i * 7919 % 60000) as u16;
                    let src4 = SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(i.wrapping_mul(2654435761))),
                        port,
                    );
                    let src6 = SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(
                            u128::from(i).wrapping_mul(0x9e3779b97f4a7c15_f39cc0605cedc835),
                        )),
                        port,
                    );
                    for (src, local) in [(src4, local4), (src6, local6)] {
                        let pkt = net_packet(src, local, 0x02);
                        let (ret, fx) = vm.run(&prog, &pkt).unwrap();
                        assert_eq!(ret, SK_PASS as u64);
                        let want = expected_index(Steering::Hash(key), n, src, local).unwrap();
                        assert_eq!(fx.selected, Some(want as u32), "{key:?} n={n} {src}");
                        assert_eq!(crate::cbpf::run(&classic, &pkt, 0) as usize, want);
                    }
                }
                // IPv4 with options: the ports follow the options.
                let mut pkt = net_packet("10.9.8.7:5555".parse().unwrap(), local4, 0x02);
                pkt[0] = 0x46;
                pkt.splice(20..20, [1, 1, 1, 1]);
                let (_, fx) = vm.run(&prog, &pkt).unwrap();
                assert_eq!(fx.selected, Some(crate::cbpf::run(&classic, &pkt, 0)));
            }
        }
    }

    #[test]
    fn ebpf_hash_leaves_unparsable_packets_to_the_kernel() {
        let prog = reuseport_hash(SOCKS, SLOT_MAP, HashKey::SrcIpPort);
        let mut vm = hash_vm(4);
        for pkt in [&[][..], &[0x45, 0, 0], &[0x60; 30], &[0x10; 64]] {
            let (ret, fx) = vm.run(&prog, pkt).unwrap();
            assert_eq!((ret, fx.selected), (SK_PASS as u64, None), "{pkt:?}");
        }
    }

    fn limiter(syn_only: bool, rate: u64, burst: u64) -> (Vm, Vec<Insn>) {
        let mut vm = Vm::new();
        vm.add_map(SOURCES, SimMap::hash(16, 16, 4));
        vm.add_map(COUNTERS_MAP, SimMap::hash(4, 8, COUNTERS as usize));
        for c in 0..COUNTERS {
            vm.update(COUNTERS_MAP, &c.to_ne_bytes(), &0u64.to_ne_bytes())
                .unwrap();
        }
        let cost = 1_000_000_000 / rate;
        let prog = xdp_rate_limit(LimitProg {
            sources: SOURCES,
            counters: COUNTERS_MAP,
            cost,
            cap: cost * burst,
            syn_only,
        });
        vm.now = 1_000_000_000_000;
        (vm, prog)
    }

    fn counter(vm: &Vm, c: i32) -> u64 {
        let v = vm.lookup(COUNTERS_MAP, &(c as u32).to_ne_bytes()).unwrap();
        u64::from_ne_bytes(v.try_into().unwrap())
    }

    #[test]
    fn xdp_limits_each_source_to_its_burst_then_its_rate() {
        let (mut vm, prog) = limiter(false, 10, 5);
        let dst: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let a = frame(&net_packet("10.1.1.1:1000".parse().unwrap(), dst, 0x10));
        let b = frame(&net_packet(
            "[2001:db8::7]:1000".parse().unwrap(),
            "[2001:db8::1]:80".parse().unwrap(),
            0x10,
        ));
        let verdicts = |vm: &mut Vm, f: &[u8], n: usize| -> Vec<u64> {
            (0..n).map(|_| vm.run(&prog, f).unwrap().0).collect()
        };
        // Burst of 5, all at the same instant: 5 pass, the rest drop.
        let v = verdicts(&mut vm, &a, 8);
        assert_eq!(v, [2, 2, 2, 2, 2, 1, 1, 1]);
        // Another source has its own bucket.
        assert_eq!(verdicts(&mut vm, &b, 6), [2, 2, 2, 2, 2, 1]);
        // 10/s: 250 ms later, two more (100 ms each, the remainder kept).
        vm.now += 250_000_000;
        assert_eq!(verdicts(&mut vm, &a, 3), [2, 2, 1]);
        vm.now += 50_000_000;
        assert_eq!(verdicts(&mut vm, &a, 2), [2, 1]);
        // A long pause refills to the burst, not beyond.
        vm.now += 3600 * 1_000_000_000;
        assert_eq!(verdicts(&mut vm, &a, 7), [2, 2, 2, 2, 2, 1, 1]);
        assert_eq!(counter(&vm, CTR_NEW), 2);
        assert_eq!(counter(&vm, CTR_DROPPED), 3 + 1 + 1 + 1 + 2);
        assert_eq!(counter(&vm, CTR_PASSED), 4 + 4 + 2 + 1 + 5);
        // The key is the IPv4-mapped address.
        let mut key = vec![0u8; 10];
        key.extend([0xff, 0xff, 10, 1, 1, 1]);
        assert!(vm.lookup(SOURCES, &key).is_some());
    }

    #[test]
    fn xdp_syn_mode_counts_only_syns() {
        let (mut vm, prog) = limiter(true, 1, 2);
        let dst: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let src: SocketAddr = "10.1.1.1:1000".parse().unwrap();
        let syn = frame(&net_packet(src, dst, 0x02));
        let synack = frame(&net_packet(src, dst, 0x12));
        let ack = frame(&net_packet(src, dst, 0x10));
        let run = |vm: &mut Vm, f: &[u8]| vm.run(&prog, f).unwrap().0;
        assert_eq!(run(&mut vm, &syn), 2);
        assert_eq!(run(&mut vm, &syn), 2);
        assert_eq!(run(&mut vm, &syn), 1);
        for _ in 0..10 {
            assert_eq!(run(&mut vm, &ack), 2);
            assert_eq!(run(&mut vm, &synack), 2);
        }
        // IPv6 SYNs too.
        let syn6 = frame(&net_packet(
            "[2001:db8::7]:1000".parse().unwrap(),
            "[2001:db8::1]:80".parse().unwrap(),
            0x02,
        ));
        assert_eq!(run(&mut vm, &syn6), 2);
        assert_eq!(run(&mut vm, &syn6), 2);
        assert_eq!(run(&mut vm, &syn6), 1);
        // A non-first fragment, UDP and IPv4 with options.
        let mut frag = syn.clone();
        frag[14 + 6] = 0x00;
        frag[14 + 7] = 0x10;
        assert_eq!(run(&mut vm, &frag), 2);
        let mut udp = syn;
        udp[14 + 9] = 17;
        assert_eq!(run(&mut vm, &udp), 2);
        let mut opts = net_packet(src, dst, 0x02);
        opts[0] = 0x46;
        opts.splice(20..20, [1, 1, 1, 1]);
        assert_eq!(run(&mut vm, &frame(&opts)), 1);
        assert_eq!(counter(&vm, CTR_DROPPED), 3);
    }

    #[test]
    fn xdp_passes_what_it_does_not_understand() {
        let (mut vm, prog) = limiter(false, 1, 1);
        for f in [&[][..], &[0u8; 13], &[0u8; 14], &[0u8; 60]] {
            assert_eq!(vm.run(&prog, f).unwrap().0, 2);
        }
        // Truncated IPv4 / IPv6 headers.
        let mut v4 = vec![0u8; 12];
        v4.extend([8, 0, 0x45, 0]);
        assert_eq!(vm.run(&prog, &v4).unwrap().0, 2);
        let mut v6 = vec![0u8; 12];
        v6.extend([0x86, 0xdd]);
        v6.extend([0x60; 39]);
        assert_eq!(vm.run(&prog, &v6).unwrap().0, 2);
        assert_eq!(vm.entries(SOURCES), 0);
    }
}
