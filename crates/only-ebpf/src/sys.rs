//! Raw kernel interfaces (Linux): `bpf(2)` commands and the socket options used here. No
//! libbpf/aya: the programs are a dozen hand-assembled instructions, so the workspace builds
//! with a stable toolchain and no BPF compiler.

use std::{
    ffi::c_void,
    io,
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

use crate::cbpf;
use only_sys::ffi;

use ffi::{SO_ATTACH_REUSEPORT_CBPF, SO_ATTACH_REUSEPORT_EBPF, SO_COOKIE};

const BPF_MAP_CREATE: ffi::c_long = 0;
const BPF_MAP_LOOKUP_ELEM: ffi::c_long = 1;
const BPF_MAP_UPDATE_ELEM: ffi::c_long = 2;
const BPF_MAP_DELETE_ELEM: ffi::c_long = 3;
const BPF_PROG_LOAD: ffi::c_long = 5;
const BPF_OBJ_PIN: ffi::c_long = 6;
const BPF_OBJ_GET: ffi::c_long = 7;
const BPF_PROG_ATTACH: ffi::c_long = 8;
const BPF_OBJ_GET_INFO_BY_FD: ffi::c_long = 15;
const BPF_LINK_CREATE: ffi::c_long = 28;

pub(crate) const MAP_ARRAY: u32 = 2;
pub(crate) const MAP_PERCPU_ARRAY: u32 = 6;
pub(crate) const MAP_LRU_PERCPU_HASH: u32 = 10;
pub(crate) const MAP_XSKMAP: u32 = 17;
pub(crate) const MAP_SOCKHASH: u32 = 18;
pub(crate) const MAP_REUSEPORT_SOCKARRAY: u32 = 20;
pub(crate) const PROG_XDP: u32 = 6;
pub(crate) const PROG_SK_SKB: u32 = 14;
pub(crate) const PROG_SK_REUSEPORT: u32 = 21;
pub(crate) const ATTACH_SK_SKB_STREAM_VERDICT: u32 = 5;
pub(crate) const ATTACH_SK_REUSEPORT_SELECT: u32 = 39;
pub(crate) const ATTACH_SK_REUSEPORT_SELECT_OR_MIGRATE: u32 = 40;
pub(crate) const ATTACH_XDP: u32 = 37;

fn cvt(r: ffi::c_int) -> io::Result<ffi::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// `bpf(cmd, attr, size_of_val(attr))`.
///
/// # Safety
///
/// `T` must be the `#[repr(C)]` layout of the prefix of `union bpf_attr` that `cmd` reads, with
/// no uninitialised padding the kernel would check (it rejects non-zero unknown tail bytes), and
/// every pointer field (encoded as `u64`) must be valid for the reads or writes the kernel
/// performs for `cmd`, with the sizes the attr states, for the duration of the call.
unsafe fn bpf<T>(cmd: ffi::c_long, attr: &mut T) -> io::Result<ffi::c_int> {
    // SAFETY: `attr` is a valid, initialized `#[repr(C)]` prefix of `union bpf_attr` for `cmd`
    // (caller), and the size passed is its exact size; the kernel zero-extends shorter attrs.
    let r = unsafe {
        ffi::syscall(
            ffi::SYS_bpf,
            cmd,
            std::ptr::from_mut::<T>(attr).cast::<c_void>(),
            size_of::<T>(),
        )
    };
    cvt(r as ffi::c_int)
}

fn owned(fd: ffi::c_int) -> OwnedFd {
    // SAFETY: `fd` was just returned by the kernel and is owned by nobody else.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[repr(C)]
struct MapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

/// `BPF_MAP_CREATE`.
fn map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> io::Result<OwnedFd> {
    let mut a = MapCreate {
        map_type,
        key_size,
        value_size,
        max_entries,
        map_flags: 0,
    };
    // SAFETY: `MapCreate` is the BPF_MAP_CREATE prefix of `bpf_attr`; it holds no pointers.
    unsafe { bpf(BPF_MAP_CREATE, &mut a) }.map(owned)
}

#[repr(C)]
struct MapElem {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// `BPF_MAP_UPDATE_ELEM` (`BPF_ANY`).
///
/// # Safety
///
/// `size_of::<K>()` and `size_of::<V>()` must equal the map's `key_size` and `value_size`: the
/// kernel copies that many bytes from `key` and `value`, and a smaller type would let it read
/// past the referenced value.
unsafe fn map_update<K, V>(map: RawFd, key: &K, value: &V) -> io::Result<()> {
    let mut a = MapElem {
        map_fd: map as u32,
        _pad: 0,
        key: std::ptr::from_ref::<K>(key) as u64,
        value: std::ptr::from_ref::<V>(value) as u64,
        flags: 0,
    };
    // SAFETY: `MapElem` is the element-command prefix of `bpf_attr`; `key` and `value` point to
    // live values of the map's key and value sizes (caller).
    unsafe { bpf(BPF_MAP_UPDATE_ELEM, &mut a) }.map(drop)
}

/// `BPF_MAP_LOOKUP_ELEM` into `out`.
///
/// # Safety
///
/// `size_of::<K>()` must equal the map's `key_size`, and `out` must be at least as long as what
/// the kernel writes for the map: `value_size`, or for per-CPU maps `value_size` rounded up to 8
/// times the number of possible CPUs.
unsafe fn map_lookup<K>(map: RawFd, key: &K, out: &mut [u8]) -> io::Result<()> {
    let mut a = MapElem {
        map_fd: map as u32,
        _pad: 0,
        key: std::ptr::from_ref::<K>(key) as u64,
        value: out.as_mut_ptr() as u64,
        flags: 0,
    };
    // SAFETY: `MapElem` is the element-command prefix of `bpf_attr`; `key` points to a key of
    // the map's size and `out` is large enough for what the kernel writes (caller).
    unsafe { bpf(BPF_MAP_LOOKUP_ELEM, &mut a) }.map(drop)
}

/// `BPF_MAP_DELETE_ELEM`.
///
/// # Safety
///
/// `size_of::<K>()` must equal the map's `key_size` (see [`map_update`]).
unsafe fn map_delete<K>(map: RawFd, key: &K) -> io::Result<()> {
    let mut a = MapElem {
        map_fd: map as u32,
        _pad: 0,
        key: std::ptr::from_ref::<K>(key) as u64,
        value: 0,
        flags: 0,
    };
    // SAFETY: as in `map_update`; `value` is unused (0) for this command.
    unsafe { bpf(BPF_MAP_DELETE_ELEM, &mut a) }.map(drop)
}

/// A BPF map whose key and value sizes are those of `K` and `V`, fixed at creation: this ties
/// the sizes `map_update`/`map_delete` rely on to the types, so the typed methods are safe.
pub(crate) struct Map<K, V> {
    fd: OwnedFd,
    _kv: std::marker::PhantomData<fn(&K, &V)>,
}

impl<K: Copy, V: Copy> Map<K, V> {
    /// `BPF_MAP_CREATE` of `map_type` with `max_entries` entries of `K` -> `V`.
    pub(crate) fn create(map_type: u32, max_entries: u32) -> io::Result<Self> {
        let fd = map_create(
            map_type,
            size_of::<K>() as u32,
            size_of::<V>() as u32,
            max_entries,
        )?;
        Ok(Map {
            fd,
            _kv: std::marker::PhantomData,
        })
    }

    /// The map's descriptor (for `LD_IMM64` map references and `BPF_PROG_ATTACH`).
    pub(crate) fn fd(&self) -> RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.fd)
    }

    /// `BPF_MAP_UPDATE_ELEM` (`BPF_ANY`).
    pub(crate) fn update(&self, key: &K, value: &V) -> io::Result<()> {
        // SAFETY: the map was created with exactly `size_of::<K>()` / `size_of::<V>()`.
        unsafe { map_update(self.fd(), key, value) }
    }

    /// `BPF_MAP_DELETE_ELEM`.
    pub(crate) fn delete(&self, key: &K) -> io::Result<()> {
        // SAFETY: as in `update`.
        unsafe { map_delete(self.fd(), key) }
    }
}

impl<K: Copy, V: Copy> Map<K, V> {
    /// Opens the map pinned at `path` (`BPF_OBJ_GET`), checking that it is a `map_type` map
    /// whose key and value sizes are those of `K` and `V` (which is what makes the typed methods
    /// safe on it). Returns the map and its `max_entries`.
    pub(crate) fn open_pinned(path: &std::path::Path, map_type: u32) -> io::Result<(Self, u32)> {
        let fd = obj_get(path)?;
        let info = map_info(std::os::fd::AsRawFd::as_raw_fd(&fd))?;
        if info.map_type != map_type
            || info.key_size as usize != size_of::<K>()
            || info.value_size as usize != size_of::<V>()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: not the expected BPF map (type {}, key {} bytes, value {} bytes)",
                    path.display(),
                    info.map_type,
                    info.key_size,
                    info.value_size
                ),
            ));
        }
        Ok((
            Map {
                fd,
                _kv: std::marker::PhantomData,
            },
            info.max_entries,
        ))
    }

    /// Pins the map at `path` (`BPF_OBJ_PIN`; the directory must be on a bpffs mount).
    pub(crate) fn pin(&self, path: &std::path::Path) -> io::Result<()> {
        obj_pin(self.fd(), path)
    }
}

impl<K: Copy, const N: usize> Map<K, [u32; N]> {
    /// `BPF_MAP_LOOKUP_ELEM` of a (non per-CPU) map of `[u32; N]` values.
    pub(crate) fn lookup(&self, key: &K) -> io::Result<[u32; N]> {
        let mut out = vec![0u8; N * 4];
        // SAFETY: the key size is `size_of::<K>()` and the value size `4 * N` (creation or
        // `open_pinned` checked it); a non per-CPU map writes exactly `value_size` bytes.
        unsafe { map_lookup(self.fd(), key, &mut out) }?;
        let mut v = [0u32; N];
        for (d, c) in v.iter_mut().zip(out.chunks_exact(4)) {
            *d = u32::from_ne_bytes([c[0], c[1], c[2], c[3]]);
        }
        Ok(v)
    }
}

impl<K: Copy> Map<K, u64> {
    /// `BPF_MAP_LOOKUP_ELEM` of a per-CPU map of `u64`s: one value per possible CPU.
    pub(crate) fn lookup_percpu(&self, key: &K) -> io::Result<Vec<u64>> {
        let cpus = possible_cpus()?;
        let mut out = vec![0u8; cpus * 8];
        // SAFETY: the key size is `size_of::<K>()` (creation); a per-CPU map of 8-byte values
        // writes exactly 8 bytes per possible CPU, which is `out`'s length.
        unsafe { map_lookup(self.fd(), key, &mut out) }?;
        Ok(out
            .chunks_exact(8)
            .map(|c| u64::from_ne_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
            .collect())
    }
}

/// Number of possible CPUs (the per-CPU map value count): one more than the highest CPU in
/// `/sys/devices/system/cpu/possible` (e.g. "0-15" or "0,2-3").
pub(crate) fn possible_cpus() -> io::Result<usize> {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible")?;
    parse_cpu_list(&s)
        .map(|max| max + 1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("cpu list {s:?}")))
}

/// The highest CPU of a kernel CPU list.
fn parse_cpu_list(s: &str) -> Option<usize> {
    s.trim()
        .split(',')
        .map(|r| r.rsplit('-').next()?.trim().parse::<usize>().ok())
        .try_fold(0, |m, v| Some(m.max(v?)))
}

#[repr(C)]
struct ObjPin {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

fn c_path(path: &std::path::Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path with NUL"))
}

/// `BPF_OBJ_PIN`: pins the map, program or link `fd` at `path` on a bpffs mount, where it stays
/// (and keeps the object alive) until the file is removed.
pub(crate) fn obj_pin(fd: RawFd, path: &std::path::Path) -> io::Result<()> {
    let p = c_path(path)?;
    let mut a = ObjPin {
        pathname: p.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    // SAFETY: `ObjPin` is the BPF_OBJ_PIN prefix of `bpf_attr`; `pathname` points to the
    // NUL-terminated `p`, alive until the call returns.
    unsafe { bpf(BPF_OBJ_PIN, &mut a) }.map(drop)
}

/// `BPF_OBJ_GET`: a new descriptor (read-write) for the object pinned at `path`.
pub(crate) fn obj_get(path: &std::path::Path) -> io::Result<OwnedFd> {
    let p = c_path(path)?;
    let mut a = ObjPin {
        pathname: p.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    // SAFETY: as in `obj_pin`.
    unsafe { bpf(BPF_OBJ_GET, &mut a) }.map(owned)
}

#[repr(C)]
struct InfoByFd {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// The first fields of `struct bpf_map_info`.
#[repr(C)]
#[derive(Default)]
pub(crate) struct MapInfo {
    pub(crate) map_type: u32,
    pub(crate) id: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
}

/// `BPF_OBJ_GET_INFO_BY_FD` of a map (the fields above; the kernel copies only `info_len`
/// bytes).
pub(crate) fn map_info(fd: RawFd) -> io::Result<MapInfo> {
    let mut info = MapInfo::default();
    let mut a = InfoByFd {
        bpf_fd: fd as u32,
        info_len: size_of::<MapInfo>() as u32,
        info: (&raw mut info) as u64,
    };
    // SAFETY: `InfoByFd` is the BPF_OBJ_GET_INFO_BY_FD prefix of `bpf_attr`; `info` points to
    // `info_len` writable bytes alive until the call returns.
    unsafe { bpf(BPF_OBJ_GET_INFO_BY_FD, &mut a) }?;
    Ok(info)
}

/// The type of the program `fd` (first field of `struct bpf_prog_info`).
pub(crate) fn prog_type(fd: RawFd) -> io::Result<u32> {
    let mut info = [0u32; 4];
    let mut a = InfoByFd {
        bpf_fd: fd as u32,
        info_len: size_of_val(&info) as u32,
        info: info.as_mut_ptr() as u64,
    };
    // SAFETY: as in `map_info`; `info` has `info_len` writable bytes.
    unsafe { bpf(BPF_OBJ_GET_INFO_BY_FD, &mut a) }?;
    Ok(info[0])
}

#[repr(C)]
struct ProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// `BPF_PROG_LOAD`. On a verifier rejection the error carries the start of the verifier log.
pub(crate) fn prog_load(
    prog_type: u32,
    expected_attach_type: u32,
    insns: &[crate::ebpf::Insn],
    name: &str,
) -> io::Result<OwnedFd> {
    prog_load_flags(prog_type, expected_attach_type, insns, name, 0)
}

/// `BPF_F_XDP_HAS_FRAGS`: an XDP program that handles multi-buffer frames (Linux 5.18+).
pub(crate) const BPF_F_XDP_HAS_FRAGS: u32 = 1 << 5;

/// [`prog_load`] with `prog_flags`.
pub(crate) fn prog_load_flags(
    prog_type: u32,
    expected_attach_type: u32,
    insns: &[crate::ebpf::Insn],
    name: &str,
    prog_flags: u32,
) -> io::Result<OwnedFd> {
    let mut log = vec![0u8; 16 << 10];
    let mut prog_name = [0u8; 16];
    for (d, s) in prog_name.iter_mut().zip(name.bytes().take(15)) {
        *d = s;
    }
    let license = b"GPL\0";
    let mut a = ProgLoad {
        prog_type,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags,
        prog_name,
        prog_ifindex: 0,
        expected_attach_type,
    };
    // SAFETY: `ProgLoad` is the BPF_PROG_LOAD prefix of `bpf_attr`; `insns` points to
    // `insn_cnt` instructions, `license` to a NUL-terminated string and `log_buf` to `log_size`
    // writable bytes, all alive until the call returns.
    match unsafe { bpf(BPF_PROG_LOAD, &mut a) } {
        Ok(fd) => Ok(owned(fd)),
        Err(e) => {
            let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
            let text = String::from_utf8_lossy(&log[..end.min(600)]);
            if text.trim().is_empty() {
                Err(e)
            } else {
                Err(io::Error::new(e.kind(), format!("{e}: {}", text.trim())))
            }
        }
    }
}

#[repr(C)]
struct ProgAttach {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
}

/// `BPF_PROG_ATTACH` of `prog` to `target` (a map fd for sockmap programs).
pub(crate) fn prog_attach(target: RawFd, prog: RawFd, attach_type: u32) -> io::Result<()> {
    let mut a = ProgAttach {
        target_fd: target as u32,
        attach_bpf_fd: prog as u32,
        attach_type,
        attach_flags: 0,
    };
    // SAFETY: `ProgAttach` is the BPF_PROG_ATTACH prefix of `bpf_attr`; it holds no pointers.
    unsafe { bpf(BPF_PROG_ATTACH, &mut a) }.map(drop)
}

#[repr(C)]
struct LinkCreate {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
}

/// `BPF_LINK_CREATE` of the XDP program `prog` on interface `ifindex` with XDP mode `flags`.
/// The program stays attached while the returned link fd (or a copy of it) is open.
pub(crate) fn xdp_link_create(prog: RawFd, ifindex: u32, flags: u32) -> io::Result<OwnedFd> {
    let mut a = LinkCreate {
        prog_fd: prog as u32,
        target_ifindex: ifindex,
        attach_type: ATTACH_XDP,
        flags,
    };
    // SAFETY: `LinkCreate` is the BPF_LINK_CREATE prefix of `bpf_attr`; it holds no pointers.
    unsafe { bpf(BPF_LINK_CREATE, &mut a) }.map(owned)
}

const AF_NETLINK: ffi::c_int = 16;
const NETLINK_ROUTE: ffi::c_int = 0;

/// A `NETLINK_ROUTE` socket.
pub(crate) fn netlink_route() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with constant arguments; the result is checked.
    let fd =
        cvt(unsafe { ffi::socket(AF_NETLINK, ffi::SOCK_RAW | ffi::SOCK_CLOEXEC, NETLINK_ROUTE) })?;
    Ok(owned(fd))
}

/// `write(2)` of a whole message (netlink sends datagrams).
pub(crate) fn write_all(fd: RawFd, msg: &[u8]) -> io::Result<()> {
    // SAFETY: `msg` is valid for reads of its length for the duration of the call.
    let n = unsafe { ffi::write(fd, msg.as_ptr().cast::<c_void>(), msg.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != msg.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short netlink write",
        ));
    }
    Ok(())
}

/// `read(2)` into `buf`.
pub(crate) fn read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid for writes of its length for the duration of the call.
    let n = unsafe { ffi::read(fd, buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// `if_nametoindex(3)`.
pub(crate) fn if_index(name: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name with NUL"))?;
    // SAFETY: `c` is a NUL-terminated string alive for the duration of the call.
    match unsafe { ffi::if_nametoindex(c.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        i => Ok(i),
    }
}

const SIOCOUTQ: ffi::c_ulong = 0x5411;
const TCP_INFO: ffi::c_int = 11;

fn ioctl_int(fd: RawFd, req: ffi::c_ulong) -> io::Result<usize> {
    let mut n: ffi::c_int = 0;
    // SAFETY: SIOCOUTQ writes one int to the pointer, which is valid for that write.
    cvt(unsafe { ffi::ioctl(fd, req, &raw mut n) })?;
    Ok(n.max(0) as usize)
}

/// `ioctl(SIOCOUTQ)`: bytes in the socket's send queue not acknowledged yet.
pub(crate) fn unsent_bytes(fd: RawFd) -> io::Result<usize> {
    ioctl_int(fd, SIOCOUTQ)
}

/// `(tcpi_bytes_received, tcpi_bytes_acked)` of `TCP_INFO` (Linux 4.1+).
pub(crate) fn tcp_bytes(fd: RawFd) -> io::Result<(u64, u64)> {
    let mut info = [0u64; 32];
    let mut len = size_of_val(&info) as ffi::socklen_t;
    // SAFETY: `info` and `len` are valid for writes and `len` holds the size of `info`; the
    // kernel writes at most `len` bytes.
    cvt(unsafe {
        ffi::getsockopt(
            fd,
            ffi::IPPROTO_TCP,
            TCP_INFO,
            info.as_mut_ptr().cast::<c_void>(),
            &raw mut len,
        )
    })?;
    // struct tcp_info: tcpi_bytes_acked is the u64 at byte 120, tcpi_bytes_received at 128.
    if (len as usize) < 136 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_INFO without tcpi_bytes_received",
        ));
    }
    Ok((info[16], info[15]))
}

fn setsockopt<T>(fd: RawFd, name: ffi::c_int, v: &T) -> io::Result<()> {
    // SAFETY: `v` is valid for reads of `size_of::<T>()` bytes for the duration of the call.
    cvt(unsafe {
        ffi::setsockopt(
            fd,
            ffi::SOL_SOCKET,
            name,
            std::ptr::from_ref::<T>(v).cast::<c_void>(),
            size_of::<T>() as ffi::socklen_t,
        )
    })
    .map(drop)
}

#[repr(C)]
struct Fprog {
    len: u16,
    filter: *const cbpf::Insn,
}

/// `SO_ATTACH_REUSEPORT_CBPF`: attaches `prog` to the reuseport group of `fd`.
pub(crate) fn attach_reuseport_cbpf(fd: RawFd, prog: &[cbpf::Insn]) -> io::Result<()> {
    let len = u16::try_from(prog.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cBPF program too long"))?;
    let p = Fprog {
        len,
        filter: prog.as_ptr(),
    };
    setsockopt(fd, SO_ATTACH_REUSEPORT_CBPF, &p)
}

/// `SO_ATTACH_REUSEPORT_EBPF`: attaches the loaded program `prog` to the group of `fd`.
pub(crate) fn attach_reuseport_ebpf(fd: RawFd, prog: RawFd) -> io::Result<()> {
    setsockopt(fd, SO_ATTACH_REUSEPORT_EBPF, &(prog as ffi::c_int))
}

/// `SO_RCVLOWAT` (the kernel caps it at half the largest receive buffer; setting it runs the
/// socket's data_ready if the queue now reaches it).
pub(crate) fn set_rcvlowat(fd: RawFd, v: i32) -> io::Result<()> {
    const SO_RCVLOWAT: ffi::c_int = 18;
    setsockopt(fd, SO_RCVLOWAT, &(v as ffi::c_int))
}

/// `SO_COOKIE`: the socket's unique, never reused 64-bit id.
pub(crate) fn socket_cookie(fd: RawFd) -> io::Result<u64> {
    let mut v = 0u64;
    let mut len = size_of::<u64>() as ffi::socklen_t;
    // SAFETY: `v` and `len` are valid for writes and `len` holds the size of `v`.
    cvt(unsafe {
        ffi::getsockopt(
            fd,
            ffi::SOL_SOCKET,
            SO_COOKIE,
            (&raw mut v).cast::<c_void>(),
            &raw mut len,
        )
    })?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    #[test]
    fn cpu_lists() {
        assert_eq!(super::parse_cpu_list("0-15\n"), Some(15));
        assert_eq!(super::parse_cpu_list("0"), Some(0));
        assert_eq!(super::parse_cpu_list("0,2-3,7"), Some(7));
        assert_eq!(super::parse_cpu_list(""), None);
    }
}
