//! Raw kernel interfaces (Linux): `bpf(2)` commands and the socket options used here. No
//! libbpf/aya: the programs are a dozen hand-assembled instructions, so the workspace builds
//! with a stable toolchain and no BPF compiler.

use std::{
    ffi::c_void,
    io,
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

use crate::cbpf;

const SO_ATTACH_REUSEPORT_CBPF: libc::c_int = 51;
const SO_ATTACH_REUSEPORT_EBPF: libc::c_int = 52;
const SO_COOKIE: libc::c_int = 57;

const BPF_MAP_CREATE: libc::c_long = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_MAP_DELETE_ELEM: libc::c_long = 3;
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_ATTACH: libc::c_long = 8;

pub(crate) const MAP_SOCKHASH: u32 = 18;
pub(crate) const MAP_REUSEPORT_SOCKARRAY: u32 = 20;
pub(crate) const PROG_SK_SKB: u32 = 14;
pub(crate) const PROG_SK_REUSEPORT: u32 = 21;
pub(crate) const ATTACH_SK_SKB_STREAM_VERDICT: u32 = 5;
pub(crate) const ATTACH_SK_REUSEPORT_SELECT: u32 = 39;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
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
unsafe fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> io::Result<libc::c_int> {
    // SAFETY: `attr` is a valid, initialized `#[repr(C)]` prefix of `union bpf_attr` for `cmd`
    // (caller), and the size passed is its exact size; the kernel zero-extends shorter attrs.
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            std::ptr::from_mut::<T>(attr).cast::<c_void>(),
            size_of::<T>(),
        )
    };
    cvt(r as libc::c_int)
}

fn owned(fd: libc::c_int) -> OwnedFd {
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
        prog_flags: 0,
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

fn setsockopt<T>(fd: RawFd, name: libc::c_int, v: &T) -> io::Result<()> {
    // SAFETY: `v` is valid for reads of `size_of::<T>()` bytes for the duration of the call.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            std::ptr::from_ref::<T>(v).cast::<c_void>(),
            size_of::<T>() as libc::socklen_t,
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
    setsockopt(fd, SO_ATTACH_REUSEPORT_EBPF, &(prog as libc::c_int))
}

/// `SO_COOKIE`: the socket's unique, never reused 64-bit id.
pub(crate) fn socket_cookie(fd: RawFd) -> io::Result<u64> {
    let mut v = 0u64;
    let mut len = size_of::<u64>() as libc::socklen_t;
    // SAFETY: `v` and `len` are valid for writes and `len` holds the size of `v`.
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_COOKIE,
            (&raw mut v).cast::<c_void>(),
            &raw mut len,
        )
    })?;
    Ok(v)
}
