//! `SO_REUSEPORT` steering shared by several processes through bpffs (ADR-063).
//!
//! [`attach_reuseport`](crate::attach_reuseport) gives each process its own program and socket
//! array: in a group shared by several processes (prefork workers binding the same port), the
//! last process to attach replaces the group's program with one that only knows its own
//! sockets. [`SharedSteering`] instead pins one program and one `REUSEPORT_SOCKARRAY` in bpffs:
//! a supervisor [creates](SharedSteering::create) them for `sockets` slots, every worker
//! [opens](SharedSteering::open) them and [joins](SharedSteering::join) its sockets at its
//! own slots, and a restarted or reloaded worker simply overwrites its slots. Attaching the
//! pinned program again from every worker is harmless: it is the same program.
//!
//! The program is loaded for `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` when the kernel has it
//! (Linux 5.14+): when a listener closes, the kernel moves its accept queue and its pending
//! handshakes to another listener of the group, and the program picks the socket now in the
//! migrating flow's slot, which after a reload is the new worker's (see
//! [`SharedSteering::migrates`]).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{fmt, io, path::Path, path::PathBuf, sync::Arc};

use crate::{SteerInfo, Steering};

/// Version tag stored in the pinned `meta` map.
const MAGIC: u32 = 0x6f6e_6c01; // "onl" 1
/// Most slots a shared group may have.
pub const MAX_SHARED_SOCKETS: usize = 4096;

/// A steering program and socket array pinned in a bpffs directory, shared by the
/// `SO_REUSEPORT` sockets of several processes. Cheap to clone; see the [module docs](self).
///
/// The handle returned by [`create`](Self::create) owns the pins: when its last clone is
/// dropped the pinned files and the directory are removed (the program stays attached to the
/// group as long as one of its sockets is open). Handles from [`open`](Self::open) do not.
#[derive(Clone)]
pub struct SharedSteering {
    inner: Arc<Inner>,
    first: usize,
    count: usize,
}

struct Inner {
    dir: PathBuf,
    sockets: usize,
    steering: Steering,
    migrate: bool,
    owner: bool,
    #[cfg(target_os = "linux")]
    objs: imp::Objects,
}

impl fmt::Debug for SharedSteering {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSteering")
            .field("dir", &self.inner.dir)
            .field("sockets", &self.inner.sockets)
            .field("steering", &self.inner.steering)
            .field("migrate", &self.inner.migrate)
            .field("slots", &(self.first..self.first + self.count))
            .finish()
    }
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

impl SharedSteering {
    /// Loads a steering program for a group of `sockets` sockets with policy `steering` (the
    /// same policies, and for [`Steering::Hash`] the same hash and Maglev table, as
    /// [`attach_reuseport`](crate::attach_reuseport) over `sockets` threads) and pins it with
    /// its maps in `dir` (created if missing; pins left there by an earlier owner that died
    /// are replaced). `dir` must be on a bpffs mount, usually under `/sys/fs/bpf`, and bpffs
    /// names cannot contain `.`. Needs
    /// `CAP_BPF` (or `CAP_SYS_ADMIN`); fails with `Unsupported` off Linux.
    pub fn create(
        dir: impl AsRef<Path>,
        sockets: usize,
        steering: Steering,
    ) -> io::Result<SharedSteering> {
        let dir = dir.as_ref().to_path_buf();
        if sockets == 0 || sockets > MAX_SHARED_SOCKETS {
            return Err(invalid(format!(
                "a shared steering group has 1 to {MAX_SHARED_SOCKETS} sockets, not {sockets}"
            )));
        }
        if matches!(steering, Steering::Hash(_)) && sockets > crate::SLOTS {
            return Err(invalid(format!(
                "hash steering supports at most {} sockets",
                crate::SLOTS
            )));
        }
        #[cfg(target_os = "linux")]
        {
            let (objs, migrate) = imp::Objects::create(&dir, sockets, steering)?;
            Ok(SharedSteering {
                inner: Arc::new(Inner {
                    dir,
                    sockets,
                    steering,
                    migrate,
                    owner: true,
                    objs,
                }),
                first: 0,
                count: sockets,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = dir;
            Err(unsupported())
        }
    }

    /// Opens the program and maps another process [created](Self::create) in `dir`.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<SharedSteering> {
        let dir = dir.as_ref().to_path_buf();
        #[cfg(target_os = "linux")]
        {
            let (objs, sockets, steering, migrate) = imp::Objects::open(&dir)?;
            Ok(SharedSteering {
                inner: Arc::new(Inner {
                    dir,
                    sockets,
                    steering,
                    migrate,
                    owner: false,
                    objs,
                }),
                first: 0,
                count: sockets,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = dir;
            Err(unsupported())
        }
    }

    /// A handle that [joins](Self::join) at slots `first..first + count` (by default a handle
    /// covers every slot). Prefork worker `i` with `t` I/O threads takes `at(i * t, t)`.
    /// Fails with `InvalidInput` when the range does not fit in the group.
    pub fn at(&self, first: usize, count: usize) -> io::Result<SharedSteering> {
        if count == 0
            || first
                .checked_add(count)
                .is_none_or(|end| end > self.inner.sockets)
        {
            return Err(invalid(format!(
                "slots {first}..{} outside a group of {} sockets",
                first.saturating_add(count),
                self.inner.sockets
            )));
        }
        Ok(SharedSteering {
            inner: self.inner.clone(),
            first,
            count,
        })
    }

    /// The pin directory.
    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }

    /// Slots (sockets) in the whole group.
    pub fn sockets(&self) -> usize {
        self.inner.sockets
    }

    /// The first slot and the number of slots this handle joins at.
    pub fn slots(&self) -> (usize, usize) {
        (self.first, self.count)
    }

    /// The policy.
    pub fn steering(&self) -> Steering {
        self.inner.steering
    }

    /// Whether the program was loaded for `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` (Linux 5.14+):
    /// then a closing listener's queued connections and pending handshakes move to the socket
    /// now in their slot, even with `net.ipv4.tcp_migrate_req` off. Otherwise they move to a
    /// random live listener only when that sysctl is on, and are reset when it is off.
    pub fn migrates(&self) -> bool {
        self.inner.migrate
    }

    /// Puts `fds` (this process's listening sockets of the group, its I/O threads in order) in
    /// this handle's slots, from the first, and attaches the pinned program to their group.
    /// Slots of the handle beyond `fds.len()` are emptied (flows hashed there fall back to the
    /// kernel's choice). Fails with `InvalidInput` when there are more sockets than slots.
    pub fn join(&self, fds: &[i32]) -> io::Result<SteerInfo> {
        if fds.is_empty() || fds.len() > self.count {
            return Err(invalid(format!(
                "{} sockets for {} shared steering slots",
                fds.len(),
                self.count
            )));
        }
        #[cfg(target_os = "linux")]
        {
            self.inner.objs.join(self.first, self.count, fds)?;
            Ok(SteerInfo {
                tier: crate::Tier::Ebpf,
                steering: self.inner.steering,
                sockets: fds.len(),
                ebpf_unavailable: None,
                pinned_threads: 0,
                shared: true,
                migrate: self.inner.migrate,
            })
        }
        #[cfg(not(target_os = "linux"))]
        Err(unsupported())
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.owner {
            imp::remove_pins(&self.dir);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "shared SO_REUSEPORT steering is Linux-only",
    )
}

/// Encodes a policy for the `meta` map.
fn steering_code(s: Steering) -> u32 {
    match s {
        Steering::Hash(crate::HashKey::SrcIp) => 1,
        Steering::Hash(crate::HashKey::SrcIpPort) => 2,
        _ => 0,
    }
}

fn steering_from(code: u32) -> Option<Steering> {
    match code {
        0 => Some(Steering::Cpu),
        1 => Some(Steering::Hash(crate::HashKey::SrcIp)),
        2 => Some(Steering::Hash(crate::HashKey::SrcIpPort)),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        io,
        os::fd::{AsRawFd, OwnedFd},
        path::Path,
    };

    use super::*;
    use crate::{ebpf, sys};

    const PROG: &str = "prog";
    const SOCKS: &str = "socks";
    const SLOTS: &str = "slots";
    const META: &str = "meta";

    pub(super) struct Objects {
        prog: OwnedFd,
        socks: sys::Map<u32, u64>,
    }

    /// Removes the pins of `dir` and the directory itself (best effort).
    pub(super) fn remove_pins(dir: &Path) {
        // `meta` first: an `open` racing with this sees an incomplete group as absent.
        for name in [META, PROG, SOCKS, SLOTS] {
            let _ = std::fs::remove_file(dir.join(name));
        }
        let _ = std::fs::remove_dir(dir);
    }

    fn pin_context(e: io::Error, dir: &Path) -> io::Error {
        let dotted = dir.components().any(
            |c| matches!(c, std::path::Component::Normal(n) if n.to_string_lossy().contains('.')),
        );
        if e.raw_os_error() == Some(akio_sys::ffi::EPERM) && dotted {
            io::Error::new(
                e.kind(),
                format!(
                    "pinning in {}: {e} (bpffs does not allow '.' in names)",
                    dir.display()
                ),
            )
        } else if e.raw_os_error() == Some(akio_sys::ffi::EPERM) {
            io::Error::new(
                e.kind(),
                format!(
                    "pinning in {}: {e} (is it on a bpffs mount, and is the process privileged?)",
                    dir.display()
                ),
            )
        } else {
            io::Error::new(e.kind(), format!("pinning in {}: {e}", dir.display()))
        }
    }

    impl Objects {
        pub(super) fn create(
            dir: &Path,
            sockets: usize,
            steering: Steering,
        ) -> io::Result<(Objects, bool)> {
            let n = sockets as u32;
            let socks = sys::Map::<u32, u64>::create(sys::MAP_REUSEPORT_SOCKARRAY, n)?;
            let slots = sys::Map::<u32, u32>::create(sys::MAP_ARRAY, crate::SLOTS as u32)?;
            if matches!(steering, Steering::Hash(_)) {
                for (s, &i) in crate::steer::slot_table(sockets).iter().enumerate() {
                    slots.update(&(s as u32), &u32::from(i))?;
                }
            }
            let meta = sys::Map::<u32, [u32; 4]>::create(sys::MAP_ARRAY, 1)?;
            // SELECT_OR_MIGRATE first (5.14+), plain SELECT otherwise.
            let mut migrate = true;
            let prog = match sys::prog_load(
                sys::PROG_SK_REUSEPORT,
                sys::ATTACH_SK_REUSEPORT_SELECT_OR_MIGRATE,
                &ebpf::reuseport_shared(socks.fd(), slots.fd(), n, steering, true),
                "akio_steer_mig",
            ) {
                Ok(p) => p,
                Err(_) => {
                    migrate = false;
                    sys::prog_load(
                        sys::PROG_SK_REUSEPORT,
                        sys::ATTACH_SK_REUSEPORT_SELECT,
                        &ebpf::reuseport_shared(socks.fd(), slots.fd(), n, steering, false),
                        "akio_steer_shr",
                    )?
                }
            };
            meta.update(&0, &[MAGIC, n, steering_code(steering), u32::from(migrate)])?;
            remove_pins(dir);
            std::fs::create_dir_all(dir).map_err(|e| pin_context(e, dir))?;
            let pinned = (|| {
                sys::obj_pin(prog.as_raw_fd(), &dir.join(PROG))?;
                socks.pin(&dir.join(SOCKS))?;
                slots.pin(&dir.join(SLOTS))?;
                // Last: its presence marks a complete group for `open`.
                meta.pin(&dir.join(META))
            })();
            if let Err(e) = pinned {
                remove_pins(dir);
                return Err(pin_context(e, dir));
            }
            Ok((Objects { prog, socks }, migrate))
        }

        pub(super) fn open(dir: &Path) -> io::Result<(Objects, usize, Steering, bool)> {
            let (meta, _) =
                sys::Map::<u32, [u32; 4]>::open_pinned(&dir.join(META), sys::MAP_ARRAY)?;
            let [magic, n, code, migrate] = meta.lookup(&0)?;
            let steering = steering_from(code);
            if magic != MAGIC || steering.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: not a shared steering group of this version",
                        dir.display()
                    ),
                ));
            }
            let (socks, entries) =
                sys::Map::<u32, u64>::open_pinned(&dir.join(SOCKS), sys::MAP_REUSEPORT_SOCKARRAY)?;
            let prog = sys::obj_get(&dir.join(PROG))?;
            if entries != n || sys::prog_type(prog.as_raw_fd())? != sys::PROG_SK_REUSEPORT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: inconsistent shared steering group", dir.display()),
                ));
            }
            Ok((
                Objects { prog, socks },
                n as usize,
                steering.unwrap_or(Steering::Cpu),
                migrate != 0,
            ))
        }

        pub(super) fn join(&self, first: usize, count: usize, fds: &[i32]) -> io::Result<()> {
            for (i, &fd) in fds.iter().enumerate() {
                self.socks.update(&((first + i) as u32), &(fd as u64))?;
            }
            for slot in first + fds.len()..first + count {
                match self.socks.delete(&(slot as u32)) {
                    Err(e) if e.raw_os_error() != Some(akio_sys::ffi::ENOENT) => return Err(e),
                    _ => {}
                }
            }
            sys::attach_reuseport_ebpf(fds[0], self.prog.as_raw_fd())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_codes_round_trip() {
        for s in [
            Steering::Cpu,
            Steering::Hash(crate::HashKey::SrcIp),
            Steering::Hash(crate::HashKey::SrcIpPort),
        ] {
            assert_eq!(steering_from(steering_code(s)), Some(s));
        }
        assert_eq!(steering_from(9), None);
    }

    #[test]
    fn bad_sizes_are_rejected_before_the_kernel() {
        let dir = std::env::temp_dir();
        assert_eq!(
            SharedSteering::create(&dir, 0, Steering::Cpu)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            SharedSteering::create(
                &dir,
                crate::SLOTS + 1,
                Steering::Hash(crate::HashKey::SrcIp)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
