//! File systems: the size and free space of the one a path is on ([`space`]), as `df` reports
//! them.
//!
//! ```
//! let space = akio_sys::fs::space(std::path::Path::new("/"))?;
//! assert!(space.available <= space.total);
//! # Ok::<(), std::io::Error>(())
//! ```

use std::ffi::{CStr, CString};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::ffi;

/// The size and free space of a file system, in bytes ([`space`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Space {
    /// The file system's size: `df`'s "size".
    pub total: u64,
    /// Its free space, counting what is kept for root (`f_bfree`): `total - free` is `df`'s
    /// "used".
    pub free: u64,
    /// Its free space for a process that is not root (`f_bavail`): `df`'s "available". Less
    /// than [`free`](Self::free) by what the file system keeps for root (ext4's 5% by default).
    pub available: u64,
}

/// The size and free space of the file system `path` is on, a file or a directory, as `df`
/// reports them: `statvfs(3)` on Linux, `statfs(2)` on macOS (whose `statvfs` counts blocks in
/// 32 bits). Each count of blocks is multiplied by the fundamental block size (`f_frsize` on
/// Linux, `f_bsize` on macOS), saturating at `u64::MAX`.
///
/// An error when `path` cannot be reached (`NotFound`, `PermissionDenied`...) or holds a NUL
/// byte (`InvalidInput`). The call may block: on a network file system whose server does not
/// answer it waits as long as the mount says, so a caller with a deadline runs it off its I/O
/// threads.
pub fn space(path: &Path) -> io::Result<Space> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    query(&path)
}

#[cfg(target_os = "linux")]
fn query(path: &CStr) -> io::Result<Space> {
    let mut s = MaybeUninit::<ffi::statvfs>::uninit();
    loop {
        // SAFETY: `path` is NUL-terminated and outlives the call; `s` is valid for writes of one
        // `statvfs`, whose layout matches the C library's (checked in `ffi::layout`).
        if unsafe { ffi::statvfs(path.as_ptr(), s.as_mut_ptr()) } == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    // SAFETY: statvfs succeeded, so it filled the whole structure.
    let s = unsafe { s.assume_init() };
    // `f_frsize` is the unit of the block counts; a file system that leaves it 0 counts in
    // `f_bsize`, as `df` falls back to.
    let unit = if s.f_frsize == 0 {
        s.f_bsize
    } else {
        s.f_frsize
    };
    Ok(Space {
        total: s.f_blocks.saturating_mul(unit),
        free: s.f_bfree.saturating_mul(unit),
        available: s.f_bavail.saturating_mul(unit),
    })
}

#[cfg(target_os = "macos")]
fn query(path: &CStr) -> io::Result<Space> {
    let mut s = MaybeUninit::<ffi::statfs>::uninit();
    loop {
        // SAFETY: `path` is NUL-terminated and outlives the call; `s` is valid for writes of one
        // `statfs` in the 64-bit-inode layout the declaration links to (checked in
        // `ffi::layout`).
        if unsafe { ffi::statfs(path.as_ptr(), s.as_mut_ptr()) } == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    // SAFETY: statfs succeeded, so it filled the whole structure.
    let s = unsafe { s.assume_init() };
    let unit = u64::from(s.f_bsize);
    Ok(Space {
        total: s.f_blocks.saturating_mul(unit),
        free: s.f_bfree.saturating_mul(unit),
        available: s.f_bavail.saturating_mul(unit),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The size as the `libc` crate's own binding reads it (the size does not change while the
    /// test runs; the free space may).
    fn libc_total(path: &Path) -> u64 {
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        #[cfg(target_os = "linux")]
        {
            // SAFETY: an all-zero statvfs is valid; `c` is NUL-terminated.
            let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
            // SAFETY: as above; `s` is a writable statvfs.
            assert_eq!(unsafe { libc::statvfs(c.as_ptr(), &raw mut s) }, 0);
            let unit = if s.f_frsize == 0 {
                s.f_bsize
            } else {
                s.f_frsize
            };
            s.f_blocks * unit
        }
        #[cfg(target_os = "macos")]
        {
            // SAFETY: an all-zero statfs is valid; `c` is NUL-terminated.
            let mut s: libc::statfs = unsafe { std::mem::zeroed() };
            // SAFETY: as above; `s` is a writable statfs.
            assert_eq!(unsafe { libc::statfs(c.as_ptr(), &raw mut s) }, 0);
            s.f_blocks * u64::from(s.f_bsize)
        }
    }

    #[test]
    fn space_of_a_directory_and_a_file() {
        let dir = std::env::temp_dir();
        let s = space(&dir).unwrap();
        assert!(s.total > 0, "{s:?}");
        assert!(s.free <= s.total && s.available <= s.total, "{s:?}");
        assert_eq!(s.total, libc_total(&dir));

        let file = dir.join(format!("akio-sys-space-{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let of_file = space(&file);
        std::fs::remove_file(&file).unwrap();
        assert_eq!(of_file.unwrap().total, s.total);

        assert_eq!(
            space(Path::new("/")).unwrap().total,
            libc_total(Path::new("/"))
        );
    }

    #[test]
    fn space_errors() {
        let gone = std::env::temp_dir().join(format!("akio-sys-space-gone-{}", std::process::id()));
        assert_eq!(space(&gone).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(
            space(Path::new("a\0b")).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
