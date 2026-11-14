//! The kernel's CSPRNG: `getrandom(2)` on Linux, `getentropy(2)` on macOS, `/dev/urandom` when
//! the syscall is missing (Linux before 3.17) or blocked (seccomp).

use std::io;

/// Fills `buf` with cryptographically secure random bytes from the kernel. Blocks only until the
/// kernel pool is initialised at boot.
#[doc(hidden)]
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    match sys_fill(buf) {
        Err(e)
            if e.raw_os_error() == Some(libc::ENOSYS) || e.raw_os_error() == Some(libc::EPERM) =>
        {
            urandom(buf)
        }
        r => r,
    }
}

fn urandom(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

#[cfg(target_os = "linux")]
fn sys_fill(mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is a live, writable slice of `buf.len()` bytes for the whole call; the
        // kernel writes at most that many bytes and returns how many it wrote.
        let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        // `n` is non-negative and at most `buf.len()`.
        buf = &mut buf[n as usize..];
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn sys_fill(buf: &mut [u8]) -> io::Result<()> {
    // getentropy fills at most 256 bytes per call.
    for chunk in buf.chunks_mut(256) {
        // SAFETY: `chunk` is a live, writable slice of `chunk.len()` (<= 256) bytes; getentropy
        // writes exactly that many bytes or fails.
        let r = unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills() {
        for n in [0usize, 1, 16, 255, 256, 257, 1000] {
            let mut a = vec![0u8; n];
            let mut b = vec![0u8; n];
            fill_random(&mut a).unwrap();
            fill_random(&mut b).unwrap();
            if n >= 16 {
                assert_ne!(a, b);
                assert!(a.iter().any(|&x| x != 0));
            }
        }
        let mut c = [0u8; 64];
        urandom(&mut c).unwrap();
        assert!(c.iter().any(|&x| x != 0));
    }
}
