//! A terminal's input modes, changed for as long as a guard lives: echo off to read a password
//! ([`no_echo`]), or raw mode to read it a key at a time ([`raw`]), as Go's
//! `golang.org/x/term` does (`ReadPassword`, `MakeRaw`). The guard restores the settings it
//! found when it is dropped or [`restore`](TerminalGuard::restore)d.
//!
//! ```no_run
//! use std::io::Read;
//! use std::os::fd::AsFd;
//!
//! let stdin = std::io::stdin();
//! let guard = akio_sys::terminal::raw(stdin.as_fd())?; // an error if stdin is not a terminal
//! let mut key = [0u8; 1];
//! stdin.lock().read_exact(&mut key)?; // one key, not echoed
//! guard.restore()?;
//! # Ok::<(), std::io::Error>(())
//! ```

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::ffi;

/// A terminal whose modes [`no_echo`] or [`raw`] changed; dropping it (or
/// [`restore`](Self::restore)) puts back the modes it found. It borrows the descriptor, so the
/// descriptor outlives it.
///
/// A process that exits without dropping the guard (`std::process::exit`, a signal that kills
/// it) leaves the terminal as the guard set it; a shell's `reset` or `stty sane` puts it back.
#[derive(Debug)]
pub struct TerminalGuard<'fd> {
    fd: BorrowedFd<'fd>,
    saved: ffi::termios,
    restored: bool,
}

impl TerminalGuard<'_> {
    /// Puts back the modes the guard found, reporting an error that dropping it would ignore.
    pub fn restore(mut self) -> io::Result<()> {
        self.restored = true;
        set(self.fd, &self.saved)
    }
}

impl Drop for TerminalGuard<'_> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = set(self.fd, &self.saved);
        }
    }
}

/// Turns the echo of the terminal `fd` off (`ECHO`), keeping line editing (`ICANON`) and
/// signals (`ISIG`, so Ctrl-C still interrupts) and turning `ICRNL` on, as Go's
/// `term.ReadPassword`: input is read a line at a time and not shown. A newline typed is not
/// echoed either (`ECHONL` off), so the caller prints one after reading.
///
/// An error for a descriptor that is not a terminal (`ENOTTY`).
pub fn no_echo(fd: BorrowedFd<'_>) -> io::Result<TerminalGuard<'_>> {
    change(fd, |t| {
        t.c_lflag &= !(ffi::ECHO | ffi::ECHONL);
        t.c_lflag |= ffi::ICANON | ffi::ISIG;
        t.c_iflag |= ffi::ICRNL;
    })
}

/// Puts the terminal `fd` in raw mode, as `cfmakeraw(3)` and Go's `term.MakeRaw`: no echo, no
/// line editing, no signals from keys (Ctrl-C arrives as byte 3), no input or output
/// translation, 8-bit characters, a read returns as soon as one byte is there. For reading a
/// password a key at a time (and showing a `*` for each); the caller handles backspace, Ctrl-C
/// and Enter (byte 13, since `ICRNL` is off) itself, and writes `"\r\n"` for a new line since
/// output post-processing (`OPOST`) is off.
///
/// An error for a descriptor that is not a terminal (`ENOTTY`).
pub fn raw(fd: BorrowedFd<'_>) -> io::Result<TerminalGuard<'_>> {
    change(fd, |t| {
        t.c_iflag &= !(ffi::IGNBRK
            | ffi::BRKINT
            | ffi::PARMRK
            | ffi::ISTRIP
            | ffi::INLCR
            | ffi::IGNCR
            | ffi::ICRNL
            | ffi::IXON);
        t.c_oflag &= !ffi::OPOST;
        t.c_lflag &= !(ffi::ECHO | ffi::ECHONL | ffi::ICANON | ffi::ISIG | ffi::IEXTEN);
        t.c_cflag &= !(ffi::CSIZE | ffi::PARENB);
        t.c_cflag |= ffi::CS8;
        t.c_cc[ffi::VMIN] = 1;
        t.c_cc[ffi::VTIME] = 0;
    })
}

/// Whether the terminal `fd`'s echo is on; an error for a descriptor that is not a terminal.
pub fn echo_enabled(fd: BorrowedFd<'_>) -> io::Result<bool> {
    Ok(get(fd)?.c_lflag & ffi::ECHO != 0)
}

fn change(
    fd: BorrowedFd<'_>,
    edit: impl FnOnce(&mut ffi::termios),
) -> io::Result<TerminalGuard<'_>> {
    let saved = get(fd)?;
    let mut t = saved;
    edit(&mut t);
    set(fd, &t)?;
    Ok(TerminalGuard {
        fd,
        saved,
        restored: false,
    })
}

fn get(fd: BorrowedFd<'_>) -> io::Result<ffi::termios> {
    let mut t = MaybeUninit::<ffi::termios>::uninit();
    // SAFETY: `fd` is a live descriptor (borrowed); `t` is valid for writes of one `termios`,
    // whose layout matches the C library's (checked in `ffi::layout`).
    if unsafe { ffi::tcgetattr(fd.as_raw_fd(), t.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `tcgetattr` succeeded, so it filled the whole structure.
    Ok(unsafe { t.assume_init() })
}

fn set(fd: BorrowedFd<'_>, t: &ffi::termios) -> io::Result<()> {
    loop {
        // SAFETY: `fd` is a live descriptor (borrowed); `t` points to an initialized `termios`
        // read by the call only.
        if unsafe { ffi::tcsetattr(fd.as_raw_fd(), ffi::TCSANOW, t) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd, FromRawFd};

    /// A pseudo-terminal pair: (controller, terminal).
    fn pty() -> (File, File) {
        // SAFETY: plain calls of the C library on descriptors this function owns; `ptsname`
        // returns a static buffer read before any other call that could change it.
        unsafe {
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(m >= 0, "posix_openpt: {}", io::Error::last_os_error());
            assert_eq!(libc::grantpt(m), 0);
            assert_eq!(libc::unlockpt(m), 0);
            let name = libc::ptsname(m);
            assert!(!name.is_null());
            let s = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(s >= 0, "open pts: {}", io::Error::last_os_error());
            (File::from_raw_fd(m), File::from_raw_fd(s))
        }
    }

    #[test]
    fn no_echo_and_restore() {
        let (_m, t) = pty();
        let before = get(t.as_fd()).unwrap();
        assert!(echo_enabled(t.as_fd()).unwrap());
        {
            let _g = no_echo(t.as_fd()).unwrap();
            let now = get(t.as_fd()).unwrap();
            assert_eq!(now.c_lflag & ffi::ECHO, 0);
            assert_ne!(now.c_lflag & ffi::ICANON, 0);
            assert_ne!(now.c_lflag & ffi::ISIG, 0);
        }
        let after = get(t.as_fd()).unwrap();
        assert_eq!(after.c_lflag, before.c_lflag);
        assert_eq!(after.c_iflag, before.c_iflag);
        assert!(echo_enabled(t.as_fd()).unwrap());
    }

    #[test]
    fn raw_reads_a_key_without_echo() {
        use std::io::{Read, Write};
        let (mut m, t) = pty();
        let before = get(t.as_fd()).unwrap();
        let g = raw(t.as_fd()).unwrap();
        let now = get(t.as_fd()).unwrap();
        assert_eq!(now.c_lflag & (ffi::ECHO | ffi::ICANON | ffi::ISIG), 0);
        assert_eq!(now.c_oflag & ffi::OPOST, 0);
        assert_eq!(now.c_cc[ffi::VMIN], 1);
        // A key typed on the controller side reaches the terminal side at once (no line
        // discipline), and nothing is echoed back.
        m.write_all(b"x").unwrap();
        let mut b = [0u8; 1];
        (&t).read_exact(&mut b).unwrap();
        assert_eq!(&b, b"x");
        g.restore().unwrap();
        let after = get(t.as_fd()).unwrap();
        // The modes the guard changed are back. (macOS's kernel may add `PENDIN`, a state bit,
        // on the way back to canonical mode.)
        let local = ffi::ECHO | ffi::ECHONL | ffi::ICANON | ffi::ISIG | ffi::IEXTEN;
        assert_eq!(after.c_lflag & local, before.c_lflag & local);
        assert_eq!(after.c_iflag, before.c_iflag);
        assert_eq!(after.c_oflag, before.c_oflag);
        assert_eq!(after.c_cflag, before.c_cflag);
        assert_eq!(after.c_cc, before.c_cc);
        // Nothing was echoed: the controller has nothing to read.
        // SAFETY: fcntl on a descriptor this test owns.
        unsafe {
            let fl = libc::fcntl(m.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(m.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        let mut echo = [0u8; 8];
        let r = m.read(&mut echo);
        assert!(
            matches!(&r, Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "{r:?}"
        );
    }

    #[test]
    fn not_a_terminal() {
        // A regular file (`/dev/null` is a device: macOS answers `ENODEV` for it).
        let f = File::open(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(
            no_echo(f.as_fd()).unwrap_err().raw_os_error(),
            Some(libc::ENOTTY)
        );
        assert_eq!(
            raw(f.as_fd()).unwrap_err().raw_os_error(),
            Some(libc::ENOTTY)
        );
        assert!(echo_enabled(f.as_fd()).is_err());
    }
}
