use std::io;
use std::mem;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain-old-data; all-zero is a valid value.
    let mut ss: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            // SAFETY: sockaddr_in fits in sockaddr_storage and shares its alignment.
            let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(a.ip().octets()),
            };
            #[cfg(target_os = "macos")]
            {
                sin.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            }
            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: as above for sockaddr_in6.
            let sin6 = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: a.ip().octets(),
            };
            sin6.sin6_scope_id = a.scope_id();
            #[cfg(target_os = "macos")]
            {
                sin6.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

/// Creates a non-blocking, close-on-exec TCP socket of the family of `addr`.
fn socket(addr: &SocketAddr) -> io::Result<OwnedFd> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    #[cfg(target_os = "linux")]
    let fd = cvt(unsafe {
        // SAFETY: plain syscall with valid constant arguments.
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    })?;
    #[cfg(not(target_os = "linux"))]
    let fd = {
        // SAFETY: plain syscall with valid constant arguments.
        let fd = cvt(unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) })?;
        crate::poller::set_nonblock_cloexec(fd)?;
        fd
    };
    // SAFETY: `fd` was just created by socket(2) and is owned by no one else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    v: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `v` outlives the call and the length matches its type.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &v as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    })
    .map(drop)
}

/// Binds and listens on `addr` with `SO_REUSEADDR`, and `SO_REUSEPORT` when `reuseport` is set.
/// The returned listener is non-blocking.
pub fn listen(addr: SocketAddr, reuseport: bool, backlog: i32) -> io::Result<TcpListener> {
    let fd = socket(&addr)?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    setsockopt_int(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    if reuseport {
        setsockopt_int(raw, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
    }
    if let SocketAddr::V6(_) = addr {
        setsockopt_int(raw, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0).ok();
    }
    let (ss, len) = sockaddr(&addr);
    // SAFETY: `ss` is a valid sockaddr of `len` bytes.
    cvt(unsafe { libc::bind(raw, &ss as *const _ as *const libc::sockaddr, len) })?;
    // SAFETY: plain syscall on an owned fd.
    cvt(unsafe { libc::listen(raw, backlog) })?;
    Ok(TcpListener::from(fd))
}

/// Starts a non-blocking connect. The stream becomes writable when the connect finished; check
/// `TcpStream::take_error` then.
pub fn connect_nonblocking(addr: SocketAddr) -> io::Result<TcpStream> {
    let fd = socket(&addr)?;
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    let (ss, len) = sockaddr(&addr);
    // SAFETY: `ss` is a valid sockaddr of `len` bytes.
    let r = unsafe { libc::connect(raw, &ss as *const _ as *const libc::sockaddr, len) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
    }
    Ok(TcpStream::from(fd))
}
