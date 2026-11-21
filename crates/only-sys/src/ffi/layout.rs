//! The own bindings compared with the `libc` crate (a dev-dependency): every structure's size,
//! alignment and field offsets, and every constant's type and value, on the target the tests
//! run on.

use std::mem::offset_of;

macro_rules! same_layout {
    ($ours:ty, $theirs:ty $(, $field:ident)* $(; $($ofield:ident = $tfield:ident),*)?) => {{
        assert_eq!(size_of::<$ours>(), size_of::<$theirs>(), "size of {}", stringify!($ours));
        assert_eq!(align_of::<$ours>(), align_of::<$theirs>(), "align of {}", stringify!($ours));
        $(
            assert_eq!(
                offset_of!($ours, $field),
                offset_of!($theirs, $field),
                "offset of {}::{}",
                stringify!($ours),
                stringify!($field)
            );
        )*
        $($(
            assert_eq!(
                offset_of!($ours, $ofield),
                offset_of!($theirs, $tfield),
                "offset of {}::{}",
                stringify!($ours),
                stringify!($ofield)
            );
        )*)?
    }};
}

macro_rules! same_value {
    ($($name:ident),* $(,)?) => {
        $(
            assert_eq!(
                super::$name,
                libc::$name,
                "value of {}",
                stringify!($name)
            );
        )*
    };
}

#[test]
fn common_layouts() {
    same_layout!(super::iovec, libc::iovec, iov_base, iov_len);
    same_layout!(super::in_addr, libc::in_addr, s_addr);
    same_layout!(super::in6_addr, libc::in6_addr, s6_addr);
    same_layout!(super::timespec, libc::timespec, tv_sec, tv_nsec);
    same_layout!(
        super::sockaddr_in,
        libc::sockaddr_in,
        sin_family,
        sin_port,
        sin_addr,
        sin_zero
    );
    same_layout!(
        super::sockaddr_in6,
        libc::sockaddr_in6,
        sin6_family,
        sin6_port,
        sin6_flowinfo,
        sin6_addr,
        sin6_scope_id
    );
    same_layout!(super::sockaddr_storage, libc::sockaddr_storage, ss_family);
    assert_eq!(size_of::<super::socklen_t>(), size_of::<libc::socklen_t>());
    assert_eq!(
        size_of::<super::sa_family_t>(),
        size_of::<libc::sa_family_t>()
    );
    assert_eq!(size_of::<super::pid_t>(), size_of::<libc::pid_t>());
    assert_eq!(size_of::<super::off_t>(), size_of::<libc::off_t>());
    // libc marks its musl `time_t` deprecated (a note about 32-bit targets); it is 64-bit here.
    #[allow(deprecated)]
    let libc_time_t = size_of::<libc::time_t>();
    assert_eq!(size_of::<super::time_t>(), libc_time_t);
    assert_eq!(size_of::<super::sigset_t>(), size_of::<libc::sigset_t>());
    assert_eq!(
        size_of::<super::sighandler_t>(),
        size_of::<libc::sighandler_t>()
    );
}

#[test]
fn common_constants() {
    same_value!(
        EPERM,
        ENOENT,
        ESRCH,
        EINTR,
        EBADF,
        EAGAIN,
        EINVAL,
        ENOSYS,
        EINPROGRESS,
        O_NONBLOCK,
        F_GETFD,
        F_SETFD,
        F_GETFL,
        F_SETFL,
        FD_CLOEXEC,
        AF_INET,
        AF_INET6,
        SOCK_STREAM,
        SOCK_DGRAM,
        SOL_SOCKET,
        SO_REUSEADDR,
        SO_REUSEPORT,
        IPPROTO_IPV6,
        IPV6_V6ONLY,
        SIGHUP,
        SIGINT,
        SIGQUIT,
        SIGTERM,
        SIGUSR1,
        SIGUSR2,
        SA_RESTART,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_layouts() {
    same_layout!(
        super::sockaddr_ll,
        libc::sockaddr_ll,
        sll_family,
        sll_protocol,
        sll_ifindex,
        sll_hatype,
        sll_pkttype,
        sll_halen,
        sll_addr
    );
    same_layout!(
        super::msghdr,
        libc::msghdr,
        msg_name,
        msg_namelen,
        msg_iov,
        msg_iovlen,
        msg_control,
        msg_controllen,
        msg_flags
    );
    same_layout!(super::mmsghdr, libc::mmsghdr, msg_hdr, msg_len);
    #[cfg(not(target_env = "musl"))]
    same_layout!(
        super::cmsghdr,
        libc::cmsghdr,
        cmsg_len,
        cmsg_level,
        cmsg_type
    );
    // musl spells `cmsg_len` as `socklen_t` plus an `int` of padding, so its `struct cmsghdr`
    // is 4-aligned; ours (and the kernel's, whose `cmsg_len` is `__kernel_size_t`) is
    // 8-aligned. Size and offsets are the same, and the CMSG_* macros of both libraries align
    // to `size_t`, so a header we build or read sits where musl's would.
    #[cfg(target_env = "musl")]
    {
        assert_eq!(size_of::<super::cmsghdr>(), size_of::<libc::cmsghdr>());
        assert_eq!(align_of::<super::cmsghdr>(), 8);
        assert_eq!(align_of::<libc::cmsghdr>(), 4);
        assert_eq!(
            offset_of!(super::cmsghdr, cmsg_level),
            offset_of!(libc::cmsghdr, cmsg_level)
        );
        assert_eq!(
            offset_of!(super::cmsghdr, cmsg_type),
            offset_of!(libc::cmsghdr, cmsg_type)
        );
    }
    same_layout!(super::epoll_event, libc::epoll_event, events, u64);
    same_layout!(
        super::tls_crypto_info,
        libc::tls_crypto_info,
        version,
        cipher_type
    );
    same_layout!(
        super::tls12_crypto_info_aes_gcm_128,
        libc::tls12_crypto_info_aes_gcm_128,
        info,
        iv,
        key,
        salt,
        rec_seq
    );
    same_layout!(
        super::tls12_crypto_info_aes_gcm_256,
        libc::tls12_crypto_info_aes_gcm_256,
        info,
        iv,
        key,
        salt,
        rec_seq
    );
    same_layout!(
        super::tls12_crypto_info_chacha20_poly1305,
        libc::tls12_crypto_info_chacha20_poly1305,
        info,
        iv,
        key,
        rec_seq
    );
    same_layout!(super::pollfd, libc::pollfd, fd, events, revents);
    same_layout!(super::cpu_set_t, libc::cpu_set_t);
    same_layout!(super::sigset_t, libc::sigset_t);
    same_layout!(
        super::sigaction,
        libc::sigaction,
        sa_sigaction,
        sa_mask,
        sa_flags,
        sa_restorer
    );
    same_layout!(
        super::ifaddrs,
        libc::ifaddrs,
        ifa_next,
        ifa_name,
        ifa_flags,
        ifa_addr,
        ifa_netmask,
        ifa_data
    );
    assert_eq!(size_of::<super::ifreq_data>(), size_of::<libc::ifreq>());
    same_layout!(
        super::utsname,
        libc::utsname,
        sysname,
        nodename,
        release,
        version,
        machine,
        domainname
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_constants() {
    same_value!(
        EBUSY,
        ETIME,
        ENOBUFS,
        ECANCELED,
        O_RDWR,
        O_CLOEXEC,
        AF_PACKET,
        SOCK_RAW,
        SOCK_NONBLOCK,
        SOCK_CLOEXEC,
        SO_RCVBUF,
        SO_RCVBUFFORCE,
        SO_ATTACH_REUSEPORT_CBPF,
        SO_ATTACH_REUSEPORT_EBPF,
        SO_COOKIE,
        SOL_UDP,
        UDP_SEGMENT,
        IN_NONBLOCK,
        IN_CLOEXEC,
        IN_MODIFY,
        IN_ATTRIB,
        IN_CLOSE_WRITE,
        IN_MOVED_FROM,
        IN_MOVED_TO,
        IN_CREATE,
        IN_DELETE,
        IN_DELETE_SELF,
        IN_MOVE_SELF,
        IN_UNMOUNT,
        IN_Q_OVERFLOW,
        IN_IGNORED,
        IN_ONLYDIR,
        IN_ISDIR,
        UDP_GRO,
        IPPROTO_IP,
        IP_TOS,
        IP_RECVTOS,
        IPV6_RECVTCLASS,
        IPV6_TCLASS,
        MSG_TRUNC,
        MSG_DONTWAIT,
        IFNAMSIZ,
        EIO,
        ENOPROTOOPT,
        EOPNOTSUPP,
        IPPROTO_TCP,
        TCP_ULP,
        SOL_TLS,
        TLS_TX,
        TLS_RX,
        TLS_SET_RECORD_TYPE,
        TLS_GET_RECORD_TYPE,
        TLS_1_2_VERSION,
        TLS_1_3_VERSION,
        TLS_CIPHER_AES_GCM_128,
        TLS_CIPHER_AES_GCM_256,
        TLS_CIPHER_CHACHA20_POLY1305,
        TLS_TX_ZEROCOPY_RO,
        TLS_RX_EXPECT_NO_PAD,
        SIOCETHTOOL,
        EPOLLIN,
        EPOLLOUT,
        EPOLLERR,
        EPOLLHUP,
        EPOLLRDHUP,
        EPOLL_CTL_ADD,
        EPOLL_CTL_DEL,
        EPOLL_CTL_MOD,
        EPOLL_CLOEXEC,
        EFD_NONBLOCK,
        EFD_CLOEXEC,
        POLLIN,
        POLLOUT,
        POLLERR,
        POLLRDHUP,
        PR_SET_PDEATHSIG,
        PROT_READ,
        PROT_WRITE,
        MAP_SHARED,
        MAP_POPULATE,
        SYS_bpf,
        SYS_io_uring_setup,
        SYS_io_uring_enter,
        SYS_io_uring_register,
    );
    assert_eq!(super::MAP_FAILED, libc::MAP_FAILED);
}

/// The CMSG_* helpers agree with libc's on a control buffer holding two headers.
#[cfg(target_os = "linux")]
#[test]
fn cmsg_helpers_match_libc() {
    for n in [0usize, 1, 2, 4, 7, 8, 9, 16, 100] {
        // SAFETY: pure size computations.
        let (space, len) = unsafe { (libc::CMSG_SPACE(n as u32), libc::CMSG_LEN(n as u32)) };
        assert_eq!(super::cmsg_space(n), space as usize);
        assert_eq!(super::cmsg_len(n), len as usize);
    }
    let mut buf = [0u64; 16];
    let mut ours: super::msghdr = super::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: buf.as_mut_ptr().cast(),
        msg_controllen: super::cmsg_space(4) + super::cmsg_space(2),
        msg_flags: 0,
    };
    // SAFETY: the control buffer holds 128 bytes; both headers fit (sizes computed above).
    unsafe {
        let c = super::cmsg_firsthdr(&raw const ours);
        (*c).cmsg_len = super::cmsg_len(4);
        let d = super::cmsg_nxthdr(&raw const ours, c);
        assert!(!d.is_null());
        (*d).cmsg_len = super::cmsg_len(2);
        assert!(super::cmsg_nxthdr(&raw const ours, d).is_null());
        let theirs = (&raw mut ours).cast::<libc::msghdr>();
        let lc = libc::CMSG_FIRSTHDR(theirs);
        assert_eq!(lc.cast::<u8>(), c.cast::<u8>());
        assert_eq!(libc::CMSG_DATA(lc), super::cmsg_data(c));
        assert_eq!(libc::CMSG_NXTHDR(theirs, lc).cast::<u8>(), d.cast::<u8>());
        // A header claiming more than the buffer holds ends the walk.
        (*d).cmsg_len = 4096;
        assert!(super::cmsg_nxthdr(&raw const ours, d).is_null());
        ours.msg_controllen = 8;
        assert!(super::cmsg_firsthdr(&raw const ours).is_null());
    }
    let mut set = super::cpu_set_t::new();
    // SAFETY: plain-old-data; all-zero is the empty set.
    let mut theirs: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for c in [0usize, 1, 63, 64, 500, 1023] {
        set.set(c);
        // SAFETY: `c` is below the set's capacity.
        unsafe { libc::CPU_SET(c, &mut theirs) };
        assert!(set.is_set(c));
    }
    set.set(1024); // ignored, out of range
    // SAFETY: both are 128 plain bytes.
    let (a, b) = unsafe {
        (
            std::mem::transmute::<super::cpu_set_t, [u8; 128]>(set),
            std::mem::transmute::<libc::cpu_set_t, [u8; 128]>(theirs),
        )
    };
    assert_eq!(a, b);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_layouts() {
    same_layout!(super::sockaddr_in, libc::sockaddr_in, sin_len);
    same_layout!(super::sockaddr_in6, libc::sockaddr_in6, sin6_len);
    same_layout!(super::sockaddr_storage, libc::sockaddr_storage, ss_len);
    same_layout!(
        super::msghdr,
        libc::msghdr,
        msg_name,
        msg_namelen,
        msg_iov,
        msg_iovlen,
        msg_control,
        msg_controllen,
        msg_flags
    );
    same_layout!(
        super::cmsghdr,
        libc::cmsghdr,
        cmsg_len,
        cmsg_level,
        cmsg_type
    );
    same_layout!(
        super::kevent,
        libc::kevent,
        ident,
        filter,
        flags,
        fflags,
        data,
        udata
    );
    same_layout!(
        super::sigaction,
        libc::sigaction,
        sa_sigaction,
        sa_mask,
        sa_flags
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_constants() {
    same_value!(
        EVFILT_READ,
        EVFILT_WRITE,
        EV_ADD,
        EV_DELETE,
        EV_ENABLE,
        EV_DISABLE,
        EV_ERROR,
        EV_EOF,
        EVFILT_VNODE,
        EVFILT_USER,
        EV_CLEAR,
        NOTE_TRIGGER,
        NOTE_DELETE,
        NOTE_WRITE,
        NOTE_EXTEND,
        NOTE_ATTRIB,
        NOTE_LINK,
        NOTE_RENAME,
        NOTE_REVOKE,
        O_EVTONLY,
        IPPROTO_IP,
        IP_TOS,
        IP_RECVTOS,
        IPV6_RECVTCLASS,
        IPV6_TCLASS,
    );
    // SAFETY: CMSG_* only compute offsets from these values.
    unsafe {
        assert_eq!(libc::CMSG_LEN(1) as usize, crate::udp_mac::CMSG_HDR + 1);
        assert_eq!(libc::CMSG_SPACE(4) as usize, crate::udp_mac::CMSG_HDR + 4);
        assert_eq!(libc::CMSG_SPACE(1) as usize, crate::udp_mac::CMSG_HDR + 4);
    }
}

/// The declared functions link and behave: errno is the C library's.
#[test]
fn errno_is_the_c_librarys() {
    // SAFETY: fcntl on an invalid descriptor only fails and sets errno.
    let r = unsafe { super::fcntl(-1, super::F_GETFD) };
    assert_eq!(r, -1);
    // SAFETY: read on the calling thread.
    assert_eq!(unsafe { *super::errno_location() }, super::EBADF);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(super::EBADF)
    );
}
