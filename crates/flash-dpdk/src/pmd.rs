//! DPDK poll-mode-driver access through the C shim (`csrc/shim.c`): EAL initialisation, port
//! setup, and per-queue rx/tx bursts on mbufs; plus [`Sendable`], which moves smoltcp's
//! (non-`Send`) TAP / AF_PACKET devices to their I/O thread. This is the only module of the crate
//! with `unsafe` (docs/unsafe-review.md). Without a linked libdpdk (`pmd` feature off, or libdpdk not found by
//! build.rs) the same API exists and [`open`] fails with `Unsupported`.

#[cfg(flash_dpdk_linked)]
#[allow(unsafe_code)]
mod imp {
    use std::{
        collections::HashMap,
        ffi::{CString, c_char, c_int, c_void},
        io,
        sync::{Mutex, OnceLock},
    };

    use crate::EalConfig;

    // The shim's ABI: integers and opaque pointers only (no DPDK struct layouts in Rust).
    unsafe extern "C" {
        fn flash_dpdk_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
        fn flash_dpdk_errno() -> c_int;
        fn flash_dpdk_thread_register() -> c_int;
        fn flash_dpdk_port_count() -> u16;
        fn flash_dpdk_port_by_name(name: *const c_char, port: *mut u16) -> c_int;
        fn flash_dpdk_port_start(
            port: u16,
            queues: u16,
            desc: u16,
            mbufs: u32,
            mtu: u16,
            mac: *mut u8,
        ) -> c_int;
        fn flash_dpdk_rx_burst(port: u16, queue: u16, pkts: *mut *mut c_void, n: u16) -> u16;
        fn flash_dpdk_tx_burst(port: u16, queue: u16, pkts: *mut *mut c_void, n: u16) -> u16;
        fn flash_dpdk_mbuf_data(m: *mut c_void, len: *mut u32) -> *mut u8;
        fn flash_dpdk_mbuf_free(m: *mut c_void);
        fn flash_dpdk_tx_alloc(port: u16, len: u16, data: *mut *mut u8) -> *mut c_void;
    }

    /// A started port.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct PortInfo {
        pub(crate) port: u16,
        pub(crate) mac: [u8; 6],
        pub(crate) queues: u16,
    }

    static EAL: OnceLock<Result<(), String>> = OnceLock::new();
    static PORTS: Mutex<Option<HashMap<u16, PortInfo>>> = Mutex::new(None);

    fn eal_init(args: &[String]) -> io::Result<()> {
        let r = EAL.get_or_init(|| {
            let mut all = vec!["flash".to_owned()];
            all.extend(args.iter().cloned());
            let mut argv: Vec<*mut c_char> = Vec::with_capacity(all.len() + 1);
            for a in &all {
                let c = CString::new(a.as_str()).map_err(|e| e.to_string())?;
                // The EAL may keep pointers into argv for the life of the process.
                argv.push(c.into_raw());
            }
            argv.push(std::ptr::null_mut());
            let argc = c_int::try_from(all.len()).map_err(|e| e.to_string())?;
            let argv = argv.leak();
            // SAFETY: `argv` is a NULL-terminated array of `argc` valid, NUL-terminated strings
            // that are leaked, so they outlive the EAL. Called at most once (OnceLock).
            let rc = unsafe { flash_dpdk_eal_init(argc, argv.as_mut_ptr()) };
            if rc < 0 {
                // SAFETY: reads DPDK's thread-local error number; no preconditions.
                let errno = unsafe { flash_dpdk_errno() };
                return Err(format!("rte_eal_init failed (rte_errno {errno})"));
            }
            Ok(())
        });
        r.clone().map_err(io::Error::other)
    }

    fn port_id(name: &str) -> io::Result<u16> {
        if let Ok(i) = name.parse::<u16>() {
            // SAFETY: no preconditions once the EAL is initialised (done by the caller).
            let n = unsafe { flash_dpdk_port_count() };
            if i >= n {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("DPDK port {i} does not exist ({n} ports available)"),
                ));
            }
            return Ok(i);
        }
        let c = CString::new(name).map_err(io::Error::other)?;
        let mut id = 0u16;
        // SAFETY: `c` is a valid NUL-terminated string and `id` a valid out pointer for the call.
        let rc = unsafe { flash_dpdk_port_by_name(c.as_ptr(), &raw mut id) };
        if rc != 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DPDK port {name:?} not found"),
            ));
        }
        Ok(id)
    }

    /// Initialises the EAL (once per process) and starts the configured port (once per port;
    /// later calls return the port as first configured).
    pub(crate) fn open(cfg: &EalConfig, mtu: usize) -> io::Result<PortInfo> {
        eal_init(&cfg.args)?;
        let port = port_id(&cfg.port)?;
        let mut ports = PORTS.lock().unwrap_or_else(|p| p.into_inner());
        let ports = ports.get_or_insert_with(HashMap::new);
        if let Some(p) = ports.get(&port) {
            return Ok(*p);
        }
        let queues = cfg.queues.max(1);
        let mut mac = [0u8; 6];
        let mtu = u16::try_from(mtu).unwrap_or(0);
        // SAFETY: `mac` is a valid 6-byte out buffer; the other arguments are plain integers.
        let rc = unsafe {
            flash_dpdk_port_start(
                port,
                queues,
                cfg.descriptors,
                cfg.mbufs,
                mtu,
                mac.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::other(format!(
                "starting DPDK port {port} failed (error {rc})"
            )));
        }
        let info = PortInfo { port, mac, queues };
        ports.insert(port, info);
        Ok(info)
    }

    /// Registers the calling I/O thread with the EAL (an lcore id, so mempool per-lcore caches
    /// apply). Failure (all `RTE_MAX_LCORE` ids taken) only costs the caches.
    pub(crate) fn register_thread() {
        // SAFETY: called on a thread after the EAL was initialised (a queue exists); no other
        // preconditions.
        let _ = unsafe { flash_dpdk_thread_register() };
    }

    const BURST: usize = 32;

    /// One rx/tx queue pair of a started port, polled by one thread.
    pub(crate) struct Queue {
        port: u16,
        queue: u16,
        rx: [*mut c_void; BURST],
        rx_len: usize,
        rx_next: usize,
        tx: Vec<*mut c_void>,
    }

    // SAFETY: the mbuf pointers a `Queue` holds are owned by it alone (taken from rx bursts or
    // allocated for tx, never shared), and DPDK allows a queue to be used from any single thread
    // at a time; the `Queue` moves to its I/O thread once and is only used there.
    unsafe impl Send for Queue {}

    impl Queue {
        pub(crate) fn new(port: u16, queue: u16) -> Queue {
            Queue {
                port,
                queue,
                rx: [std::ptr::null_mut(); BURST],
                rx_len: 0,
                rx_next: 0,
                tx: Vec::with_capacity(BURST),
            }
        }

        /// The next received frame (an mbuf, read in place), refilling with one rx burst when
        /// the last one is used up. Multi-segment frames (larger than an mbuf) are dropped.
        pub(crate) fn recv(&mut self) -> Option<Mbuf> {
            loop {
                if self.rx_next == self.rx_len {
                    // SAFETY: `rx` has room for BURST pointers; the PMD writes at most BURST.
                    let n = unsafe {
                        flash_dpdk_rx_burst(
                            self.port,
                            self.queue,
                            self.rx.as_mut_ptr(),
                            BURST as u16,
                        )
                    };
                    self.rx_len = usize::from(n);
                    self.rx_next = 0;
                    if n == 0 {
                        return None;
                    }
                }
                let m = self.rx[self.rx_next];
                self.rx_next += 1;
                let mut len = 0u32;
                // SAFETY: `m` is an mbuf this queue received and still owns.
                let data = unsafe { flash_dpdk_mbuf_data(m, &raw mut len) };
                let mbuf = Mbuf {
                    m,
                    data,
                    len: len as usize,
                };
                if !data.is_null() {
                    return Some(mbuf);
                }
                // Dropping `mbuf` frees the multi-segment frame.
            }
        }

        /// Builds a frame of `len` bytes with `f` in a fresh mbuf and queues it for transmission
        /// (sent with the next burst). `None` when the pool is exhausted: the frame is dropped.
        pub(crate) fn send<R>(&mut self, len: usize, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
            let len16 = u16::try_from(len).ok()?;
            let mut data: *mut u8 = std::ptr::null_mut();
            // SAFETY: `data` is a valid out pointer; the shim checks the port has a pool.
            let m = unsafe { flash_dpdk_tx_alloc(self.port, len16, &raw mut data) };
            if m.is_null() {
                return None;
            }
            // SAFETY: the shim appended `len` writable bytes at `data` to the new mbuf `m`, which
            // nothing else references until it is queued below.
            let buf = unsafe { std::slice::from_raw_parts_mut(data, len) };
            let r = f(buf);
            self.tx.push(m);
            if self.tx.len() >= BURST {
                self.flush();
            }
            Some(r)
        }

        /// Transmits the queued frames. Frames the NIC ring cannot take are dropped (as a full
        /// ring drops them); TCP retransmits, UDP is best effort.
        pub(crate) fn flush(&mut self) {
            if self.tx.is_empty() {
                return;
            }
            let n = u16::try_from(self.tx.len()).unwrap_or(u16::MAX);
            // SAFETY: `tx` holds `n` mbufs owned by this queue; the PMD takes ownership of the
            // first `sent` of them.
            let sent =
                unsafe { flash_dpdk_tx_burst(self.port, self.queue, self.tx.as_mut_ptr(), n) };
            for &m in &self.tx[usize::from(sent)..] {
                // SAFETY: mbufs the PMD did not take are still owned here and freed once.
                unsafe { flash_dpdk_mbuf_free(m) };
            }
            self.tx.clear();
        }
    }

    /// A received frame, owned until dropped (then returned to its pool).
    pub(crate) struct Mbuf {
        m: *mut c_void,
        data: *mut u8,
        len: usize,
    }

    impl Mbuf {
        pub(crate) fn data(&self) -> &[u8] {
            // SAFETY: `data`/`len` describe the single data segment of `m` (checked non-null by
            // `Queue::recv`), which stays valid until `m` is freed in `drop`.
            unsafe { std::slice::from_raw_parts(self.data, self.len) }
        }
    }

    impl Drop for Mbuf {
        fn drop(&mut self) {
            // SAFETY: `m` is owned by this value and freed exactly once, here.
            unsafe { flash_dpdk_mbuf_free(self.m) };
        }
    }

    impl Drop for Queue {
        fn drop(&mut self) {
            self.flush();
            for &m in &self.rx[self.rx_next..self.rx_len] {
                // SAFETY: received mbufs not yet handed out are owned here and freed once.
                unsafe { flash_dpdk_mbuf_free(m) };
            }
        }
    }
}

#[cfg(not(flash_dpdk_linked))]
mod imp {
    use std::{convert::Infallible, io};

    use crate::EalConfig;

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct PortInfo {
        pub(crate) port: u16,
        pub(crate) mac: [u8; 6],
        pub(crate) queues: u16,
    }

    pub(crate) fn open(_cfg: &EalConfig, _mtu: usize) -> io::Result<PortInfo> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            if cfg!(feature = "pmd") {
                "flash-dpdk was built without libdpdk (pkg-config did not find it)"
            } else {
                "flash-dpdk was built without the `pmd` feature (flash: `dpdk-pmd`)"
            },
        ))
    }

    pub(crate) fn register_thread() {}

    /// Never constructed: [`open`] always fails.
    pub(crate) struct Queue(Infallible);

    /// Never constructed.
    pub(crate) struct Mbuf(Infallible);

    impl Mbuf {
        pub(crate) fn data(&self) -> &[u8] {
            match self.0 {}
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)] // same signatures as the real queue
    impl Queue {
        pub(crate) fn new(_port: u16, _queue: u16) -> Queue {
            unreachable!("no DPDK queue without libdpdk")
        }
        pub(crate) fn recv(&mut self) -> Option<Mbuf> {
            match self.0 {}
        }
        pub(crate) fn send<R>(
            &mut self,
            _len: usize,
            _f: impl FnOnce(&mut [u8]) -> R,
        ) -> Option<R> {
            match self.0 {}
        }
        pub(crate) fn flush(&mut self) {
            match self.0 {}
        }
    }
}

pub(crate) use imp::{Mbuf, Queue, open, register_thread};

/// Moves a device that is not `Send` to the I/O thread that will own it.
///
/// smoltcp's `TunTapInterface` and `RawSocket` keep their file descriptor in an
/// `Rc<RefCell<..>>` so that the rx/tx tokens of one poll can share it; that makes them `!Send`
/// although nothing in them is tied to a thread. A device is created on the thread that binds the
/// listener (so errors surface in `Engine::build`), wrapped here before any token exists, moved
/// once to its loop thread together with the loop, and only ever used there; tokens are created
/// and consumed within one `Interface::poll` call on that thread.
#[cfg(target_os = "linux")]
pub(crate) struct Sendable<T>(T);

#[cfg(target_os = "linux")]
impl<T> Sendable<T> {
    /// Wraps a freshly created device (no clones of its inner `Rc` exist yet).
    pub(crate) fn new(device: T) -> Sendable<T> {
        Sendable(device)
    }

    pub(crate) fn get(&self) -> &T {
        &self.0
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// SAFETY: see the type's documentation: the wrapped device's `Rc` is never cloned outside the
// device's own transient rx/tx tokens, so all reference counts and the `RefCell` are only touched
// by the one thread that owns the `Sendable` at any time; moving it moves every reference.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe impl<T> Send for Sendable<T> {}
