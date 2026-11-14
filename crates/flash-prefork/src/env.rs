//! The environment a supervisor starts its workers with.

use std::io;

/// This worker's index (0-based); its presence marks a worker.
pub(crate) const WORKER: &str = "FLASH_PREFORK_WORKER";
/// How many worker slots the supervisor runs.
pub(crate) const WORKERS: &str = "FLASH_PREFORK_WORKERS";
/// The generation (0 at start, +1 per reload) the worker belongs to.
pub(crate) const GENERATION: &str = "FLASH_PREFORK_GENERATION";
/// `reuseport` or `inherit`.
pub(crate) const MODE: &str = "FLASH_PREFORK_MODE";
/// The listening addresses, resolved, comma-separated.
pub(crate) const ADDRS: &str = "FLASH_PREFORK_ADDRS";
/// `inherit`: the inherited listening sockets' fds, comma-separated, in `ADDRS` order.
pub(crate) const FDS: &str = "FLASH_PREFORK_FDS";
/// The worker's end of its control socket.
pub(crate) const CTL: &str = "FLASH_PREFORK_CTL";
/// `listen(2)` backlog for `reuseport` workers.
pub(crate) const BACKLOG: &str = "FLASH_PREFORK_BACKLOG";

/// Every variable above (cleared from a worker's environment before setting them again, so a
/// worker that itself runs a supervisor does not pass stale values on).
pub(crate) const ALL: [&str; 8] = [WORKER, WORKERS, GENERATION, MODE, ADDRS, FDS, CTL, BACKLOG];

/// The control protocol: single bytes on the control socket.
pub(crate) const MSG_READY: u8 = b'R';
pub(crate) const MSG_STOP: u8 = b'S';

fn bad(var: &str, v: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("prefork: bad {var}={v:?}"),
    )
}

/// The variable `var`, required.
pub(crate) fn get(var: &str) -> io::Result<String> {
    std::env::var(var).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("prefork: {var} is not set"),
        )
    })
}

pub(crate) fn number<T: std::str::FromStr>(var: &str) -> io::Result<T> {
    let v = get(var)?;
    v.parse().map_err(|_| bad(var, &v))
}

pub(crate) fn list<T: std::str::FromStr>(var: &str) -> io::Result<Vec<T>> {
    let v = std::env::var(var).unwrap_or_default();
    v.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().map_err(|_| bad(var, &v)))
        .collect()
}

pub(crate) fn join<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn join_and_parse_round_trip() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:80".parse().unwrap(),
            "[::1]:8080".parse().unwrap(),
        ];
        let s = join(&addrs);
        let back: Vec<SocketAddr> = s.split(',').map(|x| x.parse().unwrap()).collect::<Vec<_>>();
        assert_eq!(back, addrs);
        assert_eq!(join::<u8>(&[]), "");
    }
}
