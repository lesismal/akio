//! The QUIC v1 protocol core (RFC 9000, 9001, 9002, 9221), sans-io: no sockets, no threads, no
//! clocks of its own. The I/O layer (`crate::Ep` and friends) feeds it datagrams and the time,
//! and sends what it produces.
#![allow(unreachable_pub)]

pub(crate) mod cid;
pub(crate) mod coding;
pub(crate) mod conn;
pub(crate) mod crypto;
pub(crate) mod endpoint;
pub(crate) mod frame;
pub(crate) mod packet;
pub(crate) mod params;
pub(crate) mod ranges;
pub(crate) mod recovery;
pub(crate) mod stream;

#[cfg(test)]
mod sim;

pub(crate) use conn::{ConnConfig, Connection, EndpointEvent, Event, Transmit};
pub(crate) use endpoint::{ConnHandle, DatagramEvent, Endpoint, ServerSetup};
