//! The userspace TCP/IP stack: Ethernet II, ARP, IPv4 (with fragmentation and reassembly),
//! ICMPv4, UDP and TCP, in safe Rust with no dependencies. One [`Iface`] per device queue,
//! owned by that queue's I/O thread; it is driven with received frames, a clock and a
//! transmit sink, and reports what the owner must act on as [`Event`]s.
//!
//! Layout: `wire` (frame formats), `arp` (neighbour cache), `frag` (IPv4 reassembly), `buf`
//! (TCP byte rings and the out-of-order assembler), `cc` (RTT / RTO, NewReno, CUBIC), `tcp`
//! (the connection state machine), `iface` (demultiplexing, listeners, timers, IPv4 output).
#![forbid(unsafe_code)]

pub(crate) mod arp;
pub(crate) mod buf;
pub(crate) mod cc;
pub(crate) mod frag;
pub(crate) mod iface;
pub(crate) mod tcp;
pub(crate) mod wire;

#[cfg(test)]
pub(crate) mod sim;

pub(crate) use cc::CcKind;
pub(crate) use iface::{CallError, Config, Event, Iface, TcpHandle, Tx};
pub(crate) use tcp::{Params, TcpError};
