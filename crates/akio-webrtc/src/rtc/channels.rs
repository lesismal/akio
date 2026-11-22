//! Data channel priorities (RFC 8831 §6.4, RFC 8832 §5.1) on the SCTP stream scheduler
//! (RFC 8260 §3, akio-sctp ADR-037).

use super::*;

impl Rtc {
    /// The priority of channel `id`: as opened (ours), as the peer's DCEP open message said
    /// (theirs), or as last set. `None` for an unknown channel.
    pub(crate) fn channel_priority(&self, id: ChannelId) -> Option<ChannelPriority> {
        self.channels.get(&id).map(|c| c.cfg.priority)
    }

    /// Changes the priority the scheduler gives channel `id` on this side (the peer was told
    /// the priority at open time; DCEP has no update). A channel not open yet takes it when
    /// it opens. `false` for an unknown channel.
    pub(crate) fn set_channel_priority(&mut self, id: ChannelId, p: ChannelPriority) -> bool {
        let Some(ch) = self.channels.get_mut(&id) else {
            return false;
        };
        ch.cfg.priority = p;
        if let (Some(stream), Some(sctp)) = (ch.stream, self.sctp.as_mut()) {
            let _ = sctp.set_channel_priority(stream, p.dcep_value());
        }
        true
    }
}
