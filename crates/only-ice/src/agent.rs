//! The ICE agent: checklist, connectivity checks, nomination, consent freshness.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use only_turn::stun::{Class, Message, MessageBuilder, Method, attr};

use crate::candidate::{
    self, Candidate, CandidateKind, Credentials, TcpType, random_bytes, random_u64,
};

/// Most remote candidates kept (signaled plus peer-reflexive).
const MAX_REMOTE_CANDIDATES: usize = 100;
/// Most local candidates kept.
const MAX_LOCAL_CANDIDATES: usize = 50;
/// Most candidate pairs (RFC 8445 §6.1.2.5 recommends a limit; 100 is its default).
const MAX_PAIRS: usize = 100;
/// Outstanding consent transactions remembered.
const MAX_CONSENT_TX: usize = 8;
/// Transmissions of one consent check (first retransmission after [`CONSENT_RTO`], doubling).
const CONSENT_SENDS: u32 = 4;
/// First retransmission timeout of a consent check.
const CONSENT_RTO: Duration = Duration::from_millis(500);
/// Finished transactions remembered so that late duplicate responses are still consumed.
const MAX_DONE_TX: usize = 64;
/// The NOMINATION attribute of ICE renomination (draft-thatcher-ice-renomination-01 §3.1):
/// a 32-bit value, comprehension-optional; the controlled agent selects the pair of the
/// highest value it received.
pub(crate) const ATTR_NOMINATION: u16 = 0xC001;

/// Agent configuration. [`IceConfig::new`] fills in the defaults; adjust fields after.
#[derive(Clone, Debug)]
pub struct IceConfig {
    /// ICE-lite (RFC 8445 §2.5): never sends checks, always controlled.
    pub lite: bool,
    /// Initial role (ignored by a lite agent; the offerer is usually controlling).
    pub controlling: bool,
    /// Local credentials.
    pub local: Credentials,
    /// Pacing: one new check every `ta` (default 50 ms, RFC 8445 §14.2).
    pub ta: Duration,
    /// First retransmission timeout of a check (default 250 ms), doubling each time.
    pub check_rto: Duration,
    /// Cap of the retransmission timeout (default 1600 ms).
    pub check_rto_max: Duration,
    /// Transmissions of one check before its pair fails (default 7: given up about 8 s after
    /// the first send with the default timeouts).
    pub check_max_sends: u32,
    /// Controlling agent: how long to wait after the first valid pair for higher-priority
    /// pairs still being checked before nominating the best valid one (default 500 ms).
    pub nomination_delay: Duration,
    /// Consent freshness (RFC 7675): interval between checks on the selected pair (default
    /// 5 s, each one randomized by ±20 %).
    pub consent_interval: Duration,
    /// Consent freshness: no response for this long (or for a lite agent, no valid check)
    /// means [`IceState::Disconnected`] (default 30 s).
    pub consent_timeout: Duration,
    /// Without end-of-candidates: when nothing succeeded this long after the first pair was
    /// formed and every pair failed, the state becomes [`IceState::Failed`] (default 30 s).
    pub failed_timeout: Duration,
    /// Controlling: aggressive nomination (RFC 5245 §8.1.1.2, for peers that expect it):
    /// every check carries USE-CANDIDATE, the highest-priority pair whose check succeeds is
    /// selected, and checks of higher-priority pairs go on after a selection, which moves to
    /// such a pair when it succeeds. Default off (regular nomination, RFC 8445 §8.1.1).
    pub aggressive_nomination: bool,
    /// ICE renomination (draft-thatcher-ice-renomination, `a=ice-options:renomination`) is
    /// supported here; it is used once the remote supports it too
    /// ([`IceAgent::set_remote_renomination`]). Controlling: checks of higher-priority pairs
    /// go on after nomination, and a better pair that succeeds later is nominated again with
    /// a higher NOMINATION value. Controlled (always, whatever this flag says): the pair with
    /// the highest NOMINATION value is selected. Default off.
    pub renomination: bool,
    /// Components of the data stream (RFC 8445 §2): 1 (default) for RTP and RTCP muxed or
    /// BUNDLEd, 2 for RTP (component 1) and RTCP (component 2) on their own ports. Candidates
    /// carry their component ([`Candidate::with_component`]); those of components above this
    /// number are ignored. The agent is `Connected` once every component has a selected pair.
    /// Values outside 1..=256 are clamped.
    pub components: u16,
}

impl IceConfig {
    /// Defaults with random local credentials.
    pub fn new(lite: bool, controlling: bool) -> IceConfig {
        IceConfig {
            lite,
            controlling: controlling && !lite,
            local: Credentials::random(),
            ta: Duration::from_millis(50),
            check_rto: Duration::from_millis(250),
            check_rto_max: Duration::from_millis(1600),
            check_max_sends: 7,
            nomination_delay: Duration::from_millis(500),
            consent_interval: Duration::from_secs(5),
            consent_timeout: Duration::from_secs(30),
            failed_timeout: Duration::from_secs(30),
            aggressive_nomination: false,
            renomination: false,
            components: 1,
        }
    }
}

/// A datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// The local address to send from (a candidate's base; the relayed address for a relayed
    /// candidate).
    pub source: SocketAddr,
    /// Where to send it.
    pub destination: SocketAddr,
    /// The datagram (a STUN message).
    pub contents: Vec<u8>,
}

/// The agent state (the `RTCIceConnectionState` values), over every component of the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IceState {
    /// Nothing started yet.
    New,
    /// Checks are running (a lite agent: valid checks arrived) but some component has no
    /// selected pair.
    Checking,
    /// Every component has a selected pair; checks may still be running.
    Connected,
    /// Every component has a selected pair of the current generation and nothing is left to
    /// check.
    Completed,
    /// Consent expired on the selected pair of a component (it may come back).
    Disconnected,
    /// Every pair of a component without a selected pair failed (after end-of-candidates or
    /// [`IceConfig::failed_timeout`]).
    Failed,
}

/// What happened, from [`IceAgent::poll_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IceEvent {
    /// The state changed.
    StateChanged(IceState),
    /// A pair of component 1 was selected (nominated): the first time, when it changes, and
    /// after each ICE restart's nomination even if the addresses stay the same.
    SelectedPair {
        /// Local address (the base; the relayed address for a relayed candidate).
        local: SocketAddr,
        /// Remote address.
        remote: SocketAddr,
    },
    /// A pair of a component other than 1 was selected, on the same occasions as
    /// [`IceEvent::SelectedPair`] (only with [`IceConfig::components`] above 1).
    ComponentSelectedPair {
        /// The component id (2 for RTCP).
        component: u16,
        /// Local address (the base; the relayed address for a relayed candidate).
        local: SocketAddr,
        /// Remote address.
        remote: SocketAddr,
    },
    /// The ECN check of [`IceAgent::check_ecn`] ended (RFC 6679 §7.2.2): `ecn` is the codepoint
    /// the remote saw the check arrive with (`ecn & 3` as sent: the path carries it), or
    /// `None` when that could not be learnt (no answer, or a remote that does not read ECN).
    EcnChecked {
        /// Local address of the pair checked.
        local: SocketAddr,
        /// Remote address of the pair checked.
        remote: SocketAddr,
        /// The codepoint the remote reported.
        ecn: Option<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairState {
    Frozen,
    Waiting,
    InProgress,
    Succeeded,
    Failed,
}

#[derive(Debug)]
struct Tx {
    tid: [u8; 12],
    packet: Vec<u8>,
    sends: u32,
    rto: Duration,
    next: Instant,
    use_candidate: bool,
    /// The check is an explicit nomination (regular nomination or renomination), not an
    /// aggressive one.
    nominating: bool,
    controlling: bool,
    priority: u32,
    key: String,
}

#[derive(Debug)]
struct Pair {
    /// The component of both candidates.
    component: u16,
    local: SocketAddr,
    local_prio: u32,
    local_pref: u32,
    local_foundation: String,
    remote: SocketAddr,
    remote_prio: u32,
    remote_foundation: String,
    prio: u64,
    state: PairState,
    tx: Option<Tx>,
    /// Controlled: the remote sent USE-CANDIDATE on this pair.
    remote_nominated: bool,
    /// Controlled: the NOMINATION value of the remote's last USE-CANDIDATE check on this pair
    /// (renomination), `None` without the attribute.
    remote_nomination: Option<u32>,
    /// Controlling: the next check carries USE-CANDIDATE.
    nominate: bool,
    /// Controlling with renomination: the NOMINATION value of that check.
    nomination: u32,
    /// The local candidate is passive TCP: this side never opens the connection, so the pair
    /// only gets checks triggered by the remote's (over its connection).
    passive: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Selected {
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,
    pub(crate) local_ufrag: String,
    pub(crate) remote_creds: Option<Credentials>,
    pub(crate) local_pref: u32,
    generation: u64,
    /// The pair priority (0 for a lite agent, which keeps no pairs).
    prio: u64,
}

/// The state of one component of the stream: its selection, nomination, consent freshness
/// (RFC 7675 runs per component) and, for a lite agent, the last valid check. The pairs of
/// every component share one checklist (RFC 8445 §6.1.2), its pacing and triggered queue.
#[derive(Debug)]
pub(crate) struct Comp {
    pub(crate) selected: Option<Selected>,
    /// Controlling: the pair being nominated.
    nominating: Option<(SocketAddr, SocketAddr)>,
    first_valid_at: Option<Instant>,
    /// Controlling, after a selection: when a pair better than the selected one first
    /// succeeded (renomination waits [`IceConfig::nomination_delay`] from then for better
    /// pairs still being checked).
    improved_at: Option<Instant>,
    /// Controlled: the highest NOMINATION value selected in this generation.
    remote_nomination: u32,
    consent_next: Option<Instant>,
    consent_last: Instant,
    consent_lost: bool,
    consent_txs: VecDeque<ConsentTx>,
    lite_last_check: Option<Instant>,
    lite_valid: Option<(SocketAddr, SocketAddr)>,
}

impl Comp {
    fn new(now: Instant) -> Comp {
        Comp {
            selected: None,
            nominating: None,
            first_valid_at: None,
            improved_at: None,
            remote_nomination: 0,
            consent_next: None,
            consent_last: now,
            consent_lost: false,
            consent_txs: VecDeque::new(),
            lite_last_check: None,
            lite_valid: None,
        }
    }
}

#[derive(Debug)]
struct ConsentTx {
    tid: [u8; 12],
    key: String,
    local: SocketAddr,
    remote: SocketAddr,
    packet: Vec<u8>,
    sends: u32,
    rto: Duration,
    next: Instant,
}

/// Pair priority, RFC 8445 §6.1.2.3.
fn pair_priority(controlling: bool, local: u32, remote: u32) -> u64 {
    let (g, d) = if controlling {
        (local, remote)
    } else {
        (remote, local)
    };
    (u64::from(g.min(d)) << 32) + 2 * u64::from(g.max(d)) + u64::from(g > d)
}

/// Whether a local candidate takes part in ordinary pairing: a passive TCP candidate only
/// pairs with the peer-reflexive remote of a connection that arrived (RFC 6544 §6.2: the
/// signaled active candidates name no port to check).
fn pairs_on_signal(c: &Candidate) -> bool {
    c.kind() != CandidateKind::PeerReflexive && c.tcp_type() != Some(TcpType::Passive)
}

/// A sans-io ICE agent for one data stream over UDP and TCP: one component by default
/// (RTP/RTCP muxed), more with [`IceConfig::components`]. See the crate docs for how to drive
/// it.
#[derive(Debug)]
pub struct IceAgent {
    pub(crate) config: IceConfig,
    prev_local: Option<Credentials>,
    remote_creds: Option<Credentials>,
    remote_lite: bool,
    /// The remote supports renomination.
    remote_renomination: bool,
    /// Controlling: the last NOMINATION value sent (one counter for every component).
    nomination: u32,
    controlling: bool,
    tie_breaker: u64,
    local_cands: Vec<Candidate>,
    remote_cands: Vec<Candidate>,
    /// The checklist: the pairs of every component.
    pairs: Vec<Pair>,
    triggered: VecDeque<(SocketAddr, SocketAddr)>,
    end_of_candidates: bool,
    generation: u64,
    /// Component `i + 1` at index `i`.
    pub(crate) comps: Vec<Comp>,
    /// The generation in which every component's selection completed.
    completed_gen: Option<u64>,
    checking_since: Option<Instant>,
    next_check: Instant,
    done_tids: VecDeque<[u8; 12]>,
    state: IceState,
    pub(crate) transmits: VecDeque<Transmit>,
    pub(crate) events: VecDeque<IceEvent>,
    pub(crate) closed: bool,
    /// [`IceAgent::set_fixed_pair`]: no ICE runs, the selected pairs are given.
    pub(crate) fixed: bool,
    now: Instant,
    /// RFC 6679 §7.2.2 ([`crate::ecn`]): the ECN check in flight, its datagrams (sent with a
    /// codepoint), and the codepoint of the datagram being handled.
    pub(crate) ecn_check: Option<crate::ecn::EcnCheck>,
    pub(crate) ecn_transmits: VecDeque<(Transmit, u8)>,
    pub(crate) rx_ecn: Option<u8>,
}

impl IceAgent {
    /// A new agent.
    pub fn new(mut config: IceConfig, now: Instant) -> IceAgent {
        config.components = config.components.clamp(1, 256);
        let controlling = config.controlling && !config.lite;
        let comps = (0..config.components).map(|_| Comp::new(now)).collect();
        IceAgent {
            config,
            prev_local: None,
            remote_creds: None,
            remote_lite: false,
            remote_renomination: false,
            nomination: 0,
            controlling,
            tie_breaker: random_u64(),
            local_cands: Vec::new(),
            remote_cands: Vec::new(),
            pairs: Vec::new(),
            triggered: VecDeque::new(),
            end_of_candidates: false,
            generation: 0,
            comps,
            completed_gen: None,
            checking_since: None,
            next_check: now,
            done_tids: VecDeque::new(),
            state: IceState::New,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            closed: false,
            fixed: false,
            now,
            ecn_check: None,
            ecn_transmits: VecDeque::new(),
            rx_ecn: None,
        }
    }

    fn comp(&self, component: u16) -> &Comp {
        &self.comps[usize::from(component - 1)]
    }

    fn comp_mut(&mut self, component: u16) -> &mut Comp {
        &mut self.comps[usize::from(component - 1)]
    }

    fn has_component(&self, component: u16) -> bool {
        (1..=self.config.components).contains(&component)
    }

    /// The component of the local (signaled) candidate sending from `local`.
    fn component_of(&self, local: SocketAddr) -> Option<u16> {
        self.local_cands
            .iter()
            .find(|c| c.kind() != CandidateKind::PeerReflexive && c.send_addr() == local)
            .map(Candidate::component)
    }

    /// The component of the pair `key`.
    fn pair_component(&self, key: &(SocketAddr, SocketAddr)) -> Option<u16> {
        self.pairs
            .iter()
            .find(|p| (p.local, p.remote) == *key)
            .map(|p| p.component)
    }

    /// The local credentials (for the SDP).
    pub fn local_credentials(&self) -> &Credentials {
        &self.config.local
    }

    /// The remote credentials, once set.
    pub fn remote_credentials(&self) -> Option<&Credentials> {
        self.remote_creds.as_ref()
    }

    /// Sets the remote credentials. Setting different ones than before (a remote ICE restart)
    /// drops the remote candidates, the pairs and end-of-candidates; the selected pairs stay
    /// in use (with consent on the old credentials) until new ones are nominated.
    pub fn set_remote_credentials(&mut self, c: Credentials) {
        if self.remote_creds.as_ref() == Some(&c) {
            return;
        }
        let had = self.remote_creds.replace(c).is_some();
        if had {
            self.remote_cands.clear();
            self.reset_checklist();
            self.end_of_candidates = false;
        }
        let now = self.now;
        self.update_state(now);
    }

    /// Whether this is a lite agent.
    pub fn is_lite(&self) -> bool {
        self.config.lite
    }

    /// The number of components of the stream ([`IceConfig::components`]).
    pub fn components(&self) -> u16 {
        self.config.components
    }

    /// Whether this agent is currently controlling (it may change on a role conflict).
    pub fn controlling(&self) -> bool {
        self.controlling
    }

    /// Sets the role (ignored by a lite agent, which is always controlled).
    pub fn set_controlling(&mut self, yes: bool) {
        if !self.config.lite {
            self.set_role(yes);
        }
    }

    /// The remote is ICE-lite (`a=ice-lite`): this full agent becomes controlling and
    /// nominates the first valid pair of each component.
    pub fn set_remote_lite(&mut self, yes: bool) {
        self.remote_lite = yes;
        if yes {
            self.set_controlling(true);
        }
    }

    /// The remote supports ICE renomination (`renomination` in its `a=ice-options`): with
    /// [`IceConfig::renomination`] this controlling agent renominates better pairs found
    /// after nomination.
    pub fn set_remote_renomination(&mut self, yes: bool) {
        self.remote_renomination = yes;
    }

    /// Adds a local candidate (gathered by the caller); `false` (and ignored) if one with the
    /// same address, base and transport exists (a UDP and a TCP candidate may share an
    /// address: a server's listeners on one port) or its component is not one of the stream's.
    /// Host, server-reflexive and relayed candidates are paired with the remote candidates of
    /// the same component and IP family.
    pub fn add_local_candidate(&mut self, c: Candidate) -> bool {
        if !self.has_component(c.component())
            || self.local_cands.len() >= MAX_LOCAL_CANDIDATES
            || self.local_cands.iter().any(|l| {
                l.addr() == c.addr() && l.base() == c.base() && l.tcp_type() == c.tcp_type()
            })
        {
            return false;
        }
        self.local_cands.push(c.clone());
        if pairs_on_signal(&c) {
            for i in 0..self.remote_cands.len() {
                let r = self.remote_cands[i].clone();
                self.add_pair(&c, &r);
            }
        }
        let now = self.now;
        self.update_state(now);
        true
    }

    /// The local candidates, including peer-reflexive ones learned from checks (those are not
    /// signaled).
    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_cands
    }

    /// Adds a remote candidate (trickle: any time). Ignored: components the stream does not
    /// have ([`IceConfig::components`]; only 1 by default), duplicates of a known address of
    /// the same component, candidates whose `ufrag` extension names another generation than
    /// the remote credentials. A signaled candidate replaces a peer-reflexive one with the
    /// same address.
    pub fn add_remote_candidate(&mut self, c: Candidate) {
        if self.fixed {
            return;
        }
        if !self.has_component(c.component()) {
            return;
        }
        if let (Some(u), Some(rc)) = (c.ufrag(), self.remote_creds.as_ref()) {
            if u != rc.ufrag {
                return;
            }
        }
        let comp = c.component();
        if let Some(i) = self
            .remote_cands
            .iter()
            .position(|r| r.addr() == c.addr() && r.component() == comp)
        {
            if self.remote_cands[i].kind() == CandidateKind::PeerReflexive
                && c.kind() != CandidateKind::PeerReflexive
            {
                let controlling = self.controlling;
                for p in self
                    .pairs
                    .iter_mut()
                    .filter(|p| p.remote == c.addr() && p.component == comp)
                {
                    p.remote_prio = c.priority();
                    p.remote_foundation = c.foundation().to_owned();
                    p.prio = pair_priority(controlling, p.local_prio, p.remote_prio);
                }
                self.remote_cands[i] = c;
            }
            return;
        }
        if self.remote_cands.len() >= MAX_REMOTE_CANDIDATES {
            return;
        }
        self.remote_cands.push(c.clone());
        for i in 0..self.local_cands.len() {
            let l = self.local_cands[i].clone();
            if pairs_on_signal(&l) {
                self.add_pair(&l, &c);
            }
        }
        let now = self.now;
        self.update_state(now);
    }

    /// The remote candidates, including peer-reflexive ones.
    pub fn remote_candidates(&self) -> &[Candidate] {
        &self.remote_cands
    }

    /// The remote signaled end-of-candidates: once every pair of a component without a
    /// selected pair failed the state becomes [`IceState::Failed`].
    pub fn end_of_remote_candidates(&mut self) {
        self.end_of_candidates = true;
        let now = self.now;
        self.update_state(now);
    }

    /// Local ICE restart with new credentials (for every component of the stream). The pairs
    /// are rebuilt (local candidates kept if `keep_local_candidates`, peer-reflexive ones
    /// always dropped); each component's selected pair stays in use, and requests on the old
    /// credentials are still answered, until a new pair of that component is nominated. Call
    /// [`IceAgent::set_remote_credentials`] with the remote's new credentials (and re-add its
    /// candidates) when the answer arrives.
    pub fn restart(&mut self, local: Credentials, keep_local_candidates: bool) {
        let old = std::mem::replace(&mut self.config.local, local);
        self.prev_local = Some(old);
        if keep_local_candidates {
            self.local_cands
                .retain(|c| c.kind() != CandidateKind::PeerReflexive);
        } else {
            self.local_cands.clear();
        }
        self.reset_checklist();
        self.end_of_candidates = false;
        for c in &mut self.comps {
            c.lite_valid = None;
        }
        for l in self.local_cands.clone() {
            if !pairs_on_signal(&l) {
                continue;
            }
            for r in self.remote_cands.clone() {
                self.add_pair(&l, &r);
            }
        }
        let now = self.now;
        self.update_state(now);
    }

    fn reset_checklist(&mut self) {
        let tids: Vec<[u8; 12]> = self
            .pairs
            .iter()
            .filter_map(|p| p.tx.as_ref().map(|t| t.tid))
            .collect();
        for t in tids {
            self.retire(t);
        }
        self.pairs.clear();
        self.triggered.clear();
        for c in &mut self.comps {
            c.nominating = None;
            c.first_valid_at = None;
            c.improved_at = None;
            c.remote_nomination = 0;
        }
        self.checking_since = None;
        self.generation += 1;
    }

    /// Handles a received datagram (`source` the remote address, `destination` the local
    /// address it arrived on: a candidate's base, or the relayed address). Returns `true` if
    /// it was a STUN message for this agent (consumed), `false` for anything else (DTLS,
    /// SRTP, other STUN traffic), which the caller handles itself. The component is the one
    /// of the local candidate at `destination`.
    pub fn handle_receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> bool {
        if self.closed || self.fixed || !only_turn::stun::is_stun(data) {
            return false;
        }
        let Ok(m) = Message::parse(data) else {
            return false;
        };
        if m.method() != Method::BINDING {
            return false;
        }
        self.now = self.now.max(now);
        let consumed = match m.class() {
            Class::Request => self.on_request(now, source, destination, &m),
            Class::Indication => m.check_fingerprint(),
            Class::Success | Class::Error => self.on_response(now, source, destination, &m),
        };
        if consumed {
            self.handle_timeout(now);
        }
        consumed
    }

    fn respond(&mut self, src: SocketAddr, dst: SocketAddr, b: MessageBuilder) {
        self.transmits.push_back(Transmit {
            source: dst,
            destination: src,
            contents: b.fingerprint().build(),
        });
    }

    fn on_request(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        m: &Message<'_>,
    ) -> bool {
        if !m.check_fingerprint() {
            return false;
        }
        let err =
            |code: u16, reason: &str| MessageBuilder::response(m, Class::Error).error(code, reason);
        let (Some(username), true) = (m.get_str(attr::USERNAME), m.has(attr::MESSAGE_INTEGRITY))
        else {
            self.respond(source, destination, err(400, "Bad Request"));
            return true;
        };
        let first = username.split(':').next().unwrap_or("");
        let (pwd, current) = if first == self.config.local.ufrag {
            (self.config.local.pwd.clone(), true)
        } else if let Some(p) = self.prev_local.as_ref().filter(|p| p.ufrag == first) {
            (p.pwd.clone(), false)
        } else {
            self.respond(source, destination, err(401, "Unauthorized"));
            return true;
        };
        if !m.check_integrity(pwd.as_bytes()) {
            self.respond(source, destination, err(401, "Unauthorized"));
            return true;
        }
        let Some(priority) = m.get_u32(attr::PRIORITY) else {
            self.respond(source, destination, err(400, "Bad Request"));
            return true;
        };
        let tb = |t: u16| -> Result<Option<u64>, ()> {
            match m.get(t) {
                None => Ok(None),
                Some(v) => <[u8; 8]>::try_from(v)
                    .map(|b| Some(u64::from_be_bytes(b)))
                    .map_err(|_| ()),
            }
        };
        let (Ok(remote_controlling), Ok(remote_controlled)) =
            (tb(attr::ICE_CONTROLLING), tb(attr::ICE_CONTROLLED))
        else {
            self.respond(source, destination, err(400, "Bad Request"));
            return true;
        };
        // Role conflict, RFC 8445 §7.3.1.1 (the role is the agent's, for every component).
        if !self.config.lite {
            let conflict = if self.controlling {
                remote_controlling.map(|t| self.tie_breaker >= t)
            } else {
                remote_controlled.map(|t| self.tie_breaker < t)
            };
            match conflict {
                Some(true) => {
                    let b = err(487, "Role Conflict").integrity(pwd.as_bytes());
                    self.respond(source, destination, b);
                    return true;
                }
                Some(false) => {
                    let c = !self.controlling;
                    self.set_role(c);
                }
                None => {}
            }
        }
        let b =
            MessageBuilder::response(m, Class::Success).xor_addr(attr::XOR_MAPPED_ADDRESS, source);
        let b = self.ecn_echo(m, b).integrity(pwd.as_bytes());
        self.respond(source, destination, b);
        if !current {
            return true;
        }
        let use_candidate = m.has(attr::USE_CANDIDATE);
        let nomination = m.get_u32(ATTR_NOMINATION);
        if self.config.lite {
            // A lite agent may have no candidate on that address (one component): component 1.
            let comp = self.component_of(destination).unwrap_or(1);
            let c = self.comp_mut(comp);
            c.lite_last_check = Some(now);
            c.lite_valid = Some((destination, source));
            // The last USE-CANDIDATE check wins, unless renomination says it is older.
            let newer = nomination.is_none_or(|n| n > c.remote_nomination);
            if use_candidate && newer {
                if let Some(n) = nomination {
                    c.remote_nomination = n;
                }
                self.select(comp, destination, source, now);
            }
            return true;
        }
        // Peer-reflexive remote candidate, RFC 8445 §7.3.1.3, of the component of the local
        // candidate the request arrived on.
        let Some(local) = self
            .local_cands
            .iter()
            .find(|c| c.kind() != CandidateKind::PeerReflexive && c.send_addr() == destination)
            .cloned()
        else {
            return true;
        };
        let comp = local.component();
        // Over TCP the remote end is of the opposite type (RFC 6544 §7.2).
        let remote_tcp = local.tcp_type().map(|t| match t {
            TcpType::Passive => TcpType::Active,
            TcpType::Active => TcpType::Passive,
            TcpType::So => TcpType::So,
        });
        let known = self
            .remote_cands
            .iter()
            .find(|r| r.addr() == source && r.tcp_type() == remote_tcp && r.component() == comp);
        let remote = if let Some(r) = known {
            r.clone()
        } else {
            if self.remote_cands.len() >= MAX_REMOTE_CANDIDATES {
                return true;
            }
            let mut r = Candidate::remote_prflx(source, priority, remote_tcp);
            r.set_component(comp);
            self.remote_cands.push(r.clone());
            r
        };
        self.add_pair(&local, &remote);
        let nominated = use_candidate && !self.controlling;
        let Some(i) = self
            .pairs
            .iter()
            .position(|p| p.local == destination && p.remote == source)
        else {
            return true;
        };
        if nominated {
            self.pairs[i].remote_nominated = true;
            self.pairs[i].remote_nomination = nomination;
        }
        match self.pairs[i].state {
            PairState::Succeeded => {
                if nominated && self.accept_nomination(i) {
                    self.select(comp, destination, source, now);
                }
            }
            PairState::InProgress => {}
            PairState::Frozen | PairState::Waiting | PairState::Failed => {
                self.pairs[i].state = PairState::Waiting;
                if !self.triggered.contains(&(destination, source)) {
                    self.triggered.push_back((destination, source));
                }
            }
        }
        true
    }

    fn on_response(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        m: &Message<'_>,
    ) -> bool {
        let tid = m.transaction_id();
        if m.has(attr::FINGERPRINT) && !m.check_fingerprint() {
            return false;
        }
        if self.ecn_response(now, m) {
            return true;
        }
        let Some(i) = self
            .pairs
            .iter()
            .position(|p| p.tx.as_ref().is_some_and(|t| t.tid == tid))
        else {
            return self.on_consent_response(now, source, destination, m);
        };
        let Some(tx) = self.pairs[i].tx.as_ref() else {
            return true;
        };
        if !m.check_integrity(tx.key.as_bytes()) {
            return true;
        }
        let Some(tx) = self.pairs[i].tx.take() else {
            return true;
        };
        self.retire(tx.tid);
        let key = (self.pairs[i].local, self.pairs[i].remote);
        let comp = self.pairs[i].component;
        // Non-symmetric responses fail the check (RFC 8445 §7.2.5.2.1).
        if source != key.1 || destination != key.0 {
            self.fail_pair(i);
            return true;
        }
        if m.class() == Class::Error {
            if m.error_code().map(|e| e.0) == Some(487) {
                // RFC 8445 §7.2.5.1: take the other role than the one in the request, retry.
                self.set_role(!tx.controlling);
                let p = &mut self.pairs[i];
                if p.state != PairState::Succeeded {
                    p.state = PairState::Waiting;
                }
                if !self.controlling {
                    p.nominate = false;
                    let c = self.comp_mut(comp);
                    if c.nominating == Some(key) {
                        c.nominating = None;
                    }
                }
                self.triggered.retain(|k| *k != key);
                self.triggered.push_front(key);
            } else {
                self.fail_pair(i);
            }
            return true;
        }
        let Some(mapped) = m.get_xor_addr(attr::XOR_MAPPED_ADDRESS) else {
            self.fail_pair(i);
            return true;
        };
        // Peer-reflexive local candidate, RFC 8445 §7.2.5.3.1.
        if self.local_cands.len() < MAX_LOCAL_CANDIDATES
            && !self.local_cands.iter().any(|c| c.addr() == mapped)
        {
            let mut c = Candidate::peer_reflexive(mapped, key.0, tx.priority);
            c.set_component(comp);
            self.local_cands.push(c);
        }
        let p = &mut self.pairs[i];
        p.state = PairState::Succeeded;
        let remote_nominated = p.remote_nominated;
        let nominate = p.nominate;
        let prio = p.prio;
        p.nominate = false;
        // Unfreeze the pairs of the same foundations, in every component (RFC 8445
        // §7.2.5.3.3): once RTP works on a path, RTCP's pairs on it are checked.
        let found = (p.local_foundation.clone(), p.remote_foundation.clone());
        for q in &mut self.pairs {
            if q.state == PairState::Frozen
                && q.local_foundation == found.0
                && q.remote_foundation == found.1
            {
                q.state = PairState::Waiting;
            }
        }
        let selected = self.selected_prio(comp);
        let c = self.comp_mut(comp);
        c.first_valid_at.get_or_insert(now);
        if selected.is_some_and(|s| prio > s) {
            c.improved_at.get_or_insert(now);
        }
        let nominated = if self.controlling {
            // An explicit nomination always moves the selection; an aggressive one only to a
            // better pair.
            tx.use_candidate
                && ((tx.nominating && nominate)
                    || (self.config.aggressive_nomination && selected.is_none_or(|s| prio > s)))
        } else {
            remote_nominated && self.accept_nomination(i)
        };
        if nominated {
            self.select(comp, key.0, key.1, now);
        }
        if self
            .comp(comp)
            .selected
            .as_ref()
            .is_some_and(|s| s.local == key.0 && s.remote == key.1)
        {
            self.consent_ok(comp, now);
        }
        true
    }

    fn on_consent_response(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        m: &Message<'_>,
    ) -> bool {
        let tid = m.transaction_id();
        let Some((ci, i)) = self.comps.iter().enumerate().find_map(|(ci, c)| {
            c.consent_txs
                .iter()
                .position(|t| t.tid == tid)
                .map(|i| (ci, i))
        }) else {
            return self.done_tids.contains(&tid);
        };
        let t = &self.comps[ci].consent_txs[i];
        if !m.check_integrity(t.key.as_bytes()) {
            return true;
        }
        let ok = m.class() == Class::Success && t.local == destination && t.remote == source;
        self.comps[ci].consent_txs.remove(i);
        self.retire(tid);
        if ok
            && self.comps[ci]
                .selected
                .as_ref()
                .is_some_and(|s| s.local == destination && s.remote == source)
        {
            // ci < 256: the components are clamped.
            self.consent_ok(ci as u16 + 1, now);
        }
        true
    }

    fn consent_ok(&mut self, component: u16, now: Instant) {
        let c = self.comp_mut(component);
        c.consent_last = now;
        c.consent_lost = false;
    }

    pub(crate) fn retire(&mut self, tid: [u8; 12]) {
        if self.done_tids.len() >= MAX_DONE_TX {
            self.done_tids.pop_front();
        }
        self.done_tids.push_back(tid);
    }

    fn fail_pair(&mut self, i: usize) {
        if let Some(tx) = self.pairs[i].tx.take() {
            self.retire(tx.tid);
        }
        let p = &mut self.pairs[i];
        p.state = PairState::Failed;
        p.nominate = false;
        let (key, comp) = ((p.local, p.remote), p.component);
        let c = self.comp_mut(comp);
        if c.nominating == Some(key) {
            c.nominating = None;
        }
    }

    fn set_role(&mut self, controlling: bool) {
        if self.controlling == controlling {
            return;
        }
        self.controlling = controlling;
        for p in &mut self.pairs {
            p.prio = pair_priority(controlling, p.local_prio, p.remote_prio);
            if !controlling {
                p.nominate = false;
            }
        }
        if !controlling {
            for c in &mut self.comps {
                c.nominating = None;
            }
        }
    }

    /// Renomination is in use: supported here and by the remote (a lite remote never
    /// renominates nor needs it).
    fn renominating(&self) -> bool {
        self.config.renomination && self.remote_renomination && !self.remote_lite
    }

    /// Controlling and still looking for better pairs after a selection: aggressive
    /// nomination or renomination.
    fn keeps_improving(&self) -> bool {
        self.controlling
            && !self.config.lite
            && (self.config.aggressive_nomination || self.renominating())
    }

    /// The priority of the pair of `component` selected in the current generation.
    fn selected_prio(&self, component: u16) -> Option<u64> {
        self.comp(component)
            .selected
            .as_ref()
            .filter(|s| s.generation == self.generation)
            .map(|s| s.prio)
    }

    /// Whether an ordinary check may start on `p`: before a selection of its component in
    /// this generation any; after it only, when still looking, of a better pair.
    fn ordinary_check_ok(&self, p: &Pair) -> bool {
        match self.selected_prio(p.component) {
            None => true,
            Some(s) => self.keeps_improving() && p.prio > s,
        }
    }

    /// Controlled: whether the remote's nomination of valid pair `i` selects it (for its
    /// component). With a NOMINATION value, when it is higher than the one selected
    /// (renomination); without, when nothing is selected in this generation or the pair is
    /// better than the selected one (aggressive nomination: the highest-priority nominated
    /// pair is used).
    fn accept_nomination(&mut self, i: usize) -> bool {
        let p = &self.pairs[i];
        let comp = p.component;
        match p.remote_nomination {
            Some(n) => {
                let c = self.comp_mut(comp);
                if n > c.remote_nomination {
                    c.remote_nomination = n;
                    true
                } else {
                    false
                }
            }
            None => {
                let prio = p.prio;
                self.selected_prio(comp).is_none_or(|s| prio > s)
            }
        }
    }

    fn add_pair(&mut self, local: &Candidate, remote: &Candidate) {
        let la = local.send_addr();
        let ra = remote.addr();
        if !local.pairs_with(remote) {
            return;
        }
        let comp = local.component();
        let prio = pair_priority(self.controlling, local.priority(), remote.priority());
        if let Some(p) = self
            .pairs
            .iter_mut()
            .find(|p| p.local == la && p.remote == ra)
        {
            // Redundant pair (same base and remote, RFC 8445 §6.1.2.4): keep the higher priority.
            if prio > p.prio {
                p.prio = prio;
                p.local_prio = local.priority();
                p.local_pref = local.local_pref();
                p.local_foundation = local.foundation().to_owned();
            }
            return;
        }
        if self.pairs.len() >= MAX_PAIRS {
            return;
        }
        // Initial states, RFC 8445 §6.1.2.6: of the pairs of one foundation, the one of the
        // lowest component (the highest priority among those) is Waiting, the others Frozen
        // until a pair of the foundation succeeds. With trickle the pairs come in any order:
        // a new pair is Frozen behind a pair of the foundation of a lower component that has
        // not failed, or of its own component that is being checked; a new pair of a lower
        // component freezes again the Waiting (not yet checked) pairs of higher ones.
        let (lf, rf) = (local.foundation(), remote.foundation());
        let same = |p: &Pair| p.local_foundation == lf && p.remote_foundation == rf;
        let succeeded = self
            .pairs
            .iter()
            .any(|p| same(p) && p.state == PairState::Succeeded);
        let blocked = self.pairs.iter().any(|p| {
            same(p)
                && ((p.component < comp && p.state != PairState::Failed)
                    || (p.component == comp
                        && matches!(p.state, PairState::Waiting | PairState::InProgress)))
        });
        let waiting = succeeded || !blocked;
        if waiting && !succeeded {
            let triggered = &self.triggered;
            for p in &mut self.pairs {
                if same(p)
                    && p.component > comp
                    && p.state == PairState::Waiting
                    && p.tx.is_none()
                    && !triggered.contains(&(p.local, p.remote))
                {
                    p.state = PairState::Frozen;
                }
            }
        }
        self.pairs.push(Pair {
            component: comp,
            local: la,
            local_prio: local.priority(),
            local_pref: local.local_pref(),
            local_foundation: local.foundation().to_owned(),
            remote: ra,
            remote_prio: remote.priority(),
            remote_foundation: remote.foundation().to_owned(),
            prio,
            state: if waiting {
                PairState::Waiting
            } else {
                PairState::Frozen
            },
            tx: None,
            remote_nominated: false,
            remote_nomination: None,
            nominate: false,
            nomination: 0,
            passive: local.tcp_type() == Some(TcpType::Passive),
        });
        self.checking_since.get_or_insert(self.now);
    }

    fn select(&mut self, comp: u16, local: SocketAddr, remote: SocketAddr, now: Instant) {
        let generation = self.generation;
        let changed =
            self.comp(comp).selected.as_ref().is_none_or(|s| {
                s.local != local || s.remote != remote || s.generation != generation
            });
        if !changed {
            return;
        }
        let (local_pref, prio) = self
            .pairs
            .iter()
            .find(|p| p.local == local && p.remote == remote)
            .map_or((65_535, 0), |p| (p.local_pref, p.prio));
        let sel = Selected {
            local,
            remote,
            local_ufrag: self.config.local.ufrag.clone(),
            remote_creds: self.remote_creds.clone(),
            local_pref,
            generation,
            prio,
        };
        let c = self.comp_mut(comp);
        c.selected = Some(sel);
        c.nominating = None;
        c.improved_at = None;
        // Stop checking the other pairs of the component (RFC 8445 §8.1.2), except, while
        // still looking for better pairs (aggressive nomination, renomination), the better
        // ones; a pair the remote nominates later gets a triggered check again. The other
        // components' checks go on.
        let keep = self.keeps_improving();
        for i in 0..self.pairs.len() {
            let p = &self.pairs[i];
            if p.component == comp
                && p.tx.is_some()
                && (p.local, p.remote) != (local, remote)
                && !(keep && p.prio > prio)
            {
                self.fail_pair(i);
            }
        }
        let pairs = &self.pairs;
        self.triggered.retain(|k| {
            *k == (local, remote)
                || pairs.iter().any(|p| {
                    (p.local, p.remote) == *k && (p.component != comp || (keep && p.prio > prio))
                })
        });
        self.consent_ok(comp, now);
        let delay = self.consent_delay();
        let mut retired = Vec::new();
        let c = self.comp_mut(comp);
        while let Some(t) = c.consent_txs.pop_front() {
            retired.push(t.tid);
        }
        c.consent_next = Some(now + delay);
        for t in retired {
            self.retire(t);
        }
        self.events.push_back(if comp == 1 {
            IceEvent::SelectedPair { local, remote }
        } else {
            IceEvent::ComponentSelectedPair {
                component: comp,
                local,
                remote,
            }
        });
    }

    fn consent_delay(&self) -> Duration {
        // ±20 % (RFC 7675 §5.1).
        let r = (random_u64() >> 11) as f64 / (1u64 << 53) as f64;
        self.config.consent_interval.mul_f64(0.8 + 0.4 * r)
    }

    fn build_request(
        &self,
        remote: &Credentials,
        local_ufrag: &str,
        local_pref: u32,
        component: u16,
        use_candidate: bool,
        nomination: Option<u32>,
    ) -> ([u8; 12], Vec<u8>, u32) {
        let (tid, b, priority) = self.request_builder(
            remote,
            local_ufrag,
            local_pref,
            component,
            use_candidate,
            nomination,
        );
        let packet = b.integrity(remote.pwd.as_bytes()).fingerprint().build();
        (tid, packet, priority)
    }

    /// A connectivity check carrying the ECN-CHECK value `ecn_check` (RFC 6679 §7.2.2).
    pub(crate) fn build_request_with(
        &self,
        remote: &Credentials,
        local_ufrag: &str,
        local_pref: u32,
        component: u16,
        ecn_check: Option<&[u8; 4]>,
    ) -> ([u8; 12], Vec<u8>, u32) {
        let (tid, mut b, priority) =
            self.request_builder(remote, local_ufrag, local_pref, component, false, None);
        if let Some(v) = ecn_check {
            b = b.attr(crate::ecn::ATTR_ECN_CHECK, v);
        }
        let packet = b.integrity(remote.pwd.as_bytes()).fingerprint().build();
        (tid, packet, priority)
    }

    fn request_builder(
        &self,
        remote: &Credentials,
        local_ufrag: &str,
        local_pref: u32,
        component: u16,
        use_candidate: bool,
        nomination: Option<u32>,
    ) -> ([u8; 12], MessageBuilder, u32) {
        let mut tid = [0u8; 12];
        random_bytes(&mut tid);
        // PRIORITY: that of a peer-reflexive candidate of the component (RFC 8445 §7.1.1).
        let priority = candidate::priority(110, local_pref, component);
        let mut b = MessageBuilder::new(Method::BINDING, Class::Request, tid)
            .attr(
                attr::USERNAME,
                format!("{}:{}", remote.ufrag, local_ufrag).as_bytes(),
            )
            .u32(attr::PRIORITY, priority);
        b = if self.controlling {
            b.attr(attr::ICE_CONTROLLING, &self.tie_breaker.to_be_bytes())
        } else {
            b.attr(attr::ICE_CONTROLLED, &self.tie_breaker.to_be_bytes())
        };
        if use_candidate {
            b = b.attr(attr::USE_CANDIDATE, &[]);
            if let Some(n) = nomination {
                b = b.u32(ATTR_NOMINATION, n);
            }
        }
        (tid, b, priority)
    }

    fn start_check(&mut self, i: usize, now: Instant) -> bool {
        let Some(remote) = self.remote_creds.clone() else {
            return false;
        };
        let nominating = self.controlling && self.pairs[i].nominate;
        let use_candidate = nominating || (self.controlling && self.config.aggressive_nomination);
        let nomination = (nominating && self.renominating()).then_some(self.pairs[i].nomination);
        let (tid, packet, priority) = self.build_request(
            &remote,
            &self.config.local.ufrag,
            self.pairs[i].local_pref,
            self.pairs[i].component,
            use_candidate,
            nomination,
        );
        let p = &mut self.pairs[i];
        if p.state != PairState::Succeeded {
            p.state = PairState::InProgress;
        }
        self.transmits.push_back(Transmit {
            source: p.local,
            destination: p.remote,
            contents: packet.clone(),
        });
        p.tx = Some(Tx {
            tid,
            packet,
            sends: 1,
            rto: self.config.check_rto,
            next: now + self.config.check_rto,
            use_candidate,
            nominating,
            controlling: self.controlling,
            priority,
            key: remote.pwd,
        });
        true
    }

    fn can_send_checks(&self) -> bool {
        !self.config.lite && !self.closed && self.remote_creds.is_some()
    }

    fn has_pending_check(&self) -> bool {
        if !self.can_send_checks() {
            return false;
        }
        !self.triggered.is_empty() || self.ordinary_pending()
    }

    /// Whether a pair waits for an ordinary check this agent may start.
    fn ordinary_pending(&self) -> bool {
        self.pairs.iter().any(|p| {
            p.tx.is_none()
                && !p.passive
                && matches!(p.state, PairState::Waiting | PairState::Frozen)
                && self.ordinary_check_ok(p)
        })
    }

    /// Sends the next paced check, if any: the triggered queue first, then the
    /// highest-priority Waiting pair, then the highest-priority Frozen one (of any
    /// component: component 1's pairs rank first).
    fn send_next_check(&mut self, now: Instant) -> bool {
        if !self.can_send_checks() {
            return false;
        }
        while let Some(key) = self.triggered.pop_front() {
            if let Some(i) = self
                .pairs
                .iter()
                .position(|p| (p.local, p.remote) == key && p.tx.is_none())
            {
                if self.pairs[i].state != PairState::Failed && self.start_check(i, now) {
                    return true;
                }
            }
        }
        let pick = |st: PairState| {
            self.pairs
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    p.tx.is_none() && !p.passive && p.state == st && self.ordinary_check_ok(p)
                })
                .max_by_key(|(_, p)| p.prio)
                .map(|(i, _)| i)
        };
        match pick(PairState::Waiting).or_else(|| pick(PairState::Frozen)) {
            Some(i) => self.start_check(i, now),
            None => false,
        }
    }

    /// When the controlling agent nominates a pair of `comp` (RFC 8445 §8.1.1 runs per
    /// component).
    fn nomination_deadline(&self, comp: u16) -> Option<Instant> {
        let c = self.comp(comp);
        if !self.controlling
            || self.config.lite
            || c.nominating.is_some()
            || !self.can_send_checks()
        {
            return None;
        }
        // Aggressive nomination nominates with every check; renomination nominates again a
        // pair better than the selected one.
        let selected = self.selected_prio(comp);
        if (self.config.aggressive_nomination && !self.remote_lite)
            || (selected.is_some() && !self.renominating())
        {
            return None;
        }
        let best = self.best_valid(comp)?;
        if selected.is_some_and(|s| best.prio <= s) {
            return None;
        }
        let pending_higher = self.pairs.iter().any(|p| {
            p.component == comp
                && p.prio > best.prio
                && matches!(
                    p.state,
                    PairState::Frozen | PairState::Waiting | PairState::InProgress
                )
        });
        if self.remote_lite || !pending_higher {
            Some(self.now)
        } else {
            let since = if selected.is_some() {
                c.improved_at
            } else {
                c.first_valid_at
            };
            since.map(|t| t + self.config.nomination_delay)
        }
    }

    fn best_valid(&self, comp: u16) -> Option<&Pair> {
        self.pairs
            .iter()
            .filter(|p| p.component == comp && p.state == PairState::Succeeded && p.tx.is_none())
            .max_by_key(|p| p.prio)
    }

    /// Drives timers: retransmissions, paced checks, nomination, consent.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.closed || self.fixed {
            return;
        }
        self.now = self.now.max(now);
        // Retransmissions.
        let max_sends = self.config.check_max_sends;
        let rto_max = self.config.check_rto_max;
        for i in 0..self.pairs.len() {
            let (source, destination) = (self.pairs[i].local, self.pairs[i].remote);
            let Some(tx) = self.pairs[i].tx.as_mut() else {
                continue;
            };
            if tx.next > now {
                continue;
            }
            if tx.sends >= max_sends {
                self.fail_pair(i);
                continue;
            }
            tx.sends += 1;
            tx.rto = (tx.rto * 2).min(rto_max);
            tx.next = now + tx.rto;
            let t = Transmit {
                source,
                destination,
                contents: tx.packet.clone(),
            };
            self.transmits.push_back(t);
        }
        // Nomination (regular, RFC 8445 §8.1.1), per component.
        for comp in 1..=self.config.components {
            if !self.nomination_deadline(comp).is_some_and(|d| d <= now) {
                continue;
            }
            let Some(key) = self.best_valid(comp).map(|p| (p.local, p.remote)) else {
                continue;
            };
            let n = if self.renominating() {
                self.nomination = self.nomination.wrapping_add(1).max(1);
                self.nomination
            } else {
                0
            };
            if let Some(p) = self.pairs.iter_mut().find(|p| (p.local, p.remote) == key) {
                p.nominate = true;
                p.nomination = n;
            }
            self.comp_mut(comp).nominating = Some(key);
            self.triggered.retain(|k| *k != key);
            self.triggered.push_front(key);
        }
        // Paced checks.
        if now >= self.next_check && self.send_next_check(now) {
            self.next_check = now + self.config.ta;
        }
        // Consent freshness (RFC 7675), per component.
        if !self.config.lite {
            self.consent_tick(now);
        }
        self.ecn_tick(now);
        self.update_state(now);
    }

    fn consent_tick(&mut self, now: Instant) {
        for comp in 1..=self.config.components {
            let ci = usize::from(comp - 1);
            let Some(sel) = self.comps[ci].selected.clone() else {
                continue;
            };
            for t in &mut self.comps[ci].consent_txs {
                if t.sends < CONSENT_SENDS && t.next <= now {
                    t.sends += 1;
                    t.rto *= 2;
                    t.next = now + t.rto;
                    self.transmits.push_back(Transmit {
                        source: t.local,
                        destination: t.remote,
                        contents: t.packet.clone(),
                    });
                }
            }
            if self.comps[ci].consent_next.is_some_and(|t| t <= now) {
                if let Some(remote) = sel.remote_creds.as_ref() {
                    let (tid, packet, _) = self.build_request(
                        remote,
                        &sel.local_ufrag,
                        sel.local_pref,
                        comp,
                        false,
                        None,
                    );
                    self.transmits.push_back(Transmit {
                        source: sel.local,
                        destination: sel.remote,
                        contents: packet.clone(),
                    });
                    if self.comps[ci].consent_txs.len() >= MAX_CONSENT_TX {
                        if let Some(old) = self.comps[ci].consent_txs.pop_front() {
                            self.retire(old.tid);
                        }
                    }
                    self.comps[ci].consent_txs.push_back(ConsentTx {
                        tid,
                        key: remote.pwd.clone(),
                        local: sel.local,
                        remote: sel.remote,
                        packet,
                        sends: 1,
                        rto: CONSENT_RTO,
                        next: now + CONSENT_RTO,
                    });
                }
                let delay = self.consent_delay();
                self.comps[ci].consent_next = Some(now + delay);
            }
            let timeout = self.config.consent_timeout;
            let c = &mut self.comps[ci];
            if !c.consent_lost && now >= c.consent_last + timeout {
                c.consent_lost = true;
            }
        }
    }

    fn checks_done(&self) -> bool {
        self.triggered.is_empty()
            && self.pairs.iter().all(|p| p.tx.is_none())
            && !(self.keeps_improving() && self.ordinary_pending())
    }

    /// Whether `comp`, which has no selected pair, cannot get one: no triggered check of it
    /// waits and every one of its pairs (if any) failed.
    fn comp_failed(&self, comp: u16) -> bool {
        !self
            .triggered
            .iter()
            .any(|k| self.pair_component(k).is_none_or(|c| c == comp))
            && self
                .pairs
                .iter()
                .filter(|p| p.component == comp)
                .all(|p| p.state == PairState::Failed)
    }

    fn update_state(&mut self, now: Instant) {
        if self.closed || self.fixed {
            return;
        }
        let all_selected = self.comps.iter().all(|c| c.selected.is_some());
        let new = if self.config.lite {
            let timeout = self.config.consent_timeout;
            let lost = self
                .comps
                .iter()
                .any(|c| c.lite_last_check.is_some_and(|t| now >= t + timeout));
            if all_selected {
                if lost {
                    IceState::Disconnected
                } else {
                    IceState::Completed
                }
            } else if self.comps.iter().any(|c| c.lite_last_check.is_some()) {
                if lost {
                    IceState::Disconnected
                } else {
                    IceState::Checking
                }
            } else {
                IceState::New
            }
        } else if all_selected {
            let generation = self.generation;
            let current = self.comps.iter().all(|c| {
                c.selected
                    .as_ref()
                    .is_some_and(|s| s.generation == generation)
            });
            if self.comps.iter().any(|c| c.consent_lost) {
                IceState::Disconnected
            } else if current && (self.completed_gen == Some(generation) || self.checks_done()) {
                self.completed_gen = Some(generation);
                IceState::Completed
            } else {
                IceState::Connected
            }
        } else if self.pairs.is_empty() && self.checking_since.is_none() {
            if self.state == IceState::Failed {
                IceState::Failed
            } else {
                IceState::New
            }
        } else {
            let give_up = self.end_of_candidates
                || self
                    .checking_since
                    .is_some_and(|t| now >= t + self.config.failed_timeout);
            let failed = (1..=self.config.components)
                .any(|c| self.comp(c).selected.is_none() && self.comp_failed(c));
            if failed && give_up {
                IceState::Failed
            } else {
                IceState::Checking
            }
        };
        self.set_state(new);
    }

    fn set_state(&mut self, new: IceState) {
        if new == self.state {
            return;
        }
        if new == IceState::Completed
            && matches!(
                self.state,
                IceState::New | IceState::Checking | IceState::Failed
            )
        {
            self.events
                .push_back(IceEvent::StateChanged(IceState::Connected));
        }
        self.state = new;
        self.events.push_back(IceEvent::StateChanged(new));
    }

    /// When [`IceAgent::handle_timeout`] wants to be called next (`None`: no timer).
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.closed || self.fixed {
            return None;
        }
        let mut t: Option<Instant> = None;
        let mut at = |x: Instant| t = Some(t.map_or(x, |t| t.min(x)));
        if let Some(x) = self.ecn_timeout() {
            at(x);
        }
        for p in &self.pairs {
            if let Some(tx) = &p.tx {
                at(tx.next);
            }
        }
        if self.has_pending_check() {
            at(self.next_check.max(self.now));
        }
        for comp in 1..=self.config.components {
            if let Some(d) = self.nomination_deadline(comp) {
                at(d.max(self.now));
            }
        }
        for c in &self.comps {
            if c.selected.is_some() && !self.config.lite {
                if let Some(n) = c.consent_next {
                    at(n);
                }
                for x in &c.consent_txs {
                    if x.sends < CONSENT_SENDS {
                        at(x.next);
                    }
                }
                if !c.consent_lost {
                    at(c.consent_last + self.config.consent_timeout);
                }
            }
            if self.config.lite && self.state != IceState::Disconnected {
                if let Some(l) = c.lite_last_check {
                    at(l + self.config.consent_timeout);
                }
            }
        }
        if self.comps.iter().any(|c| c.selected.is_none()) && self.state != IceState::Failed {
            if let Some(c) = self.checking_since {
                let d = c + self.config.failed_timeout;
                if d > self.now {
                    at(d);
                }
            }
        }
        t
    }

    /// The next datagram to send.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<IceEvent> {
        self.events.pop_front()
    }

    /// The current state.
    pub fn state(&self) -> IceState {
        self.state
    }

    /// The selected (nominated) pair of component 1: (local address, remote address).
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.selected_pair_of(1)
    }

    /// The selected (nominated) pair of `component` (`None` for a component the stream does
    /// not have).
    pub fn selected_pair_of(&self, component: u16) -> Option<(SocketAddr, SocketAddr)> {
        if !self.has_component(component) {
            return None;
        }
        self.comp(component)
            .selected
            .as_ref()
            .map(|s| (s.local, s.remote))
    }

    /// Where application data of component 1 goes (local address to send from, remote
    /// address): the selected pair, else the highest-priority valid pair (before nomination);
    /// for a lite agent, the pair the last valid check with USE-CANDIDATE arrived on, else the
    /// last valid check's.
    pub fn send_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.send_pair_of(1)
    }

    /// Where application data of `component` goes (RTCP without rtcp-mux: component 2), by
    /// the rules of [`IceAgent::send_pair`].
    pub fn send_pair_of(&self, component: u16) -> Option<(SocketAddr, SocketAddr)> {
        if let Some(s) = self.selected_pair_of(component) {
            return Some(s);
        }
        if !self.has_component(component) {
            return None;
        }
        if self.config.lite {
            return self.comp(component).lite_valid;
        }
        self.pairs
            .iter()
            .filter(|p| p.component == component && p.state == PairState::Succeeded)
            .max_by_key(|p| p.prio)
            .map(|p| (p.local, p.remote))
    }

    /// Uses `local` -> `remote` as the path of `component` without ICE, for a peer that does
    /// not do ICE (an SDP without `a=ice-ufrag`: plain `c=` address and `m=` port, as SIP
    /// endpoints write it; the RTCP component at `a=rtcp` or the next port). The pair is
    /// selected at once ([`IceEvent::SelectedPair`] or [`IceEvent::ComponentSelectedPair`]),
    /// and from the first call on the agent runs no checks, consent freshness or timers, and
    /// ignores remote candidates and STUN; once every component has its pair the state is
    /// [`IceState::Completed`]. Calling it again moves the component to another pair (for
    /// example to latch onto the address media really comes from). `false` (and nothing
    /// changes) for a component the stream does not have.
    pub fn set_fixed_pair(
        &mut self,
        component: u16,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> bool {
        if !self.has_component(component) || self.closed {
            return false;
        }
        if !self.fixed {
            self.fixed = true;
            self.pairs.clear();
            self.triggered.clear();
            self.transmits.clear();
            self.ecn_transmits.clear();
            self.ecn_check = None;
            self.checking_since = None;
        }
        let generation = self.generation;
        let changed = self
            .comp(component)
            .selected
            .as_ref()
            .is_none_or(|s| s.local != local || s.remote != remote);
        let sel = Selected {
            local,
            remote,
            local_ufrag: self.config.local.ufrag.clone(),
            remote_creds: None,
            local_pref: 65_535,
            generation,
            prio: 0,
        };
        let c = self.comp_mut(component);
        c.selected = Some(sel);
        c.nominating = None;
        c.consent_next = None;
        c.consent_lost = false;
        c.consent_txs.clear();
        if changed {
            self.events.push_back(if component == 1 {
                IceEvent::SelectedPair { local, remote }
            } else {
                IceEvent::ComponentSelectedPair {
                    component,
                    local,
                    remote,
                }
            });
        }
        if self.comps.iter().all(|c| c.selected.is_some()) {
            self.completed_gen = Some(generation);
            self.set_state(IceState::Completed);
        }
        true
    }

    /// Whether the paths are given ([`IceAgent::set_fixed_pair`]) instead of found by ICE.
    pub fn is_fixed(&self) -> bool {
        self.fixed
    }

    /// Stops the agent: no more timers or transmissions; received datagrams are no longer
    /// consumed. The state is left as it was.
    pub fn close(&mut self) {
        self.closed = true;
        self.transmits.clear();
        self.ecn_transmits.clear();
        self.ecn_check = None;
        self.pairs.iter_mut().for_each(|p| p.tx = None);
        self.triggered.clear();
    }
}
