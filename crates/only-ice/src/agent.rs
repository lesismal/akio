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

/// The agent state (the `RTCIceConnectionState` values that apply to one component).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IceState {
    /// Nothing started yet.
    New,
    /// Checks are running (a lite agent: valid checks arrived) but nothing is selected.
    Checking,
    /// A pair is selected; checks may still be running.
    Connected,
    /// A pair is selected and nothing is left to check.
    Completed,
    /// Consent expired on the selected pair (it may come back).
    Disconnected,
    /// Every pair failed (after end-of-candidates or [`IceConfig::failed_timeout`]).
    Failed,
}

/// What happened, from [`IceAgent::poll_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IceEvent {
    /// The state changed.
    StateChanged(IceState),
    /// A pair was selected (nominated): the first time, when it changes, and after each ICE
    /// restart's nomination even if the addresses stay the same.
    SelectedPair {
        /// Local address (the base; the relayed address for a relayed candidate).
        local: SocketAddr,
        /// Remote address.
        remote: SocketAddr,
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
    controlling: bool,
    priority: u32,
    key: String,
}

#[derive(Debug)]
struct Pair {
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
    /// Controlling: the next check carries USE-CANDIDATE.
    nominate: bool,
    /// The local candidate is passive TCP: this side never opens the connection, so the pair
    /// only gets checks triggered by the remote's (over its connection).
    passive: bool,
}

#[derive(Clone, Debug)]
struct Selected {
    local: SocketAddr,
    remote: SocketAddr,
    local_ufrag: String,
    remote_creds: Option<Credentials>,
    local_pref: u32,
    generation: u64,
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

/// A sans-io ICE agent for one component over UDP. See the crate docs for how to drive it.
#[derive(Debug)]
pub struct IceAgent {
    config: IceConfig,
    prev_local: Option<Credentials>,
    remote_creds: Option<Credentials>,
    remote_lite: bool,
    controlling: bool,
    tie_breaker: u64,
    local_cands: Vec<Candidate>,
    remote_cands: Vec<Candidate>,
    pairs: Vec<Pair>,
    triggered: VecDeque<(SocketAddr, SocketAddr)>,
    end_of_candidates: bool,
    generation: u64,
    selected: Option<Selected>,
    completed_gen: Option<u64>,
    nominating: Option<(SocketAddr, SocketAddr)>,
    first_valid_at: Option<Instant>,
    checking_since: Option<Instant>,
    next_check: Instant,
    consent_next: Option<Instant>,
    consent_last: Instant,
    consent_lost: bool,
    consent_txs: VecDeque<ConsentTx>,
    done_tids: VecDeque<[u8; 12]>,
    lite_last_check: Option<Instant>,
    lite_valid: Option<(SocketAddr, SocketAddr)>,
    state: IceState,
    transmits: VecDeque<Transmit>,
    events: VecDeque<IceEvent>,
    closed: bool,
    now: Instant,
}

impl IceAgent {
    /// A new agent.
    pub fn new(config: IceConfig, now: Instant) -> IceAgent {
        let controlling = config.controlling && !config.lite;
        IceAgent {
            config,
            prev_local: None,
            remote_creds: None,
            remote_lite: false,
            controlling,
            tie_breaker: random_u64(),
            local_cands: Vec::new(),
            remote_cands: Vec::new(),
            pairs: Vec::new(),
            triggered: VecDeque::new(),
            end_of_candidates: false,
            generation: 0,
            selected: None,
            completed_gen: None,
            nominating: None,
            first_valid_at: None,
            checking_since: None,
            next_check: now,
            consent_next: None,
            consent_last: now,
            consent_lost: false,
            consent_txs: VecDeque::new(),
            done_tids: VecDeque::new(),
            lite_last_check: None,
            lite_valid: None,
            state: IceState::New,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            closed: false,
            now,
        }
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
    /// drops the remote candidates, the pairs and end-of-candidates; the selected pair stays
    /// in use (with consent on the old credentials) until a new one is nominated.
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
    /// nominates the first valid pair.
    pub fn set_remote_lite(&mut self, yes: bool) {
        self.remote_lite = yes;
        if yes {
            self.set_controlling(true);
        }
    }

    /// Adds a local candidate (gathered by the caller); `false` (and ignored) if one with the
    /// same address, base and transport exists (a UDP and a TCP candidate may share an
    /// address: a server's listeners on one port). Host, server-reflexive and relayed candidates are paired
    /// with the remote candidates of the same IP family.
    pub fn add_local_candidate(&mut self, c: Candidate) -> bool {
        if self.local_cands.len() >= MAX_LOCAL_CANDIDATES
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

    /// Adds a remote candidate (trickle: any time). Ignored: components other than 1,
    /// duplicates of a known address, candidates whose `ufrag` extension names another
    /// generation than the remote credentials. A signaled candidate replaces a peer-reflexive
    /// one with the same address.
    pub fn add_remote_candidate(&mut self, c: Candidate) {
        if c.component() != 1 {
            return;
        }
        if let (Some(u), Some(rc)) = (c.ufrag(), self.remote_creds.as_ref()) {
            if u != rc.ufrag {
                return;
            }
        }
        if let Some(i) = self.remote_cands.iter().position(|r| r.addr() == c.addr()) {
            if self.remote_cands[i].kind() == CandidateKind::PeerReflexive
                && c.kind() != CandidateKind::PeerReflexive
            {
                let controlling = self.controlling;
                for p in self.pairs.iter_mut().filter(|p| p.remote == c.addr()) {
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

    /// The remote signaled end-of-candidates: once every pair failed the state becomes
    /// [`IceState::Failed`].
    pub fn end_of_remote_candidates(&mut self) {
        self.end_of_candidates = true;
        let now = self.now;
        self.update_state(now);
    }

    /// Local ICE restart with new credentials. The pairs are rebuilt (local candidates kept
    /// if `keep_local_candidates`, peer-reflexive ones always dropped); the selected pair stays
    /// in use, and requests on the old credentials are still answered, until a new pair is
    /// nominated. Call [`IceAgent::set_remote_credentials`] with the remote's new credentials
    /// (and re-add its candidates) when the answer arrives.
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
        self.lite_valid = None;
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
        self.nominating = None;
        self.first_valid_at = None;
        self.checking_since = None;
        self.generation += 1;
    }

    /// Handles a received datagram (`source` the remote address, `destination` the local
    /// address it arrived on: a candidate's base, or the relayed address). Returns `true` if
    /// it was a STUN message for this agent (consumed), `false` for anything else (DTLS,
    /// SRTP, other STUN traffic), which the caller handles itself.
    pub fn handle_receive(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> bool {
        if self.closed || !only_turn::stun::is_stun(data) {
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
        // Role conflict, RFC 8445 §7.3.1.1.
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
        let b = MessageBuilder::response(m, Class::Success)
            .xor_addr(attr::XOR_MAPPED_ADDRESS, source)
            .integrity(pwd.as_bytes());
        self.respond(source, destination, b);
        if !current {
            return true;
        }
        let use_candidate = m.has(attr::USE_CANDIDATE);
        if self.config.lite {
            self.lite_last_check = Some(now);
            self.lite_valid = Some((destination, source));
            if use_candidate {
                self.select(destination, source, now);
            }
            return true;
        }
        // Peer-reflexive remote candidate, RFC 8445 §7.3.1.3.
        let Some(local) = self
            .local_cands
            .iter()
            .find(|c| c.kind() != CandidateKind::PeerReflexive && c.send_addr() == destination)
            .cloned()
        else {
            return true;
        };
        // Over TCP the remote end is of the opposite type (RFC 6544 §7.2).
        let remote_tcp = local.tcp_type().map(|t| match t {
            TcpType::Passive => TcpType::Active,
            TcpType::Active => TcpType::Passive,
            TcpType::So => TcpType::So,
        });
        let known = self
            .remote_cands
            .iter()
            .find(|r| r.addr() == source && r.tcp_type() == remote_tcp);
        let remote = if let Some(r) = known {
            r.clone()
        } else {
            if self.remote_cands.len() >= MAX_REMOTE_CANDIDATES {
                return true;
            }
            let r = Candidate::remote_prflx(source, priority, remote_tcp);
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
        self.pairs[i].remote_nominated |= nominated;
        match self.pairs[i].state {
            PairState::Succeeded => {
                if nominated {
                    self.select(destination, source, now);
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
                    if self.nominating == Some(key) {
                        self.nominating = None;
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
            self.local_cands
                .push(Candidate::peer_reflexive(mapped, key.0, tx.priority));
        }
        let p = &mut self.pairs[i];
        p.state = PairState::Succeeded;
        let remote_nominated = p.remote_nominated;
        let nominate = p.nominate;
        p.nominate = false;
        let found = (p.local_foundation.clone(), p.remote_foundation.clone());
        for q in &mut self.pairs {
            if q.state == PairState::Frozen
                && q.local_foundation == found.0
                && q.remote_foundation == found.1
            {
                q.state = PairState::Waiting;
            }
        }
        self.first_valid_at.get_or_insert(now);
        let nominated = if self.controlling {
            tx.use_candidate && nominate
        } else {
            remote_nominated
        };
        if nominated {
            self.select(key.0, key.1, now);
        }
        if self
            .selected
            .as_ref()
            .is_some_and(|s| s.local == key.0 && s.remote == key.1)
        {
            self.consent_ok(now);
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
        let Some(i) = self.consent_txs.iter().position(|t| t.tid == tid) else {
            return self.done_tids.contains(&tid);
        };
        let t = &self.consent_txs[i];
        if !m.check_integrity(t.key.as_bytes()) {
            return true;
        }
        let ok = m.class() == Class::Success && t.local == destination && t.remote == source;
        self.consent_txs.remove(i);
        self.retire(tid);
        if ok
            && self
                .selected
                .as_ref()
                .is_some_and(|s| s.local == destination && s.remote == source)
        {
            self.consent_ok(now);
        }
        true
    }

    fn consent_ok(&mut self, now: Instant) {
        self.consent_last = now;
        self.consent_lost = false;
    }

    fn retire(&mut self, tid: [u8; 12]) {
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
        if self.nominating == Some((p.local, p.remote)) {
            self.nominating = None;
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
            self.nominating = None;
        }
    }

    fn add_pair(&mut self, local: &Candidate, remote: &Candidate) {
        let la = local.send_addr();
        let ra = remote.addr();
        if !local.pairs_with(remote) {
            return;
        }
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
        // Frozen unless no other pair of this foundation is being checked (RFC 8445 §6.1.2.6).
        let active = self.pairs.iter().any(|p| {
            p.local_foundation == local.foundation()
                && p.remote_foundation == remote.foundation()
                && matches!(p.state, PairState::Waiting | PairState::InProgress)
        });
        let succeeded = self.pairs.iter().any(|p| {
            p.local_foundation == local.foundation()
                && p.remote_foundation == remote.foundation()
                && p.state == PairState::Succeeded
        });
        self.pairs.push(Pair {
            local: la,
            local_prio: local.priority(),
            local_pref: local.local_pref(),
            local_foundation: local.foundation().to_owned(),
            remote: ra,
            remote_prio: remote.priority(),
            remote_foundation: remote.foundation().to_owned(),
            prio,
            state: if active && !succeeded {
                PairState::Frozen
            } else {
                PairState::Waiting
            },
            tx: None,
            remote_nominated: false,
            nominate: false,
            passive: local.tcp_type() == Some(TcpType::Passive),
        });
        self.checking_since.get_or_insert(self.now);
    }

    fn select(&mut self, local: SocketAddr, remote: SocketAddr, now: Instant) {
        let changed = self.selected.as_ref().is_none_or(|s| {
            s.local != local || s.remote != remote || s.generation != self.generation
        });
        if !changed {
            return;
        }
        let local_pref = self
            .pairs
            .iter()
            .find(|p| p.local == local && p.remote == remote)
            .map_or(65_535, |p| p.local_pref);
        self.selected = Some(Selected {
            local,
            remote,
            local_ufrag: self.config.local.ufrag.clone(),
            remote_creds: self.remote_creds.clone(),
            local_pref,
            generation: self.generation,
        });
        self.nominating = None;
        // Stop checking the other pairs (RFC 8445 §8.1.2); a pair the remote nominates later
        // gets a triggered check again.
        for i in 0..self.pairs.len() {
            let p = &self.pairs[i];
            if p.tx.is_some() && (p.local, p.remote) != (local, remote) {
                self.fail_pair(i);
            }
        }
        self.triggered.retain(|k| *k == (local, remote));
        self.consent_ok(now);
        while let Some(t) = self.consent_txs.pop_front() {
            self.retire(t.tid);
        }
        self.consent_next = Some(now + self.consent_delay());
        self.events
            .push_back(IceEvent::SelectedPair { local, remote });
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
        use_candidate: bool,
    ) -> ([u8; 12], Vec<u8>, u32) {
        let mut tid = [0u8; 12];
        random_bytes(&mut tid);
        let priority = candidate::priority(110, local_pref, 1);
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
        }
        let packet = b.integrity(remote.pwd.as_bytes()).fingerprint().build();
        (tid, packet, priority)
    }

    fn start_check(&mut self, i: usize, now: Instant) -> bool {
        let Some(remote) = self.remote_creds.clone() else {
            return false;
        };
        let use_candidate = self.controlling && self.pairs[i].nominate;
        let (tid, packet, priority) = self.build_request(
            &remote,
            &self.config.local.ufrag,
            self.pairs[i].local_pref,
            use_candidate,
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
            controlling: self.controlling,
            priority,
            key: remote.pwd,
        });
        true
    }

    fn ordinary_checks_allowed(&self) -> bool {
        self.selected
            .as_ref()
            .is_none_or(|s| s.generation != self.generation)
    }

    fn can_send_checks(&self) -> bool {
        !self.config.lite && !self.closed && self.remote_creds.is_some()
    }

    fn has_pending_check(&self) -> bool {
        if !self.can_send_checks() {
            return false;
        }
        !self.triggered.is_empty()
            || (self.ordinary_checks_allowed()
                && self.pairs.iter().any(|p| {
                    p.tx.is_none()
                        && !p.passive
                        && matches!(p.state, PairState::Waiting | PairState::Frozen)
                }))
    }

    /// Sends the next paced check, if any: the triggered queue first, then the
    /// highest-priority Waiting pair, then the highest-priority Frozen one.
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
        if !self.ordinary_checks_allowed() {
            return false;
        }
        let pick = |st: PairState| {
            self.pairs
                .iter()
                .enumerate()
                .filter(|(_, p)| p.tx.is_none() && !p.passive && p.state == st)
                .max_by_key(|(_, p)| p.prio)
                .map(|(i, _)| i)
        };
        match pick(PairState::Waiting).or_else(|| pick(PairState::Frozen)) {
            Some(i) => self.start_check(i, now),
            None => false,
        }
    }

    fn nomination_deadline(&self) -> Option<Instant> {
        if !self.controlling
            || self.config.lite
            || self.nominating.is_some()
            || !self.ordinary_checks_allowed()
            || !self.can_send_checks()
        {
            return None;
        }
        let best = self.best_valid()?;
        let pending_higher = self.pairs.iter().any(|p| {
            p.prio > best.prio
                && matches!(
                    p.state,
                    PairState::Frozen | PairState::Waiting | PairState::InProgress
                )
        });
        if self.remote_lite || !pending_higher {
            Some(self.now)
        } else {
            self.first_valid_at
                .map(|t| t + self.config.nomination_delay)
        }
    }

    fn best_valid(&self) -> Option<&Pair> {
        self.pairs
            .iter()
            .filter(|p| p.state == PairState::Succeeded && p.tx.is_none())
            .max_by_key(|p| p.prio)
    }

    /// Drives timers: retransmissions, paced checks, nomination, consent.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.closed {
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
        // Nomination (regular, RFC 8445 §8.1.1).
        if self.nomination_deadline().is_some_and(|d| d <= now) {
            if let Some(key) = self.best_valid().map(|p| (p.local, p.remote)) {
                if let Some(p) = self.pairs.iter_mut().find(|p| (p.local, p.remote) == key) {
                    p.nominate = true;
                }
                self.nominating = Some(key);
                self.triggered.retain(|k| *k != key);
                self.triggered.push_front(key);
            }
        }
        // Paced checks.
        if now >= self.next_check && self.send_next_check(now) {
            self.next_check = now + self.config.ta;
        }
        // Consent freshness (RFC 7675).
        if !self.config.lite {
            self.consent_tick(now);
        }
        self.update_state(now);
    }

    fn consent_tick(&mut self, now: Instant) {
        let Some(sel) = self.selected.clone() else {
            return;
        };
        for t in &mut self.consent_txs {
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
        if self.consent_next.is_some_and(|t| t <= now) {
            if let Some(remote) = sel.remote_creds.as_ref() {
                let (tid, packet, _) =
                    self.build_request(remote, &sel.local_ufrag, sel.local_pref, false);
                self.transmits.push_back(Transmit {
                    source: sel.local,
                    destination: sel.remote,
                    contents: packet.clone(),
                });
                if self.consent_txs.len() >= MAX_CONSENT_TX {
                    if let Some(old) = self.consent_txs.pop_front() {
                        self.retire(old.tid);
                    }
                }
                self.consent_txs.push_back(ConsentTx {
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
            self.consent_next = Some(now + self.consent_delay());
        }
        if !self.consent_lost && now >= self.consent_last + self.config.consent_timeout {
            self.consent_lost = true;
        }
    }

    fn checks_done(&self) -> bool {
        self.triggered.is_empty() && self.pairs.iter().all(|p| p.tx.is_none())
    }

    fn update_state(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        let new = if self.config.lite {
            let lost = self
                .lite_last_check
                .is_some_and(|t| now >= t + self.config.consent_timeout);
            if self.selected.is_some() {
                if lost {
                    IceState::Disconnected
                } else {
                    IceState::Completed
                }
            } else if self.lite_last_check.is_some() {
                if lost {
                    IceState::Disconnected
                } else {
                    IceState::Checking
                }
            } else {
                IceState::New
            }
        } else if let Some(sel) = self.selected.as_ref() {
            if self.consent_lost {
                IceState::Disconnected
            } else if self.completed_gen == Some(sel.generation)
                || (sel.generation == self.generation && self.checks_done())
            {
                self.completed_gen = Some(sel.generation);
                if sel.generation == self.generation {
                    IceState::Completed
                } else {
                    IceState::Connected
                }
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
            let all_failed = self.triggered.is_empty()
                && self.pairs.iter().all(|p| p.state == PairState::Failed);
            let give_up = self.end_of_candidates
                || self
                    .checking_since
                    .is_some_and(|t| now >= t + self.config.failed_timeout);
            if all_failed && give_up {
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
        if self.closed {
            return None;
        }
        let mut t: Option<Instant> = None;
        let mut at = |x: Instant| t = Some(t.map_or(x, |t| t.min(x)));
        for p in &self.pairs {
            if let Some(tx) = &p.tx {
                at(tx.next);
            }
        }
        if self.has_pending_check() {
            at(self.next_check.max(self.now));
        }
        if let Some(d) = self.nomination_deadline() {
            at(d.max(self.now));
        }
        if self.selected.is_some() && !self.config.lite {
            if let Some(c) = self.consent_next {
                at(c);
            }
            for c in &self.consent_txs {
                if c.sends < CONSENT_SENDS {
                    at(c.next);
                }
            }
            if !self.consent_lost {
                at(self.consent_last + self.config.consent_timeout);
            }
        }
        if self.config.lite && self.state != IceState::Disconnected {
            if let Some(l) = self.lite_last_check {
                at(l + self.config.consent_timeout);
            }
        }
        if self.selected.is_none() && self.state != IceState::Failed {
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

    /// The selected (nominated) pair: (local address, remote address).
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.selected.as_ref().map(|s| (s.local, s.remote))
    }

    /// Where application data goes (local address to send from, remote address): the selected
    /// pair, else the highest-priority valid pair (before nomination); for a lite agent, the
    /// pair the last valid check with USE-CANDIDATE arrived on, else the last valid check's.
    pub fn send_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        if let Some(s) = self.selected_pair() {
            return Some(s);
        }
        if self.config.lite {
            return self.lite_valid;
        }
        self.best_valid_any().map(|p| (p.local, p.remote))
    }

    fn best_valid_any(&self) -> Option<&Pair> {
        self.pairs
            .iter()
            .filter(|p| p.state == PairState::Succeeded)
            .max_by_key(|p| p.prio)
    }

    /// Stops the agent: no more timers or transmissions; received datagrams are no longer
    /// consumed. The state is left as it was.
    pub fn close(&mut self) {
        self.closed = true;
        self.transmits.clear();
        self.pairs.iter_mut().for_each(|p| p.tx = None);
        self.triggered.clear();
    }
}
