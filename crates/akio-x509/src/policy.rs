//! Certificate policy processing (RFC 5280 §6.1.2–6.1.6), on the policy graph of RFC 9618
//! instead of the policy tree: each depth holds at most one node per policy OID (a node may
//! have several parents), which keeps the work polynomial in the number of policies and
//! mappings (the tree can grow exponentially with crafted mappings, CVE-2023-0464).

use crate::Error;
use crate::cert::{Certificate, ext};

/// Policy inputs of path validation (RFC 5280 §6.1.1 (c), (e), (f), (g)).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PolicyOptions {
    /// `user-initial-policy-set`: the policies (OID content bytes) acceptable to the
    /// application. Empty means any-policy (the default).
    pub initial_policy_set: Vec<Vec<u8>>,
    /// `initial-explicit-policy`: the path must be valid for at least one policy of
    /// `initial_policy_set`.
    pub explicit_policy: bool,
    /// `initial-policy-mapping-inhibit`: policy mapping is not allowed.
    pub inhibit_policy_mapping: bool,
    /// `initial-any-policy-inhibit`: anyPolicy in a certificate does not match other
    /// policies.
    pub inhibit_any_policy: bool,
}

impl PolicyOptions {
    /// The defaults: any policy, nothing required or inhibited.
    #[must_use]
    pub fn new() -> PolicyOptions {
        PolicyOptions::default()
    }

    /// Requires an explicit policy from `policies` (`initial-explicit-policy` set).
    #[must_use]
    pub fn require(policies: impl IntoIterator<Item = Vec<u8>>) -> PolicyOptions {
        PolicyOptions {
            initial_policy_set: policies.into_iter().collect(),
            explicit_policy: true,
            ..PolicyOptions::default()
        }
    }
}

/// The policies a validated path is good for: the `user-constrained-policy-set` of RFC 5280
/// §6.1.6.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidPolicies {
    /// Any policy (every certificate asserted anyPolicy, and the application accepts any).
    Any,
    /// These policies (OID content bytes, sorted); empty when the path is valid for no
    /// policy (allowed when no explicit policy is required).
    Set(Vec<Vec<u8>>),
}

impl ValidPolicies {
    /// Whether the path is valid for `policy`.
    #[must_use]
    pub fn contains(&self, policy: &[u8]) -> bool {
        match self {
            ValidPolicies::Any => true,
            ValidPolicies::Set(s) => s.iter().any(|p| p == policy),
        }
    }

    /// Whether the path is valid for no policy.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, ValidPolicies::Set(s) if s.is_empty())
    }
}

struct Node {
    policy: Vec<u8>,
    expected: Vec<Vec<u8>>,
    /// Indices into the previous level.
    parents: Vec<usize>,
}

fn is_any(p: &[u8]) -> bool {
    p == ext::ANY_POLICY
}

/// The graph: `levels[0]` is the root (anyPolicy); `None` once it is NULL.
struct Graph {
    levels: Vec<Vec<Node>>,
}

impl Graph {
    fn new() -> Graph {
        Graph {
            levels: vec![vec![Node {
                policy: ext::ANY_POLICY.to_vec(),
                expected: vec![ext::ANY_POLICY.to_vec()],
                parents: Vec::new(),
            }]],
        }
    }

    fn find(level: &[Node], policy: &[u8]) -> Option<usize> {
        level.iter().position(|n| n.policy == policy)
    }

    /// Deletes nodes above the last level that have no children, repeatedly. Returns
    /// whether the graph is still non-NULL (the root survives).
    fn prune(&mut self) -> bool {
        for d in (0..self.levels.len().saturating_sub(1)).rev() {
            let mut has_child = vec![false; self.levels[d].len()];
            for n in &self.levels[d + 1] {
                for &p in &n.parents {
                    has_child[p] = true;
                }
            }
            if has_child.iter().all(|&h| h) {
                continue;
            }
            // Remap indices of the surviving nodes.
            let mut map = vec![usize::MAX; has_child.len()];
            let mut kept = Vec::new();
            for (i, n) in std::mem::take(&mut self.levels[d]).into_iter().enumerate() {
                if has_child[i] {
                    map[i] = kept.len();
                    kept.push(n);
                }
            }
            self.levels[d] = kept;
            for n in &mut self.levels[d + 1] {
                for p in &mut n.parents {
                    *p = map[*p];
                }
            }
        }
        !self.levels[0].is_empty()
    }

    /// Removes the node at `(depth, idx)` and fixes the parent indices of the next level.
    fn remove(&mut self, depth: usize, idx: usize) {
        self.levels[depth].remove(idx);
        if let Some(next) = self.levels.get_mut(depth + 1) {
            for n in next.iter_mut() {
                n.parents.retain(|&p| p != idx);
                for p in &mut n.parents {
                    if *p > idx {
                        *p -= 1;
                    }
                }
            }
        }
    }
}

/// Runs policy processing over `path` (the certificates below the trust anchor, the one the
/// anchor issued first, the end entity last). Returns the user-constrained policy set, or
/// [`Error::PolicyViolation`].
pub(crate) fn process(path: &[&Certificate], opts: &PolicyOptions) -> Result<ValidPolicies, Error> {
    let n = path.len();
    let start = u64::try_from(n).unwrap_or(u64::MAX).saturating_add(1);
    let init = |inhibit: bool| if inhibit { 0 } else { start };
    let mut explicit = init(opts.explicit_policy);
    let mut mapping = init(opts.inhibit_policy_mapping);
    let mut inhibit_any = init(opts.inhibit_any_policy);
    let mut graph = Some(Graph::new());

    for (k, cert) in path.iter().enumerate() {
        let i = k + 1;
        let last = i == n;
        let self_issued = cert.is_self_issued() && !last;
        // (d) certificatePolicies, (e) absent: NULL.
        if let Some(g) = graph.as_mut() {
            match cert.certificate_policies() {
                Some(policies) => {
                    let prev = &g.levels[i - 1];
                    let any_prev = Graph::find(prev, ext::ANY_POLICY);
                    let mut level: Vec<Node> = Vec::new();
                    for p in policies.iter().filter(|p| !is_any(p)) {
                        // (d)(1)(i): every node expecting p; (ii) else the anyPolicy node.
                        let mut parents: Vec<usize> = prev
                            .iter()
                            .enumerate()
                            .filter(|(_, nd)| nd.expected.iter().any(|e| e == p))
                            .map(|(j, _)| j)
                            .collect();
                        if parents.is_empty() {
                            parents.extend(any_prev);
                        }
                        if !parents.is_empty() {
                            level.push(Node {
                                policy: p.clone(),
                                expected: vec![p.clone()],
                                parents,
                            });
                        }
                    }
                    // (d)(2): anyPolicy, if not inhibited (self-issued intermediates always).
                    if policies.iter().any(|p| is_any(p)) && (inhibit_any > 0 || self_issued) {
                        let mut values: Vec<&Vec<u8>> = Vec::new();
                        for nd in prev {
                            for e in &nd.expected {
                                if !values.contains(&e) {
                                    values.push(e);
                                }
                            }
                        }
                        for v in values {
                            if Graph::find(&level, v).is_some() {
                                continue;
                            }
                            let parents: Vec<usize> = prev
                                .iter()
                                .enumerate()
                                .filter(|(_, nd)| nd.expected.contains(v))
                                .map(|(j, _)| j)
                                .collect();
                            level.push(Node {
                                policy: v.clone(),
                                expected: vec![v.clone()],
                                parents,
                            });
                        }
                    }
                    g.levels.push(level);
                    // (d)(3)
                    if !g.prune() || g.levels[i].is_empty() {
                        graph = None;
                    }
                }
                None => graph = None,
            }
        }
        // (f)
        if explicit == 0 && graph.is_none() {
            return Err(Error::PolicyViolation);
        }
        if last {
            break;
        }
        // Preparation for certificate i+1 (RFC 5280 §6.1.4 (a), (b), (h)–(j)).
        let maps = cert.policy_mappings();
        if maps.iter().any(|(a, b)| is_any(a) || is_any(b)) {
            return Err(Error::PolicyViolation);
        }
        if let Some(g) = graph.as_mut() {
            let mut issuers: Vec<&Vec<u8>> = Vec::new();
            for (a, _) in maps {
                if !issuers.contains(&a) {
                    issuers.push(a);
                }
            }
            for idp in issuers {
                let subjects: Vec<Vec<u8>> = maps
                    .iter()
                    .filter(|(a, _)| a == idp)
                    .map(|(_, b)| b.clone())
                    .collect();
                if mapping > 0 {
                    if let Some(j) = Graph::find(&g.levels[i], idp) {
                        g.levels[i][j].expected = subjects;
                    } else if let Some(a) = Graph::find(&g.levels[i], ext::ANY_POLICY) {
                        // A node for idp under the anyPolicy node's parents.
                        let parents = g.levels[i][a].parents.clone();
                        g.levels[i].push(Node {
                            policy: idp.clone(),
                            expected: subjects,
                            parents,
                        });
                    }
                } else if let Some(j) = Graph::find(&g.levels[i], idp) {
                    g.remove(i, j);
                    if !g.prune() || g.levels[i].is_empty() {
                        graph = None;
                        break;
                    }
                }
            }
        }
        // (h)
        if !cert.is_self_issued() {
            explicit = explicit.saturating_sub(1);
            mapping = mapping.saturating_sub(1);
            inhibit_any = inhibit_any.saturating_sub(1);
        }
        // (i), (j)
        if let Some(pc) = cert.policy_constraints() {
            if let Some(r) = pc.require_explicit_policy {
                explicit = explicit.min(u64::from(r));
            }
            if let Some(m) = pc.inhibit_policy_mapping {
                mapping = mapping.min(u64::from(m));
            }
        }
        if let Some(a) = cert.inhibit_any_policy() {
            inhibit_any = inhibit_any.min(u64::from(a));
        }
    }

    // Wrap-up (§6.1.5 (a), (b)).
    explicit = explicit.saturating_sub(1);
    if path
        .last()
        .and_then(|c| c.policy_constraints())
        .and_then(|pc| pc.require_explicit_policy)
        == Some(0)
    {
        explicit = 0;
    }
    let result = match graph {
        None => ValidPolicies::Set(Vec::new()),
        Some(g) => intersect(&g, n, &opts.initial_policy_set),
    };
    // (g): the path fails without a valid policy when one is required (an application that
    // needs one of its policies without requiring explicit policies checks the result).
    if result.is_empty() && explicit == 0 {
        return Err(Error::PolicyViolation);
    }
    Ok(result)
}

/// §6.1.5 (g): the intersection of the graph's leaves with the user-initial-policy-set.
fn intersect(g: &Graph, n: usize, user: &[Vec<u8>]) -> ValidPolicies {
    let leaves = &g.levels[n];
    if user.is_empty() || user.iter().any(|p| is_any(p)) {
        if Graph::find(leaves, ext::ANY_POLICY).is_some() {
            return ValidPolicies::Any;
        }
        let mut v: Vec<Vec<u8>> = leaves.iter().map(|l| l.policy.clone()).collect();
        v.sort();
        return ValidPolicies::Set(v);
    }
    // good[d][j]: some path from the root reaches node j of depth d on which the first
    // non-anyPolicy node is in the user set. Nodes with an anyPolicy parent form the
    // valid_policy_node_set.
    let mut good: Vec<Vec<bool>> = vec![vec![false; g.levels[0].len()]];
    let mut node_set: Vec<&Vec<u8>> = Vec::new();
    for d in 1..=n {
        let prev = &g.levels[d - 1];
        let mut cur = Vec::with_capacity(g.levels[d].len());
        for nd in &g.levels[d] {
            let mut ok = false;
            for &p in &nd.parents {
                if is_any(&prev[p].policy) {
                    if !is_any(&nd.policy) {
                        ok |= user.contains(&nd.policy);
                        if !node_set.contains(&&nd.policy) {
                            node_set.push(&nd.policy);
                        }
                    }
                } else {
                    ok |= good[d - 1][p];
                }
            }
            cur.push(ok);
        }
        good.push(cur);
    }
    let mut out: Vec<Vec<u8>> = leaves
        .iter()
        .zip(&good[n])
        .filter(|(l, ok)| **ok && !is_any(&l.policy))
        .map(|(l, _)| l.policy.clone())
        .collect();
    if Graph::find(leaves, ext::ANY_POLICY).is_some() {
        for p in user {
            if !node_set.contains(&p) && !out.contains(p) {
                out.push(p.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    ValidPolicies::Set(out)
}
