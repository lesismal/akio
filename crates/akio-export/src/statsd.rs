//! StatsD and DogStatsD lines from `Families`: counters as deltas since the previous push,
//! gauges as values, histograms as count / sum / per-bucket deltas.

use std::collections::HashMap;

use akio_core::metrics::{Families, Value};

/// The StatsD dialect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Flavor {
    /// Plain StatsD (Etsy): labels become name segments (`name.label.value`).
    Statsd,
    /// DogStatsD: labels become tags (`|#label:value`).
    #[default]
    DogStatsd,
}

/// Turns snapshots into lines, remembering counter values between pushes.
#[derive(Debug)]
pub(crate) struct Renderer {
    flavor: Flavor,
    prefix: String,
    /// Last cumulative value per series, for deltas. Bounded by `max_series`.
    last: HashMap<String, f64>,
    max_series: usize,
    /// Series that were not tracked because `last` was full.
    pub(crate) dropped: u64,
}

/// Copies `s`, replacing the characters StatsD gives a meaning (`:` unless `keep_colon`, `|`,
/// `@`, `#`, whitespace) and `extra_bad` with `_`.
fn clean(out: &mut String, s: &str, extra_bad: &[char], keep_colon: bool) {
    for c in s.chars() {
        let bad = (c == ':' && !keep_colon)
            || c == '|'
            || c == '@'
            || c == '#'
            || c.is_whitespace()
            || extra_bad.contains(&c);
        out.push(if bad { '_' } else { c });
    }
}

/// A number without exponent noise for integers.
fn num(out: &mut String, v: f64) {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        out.push_str(&format!("{}", v as i64));
    } else {
        out.push_str(&format!("{v}"));
    }
}

impl Renderer {
    pub(crate) fn new(flavor: Flavor, prefix: String, max_series: usize) -> Renderer {
        // The prefix is part of every name: the same characters are replaced.
        let mut clean_prefix = String::with_capacity(prefix.len());
        clean(&mut clean_prefix, &prefix, &[], false);
        Renderer {
            flavor,
            prefix: clean_prefix,
            last: HashMap::new(),
            max_series,
            dropped: 0,
        }
    }

    /// The series' name and tag part: (`prefix + name[.label.value...]`, `|#k:v,...` or "").
    fn series(
        &self,
        name: &str,
        suffix: &str,
        labels: &[(String, String)],
        extra: Option<(&str, &str)>,
    ) -> (String, String) {
        let mut n = String::with_capacity(self.prefix.len() + name.len() + suffix.len() + 16);
        n.push_str(&self.prefix);
        clean(&mut n, name, &[], false);
        n.push_str(suffix);
        let mut tags = String::new();
        let all = labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .chain(extra);
        match self.flavor {
            Flavor::Statsd => {
                for (k, v) in all {
                    n.push('.');
                    clean(&mut n, k, &['.'], false);
                    n.push('.');
                    clean(&mut n, v, &['.'], false);
                }
            }
            Flavor::DogStatsd => {
                for (i, (k, v)) in all.enumerate() {
                    tags.push_str(if i == 0 { "|#" } else { "," });
                    clean(&mut tags, k, &[','], false);
                    tags.push(':');
                    clean(&mut tags, v, &[','], true); // the first `:` splits a tag
                }
            }
        }
        (n, tags)
    }

    /// The delta of a cumulative value since the last push (the whole value the first time, or
    /// after a reset). `None` when the series cannot be tracked (table full) or did not move.
    fn delta(&mut self, key: String, v: f64) -> Option<f64> {
        let d = match self.last.get_mut(&key) {
            Some(prev) => {
                let d = if v >= *prev { v - *prev } else { v };
                *prev = v;
                d
            }
            None => {
                if self.last.len() >= self.max_series {
                    self.dropped += 1;
                    return None;
                }
                self.last.insert(key, v);
                v
            }
        };
        (d != 0.0).then_some(d)
    }

    fn counter(
        &mut self,
        out: &mut Vec<String>,
        name: &str,
        suffix: &str,
        labels: &[(String, String)],
        extra: Option<(&str, &str)>,
        v: f64,
    ) {
        let (n, tags) = self.series(name, suffix, labels, extra);
        let key = format!("{n}{tags}");
        if let Some(d) = self.delta(key, v) {
            let mut l = n;
            l.push(':');
            num(&mut l, d);
            l.push_str("|c");
            l.push_str(&tags);
            out.push(l);
        }
    }

    /// The lines for one snapshot.
    pub(crate) fn render(&mut self, f: &Families) -> Vec<String> {
        let mut out = Vec::new();
        for fam in f.iter() {
            for s in &fam.samples {
                match &s.value {
                    Value::Counter(v) => self.counter(&mut out, &fam.name, "", &s.labels, None, *v),
                    Value::Gauge(v) => {
                        let (n, tags) = self.series(&fam.name, "", &s.labels, None);
                        if *v < 0.0 && self.flavor == Flavor::Statsd {
                            // A leading sign means "change by" in plain StatsD: set 0 first.
                            out.push(format!("{n}:0|g{tags}"));
                        }
                        let mut l = n;
                        l.push(':');
                        num(&mut l, *v);
                        l.push_str("|g");
                        l.push_str(&tags);
                        out.push(l);
                    }
                    Value::Histogram(h) => {
                        self.counter(
                            &mut out,
                            &fam.name,
                            ".count",
                            &s.labels,
                            None,
                            h.count() as f64,
                        );
                        self.counter(&mut out, &fam.name, ".sum", &s.labels, None, h.sum);
                        let mut cum = 0u64;
                        for (i, c) in h.counts.iter().enumerate() {
                            cum += c;
                            let le = h
                                .bounds
                                .get(i)
                                .map_or_else(|| "+Inf".to_owned(), |b| format!("{b}"));
                            self.counter(
                                &mut out,
                                &fam.name,
                                ".bucket",
                                &s.labels,
                                Some(("le", &le)),
                                cum as f64,
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

/// Packs lines into datagrams of at most `max` bytes (a longer line goes alone).
pub(crate) fn packets(lines: &[String], max: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for l in lines {
        if !cur.is_empty() && cur.len() + 1 + l.len() > max {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(b'\n');
        }
        cur.extend_from_slice(l.as_bytes());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use akio_core::metrics::HistogramSnapshot;

    #[test]
    fn deltas_tags_and_names() {
        let mut r = Renderer::new(Flavor::DogStatsd, "app.".into(), 100);
        let mut f = Families::new();
        f.counter(
            "reqs_total",
            "",
            &[("route", "/a b:c"), ("class", "2xx")],
            5.0,
        );
        f.gauge("open", "", &[], 3.0);
        let h = HistogramSnapshot::new(vec![0.5], vec![1, 1], 2.0).unwrap();
        f.histogram("lat", "", &[], &h);
        let l = r.render(&f);
        assert_eq!(
            l,
            [
                "app.reqs_total:5|c|#route:/a_b:c,class:2xx",
                "app.open:3|g",
                "app.lat.count:2|c",
                "app.lat.sum:2|c",
                "app.lat.bucket:1|c|#le:0.5",
                "app.lat.bucket:2|c|#le:+Inf",
            ]
        );
        // Next push: only what moved.
        let mut f = Families::new();
        f.counter(
            "reqs_total",
            "",
            &[("route", "/a b:c"), ("class", "2xx")],
            7.0,
        );
        f.gauge("open", "", &[], 3.0);
        f.histogram("lat", "", &[], &h);
        assert_eq!(
            r.render(&f),
            ["app.reqs_total:2|c|#route:/a_b:c,class:2xx", "app.open:3|g"]
        );
        // A reset (restart) sends the whole value.
        let mut f = Families::new();
        f.counter(
            "reqs_total",
            "",
            &[("route", "/a b:c"), ("class", "2xx")],
            1.0,
        );
        assert_eq!(r.render(&f), ["app.reqs_total:1|c|#route:/a_b:c,class:2xx"]);
    }

    #[test]
    fn plain_statsd_and_limits() {
        let mut r = Renderer::new(Flavor::Statsd, String::new(), 1);
        let mut f = Families::new();
        f.counter("a_total", "", &[("k", "v.w")], 1.0);
        f.counter("b_total", "", &[], 1.0);
        f.gauge("g", "", &[], -2.5);
        assert_eq!(r.render(&f), ["a_total.k.v_w:1|c", "g:0|g", "g:-2.5|g"]);
        assert_eq!(r.dropped, 1, "the second counter series did not fit");
        let p = packets(
            &[
                "aaaa".into(),
                "bbbb".into(),
                "c".into(),
                "dddddddddd".into(),
            ],
            9,
        );
        assert_eq!(
            p,
            [
                b"aaaa\nbbbb".to_vec(),
                b"c".to_vec(),
                b"dddddddddd".to_vec()
            ]
        );
    }
}
