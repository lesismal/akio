//! Matches, groups, `expand` and `replace_all` (ADR-115). The table's expectations were printed
//! by Go's `regexp` (`FindStringSubmatchIndex`, `FindAllStringIndex`, `ReplaceAllString`): fit,
//! which akit follows, runs Go's engine, and akio-regex matches the way it does, leftmost-first.

use std::{borrow::Cow, time::Instant};

use akio_regex::{Regex, RegexBuilder};

/// Pattern, text, template; then Go's submatch indexes (-1 for a group that took no part), the
/// bounds of every match `FindAll` finds, and `ReplaceAllString`'s result.
#[allow(clippy::type_complexity)]
const GO: &[(&str, &str, &str, Option<&[i64]>, &[i64], &str)] = &[
    (r"a+", "baaac", "<$0>", Some(&[1, 4]), &[1, 4], "b<aaa>c"),
    (
        r"(a)(b)?",
        "xa",
        "[$1|$2]",
        Some(&[1, 2, 1, 2, -1, -1]),
        &[1, 2],
        "x[a|]",
    ),
    (
        r"^/old/(?P<id>[0-9]+)(/.*)?$",
        "/old/42/edit",
        "/new/${id}$2",
        Some(&[0, 12, 5, 7, 7, 12]),
        &[0, 12],
        "/new/42/edit",
    ),
    (
        r"^/old/(?P<id>[0-9]+)(/.*)?$",
        "/old/42",
        "/new/$id$2",
        Some(&[0, 7, 5, 7, -1, -1]),
        &[0, 7],
        "/new/42",
    ),
    (
        r"/api/v1/(.*)",
        "/api/v1/users/7",
        "/v1/api/$1",
        Some(&[0, 15, 8, 15]),
        &[0, 15],
        "/v1/api/users/7",
    ),
    (
        r"^/users/([^/]+)/posts/([^/]+)$",
        "/users/ann/posts/9",
        "/p/$2?u=$1",
        Some(&[0, 18, 7, 10, 17, 18]),
        &[0, 18],
        "/p/9?u=ann",
    ),
    (
        r"(a*)*",
        "b",
        "<$1>",
        Some(&[0, 0, 0, 0]),
        &[0, 0, 1, 1],
        "<>b<>",
    ),
    (
        r"(a*)+",
        "b",
        "<$1>",
        Some(&[0, 0, 0, 0]),
        &[0, 0, 1, 1],
        "<>b<>",
    ),
    (
        r"(a|ab)(c|bcd)(d*)",
        "abcd",
        "$1-$2-$3",
        Some(&[0, 4, 0, 1, 1, 4, 4, 4]),
        &[0, 4],
        "a-bcd-",
    ),
    (
        r"(a+)(b+)?",
        "aaab",
        "$2$1",
        Some(&[0, 4, 0, 3, 3, 4]),
        &[0, 4],
        "baaa",
    ),
    (
        r"(a+?)(a*)",
        "aaa",
        "$1|$2",
        Some(&[0, 3, 0, 1, 1, 3]),
        &[0, 3],
        "a|aa",
    ),
    (
        r"(?U)(a+)(a*)",
        "aaa",
        "$1|$2",
        Some(&[0, 1, 0, 1, 1, 1]),
        &[0, 1, 1, 2, 2, 3],
        "a|a|a|",
    ),
    (
        r"(?U)(a+?)(a*)",
        "aaa",
        "$1|$2",
        Some(&[0, 3, 0, 3, 3, 3]),
        &[0, 3],
        "aaa|",
    ),
    (
        r"x*",
        "abc",
        "-",
        Some(&[0, 0]),
        &[0, 0, 1, 1, 2, 2, 3, 3],
        "-a-b-c-",
    ),
    (
        r"a*",
        "baaac",
        "-",
        Some(&[0, 0]),
        &[0, 0, 1, 4, 5, 5],
        "-b-c-",
    ),
    (
        r"a|",
        "abc",
        "<$0>",
        Some(&[0, 1]),
        &[0, 1, 2, 2, 3, 3],
        "<a>b<>c<>",
    ),
    (
        r"\b",
        "ab cd",
        "|",
        Some(&[0, 0]),
        &[0, 0, 2, 2, 3, 3, 5, 5],
        "|ab| |cd|",
    ),
    (
        r"(?i)(é+)",
        "aÉéb",
        "[$1]",
        Some(&[1, 5, 1, 5]),
        &[1, 5],
        "a[Éé]b",
    ),
    (
        r".",
        "日本",
        "<$0>",
        Some(&[0, 3]),
        &[0, 3, 3, 6],
        "<日><本>",
    ),
    (r"(x)?y", "y", "[$1]", Some(&[0, 1, -1, -1]), &[0, 1], "[]"),
    (
        r"(?:(a)|b)+",
        "ab",
        "[$1]",
        Some(&[0, 2, 0, 1]),
        &[0, 2],
        "[a]",
    ),
    (
        r"(a)|(b)",
        "b",
        "[$1][$2]",
        Some(&[0, 1, -1, -1, 0, 1]),
        &[0, 1],
        "[][b]",
    ),
    (
        r"(\.)",
        "a.b",
        "$1x${1}x",
        Some(&[1, 2, 1, 2]),
        &[1, 2],
        "a.xb",
    ),
    (
        r"(?P<n>a)",
        "a",
        "$n$nx${n}x$$n$",
        Some(&[0, 1, 0, 1]),
        &[0, 1],
        "aax$n$",
    ),
    (
        r"(a)",
        "a",
        "$01 $1 ${1} ${01} $ $} ${ ${1 $-",
        Some(&[0, 1, 0, 1]),
        &[0, 1],
        " a a  $ $} ${ ${1 $-",
    ),
    (
        r"(((a)))",
        "a",
        "$3$2$1$4",
        Some(&[0, 1, 0, 1, 0, 1, 0, 1]),
        &[0, 1],
        "aaa",
    ),
    (
        r"a{2,3}",
        "aaaaaaa",
        "<$0>",
        Some(&[0, 3]),
        &[0, 3, 3, 6],
        "<aaa><aaa>a",
    ),
    (
        r"(a{2,3}?)",
        "aaaaaaa",
        "<$1>",
        Some(&[0, 2, 0, 2]),
        &[0, 2, 2, 4, 4, 6],
        "<aa><aa><aa>a",
    ),
    (r"^", "abc", "^", Some(&[0, 0]), &[0, 0], "^abc"),
    (r"$", "abc", "$$", Some(&[3, 3]), &[3, 3], "abc$"),
    (
        r"(?m)^",
        "a\nb",
        ">",
        Some(&[0, 0]),
        &[0, 0, 2, 2],
        ">a\n>b",
    ),
    (
        r"/+",
        "//a///b/",
        "/",
        Some(&[0, 2]),
        &[0, 2, 3, 6, 7, 8],
        "/a/b/",
    ),
];

/// `caps` as Go writes submatch indexes.
fn go_indexes(re: &Regex, text: &str) -> Option<Vec<i64>> {
    let caps = re.captures(text)?;
    assert_eq!(caps.len(), re.captures_len());
    let mut v = Vec::new();
    for i in 0..caps.len() {
        match caps.get(i) {
            Some(r) => v.extend([r.start as i64, r.end as i64]),
            None => v.extend([-1, -1]),
        }
    }
    Some(v)
}

#[test]
fn as_go_finds_and_replaces() {
    for &(p, text, template, groups, all, replaced) in GO {
        let re = Regex::new(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        assert_eq!(
            go_indexes(&re, text).as_deref(),
            groups,
            "captures {p:?} / {text:?}"
        );
        let found: Vec<i64> = re
            .find_iter(text)
            .flat_map(|r| [r.start as i64, r.end as i64])
            .collect();
        assert_eq!(found, all, "find_iter {p:?} / {text:?}");
        assert_eq!(
            re.find(text),
            re.captures(text).map(|c| c.range()),
            "find {p:?} / {text:?}"
        );
        assert_eq!(
            re.replace_all(text, template),
            replaced,
            "replace_all {p:?} / {text:?} / {template:?}"
        );
    }
}

#[test]
fn expand_follows_go() {
    let re = Regex::new(r"(?P<first>\w+) (?P<last>\w+)(x)?").unwrap();
    let text = "Ada Lovelace";
    let caps = re.captures(text).unwrap();
    let ex = |t: &str| {
        let mut out = String::from(">");
        re.expand(&caps, t, text, &mut out);
        out
    };
    assert_eq!(ex("$last, $first"), ">Lovelace, Ada");
    assert_eq!(ex("${last}_x"), ">Lovelace_x");
    // `$last_x` names the group `last_x`, which does not exist.
    assert_eq!(ex("$last_x"), ">");
    assert_eq!(ex("$1$2$3$9"), ">AdaLovelace");
    assert_eq!(ex("$$1 $ $. ${x ${}"), ">$1 $ $. ${x ${}");
    assert_eq!(ex("$0"), ">Ada Lovelace");
    assert_eq!(ex("$00 $01 $1é"), ">  ");
    assert_eq!(ex("${1}é"), ">Adaé");
    assert_eq!(ex("$999999999999"), ">");
    assert_eq!(ex(""), ">");
    assert_eq!(ex("no dollars"), ">no dollars");
}

#[test]
fn groups_and_names() {
    let re = Regex::new(r"(?P<y>\d{4})-(\d{2})(?:-(?<d>\d{2}))?").unwrap();
    assert_eq!(re.captures_len(), 4);
    assert_eq!(
        re.group_names().collect::<Vec<_>>(),
        [None, Some("y"), None, Some("d")]
    );
    let text = "on 2026-11 and";
    let caps = re.captures(text).unwrap();
    assert_eq!(caps.range(), 3..10);
    assert_eq!(caps.name("y"), Some(3..7));
    assert_eq!(caps.get(2), Some(8..10));
    assert_eq!(caps.name("d"), None);
    assert_eq!(caps.name("nope"), None);
    assert_eq!(caps.get(4), None);
    assert_eq!(caps.get(usize::MAX), None);
    assert_eq!(
        format!("{caps:?}"),
        "[Some(3..10), Some(3..7), Some(8..10), None]"
    );
    assert_eq!(caps.clone(), caps);
    // A pattern without groups has group 0 only.
    let plain = Regex::new("b+").unwrap();
    assert_eq!(plain.captures_len(), 1);
    assert_eq!(plain.captures("abbc").map(|c| c.range()), Some(1..3));
    assert!(plain.captures("ac").is_none());
}

#[test]
fn find_at_sees_the_text_before_start() {
    let re = Regex::new(r"\bfoo").unwrap();
    assert_eq!(re.find_at("xfoo foo", 0), Some(5..8));
    // `\b` looks at the character before `start`: no boundary between `x` and `f`.
    assert_eq!(re.find_at("xfoo", 1), None);
    assert_eq!(Regex::new("^a").unwrap().find_at("aa", 1), None);
    assert_eq!(Regex::new("a$").unwrap().find_at("aa", 1), Some(1..2));
    assert_eq!(Regex::new("a").unwrap().find_at("aa", 2), None);
    // Past the end or inside a character: no match, no panic.
    assert_eq!(Regex::new("").unwrap().find_at("a", 1), Some(1..1));
    assert_eq!(Regex::new("").unwrap().find_at("a", 2), None);
    assert_eq!(Regex::new(".").unwrap().find_at("é", 1), None);
    assert!(Regex::new("(.)").unwrap().captures_at("é", 1).is_none());
    // Literal patterns take the `str::find` path, whole-text ones compare.
    let lit = Regex::new("ab").unwrap();
    assert_eq!(lit.find_at("abab", 1), Some(2..4));
    assert_eq!(
        lit.find_iter("ababxab").collect::<Vec<_>>(),
        [0..2, 2..4, 5..7]
    );
    let whole = RegexBuilder::new("ab").whole_text(true).build().unwrap();
    assert_eq!(whole.find("ab"), Some(0..2));
    assert_eq!(whole.find("abc"), None);
    assert_eq!(whole.find_at("ab", 1), None);
    let whole = RegexBuilder::new("(a)(b)?")
        .whole_text(true)
        .build()
        .unwrap();
    assert_eq!(whole.captures("a").and_then(|c| c.get(1)), Some(0..1));
    assert!(whole.captures("ab ").is_none());
}

#[test]
fn replace_all_borrows_when_nothing_matches() {
    let re = Regex::new("[0-9]+").unwrap();
    assert!(matches!(re.replace_all("abc", "#"), Cow::Borrowed("abc")));
    assert_eq!(re.replace_all("a1b22", "#"), "a#b#");
    assert!(matches!(re.replace_all("", "#"), Cow::Borrowed("")));
}

#[test]
fn groups_are_limited() {
    assert!(Regex::new(&"()".repeat(1000)).is_ok());
    assert_eq!(
        Regex::new(&"()".repeat(1001)).unwrap_err().message(),
        "too many groups"
    );
    // Groups repeated: the capturing program, with two instructions per group copy, is bounded
    // as the matching one is.
    assert_eq!(
        Regex::new("(?:(){100}){100}").unwrap_err().message(),
        "pattern too large"
    );
}

#[test]
#[cfg_attr(miri, ignore = "long inputs: minutes under Miri")]
fn captures_are_linear() {
    let long = "a".repeat(20_000);
    let t = Instant::now();
    for p in ["(a*)*b", "(a|aa)*(a|aa)*$c", "((a+)+)+x", "(?:(a)|(aa))*$z"] {
        let re = Regex::new(p).unwrap();
        assert!(re.captures(&long).is_none(), "{p}");
        // From a later start the DFA does not reject first: the Pike VM runs to the end.
        assert!(re.captures_at(&long, 1).is_none(), "{p}");
    }
    let re = Regex::new("(a+)(a+)").unwrap();
    let caps = re.captures(&long).unwrap();
    assert_eq!(
        (caps.get(1), caps.get(2)),
        (Some(0..19_999), Some(19_999..20_000))
    );
    assert!(
        t.elapsed().as_secs() < 20,
        "took {:?}: not linear",
        t.elapsed()
    );
}

#[test]
fn many_searches_on_one_thread_and_on_others() {
    // The working memory is kept per thread: searches of different programs in a row, and on
    // several threads at once, do not see each other's.
    let a = Regex::new("(x+)(y+)").unwrap();
    let b = Regex::new("(?P<w>[a-z]+)@").unwrap();
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for i in 0..200 {
                    let text = format!("{}xxyyy {}abc@", " ".repeat(i % 7), i);
                    let ca = a.captures(&text).unwrap();
                    assert_eq!(&text[ca.get(2).unwrap()], "yyy");
                    let cb = b.captures(&text).unwrap();
                    assert_eq!(&text[cb.name("w").unwrap()], "abc");
                }
            });
        }
    });
}
