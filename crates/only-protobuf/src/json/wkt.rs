//! Text forms: base64, numbers, timestamps, durations, field masks.

use super::{JResult, err};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub(crate) fn base64_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Standard or URL-safe base64, padded or not.
pub(crate) fn base64_decode(s: &str) -> JResult<Vec<u8>> {
    let b = s.as_bytes();
    let body = b
        .strip_suffix(b"==")
        .or_else(|| b.strip_suffix(b"="))
        .unwrap_or(b);
    if b.len() != body.len() && b.len() % 4 != 0 {
        return err("invalid base64 padding");
    }
    if body.len() % 4 == 1 {
        return err("invalid base64 length");
    }
    let val = |c: u8| -> JResult<u32> {
        Ok(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return err("invalid base64 character"),
        }
        .into())
    };
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for c in body.chunks(4) {
        let mut n = 0u32;
        for (i, &x) in c.iter().enumerate() {
            n |= val(x)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if c.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if c.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Whether `s` is a JSON number (the grammar the tree reader enforces).
pub(crate) fn is_json_number(s: &str) -> bool {
    super::tree::parse(s).is_ok_and(|v| matches!(v, super::tree::Json::Num(_)))
}

/// The exact integer value of a JSON number (`1`, `-2`, `1e2`, `100.000`), when it is one.
pub(crate) fn integer(text: &str) -> Option<i128> {
    let (neg, t) = match text.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, text),
    };
    let (mant, exp) = match t.find(['e', 'E']) {
        Some(i) => (&t[..i], t[i + 1..].parse::<i64>().ok()?),
        None => (t, 0),
    };
    let (int, frac) = mant.split_once('.').unwrap_or((mant, ""));
    let mut digits: String = format!("{int}{frac}");
    let mut exp = exp - frac.len() as i64;
    // Drop trailing zeros into the exponent, leading zeros away.
    while exp < 0 && digits.ends_with('0') {
        digits.pop();
        exp += 1;
    }
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some(0);
    }
    if exp < 0 || digits.len() as i64 + exp > 30 {
        return None;
    }
    let mut v: i128 = digits.parse().ok()?;
    for _ in 0..exp {
        v = v.checked_mul(10)?;
    }
    Some(if neg { -v } else { v })
}

/// A double as JSON: the shortest decimal that reads back the same.
pub(crate) fn f64_text(v: f64) -> String {
    if v.is_nan() {
        "\"NaN\"".into()
    } else if v.is_infinite() {
        if v > 0.0 {
            "\"Infinity\""
        } else {
            "\"-Infinity\""
        }
        .into()
    } else {
        trim_float(format!("{v:?}"))
    }
}

/// A float as JSON.
pub(crate) fn f32_text(v: f32) -> String {
    if v.is_nan() {
        "\"NaN\"".into()
    } else if v.is_infinite() {
        if v > 0.0 {
            "\"Infinity\""
        } else {
            "\"-Infinity\""
        }
        .into()
    } else {
        trim_float(format!("{v:?}"))
    }
}

/// `1.0` -> `1`, `1e20` stays.
fn trim_float(s: String) -> String {
    match s.strip_suffix(".0") {
        Some(t) => t.to_owned(),
        None => s,
    }
}

// ---- time ------------------------------------------------------------------------------------

/// Seconds of 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z.
pub(crate) const MIN_TS: i64 = -62_135_596_800;
pub(crate) const MAX_TS: i64 = 253_402_300_799;
pub(crate) const MAX_DURATION: i64 = 315_576_000_000;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Nanoseconds as `.123`, `.123456` or `.123456789` (nothing for 0).
fn frac(n: i32) -> String {
    if n == 0 {
        String::new()
    } else if n % 1_000_000 == 0 {
        format!(".{:03}", n / 1_000_000)
    } else if n % 1000 == 0 {
        format!(".{:06}", n / 1000)
    } else {
        format!(".{n:09}")
    }
}

pub(crate) fn timestamp_text(seconds: i64, nanos: i32) -> JResult<String> {
    if !(MIN_TS..=MAX_TS).contains(&seconds) || !(0..1_000_000_000).contains(&nanos) {
        return err("Timestamp out of range");
    }
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}{}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        frac(nanos)
    ))
}

fn digits(b: &[u8], n: usize) -> Option<i64> {
    if b.len() < n || !b[..n].iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(&b[..n]).ok()?.parse().ok()
}

/// Parses `.123456789` fractional seconds (1 to 9 digits); returns nanos and bytes used.
fn parse_frac(b: &[u8]) -> JResult<(i32, usize)> {
    if b.first() != Some(&b'.') {
        return Ok((0, 0));
    }
    let n = b[1..].iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 || n > 9 {
        return err("bad fractional seconds");
    }
    let mut v: i32 = std::str::from_utf8(&b[1..=n])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    for _ in n..9 {
        v *= 10;
    }
    Ok((v, n + 1))
}

pub(crate) fn parse_timestamp(s: &str) -> JResult<(i64, i32)> {
    let b = s.as_bytes();
    let bad = || super::JsonError::new(format!("invalid Timestamp {s:?}"));
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(bad());
    }
    let y = digits(b, 4).ok_or_else(bad)?;
    let mo = digits(&b[5..], 2).ok_or_else(bad)?;
    let d = digits(&b[8..], 2).ok_or_else(bad)?;
    let h = digits(&b[11..], 2).ok_or_else(bad)?;
    let mi = digits(&b[14..], 2).ok_or_else(bad)?;
    let se = digits(&b[17..], 2).ok_or_else(bad)?;
    let mdays = [
        31,
        if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            29
        } else {
            28
        },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo)
        || d < 1
        || d > mdays[(mo - 1) as usize]
        || h > 23
        || mi > 59
        || se > 59
    {
        return Err(bad());
    }
    let (nanos, used) = parse_frac(&b[19..])?;
    let rest = &b[19 + used..];
    let offset = match rest {
        b"Z" => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let oh = digits(&[*h1, *h2], 2).ok_or_else(bad)?;
            let om = digits(&[*m1, *m2], 2).ok_or_else(bad)?;
            if oh > 23 || om > 59 {
                return Err(bad());
            }
            let o = oh * 3600 + om * 60;
            if *sign == b'+' { o } else { -o }
        }
        _ => return Err(bad()),
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset;
    if !(MIN_TS..=MAX_TS).contains(&secs) {
        return err("Timestamp out of range");
    }
    Ok((secs, nanos))
}

pub(crate) fn duration_text(seconds: i64, nanos: i32) -> JResult<String> {
    if !(-MAX_DURATION..=MAX_DURATION).contains(&seconds)
        || !(-999_999_999..=999_999_999).contains(&nanos)
        || (seconds > 0 && nanos < 0)
        || (seconds < 0 && nanos > 0)
    {
        return err("Duration out of range");
    }
    let neg = seconds < 0 || nanos < 0;
    Ok(format!(
        "{}{}{}s",
        if neg { "-" } else { "" },
        seconds.unsigned_abs(),
        frac(nanos.abs())
    ))
}

pub(crate) fn parse_duration(s: &str) -> JResult<(i64, i32)> {
    let bad = || super::JsonError::new(format!("invalid Duration {s:?}"));
    let t = s.strip_suffix('s').ok_or_else(bad)?;
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t),
    };
    let b = t.as_bytes();
    let n = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 || n > 12 {
        return Err(bad());
    }
    let secs: i64 = t[..n].parse().map_err(|_| bad())?;
    let (nanos, used) = parse_frac(&b[n..]).map_err(|_| bad())?;
    if n + used != b.len() {
        return Err(bad());
    }
    if secs > MAX_DURATION {
        return err("Duration out of range");
    }
    Ok(if neg { (-secs, -nanos) } else { (secs, nanos) })
}

/// `foo_bar.baz` -> `fooBar.baz`; fails when the path would not come back the same.
pub(crate) fn mask_path_to_json(p: &str) -> JResult<String> {
    let mut out = String::new();
    let mut up = false;
    for c in p.chars() {
        if c.is_ascii_uppercase() {
            return err(format!("FieldMask path {p:?} has an uppercase letter"));
        }
        if c == '_' {
            if up {
                return err(format!("FieldMask path {p:?} cannot be written in JSON"));
            }
            up = true;
            continue;
        }
        if up {
            if !c.is_ascii_lowercase() {
                return err(format!("FieldMask path {p:?} cannot be written in JSON"));
            }
            out.push(c.to_ascii_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    if up {
        return err(format!("FieldMask path {p:?} cannot be written in JSON"));
    }
    Ok(out)
}

/// `fooBar.baz` -> `foo_bar.baz`.
pub(crate) fn mask_path_from_json(p: &str) -> JResult<String> {
    let mut out = String::new();
    for c in p.chars() {
        if c == '_' {
            return err(format!("FieldMask path {p:?} has an underscore"));
        }
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        for b in [&b""[..], b"f", b"fo", b"foo", b"foob", &[0xff, 0xfe, 0x00]] {
            assert_eq!(base64_decode(&base64_encode(b)).unwrap(), b);
        }
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode("_-8").unwrap(), [0xff, 0xef]);
        assert!(base64_decode("Zm8=x").is_err());
        assert_eq!(integer("1e2"), Some(100));
        assert_eq!(integer("100.000"), Some(100));
        assert_eq!(integer("-0"), Some(0));
        assert_eq!(integer("0.5"), None);
        assert_eq!(integer("1.5e1"), Some(15));
        assert_eq!(integer("9223372036854775807"), Some(i64::MAX.into()));
        assert_eq!(timestamp_text(0, 0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp_text(MIN_TS, 0).unwrap(), "0001-01-01T00:00:00Z");
        assert_eq!(
            timestamp_text(MAX_TS, 999_999_999).unwrap(),
            "9999-12-31T23:59:59.999999999Z"
        );
        assert_eq!(
            parse_timestamp("0001-01-01T00:00:00Z").unwrap(),
            (MIN_TS, 0)
        );
        assert_eq!(
            parse_timestamp("1970-01-01T01:00:00.010+01:00").unwrap(),
            (0, 10_000_000)
        );
        assert!(parse_timestamp("1970-01-01t00:00:00Z").is_err());
        assert_eq!(duration_text(-1, -500_000).unwrap(), "-1.000500s");
        assert_eq!(duration_text(0, -1).unwrap(), "-0.000000001s");
        assert_eq!(parse_duration("-0.5s").unwrap(), (0, -500_000_000));
        assert_eq!(mask_path_to_json("foo_bar.baz_q").unwrap(), "fooBar.bazQ");
        assert!(mask_path_to_json("foo__bar").is_err());
        assert_eq!(mask_path_from_json("fooBar").unwrap(), "foo_bar");
        assert_eq!(f64_text(1.0), "1");
        assert_eq!(f64_text(0.1), "0.1");
        assert_eq!(f32_text(0.1), "0.1");
    }
}
