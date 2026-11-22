//! X.509 times: UTCTime and GeneralizedTime (RFC 5280 §4.1.2.5) as Unix seconds.

use akio_crypto::der::{Reader, Writer, tag};

use crate::Error;

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day)` of a day count since 1970-01-01.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn digits(b: &[u8]) -> Result<u32, Error> {
    let mut v = 0u32;
    for &c in b {
        if !c.is_ascii_digit() {
            return Err(Error::Encoding);
        }
        v = v * 10 + u32::from(c - b'0');
    }
    Ok(v)
}

/// Reads a `Time` (UTCTime or GeneralizedTime, `Z` form with seconds, as RFC 5280 requires).
pub(crate) fn read_time(r: &mut Reader<'_>) -> Result<i64, Error> {
    let (t, c, _) = r.read_tlv()?;
    let (year, rest) = match (t, c.len()) {
        (tag::UTC_TIME, 13) => {
            let yy = i64::from(digits(&c[..2])?);
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &c[2..])
        }
        (tag::GENERALIZED_TIME, 15) => (i64::from(digits(&c[..4])?), &c[4..]),
        _ => return Err(Error::Encoding),
    };
    if rest[10] != b'Z' {
        return Err(Error::Encoding);
    }
    let mo = digits(&rest[0..2])?;
    let d = digits(&rest[2..4])?;
    let h = digits(&rest[4..6])?;
    let mi = digits(&rest[6..8])?;
    let s = digits(&rest[8..10])?;
    let mdays = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return Err(Error::Encoding),
    };
    if d == 0 || d > mdays || h > 23 || mi > 59 || s > 59 {
        return Err(Error::Encoding);
    }
    Ok(days_from_civil(year, mo, d) * 86_400
        + i64::from(h) * 3600
        + i64::from(mi) * 60
        + i64::from(s))
}

/// Writes a `Time`: UTCTime for 1950–2049, GeneralizedTime otherwise (RFC 5280).
pub(crate) fn write_time(w: &mut Writer, t: i64) {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if (1950..2050).contains(&y) {
        let v = format!("{:02}{m:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100);
        w.tlv(tag::UTC_TIME, v.as_bytes());
    } else {
        let v = format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z");
        w.tlv(tag::GENERALIZED_TIME, v.as_bytes());
    }
}

/// Reads a GeneralizedTime (`YYYYMMDDHHMMSSZ`, as RFC 5280 and RFC 6960 require).
pub(crate) fn read_generalized_time(r: &mut Reader<'_>) -> Result<i64, Error> {
    if r.peek_tag() != Some(tag::GENERALIZED_TIME) {
        return Err(Error::Encoding);
    }
    read_time(r)
}

/// Writes a GeneralizedTime.
pub(crate) fn write_generalized_time(w: &mut Writer, t: i64) {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    let v = format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z");
    w.tlv(tag::GENERALIZED_TIME, v.as_bytes());
}

/// The current time as Unix seconds.
pub(crate) fn now() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: u8, s: &str) -> Result<i64, Error> {
        let mut w = Writer::new();
        w.tlv(t, s.as_bytes());
        let v = w.into_vec();
        read_time(&mut Reader::new(&v))
    }

    #[test]
    fn times() {
        assert_eq!(parse(tag::UTC_TIME, "700101000000Z").unwrap(), 0);
        assert_eq!(
            parse(tag::UTC_TIME, "491231235959Z").unwrap(),
            2_524_607_999
        );
        assert_eq!(
            parse(tag::GENERALIZED_TIME, "20500101000000Z").unwrap(),
            2_524_608_000
        );
        assert_eq!(
            parse(tag::GENERALIZED_TIME, "20240229120000Z").unwrap(),
            1_709_208_000
        );
        assert!(parse(tag::GENERALIZED_TIME, "20230229120000Z").is_err());
        assert!(parse(tag::UTC_TIME, "7001010000Z").is_err());
        assert!(parse(tag::UTC_TIME, "700101000000+0100").is_err());
        assert!(parse(tag::UTC_TIME, "701301000000Z").is_err());
        for t in [
            0i64,
            1_709_208_000,
            2_524_608_000,
            -86_400 * 365 * 30,
            253_402_300_799,
        ] {
            let mut w = Writer::new();
            write_time(&mut w, t);
            let v = w.into_vec();
            assert_eq!(read_time(&mut Reader::new(&v)).unwrap(), t);
        }
        for d in [-1_000_000i64, -1, 0, 59, 60, 365, 11_016, 2_932_896] {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
    }
}
