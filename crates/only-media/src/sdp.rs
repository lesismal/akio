//! SDP (RFC 8866): a lenient parser and a writer, with the mapping between media descriptions
//! and [`Track`]s that RTSP uses (`rtpmap`, `fmtp` with `sprop-parameter-sets`,
//! `sprop-vps/sps/pps`, `profile-level-id`, AAC `config`, `a=control`). WHIP/WHEP use the same
//! [`Session`] type for offers and answers.

use std::fmt::{self, Write as _};

use only_crypto::base64::STANDARD as B64;

use crate::{
    av::{Codec, Track},
    codec::{aac, h264, h265, opus},
};

/// A malformed session description.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdpError {
    /// A line is not `x=value`.
    Line(usize),
    /// An `m=` line is malformed.
    Media(usize),
    /// Too large.
    TooLarge,
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdpError::Line(n) => write!(f, "SDP line {n} malformed"),
            SdpError::Media(n) => write!(f, "SDP media line {n} malformed"),
            SdpError::TooLarge => f.write_str("SDP too large"),
        }
    }
}

impl std::error::Error for SdpError {}

/// The most media descriptions (and the largest description) parsed.
const MAX_MEDIA: usize = 64;
const MAX_BYTES: usize = 64 << 10;

/// An attribute line `a=name[:value]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attribute {
    /// The name.
    pub name: String,
    /// The value after `:`, if any.
    pub value: Option<String>,
}

impl Attribute {
    /// `a=name:value`.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Attribute {
        Attribute {
            name: name.into(),
            value: Some(value.into()),
        }
    }

    /// `a=name` (a flag).
    pub fn flag(name: impl Into<String>) -> Attribute {
        Attribute {
            name: name.into(),
            value: None,
        }
    }
}

fn find<'a>(attrs: &'a [Attribute], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(name))
        .map(|a| a.value.as_deref().unwrap_or(""))
}

/// One media description (`m=` and the lines after it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Media {
    /// `video`, `audio`, `application`...
    pub kind: String,
    /// The port.
    pub port: u16,
    /// The protocol (`RTP/AVP`, `UDP/TLS/RTP/SAVPF`...).
    pub proto: String,
    /// The formats (payload types).
    pub formats: Vec<String>,
    /// `c=` of this media, if any.
    pub connection: Option<String>,
    /// `b=` lines.
    pub bandwidth: Vec<String>,
    /// The attributes.
    pub attributes: Vec<Attribute>,
}

impl Media {
    /// A media description of `kind` on `port` over `proto` with `formats`.
    pub fn new(kind: &str, port: u16, proto: &str, formats: Vec<String>) -> Media {
        Media {
            kind: kind.to_owned(),
            port,
            proto: proto.to_owned(),
            formats,
            ..Media::default()
        }
    }

    /// The value of the first attribute `name` (`""` for a flag).
    pub fn attr(&self, name: &str) -> Option<&str> {
        find(&self.attributes, name)
    }

    /// Every value of attribute `name`.
    pub fn attrs<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.attributes
            .iter()
            .filter(move |a| a.name.eq_ignore_ascii_case(name))
            .map(|a| a.value.as_deref().unwrap_or(""))
    }

    /// The `rtpmap` of payload type `pt`: encoding name, clock rate and parameters (channels).
    pub fn rtpmap(&self, pt: &str) -> Option<(String, u32, Option<String>)> {
        self.attrs("rtpmap").find_map(|v| {
            let (p, rest) = v.split_once(' ')?;
            if p != pt {
                return None;
            }
            let mut it = rest.trim().split('/');
            let enc = it.next()?.to_owned();
            let rate = it.next().and_then(|r| r.parse().ok()).unwrap_or(0);
            Some((enc, rate, it.next().map(str::to_owned)))
        })
    }

    /// The `fmtp` parameters of payload type `pt`, as `(name, value)` pairs.
    pub fn fmtp(&self, pt: &str) -> Vec<(String, String)> {
        self.attrs("fmtp")
            .find_map(|v| {
                let (p, rest) = v.split_once(' ')?;
                (p == pt).then(|| {
                    rest.split(';')
                        .filter_map(|kv| {
                            let kv = kv.trim();
                            if kv.is_empty() {
                                return None;
                            }
                            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                            Some((k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                        })
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    /// The `a=control` URL or relative path.
    pub fn control(&self) -> Option<&str> {
        self.attr("control")
    }
}

/// A session description.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Session {
    /// `o=` (without `o=`).
    pub origin: String,
    /// `s=`.
    pub name: String,
    /// Session-level `c=`.
    pub connection: Option<String>,
    /// `t=` (default `0 0`).
    pub timing: String,
    /// Session-level attributes.
    pub attributes: Vec<Attribute>,
    /// The media descriptions.
    pub media: Vec<Media>,
}

impl Session {
    /// An empty session named `name` with a generic origin.
    pub fn new(name: &str) -> Session {
        Session {
            origin: "- 0 0 IN IP4 127.0.0.1".to_owned(),
            name: name.to_owned(),
            connection: None,
            timing: "0 0".to_owned(),
            attributes: Vec::new(),
            media: Vec::new(),
        }
    }

    /// The value of the first session-level attribute `name`.
    pub fn attr(&self, name: &str) -> Option<&str> {
        find(&self.attributes, name)
    }

    /// Parses a description (CRLF or LF line ends; unknown lines are ignored).
    pub fn parse(text: &str) -> Result<Session, SdpError> {
        if text.len() > MAX_BYTES {
            return Err(SdpError::TooLarge);
        }
        let mut s = Session {
            timing: "0 0".to_owned(),
            ..Session::default()
        };
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            let (k, v) = line.split_once('=').ok_or(SdpError::Line(i + 1))?;
            if k.len() != 1 {
                return Err(SdpError::Line(i + 1));
            }
            let in_media = !s.media.is_empty();
            match k {
                "o" => s.origin = v.to_owned(),
                "s" => s.name = v.to_owned(),
                "t" => s.timing = v.to_owned(),
                "c" => {
                    if let Some(m) = s.media.last_mut() {
                        m.connection = Some(v.to_owned());
                    } else {
                        s.connection = Some(v.to_owned());
                    }
                }
                "b" if in_media => {
                    if let Some(m) = s.media.last_mut() {
                        m.bandwidth.push(v.to_owned());
                    }
                }
                "m" => {
                    if s.media.len() >= MAX_MEDIA {
                        return Err(SdpError::TooLarge);
                    }
                    let mut it = v.split_ascii_whitespace();
                    let kind = it.next().ok_or(SdpError::Media(i + 1))?;
                    let port = it
                        .next()
                        .and_then(|p| p.split('/').next())
                        .and_then(|p| p.parse().ok())
                        .ok_or(SdpError::Media(i + 1))?;
                    let proto = it.next().ok_or(SdpError::Media(i + 1))?;
                    s.media.push(Media::new(
                        kind,
                        port,
                        proto,
                        it.map(str::to_owned).collect(),
                    ));
                }
                "a" => {
                    let (n, val) = match v.split_once(':') {
                        Some((n, val)) => (n, Some(val.to_owned())),
                        None => (v, None),
                    };
                    let a = Attribute {
                        name: n.to_owned(),
                        value: val,
                    };
                    match s.media.last_mut() {
                        Some(m) => m.attributes.push(a),
                        None => s.attributes.push(a),
                    }
                }
                _ => {}
            }
        }
        Ok(s)
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn attr(f: &mut fmt::Formatter<'_>, a: &Attribute) -> fmt::Result {
            match &a.value {
                Some(v) => write!(f, "a={}:{}\r\n", a.name, v),
                None => write!(f, "a={}\r\n", a.name),
            }
        }
        f.write_str("v=0\r\n")?;
        write!(
            f,
            "o={}\r\ns={}\r\n",
            self.origin,
            if self.name.is_empty() {
                "-"
            } else {
                &self.name
            }
        )?;
        if let Some(c) = &self.connection {
            write!(f, "c={c}\r\n")?;
        }
        write!(f, "t={}\r\n", self.timing)?;
        for a in &self.attributes {
            attr(f, a)?;
        }
        for m in &self.media {
            write!(
                f,
                "m={} {} {} {}\r\n",
                m.kind,
                m.port,
                m.proto,
                m.formats.join(" ")
            )?;
            if let Some(c) = &m.connection {
                write!(f, "c={c}\r\n")?;
            }
            for b in &m.bandwidth {
                write!(f, "b={b}\r\n")?;
            }
            for a in &m.attributes {
                attr(f, a)?;
            }
        }
        Ok(())
    }
}

/// The RTSP media description of `track` with payload type `pt` and control `control`;
/// `None` for a codec RTP does not carry here.
pub fn track_media(track: &Track, pt: u8, control: &str) -> Option<Media> {
    let kind = if track.is_video() { "video" } else { "audio" };
    let (pt, rtpmap, fmtp) = match track.codec {
        Codec::H264 => {
            let mut fmtp = format!("{pt} packetization-mode=1");
            if let Ok(c) = h264::Config::parse(&track.config) {
                if let (Some(s), Some(p)) = (c.sps.first(), c.pps.first()) {
                    let _ = write!(
                        fmtp,
                        ";profile-level-id={:02X}{:02X}{:02X};sprop-parameter-sets={},{}",
                        c.profile,
                        c.compat,
                        c.level,
                        B64.encode(s),
                        B64.encode(p)
                    );
                }
            }
            (pt, format!("{pt} H264/90000"), Some(fmtp))
        }
        Codec::H265 => {
            let mut fmtp = format!("{pt} ");
            if let Ok(c) = h265::Config::parse(&track.config) {
                if let (Some(v), Some(s), Some(p)) = (c.vps.first(), c.sps.first(), c.pps.first()) {
                    let _ = write!(
                        fmtp,
                        "sprop-vps={};sprop-sps={};sprop-pps={}",
                        B64.encode(v),
                        B64.encode(s),
                        B64.encode(p)
                    );
                }
            }
            let fmtp = (fmtp.len() > 4).then_some(fmtp);
            (pt, format!("{pt} H265/90000"), fmtp)
        }
        Codec::Aac => {
            let c = aac::Config::parse(&track.config).ok()?;
            let hex: String = track.config.iter().map(|b| format!("{b:02X}")).collect();
            (
                pt,
                format!("{pt} MPEG4-GENERIC/{}/{}", c.sample_rate, c.channels),
                Some(format!(
                    "{pt} profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config={hex}"
                )),
            )
        }
        Codec::Opus => (
            pt,
            format!("{pt} opus/48000/2"),
            Some(format!(
                "{pt} sprop-stereo={}",
                u8::from(track.channels != 1)
            )),
        ),
        Codec::Pcmu => (0, "0 PCMU/8000".to_owned(), None),
        Codec::Pcma => (8, "8 PCMA/8000".to_owned(), None),
        _ => return None,
    };
    let mut m = Media::new(kind, 0, "RTP/AVP", vec![pt.to_string()]);
    m.attributes.push(Attribute::new("rtpmap", rtpmap));
    if let Some(f) = fmtp {
        m.attributes.push(Attribute::new("fmtp", f));
    }
    m.attributes.push(Attribute::new("control", control));
    Some(m)
}

/// The track a media description declares and its payload type; `None` when no format of it
/// maps to a codec here.
pub fn media_track(m: &Media) -> Option<(Track, u8)> {
    for f in &m.formats {
        let Ok(pt) = f.parse::<u8>() else { continue };
        let (enc, rate, _channels) = match m.rtpmap(f) {
            Some(r) => r,
            None => match pt {
                0 => ("PCMU".to_owned(), 8000, None),
                8 => ("PCMA".to_owned(), 8000, None),
                _ => continue,
            },
        };
        let fmtp = m.fmtp(f);
        let get = |k: &str| fmtp.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let dec = |v: &str| B64.decode(v.trim()).ok();
        let track = match enc.to_ascii_uppercase().as_str() {
            "H264" => {
                let mut cfg = Vec::new();
                if let Some(sets) = get("sprop-parameter-sets") {
                    let sets: Vec<Vec<u8>> = sets.split(',').filter_map(dec).collect();
                    let sps = sets
                        .iter()
                        .find(|s| !s.is_empty() && h264::nal_type(s[0]) == h264::NAL_SPS);
                    let pps = sets
                        .iter()
                        .find(|s| !s.is_empty() && h264::nal_type(s[0]) == h264::NAL_PPS);
                    if let (Some(s), Some(p)) = (sps, pps) {
                        cfg = h264::Config::from_sets(s, p).encode();
                    }
                }
                Track::video(Codec::H264, cfg)
            }
            "H265" | "HEVC" => {
                let sets = (
                    get("sprop-vps").and_then(dec),
                    get("sprop-sps").and_then(dec),
                    get("sprop-pps").and_then(dec),
                );
                let cfg = match sets {
                    (Some(v), Some(s), Some(p)) => h265::Config::from_sets(&v, &s, &p)
                        .map(|c| c.encode())
                        .unwrap_or_default(),
                    _ => Vec::new(),
                };
                Track::video(Codec::H265, cfg)
            }
            "MPEG4-GENERIC" => {
                let mode = get("mode").unwrap_or("").to_ascii_lowercase();
                if !mode.is_empty() && mode != "aac-hbr" {
                    continue;
                }
                let cfg = get("config").and_then(hex).unwrap_or_default();
                let mut t = Track::aac(cfg);
                if t.sample_rate == 0 {
                    t.sample_rate = rate;
                }
                t
            }
            "OPUS" => {
                let ch = if get("sprop-stereo") == Some("0") {
                    1
                } else {
                    2
                };
                Track::audio(Codec::Opus, opus::Head::new(ch).encode(), 48000, ch)
            }
            "PCMU" => Track::audio(Codec::Pcmu, vec![], 8000, 1),
            "PCMA" => Track::audio(Codec::Pcma, vec![], 8000, 1),
            _ => continue,
        };
        return Some((track, pt));
    }
    None
}

fn hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FFMPEG_ANNOUNCE: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=No Name\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=tool:libavformat 61.7.100\r\nm=video 0 RTP/AVP 96\r\nb=AS:200\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1; sprop-parameter-sets=Z2QADazZQUH7ARAAAAMAEAAAAwMg8UKZYA==,aOvjyyLA; profile-level-id=64000D\r\na=control:streamid=0\r\nm=audio 0 RTP/AVP 97\r\nb=AS:64\r\na=rtpmap:97 MPEG4-GENERIC/44100/2\r\na=fmtp:97 profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3; config=121056E500\r\na=control:streamid=1\r\n";

    #[test]
    fn parse_ffmpeg_announce() {
        let s = Session::parse(FFMPEG_ANNOUNCE).unwrap();
        assert_eq!(s.media.len(), 2);
        assert_eq!(s.attr("tool"), Some("libavformat 61.7.100"));
        let (v, pt) = media_track(&s.media[0]).unwrap();
        assert_eq!(pt, 96);
        assert_eq!(v.codec, Codec::H264);
        assert_eq!((v.width, v.height), (320, 240));
        assert_eq!(s.media[0].control(), Some("streamid=0"));
        let (a, pt) = media_track(&s.media[1]).unwrap();
        assert_eq!(pt, 97);
        assert_eq!((a.codec, a.sample_rate, a.channels), (Codec::Aac, 44100, 2));
        assert!(Session::parse("garbage").is_err());
        assert!(Session::parse("m=video\r\n").is_err());
    }

    #[test]
    fn write_and_read_back() {
        let sps = [
            0x67, 0x64, 0x00, 0x0d, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x01, 0x10, 0x00, 0x00, 0x03,
            0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0x20, 0xf1, 0x42, 0x99, 0x60,
        ];
        let tracks = [
            Track::video(
                Codec::H264,
                h264::Config::from_sets(&sps, &[0x68, 1]).encode(),
            ),
            Track::aac(vec![0x11, 0x90]),
            Track::audio(Codec::Opus, vec![], 48000, 2),
            Track::audio(Codec::Pcma, vec![], 8000, 1),
        ];
        let mut s = Session::new("only");
        for (i, t) in tracks.iter().enumerate() {
            s.media
                .push(track_media(t, 96 + i as u8, &format!("trackID={i}")).unwrap());
        }
        let text = s.to_string();
        let back = Session::parse(&text).unwrap();
        assert_eq!(back, s);
        for (i, t) in tracks.iter().enumerate() {
            let (got, _) = media_track(&back.media[i]).unwrap();
            assert_eq!(got.codec, t.codec);
            if t.codec != Codec::Opus {
                assert_eq!(got.config, t.config, "{i}");
            }
        }
        assert!(track_media(&Track::new(Codec::Mp3, vec![]), 96, "x").is_none());
    }
}
