//! RTMP server tests: a hand-written blocking client publishing a real FLV file and playing it
//! back, and ffmpeg / ffprobe as publisher and player (skipped when they are not installed).

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_media::{
    Codec, Hub,
    amf::{self, Value},
    flv::{self, Decoder, Demuxer, Event},
    rtmp::{
        RtmpConfig, RtmpServer,
        chunk::{self, ChunkReader, Message},
        handshake,
    },
};

const SAMPLE: &[u8] = include_bytes!("../testdata/h264_aac.flv");

fn start(cfg: RtmpConfig) -> (Hub, Arc<Engine>, SocketAddr) {
    let hub = Hub::default();
    let srv = RtmpServer::new(hub.clone(), cfg);
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(srv))
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let addr = engine.local_addrs()[0];
    (hub, engine, addr)
}

/// A minimal blocking RTMP client.
struct Client {
    s: TcpStream,
    r: ChunkReader,
    pending: Vec<Message>,
}

impl Client {
    fn connect(addr: SocketAddr, app: &str, simple: bool) -> Client {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(&handshake::client_hello(simple)).unwrap();
        let mut s0s1s2 = vec![0u8; 1 + 2 * handshake::SIZE];
        s.read_exact(&mut s0s1s2).unwrap();
        s.write_all(&handshake::client_reply(&s0s1s2).unwrap())
            .unwrap();
        let mut c = Client {
            s,
            r: ChunkReader::new(),
            pending: Vec::new(),
        };
        c.send(&Message::new(
            2,
            chunk::SET_CHUNK_SIZE,
            0,
            0,
            60000u32.to_be_bytes().to_vec(),
        ));
        c.command(
            0,
            &[
                Value::from("connect"),
                Value::Number(1.0),
                Value::object([
                    ("app", Value::from(app)),
                    (
                        "tcUrl",
                        Value::from(format!("rtmp://{addr}/{app}").as_str()),
                    ),
                ]),
            ],
        );
        let r = c.wait_command("_result");
        assert_eq!(
            r[3].get("code").and_then(Value::as_str),
            Some("NetConnection.Connect.Success")
        );
        c.command(
            0,
            &[Value::from("createStream"), Value::Number(2.0), Value::Null],
        );
        c.wait_command("_result");
        c
    }

    fn send(&mut self, m: &Message) {
        let mut out = Vec::new();
        chunk::write_message(&mut out, m, 60000);
        self.s.write_all(&out).unwrap();
    }

    fn command(&mut self, sid: u32, vals: &[Value]) {
        self.send(&Message::new(
            3,
            chunk::COMMAND_AMF0,
            sid,
            0,
            amf::encode(vals),
        ));
    }

    fn next(&mut self) -> Option<Message> {
        loop {
            if !self.pending.is_empty() {
                return Some(self.pending.remove(0));
            }
            let mut b = vec![0u8; 65536];
            let n = self.s.read(&mut b).ok()?;
            if n == 0 {
                return None;
            }
            self.pending.extend(self.r.feed(&b[..n]).unwrap());
        }
    }

    fn wait_command(&mut self, name: &str) -> Vec<Value> {
        loop {
            let m = self.next().expect("connection closed");
            if m.msg_type == chunk::COMMAND_AMF0 {
                let v = amf::decode_all(&m.payload).unwrap();
                if v[0].as_str() == Some(name) {
                    return v;
                }
            }
        }
    }

    fn wait_status(&mut self) -> String {
        let v = self.wait_command("onStatus");
        v[3].get("code").and_then(Value::as_str).unwrap().to_owned()
    }
}

#[test]
fn publish_file_and_play_back() {
    let (hub, engine, addr) = start(RtmpConfig::default());
    let mut publisher = Client::connect(addr, "live", false);
    publisher.command(
        1,
        &[
            Value::from("publish"),
            Value::Number(3.0),
            Value::Null,
            Value::from("s?token=x"),
            Value::from("live"),
        ],
    );
    assert_eq!(publisher.wait_status(), "NetStream.Publish.Start");

    // A second publisher is refused at once.
    let mut second = Client::connect(addr, "live", true);
    second.command(
        1,
        &[
            Value::from("publish"),
            Value::Number(3.0),
            Value::Null,
            Value::from("s"),
        ],
    );
    assert_eq!(second.wait_status(), "NetStream.Publish.BadName");

    // Publish the header tags and the first GOP, then a player joins and gets the cached GOP.
    let mut tags = Demuxer::new().feed(SAMPLE).unwrap();
    let rest = tags.split_off(tags.iter().position(|t| t.ts >= 1000).unwrap());
    for t in &tags {
        let mt = match t.tag_type {
            flv::TAG_AUDIO => chunk::AUDIO,
            flv::TAG_VIDEO => chunk::VIDEO,
            _ => chunk::DATA_AMF0,
        };
        publisher.send(&Message::new(4, mt, 1, t.ts, t.body.clone()));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while hub.stream_info("live/s").is_none_or(|s| !s.publishing) {
        assert!(Instant::now() < deadline, "stream never went live");
        std::thread::sleep(Duration::from_millis(5));
    }
    let info = hub.stream_info("live/s").unwrap();
    assert_eq!(info.publisher.query, "token=x");
    assert_eq!(info.tracks.len(), 2);

    let mut player = Client::connect(addr, "live", false);
    player.command(
        1,
        &[
            Value::from("play"),
            Value::Number(4.0),
            Value::Null,
            Value::from("s"),
        ],
    );
    assert_eq!(player.wait_status(), "NetStream.Play.Reset");
    assert_eq!(player.wait_status(), "NetStream.Play.Start");
    for t in &rest {
        let mt = if t.tag_type == flv::TAG_AUDIO {
            chunk::AUDIO
        } else {
            chunk::VIDEO
        };
        publisher.send(&Message::new(4, mt, 1, t.ts, t.body.clone()));
    }
    publisher.command(
        1,
        &[
            Value::from("deleteStream"),
            Value::Number(5.0),
            Value::Null,
            Value::Number(1.0),
        ],
    );

    let mut dec = Decoder::new();
    let mut tracks = None;
    let mut video = 0;
    let mut keys = 0;
    while let Some(m) = player.next() {
        let tag = match m.msg_type {
            chunk::AUDIO => flv::TAG_AUDIO,
            chunk::VIDEO => flv::TAG_VIDEO,
            chunk::DATA_AMF0 => flv::TAG_SCRIPT,
            _ => continue,
        };
        for e in dec.write(tag, m.timestamp, &m.payload) {
            match e {
                Event::Tracks(t) => tracks = Some(t),
                Event::Packet(p) if p.track == 0 => {
                    video += 1;
                    keys += usize::from(p.keyframe);
                }
                _ => {}
            }
        }
    }
    let tracks = tracks.expect("tracks");
    assert_eq!(tracks[0].codec, Codec::H264);
    assert_eq!((tracks[0].width, tracks[0].height), (320, 240));
    assert_eq!(tracks[1].codec, Codec::Aac);
    // The whole file: the cached first GOP and the live rest.
    assert_eq!(video, 50);
    assert_eq!(keys, 2);
    engine.shutdown();
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn ffprobe_streams(url: &str) -> String {
    let out = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name,width,height",
            "-of",
            "csv=p=0",
            "-rw_timeout",
            "5000000",
            url,
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// ffmpeg publishes over RTMP (H.264 + AAC, then H.265 + Opus with Enhanced RTMP), ffprobe and
/// ffmpeg play it back over RTMP.
/// Whether the installed ffmpeg can write Opus into FLV (enhanced RTMP, ffmpeg 7+).
fn ffmpeg_muxes_opus_into_flv() -> bool {
    Command::new("ffmpeg")
        .args([
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "sine=sample_rate=48000",
            "-t",
            "0.1",
            "-c:a",
            "libopus",
            "-f",
            "flv",
            "-y",
        ])
        .arg(if cfg!(windows) { "NUL" } else { "/dev/null" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn ffmpeg_publish_and_play() {
    if !have("ffmpeg") || !have("ffprobe") {
        eprintln!("ffmpeg/ffprobe not found: skipped");
        return;
    }
    let mut cfg = RtmpConfig::default();
    cfg.play_wait = Some(Duration::from_secs(5));
    let (hub, engine, addr) = start(cfg);
    let mut rounds = vec![("libx264", "aac", "h264,320,240")];
    if ffmpeg_muxes_opus_into_flv() {
        rounds.push(("libx265", "libopus", "hevc,320,240"));
    } else {
        // Enhanced RTMP (HEVC / Opus in FLV) needs ffmpeg 7 or newer.
        eprintln!("this ffmpeg cannot mux Opus into FLV: HEVC/Opus round skipped");
    }
    for (vcodec, acodec, want) in rounds {
        let url = format!("rtmp://{addr}/live/ff");
        let mut pubp = Command::new("ffmpeg")
            .args([
                "-v",
                "error",
                "-re",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=320x240:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine=sample_rate=48000",
            ])
            .args([
                "-t", "8", "-pix_fmt", "yuv420p", "-c:v", vcodec, "-g", "25", "-c:a", acodec,
            ])
            .args(if vcodec == "libx265" {
                vec!["-x265-params", "log-level=error"]
            } else {
                vec![]
            })
            .args(["-f", "flv", &url])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while hub.stream_info("live/ff").is_none_or(|s| !s.publishing) {
            assert!(Instant::now() < deadline, "ffmpeg never went live");
            std::thread::sleep(Duration::from_millis(20));
        }
        let probe = ffprobe_streams(&url);
        assert!(probe.contains(want), "{vcodec}: ffprobe said {probe:?}");
        let audio = if acodec == "aac" { "aac" } else { "opus" };
        assert!(probe.contains(audio), "{acodec}: ffprobe said {probe:?}");
        let status = Command::new("ffmpeg")
            .args(["-v", "error", "-i", &url, "-t", "2", "-f", "null", "-"])
            .status()
            .unwrap();
        assert!(status.success());
        let _ = pubp.kill();
        let _ = pubp.wait();
        let deadline = Instant::now() + Duration::from_secs(10);
        while hub.stream_info("live/ff").is_some_and(|s| s.publishing) {
            assert!(Instant::now() < deadline, "publisher never left");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    engine.shutdown();
}
