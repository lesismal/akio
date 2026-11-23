//! The shared brotli framing format (RFC 9841 section 8): containers our writer makes, and
//! hand-made ones for each rule the reader checks.

use akio_brotli::{
    Compressor, Container, ContainerWriter, DictionaryRef, Error, Flush, Level, Resource,
    SharedDictionary, compress, compress_large_window, compress_with_dictionary, read_container,
};

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 128 {
        out.push(v as u8 | 128);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A chunk: its length, `kind`, `head` (the header bytes after the type) and `content`.
fn chunk(kind: u8, head: &[u8], content: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    varint(&mut c, (1 + head.len() + content.len()) as u64);
    c.push(kind);
    c.extend_from_slice(head);
    c.extend_from_slice(content);
    c
}

/// A data chunk header: `codec`, the uncompressed size (if compressed), `refs` (shared
/// brotli), `flags`.
fn data_head(codec: u8, size: usize, refs: &[&[u8]], flags: u8) -> Vec<u8> {
    let mut h = vec![codec];
    if codec != 0 {
        varint(&mut h, size as u64);
    }
    if codec == 3 {
        h.push(refs.len() as u8);
        for r in refs {
            h.extend_from_slice(r);
        }
    }
    h.push(flags);
    h
}

fn container(multi: bool, chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut c = vec![0x91, 0x0a, 0x42, 0x52, if multi { 4 } else { 0 }];
    for ch in chunks {
        c.extend_from_slice(ch);
    }
    c
}

/// The final footer of a container whose other bytes are `before`: the size and the
/// directory position as reversed varints.
fn footer(before: usize, dir: usize) -> Vec<u8> {
    // The size includes the footer: 3 bytes of chunk header and varints for small values.
    for guess in 0..4 {
        let mut body = Vec::new();
        let mut v = Vec::new();
        let size = before + 4 + guess;
        varint(&mut v, size as u64);
        body.extend(v.iter().rev());
        v.clear();
        varint(&mut v, dir as u64);
        body.extend(v.iter().rev());
        let f = chunk(10, &[], &body);
        if before + f.len() == size {
            return f;
        }
    }
    unreachable!()
}

fn read(c: &[u8]) -> Result<Vec<Resource>, Error> {
    read_container(c, 1 << 24, &mut |_| None)
}

fn text(n: usize) -> Vec<u8> {
    let words = [
        "frame ",
        "chunk ",
        "resource ",
        "brotli ",
        "shared ",
        "dictionary ",
        "<p>",
        "</p>\n",
    ];
    let mut out = Vec::new();
    let mut x = 7u32;
    while out.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        out.extend_from_slice(words[(x >> 16) as usize % words.len()].as_bytes());
    }
    out.truncate(n);
    out
}

#[test]
fn writer_round_trips() {
    let page = text(20_000);
    let random: Vec<u8> = (0..3000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    // A serialized dictionary: a prefix and no custom words.
    let mut ser = vec![0x91, 0x00];
    varint(&mut ser, 4000);
    ser.extend_from_slice(&page[..4000]);
    ser.extend_from_slice(&[0, 0]);
    let shared = SharedDictionary::new(&ser).unwrap();
    let hash = [0x5a; 32];

    let mut w = ContainerWriter::new(Level::new(9));
    let dict = w.add_dictionary(&page[..8000]);
    let a = w.add_with_dictionary("a.html", &page[8000..], dict);
    let b = w.add("random.bin", &random);
    let c = w.add_with_shared_dictionary("c.html", &page[2000..9000], &shared, &hash);
    let d = w.add("", b"");
    assert_eq!((dict, a, b, c, d), (0, 1, 2, 3, 4));
    let packed = w.finish();

    // The hash reference needs the dictionary.
    assert_eq!(read(&packed), Err(Error::MissingDictionary));
    let mut asked = 0;
    let res = read_container(&packed, 1 << 24, &mut |h| {
        asked += 1;
        (h == &hash).then(|| ser.clone())
    })
    .unwrap();
    assert_eq!(asked, 1);
    assert_eq!(res.len(), 5);
    assert!(res[0].hidden && res[0].name.is_none());
    assert_eq!(res[0].data, &page[..8000]);
    assert_eq!(res[1].name.as_deref(), Some(&b"a.html"[..]));
    assert_eq!(res[1].data, &page[8000..]);
    assert_eq!(res[2].data, random);
    assert_eq!(res[3].data, &page[2000..9000]);
    assert_eq!(res[4].data, b"");
    assert!(res[1..].iter().all(|r| !r.hidden && r.hash.is_none()));
    // The dictionaries pay: the container is smaller than the pieces compressed alone.
    let alone = compress(Level::new(9), &page[8000..]).len()
        + compress(Level::new(9), &page[2000..9000]).len();
    assert!(packed.len() < alone + compress(Level::new(9), &page[..8000]).len() + 3100);
    // The limit covers everything decoded.
    let total: usize = res.iter().map(|r| r.data.len()).sum();
    assert_eq!(
        read_container(&packed, total - 1, &mut |_| Some(ser.clone())),
        Err(Error::TooLarge)
    );
    // Any byte changed: an error or other data, never a panic.
    for i in 0..packed.len() {
        let mut bad = packed.clone();
        bad[i] ^= 0x41;
        let _ = read_container(&bad, 1 << 24, &mut |_| Some(ser.clone()));
    }
    for n in 0..packed.len() {
        assert!(read_container(&packed[..n], 1 << 24, &mut |_| Some(ser.clone())).is_err());
    }
}

#[test]
fn single_resource_containers() {
    let data = text(5000);
    let packed = compress(Level::new(5), &data);
    // One data chunk, brotli; padding around it (an empty one and zeros).
    let c = container(
        false,
        &[
            vec![0],
            chunk(2, &data_head(2, data.len(), &[], 0), &packed),
            chunk(0, &[0, 0, 0], &[]),
        ],
    );
    let res = read(&c).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].data, data);
    // Uncompressed, with a hash code (kept, not checked).
    let mut head = data_head(0, 0, &[], 2);
    head.push(3);
    head.extend_from_slice(&[7; 32]);
    let res = read(&container(false, &[chunk(2, &head, b"plain")])).unwrap();
    assert_eq!(res[0].data, b"plain");
    assert_eq!(res[0].hash, Some([7; 32]));
    // Empty.
    assert_eq!(read(&container(false, &[])), Ok(vec![]));
    // Not allowed without flag bit 2: two resources, metadata, a footer.
    let one = chunk(2, &data_head(0, 0, &[], 0), b"x");
    assert_eq!(
        read(&container(false, &[one.clone(), one.clone()])),
        Err(Error::BadContainer)
    );
    let meta = chunk(1, &[0], b"id\x01a");
    assert_eq!(
        read(&container(false, &[meta, one.clone()])),
        Err(Error::BadContainer)
    );
    let f = footer(5 + one.len(), 0);
    assert_eq!(read(&container(false, &[one, f])), Err(Error::BadContainer));
    // Padding must be zeros.
    assert_eq!(
        read(&container(false, &[chunk(0, &[0, 1], &[])])),
        Err(Error::BadContainer)
    );
}

#[test]
fn partial_chunks_continue_one_stream() {
    // One stream cut at its flushes into three chunks: brotli, then "keep decoder" twice.
    let data = text(30_000);
    let mut c = Compressor::new(Level::new(6));
    let (mut s1, mut s2, mut s3) = (Vec::new(), Vec::new(), Vec::new());
    c.compress(&data[..10_000], &mut s1, Flush::Flush);
    c.compress(&data[10_000..25_000], &mut s2, Flush::Flush);
    c.compress(&data[25_000..], &mut s3, Flush::Finish);
    let pieces = [
        (3u8, data_head(2, 10_000, &[], 0), &s1),
        (4, data_head(1, 15_000, &[], 0), &s2),
        (5, data_head(1, 5_000, &[], 0), &s3),
    ];
    let parts: Vec<Vec<u8>> = pieces.iter().map(|(k, h, c)| chunk(*k, h, c)).collect();
    let dir_pos = 5 + parts.iter().map(Vec::len).sum::<usize>();
    let mut dir = vec![0];
    let mut pos = 5;
    for (p, (_, _, content)) in parts.iter().zip(&pieces) {
        varint(&mut dir, pos as u64);
        let head_len = p.len() - content.len();
        varint(&mut dir, head_len as u64);
        dir.extend_from_slice(&p[..head_len]);
        pos += p.len();
    }
    let dir = chunk(9, &[], &dir);
    let mut all: Vec<Vec<u8>> = parts.clone();
    all.push(dir.clone());
    all.push(footer(dir_pos + dir.len(), dir_pos));
    let res = read(&container(true, &all)).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].data, data);

    // Without the directory and with size 0 in the footer.
    let mut all: Vec<Vec<u8>> = parts.clone();
    all.push(chunk(10, &[], &[0, 0]));
    assert_eq!(read(&container(true, &all)).unwrap()[0].data, data);
    // A wrong size or directory position in the footer.
    let mut all: Vec<Vec<u8>> = parts.clone();
    all.push(chunk(10, &[], &[9, 0]));
    assert_eq!(read(&container(true, &all)), Err(Error::BadContainer));
    let mut all: Vec<Vec<u8>> = parts.clone();
    all.push(chunk(10, &[], &[0, 5]));
    assert_eq!(read(&container(true, &all)), Err(Error::BadContainer));
    // A directory that misses a chunk.
    let mut all: Vec<Vec<u8>> = parts.clone();
    all.push(chunk(9, &[], &[0]));
    all.push(chunk(10, &[], &[0, 0]));
    assert_eq!(read(&container(true, &all)), Err(Error::BadContainer));

    let end = || chunk(10, &[], &[0, 0]);
    // The stream does not continue: the next chunk does not keep the decoder.
    let c = container(
        true,
        &[
            chunk(3, &data_head(2, 10_000, &[], 0), &s1),
            chunk(5, &data_head(0, 0, &[], 0), b"x"),
            end(),
        ],
    );
    assert_eq!(read(&c), Err(Error::BadContainer));
    // Keep the decoder with nothing to keep.
    let c = container(
        true,
        &[
            chunk(3, &data_head(0, 0, &[], 0), b"x"),
            chunk(5, &data_head(1, 15_000, &[], 0), &s2),
            end(),
        ],
    );
    assert_eq!(read(&c), Err(Error::BadContainer));
    // The wrong uncompressed size.
    let c = container(
        true,
        &[
            chunk(3, &data_head(2, 9_999, &[], 0), &s1),
            chunk(
                5,
                &data_head(1, 20_001, &[], 0),
                &[s2.clone(), s3.clone()].concat(),
            ),
            end(),
        ],
    );
    assert_eq!(read(&c), Err(Error::BadContainer));
    // A run of parts that does not end, or ends without a start.
    let c = container(true, &[chunk(3, &data_head(0, 0, &[], 0), b"x"), end()]);
    assert_eq!(read(&c), Err(Error::BadContainer));
    let c = container(true, &[chunk(5, &data_head(0, 0, &[], 0), b"x"), end()]);
    assert_eq!(read(&c), Err(Error::BadContainer));
    // Flags not allowed on a middle part.
    let c = container(
        true,
        &[
            chunk(3, &data_head(0, 0, &[], 0), b"x"),
            chunk(4, &data_head(0, 0, &[], 1), b"y"),
            chunk(5, &data_head(0, 0, &[], 0), b"z"),
            end(),
        ],
    );
    assert_eq!(read(&c), Err(Error::BadContainer));
}

#[test]
fn metadata() {
    let end = || chunk(10, &[], &[0, 0]);
    let one = chunk(2, &data_head(0, 0, &[], 0), b"x");
    let mt = 1_700_000_000_000_000i64.to_le_bytes();
    let mut fields = b"id\x05a.txtmt\x08".to_vec();
    fields.extend_from_slice(&mt);
    fields.extend_from_slice(b"XY\x02hi");
    // Compressed metadata, footer and global metadata with custom fields only.
    let packed = compress(Level::new(5), &fields);
    let mut head = vec![2];
    varint(&mut head, fields.len() as u64);
    let c = container(
        true,
        &[
            chunk(7, &[0], b"AB\x00"),
            chunk(1, &head, &packed),
            one.clone(),
            chunk(6, &[0], b"QQ\x01z"),
            end(),
        ],
    );
    let res = read(&c).unwrap();
    assert_eq!(res[0].name.as_deref(), Some(&b"a.txt"[..]));
    assert_eq!(res[0].modified, Some(1_700_000_000_000_000));
    for (bad, why) in [
        (&b"Ab\x00"[..], "mixed case"),
        (b"i1\x00", "not letters"),
        (b"zz\x00", "unknown lower-case field"),
        (b"id\x01aid\x01b", "two names"),
        (b"mt\x01a", "short time"),
        (b"id\x05a", "past the content"),
    ] {
        let c = container(true, &[chunk(1, &[0], bad), one.clone(), end()]);
        assert_eq!(read(&c), Err(Error::BadContainer), "{why}");
    }
    // Lower-case fields are for metadata chunks only.
    let c = container(true, &[one.clone(), chunk(6, &[0], b"id\x01a"), end()]);
    assert_eq!(read(&c), Err(Error::BadContainer));
    // Order: metadata right before the data, one each, the footer metadata after it.
    for chunks in [
        vec![chunk(1, &[0], b""), end()],
        vec![chunk(1, &[0], b""), chunk(1, &[0], b""), one.clone(), end()],
        vec![chunk(1, &[0], b""), chunk(7, &[0], b""), one.clone(), end()],
        vec![chunk(6, &[0], b""), one.clone(), end()],
        vec![one.clone(), chunk(6, &[0], b""), chunk(6, &[0], b""), end()],
        vec![one.clone(), end(), one.clone()],
        vec![one.clone()],
        vec![one.clone(), end(), end()],
        vec![one.clone(), chunk(9, &[], &[0]), chunk(9, &[], &[0]), end()],
        vec![chunk(11, &[0], b""), end()],
        vec![chunk(2, &[4], b"x"), end()],
    ] {
        assert_eq!(read(&container(true, &chunks)), Err(Error::BadContainer));
    }
    // Padding anywhere, even between metadata and data.
    let c = container(
        true,
        &[
            chunk(1, &[0], b"id\x01a"),
            vec![0],
            one.clone(),
            vec![0],
            end(),
        ],
    );
    assert_eq!(read(&c).unwrap()[0].name.as_deref(), Some(&b"a"[..]));
    // Flags: version bits, undefined bits.
    for f in [1u8, 2, 8, 0x80] {
        let mut c = container(true, &[one.clone(), end()]);
        c[4] = 4 | f;
        assert_eq!(read(&c), Err(Error::BadContainer));
    }
    assert_eq!(read(b"\x91\x0aBr\x00"), Err(Error::BadContainer));
}

#[test]
fn dictionary_references() {
    let end = || chunk(10, &[], &[0, 0]);
    let base = text(6000);
    let more = text(9000);
    let dict_chunk = chunk(2, &data_head(0, 0, &[], 1), &base);
    let packed = compress_with_dictionary(Level::new(9), &more, &base);
    // A resource by pointer (source 0, prefix), and a chunk's content (source 1).
    for flags in [0u8, 1] {
        let mut r = vec![flags];
        varint(&mut r, 5);
        let c = container(
            true,
            &[
                dict_chunk.clone(),
                chunk(2, &data_head(3, more.len(), &[&r], 0), &packed),
                end(),
            ],
        );
        let res = read(&c).unwrap();
        assert!(res[0].hidden);
        assert_eq!(res[1].data, more);
    }
    // Pointers that point at nothing, at the chunk itself or later; a serialized dictionary
    // as one chunk's content; unknown flags.
    let at = 5 + dict_chunk.len();
    for (flags, ptr) in [
        (0u8, 6usize),
        (0, at),
        (1, at + 1),
        (1 | 4, 5),
        (16, 5),
        (3, 5),
    ] {
        let mut r = vec![flags];
        varint(&mut r, ptr as u64);
        let c = container(
            true,
            &[
                dict_chunk.clone(),
                chunk(2, &data_head(3, more.len(), &[&r], 0), &packed),
                end(),
            ],
        );
        assert_eq!(
            read(&c),
            Err(Error::BadContainer),
            "flags {flags} pointer {ptr}"
        );
    }
    // By hash: the caller resolves it; a prefix and a serialized one together (the
    // serialized one's prefix after the other).
    let mut ser = vec![0x91, 0x00];
    varint(&mut ser, 1000);
    ser.extend_from_slice(&base[..1000]);
    ser.extend_from_slice(&[0, 0]);
    let mut prefix_and_ser = base.clone();
    prefix_and_ser.extend_from_slice(&base[..1000]);
    let packed = compress_with_dictionary(Level::new(9), &more, &prefix_and_ser);
    let mut r1 = vec![2, 3];
    r1.extend_from_slice(&[1; 32]);
    let mut r2 = vec![2 | 4, 3];
    r2.extend_from_slice(&[2; 32]);
    let c = container(
        true,
        &[
            chunk(2, &data_head(3, more.len(), &[&r1, &r2], 0), &packed),
            end(),
        ],
    );
    let res = read_container(&c, 1 << 24, &mut |h| match h[0] {
        1 => Some(base.clone()),
        2 => Some(ser.clone()),
        _ => None,
    })
    .unwrap();
    assert_eq!(res[0].data, more);
    assert_eq!(
        read_container(&c, 1 << 24, &mut |h| (h[0] == 1).then(|| base.clone())),
        Err(Error::MissingDictionary)
    );
    // A bad hash type; two serialized dictionaries.
    let mut r3 = vec![2, 2];
    r3.extend_from_slice(&[1; 32]);
    let c = container(true, &[chunk(2, &data_head(3, 1, &[&r3], 0), b"x"), end()]);
    assert_eq!(read(&c), Err(Error::BadContainer));
    let c = container(
        true,
        &[
            chunk(2, &data_head(3, more.len(), &[&r2, &r2], 0), &packed),
            end(),
        ],
    );
    assert_eq!(
        read_container(&c, 1 << 24, &mut |_| Some(ser.clone())),
        Err(Error::BadContainer)
    );
}

#[test]
fn large_window_in_shared_brotli_chunks() {
    let end = || chunk(10, &[], &[0, 0]);
    let data = text(50_000);
    let packed = compress_large_window(Level::new(5), &data);
    // Shared brotli allows large-window streams; brotli (RFC 7932) does not.
    let c = container(
        true,
        &[chunk(2, &data_head(3, data.len(), &[], 0), &packed), end()],
    );
    assert_eq!(read(&c).unwrap()[0].data, data);
    let c = container(
        true,
        &[chunk(2, &data_head(2, data.len(), &[], 0), &packed), end()],
    );
    assert_eq!(read(&c), Err(Error::BadWindow));
}

/// The chunks of a container: (type, codec or 255, extra header byte of a repeat metadata
/// chunk or 255), parsed apart from the reader.
fn chunk_kinds(c: &[u8]) -> Vec<(u8, u8, u8)> {
    fn uvar(c: &[u8], at: &mut usize) -> usize {
        let (mut v, mut shift) = (0usize, 0);
        loop {
            let b = c[*at];
            *at += 1;
            v |= usize::from(b & 127) << shift;
            shift += 7;
            if b < 128 {
                return v;
            }
        }
    }
    let mut out = Vec::new();
    let mut at = 5;
    while at < c.len() {
        let len = uvar(c, &mut at);
        let end = at + len;
        let kind = if len == 0 { 0 } else { c[at] };
        let (mut codec, mut extra) = (255, 255);
        if (1..=8).contains(&kind) {
            let mut p = at + 1;
            codec = c[p];
            p += 1;
            if codec != 0 {
                uvar(c, &mut p);
            }
            if codec == 3 {
                let n = c[p];
                p += 1;
                for _ in 0..n {
                    let f = c[p];
                    p += 1;
                    if f & 3 == 2 {
                        p += 33;
                    } else {
                        uvar(c, &mut p);
                    }
                }
            }
            if kind == 8 {
                extra = c[p];
            }
        }
        out.push((kind, codec, extra));
        at = end;
    }
    out
}

fn resource(name: &str, data: &[u8]) -> Resource {
    let mut r = Resource::default();
    r.name = Some(name.as_bytes().to_vec());
    r.data = data.to_vec();
    r
}

#[test]
fn writer_metadata_parts_and_repeats() {
    let page = text(40_000);
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let random: Vec<u8> = (0..5000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    let mut ser = vec![0x91, 0x00];
    varint(&mut ser, 4000);
    ser.extend_from_slice(&page[..4000]);
    ser.extend_from_slice(&[0, 0]);
    let shared = SharedDictionary::new(&ser).unwrap();
    let hash = [0x5a; 32];

    let mut dict = resource("dict.html", &page[..8000]);
    dict.hidden = true;
    dict.hash = Some([1; 32]);
    let mut a = resource("a.html", &page[8000..]);
    a.modified = Some(-1_234_567);
    a.fields = vec![(*b"CT", b"text/html".to_vec()), (*b"CT", b"again".to_vec())];
    a.footer = vec![(*b"SG", vec![9; 40])];
    a.hash = Some([2; 32]);
    let mut b = resource("random.bin", &random);
    b.footer = vec![(*b"ZZ", Vec::new())];
    let c = resource("c.html", &page[2000..9000]);
    let mut d = Resource::default();
    d.data = b"no metadata".to_vec();
    let mut e = resource("", b"");
    e.modified = Some(0);
    let global = vec![(*b"AU", b"akio".to_vec()), (*b"VR", vec![1, 2])];

    let mut w = ContainerWriter::new(Level::new(9))
        .part_size(3000)
        .repeat_metadata(true);
    w.add_global_metadata(&global[..1]);
    assert_eq!(w.add_resource(&dict, None), 0);
    assert_eq!(w.add_resource(&a, Some(DictionaryRef::Resource(0))), 1);
    assert_eq!(w.add_resource(&b, None), 2);
    assert_eq!(
        w.add_resource(&c, Some(DictionaryRef::Shared(&shared, &hash))),
        3
    );
    w.add_global_metadata(&global[1..]);
    assert_eq!(w.add_resource(&d, None), 4);
    assert_eq!(w.add_resource(&e, None), 5);
    let packed = w.finish();

    let got =
        Container::read(&packed, 1 << 24, &mut |h| (h == &hash).then(|| ser.clone())).unwrap();
    assert_eq!(got.resources, [dict, a, b, c, d, e]);
    assert_eq!(got.global, global);

    let kinds = chunk_kinds(&packed);
    let types: Vec<u8> = kinds.iter().map(|k| k.0).collect();
    // The dictionary: 8000 bytes in three parts of one stream (brotli, keep decoder twice).
    assert_eq!(&types[..6], [7, 1, 3, 4, 5, 1]);
    assert_eq!(
        kinds[2..5].iter().map(|k| k.1).collect::<Vec<_>>(),
        [2, 1, 1]
    );
    // a.html: one stream with the dictionary by pointer, then keep decoder; its footer.
    let a_at = 6;
    assert_eq!(kinds[a_at].0, 3);
    assert_eq!(kinds[a_at].1, 3);
    assert!(
        kinds[a_at + 1..]
            .iter()
            .take_while(|k| k.0 == 4 || k.0 == 5)
            .all(|k| k.1 == 1)
    );
    // random.bin: stored parts.
    let b_at = types.iter().position(|&t| t == 6).unwrap() + 2;
    assert_eq!(kinds[b_at].0, 3);
    assert!(kinds[b_at..b_at + 2].iter().all(|k| k.1 == 0));
    // c.html: parts each a shared brotli stream of their own.
    let c_at = kinds.iter().rposition(|k| k.0 == 3).unwrap();
    assert!(kinds[c_at..c_at + 3].iter().all(|k| k.1 == 3));
    // Repeat metadata for each metadata and footer metadata chunk, in order, then the
    // directory and the footer.
    let originals: Vec<u8> = types
        .iter()
        .copied()
        .filter(|&t| t == 1 || t == 6)
        .collect();
    let repeats: Vec<u8> = kinds.iter().filter(|k| k.0 == 8).map(|k| k.2).collect();
    assert_eq!(originals, repeats);
    assert_eq!(originals, [1, 1, 6, 1, 6, 1, 1]);
    assert_eq!(&types[types.len() - 2..], [9, 10]);

    // Read back and written again chunk by chunk: the same resources.
    let mut w = ContainerWriter::new(Level::new(5)).part_size(7000);
    for r in &got.resources {
        w.add_resource(r, None);
    }
    let again = read(&w.finish()).unwrap();
    assert_eq!(again, got.resources);

    // Any byte changed: an error or other data, never a panic; any cut: an error.
    for i in 0..packed.len() {
        let mut bad = packed.clone();
        bad[i] ^= 0x22;
        let _ = read_container(&bad, 1 << 24, &mut |_| Some(ser.clone()));
    }
    for n in 0..packed.len() {
        assert!(read_container(&packed[..n], 1 << 24, &mut |_| Some(ser.clone())).is_err());
    }
}

#[test]
fn writer_repeat_series_compressed() {
    // Many resources with long, similar metadata: the repeat series is one brotli stream.
    let mut w = ContainerWriter::new(Level::new(6)).repeat_metadata(true);
    let mut want = Vec::new();
    for i in 0..40 {
        let mut r = resource(
            &format!("static/assets/images/photo-{i:04}.jpeg"),
            &[i as u8; 3],
        );
        r.fields = vec![(*b"CT", b"image/jpeg; quality=high; profile=srgb".to_vec())];
        r.modified = Some(1_700_000_000_000_000 + i);
        w.add_resource(&r, None);
        want.push(r);
    }
    let packed = w.finish();
    assert_eq!(read(&packed).unwrap(), want);
    let repeats: Vec<u8> = chunk_kinds(&packed)
        .iter()
        .filter(|k| k.0 == 8)
        .map(|k| k.1)
        .collect();
    assert_eq!(repeats.len(), 40);
    assert_eq!(repeats[0], 2);
    assert!(repeats[1..].iter().all(|&c| c == 1));
}

#[test]
#[should_panic(expected = "upper-case")]
fn writer_refuses_lower_case_custom_fields() {
    let mut r = resource("x", b"x");
    r.fields = vec![(*b"ct", Vec::new())];
    ContainerWriter::new(Level::new(1)).add_resource(&r, None);
}

/// A container made byte by byte from RFC 9841 section 8: a resource "a" with data "hi" and
/// a footer field, repeat metadata for both metadata chunks, a central directory pointing at
/// the first repeat chunk, and the final footer.
const RFC_VECTOR: [u8; 76] = [
    0x91, 0x0a, 0x42, 0x52, 0x04, // signature; flags: bit 2
    // 5: metadata chunk, uncompressed: "id" 1 "a"
    0x06, 0x01, 0x00, b'i', b'd', 0x01, b'a', //
    // 12: data chunk, uncompressed, no flags: "hi"
    0x05, 0x02, 0x00, 0x00, b'h', b'i', //
    // 18: footer metadata chunk, uncompressed: "XY" 1 "z"
    0x06, 0x06, 0x00, b'X', b'Y', 0x01, b'z', //
    // 25: repeat metadata chunk, uncompressed, repeating a metadata chunk
    0x07, 0x08, 0x00, 0x01, b'i', b'd', 0x01, b'a', //
    // 33: repeat metadata chunk, uncompressed, repeating a footer metadata chunk
    0x07, 0x08, 0x00, 0x06, b'X', b'Y', 0x01, b'z', //
    // 41: central directory: repeat metadata at 25, then pointer, header length, header
    // copy of each data and metadata chunk
    0x1e, 0x09, 0x19, //
    0x05, 0x03, 0x06, 0x01, 0x00, //
    0x0c, 0x04, 0x05, 0x02, 0x00, 0x00, //
    0x12, 0x03, 0x06, 0x06, 0x00, //
    0x19, 0x04, 0x07, 0x08, 0x00, 0x01, //
    0x21, 0x04, 0x07, 0x08, 0x00, 0x06, //
    // 72: final footer: size 76 and directory at 41, reversed varints
    0x03, 0x0a, 0x4c, 0x29,
];

#[test]
fn repeat_metadata_vector() {
    let res = read(&RFC_VECTOR).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].name.as_deref(), Some(&b"a"[..]));
    assert_eq!(res[0].data, b"hi");
    assert_eq!(res[0].footer, [(*b"XY", b"z".to_vec())]);
    // A repeated value that differs; a repeat of the wrong type; the directory pointing at
    // the second repeat chunk, or at none.
    for (at, v) in [(32, b'b'), (36, 0x01), (28, 0x06), (43, 0x21), (43, 0x00)] {
        let mut c = RFC_VECTOR;
        c[at] = v;
        assert_eq!(read(&c), Err(Error::BadContainer), "byte {at} = {v:#x}");
    }
}

/// A container of `chunks` (multi) with a central directory whose repeat metadata pointer is
/// the chunk at `repeat` (0 if `None`), and the final footer.
fn with_directory(chunks: &[(Vec<u8>, usize)], repeat: Option<usize>) -> Vec<u8> {
    let mut c = container(true, &[]);
    let mut listed = Vec::new();
    let mut at = Vec::new();
    for (ch, content) in chunks {
        at.push(c.len());
        let head = ch.len() - content;
        // The type: after the length varint (padding has none listed).
        let mut p = 0;
        while ch[p] >= 128 {
            p += 1;
        }
        if ch[p] != 0 && (1..=8).contains(&ch[p + 1]) {
            varint(&mut listed, c.len() as u64);
            varint(&mut listed, head as u64);
            listed.extend_from_slice(&ch[..head]);
        }
        c.extend_from_slice(ch);
    }
    let mut dir = Vec::new();
    varint(&mut dir, repeat.map_or(0, |i| at[i]) as u64);
    dir.extend_from_slice(&listed);
    let dir_pos = c.len();
    c.extend_from_slice(&chunk(9, &[], &dir));
    let f = footer(c.len(), dir_pos);
    c.extend_from_slice(&f);
    c
}

#[test]
fn repeat_metadata_checks() {
    let meta = b"id\x01amt\x08\x01\x02\x03\x04\x05\x06\x07\x08AB\x01c".to_vec();
    let foot = b"QQ\x02zzRR\x00".to_vec();
    let m = |c: &[u8]| (chunk(1, &[0], c), c.len());
    let data = |c: &[u8]| (chunk(2, &data_head(0, 0, &[], 0), c), c.len());
    let f = |c: &[u8]| (chunk(6, &[0], c), c.len());
    let rep = |kind: u8, c: &[u8]| (chunk(8, &[0, kind], c), c.len());
    let base = || vec![m(&meta), data(b"x"), f(&foot), m(b"id\x01b"), data(b"y")];
    let ok = |extra: Vec<(Vec<u8>, usize)>| {
        let mut all = base();
        let first = all.len();
        all.extend(extra);
        let c = with_directory(&all, Some(first));
        read(&c)
    };
    // Whole copies.
    let res = ok(vec![rep(1, &meta), rep(6, &foot), rep(1, b"id\x01b")]).unwrap();
    assert_eq!(res[0].footer, [(*b"QQ", b"zz".to_vec()), (*b"RR", vec![])]);
    // Fields left out (in every copy whose chunk has them) and in another order.
    ok(vec![
        rep(1, b"AB\x01cid\x01a"),
        rep(6, b""),
        rep(1, b"id\x01b"),
    ])
    .unwrap();
    ok(vec![
        rep(1, b"id\x01a"),
        rep(6, b"RR\x00"),
        rep(1, b"id\x01b"),
    ])
    .unwrap();
    for (bad, why) in [
        (vec![rep(1, &meta), rep(6, &foot)], "a chunk not repeated"),
        (
            vec![
                rep(1, &meta),
                rep(6, &foot),
                rep(1, b"id\x01b"),
                rep(1, b""),
            ],
            "one too many",
        ),
        (
            vec![rep(1, &meta), rep(1, &foot), rep(1, b"id\x01b")],
            "the wrong type",
        ),
        (
            vec![rep(1, b"id\x01a"), rep(6, &foot), rep(1, b"id\x01c")],
            "another value",
        ),
        (
            vec![rep(1, b"id\x01aXX\x00"), rep(6, &foot), rep(1, b"id\x01b")],
            "a field the chunk does not have",
        ),
        (
            vec![rep(1, b"id\x01aid\x01a"), rep(6, &foot), rep(1, b"id\x01b")],
            "a field twice",
        ),
        (
            vec![rep(1, b"id\x01a"), rep(6, &foot), rep(1, b"")],
            "a name in one copy, not in another",
        ),
        (
            vec![rep(6, &foot), rep(1, &meta), rep(1, b"id\x01b")],
            "out of order",
        ),
        (
            vec![rep(1, &meta), rep(6, b"id\x01a"), rep(1, b"id\x01b")],
            "a lower-case field in a footer copy",
        ),
        (
            vec![rep(1, &meta), rep(7, &foot), rep(1, b"id\x01b")],
            "repeating global metadata",
        ),
    ] {
        assert_eq!(ok(bad), Err(Error::BadContainer), "{why}");
    }
    // The directory's pointer: the first repeat chunk, 0 only if there is none.
    let mut all = base();
    all.extend(vec![rep(1, &meta), rep(6, &foot), rep(1, b"id\x01b")]);
    for p in [None, Some(6), Some(1)] {
        assert_eq!(read(&with_directory(&all, p)), Err(Error::BadContainer));
    }
    assert!(read(&with_directory(&base(), None)).is_ok());
    // Without a directory, repeat chunks are checked all the same.
    let mut chunks: Vec<Vec<u8>> = all.iter().map(|(c, _)| c.clone()).collect();
    chunks.push(chunk(10, &[], &[0, 0]));
    assert!(read(&container(true, &chunks)).is_ok());
    chunks[6] = rep(6, b"RR\x00").0;
    assert!(read(&container(true, &chunks)).is_ok());
    chunks[7] = rep(1, b"").0;
    assert_eq!(read(&container(true, &chunks)), Err(Error::BadContainer));
}

#[test]
fn repeat_metadata_compression() {
    let end = || chunk(10, &[], &[0, 0]);
    let one = chunk(2, &data_head(0, 0, &[], 0), b"x");
    let meta = b"id\x05a.txtXY\x04abcd".to_vec();
    let foot = b"QQ\x03abc".to_vec();
    // The series as one stream: brotli, then keep decoder.
    let mut c = Compressor::new(Level::new(5));
    let (mut s1, mut s2) = (Vec::new(), Vec::new());
    c.compress(&meta, &mut s1, Flush::Flush);
    c.compress(&foot, &mut s2, Flush::Finish);
    // data_head's last byte (the flags of a data chunk) is the repeated type here.
    let head = data_head;
    let r1 = chunk(8, &head(2, meta.len(), &[], 1), &s1);
    let r2 = chunk(8, &head(1, foot.len(), &[], 6), &s2);
    let originals = [chunk(1, &[0], &meta), one, chunk(6, &[0], &foot)];
    let c = container(
        true,
        &[originals.to_vec(), vec![r1, vec![0], r2, end()]].concat(),
    );
    assert_eq!(read(&c).unwrap()[0].footer, [(*b"QQ", b"abc".to_vec())]);
    // Keeping the decoder of a chunk that is not repeat metadata.
    let mut c2 = Compressor::new(Level::new(5));
    let (mut d1, mut d2) = (Vec::new(), Vec::new());
    c2.compress(b"x", &mut d1, Flush::Flush);
    c2.compress(&meta, &mut d2, Flush::Finish);
    let c = container(
        true,
        &[
            chunk(1, &[0], &meta),
            chunk(2, &data_head(2, 1, &[], 0), &d1),
            chunk(8, &head(1, meta.len(), &[], 1), &d2),
            end(),
        ],
    );
    assert_eq!(read(&c), Err(Error::BadContainer));
    // Dictionaries: an earlier repeat chunk's content or a hash, not other chunks.
    let packed = compress_with_dictionary(Level::new(9), &foot, &meta);
    let r1 = chunk(8, &[0, 1], &meta);
    let r1_at = 5 + originals.iter().map(Vec::len).sum::<usize>();
    for (flags, ptr, good) in [
        (1u8, r1_at, true),
        (1, 5, false),
        (0, 5 + originals[0].len(), false),
    ] {
        let mut r = vec![flags];
        varint(&mut r, ptr as u64);
        let r2 = chunk(8, &head(3, foot.len(), &[&r], 6), &packed);
        let c = container(
            true,
            &[originals.to_vec(), vec![r1.clone(), r2, end()]].concat(),
        );
        assert_eq!(read(&c).is_ok(), good, "flags {flags} pointer {ptr}");
    }
    let mut r = vec![2, 3];
    r.extend_from_slice(&[4; 32]);
    let r2 = chunk(8, &head(3, foot.len(), &[&r], 6), &packed);
    let c = container(true, &[originals.to_vec(), vec![r1, r2, end()]].concat());
    assert!(read_container(&c, 1 << 20, &mut |_| Some(meta.clone())).is_ok());
}
