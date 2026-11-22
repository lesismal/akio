//! The shared brotli framing format (RFC 9841 section 8): containers our writer makes, and
//! hand-made ones for each rule the reader checks.

use akio_brotli::{
    Compressor, ContainerWriter, Error, Flush, Level, Resource, SharedDictionary, compress,
    compress_large_window, compress_with_dictionary, read_container,
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
