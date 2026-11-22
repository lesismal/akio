# ADR-079: Large-window brotli, the shared brotli framing format, and custom word lists in the encoder (RFC 9841)

English | [简体中文](079-brotli-large-window-framing-custom-words.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-069's note of 2026-11-22 implemented RFC 9841's serialized shared dictionaries in
akio-brotli: both decoders resolve custom word lists, custom transforms and context-dependent
dictionaries, cross-checked against Google's libbrotli built with `BROTLI_EXPERIMENTAL`. It
left three parts of RFC 9841 open:

- **Large-window brotli** (section 6): a 14-bit stream header (`0x11`, then the window bits
  in 6 bits) for windows up to 2^62 bytes, and a distance alphabet of up to `16 + NDIRECT +
  (124 << NPOSTFIX)` symbols. Our decoders refused the header (`Error::BadWindow`); the
  encoder's windows stopped at 2^24.
- **The framing format** (section 8): a container of resources (one data chunk or a run of
  partial ones), metadata, dictionary references between chunks (by pointer, or by hash code
  for dictionaries kept elsewhere), a central directory and a final footer.
- **The encoder searching custom word lists.** With a serialized dictionary that has custom
  static dictionaries, `compress_with_shared_dictionary` used the LZ77 prefix only and no static
  words at all (the built-in ones would decode as something else).

## Decision

1. **Large window, decoders.** `decompress_large_window(data, limit)` and
   `Decompressor::large_window(true)` accept the large-window header besides the regular ones;
   `decompress` and a default `Decompressor` still refuse it, as Google's decoder does without
   `BROTLI_DECODER_PARAM_LARGE_WINDOW` (such streams are not RFC 7932). As Google's decoder,
   the window is 2^10..2^30 (RFC 9841 allows decoders without 64-bit distances to stop there),
   the bit after `0x11` must be zero, a simple prefix code's distance symbols take the bits of
   the full alphabet (8 with `NPOSTFIX` = `NDIRECT` = 0), and a complex code's lengths are read
   for the symbols that cannot code a distance beyond 2^31 - 4 only
   (`BrotliCalculateDistanceCodeLimit`: 74 symbols for `NPOSTFIX` = `NDIRECT` = 0).
   `Decompressor::max_window_bits` now takes up to 30 and still bounds memory: 2^24 unless
   raised.
2. **Large window, encoder.** `compress_large_window(level, data)` picks the smallest window
   holding the input, up to 2^30; `Compressor::large_window(true)` with `window_bits` up to 30.
   The header is the large one whenever large window is on (whatever the window), so only
   large-window decoders decode the stream (Google's encoder writes the regular header for
   windows up to 2^24 and never uses large windows at qualities 0..2; ours does at every level).
   Distances up to 2^31 - 4 use symbols 64..73. The match finder's hash chains (levels 7..11)
   are capped at 2^25 positions: older links are overwritten, and a candidate found through one
   is checked like any other; the buckets of levels 0..6 reach the whole window. A meta-block
   of the optimal levels stays within 2^24 bytes.
3. **Custom word lists, encoder.** At levels 10 and 11, where the built-in static dictionary is
   searched, `compress_with_shared_dictionary` searches the dictionary's custom static
   dictionaries instead. Each dictionary of the serialized dictionary (a word list and a
   transform list, either possibly brotli's own) gets an index of all its words under all its
   transforms whose output has at least four bytes, keyed by those four bytes, built once per
   `SharedDictionary` on first use (at most 2^21 transformed words and 32 MiB per dictionary,
   transforms in list order), as Google's encoder builds a trie of them at its highest
   qualities. At a position the parse looks up the dictionary its literal context selects
   (addresses from 0) and the others after it in the decoder's order (each address offset by
   the words of the dictionaries before it; Google's encoder searches the first two), keeps the
   lowest address per output length and leaves out distances the distance alphabet cannot code.
   A context-dependent dictionary selects by the context mode written in the meta-block, so
   with one every literal block type uses UTF8 (as Google's encoder does for text).
4. **The framing format.** `read_container(data, limit, lookup)` reads a container and returns
   its resources (`Resource`: name and modification time from the `id` / `mt` metadata, data,
   the hash code if given, whether it is hidden, i.e. meant as a dictionary). Every rule is
   checked: signature and flags, chunk headers (types, codecs, dictionary reference flags,
   data chunk flags per type), metadata fields (two letters of one case, lower-case ones only
   where defined, `id` and `mt` at most once, nothing past the last field), chunk order (padding
   anywhere, a metadata chunk just before its resource's data, footer metadata just after it,
   runs of partial chunks, at most one central directory, the final footer last and only in a
   container that announces it), central directory copies of the chunk headers, the footer's
   size and pointer. Content is decoded by its codec: uncompressed, brotli (RFC 7932), shared
   brotli (large-window streams allowed, section 7) with the dictionaries it references, or the
   continuation of the previous chunk's stream ("keep decoder"; a stream that does not end
   in its chunk must continue in the next). Prefix dictionaries are concatenated in order with a
   serialized dictionary's own prefix in its place (Google's compound dictionary), at most 15.
   All decoded content counts against `limit`. `ContainerWriter` writes a container of several
   resources: a metadata chunk with the name, one data chunk each (brotli; shared brotli with an
   earlier resource as prefix dictionary by pointer, or with a serialized dictionary by hash
   code; stored if that is not smaller; hidden resources as dictionaries), a central directory
   and the final footer. New errors: `Error::BadContainer`, `Error::MissingDictionary`.
5. **Where RFC 9841 is unclear.** Section 8.1 (and 8.4.11) says container flag bit 2 set means
   several resources and a final footer; section 8.4.12 says the opposite: we follow 8.1. A
   pointer is taken as the offset of the chunk's first byte (its length varint); undefined
   container flag bits must be zero. The RFC names 256-bit HighwayHash for hash codes but no
   key (nor did its drafts), so a hash cannot be computed interoperably: hash codes are opaque
   32-byte values, resolved by the caller's `lookup` for dictionary references and kept, not
   checked, for data. No implementation of the framing format exists to test against.

## Consequences

- Large-window streams interoperate with Google's brotli both ways (its CLI's
  `--large_window`, built from source in Docker on gpu51 and Homebrew's 1.2.1): ours at levels
  0..11, one-shot and streamed, including distances past 64 MiB (symbols 64 and 65), decode with
  it; its output at qualities 1..11 and windows 2^24..2^30 decodes with ours. Regular streams
  decode as before; one-shot output is unchanged at every level.
- With custom word lists the encoder's output at level 11 is 7-11% smaller than before on
  alice29.txt's first 20,000 bytes (words 7,692 → 6,890 bytes, transforms 7,609 → 7,054,
  context 7,692 → 6,867) and within 0.4% of libbrotli's quality 11 on all of alice29.txt
  (46,332 / 46,591 / 45,896 against 46,188 / 46,396 / 45,933); libbrotli decodes it with every
  dictionary of the cross-check. The first use of a dictionary builds its index: 0.5 ms for
  1,600 words under 13 transforms, 4-5 ms under brotli's 121 (Apple M-series laptop).
- Containers are only checked against our own writer and hand-made ones; their hash codes mean
  whatever the producer meant. Not done: writing partial chunks, metadata other than names, and
  repeat metadata chunks (all are read); checking repeat metadata against the chunks it repeats.
- Fuzzing: `brotli_shared` round-trips the words of random dictionaries at levels 10 and 11;
  new target `brotli_container`.
