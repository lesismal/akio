#![no_main]

// The HPACK decoder's own properties, then a differential check against loona-hpack (a
// fuzz-only dependency): both decoders see the same blocks and must produce the same fields,
// except where only is deliberately stricter (a table size update after a field, which RFC 7541
// §4.2 forbids) or the decoders bound integers differently; and each side decodes what the
// other side's encoder produces from the decoded fields.

use only_http::hpack::{Decoder, DecoderError, Encoder};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    only_http::fuzzing::hpack(data);

    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let cut = usize::from(cut).min(rest.len());
    let mut ours = Decoder::new();
    let mut theirs = loona_hpack::Decoder::new();
    theirs.set_max_allowed_table_size(4096);
    let (mut our_enc, mut their_dec) = (Encoder::new(), loona_hpack::Decoder::new());
    let (mut their_enc, mut our_dec) = (loona_hpack::Encoder::new(), Decoder::new());
    for block in [&rest[..cut], &rest[cut..]] {
        let o = ours.decode(block);
        let t = theirs.decode(block);
        let list = match (o, t) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "decoded fields differ");
                a
            }
            (Err(DecoderError::SizeUpdateNotAtStart | DecoderError::IntegerOverflow), _) => return,
            (Ok(_), Err(loona_hpack::decoder::DecoderError::SizeUpdateAtEnd)) => return,
            (Ok(_), Err(loona_hpack::decoder::DecoderError::IntegerDecodingError(_))) => return,
            (Ok(a), Err(e)) => panic!("only decoded {a:?}, loona-hpack: {e:?}"),
            (Err(e), Ok(b)) => panic!("loona-hpack decoded {b:?}, only: {e:?}"),
            (Err(_), Err(_)) => return,
        };
        let fields = || list.iter().map(|(n, v)| (&n[..], &v[..]));
        let wire = our_enc.encode(fields());
        assert_eq!(their_dec.decode(&wire).expect("loona-hpack decodes only's encoding"), list);
        let wire = their_enc.encode(fields());
        assert_eq!(our_dec.decode(&wire).expect("only decodes loona-hpack's encoding"), list);
    }
});
