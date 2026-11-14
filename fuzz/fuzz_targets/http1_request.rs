#![no_main]

// The request head parser's own properties, then a differential check against httparse (a
// fuzz-only dependency): whatever only accepts, httparse accepts identically; whatever httparse
// accepts, only accepts too, except where only is deliberately stricter (non-ASCII bytes in the
// request target).

use only_ws::http1::{Header, Resume, Status, parse_request};

const MAX: usize = 100;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    only_http::fuzzing::http1_request(data);

    let mut ours_h = [Header::EMPTY; MAX];
    let ours = parse_request(data, &mut ours_h, &mut Resume::default());
    let mut theirs_h = [httparse::EMPTY_HEADER; MAX];
    let mut req = httparse::Request::new(&mut theirs_h);
    let theirs = req.parse(data);
    match (&ours, &theirs) {
        (Ok(Status::Complete(o)), Ok(httparse::Status::Complete(n))) => {
            assert_eq!(o.len, *n, "head length");
            assert_eq!(Some(o.method), req.method);
            assert_eq!(Some(o.target), req.path);
            assert_eq!(Some(o.minor), req.version);
            assert_eq!(o.headers.len(), req.headers.len());
            for (a, b) in o.headers.iter().zip(req.headers.iter()) {
                assert_eq!((a.name, a.value), (b.name, b.value));
            }
        }
        (Ok(Status::Complete(_)), t) => panic!("only accepted, httparse: {t:?}"),
        (o, Ok(httparse::Status::Complete(_))) => {
            let target = req.path.unwrap_or_default();
            assert!(
                !target.is_ascii(),
                "httparse accepted, only: {o:?} (target {target:?})"
            );
        }
        _ => {}
    }
});
