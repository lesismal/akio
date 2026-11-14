#![no_main]

// The HTTP/1 client's response handling, then a differential check of the response head parser
// against httparse (a fuzz-only dependency) on `data[2..]` (the response bytes): both accept
// the same heads, with the same results.

use only_ws::http1::{Header, Resume, Status, parse_response};

const MAX: usize = 100;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    only_http::fuzzing::http1_client(data);

    let wire = data.get(2..).unwrap_or_default();
    let mut ours_h = [Header::EMPTY; MAX];
    let ours = parse_response(wire, &mut ours_h, &mut Resume::default());
    let mut theirs_h = [httparse::EMPTY_HEADER; MAX];
    let mut resp = httparse::Response::new(&mut theirs_h);
    let theirs = resp.parse(wire);
    match (&ours, &theirs) {
        (Ok(Status::Complete(o)), Ok(httparse::Status::Complete(n))) => {
            assert_eq!(o.len, *n, "head length");
            assert_eq!(Some(o.minor), resp.version);
            assert_eq!(Some(o.code), resp.code);
            assert_eq!(Some(o.reason), resp.reason);
            assert_eq!(o.headers.len(), resp.headers.len());
            for (a, b) in o.headers.iter().zip(resp.headers.iter()) {
                assert_eq!((a.name, a.value), (b.name, b.value));
            }
        }
        (Ok(Status::Complete(_)), t) => panic!("only accepted, httparse: {t:?}"),
        (o, Ok(httparse::Status::Complete(_))) => panic!("httparse accepted, only: {o:?}"),
        _ => {}
    }
});
