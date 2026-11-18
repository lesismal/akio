//! The protobuf conformance testee: reads length-prefixed (little-endian u32) `ConformanceRequest`s
//! from stdin and answers each with a `ConformanceResponse` on stdout, until EOF. Binary payloads
//! go through the generated message types, JSON through `only_protobuf::json` and text through
//! `only_protobuf::text` on the same types.
//!
//! Run by the conformance runner: `tools/protobuf-test/conformance/run.sh`.

use std::io::{self, Read, Write};

use only_protobuf::{
    Message,
    json::{self, ParseOptions, PrintOptions},
    reflect::ReflectMessage,
    text,
};
use protobuf_test::{
    conformance::{
        ConformanceRequest, ConformanceResponse, TestCategory, WireFormat,
        conformance_request::Payload, conformance_response::Result as R,
    },
    protobuf_test_messages::{editions, proto2, proto3},
};

/// Expanded `Any`s may name `TestAllTypesProto3` from any of the test messages (the C++ runtime
/// finds it in its global pool).
fn text_parse_options() -> text::ParseOptions {
    text::ParseOptions {
        type_pool: Some(proto3::descriptor_pool().clone()),
        ..Default::default()
    }
}

fn run<M: ReflectMessage>(req: &ConformanceRequest) -> R {
    let opts = ParseOptions {
        ignore_unknown_fields: req.test_category == TestCategory::JSON_IGNORE_UNKNOWN_PARSING_TEST,
        ..Default::default()
    };
    let m: M = match &req.payload {
        Some(Payload::ProtobufPayload(b)) => match M::decode(b) {
            Ok(m) => m,
            Err(e) => return R::ParseError(e.to_string()),
        },
        Some(Payload::JsonPayload(s)) => match json::from_str_with::<M>(s, &opts) {
            Ok(m) => m,
            Err(e) => return R::ParseError(e.to_string()),
        },
        Some(Payload::JspbPayload(_)) => return R::Skipped("JSPB is not supported".into()),
        Some(Payload::TextPayload(s)) => match text::from_str_with::<M>(s, &text_parse_options()) {
            Ok(m) => m,
            Err(e) => return R::ParseError(e.to_string()),
        },
        None => return R::RuntimeError("no payload".into()),
    };
    match req.requested_output_format {
        WireFormat::PROTOBUF => R::ProtobufPayload(m.encode_to_vec()),
        WireFormat::JSON => match json::to_string_with(&m, &PrintOptions::default()) {
            Ok(s) => R::JsonPayload(s),
            Err(e) => R::SerializeError(e.to_string()),
        },
        WireFormat::JSPB => R::Skipped("JSPB is not supported".into()),
        WireFormat::TEXT_FORMAT => {
            let opts = text::PrintOptions {
                print_unknown_fields: req.print_unknown_fields,
                type_pool: Some(proto3::descriptor_pool().clone()),
                ..Default::default()
            };
            match text::to_string_with(&m, &opts) {
                Ok(s) => R::TextPayload(s),
                Err(e) => R::SerializeError(e.to_string()),
            }
        }
        f => R::RuntimeError(format!("unknown output format {f:?}")),
    }
}

fn handle(req: &ConformanceRequest) -> R {
    match req.message_type.as_str() {
        "protobuf_test_messages.proto3.TestAllTypesProto3" => {
            run::<proto3::TestAllTypesProto3>(req)
        }
        "protobuf_test_messages.proto2.TestAllTypesProto2" => {
            run::<proto2::TestAllTypesProto2>(req)
        }
        "protobuf_test_messages.editions.TestAllTypesEdition2023" => {
            run::<editions::TestAllTypesEdition2023>(req)
        }
        "protobuf_test_messages.editions.proto2.TestAllTypesProto2" => {
            run::<editions::proto2::TestAllTypesProto2>(req)
        }
        "protobuf_test_messages.editions.proto3.TestAllTypesProto3" => {
            run::<editions::proto3::TestAllTypesProto3>(req)
        }
        "conformance.FailureSet" => run::<protobuf_test::conformance::FailureSet>(req),
        t => R::Skipped(format!("unknown message type {t}")),
    }
}

/// With `ONLY_CONFORMANCE_STATS=<file>`, counts of requests and skips per test category are
/// kept in that file (the runner may stop the testee without closing its input).
fn main() -> io::Result<()> {
    let stats = std::env::var_os("ONLY_CONFORMANCE_STATS");
    let mut counts: std::collections::BTreeMap<String, (u32, u32)> = Default::default();
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    loop {
        let mut len = [0u8; 4];
        match stdin.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let mut buf = vec![0; u32::from_le_bytes(len) as usize];
        stdin.read_exact(&mut buf)?;
        let result = match ConformanceRequest::decode(&buf) {
            Ok(req) => {
                let r = handle(&req);
                if let Some(path) = &stats {
                    let c = counts
                        .entry(format!("{:?}", req.test_category))
                        .or_default();
                    c.0 += 1;
                    c.1 += u32::from(matches!(r, R::Skipped(_)));
                    let text: String = counts
                        .iter()
                        .map(|(k, (n, s))| format!("{k}: {n} requests, {s} skipped\n"))
                        .collect();
                    let mut p = path.clone();
                    p.push(format!(".{}", std::process::id()));
                    std::fs::write(p, text)?;
                }
                r
            }
            Err(e) => R::RuntimeError(format!("bad request: {e}")),
        };
        let resp = ConformanceResponse {
            result: Some(result),
            ..Default::default()
        }
        .encode_to_vec();
        stdout.write_all(&(resp.len() as u32).to_le_bytes())?;
        stdout.write_all(&resp)?;
        stdout.flush()?;
    }
}
