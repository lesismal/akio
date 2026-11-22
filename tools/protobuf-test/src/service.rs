//! The route_guide and helloworld services as the tests and the grpc-go interop peer
//! (`tools/interop/grpc/main.go`) implement them, plus the client-side checks both run.

use akio_grpc::{CallOptions, Code, Metadata, Sink, Status};
use akio_protobuf::well_known;

use crate::{
    helloworld::{
        HelloReply, HelloRequest, greeter_client::GreeterClient, greeter_server::Greeter,
    },
    routeguide::{
        Feature, Point, Rectangle, RouteNote, RouteSummary, route_guide_client::RouteGuideClient,
        route_guide_server::RouteGuide,
    },
};

/// The feature at `p`.
pub fn feature_at(p: &Point) -> Feature {
    Feature {
        name: format!("feature {},{}", p.latitude, p.longitude),
        location: Some(p.clone()),
        ..Default::default()
    }
}

/// The summary of a route: points, points with an even coordinate sum, Manhattan length.
pub fn summarize(points: &[Point]) -> RouteSummary {
    let distance = points
        .windows(2)
        .map(|w| (w[1].latitude - w[0].latitude).abs() + (w[1].longitude - w[0].longitude).abs())
        .sum();
    RouteSummary {
        point_count: points.len() as i32,
        feature_count: points
            .iter()
            .filter(|p| (p.latitude + p.longitude) % 2 == 0)
            .count() as i32,
        distance,
        elapsed_time: 7,
        ..Default::default()
    }
}

/// The server side.
#[derive(Debug, Default)]
pub struct Impl;

impl crate::test::ext::ext_server::Ext for Impl {
    fn echo(
        &self,
        _md: &Metadata,
        request: crate::test::ext::Base,
    ) -> Result<crate::test::ext::Base, Status> {
        Ok(request)
    }
}

impl crate::test::ed::items_server::Items for Impl {
    fn get(
        &self,
        _md: &Metadata,
        request: crate::test::ed::Item,
    ) -> Result<crate::test::ed::Item, Status> {
        Ok(request)
    }
}

// ANCHOR: server
impl RouteGuide for Impl {
    fn get_feature(&self, _md: &Metadata, request: Point) -> Result<Feature, Status> {
        if request.latitude == i32::MIN {
            return Err(Status::new(Code::InvalidArgument, "no such place"));
        }
        Ok(feature_at(&request))
    }

    fn list_features(&self, _md: &Metadata, request: Rectangle, sink: Sink) {
        let (lo, hi) = (
            request.lo.unwrap_or_default(),
            request.hi.unwrap_or_default(),
        );
        for lat in lo.latitude..=hi.latitude {
            for lng in lo.longitude..=hi.longitude {
                sink.send_message(&feature_at(&Point {
                    latitude: lat,
                    longitude: lng,
                    ..Default::default()
                }));
            }
        }
        sink.finish(Status::ok());
    }

    fn record_route(&self, _md: &Metadata, requests: Vec<Point>) -> Result<RouteSummary, Status> {
        Ok(summarize(&requests))
    }

    fn route_chat(&self, _md: &Metadata, sink: Sink) -> Box<dyn FnMut(Option<RouteNote>) + Send> {
        Box::new(move |note| match note {
            Some(n) => {
                sink.send_message(&RouteNote {
                    location: n.location,
                    message: format!("re: {}", n.message),
                    ..Default::default()
                });
            }
            None => sink.finish(Status::ok()),
        })
    }
}
// ANCHOR_END: server

impl Greeter for Impl {
    fn say_hello(&self, md: &Metadata, request: HelloRequest) -> Result<HelloReply, Status> {
        let from = md
            .get("x-user")
            .map_or_else(String::new, |u| format!(" (from {u})"));
        Ok(HelloReply {
            message: format!("Hello {}{from}", request.name),
            ..Default::default()
        })
    }
}

/// `/test.Echo/Struct`: the request `Struct` with a `server` field added.
pub fn echo_struct(mut s: well_known::Struct, server: &str) -> well_known::Struct {
    s.fields.insert(
        "server".into(),
        well_known::Value {
            kind: Some(well_known::value::Kind::StringValue(server.into())),
        },
    );
    s
}

/// `/test.Echo/Any`: an `Any` holding a `Timestamp` becomes one holding the `Duration` with the
/// same seconds and nanos.
pub fn echo_any(a: &well_known::Any) -> Result<well_known::Any, Status> {
    let ts = a
        .unpack::<well_known::Timestamp>()
        .map_err(|e| Status::new(Code::InvalidArgument, e.to_string()))?
        .ok_or_else(|| {
            Status::new(
                Code::InvalidArgument,
                format!("not a Timestamp: {}", a.type_url),
            )
        })?;
    Ok(well_known::Any::pack(&well_known::Duration {
        seconds: ts.seconds,
        nanos: ts.nanos,
    }))
}

/// A `Struct` with every kind of `Value` (null, number, string, bool, nested struct, list).
pub fn sample_struct() -> well_known::Struct {
    use well_known::{ListValue, NullValue, Struct, Value, value::Kind};
    let v = |k| Value { kind: Some(k) };
    Struct {
        fields: [
            (
                "null".to_string(),
                v(Kind::NullValue(NullValue::NULL_VALUE)),
            ),
            ("pi".to_string(), v(Kind::NumberValue(3.25))),
            ("name".to_string(), v(Kind::StringValue("ünïcode".into()))),
            ("yes".to_string(), v(Kind::BoolValue(true))),
            (
                "obj".to_string(),
                v(Kind::StructValue(Struct {
                    fields: [("n".to_string(), v(Kind::NumberValue(-1.0)))].into(),
                })),
            ),
            (
                "list".to_string(),
                v(Kind::ListValue(ListValue {
                    values: vec![
                        v(Kind::BoolValue(false)),
                        v(Kind::StringValue(String::new())),
                    ],
                })),
            ),
        ]
        .into(),
    }
}

fn opts() -> CallOptions {
    let mut o = CallOptions::default();
    o.timeout = Some(std::time::Duration::from_secs(10));
    o
}

fn fail(what: &str, detail: impl std::fmt::Debug) -> String {
    format!("{what}: {detail:?}")
}

/// Runs every call against a server implementing the services above (an `akio` one or the
/// grpc-go peer); `server` is the name the server puts in `echo_struct`.
pub fn check_server(grpc: &akio_grpc::GrpcClient, server: &str) -> Result<(), String> {
    let rg = RouteGuideClient::new(grpc.clone());
    // Unary, with an unknown field the server must keep in the returned location.
    let mut p = Point {
        latitude: 409_146_138,
        longitude: -746_188_906,
        ..Default::default()
    };
    let mut with_unknown = Vec::new();
    akio_protobuf::Message::encode(&p, &mut with_unknown);
    with_unknown.extend_from_slice(&[0x98, 0x06, 0xd2, 0x09]); // field 99 = 1234
    p = akio_protobuf::Message::decode(&with_unknown).map_err(|e| fail("decode", e))?;
    let f = rg
        .get_feature(&p, opts())
        .map_err(|e| fail("GetFeature", e))?;
    if f != feature_at(&p) {
        return Err(fail("GetFeature reply", f));
    }
    if f.location.as_ref().map(|l| l.unknown_fields.as_bytes())
        != Some(&[0x98, 0x06, 0xd2, 0x09][..])
    {
        return Err(fail("unknown field not echoed", f.location));
    }
    let nowhere = Point {
        latitude: i32::MIN,
        ..Default::default()
    };
    match rg.get_feature(&nowhere, opts()) {
        Err(e) if e.code == Code::InvalidArgument => {}
        other => return Err(fail("GetFeature error", other)),
    }
    // Server streaming.
    let rect = Rectangle {
        lo: Some(Point::default()),
        hi: Some(Point {
            latitude: 2,
            longitude: 1,
            ..Default::default()
        }),
        ..Default::default()
    };
    let fs = rg
        .list_features(&rect, opts())
        .map_err(|e| fail("ListFeatures", e))?;
    if fs.len() != 6 || fs[5].name != "feature 2,1" {
        return Err(fail("ListFeatures reply", fs));
    }
    // Client streaming.
    let pts: Vec<Point> = (0..10)
        .map(|i| Point {
            latitude: i,
            longitude: i * 2,
            ..Default::default()
        })
        .collect();
    let s = rg
        .record_route(&pts, opts())
        .map_err(|e| fail("RecordRoute", e))?;
    if s != summarize(&pts) {
        return Err(fail("RecordRoute reply", s));
    }
    // Bidirectional.
    let (tx, rx) = std::sync::mpsc::channel();
    let tx2 = tx.clone();
    let sink = rg.route_chat(
        opts(),
        move |n| {
            let _ = tx.send(Ok(n));
        },
        move |st, _| {
            let _ = tx2.send(Err(st));
        },
    );
    for (i, m) in ["a", "b", "c"].iter().enumerate() {
        sink.send_message(&RouteNote {
            location: Some(Point {
                latitude: i as i32,
                ..Default::default()
            }),
            message: (*m).to_string(),
            ..Default::default()
        });
    }
    sink.close_send();
    let mut notes = Vec::new();
    loop {
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(n)) => notes.push(n),
            Ok(Err(st)) if st.code == Code::Ok => break,
            other => return Err(fail("RouteChat", other)),
        }
    }
    let msgs: Vec<&str> = notes.iter().map(|n| n.message.as_str()).collect();
    if msgs != ["re: a", "re: b", "re: c"]
        || notes[2].location.as_ref().map(|l| l.latitude) != Some(2)
    {
        return Err(fail("RouteChat replies", notes));
    }
    // helloworld, with metadata.
    let g = GreeterClient::new(grpc.clone());
    let mut o = opts();
    o.metadata = vec![("x-user".into(), "ada".into())];
    let r = g
        .say_hello(
            &HelloRequest {
                name: "world".into(),
                ..Default::default()
            },
            o,
        )
        .map_err(|e| fail("SayHello", e))?;
    if r.message != "Hello world (from ada)" {
        return Err(fail("SayHello reply", r));
    }
    // Well-known types through raw methods.
    let st = sample_struct();
    let b = grpc
        .unary(
            "/test.Echo/Struct",
            &akio_protobuf::Message::encode_to_vec(&st),
            opts(),
        )
        .map_err(|e| fail("Struct", e))?;
    let back: well_known::Struct =
        akio_protobuf::Message::decode(&b).map_err(|e| fail("Struct decode", e))?;
    if back != echo_struct(st, server) {
        return Err(fail("Struct reply", back));
    }
    let ts = well_known::Timestamp {
        seconds: 1_700_000_000,
        nanos: 123,
    };
    let b = grpc
        .unary(
            "/test.Echo/Any",
            &akio_protobuf::Message::encode_to_vec(&well_known::Any::pack(&ts)),
            opts(),
        )
        .map_err(|e| fail("Any", e))?;
    let any: well_known::Any =
        akio_protobuf::Message::decode(&b).map_err(|e| fail("Any decode", e))?;
    let d = any
        .unpack::<well_known::Duration>()
        .map_err(|e| fail("Any unpack", e))?;
    if d != Some(well_known::Duration {
        seconds: 1_700_000_000,
        nanos: 123,
    }) {
        return Err(fail("Any reply", any));
    }
    Ok(())
}

/// A `GrpcServer` with route_guide, helloworld and the well-known-type echo methods.
pub fn server(name: &'static str) -> akio_grpc::GrpcServer {
    // ANCHOR: register
    let s = crate::routeguide::route_guide_server::register(akio_grpc::GrpcServer::new(), Impl);
    let s = crate::helloworld::greeter_server::register(s, Impl);
    // ANCHOR_END: register
    // ANCHOR: reflection
    // Server reflection (grpcurl, grpcui): the descriptors of both packages in one pool.
    let mut pool = crate::routeguide::descriptor_pool().clone();
    pool.add_file_descriptor_set(crate::helloworld::FILE_DESCRIPTOR_SET)
        .expect("descriptors");
    // ANCHOR_END: reflection
    // proto2 groups and extensions, edition 2024, proto3 test messages (with the WKTs).
    for set in [
        crate::test::ext::FILE_DESCRIPTOR_SET,
        crate::test::ed::FILE_DESCRIPTOR_SET,
        crate::protobuf_test_messages::proto3::FILE_DESCRIPTOR_SET,
    ] {
        pool.add_file_descriptor_set(set).expect("descriptors");
    }
    let s = crate::test::ext::ext_server::register(s, Impl);
    let s = crate::test::ed::items_server::register(s, Impl);
    // ANCHOR: reflection_register
    let s = akio_grpc::reflection::register(s, &pool);
    // ANCHOR_END: reflection_register
    s.unary("/test.Echo/Struct", move |_md, req, sink| {
        match <well_known::Struct as akio_protobuf::Message>::decode(&req) {
            Ok(st) => {
                sink.send(&akio_protobuf::Message::encode_to_vec(&echo_struct(
                    st, name,
                )));
                sink.finish(Status::ok());
            }
            Err(e) => sink.finish(Status::new(Code::InvalidArgument, e.to_string())),
        }
    })
    .unary("/test.Echo/Any", |_md, req, sink| {
        let r = <well_known::Any as akio_protobuf::Message>::decode(&req)
            .map_err(|e| Status::new(Code::InvalidArgument, e.to_string()))
            .and_then(|a| echo_any(&a));
        match r {
            Ok(a) => {
                sink.send(&akio_protobuf::Message::encode_to_vec(&a));
                sink.finish(Status::ok());
            }
            Err(st) => sink.finish(st),
        }
    })
}
