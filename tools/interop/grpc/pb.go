// The protobuf half of the interop check: grpc-go's generated route_guide and helloworld code
// and the well-known types of google.golang.org/protobuf, against akio-protobuf messages and
// the stubs akio-protobuf-build generates (tools/protobuf-test, `pb-interop`). The semantics
// mirror tools/protobuf-test/src/service.rs.
package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"time"

	hw "google.golang.org/grpc/examples/helloworld/helloworld"
	rg "google.golang.org/grpc/examples/route_guide/routeguide"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func featureAt(p *rg.Point) *rg.Feature {
	return &rg.Feature{Name: fmt.Sprintf("feature %d,%d", p.GetLatitude(), p.GetLongitude()), Location: p}
}

func summarize(pts []*rg.Point) *rg.RouteSummary {
	abs := func(v int32) int32 {
		if v < 0 {
			return -v
		}
		return v
	}
	s := &rg.RouteSummary{PointCount: int32(len(pts)), ElapsedTime: 7}
	for i, p := range pts {
		if (p.Latitude+p.Longitude)%2 == 0 {
			s.FeatureCount++
		}
		if i > 0 {
			s.Distance += abs(p.Latitude-pts[i-1].Latitude) + abs(p.Longitude-pts[i-1].Longitude)
		}
	}
	return s
}

type routeGuide struct {
	rg.UnimplementedRouteGuideServer
}

func (routeGuide) GetFeature(_ context.Context, p *rg.Point) (*rg.Feature, error) {
	if p.Latitude == math.MinInt32 {
		return nil, status.Error(codes.InvalidArgument, "no such place")
	}
	return featureAt(p), nil
}

func (routeGuide) ListFeatures(r *rg.Rectangle, s grpc.ServerStreamingServer[rg.Feature]) error {
	for lat := r.GetLo().GetLatitude(); lat <= r.GetHi().GetLatitude(); lat++ {
		for lng := r.GetLo().GetLongitude(); lng <= r.GetHi().GetLongitude(); lng++ {
			if err := s.Send(featureAt(&rg.Point{Latitude: lat, Longitude: lng})); err != nil {
				return err
			}
		}
	}
	return nil
}

func (routeGuide) RecordRoute(s grpc.ClientStreamingServer[rg.Point, rg.RouteSummary]) error {
	var pts []*rg.Point
	for {
		p, err := s.Recv()
		if err == io.EOF {
			return s.SendAndClose(summarize(pts))
		}
		if err != nil {
			return err
		}
		pts = append(pts, p)
	}
}

func (routeGuide) RouteChat(s grpc.BidiStreamingServer[rg.RouteNote, rg.RouteNote]) error {
	for {
		n, err := s.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.Send(&rg.RouteNote{Location: n.Location, Message: "re: " + n.Message}); err != nil {
			return err
		}
	}
}

type greeter struct{ hw.UnimplementedGreeterServer }

func (greeter) SayHello(ctx context.Context, r *hw.HelloRequest) (*hw.HelloReply, error) {
	from := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get("x-user")) > 0 {
		from = " (from " + md.Get("x-user")[0] + ")"
	}
	return &hw.HelloReply{Message: "Hello " + r.GetName() + from}, nil
}

func echoStruct(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	in.Fields["server"] = structpb.NewStringValue("go")
	return in, nil
}

func echoAny(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	in := &anypb.Any{}
	if err := dec(in); err != nil {
		return nil, err
	}
	ts := &timestamppb.Timestamp{}
	if err := in.UnmarshalTo(ts); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return anypb.New(&durationpb.Duration{Seconds: ts.Seconds, Nanos: ts.Nanos})
}

func registerPB(s *grpc.Server) {
	rg.RegisterRouteGuideServer(s, routeGuide{})
	hw.RegisterGreeterServer(s, greeter{})
}

func sampleStruct() *structpb.Struct {
	s, err := structpb.NewStruct(map[string]any{
		"null": nil,
		"pi":   3.25,
		"name": "ünïcode",
		"yes":  true,
		"obj":  map[string]any{"n": -1.0},
		"list": []any{false, ""},
	})
	if err != nil {
		fail("struct", err)
	}
	return s
}

// pbClient runs the checks of service.rs `check_server` against an akio-protobuf server.
func pbClient(addr string) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fail("dial", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := rg.NewRouteGuideClient(conn)

	// Unary, with an unknown field the server must keep (field 99 = 1234).
	unknown := protoreflect.RawFields{0x98, 0x06, 0xd2, 0x09}
	p := &rg.Point{Latitude: 409146138, Longitude: -746188906}
	p.ProtoReflect().SetUnknown(unknown)
	f, err := c.GetFeature(ctx, p)
	if err != nil || f.GetName() != "feature 409146138,-746188906" || f.GetLocation().GetLongitude() != -746188906 {
		fail("GetFeature", err, f)
	}
	if string(f.GetLocation().ProtoReflect().GetUnknown()) != string(unknown) {
		fail("unknown field not echoed", f.GetLocation().ProtoReflect().GetUnknown())
	}
	if _, err := c.GetFeature(ctx, &rg.Point{Latitude: math.MinInt32}); status.Code(err) != codes.InvalidArgument {
		fail("GetFeature error", err)
	}

	// Server streaming.
	ls, err := c.ListFeatures(ctx, &rg.Rectangle{Lo: &rg.Point{}, Hi: &rg.Point{Latitude: 2, Longitude: 1}})
	if err != nil {
		fail("ListFeatures", err)
	}
	var names []string
	for {
		f, err := ls.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail("ListFeatures recv", err)
		}
		names = append(names, f.GetName())
	}
	if len(names) != 6 || names[5] != "feature 2,1" {
		fail("ListFeatures reply", names)
	}

	// Client streaming.
	rs, err := c.RecordRoute(ctx)
	if err != nil {
		fail("RecordRoute", err)
	}
	var pts []*rg.Point
	for i := int32(0); i < 10; i++ {
		pt := &rg.Point{Latitude: i, Longitude: i * 2}
		pts = append(pts, pt)
		if err := rs.Send(pt); err != nil {
			fail("RecordRoute send", err)
		}
	}
	sum, err := rs.CloseAndRecv()
	if err != nil || !proto.Equal(sum, summarize(pts)) {
		fail("RecordRoute reply", err, sum)
	}

	// Bidirectional.
	chat, err := c.RouteChat(ctx)
	if err != nil {
		fail("RouteChat", err)
	}
	for i, m := range []string{"a", "b", "c"} {
		if err := chat.Send(&rg.RouteNote{Location: &rg.Point{Latitude: int32(i)}, Message: m}); err != nil {
			fail("RouteChat send", err)
		}
		n, err := chat.Recv()
		if err != nil || n.GetMessage() != "re: "+m || n.GetLocation().GetLatitude() != int32(i) {
			fail("RouteChat recv", err, n)
		}
	}
	_ = chat.CloseSend()
	if _, err := chat.Recv(); err != io.EOF {
		fail("RouteChat end", err)
	}

	// helloworld, with metadata.
	r, err := hw.NewGreeterClient(conn).SayHello(metadata.AppendToOutgoingContext(ctx, "x-user", "ada"), &hw.HelloRequest{Name: "world"})
	if err != nil || r.GetMessage() != "Hello world (from ada)" {
		fail("SayHello", err, r)
	}

	// Well-known types.
	in, out := sampleStruct(), &structpb.Struct{}
	if err := conn.Invoke(ctx, "/test.Echo/Struct", in, out); err != nil {
		fail("Struct", err)
	}
	want := proto.Clone(in).(*structpb.Struct)
	want.Fields["server"] = structpb.NewStringValue("akio")
	if !proto.Equal(out, want) {
		fail("Struct reply", out)
	}
	a, _ := anypb.New(&timestamppb.Timestamp{Seconds: 1700000000, Nanos: 123})
	back := &anypb.Any{}
	if err := conn.Invoke(ctx, "/test.Echo/Any", a, back); err != nil {
		fail("Any", err)
	}
	d := &durationpb.Duration{}
	if err := back.UnmarshalTo(d); err != nil || d.Seconds != 1700000000 || d.Nanos != 123 {
		fail("Any reply", err, d)
	}
	fmt.Println("OK")
}
