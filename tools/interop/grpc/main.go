// gRPC interop peer (grpc-go) for only-grpc, with a pass-through bytes codec so no generated
// code is needed:
//
//	go run . server 127.0.0.1:9200
//	go run . client 127.0.0.1:9201
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error)      { return *(v.(*[]byte)), nil }
func (rawCodec) Unmarshal(b []byte, v any) error    { *(v.(*[]byte)) = append([]byte(nil), b...); return nil }
func (rawCodec) Name() string                        { return "proto" }

func init() { encoding.RegisterCodec(rawCodec{}) }

type svc interface{}

func unary(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	var in []byte
	if err := dec(&in); err != nil {
		return nil, err
	}
	if string(in) == "fail" {
		return nil, status.Error(codes.InvalidArgument, "go says no")
	}
	return &in, nil
}

func count(srv any, st grpc.ServerStream) error {
	var in []byte
	if err := st.RecvMsg(&in); err != nil {
		return err
	}
	n, _ := strconv.Atoi(string(in))
	for i := 0; i < n; i++ {
		b := []byte(strconv.Itoa(i))
		if err := st.SendMsg(&b); err != nil {
			return err
		}
	}
	return nil
}

func chat(srv any, st grpc.ServerStream) error {
	for {
		var in []byte
		if err := st.RecvMsg(&in); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		out := append([]byte("re:"), in...)
		if err := st.SendMsg(&out); err != nil {
			return err
		}
	}
}

var desc = grpc.ServiceDesc{
	ServiceName: "test.Echo",
	HandlerType: (*svc)(nil),
	Methods:     []grpc.MethodDesc{{MethodName: "Unary", Handler: unary}},
	Streams: []grpc.StreamDesc{
		{StreamName: "Count", Handler: count, ServerStreams: true},
		{StreamName: "Chat", Handler: chat, ServerStreams: true, ClientStreams: true},
	},
}

func fail(what string, args ...any) {
	fmt.Println("FAIL", what, fmt.Sprint(args...))
	os.Exit(1)
}

func main() {
	mode, addr := os.Args[1], os.Args[2]
	if mode == "server" {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			fail("listen", err)
		}
		s := grpc.NewServer()
		s.RegisterService(&desc, struct{}{})
		fmt.Println("ready")
		_ = s.Serve(l)
		return
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fail("dial", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	in, out := []byte("from go"), []byte(nil)
	if err := conn.Invoke(metadata.AppendToOutgoingContext(ctx, "x-user", "gopher"), "/test.Echo/Unary", &in, &out); err != nil || string(out) != "from go" {
		fail("unary", err, string(out))
	}
	big := make([]byte, 3<<20)
	if err := conn.Invoke(ctx, "/test.Echo/Unary", &big, &out); err != nil || len(out) != len(big) {
		fail("big unary", err)
	}
	bad := []byte("fail")
	err = conn.Invoke(ctx, "/test.Echo/Fail", &bad, &out)
	if status.Code(err) != codes.InvalidArgument {
		fail("error status", err)
	}
	if err := conn.Invoke(ctx, "/test.Echo/Nope", &in, &out); status.Code(err) != codes.Unimplemented {
		fail("unimplemented", err)
	}
	st, err := conn.NewStream(ctx, &desc.Streams[0], "/test.Echo/Count")
	if err != nil {
		fail("count stream", err)
	}
	n := []byte("50")
	_ = st.SendMsg(&n)
	_ = st.CloseSend()
	got := 0
	for {
		var m []byte
		if err := st.RecvMsg(&m); err == io.EOF {
			break
		} else if err != nil {
			fail("count recv", err)
		}
		got++
	}
	if got != 50 {
		fail("count", got)
	}
	bs, err := conn.NewStream(ctx, &desc.Streams[1], "/test.Echo/Chat")
	if err != nil {
		fail("chat", err)
	}
	for _, w := range []string{"x", "y"} {
		b := []byte(w)
		_ = bs.SendMsg(&b)
		var m []byte
		if err := bs.RecvMsg(&m); err != nil || string(m) != "re:"+w {
			fail("chat recv", err, string(m))
		}
	}
	_ = bs.CloseSend()
	fmt.Println("OK")
}
