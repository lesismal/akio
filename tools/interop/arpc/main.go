// arpc interop peer (fib's Go arpc) for akio-arpc:
//
//	go run . server 127.0.0.1:9100        serves /echo, /fail and the /upper stream
//	go run . client 127.0.0.1:9101        calls a akio server and checks the answers
//	go run . server-coded 127.0.0.1:9102  the same with the gzip and trace-value coders and a
//	                                      middleware that refuses calls without a trace value
//	go run . client-coded 127.0.0.1:9103  checks a coded akio server, from a ClientPool too
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	fib "github.com/lesismal/fib"
	"github.com/lesismal/fib/arpc"
)

func main() {
	mode, addr := os.Args[1], os.Args[2]
	switch mode {
	case "server-coded":
		serveCoded(addr)
		return
	case "client-coded":
		clientCoded(addr)
		return
	}
	if mode == "server" {
		s := arpc.NewServer()
		s.Handler.Handle("/echo", func(ctx *arpc.Context) { _ = ctx.Write(ctx.Body()) })
		s.Handler.Handle("/fail", func(ctx *arpc.Context) { _ = ctx.Error("go failed") })
		s.Handler.HandleStream("/upper", func(st *arpc.Stream) {
			for {
				var b []byte
				if err := st.Recv(&b); err != nil {
					st.CloseSend()
					return
				}
				_ = st.Send([]byte(strings.ToUpper(string(b))))
			}
		})
		fmt.Println("ready")
		if err := s.Run(addr); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}
	engine, err := fib.New(fib.DefaultConfig())
	if err != nil {
		fmt.Println("engine:", err)
		os.Exit(1)
	}
	go func() { _ = engine.Run() }()
	c, err := arpc.Dial(engine, "tcp", addr, 3*time.Second, nil)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer c.Stop()
	var out []byte
	check := func(ok bool, what string) {
		if !ok {
			fmt.Println("FAIL", what)
			os.Exit(1)
		}
	}
	err = c.Call("/echo", []byte("from go"), &out, time.Second)
	check(err == nil && string(out) == "from go", fmt.Sprint("echo ", err, string(out)))
	big := []byte(strings.Repeat("z", 1<<20))
	err = c.Call("/echo", big, &out, 5*time.Second)
	check(err == nil && len(out) == len(big), "big echo")
	err = c.Call("/fail", nil, &out, time.Second)
	check(err != nil && err.Error() == "rust failed", fmt.Sprint("error ", err))
	err = c.Call("/missing", nil, &out, time.Second)
	check(err != nil && err.Error() == "method not found", fmt.Sprint("missing ", err))
	check(c.Notify("/note", []byte("note from go"), time.Second) == nil, "notify")
	st := c.NewStream("/upper")
	for _, w := range []string{"one", "two"} {
		check(st.Send([]byte(w)) == nil, "stream send")
		var b []byte
		check(st.Recv(&b) == nil && string(b) == strings.ToUpper(w), "stream recv")
	}
	st.CloseSend()
	fmt.Println("OK")
}

func check(ok bool, what string) {
	if !ok {
		fmt.Println("FAIL", what)
		os.Exit(1)
	}
}

func serveCoded(addr string) {
	s := arpc.NewServer()
	g := useCoders(s.Handler)
	// Registered before the handlers: runs before each of them. A request without the
	// trace value the appender carries is refused and the chain aborted.
	s.Handler.Use(func(ctx *arpc.Context) {
		if _, ok := ctx.Get("trace"); !ok && ctx.Message.Cmd() == arpc.CmdRequest {
			_ = ctx.Error("no trace")
			ctx.Abort()
		}
	})
	s.Handler.Handle("/echo", func(ctx *arpc.Context) {
		v, _ := ctx.Get("trace")
		ctx.Set("trace", "answered by go")
		_ = ctx.Write(append([]byte(v.(string)+"|"), ctx.Body()...))
	})
	s.Handler.Handle("/gzipped", func(ctx *arpc.Context) {
		_ = ctx.Write(fmt.Sprint(g.decoded.Load()))
	})
	s.Handler.HandleStream("/upper", func(st *arpc.Stream) {
		for {
			var b []byte
			if err := st.Recv(&b); err != nil {
				st.CloseSend()
				return
			}
			_ = st.Send([]byte(strings.ToUpper(string(b))))
		}
	})
	fmt.Println("ready")
	if err := s.Run(addr); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func clientCoded(addr string) {
	engine, err := fib.New(fib.DefaultConfig())
	if err != nil {
		fmt.Println("engine:", err)
		os.Exit(1)
	}
	go func() { _ = engine.Run() }()
	h := arpc.NewHandler()
	g := useCoders(h)
	pool, err := arpc.NewClientPool(arpc.TCPDialer(engine, "tcp", addr, 3*time.Second), 3, h)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer pool.Stop()
	trace := map[any]any{"trace": "from go"}
	for i := 0; i < 6; i++ {
		c := pool.Next()
		var out []byte
		err = c.Call("/echo", []byte("x"), &out, time.Second, trace)
		check(err == nil && string(out) == "from go|x", fmt.Sprint("coded echo ", err, string(out)))
		big := []byte(strings.Repeat("z", 1<<20))
		err = c.Call("/echo", big, &out, 5*time.Second, trace)
		check(err == nil && string(out) == "from go|"+string(big), fmt.Sprint("coded big echo ", err, len(out)))
		// The only side's middleware refuses calls without the value.
		err = c.Call("/echo", []byte("x"), &out, time.Second)
		check(err != nil && err.Error() == "no trace", fmt.Sprint("no trace ", err))
	}
	// The value the only handler set comes back with the answer.
	done := make(chan string, 1)
	err = pool.Next().CallAsync("/echo", []byte("a"), func(ctx *arpc.Context, err error) {
		v, _ := ctx.Get("trace")
		s, _ := v.(string)
		done <- fmt.Sprint(err, " ", s)
	}, time.Second, trace)
	check(err == nil, "call async")
	got := <-done
	check(got == "<nil> answered by only", "answer value "+got)
	c := pool.Next()
	check(c.Notify("/note", []byte(strings.Repeat("note from go ", 100)), time.Second, trace) == nil, "notify")
	st := c.NewStream("/upper")
	w := strings.Repeat("one", 200)
	check(st.Send([]byte(w)) == nil, "stream send")
	var b []byte
	check(st.Recv(&b) == nil && string(b) == strings.ToUpper(w), "stream recv")
	st.CloseSend()
	// Both sides really compressed: the akio server counts the frames it inflated.
	var n []byte
	check(c.Call("/gzipped", nil, &n, time.Second, trace) == nil, "gzipped")
	check(string(n) != "0", "only inflated nothing")
	check(g.decoded.Load() > 0, "go inflated nothing")
	fmt.Println("OK coded, only inflated", string(n), "go inflated", g.decoded.Load())
}
