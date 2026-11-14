// arpc interop peer (fib's Go arpc) for only-arpc:
//
//	go run . server 127.0.0.1:9100     serves /echo, /fail and the /upper stream
//	go run . client 127.0.0.1:9101     calls a only server and checks the answers
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
