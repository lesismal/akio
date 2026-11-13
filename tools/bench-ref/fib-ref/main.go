// fib reference server for docs/BENCHMARKS.md:
//
//	fib-ref <tcp|udp> <addr> [echo|block [ms]]
//
// fib runs handler callbacks on its worker pool, so `block` sleeps inside OnData.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	fib "github.com/lesismal/fib"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: fib-ref <tcp|udp> <addr> [echo|block [ms]]")
		os.Exit(2)
	}
	proto, addr := os.Args[1], os.Args[2]
	mode := "echo"
	if len(os.Args) > 3 {
		mode = os.Args[3]
	}
	ms := 5
	if len(os.Args) > 4 {
		ms, _ = strconv.Atoi(os.Args[4])
	}
	h := fib.HandlerFuncs{
		Data: func(c *fib.Connection, b []byte) {
			if mode == "block" {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
			if c.Send(append([]byte(nil), b...)) != nil {
				c.Close()
			}
		},
	}
	cfg := fib.DefaultConfig()
	cfg.Name = "bench"
	cfg.Network = proto
	e, err := fib.New(cfg, fib.Binding{Network: proto, Addr: addr, Handler: h})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := e.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
