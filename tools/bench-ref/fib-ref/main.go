// fib reference server for docs/BENCHMARKS.md:
//
//	fib-ref <tcp|udp|tls> <addr> [echo|block [ms]]
//	fib-ref <http|ws> <addr>
//
// fib runs handler callbacks on its worker pool, so `block` sleeps inside OnData.
// `tls` is the echo handler behind fib/tls (ECDSA P-256 self-signed certificate, TLS 1.3).
// `http` serves GET /plaintext and GET /json (HTTP/1.1 and h2c), `ws` a WebSocket echo.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	stdhttp "net/http"
	"os"
	"strconv"
	"time"

	fib "github.com/lesismal/fib"
	fibhttp "github.com/lesismal/fib/http"
	fibtls "github.com/lesismal/fib/tls"
	"github.com/lesismal/fib/websocket"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: fib-ref <tcp|udp|tls|http|ws> <addr> [echo|block [ms]]")
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
	var h fib.Handler = fib.HandlerFuncs{
		Data: func(c *fib.Connection, b []byte) {
			if mode == "block" {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
			if c.Send(append([]byte(nil), b...)) != nil {
				c.Close()
			}
		},
	}
	network := proto
	switch proto {
	case "tls":
		network = "tcp"
		h = fibtls.NewServer(&tls.Config{
			Certificates: []tls.Certificate{makeCertificate()},
			MinVersion:   tls.VersionTLS13,
		}, h)
	case "http":
		network = "tcp"
		h = fibhttp.NewHandler(fibhttp.HandlerFunc(serveHTTP))
	case "ws":
		network = "tcp"
		cfg := websocket.DefaultConfig()
		cfg.CheckOrigin = nil
		h = websocket.NewHandlerWithConfig(cfg, websocket.HandlerFuncs{
			Message: func(c *websocket.Connection, op websocket.Opcode, b []byte) {
				_ = c.WriteMessage(op, b)
			},
		})
	}
	cfg := fib.DefaultConfig()
	cfg.Name = "bench"
	cfg.Network = network
	e, err := fib.New(cfg, fib.Binding{Network: network, Addr: addr, Handler: h})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := e.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type message struct {
	Message string `json:"message"`
}

func serveHTTP(c *fibhttp.Context) {
	switch c.Request.URL.Path {
	case "/plaintext":
		_ = c.Respond(stdhttp.StatusOK, "text/plain; charset=utf-8", []byte("Hello, World!"))
	case "/json":
		b, _ := json.Marshal(message{Message: "Hello, World!"})
		_ = c.Respond(stdhttp.StatusOK, "application/json", b)
	default:
		_ = c.Respond(stdhttp.StatusNotFound, "text/plain; charset=utf-8", nil)
	}
}

func makeCertificate() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
