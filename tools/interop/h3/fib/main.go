// HTTP/3 interop peer on fib's own QUIC and HTTP/3 (github.com/lesismal/fib/http3):
//
//	go run . server 127.0.0.1:9402    serves / and /echo
//	go run . client 127.0.0.1:9401    checks a flash-h3 server
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	stdhttp "net/http"
	"os"
	"strings"
	"sync"
	"time"

	fib "github.com/lesismal/fib"
	fibhttp "github.com/lesismal/fib/http"
	"github.com/lesismal/fib/http3"
)

func fail(format string, args ...any) {
	fmt.Printf("FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>9)
	}
	return b
}

func main() {
	mode, addr := os.Args[1], os.Args[2]
	if mode == "server" {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames: []string{"localhost"}}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		config := http3.DefaultConfig()
		config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}
		handler := http3.NewHandlerWithConfig(config, fibhttp.HandlerFunc(func(c *fibhttp.Context) {
			if c.Request.URL.Path == "/echo" {
				_ = c.Respond(200, "application/octet-stream", c.Body())
				return
			}
			_ = c.Respond(200, "text/plain", []byte("hello from fib "+c.Request.Proto))
		}))
		ec := fib.DefaultConfig()
		ec.LogSettings = false
		engine, err := fib.New(ec, fib.Binding{Network: "udp", Addr: addr, Handler: handler})
		if err != nil {
			fail("engine: %v", err)
		}
		fmt.Println("ready")
		if err := engine.Run(); err != nil {
			fail("run: %v", err)
		}
		return
	}
	ec := fib.DefaultConfig()
	ec.LogSettings = false
	engine, err := fib.New(ec)
	if err != nil {
		fail("engine: %v", err)
	}
	go func() { _ = engine.Run() }()
	cfg := http3.ClientConfig{Timeout: 20 * time.Second}
	cfg.TLSConfig = &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}
	c := http3.NewClient(engine, cfg)
	defer c.Close()
	do := func(method, path string, body []byte) (*stdhttp.Response, []byte) {
		req, _ := stdhttp.NewRequest(method, "https://"+addr+path, bytes.NewReader(body))
		resp, err := c.Go(req).Wait()
		if err != nil {
			fail("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	if r, b := do("GET", "/", nil); r.StatusCode != 200 || string(b) != "hello h3" {
		fail("GET /: %d %q", r.StatusCode, b)
	}
	body := pattern(2 << 20)
	if _, b := do("POST", "/echo", body); !bytes.Equal(b, body) {
		fail("POST /echo: %d bytes", len(b))
	}
	if r, _ := do("GET", "/missing", nil); r.StatusCode != 404 {
		fail("404: %d", r.StatusCode)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, b := do("GET", fmt.Sprintf("/user/%d", i), nil); !strings.HasPrefix(string(b), fmt.Sprintf("user %d ", i)) {
				fail("parallel %d: %q", i, b)
			}
		}(i)
	}
	wg.Wait()
	fmt.Println("ok: fib client -> flash-h3 server")
}
