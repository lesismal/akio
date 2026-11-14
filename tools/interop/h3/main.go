// HTTP/3 interop peer (github.com/quic-go/quic-go) for only-h3:
//
//	go run . server 127.0.0.1:9400    serves /, /echo, /trailers, /big
//	go run . client 127.0.0.1:9401    checks a only-h3 server (crates/only-h3/examples/h3-interop.rs)
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
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func fail(format string, args ...any) {
	fmt.Printf("FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func cert() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		fail("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "hello from quic-go %s %s", r.Proto, r.Host)
		})
		mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			w.Header().Set("X-Req-Header", r.Header.Get("X-Test"))
			_, _ = w.Write(b)
		})
		mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Trailer", "X-Sum")
			_, _ = w.Write([]byte("body"))
			w.Header().Set("X-Sum", "42")
		})
		mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(pattern(4 << 20))
		})
		s := &http3.Server{
			Addr:      addr,
			TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert()}}),
			Handler:   mux,
		}
		fmt.Println("ready")
		if err := s.ListenAndServe(); err != nil {
			fail("serve: %v", err)
		}
		return
	}
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}}
	defer tr.Close()
	c := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	base := "https://" + addr
	get := func(path string) (*http.Response, []byte) {
		resp, err := c.Get(base + path)
		if err != nil {
			fail("GET %s: %v", path, err)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			fail("GET %s body: %v", path, err)
		}
		resp.Body.Close()
		return resp, b
	}
	resp, b := get("/")
	if resp.StatusCode != 200 || string(b) != "hello h3" || resp.Proto != "HTTP/3.0" {
		fail("GET /: %d %q %s", resp.StatusCode, b, resp.Proto)
	}
	resp, b = get("/user/7")
	if !strings.HasPrefix(string(b), "user 7 Http3") {
		fail("GET /user/7: %q", b)
	}
	if resp, _ = get("/missing"); resp.StatusCode != 404 {
		fail("404: %d", resp.StatusCode)
	}
	body := pattern(2 << 20)
	req, _ := http.NewRequest("POST", base+"/echo", bytes.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		fail("POST: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, body) {
		fail("POST echo: %d bytes", len(got))
	}
	resp, b = get("/stream")
	if strings.Count(string(b), "\n") != 50 || resp.Trailer.Get("X-Checksum") != "abc" {
		fail("stream: %d lines, trailer %q", strings.Count(string(b), "\n"), resp.Trailer.Get("X-Checksum"))
	}
	hr, err := c.Head(base + "/")
	if err != nil || hr.StatusCode != 200 || hr.ContentLength != 8 {
		fail("HEAD: %v %v", err, hr)
	}
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, b := get(fmt.Sprintf("/user/%d", i))
			if !strings.HasPrefix(string(b), fmt.Sprintf("user %d ", i)) {
				fail("parallel %d: %q", i, b)
			}
		}(i)
	}
	wg.Wait()
	fmt.Println("ok: quic-go client -> only-h3 server")
}
