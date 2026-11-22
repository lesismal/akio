// HTTP/3 interop peer (github.com/quic-go/quic-go) for akio-h3:
//
//	go run . server 127.0.0.1:9400    serves /, /echo, /trailers, /big, /ws (WebSocket, RFC 9220)
//	go run . client 127.0.0.1:9401    checks a akio-h3 server (crates/akio-h3/examples/h3-interop.rs)
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// A minimal WebSocket framing (RFC 6455) over an HTTP/3 stream: unfragmented messages only.
func wsWrite(w io.Writer, op byte, payload []byte, mask bool) error {
	h := []byte{0x80 | op}
	m := byte(0)
	if mask {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		h = append(h, m|byte(n))
	case n < 1<<16:
		h = append(h, m|126, byte(n>>8), byte(n))
	default:
		h = append(h, m|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	body := payload
	if mask {
		key := []byte{0x12, 0x34, 0x56, 0x78}
		h = append(h, key...)
		body = make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ key[i%4]
		}
	}
	_, err := w.Write(append(h, body...))
	return err
}

func wsRead(r *bufio.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0]&0x80 == 0 {
		return 0, nil, fmt.Errorf("fragmented frame")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	var key []byte
	if h[1]&0x80 != 0 {
		key = make([]byte, 4)
		if _, err := io.ReadFull(r, key); err != nil {
			return 0, nil, err
		}
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	if key != nil {
		for i := range p {
			p[i] ^= key[i%4]
		}
	}
	return h[0] & 0x0f, p, nil
}

// wsEcho serves an RFC 9220 WebSocket: echoes messages, answers pings and the close.
func wsEcho(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.Proto != "websocket" || r.Header.Get("Sec-Websocket-Version") != "13" {
		w.WriteHeader(400)
		return
	}
	if p := r.Header.Get("Sec-Websocket-Protocol"); strings.Contains(p, "chat") {
		w.Header().Set("Sec-Websocket-Protocol", "chat")
	}
	w.WriteHeader(200)
	str := w.(http3.HTTPStreamer).HTTPStream()
	defer str.Close()
	br := bufio.NewReader(str)
	for {
		op, p, err := wsRead(br)
		if err != nil {
			return
		}
		switch op {
		case 1, 2:
			if wsWrite(str, op, p, false) != nil {
				return
			}
		case 9:
			_ = wsWrite(str, 10, p, false)
		case 8:
			_ = wsWrite(str, 8, p, false)
			return
		}
	}
}

// wsCheck opens a WebSocket over HTTP/3 on a akio-h3 server's /ws and checks the echo.
func wsCheck(addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}}
	qc, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{})
	if err != nil {
		fail("ws dial: %v", err)
	}
	tr := &http3.Transport{}
	cc := tr.NewClientConn(qc)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		fail("ws: no SETTINGS")
	}
	if !cc.Settings().EnableExtendedConnect {
		fail("ws: server did not enable extended CONNECT")
	}
	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		fail("ws stream: %v", err)
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://"+addr+"/ws", nil)
	req.Proto = "websocket"
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Protocol", "v0, chat")
	if err := rs.SendRequestHeader(req); err != nil {
		fail("ws request: %v", err)
	}
	resp, err := rs.ReadResponse()
	if err != nil || resp.StatusCode != 200 {
		fail("ws response: %v %v", err, resp)
	}
	if resp.Header.Get("Sec-Websocket-Protocol") != "chat" {
		fail("ws subprotocol: %q", resp.Header.Get("Sec-Websocket-Protocol"))
	}
	br := bufio.NewReader(rs)
	for _, m := range [][]byte{[]byte("hello from quic-go"), pattern(200 << 10)} {
		op := byte(2)
		if len(m) < 100 {
			op = 1
		}
		if err := wsWrite(rs, op, m, true); err != nil {
			fail("ws write: %v", err)
		}
		gop, got, err := wsRead(br)
		if err != nil || gop != op || !bytes.Equal(got, m) {
			fail("ws echo: %v op %d, %d bytes", err, gop, len(got))
		}
	}
	if err := wsWrite(rs, 8, []byte{0x03, 0xe8}, true); err != nil {
		fail("ws close: %v", err)
	}
	op, p, err := wsRead(br)
	if err != nil || op != 8 || !bytes.Equal(p, []byte{0x03, 0xe8}) {
		fail("ws close echo: %v %d %v", err, op, p)
	}
	_ = rs.Close()
	// The server ends its side after the close handshake.
	if _, err := br.ReadByte(); err != io.EOF {
		fail("ws: stream not ended: %v", err)
	}
	_ = qc.CloseWithError(0, "")
}

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
		mux.HandleFunc("/ws", wsEcho)
		mux.HandleFunc("/count", func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.Copy(io.Discard, r.Body)
			fmt.Fprintf(w, "%d", n)
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
	// A streamed upload of unknown length (no content-length) to a streaming handler.
	pr, pw := io.Pipe()
	go func() {
		chunk := pattern(64 << 10)
		for i := 0; i < 256; i++ {
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
		pw.Close()
	}()
	req, _ = http.NewRequest("POST", base+"/count", pr)
	resp, err = c.Do(req)
	if err != nil {
		fail("streamed POST: %v", err)
	}
	got, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != fmt.Sprint(256<<16) {
		fail("streamed POST: %q", got)
	}
	wsCheck(addr)
	fmt.Println("ok: quic-go client -> akio-h3 server (incl. WebSocket over HTTP/3, streamed upload)")
}
