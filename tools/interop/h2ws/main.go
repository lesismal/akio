// WebSocket over HTTP/2 (RFC 8441) interop peer for akio-http, on Go's own HTTP/2: net/http's
// server, and golang.org/x/net/http2's transport for the client (net/http's own transport
// refuses the `:protocol` field; build with -tags http2legacy on Go 1.27, where x/net otherwise
// wraps net/http). Extended CONNECT needs GODEBUG=http2xconnect=1 on both. The WebSocket
// framing (RFC 6455) and permessage-deflate (RFC 7692, without context takeover) are written
// out here.
//
//	h2ws server <h2c-addr> <tls-addr>   echo WebSocket at /ws, text at /hello
//	h2ws client <h2c-addr> <tls-addr>   checks a server: echoes, deflate, fragments, ping,
//	                                    requests and a second WebSocket on the same connection,
//	                                    close handshake
package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const deflateResp = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("usage: %s server|client <h2c-addr> <tls-addr>", os.Args[0])
	}
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		log.Fatal("run with GODEBUG=http2xconnect=1 (Go's extended CONNECT switch)")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2], os.Args[3])
	case "client":
		for _, tc := range []struct {
			name, url string
			tls       bool
		}{{"h2c", "http://" + os.Args[2], false}, {"tls", "https://" + os.Args[3], true}} {
			if err := client(tc.url, tc.tls); err != nil {
				log.Fatalf("go client -> only (%s): %v", tc.name, err)
			}
			log.Printf("go client -> only (%s): ok", tc.name)
		}
	default:
		log.Fatal("server or client")
	}
}

// ---- framing ---------------------------------------------------------------------------------

type frame struct {
	fin, rsv1 bool
	op        byte
	payload   []byte
}

func readFrame(r io.Reader, masked bool) (frame, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	f := frame{fin: h[0]&0x80 != 0, rsv1: h[0]&0x40 != 0, op: h[0] & 0x0f}
	if (h[1]&0x80 != 0) != masked {
		return f, fmt.Errorf("mask bit %v, want %v", h[1]&0x80 != 0, masked)
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return f, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return f, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 64<<20 {
		return f, fmt.Errorf("frame too large: %d", n)
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return f, err
		}
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(r, f.payload); err != nil {
		return f, err
	}
	if masked {
		for i := range f.payload {
			f.payload[i] ^= key[i%4]
		}
	}
	return f, nil
}

func encodeFrame(f frame, mask bool) []byte {
	b0 := f.op
	if f.fin {
		b0 |= 0x80
	}
	if f.rsv1 {
		b0 |= 0x40
	}
	out := []byte{b0}
	var m byte
	if mask {
		m = 0x80
	}
	n := len(f.payload)
	switch {
	case n < 126:
		out = append(out, m|byte(n))
	case n < 65536:
		out = append(out, m|126, byte(n>>8), byte(n))
	default:
		out = append(out, m|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	if !mask {
		return append(out, f.payload...)
	}
	var key [4]byte
	rand.Read(key[:])
	out = append(out, key[:]...)
	for i, c := range f.payload {
		out = append(out, c^key[i%4])
	}
	return out
}

func deflate(p []byte) []byte {
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.DefaultCompression)
	w.Write(p)
	w.Flush()
	out := b.Bytes()
	return bytes.Clone(bytes.TrimSuffix(out, []byte{0, 0, 0xff, 0xff}))
}

func inflate(p []byte) ([]byte, error) {
	r := flate.NewReader(io.MultiReader(bytes.NewReader(p), bytes.NewReader([]byte{0, 0, 0xff, 0xff, 1, 0, 0, 0xff, 0xff})))
	return io.ReadAll(r)
}

// conn is one WebSocket: frames read from r, written to w (flushed each time).
type conn struct {
	r      io.Reader
	w      io.Writer
	flush  func()
	client bool
	pmd    bool
	mu     sync.Mutex
}

func (c *conn) write(f frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(encodeFrame(f, c.client)); err != nil {
		return err
	}
	c.flush()
	return nil
}

// send sends a message, compressed when negotiated and worth it, in `parts` frames.
func (c *conn) send(op byte, p []byte, parts int) error {
	rsv1 := false
	if c.pmd && len(p) >= 64 {
		p, rsv1 = deflate(p), true
	}
	if parts < 1 {
		parts = 1
	}
	step := (len(p) + parts - 1) / parts
	if step == 0 {
		return c.write(frame{fin: true, rsv1: rsv1, op: op, payload: p})
	}
	for i := 0; i < len(p); i += step {
		end := min(i+step, len(p))
		f := frame{fin: end == len(p), op: 0, payload: p[i:end]}
		if i == 0 {
			f.op, f.rsv1 = op, rsv1
		}
		if err := c.write(f); err != nil {
			return err
		}
	}
	return nil
}

// recv reads the next message (control frames other than close handled: ping answered).
func (c *conn) recv() (byte, []byte, error) {
	var op byte
	var msg []byte
	var compressed, started bool
	for {
		f, err := readFrame(c.r, !c.client)
		if err != nil {
			return 0, nil, err
		}
		switch f.op {
		case 0x8:
			return 0x8, f.payload, nil
		case 0x9:
			if err := c.write(frame{fin: true, op: 0xa, payload: f.payload}); err != nil {
				return 0, nil, err
			}
			continue
		case 0xa:
			return 0xa, f.payload, nil
		case 0x0:
			if !started {
				return 0, nil, errors.New("continuation without a start")
			}
		default:
			op, compressed, started = f.op, f.rsv1, true
		}
		if f.rsv1 && !c.pmd {
			return 0, nil, errors.New("RSV1 without permessage-deflate")
		}
		msg = append(msg, f.payload...)
		if f.fin {
			if compressed {
				m, err := inflate(msg)
				return op, m, err
			}
			return op, msg, nil
		}
	}
}

// ---- server ----------------------------------------------------------------------------------

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hello" {
		fmt.Fprint(w, "hello from go")
		return
	}
	if r.Method != http.MethodConnect || r.Header.Get(":protocol") != "websocket" || r.ProtoMajor != 2 {
		http.Error(w, "extended CONNECT websocket only", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Sec-Websocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "version", http.StatusUpgradeRequired)
		return
	}
	pmd := strings.Contains(r.Header.Get("Sec-Websocket-Extensions"), "permessage-deflate")
	if pmd {
		w.Header().Set("Sec-WebSocket-Extensions", deflateResp)
	}
	for _, p := range strings.Split(r.Header.Get("Sec-Websocket-Protocol"), ",") {
		if strings.TrimSpace(p) == "chat" {
			w.Header().Set("Sec-WebSocket-Protocol", "chat")
			break
		}
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	rc.Flush()
	c := &conn{r: r.Body, w: w, flush: func() { rc.Flush() }, pmd: pmd}
	for {
		op, p, err := c.recv()
		if err != nil {
			log.Printf("server: %v", err)
			return
		}
		switch op {
		case 0x8:
			// Echo the close; returning ends our half of the stream.
			c.write(frame{fin: true, op: 0x8, payload: p})
			return
		case 0xa:
		default:
			if err := c.send(op, p, 1); err != nil {
				return
			}
		}
	}
}

func selfSigned() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func server(h2c, tlsAddr string) {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	s := &http.Server{Addr: h2c, Handler: http.HandlerFunc(handler), Protocols: p}
	go func() { log.Fatal(s.ListenAndServe()) }()
	t := &http.Server{
		Addr:      tlsAddr,
		Handler:   http.HandlerFunc(handler),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned()}, NextProtos: []string{"h2"}},
	}
	log.Printf("go h2 websocket server on %s (h2c) and %s (tls)", h2c, tlsAddr)
	log.Fatal(t.ListenAndServeTLS("", ""))
}

// ---- client ----------------------------------------------------------------------------------

func dialWS(hc *http.Client, url string, deflate bool) (*conn, *http.Response, error) {
	pr, pw := io.Pipe()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodConnect, url+"/ws", pr)
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Protocol", "v9, chat")
	if deflate {
		req.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 {
		return nil, nil, fmt.Errorf("status %d proto %s", resp.StatusCode, resp.Proto)
	}
	if got := resp.Header.Get("Sec-Websocket-Protocol"); got != "chat" {
		return nil, nil, fmt.Errorf("subprotocol %q", got)
	}
	ext := resp.Header.Get("Sec-Websocket-Extensions")
	if deflate != strings.HasPrefix(ext, "permessage-deflate") {
		return nil, nil, fmt.Errorf("extensions %q (offered: %v)", ext, deflate)
	}
	return &conn{r: resp.Body, w: pw, flush: func() {}, client: true, pmd: deflate}, resp, nil
}

func expect(c *conn, op byte, want []byte) error {
	gop, got, err := c.recv()
	if err != nil {
		return err
	}
	if gop != op || !bytes.Equal(got, want) {
		return fmt.Errorf("got op %d len %d, want op %d len %d", gop, len(got), op, len(want))
	}
	return nil
}

func client(url string, useTLS bool) error {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			if !useTLS {
				return (&net.Dialer{}).DialContext(ctx, network, addr) // h2c, prior knowledge
			}
			return (&tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}}).DialContext(ctx, network, addr)
		},
	}
	hc := &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()
	errs := make(chan error, 3)
	for _, deflate := range []bool{true, false} {
		go func() {
			c, resp, err := dialWS(hc, url, deflate)
			if err != nil {
				errs <- fmt.Errorf("dial (deflate %v): %w", deflate, err)
				return
			}
			defer resp.Body.Close()
			big := make([]byte, 3<<20)
			rand.Read(big)
			text := strings.Repeat("compress me please ", 4000)
			steps := []struct {
				op    byte
				p     []byte
				parts int
			}{
				{0x1, []byte("hello"), 1},
				{0x2, big, 1},
				{0x1, []byte(text), 1},
				{0x1, []byte(text), 5},
				{0x2, []byte{}, 1},
			}
			for i, s := range steps {
				if err := c.send(s.op, s.p, s.parts); err != nil {
					errs <- fmt.Errorf("send %d: %w", i, err)
					return
				}
				if err := expect(c, s.op, s.p); err != nil {
					errs <- fmt.Errorf("echo %d (deflate %v): %w", i, deflate, err)
					return
				}
			}
			if err := c.write(frame{fin: true, op: 0x9, payload: []byte("ping")}); err != nil {
				errs <- err
				return
			}
			if err := expect(c, 0xa, []byte("ping")); err != nil {
				errs <- fmt.Errorf("pong: %w", err)
				return
			}
			bye := []byte{0x03, 0xe8, 'b', 'y', 'e'}
			if err := c.write(frame{fin: true, op: 0x8, payload: bye}); err != nil {
				errs <- err
				return
			}
			if err := expect(c, 0x8, bye[:2]); err != nil {
				errs <- fmt.Errorf("close echo: %w", err)
				return
			}
			// The server ends its half after the close; then ours.
			if _, err := io.ReadAll(resp.Body); err != nil {
				errs <- fmt.Errorf("after close: %w", err)
				return
			}
			c.w.(*io.PipeWriter).Close()
			errs <- nil
		}()
	}
	// A plain request on the same connection meanwhile.
	go func() {
		resp, err := hc.Get(url + "/hello")
		if err != nil {
			errs <- err
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 || string(b) != "hello h2" {
			errs <- fmt.Errorf("plain request: %s %q", resp.Proto, b)
			return
		}
		errs <- nil
	}()
	for range 3 {
		select {
		case err := <-errs:
			if err != nil {
				return err
			}
		case <-time.After(20 * time.Second):
			return errors.New("timed out")
		}
	}
	return nil
}
