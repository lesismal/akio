// Raw QUIC interop peer (github.com/quic-go/quic-go) for only-quic: an echo of streams and
// datagrams, ALPN "echo".
//
//	go run . server 127.0.0.1:9500 [retry]      echoes every bidirectional stream and datagram
//	go run . client 127.0.0.1:9501 [bulk MB]    checks an only-quic echo server
//	                                            (crates/only-quic/examples/quic-interop.rs)
//
// "retry" makes the server validate every client address with a Retry first. "bulk MB" adds one
// stream of MB megabytes (150 MB crosses quic-go's key update interval of 100k packets).
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
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

func pattern(n, salt int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>9 + salt)
	}
	return b
}

var qconf = &quic.Config{
	EnableDatagrams:      true,
	MaxIdleTimeout:       30 * time.Second,
	MaxIncomingStreams:   1000,
	KeepAlivePeriod:      0,
	HandshakeIdleTimeout: 10 * time.Second,
}

func server(addr string, retry bool) {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		fail("listen: %v", err)
	}
	tr := &quic.Transport{Conn: udp}
	if retry {
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
	}
	ln, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert()}, NextProtos: []string{"echo"}}, qconf)
	if err != nil {
		fail("listen: %v", err)
	}
	fmt.Println("ready")
	for {
		c, err := ln.Accept(context.Background())
		if err != nil {
			fail("accept: %v", err)
		}
		go func() {
			go func() {
				for {
					d, err := c.ReceiveDatagram(context.Background())
					if err != nil {
						return
					}
					_ = c.SendDatagram(d)
				}
			}()
			for {
				s, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					_, _ = io.Copy(s, s)
					_ = s.Close()
				}()
			}
		}()
	}
}

func echoStream(c *quic.Conn, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	go func() {
		_, _ = s.Write(body)
		_ = s.Close()
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, body) {
		return fmt.Errorf("stream %d: got %d bytes, want %d", s.StreamID(), len(got), len(body))
	}
	return nil
}

func client(addr string, bulkMB int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"echo"}, ServerName: "localhost"}
	c, err := quic.DialAddr(ctx, addr, tlsConf, qconf)
	if err != nil {
		fail("dial: %v", err)
	}
	if p := c.ConnectionState().TLS.NegotiatedProtocol; p != "echo" {
		fail("alpn %q", p)
	}
	// 50 concurrent streams of growing sizes.
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := echoStream(c, pattern(i*3000, i)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		fail("echo: %v", err)
	}
	// Datagrams: unreliable, but loopback loses none in practice; most must come back.
	got := make(chan string, 64)
	go func() {
		for {
			d, err := c.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			got <- string(d)
		}
	}()
	for i := 0; i < 20; i++ {
		if err := c.SendDatagram([]byte("dg-" + strconv.Itoa(i))); err != nil {
			fail("datagram: %v", err)
		}
	}
	n := 0
	deadline := time.After(3 * time.Second)
wait:
	for n < 20 {
		select {
		case <-got:
			n++
		case <-deadline:
			break wait
		}
	}
	if n < 15 {
		fail("only %d of 20 datagrams echoed", n)
	}
	if bulkMB > 0 {
		body := pattern(bulkMB<<20, 3)
		start := time.Now()
		if err := echoStream(c, body); err != nil {
			fail("bulk: %v", err)
		}
		sum := sha256.Sum256(body)
		fmt.Printf("bulk %d MB echoed in %v (sha256 %x...)\n", bulkMB, time.Since(start).Round(time.Millisecond), sum[:4])
	}
	_ = c.CloseWithError(0, "done")
	fmt.Printf("ok: %d streams, %d/20 datagrams\n", 50, n)
}

func main() {
	if len(os.Args) < 3 {
		fail("usage: server|client ADDR [retry|bulk MB]")
	}
	mode, addr := os.Args[1], os.Args[2]
	switch mode {
	case "server":
		server(addr, len(os.Args) > 3 && os.Args[3] == "retry")
	case "client":
		mb := 0
		if len(os.Args) > 4 && os.Args[3] == "bulk" {
			mb, _ = strconv.Atoi(os.Args[4])
		}
		client(addr, mb)
	default:
		fail("unknown mode %q", mode)
	}
}
