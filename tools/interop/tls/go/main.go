// Go crypto/tls peer for only-tls interop runs (tools/interop/tls/run.sh).
//
//	tlsgo server -addr A -cert C -key K [-ca CA -require] [-tls12|-tls13] [-alpn h2,..] [-count N]
//	             [-ocsp resp.der]
//	tlsgo client -addr A -name N [-ca CA|-insecure] [-cert C -key K] [-tls12|-tls13]
//	             [-alpn ..] [-count N] [-expect-resume] [-suite 0xc02b] [-curve 23]
//	             [-expect-ocsp resp.der]
//
// -ocsp staples a DER OCSP response; -expect-ocsp checks the server stapled exactly that one
// (Go's client always asks for one).
//
// The server echoes; the client writes a line, checks the echo and prints what was negotiated.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}

func pool(path string) *x509.CertPool {
	b, err := os.ReadFile(path)
	must(err)
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		must(fmt.Errorf("no certificates in %s", path))
	}
	return p
}

func describe(s tls.ConnectionState) string {
	return fmt.Sprintf("version=%s suite=%s alpn=%q resumed=%v peer_certs=%d",
		tls.VersionName(s.Version), tls.CipherSuiteName(s.CipherSuite),
		s.NegotiatedProtocol, s.DidResume, len(s.PeerCertificates))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: tlsgo server|client ...")
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9443", "address")
	name := fs.String("name", "localhost", "server name")
	certF := fs.String("cert", "", "certificate PEM")
	keyF := fs.String("key", "", "key PEM")
	caF := fs.String("ca", "", "CA PEM")
	require := fs.Bool("require", false, "require a client certificate")
	insecure := fs.Bool("insecure", false, "skip verification")
	tls12 := fs.Bool("tls12", false, "TLS 1.2 only")
	tls13 := fs.Bool("tls13", false, "TLS 1.3 only")
	alpn := fs.String("alpn", "", "ALPN protocols")
	count := fs.Int("count", 1, "connections")
	expectResume := fs.Bool("expect-resume", false, "later connections must resume")
	suite := fs.String("suite", "", "TLS 1.2 cipher suite id")
	curve := fs.Int("curve", 0, "only this curve id")
	keyUpdate := fs.Bool("key-update", false, "client: send many records")
	ocspF := fs.String("ocsp", "", "server: DER OCSP response to staple")
	expectOCSP := fs.String("expect-ocsp", "", "client: the OCSP response the server must staple")
	must(fs.Parse(os.Args[2:]))

	cfg := &tls.Config{ServerName: *name}
	if *tls12 {
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	}
	if *tls13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	if *alpn != "" {
		cfg.NextProtos = strings.Split(*alpn, ",")
	}
	if *suite != "" {
		v, err := strconv.ParseUint(strings.TrimPrefix(*suite, "0x"), 16, 16)
		must(err)
		cfg.CipherSuites = []uint16{uint16(v)}
	}
	if *curve != 0 {
		cfg.CurvePreferences = []tls.CurveID{tls.CurveID(*curve)}
	}
	if *certF != "" {
		c, err := tls.LoadX509KeyPair(*certF, *keyF)
		must(err)
		if *ocspF != "" {
			c.OCSPStaple, err = os.ReadFile(*ocspF)
			must(err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	switch mode {
	case "server":
		if *caF != "" {
			cfg.ClientCAs = pool(*caF)
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
			if *require {
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}
		l, err := tls.Listen("tcp", *addr, cfg)
		must(err)
		fmt.Println("listening", l.Addr())
		for i := 0; i < *count; i++ {
			c, err := l.Accept()
			must(err)
			tc := c.(*tls.Conn)
			_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
			if err := tc.Handshake(); err != nil {
				fmt.Println("handshake failed:", err)
				tc.Close()
				continue
			}
			fmt.Println("server:", describe(tc.ConnectionState()))
			_, _ = io.Copy(tc, tc)
			tc.Close()
		}
	case "client":
		if *insecure {
			cfg.InsecureSkipVerify = true
		} else if *caF != "" {
			cfg.RootCAs = pool(*caF)
		}
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(8)
		for i := 0; i < *count; i++ {
			c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", *addr, cfg)
			must(err)
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))
			st := c.ConnectionState()
			fmt.Printf("client[%d]: %s\n", i, describe(st))
			if *expectResume && i > 0 && !st.DidResume {
				fmt.Println("expected a resumed session")
				os.Exit(2)
			}
			if *expectOCSP != "" && !st.DidResume {
				want, err := os.ReadFile(*expectOCSP)
				must(err)
				if !bytes.Equal(st.OCSPResponse, want) {
					fmt.Printf("expected the stapled OCSP response of %s, got %d bytes\n", *expectOCSP, len(st.OCSPResponse))
					os.Exit(2)
				}
			}
			msgs := 1
			if *keyUpdate {
				msgs = 200
			}
			r := bufio.NewReader(c)
			for j := 0; j < msgs; j++ {
				line := fmt.Sprintf("hello from go %d/%d\n", i, j)
				_, err = c.Write([]byte(line))
				must(err)
				got, err := r.ReadString('\n')
				must(err)
				if got != line {
					fmt.Println("echo mismatch:", got)
					os.Exit(1)
				}
			}
			c.Close()
		}
		fmt.Println("ok")
	}
}
