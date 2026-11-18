// The pion/dtls side of the only-dtls interop checks (../run.sh).
//
//	pion server <bind> <cert.pem> <key.pem> <srtp-profile> [cipher-suite]
//	pion client <addr> <cert.pem> <key.pem> <srtp-profile> [cipher-suite]
//	pion cid-server <bind> <cid-len>      connection IDs (RFC 9146), self-signed
//	pion cid-client <addr> <cid-len>      (cid-len 0: only send the peer's CID)
//	pion psk-server <bind> <identity> <hex-key> <cipher-suite>
//	pion psk-client <addr> <identity> <hex-key> <cipher-suite>
//
// Both require a peer certificate and the extended master secret, print
// `CONNECTED suite=.. srtp=.. peer=sha-256 ..` and `SRTP_MATERIAL <hex>` (the
// EXTRACTOR-dtls_srtp export); the server echoes one message, the client sends one and waits
// for the echo.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

var profiles = map[string]dtls.SRTPProtectionProfile{
	"SRTP_AES128_CM_SHA1_80": dtls.SRTP_AES128_CM_HMAC_SHA1_80,
	"SRTP_AES128_CM_SHA1_32": dtls.SRTP_AES128_CM_HMAC_SHA1_32,
	"SRTP_AEAD_AES_128_GCM":  dtls.SRTP_AEAD_AES_128_GCM,
	"SRTP_AEAD_AES_256_GCM":  dtls.SRTP_AEAD_AES_256_GCM,
}

var suites = map[string]dtls.CipherSuiteID{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_PSK_WITH_AES_128_GCM_SHA256":               dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256":         dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256":   dtls.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
}

// keyLens: SRTP master key + salt per profile (RFC 5764, RFC 7714).
var keyLens = map[dtls.SRTPProtectionProfile]int{
	dtls.SRTP_AES128_CM_HMAC_SHA1_80: 30,
	dtls.SRTP_AES128_CM_HMAC_SHA1_32: 30,
	dtls.SRTP_AEAD_AES_128_GCM:       28,
	dtls.SRTP_AEAD_AES_256_GCM:       44,
}

func must(err error) {
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return "sha-256 " + strings.Join(parts, ":")
}

func report(c *dtls.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	must(c.HandshakeContext(ctx))
	state, ok := c.ConnectionState()
	if !ok {
		must(fmt.Errorf("no connection state"))
	}
	profile, _ := c.SelectedSRTPProtectionProfile()
	peer := "-"
	if len(state.PeerCertificates) > 0 {
		peer = fingerprint(state.PeerCertificates[0])
	}
	fmt.Printf("CONNECTED suite=%v srtp=%v peer=%s\n", state.CipherSuiteID, profile, peer)
	if n, ok := keyLens[profile]; ok {
		m, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, 2*n)
		must(err)
		fmt.Printf("SRTP_MATERIAL %X\n", m)
	}
}

// echo runs the server (echo one message) or client (send one, wait for the echo) side.
func echo(mode string, addr *net.UDPAddr, cfg *dtls.Config) {
	buf := make([]byte, 8192)
	switch mode {
	case "server":
		ln, err := dtls.Listen("udp", addr, cfg)
		must(err)
		nc, err := ln.Accept()
		must(err)
		c := nc.(*dtls.Conn)
		report(c)
		must(c.SetReadDeadline(time.Now().Add(10 * time.Second)))
		n, err := c.Read(buf)
		must(err)
		fmt.Printf("RECV %s\n", buf[:n])
		_, err = c.Write(buf[:n])
		must(err)
		time.Sleep(500 * time.Millisecond)
		_ = c.Close()
	default:
		c, err := dtls.Dial("udp", addr, cfg)
		must(err)
		report(c)
		_, err = c.Write([]byte("hello from pion"))
		must(err)
		must(c.SetReadDeadline(time.Now().Add(10 * time.Second)))
		n, err := c.Read(buf)
		must(err)
		fmt.Printf("RECV %s\n", buf[:n])
		_ = c.Close()
	}
}

// extra handles the cid-* and psk-* modes; false for the others.
func extra() bool {
	mode := os.Args[1]
	role := "client"
	if strings.HasSuffix(mode, "server") {
		role = "server"
	}
	addr, err := net.ResolveUDPAddr("udp", os.Args[2])
	must(err)
	switch {
	case strings.HasPrefix(mode, "cid-"):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		cert, err := selfsign.SelfSign(key)
		must(err)
		var n int
		_, err = fmt.Sscan(os.Args[3], &n)
		must(err)
		gen := dtls.OnlySendCIDGenerator()
		if n > 0 {
			gen = dtls.RandomCIDGenerator(n)
		}
		echo(role, addr, &dtls.Config{
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    true,
			ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
			ConnectionIDGenerator: gen,
		})
	case strings.HasPrefix(mode, "psk-"):
		identity, keyHex, suite := os.Args[3], os.Args[4], os.Args[5]
		key, err := hex.DecodeString(keyHex)
		must(err)
		echo(role, addr, &dtls.Config{
			PSK: func(hint []byte) ([]byte, error) {
				fmt.Printf("PSK_IDENTITY %s\n", hint)
				return key, nil
			},
			PSKIdentityHint:      []byte(identity),
			CipherSuites:         []dtls.CipherSuiteID{suites[suite]},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		})
	default:
		return false
	}
	return true
}

func main() {
	if extra() {
		return
	}
	mode, addr, certFile, keyFile, profile := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	must(err)
	cfg := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		ClientAuth:             dtls.RequireAnyClientCert,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{profiles[profile]},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			_, err := x509.ParseCertificate(raw[0])
			return err
		},
	}
	if len(os.Args) > 6 {
		cfg.CipherSuites = []dtls.CipherSuiteID{suites[os.Args[6]]}
	}
	udp, err := net.ResolveUDPAddr("udp", addr)
	must(err)
	buf := make([]byte, 8192)
	switch mode {
	case "server":
		ln, err := dtls.Listen("udp", udp, cfg)
		must(err)
		nc, err := ln.Accept()
		must(err)
		c := nc.(*dtls.Conn)
		report(c)
		must(c.SetReadDeadline(time.Now().Add(10 * time.Second)))
		n, err := c.Read(buf)
		must(err)
		fmt.Printf("RECV %s\n", buf[:n])
		_, err = c.Write(buf[:n])
		must(err)
		time.Sleep(500 * time.Millisecond)
		_ = c.Close()
	case "client":
		c, err := dtls.Dial("udp", udp, cfg)
		must(err)
		report(c)
		_, err = c.Write([]byte("hello from pion"))
		must(err)
		must(c.SetReadDeadline(time.Now().Add(10 * time.Second)))
		n, err := c.Read(buf)
		must(err)
		fmt.Printf("RECV %s\n", buf[:n])
		_ = c.Close()
	}
}
