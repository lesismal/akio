// KCP interop peer (github.com/xtaci/kcp-go, as kcptun uses it) for only-kcp:
//
//	go run . server 127.0.0.1:9200 aes 10 3          echoes every session's bytes
//	go run . client 127.0.0.1:9201 aes 10 3          sends 2 MiB, checks the echo
//	go run . relay  127.0.0.1:9202 127.0.0.1:9201 7  forwards, dropping every 7th datagram
//
// Crypts: none, xor, aes, aes-128, aes-128-gcm; keys are fixed test keys both sides share.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

func block(name string) kcp.BlockCrypt {
	var b kcp.BlockCrypt
	var err error
	switch name {
	case "none":
		b, err = kcp.NewNoneBlockCrypt(nil)
	case "xor":
		b, err = kcp.NewSimpleXORBlockCrypt([]byte("only-xor-key"))
	case "aes":
		b, err = kcp.NewAESBlockCrypt(bytes.Repeat([]byte{0x42}, 32))
	case "aes-128":
		b, err = kcp.NewAESBlockCrypt(bytes.Repeat([]byte{0x42}, 16))
	case "aes-128-gcm":
		b, err = kcp.NewAESGCMCrypt(bytes.Repeat([]byte{0x42}, 16))
	case "plain":
		return nil
	default:
		err = fmt.Errorf("unknown crypt %q", name)
	}
	if err != nil {
		fail(err)
	}
	return b
}

func fail(err error) {
	fmt.Println("FAIL:", err)
	os.Exit(1)
}

func tune(s *kcp.UDPSession) {
	s.SetNoDelay(1, 10, 2, 1)
	s.SetWindowSize(256, 256)
}

func main() {
	mode, addr := os.Args[1], os.Args[2]
	if mode == "relay" {
		every, _ := strconv.Atoi(os.Args[4])
		relay(addr, os.Args[3], every)
		return
	}
	crypt := block(os.Args[3])
	data, _ := strconv.Atoi(os.Args[4])
	parity, _ := strconv.Atoi(os.Args[5])
	if mode == "server" {
		l, err := kcp.ListenWithOptions(addr, crypt, data, parity)
		if err != nil {
			fail(err)
		}
		fmt.Println("ready")
		for {
			s, err := l.AcceptKCP()
			if err != nil {
				fail(err)
			}
			tune(s)
			go func() { _, _ = io.Copy(s, s) }()
		}
	}
	s, err := kcp.DialWithOptions(addr, crypt, data, parity)
	if err != nil {
		fail(err)
	}
	tune(s)
	want := make([]byte, 2<<20)
	for i := range want {
		want[i] = byte(i*7 + i>>11)
	}
	go func() {
		for off := 0; off < len(want); {
			n := 1 + (off*31)%6000
			if off+n > len(want) {
				n = len(want) - off
			}
			if _, err := s.Write(want[off : off+n]); err != nil {
				fail(err)
			}
			off += n
		}
	}()
	got := make([]byte, len(want))
	_ = s.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(s, got); err != nil {
		fail(err)
	}
	if !bytes.Equal(got, want) {
		fail(fmt.Errorf("echo differs"))
	}
	fmt.Println("ok: 2 MiB echoed")
}

func relay(listen, target string, every int) {
	front, err := net.ListenPacket("udp", listen)
	if err != nil {
		fail(err)
	}
	ta, _ := net.ResolveUDPAddr("udp", target)
	back, err := net.DialUDP("udp", nil, ta)
	if err != nil {
		fail(err)
	}
	var client net.Addr
	n := 0
	drop := func() bool { n++; return every > 0 && n%every == 0 }
	go func() {
		buf := make([]byte, 2048)
		for {
			k, err := back.Read(buf)
			if err != nil {
				return
			}
			if client != nil && !drop() {
				_, _ = front.WriteTo(buf[:k], client)
			}
		}
	}()
	fmt.Println("ready")
	buf := make([]byte, 2048)
	for {
		k, from, err := front.ReadFrom(buf)
		if err != nil {
			return
		}
		client = from
		if !drop() {
			_, _ = back.Write(buf[:k])
		}
	}
}
