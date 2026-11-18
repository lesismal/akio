// The pion/sctp + pion/datachannel side of crates/only-sctp/examples/udp_peer.rs: SCTP over
// plain UDP (no DTLS). It echoes every message on channels the Rust side opens, opens
// "from-pion" (50 strings, a 70000-byte binary message, an empty string, "pion-end") and
// "pion-pr" (unordered, at most 3 retransmissions; 20 messages, then closed from this side),
// and closes each channel the Rust side resets.
//
//	go run . connect|accept LOCAL REMOTE [drop-every-n] [interleave 0|1]
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/logging"
	"github.com/pion/sctp"
)

// lossy drops every n-th datagram it sends.
type lossy struct {
	net.Conn
	n, sent uint64
}

func (l *lossy) Write(b []byte) (int, error) {
	if l.n > 0 && atomic.AddUint64(&l.sent, 1)%l.n == 0 {
		return len(b), nil
	}
	return l.Conn.Write(b)
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "pion: FAILED: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 4 {
		fail("usage: connect|accept LOCAL REMOTE [drop-every-n] [interleave 0|1]")
	}
	active := os.Args[1] == "connect"
	var drop uint64
	if len(os.Args) > 4 {
		drop, _ = strconv.ParseUint(os.Args[4], 10, 64)
	}
	interleave := len(os.Args) <= 5 || os.Args[5] != "0"
	laddr, err := net.ResolveUDPAddr("udp", os.Args[2])
	if err != nil {
		fail("%v", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", os.Args[3])
	if err != nil {
		fail("%v", err)
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		fail("%v", err)
	}
	lf := logging.NewDefaultLoggerFactory()
	opts := []sctp.AssociationOption{
		sctp.WithNetConn(&lossy{Conn: conn, n: drop}),
		sctp.WithLoggerFactory(lf),
		sctp.WithEnableInterleaving(interleave),
		sctp.WithMaxMessageSize(262144),
	}
	var a *sctp.Association
	if active {
		co := make([]sctp.ClientOption, len(opts))
		for i, o := range opts {
			co[i] = o
		}
		a, err = sctp.ClientWithOptions(co...)
	} else {
		so := make([]sctp.ServerOption, len(opts))
		for i, o := range opts {
			so[i] = o
		}
		a, err = sctp.ServerWithOptions(so...)
	}
	if err != nil {
		fail("association: %v", err)
	}
	md, _ := a.Metadata()
	fmt.Printf("pion: established, interleaving=%v partial-reliability=%v\n", md.MessageInterleavingEnabled, md.PartialReliabilityMode)

	// Stream ids of our parity: the Rust side uses even ids when it connects.
	base := uint16(0)
	if !active {
		base = 1
	}
	go func() {
		for {
			dc, err := datachannel.Accept(a, &datachannel.Config{LoggerFactory: lf})
			if err != nil {
				return
			}
			fmt.Printf("pion: accepted %q (%d)\n", dc.Config.Label, dc.StreamIdentifier())
			go func() {
				buf := make([]byte, 1<<20)
				for {
					n, isString, err := dc.ReadDataChannel(buf)
					if err != nil {
						_ = dc.Close()
						return
					}
					if _, err := dc.WriteDataChannel(buf[:n], isString); err != nil {
						fail("echo: %v", err)
					}
				}
			}()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	from, err := datachannel.Dial(a, base+10, &datachannel.Config{Label: "from-pion", Protocol: "p1", LoggerFactory: lf})
	if err != nil {
		fail("dial: %v", err)
	}
	pr, err := datachannel.Dial(a, base+12, &datachannel.Config{
		Label: "pion-pr", ChannelType: datachannel.ChannelTypePartialReliableRexmitUnordered, ReliabilityParameter: 3,
		LoggerFactory: lf,
	})
	if err != nil {
		fail("dial: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, err := from.WriteDataChannel([]byte(fmt.Sprintf("pion message %d", i)), true); err != nil {
			fail("write: %v", err)
		}
	}
	big := make([]byte, 70000)
	for i := range big {
		big[i] = 0xab
	}
	for _, m := range []struct {
		b []byte
		s bool
	}{{big, false}, {nil, true}, {[]byte("pion-end"), true}} {
		if _, err := from.WriteDataChannel(m.b, m.s); err != nil {
			fail("write: %v", err)
		}
	}
	for i := 0; i < 20; i++ {
		if _, err := pr.WriteDataChannel([]byte(fmt.Sprintf("pr %d", i)), true); err != nil {
			fail("write: %v", err)
		}
	}
	go func() {
		buf := make([]byte, 1<<16)
		for {
			if _, _, err := from.ReadDataChannel(buf); err != nil {
				_ = from.Close()
				return
			}
		}
	}()
	time.Sleep(time.Second)
	_ = pr.Close()
	// The Rust side shuts the association down; it is killed by the script otherwise.
	time.Sleep(120 * time.Second)
}
