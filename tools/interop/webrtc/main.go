// Command webrtc-pion is the pion side of tools/interop/webrtc/run.sh.
//
//	webrtc-pion server <http-addr>                   pion answerer: data channel and RTP echo
//	webrtc-pion client-dc <http-addr>                offers a data channel, checks 100 echoes
//	webrtc-pion client-media <http-addr>             offers Opus + VP8 + a data channel, checks
//	                                                 RTP echo and that a PLI reaches the server
//	webrtc-pion client-turn <http-addr> <turn> <user> <pass>
//	                                                 client-dc over a TURN relay only
//	webrtc-pion turn-raw <turn> <user> <pass>        pion/turn client: allocate, permission,
//	                                                 send and receive through the relay
//	webrtc-pion turn-raw-tcp <turn> <user> <pass>    the same over TCP
//	webrtc-pion turn-raw-tls <turn> <user> <pass>    the same over TLS (certificate not checked)
//	webrtc-pion turn-family-raw <turn> <user> <pass> <4|6>
//	                                                 turn-raw asking for that relay family
//	                                                 (REQUESTED-ADDRESS-FAMILY), with a peer on
//	                                                 127.0.0.1 or ::1
//	webrtc-pion turn-tcp-raw <turn> <user> <pass>    pion/turn TCP allocation (RFC 6062) over TCP:
//	                                                 Dial (Connect + ConnectionBind) to a TCP echo
//	                                                 peer, then Accept a peer connecting to the
//	                                                 relayed address; data both ways on each
//	webrtc-pion server-tcp <http-addr>               answerer with ICE-TCP only (active candidates)
//	webrtc-pion server-tcp-passive <http-addr> <tcp-addr>
//	                                                 answerer with ICE-TCP only, passive
//	                                                 candidates on <tcp-addr> (an ICE TCP mux)
//	webrtc-pion client-dc-tcp <http-addr>            client-dc with ICE-TCP only (active)
//	webrtc-pion server-simulcast <http-addr>         answerer receiving simulcast: reports RTP
//	                                                 packets per RID on the "stats" data channel
//	webrtc-pion turn-server <udp> <tcp> <tls> <user> <pass>
//	                                                 pion/turn server (realm "only") on UDP, TCP
//	                                                 and TLS, relaying from 127.0.0.1
//
// Signalling is one HTTP POST: the offer as the body, the answer as the response body.
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
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/sdp/v3"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/turn/v5"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func newPC(iceServers []webrtc.ICEServer, relayOnly bool) *webrtc.PeerConnection {
	cfg := webrtc.Configuration{ICEServers: iceServers}
	if relayOnly {
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	pc, err := webrtc.NewPeerConnection(cfg)
	check(err)
	return pc
}

// offer runs the offer/answer exchange against the only server at http.
func offer(pc *webrtc.PeerConnection, addr string) {
	o, err := pc.CreateOffer(nil)
	check(err)
	gathered := webrtc.GatheringCompletePromise(pc)
	check(pc.SetLocalDescription(o))
	<-gathered
	resp, err := http.Post("http://"+addr+"/", "application/sdp",
		strings.NewReader(pc.LocalDescription().SDP))
	check(err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		fail("signalling: %s: %s", resp.Status, body)
	}
	check(pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(body)}))
}

func dcEcho(pc *webrtc.PeerConnection, addr string, what string) {
	dc, err := pc.CreateDataChannel("pion", nil)
	check(err)
	ordered := false
	var zero uint16
	lossy, err := pc.CreateDataChannel("pion-lossy", &webrtc.DataChannelInit{Ordered: &ordered, MaxRetransmits: &zero})
	check(err)
	got := make(chan []byte, 200)
	dc.OnMessage(func(m webrtc.DataChannelMessage) { got <- m.Data })
	lossyGot := make(chan []byte, 10)
	lossy.OnMessage(func(m webrtc.DataChannelMessage) { lossyGot <- m.Data })
	opened := make(chan struct{})
	dc.OnOpen(func() { close(opened) })
	offer(pc, addr)
	select {
	case <-opened:
	case <-time.After(15 * time.Second):
		fail("data channel did not open (ICE %s)", pc.ICEConnectionState())
	}
	for i := 0; i < 100; i++ {
		msg := fmt.Sprintf("pion message %d", i)
		if i%2 == 0 {
			check(dc.SendText(msg))
		} else {
			check(dc.Send([]byte(msg)))
		}
	}
	for i := 0; i < 100; i++ {
		select {
		case m := <-got:
			if want := fmt.Sprintf("pion message %d", i); string(m) != want {
				fail("echo %d: got %q want %q", i, m, want)
			}
		case <-time.After(10 * time.Second):
			fail("echo %d timed out", i)
		}
	}
	// The unordered, unreliable channel works too (loopback: nothing is lost).
	for lossy.ReadyState() != webrtc.DataChannelStateOpen {
		time.Sleep(10 * time.Millisecond)
	}
	check(lossy.Send([]byte("lossy")))
	select {
	case m := <-lossyGot:
		if string(m) != "lossy" {
			fail("lossy echo: %q", m)
		}
	case <-time.After(10 * time.Second):
		fail("lossy echo timed out")
	}
	fmt.Printf("ok: pion %s: 100 ordered messages and an unordered/unreliable one echoed\n", what)
	pc.Close()
}

func clientMedia(addr string) {
	pc := newPC(nil, false)
	audio, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "audio", "pion")
	check(err)
	video, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}, "video", "pion")
	check(err)
	_, err = pc.AddTrack(audio)
	check(err)
	vs, err := pc.AddTrack(video)
	check(err)
	go func() { // drain the sender's RTCP
		buf := make([]byte, 1500)
		for {
			if _, _, err := vs.Read(buf); err != nil {
				return
			}
		}
	}()
	dc, err := pc.CreateDataChannel("ctl", nil)
	check(err)
	pli := make(chan struct{}, 1)
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if string(m.Data) == "keyframe-request" {
			select {
			case pli <- struct{}{}:
			default:
			}
		}
	})
	audioBack := make(chan []byte, 1000)
	videoBack := make(chan uint32, 1000)
	pc.OnTrack(func(t *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			p, _, err := t.ReadRTP()
			if err != nil {
				return
			}
			if t.Kind() == webrtc.RTPCodecTypeAudio {
				audioBack <- p.Payload
			} else {
				videoBack <- uint32(t.SSRC())
			}
		}
	})
	connected := make(chan struct{})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateConnected {
			close(connected)
		}
	})
	offer(pc, addr)
	select {
	case <-connected:
	case <-time.After(15 * time.Second):
		fail("not connected")
	}
	stop := make(chan struct{})
	go func() {
		seq := uint16(1000)
		ts := uint32(5000)
		frame := bytes.Repeat([]byte{0x9d, 0x01, 0x2a}, 1200) // larger than an MTU
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			p := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 111, SequenceNumber: seq, Timestamp: ts, SSRC: 1},
				Payload: []byte{0xfc, byte(i), 0x11, 0x22, 0x33}}
			seq++
			ts += 960
			_ = audio.WriteRTP(p)
			f := append([]byte{0x10, byte(i)}, frame...)
			_ = video.WriteSample(media.Sample{Data: f, Duration: 33 * time.Millisecond})
		}
	}()
	audioN, videoN := 0, 0
	var videoSSRC uint32
	deadline := time.After(15 * time.Second)
	for audioN < 30 || videoN < 30 {
		select {
		case p := <-audioBack:
			if len(p) != 5 || !bytes.Equal(p[2:], []byte{0x11, 0x22, 0x33}) {
				fail("audio echo payload %x", p)
			}
			audioN++
		case s := <-videoBack:
			videoSSRC = s
			videoN++
		case <-deadline:
			fail("media echo: %d audio, %d video RTP packets back", audioN, videoN)
		}
	}
	// A PLI for the echoed video reaches the only side as a keyframe request.
	check(pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: videoSSRC}}))
	select {
	case <-pli:
	case <-time.After(10 * time.Second):
		fail("PLI not reported by the only peer")
	}
	close(stop)
	fmt.Printf("ok: pion media: %d Opus and %d VP8 RTP packets echoed, PLI delivered as a keyframe request\n", audioN, videoN)
	pc.Close()
}

func server(addr string) { serverWith(addr, nil, nil) }

// tcpOnlyAPI gathers no UDP candidates: pion's agent then dials the passive TCP candidates of
// the offer from active ones (loopback included).
func tcpOnlyAPI() *webrtc.API {
	se := webrtc.SettingEngine{}
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeTCP4})
	se.SetIncludeLoopbackCandidate(true)
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

// passiveTCPAPI gathers passive TCP candidates on a listener (no UDP).
func passiveTCPAPI(tcpAddr string) *webrtc.API {
	l, err := net.Listen("tcp4", tcpAddr)
	check(err)
	se := webrtc.SettingEngine{}
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeTCP4})
	se.SetIncludeLoopbackCandidate(true)
	se.SetICETCPMux(webrtc.NewICETCPMux(nil, l, 32))
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

func serverWith(addr string, api *webrtc.API, _ any) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var pc *webrtc.PeerConnection
		if api != nil {
			var err error
			pc, err = api.NewPeerConnection(webrtc.Configuration{})
			check(err)
			pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
				fmt.Fprintf(os.Stderr, "pion server: ICE %s\n", s)
			})
		} else {
			pc = newPC(nil, false)
		}
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			dc.OnMessage(func(m webrtc.DataChannelMessage) {
				if m.IsString {
					_ = dc.SendText(string(m.Data))
				} else {
					_ = dc.Send(m.Data)
				}
			})
		})
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(body)}); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		echo, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "echo", "pion")
		check(err)
		hasAudio := strings.Contains(string(body), "m=audio")
		if hasAudio {
			_, err = pc.AddTrack(echo)
			check(err)
		}
		pc.OnTrack(func(t *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
			for {
				p, _, err := t.ReadRTP()
				if err != nil {
					return
				}
				_ = echo.WriteRTP(p)
			}
		})
		answer, err := pc.CreateAnswer(nil)
		check(err)
		gathered := webrtc.GatheringCompletePromise(pc)
		check(pc.SetLocalDescription(answer))
		<-gathered
		sdp := pc.LocalDescription().SDP
		w.Header().Set("Content-Type", "application/sdp")
		w.Header().Set("Content-Length", fmt.Sprint(len(sdp)))
		w.WriteHeader(201)
		_, _ = w.Write([]byte(sdp))
	})
	check(http.ListenAndServe(addr, nil))
}

func turnRaw(server, user, pass, transport string) {
	var conn net.PacketConn
	var err error
	switch transport {
	case "tcp":
		var c net.Conn
		c, err = net.Dial("tcp4", server)
		check(err)
		conn = turn.NewSTUNConn(c)
	case "tls":
		var c net.Conn
		c, err = tls.Dial("tcp4", server, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
		check(err)
		conn = turn.NewSTUNConn(c)
	default:
		conn, err = net.ListenPacket("udp4", "127.0.0.1:0")
		check(err)
	}
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server, TURNServerAddr: server, Conn: conn,
		Username: user, Password: pass, Realm: "only",
	})
	check(err)
	check(c.Listen())
	mapped, err := c.SendBindingRequest()
	check(err)
	relay, err := c.Allocate()
	check(err)
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	check(err)
	go func() { // the peer echoes what the relay sends it
		buf := make([]byte, 1500)
		for {
			n, from, err := peer.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = peer.WriteTo(buf[:n], from)
		}
	}()
	check(relay.SetReadDeadline(time.Now().Add(10 * time.Second)))
	buf := make([]byte, 1500)
	for i := 0; i < 20; i++ { // pion switches from Send indications to a channel binding
		msg := fmt.Sprintf("through the relay %d", i)
		_, err = relay.WriteTo([]byte(msg), peer.LocalAddr())
		check(err)
		n, from, err := relay.ReadFrom(buf)
		check(err)
		if string(buf[:n]) != msg || from.String() != peer.LocalAddr().String() {
			fail("relay echo %d: %q from %v", i, buf[:n], from)
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Printf("ok: pion/turn over %s: binding (mapped %v), allocation %v, permission, 20 datagrams relayed both ways\n", transport, mapped, relay.LocalAddr())
	relay.Close()
	c.Close()
}

// turnFamilyRaw: a pion/turn allocation of the IPv4 or IPv6 family (REQUESTED-ADDRESS-FAMILY),
// relaying to a peer of that family.
func turnFamilyRaw(server, user, pass, family string) {
	fam, peerNet, peerAddr := turn.RequestedAddressFamilyIPv4, "udp4", "127.0.0.1:0"
	if family == "6" {
		fam, peerNet, peerAddr = turn.RequestedAddressFamilyIPv6, "udp6", "[::1]:0"
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	check(err)
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server, TURNServerAddr: server, Conn: conn,
		Username: user, Password: pass, Realm: "only", RequestedAddressFamily: fam,
	})
	check(err)
	check(c.Listen())
	relay, err := c.Allocate()
	check(err)
	ra, ok := relay.LocalAddr().(*net.UDPAddr)
	if !ok || (ra.IP.To4() == nil) != (family == "6") {
		fail("relayed address %v is not of family %s", relay.LocalAddr(), family)
	}
	peer, err := net.ListenPacket(peerNet, peerAddr)
	check(err)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := peer.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = peer.WriteTo(buf[:n], from)
		}
	}()
	check(relay.SetReadDeadline(time.Now().Add(10 * time.Second)))
	buf := make([]byte, 1500)
	for i := 0; i < 20; i++ {
		msg := fmt.Sprintf("family %s %d", family, i)
		_, err = relay.WriteTo([]byte(msg), peer.LocalAddr())
		check(err)
		n, from, err := relay.ReadFrom(buf)
		check(err)
		if string(buf[:n]) != msg || from.String() != peer.LocalAddr().String() {
			fail("relay echo %d: %q from %v", i, buf[:n], from)
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Printf("ok: pion/turn REQUESTED-ADDRESS-FAMILY IPv%s: relayed %v, 20 datagrams echoed by %v\n", family, relay.LocalAddr(), peer.LocalAddr())
	relay.Close()
	c.Close()
}

// turnTCPRaw: a pion/turn TCP allocation (RFC 6062). pion binds data connections over plain
// TCP to the server's address, so the control connection is TCP too.
func turnTCPRaw(server, user, pass string) {
	c0, err := net.Dial("tcp4", server)
	check(err)
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: server, TURNServerAddr: server, Conn: turn.NewSTUNConn(c0),
		Username: user, Password: pass, Realm: "only",
	})
	check(err)
	check(c.Listen())
	alloc, err := c.AllocateTCP()
	check(err)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	check(err)
	go func() { // a TCP echo peer
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); conn.Close() }()
		}
	}()
	echo := func(conn net.Conn, what string) {
		check(conn.SetDeadline(time.Now().Add(10 * time.Second)))
		buf := make([]byte, 1<<20)
		for i := 0; i < 20; i++ {
			msg := fmt.Sprintf("through the tcp relay %d", i)
			_, err := conn.Write([]byte(msg))
			check(err)
			_, err = io.ReadFull(conn, buf[:len(msg)])
			check(err)
			if string(buf[:len(msg)]) != msg {
				fail("%s echo %d: %q", what, i, buf[:len(msg)])
			}
		}
		big := make([]byte, 1<<20)
		for i := range big {
			big[i] = byte(i * 7)
		}
		go func() { _, _ = conn.Write(big) }()
		_, err := io.ReadFull(conn, buf)
		check(err)
		if !bytes.Equal(buf, big) {
			fail("%s: 1 MiB echo differs", what)
		}
	}
	dc, err := alloc.Dial("tcp4", ln.Addr().String())
	check(err)
	echo(dc, "dial")
	dc.Close()
	// A peer connecting to the relayed address needs a permission.
	check(alloc.CreatePermissions(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}))
	go func() {
		p, err := net.Dial("tcp4", alloc.Addr().String())
		check(err)
		_, _ = io.Copy(p, p)
		p.Close()
	}()
	check(alloc.SetDeadline(time.Now().Add(10 * time.Second)))
	ac, err := alloc.AcceptTCP()
	check(err)
	echo(ac, "accept")
	ac.Close()
	fmt.Printf("ok: pion/turn TCP allocation %v: Dial and Accept, 20 messages and 1 MiB echoed on each\n", alloc.Addr())
	_ = alloc.Close()
	c.Close()
}

func main() {
	if len(os.Args) < 3 {
		fail("usage: webrtc-pion server|client-dc|client-media|client-turn|turn-raw ...")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2])
	case "client-dc":
		dcEcho(newPC(nil, false), os.Args[2], "data channels")
	case "client-media":
		clientMedia(os.Args[2])
	case "client-turn":
		ice := []webrtc.ICEServer{{URLs: []string{"turn:" + os.Args[3] + "?transport=udp"}, Username: os.Args[4], Credential: os.Args[5]}}
		dcEcho(newPC(ice, true), os.Args[2], "over a only TURN relay")
	case "turn-raw":
		turnRaw(os.Args[2], os.Args[3], os.Args[4], "udp")
	case "turn-raw-tcp":
		turnRaw(os.Args[2], os.Args[3], os.Args[4], "tcp")
	case "turn-raw-tls":
		turnRaw(os.Args[2], os.Args[3], os.Args[4], "tls")
	case "turn-tcp-raw":
		turnTCPRaw(os.Args[2], os.Args[3], os.Args[4])
	case "turn-family-raw":
		turnFamilyRaw(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	case "server-tcp":
		serverWith(os.Args[2], tcpOnlyAPI(), nil)
	case "server-tcp-passive":
		serverWith(os.Args[2], passiveTCPAPI(os.Args[3]), nil)
	case "client-dc-tcp":
		pc, err := tcpOnlyAPI().NewPeerConnection(webrtc.Configuration{})
		check(err)
		dcEcho(pc, os.Args[2], "data channels over ICE-TCP (active)")
	case "server-simulcast":
		serverSimulcast(os.Args[2])
	case "turn-server":
		turnServer(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
	default:
		fail("unknown mode %s", os.Args[1])
	}
}

// serverSimulcast answers offers that send simulcast video: it counts RTP packets per RID
// and reports them every 300 ms on the "stats" data channel as "h=N m=N l=N".
func serverSimulcast(addr string) {
	m := &webrtc.MediaEngine{}
	check(m.RegisterDefaultCodecs())
	for _, uri := range []string{sdp.SDESMidURI, sdp.SDESRTPStreamIDURI, sdp.SDESRepairRTPStreamIDURI} {
		check(m.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: uri}, webrtc.RTPCodecTypeVideo))
	}
	ir := &interceptor.Registry{}
	check(webrtc.RegisterDefaultInterceptors(m, ir))
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(ir))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		pc, err := api.NewPeerConnection(webrtc.Configuration{})
		check(err)
		var mu sync.Mutex
		counts := map[string]int{}
		ssrcs := map[string]webrtc.SSRC{}
		pc.OnTrack(func(t *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
			rid := t.RID()
			mu.Lock()
			ssrcs[rid] = t.SSRC()
			mu.Unlock()
			// Ask each encoding for a keyframe once.
			_ = pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(t.SSRC())}})
			for {
				if _, _, err := t.ReadRTP(); err != nil {
					return
				}
				mu.Lock()
				counts[rid]++
				mu.Unlock()
			}
		})
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			dc.OnOpen(func() {
				go func() {
					for dc.ReadyState() == webrtc.DataChannelStateOpen {
						mu.Lock()
						msg := fmt.Sprintf("h=%d m=%d l=%d", counts["h"], counts["m"], counts["l"])
						distinct := len(ssrcs) == 3 && ssrcs["h"] != ssrcs["m"] && ssrcs["m"] != ssrcs["l"]
						mu.Unlock()
						if distinct {
							msg += " ssrcs=3"
						}
						_ = dc.SendText(msg)
						time.Sleep(300 * time.Millisecond)
					}
				}()
			})
		})
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: string(body)}); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		answer, err := pc.CreateAnswer(nil)
		check(err)
		gathered := webrtc.GatheringCompletePromise(pc)
		check(pc.SetLocalDescription(answer))
		<-gathered
		out := pc.LocalDescription().SDP
		w.Header().Set("Content-Type", "application/sdp")
		w.Header().Set("Content-Length", fmt.Sprint(len(out)))
		w.WriteHeader(201)
		_, _ = w.Write([]byte(out))
	})
	check(http.ListenAndServe(addr, nil))
}

func selfSigned() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	check(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// turnServer runs pion/turn on UDP, TCP and TLS for the only TURN client.
func turnServer(udpAddr, tcpAddr, tlsAddr, user, pass string) {
	key := turn.GenerateAuthKey(user, "only", pass)
	gen := func() turn.RelayAddressGenerator {
		return &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}
	}
	udp, err := net.ListenPacket("udp4", udpAddr)
	check(err)
	tcp, err := net.Listen("tcp4", tcpAddr)
	check(err)
	tl, err := tls.Listen("tcp4", tlsAddr, &tls.Config{Certificates: []tls.Certificate{selfSigned()}})
	check(err)
	_, err = turn.NewServer(turn.ServerConfig{
		Realm: "only",
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username == user {
				return ra.Username, key, true
			}
			return "", nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udp, RelayAddressGenerator: gen()}},
		ListenerConfigs: []turn.ListenerConfig{
			{Listener: tcp, RelayAddressGenerator: gen()},
			{Listener: tl, RelayAddressGenerator: gen()},
		},
	})
	check(err)
	fmt.Fprintf(os.Stderr, "pion turn: udp %s tcp %s tls %s\n", udpAddr, tcpAddr, tlsAddr)
	select {}
}
