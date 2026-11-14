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
//
// Signalling is one HTTP POST: the offer as the body, the answer as the response body.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

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

func server(addr string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		pc := newPC(nil, false)
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

func turnRaw(server, user, pass string) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	check(err)
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
	fmt.Printf("ok: pion/turn: binding (mapped %v), allocation %v, permission, 20 datagrams relayed both ways\n", mapped, relay.LocalAddr())
	relay.Close()
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
		turnRaw(os.Args[2], os.Args[3], os.Args[4])
	default:
		fail("unknown mode %s", os.Args[1])
	}
}
