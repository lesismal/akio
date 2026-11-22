// Command webrtc-fib is the fib (Go, lesismal/fib/webrtc) side of tools/interop/webrtc/run.sh.
//
//	webrtc-fib server <http-addr>      fib answerer (full ICE, a port per peer): data channel echo
//	webrtc-fib client-dc <http-addr>   fib offers a data channel to a akio server, checks 100 echoes
//
// Signalling is one HTTP POST: the offer as the body, the answer as the response body.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lesismal/fib"
	fibwebrtc "github.com/lesismal/fib/webrtc"
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

func engine() *fib.Engine {
	cfg := fib.DefaultConfig()
	cfg.LogSettings = false
	e, err := fib.New(cfg)
	check(err)
	go func() { _ = e.Run() }()
	return e
}

func newPC(e *fib.Engine) *fibwebrtc.PeerConnection {
	pc, err := fibwebrtc.NewPeerConnection(fibwebrtc.Configuration{Engine: e, ListenAddr: "127.0.0.1:0"})
	check(err)
	return pc
}

func server(addr string) {
	e := engine()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		pc := newPC(e)
		pc.OnDataChannel(func(d *fibwebrtc.DataChannel) {
			d.OnMessage(func(m fibwebrtc.DataChannelMessage) {
				if m.IsString {
					_ = d.SendText(string(m.Data))
				} else {
					_ = d.Send(m.Data)
				}
			})
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		answer, err := fibwebrtc.Answer(ctx, pc, fibwebrtc.SessionDescription{Type: fibwebrtc.SDPTypeOffer, SDP: string(body)})
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/sdp")
		w.Header().Set("Content-Length", fmt.Sprint(len(answer.SDP)))
		w.WriteHeader(201)
		_, _ = w.Write([]byte(answer.SDP))
	})
	check(http.ListenAndServe(addr, nil))
}

func clientDC(addr string) {
	pc := newPC(engine())
	d, err := pc.CreateDataChannel("fib", nil)
	check(err)
	got := make(chan []byte, 200)
	d.OnMessage(func(m fibwebrtc.DataChannelMessage) { got <- m.Data })
	opened := make(chan struct{})
	d.OnOpen(func() { close(opened) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	offer, err := fibwebrtc.Offer(ctx, pc, nil)
	check(err)
	resp, err := http.Post("http://"+addr+"/", "application/sdp", strings.NewReader(offer.SDP))
	check(err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		fail("signalling: %s: %s", resp.Status, body)
	}
	check(pc.SetRemoteDescription(fibwebrtc.SessionDescription{Type: fibwebrtc.SDPTypeAnswer, SDP: string(body)}))
	select {
	case <-opened:
	case <-time.After(15 * time.Second):
		fail("data channel did not open")
	}
	for i := 0; i < 100; i++ {
		check(d.SendText(fmt.Sprintf("fib message %d", i)))
	}
	for i := 0; i < 100; i++ {
		select {
		case m := <-got:
			if want := fmt.Sprintf("fib message %d", i); string(m) != want {
				fail("echo %d: got %q want %q", i, m, want)
			}
		case <-time.After(10 * time.Second):
			fail("echo %d timed out", i)
		}
	}
	fmt.Println("ok: fib data channel: 100 messages echoed in order")
	_ = pc.Close()
}

func main() {
	if len(os.Args) < 3 {
		fail("usage: webrtc-fib server|client-dc <http-addr>")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2])
	case "client-dc":
		clientDC(os.Args[2])
	default:
		fail("unknown mode %s", os.Args[1])
	}
}
