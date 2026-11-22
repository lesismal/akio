// Headless Firefox <-> akio-webrtc data channels, driven over WebDriver BiDi (Firefox's
// remote protocol; it has no DevTools Protocol any more). Firefox's data channels run on
// usrsctp, so this checks akio-sctp against usrsctp. Used by ../firefox.sh.
//
//	go run . <bidi-port> offer <http-signalling-addr>   Firefox offers to the akio ICE-lite
//	                                                     server: messages echoed on an ordered
//	                                                     and an unordered/unreliable channel,
//	                                                     large binary ones, an idle spell long
//	                                                     enough for HEARTBEATs both ways, then
//	                                                     Firefox closes a channel (stream
//	                                                     reset both ways) and opens a new one
//	go run . <bidi-port> answer <listen-addr>           Firefox answers offers POSTed to
//	                                                     http://<listen-addr>/ and echoes data
//	                                                     channel messages
//
// IDLE_SECONDS sets the idle spell of the offer mode (default 75).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+f+"\n", a...)
	os.Exit(1)
}

type bidi struct {
	ws      *websocket.Conn
	mu      sync.Mutex
	id      int
	pending map[int]chan map[string]any
	ctx     string
}

func dial(port string) *bidi {
	var ws *websocket.Conn
	var err error
	for i := 0; i < 100; i++ {
		ws, _, err = websocket.DefaultDialer.Dial("ws://127.0.0.1:"+port+"/session", nil)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		fail("WebDriver BiDi not reachable: %v", err)
	}
	b := &bidi{ws: ws, pending: map[int]chan map[string]any{}}
	go func() {
		for {
			var m map[string]any
			if err := ws.ReadJSON(&m); err != nil {
				return
			}
			id, ok := m["id"].(float64)
			if !ok {
				continue // an event
			}
			b.mu.Lock()
			ch := b.pending[int(id)]
			delete(b.pending, int(id))
			b.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}()
	return b
}

func (b *bidi) call(method string, params map[string]any) map[string]any {
	b.mu.Lock()
	b.id++
	id := b.id
	ch := make(chan map[string]any, 1)
	b.pending[id] = ch
	err := b.ws.WriteJSON(map[string]any{"id": id, "method": method, "params": params})
	b.mu.Unlock()
	if err != nil {
		fail("%s: %v", method, err)
	}
	m := <-ch
	if m["type"] == "error" {
		fail("%s: %v: %v", method, m["error"], m["message"])
	}
	r, _ := m["result"].(map[string]any)
	return r
}

// eval runs an (async) expression in the page and returns its string value.
func (b *bidi) eval(expr string) string {
	r := b.call("script.evaluate", map[string]any{
		"expression":   expr,
		"target":       map[string]any{"context": b.ctx},
		"awaitPromise": true,
	})
	if r["type"] == "exception" {
		d, _ := json.Marshal(r["exceptionDetails"])
		fail("page: %s", d)
	}
	v, _ := r["result"].(map[string]any)
	s, _ := v["value"].(string)
	return s
}

// page starts a session and opens a blank page served from 127.0.0.1 (a secure context).
func page(port string) *bidi {
	b := dial(port)
	b.call("session.new", map[string]any{"capabilities": map[string]any{}})
	tree := b.call("browsingContext.getTree", map[string]any{})
	ctxs, _ := tree["contexts"].([]any)
	if len(ctxs) == 0 {
		fail("no browsing context")
	}
	b.ctx, _ = ctxs[0].(map[string]any)["context"].(string)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("%v", err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/html")
		io.WriteString(w, "<!doctype html><title>akio-webrtc</title>")
	}))
	b.call("browsingContext.navigate", map[string]any{
		"context": b.ctx, "url": "http://" + ln.Addr().String() + "/", "wait": "complete",
	})
	b.eval(pageLib)
	// Firefox gathers host candidates beyond the default address (loopback among them) only
	// for a page with media permission: a fake microphone stream grants it.
	b.eval(`(async () => { try { window.keep = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch (e) {} return ""; })()`)
	return b
}

const pageLib = `(() => {
window.waitFor = (f, ms, what) => new Promise((res, rej) => {
  const t0 = Date.now();
  const tick = () => { const v = f(); if (v) return res(v); if (Date.now() - t0 > ms) return rej(new Error("timeout: " + what)); setTimeout(tick, 50); };
  tick();
});
window.gather = (pc) => new Promise((r) => {
  if (pc.iceGatheringState === "complete") return r();
  pc.addEventListener("icegatheringstatechange", () => pc.iceGatheringState === "complete" && r());
  setTimeout(r, 3000);
});
window.collect = (dc, into) => { dc.binaryType = "arraybuffer"; dc.onmessage = (m) => into.push(typeof m.data === "string" ? m.data : "bin:" + m.data.byteLength); };
return "";
})()`

func offerMode(port, addr string) {
	idle := 75
	if v, err := strconv.Atoi(os.Getenv("IDLE_SECONDS")); err == nil {
		idle = v
	}
	p := page(port)
	offer := p.eval(`(async () => {
    const pc = new RTCPeerConnection();
    window.pc = pc;
    window.dc = pc.createDataChannel("firefox"); window.got = []; collect(dc, got);
    window.lossy = pc.createDataChannel("firefox-lossy", { ordered: false, maxRetransmits: 0 });
    window.lossyGot = []; collect(lossy, lossyGot);
    await pc.setLocalDescription(await pc.createOffer());
    await gather(pc);
    return pc.localDescription.sdp;
  })()`)
	resp, err := http.Post("http://"+addr+"/", "application/sdp", strings.NewReader(offer))
	if err != nil {
		fail("signalling: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		fail("signalling: %s", body)
	}
	if os.Getenv("DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "offer:\n%s\nanswer:\n%s\n", offer, body)
	}
	answer, _ := json.Marshal(string(body))
	r := p.eval(`(async () => {
    await pc.setRemoteDescription({ type: "answer", sdp: ` + string(answer) + ` });
    await waitFor(() => dc.readyState === "open", 15000, "data channel open (ICE " + pc.iceConnectionState + ")");
    for (let i = 0; i < 100; i++) dc.send("firefox message " + i);
    dc.send(new Uint8Array(70000));
    dc.send(new Uint8Array(200000));
    dc.send("");
    await waitFor(() => got.length >= 103, 20000, "echoes (" + got.length + ")");
    for (let i = 0; i < 100; i++) if (got[i] !== "firefox message " + i) throw new Error("echo " + i + ": " + got[i]);
    if (got[100] !== "bin:70000" || got[101] !== "bin:200000" || got[102] !== "") throw new Error("echoes: " + got.slice(100));
    await waitFor(() => lossy.readyState === "open", 5000, "lossy open");
    lossy.send("lossy");
    await waitFor(() => lossyGot.length > 0, 10000, "lossy echo");
    return "ok: Firefox offers: 100 ordered messages, 70000- and 200000-byte binary ones and an empty one echoed, an unordered/unreliable one too (max-message-size " + pc.sctp.maxMessageSize + ")";
  })()`)
	fmt.Println(r)
	// Idle: both sides send HEARTBEATs (usrsctp every 30 s, akio-sctp after 30 s + RTO);
	// the association must survive them.
	r = p.eval(`(async () => {
    await new Promise((r) => setTimeout(r, ` + strconv.Itoa(idle*1000) + `));
    if (dc.readyState !== "open" || pc.connectionState !== "connected") throw new Error("after idle: " + dc.readyState + " " + pc.connectionState);
    dc.send("after idle");
    await waitFor(() => got.includes("after idle"), 10000, "echo after idle");
    // Firefox closes its channel: an Outgoing SSN Reset Request each way.
    dc.close();
    await waitFor(() => dc.readyState === "closed", 10000, "closed (" + dc.readyState + ")");
    // A new channel takes the stream id again and works.
    const again = pc.createDataChannel("firefox-again"); const g = []; collect(again, g);
    await waitFor(() => again.readyState === "open", 10000, "reopen");
    again.send("again");
    await waitFor(() => g.length > 0, 10000, "echo on the new channel");
    return "ok: idle ` + strconv.Itoa(idle) + ` s survived, channel closed by Firefox (stream reset both ways), new channel " + again.id + " echoes";
  })()`)
	fmt.Println(r)
	p.eval(`(() => { pc.close(); return ""; })()`)
	// One BiDi session at a time: the answer mode starts the next.
	p.call("session.end", map[string]any{})
	os.Exit(0)
}

func answerMode(port, addr string) {
	p := page(port)
	var mu sync.Mutex
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(req.Body)
		offer, _ := json.Marshal(string(body))
		answer := p.eval(`(async () => {
        const pc = new RTCPeerConnection();
        window.pc2 = pc;
        pc.ondatachannel = (e) => { const dc = e.channel; dc.binaryType = "arraybuffer"; dc.onmessage = (m) => dc.send(m.data); };
        await pc.setRemoteDescription({ type: "offer", sdp: ` + string(offer) + ` });
        await pc.setLocalDescription(await pc.createAnswer());
        await gather(pc);
        return pc.localDescription.sdp;
      })()`)
		w.Header().Set("content-type", "application/sdp")
		w.WriteHeader(201)
		io.WriteString(w, answer)
	})
	fmt.Fprintln(os.Stderr, "firefox answerer on "+addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fail("%v", err)
	}
}

func main() {
	if len(os.Args) < 4 {
		fail("usage: <bidi-port> offer|answer <addr>")
	}
	switch os.Args[2] {
	case "offer":
		offerMode(os.Args[1], os.Args[3])
	case "answer":
		answerMode(os.Args[1], os.Args[3])
	default:
		fail("unknown mode %s", os.Args[2])
	}
}
