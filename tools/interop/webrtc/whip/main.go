// Command whip-pion is the pion side of tools/interop/webrtc/media.sh: WHIP and WHEP clients
// against only-media's WHIP/WHEP endpoints (only_media::webrtc::RtcMedia).
//
//	whip-pion whip <url> <in.h264> <in.ogg> <seconds> <min-plis>
//	    publishes the H.264 Annex B file (looped, 25 fps) and the Ogg Opus file over WHIP for
//	    <seconds>; a PLI makes it jump to the next IDR at once. Counts the PLIs that arrive
//	    after the first two seconds (the ingest asks for one on connect) and fails with fewer
//	    than <min-plis>.
//	whep <url> <out.h264> <seconds> [pli]
//	    plays over WHEP: checks that H.264 starts with a keyframe and that audio arrives,
//	    writes the H.264 to <out.h264>; with "pli", sends a PLI after three seconds and checks
//	    a keyframe follows within 600 ms (the source's GOP is ten seconds).
//
// Prints one "ok" line with counts and exits 0 when the checks pass.
package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/h264reader"
	"github.com/pion/webrtc/v4/pkg/media/h264writer"
	"github.com/pion/webrtc/v4/pkg/media/oggreader"
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

// signal POSTs the offer of pc to endpoint and applies the answer; returns the session URL.
func signal(pc *webrtc.PeerConnection, endpoint string) string {
	o, err := pc.CreateOffer(nil)
	check(err)
	gathered := webrtc.GatheringCompletePromise(pc)
	check(pc.SetLocalDescription(o))
	<-gathered
	resp, err := http.Post(endpoint, "application/sdp", strings.NewReader(pc.LocalDescription().SDP))
	check(err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		fail("%s: %s: %s", endpoint, resp.Status, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/sdp") {
		fail("answer content type %q", ct)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		fail("no Location")
	}
	base, err := url.Parse(endpoint)
	check(err)
	ref, err := url.Parse(loc)
	check(err)
	check(pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(body)}))
	return base.ResolveReference(ref).String()
}

func deleteSession(session string) {
	req, err := http.NewRequest(http.MethodDelete, session, nil)
	check(err)
	resp, err := http.DefaultClient.Do(req)
	check(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fail("DELETE %s: %s", session, resp.Status)
	}
}

func waitConnected(pc *webrtc.PeerConnection) {
	done := make(chan struct{})
	var once sync.Once
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateConnected {
			once.Do(func() { close(done) })
		}
	})
	if pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
		return
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		fail("not connected: %s", pc.ConnectionState())
	}
}

// accessUnits reads an Annex B H.264 file as access units (one per VCL NAL unit, with the
// non-VCL units before it), each as Annex B, and whether it holds an IDR.
func accessUnits(path string) ([][]byte, []bool) {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	r, err := h264reader.NewReader(f)
	check(err)
	var aus [][]byte
	var keys []bool
	var cur []byte
	key := false
	for {
		nal, err := r.NextNAL()
		if errors.Is(err, io.EOF) {
			break
		}
		check(err)
		t := nal.UnitType
		if t == h264reader.NalUnitTypeAUD {
			continue
		}
		cur = append(cur, 0, 0, 0, 1)
		cur = append(cur, nal.Data...)
		if t == h264reader.NalUnitTypeCodedSliceIdr {
			key = true
		}
		if t == h264reader.NalUnitTypeCodedSliceIdr || t == h264reader.NalUnitTypeCodedSliceNonIdr {
			aus = append(aus, cur)
			keys = append(keys, key)
			cur, key = nil, false
		}
	}
	if len(aus) == 0 || !keys[0] {
		fail("%s: no access units, or it does not start with an IDR", path)
	}
	return aus, keys
}

func opusPackets(path string) [][]byte {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	r, _, err := oggreader.NewWith(f)
	check(err)
	var out [][]byte
	for {
		page, _, err := r.ParseNextPage()
		if errors.Is(err, io.EOF) {
			break
		}
		check(err)
		if len(page) > 0 && !strings.HasPrefix(string(page), "OpusTags") {
			out = append(out, page)
		}
	}
	return out
}

func whip(endpoint, h264, ogg string, seconds int, minPLIs int) {
	aus, keys := accessUnits(h264)
	opus := opusPackets(ogg)
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	check(err)
	defer pc.Close()
	video, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264}, "video", "pion")
	check(err)
	audio, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "audio", "pion")
	check(err)
	vt, err := pc.AddTransceiverFromTrack(video, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	check(err)
	_, err = pc.AddTransceiverFromTrack(audio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	check(err)
	start := time.Now()
	var plis, latePLIs atomic.Int32
	var jump atomic.Bool
	go func() {
		for {
			pkts, _, err := vt.Sender().ReadRTCP()
			if err != nil {
				return
			}
			for _, p := range pkts {
				switch p.(type) {
				case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
					plis.Add(1)
					if time.Since(start) > 2*time.Second {
						latePLIs.Add(1)
					}
					jump.Store(true)
				}
			}
		}
	}()
	session := signal(pc, endpoint)
	waitConnected(pc)
	start = time.Now()
	go func() {
		for i := 0; ; i++ {
			if time.Since(start) > time.Duration(seconds)*time.Second {
				return
			}
			if err := audio.WriteSample(media.Sample{Data: opus[i%len(opus)], Duration: 20 * time.Millisecond}); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	frames := 0
	i := 0
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for time.Since(start) < time.Duration(seconds)*time.Second {
		if jump.Swap(false) {
			// A keyframe now: skip to the next IDR of the file.
			for n := 1; n <= len(aus); n++ {
				if keys[(i+n)%len(aus)] {
					i = (i + n) % len(aus)
					break
				}
			}
		}
		check(video.WriteSample(media.Sample{Data: aus[i], Duration: 40 * time.Millisecond}))
		frames++
		i = (i + 1) % len(aus)
		<-tick.C
	}
	deleteSession(session)
	if int(latePLIs.Load()) < minPLIs {
		fail("whip: %d PLIs after the start, want at least %d", latePLIs.Load(), minPLIs)
	}
	fmt.Printf("whip ok: %d video frames, %d PLIs (%d after the start)\n", frames, plis.Load(), latePLIs.Load())
}

// keyframe reports whether an H.264 RTP payload starts a keyframe: an IDR, or the SPS sent
// right before one.
func keyframe(p []byte) bool {
	if len(p) < 2 {
		return false
	}
	switch p[0] & 0x1f {
	case 5, 7:
		return true
	case 24: // STAP-A
		for r := p[1:]; len(r) > 2; {
			n := int(r[0])<<8 | int(r[1])
			if n == 0 || n > len(r)-2 {
				break
			}
			if t := r[2] & 0x1f; t == 5 || t == 7 {
				return true
			}
			r = r[2+n:]
		}
	case 28: // FU-A start
		return p[1]&0x80 != 0 && p[1]&0x1f == 5
	}
	return false
}

func whep(endpoint, out string, seconds int, pli bool) {
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	check(err)
	defer pc.Close()
	for _, k := range []webrtc.RTPCodecType{webrtc.RTPCodecTypeVideo, webrtc.RTPCodecTypeAudio} {
		_, err := pc.AddTransceiverFromKind(k, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly})
		check(err)
	}
	w, err := h264writer.New(out)
	check(err)
	var mu sync.Mutex
	var videoPkts, audioPkts, keyPkts int
	var firstVideoKey *bool
	var videoSSRC atomic.Uint32
	keyAt := make(chan time.Time, 1024)
	audioCodec := ""
	pc.OnTrack(func(t *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		mime := t.Codec().MimeType
		if t.Kind() == webrtc.RTPCodecTypeVideo {
			videoSSRC.Store(uint32(t.SSRC()))
		}
		for {
			p, _, err := t.ReadRTP()
			if err != nil {
				return
			}
			mu.Lock()
			if t.Kind() == webrtc.RTPCodecTypeVideo {
				if !strings.EqualFold(mime, webrtc.MimeTypeH264) {
					mu.Unlock()
					fail("video codec %s", mime)
				}
				videoPkts++
				k := keyframe(p.Payload)
				if firstVideoKey == nil {
					firstVideoKey = &k
				}
				if k {
					keyPkts++
					select {
					case keyAt <- time.Now():
					default:
					}
				}
				_ = w.WriteRTP(p)
			} else {
				audioPkts++
				audioCodec = mime
			}
			mu.Unlock()
		}
	})
	session := signal(pc, endpoint)
	waitConnected(pc)
	start := time.Now()
	pliChecked := false
	if pli {
		time.Sleep(3 * time.Second)
		for len(keyAt) > 0 {
			<-keyAt
		}
		sent := time.Now()
		check(pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: videoSSRC.Load()}}))
		select {
		case t := <-keyAt:
			fmt.Printf("whep: keyframe %v after the PLI\n", t.Sub(sent).Round(time.Millisecond))
			pliChecked = true
		case <-time.After(600 * time.Millisecond):
			fail("whep: no keyframe within 600 ms of the PLI")
		}
	}
	if rest := time.Duration(seconds)*time.Second - time.Since(start); rest > 0 {
		time.Sleep(rest)
	}
	deleteSession(session)
	mu.Lock()
	defer mu.Unlock()
	check(w.Close())
	if videoPkts == 0 || firstVideoKey == nil || !*firstVideoKey {
		fail("whep: video packets %d, first is a keyframe: %v", videoPkts, firstVideoKey != nil && *firstVideoKey)
	}
	if audioPkts == 0 {
		fail("whep: no audio")
	}
	fmt.Printf("whep ok: %d video packets (%d keyframe), %d audio packets (%s), pli checked: %v\n",
		videoPkts, keyPkts, audioPkts, audioCodec, pliChecked)
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	check(err)
	return n
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: whip-pion whip|whep ...")
	}
	switch a := os.Args[1:]; a[0] {
	case "whip":
		if len(a) != 6 {
			fail("usage: whip-pion whip <url> <in.h264> <in.ogg> <seconds> <min-plis>")
		}
		whip(a[1], a[2], a[3], atoi(a[4]), atoi(a[5]))
	case "whep":
		if len(a) < 4 {
			fail("usage: whip-pion whep <url> <out.h264> <seconds> [pli]")
		}
		whep(a[1], a[2], atoi(a[3]), len(a) > 4 && a[4] == "pli")
	default:
		fail("unknown command %q", a[0])
	}
}
