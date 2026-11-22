// Headless Chrome against akio-media's whip-server (WHIP/WHEP with WebRTC media, fMP4 LL-HLS,
// a multivariant playlist), driven over the Chrome DevTools Protocol like
// tools/interop/webrtc/browser.mjs (no npm packages: Node >= 22 has fetch and WebSocket). Used by
// browser.sh.
//
//   node browser.mjs <cdp-port> <whip-server-http-addr>
//
// Chrome publishes its fake camera and microphone over WHIP with VP8, VP9, AV1 and H.264 in turn;
// the hub stream must have that codec and the camera's size; Chrome plays each back over WHEP and
// must decode 30 frames of the same codec and receive Opus. Then it publishes an AV1 ladder of
// two renditions (640x360, 320x180) under the multivariant playlist live/abr.m3u8, which must list both
// with CODECS and RESOLUTION; hls.js (from jsDelivr, skipped when unreachable) must play it and
// switch renditions; Chrome's own HLS player is tried too (reported, not required).
import http from "node:http";

const [port, addr] = process.argv.slice(2);
const fail = (m) => {
  console.error("FAIL: " + m);
  process.exit(1);
};

async function page() {
  let targets;
  for (let i = 0; i < 50; i++) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  if (!targets) fail("Chrome DevTools not reachable");
  let t = targets.find((x) => x.type === "page");
  if (!t) t = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise((r, j) => {
    ws.onopen = r;
    ws.onerror = j;
  });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  };
  const call = (method, params) =>
    new Promise((r) => {
      id++;
      pending.set(id, r);
      ws.send(JSON.stringify({ id, method, params }));
    });
  const evaluate = async (expr) => {
    const r = await call("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) fail("page: " + JSON.stringify(r.result.exceptionDetails));
    return r.result?.result?.value;
  };
  // A secure context (http://127.0.0.1) for getUserMedia: a blank page served here.
  const blank = http.createServer((_q, r) => {
    r.writeHead(200, { "content-type": "text/html" });
    r.end("<!doctype html><title>akio-media</title>");
  });
  await new Promise((r) => blank.listen(0, "127.0.0.1", r));
  await call("Page.enable", {});
  await call("Page.navigate", { url: `http://127.0.0.1:${blank.address().port}/` });
  await new Promise((r) => setTimeout(r, 500));
  return { evaluate, close: () => { ws.close(); blank.close(); } };
}

const PAGE_LIB = `
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
true`;

const MEDIA_LIB = `
window.pcs = {};
window.pubOffer = async (name, codec, w, h, scale) => {
  const pc = new RTCPeerConnection();
  pcs[name] = pc;
  const media = await navigator.mediaDevices.getUserMedia({
    audio: true, video: { width: { exact: w * scale }, height: { exact: h * scale } },
  });
  const vt = pc.addTransceiver(media.getVideoTracks()[0], {
    direction: "sendonly", streams: [media], sendEncodings: [{ scaleResolutionDownBy: scale }],
  });
  pc.addTransceiver(media.getAudioTracks()[0], { direction: "sendonly", streams: [media] });
  const want = RTCRtpSender.getCapabilities("video").codecs
    .filter((c) => c.mimeType.toLowerCase() === "video/" + codec.toLowerCase());
  if (!want.length) throw new Error("Chrome cannot send " + codec);
  vt.setCodecPreferences(want);
  await pc.setLocalDescription(await pc.createOffer());
  await gather(pc);
  return pc.localDescription.sdp;
};
window.playOffer = async (name) => {
  const pc = new RTCPeerConnection();
  pcs[name] = pc;
  pc.addTransceiver("video", { direction: "recvonly" });
  pc.addTransceiver("audio", { direction: "recvonly" });
  await pc.setLocalDescription(await pc.createOffer());
  await gather(pc);
  return pc.localDescription.sdp;
};
window.closePc = (name) => {
  const pc = pcs[name];
  for (const s of pc.getSenders()) if (s.track) s.track.stop();
  pc.close();
  delete pcs[name];
  return true;
};
window.inbound = async (name) => {
  const pc = pcs[name];
  const stats = await pc.getStats();
  let v = 0, a = 0, codec = "", w = 0, kf = 0;
  stats.forEach((s) => {
    if (s.type === "inbound-rtp" && s.kind === "video") {
      v = s.framesDecoded || 0; w = s.frameWidth || 0; kf = s.keyFramesDecoded || 0;
      const c = stats.get(s.codecId); if (c) codec = c.mimeType;
    }
    if (s.type === "inbound-rtp" && s.kind === "audio") a = s.packetsReceived || 0;
  });
  return { v, a, codec, w, kf };
};
window.sent = async (name) => {
  let codec = "";
  const stats = await pcs[name].getStats();
  stats.forEach((s) => {
    if (s.type === "outbound-rtp" && s.kind === "video") { const c = stats.get(s.codecId); if (c) codec = c.mimeType; }
  });
  return codec;
};
true`;

async function mediaMode() {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  await p.evaluate(MEDIA_LIB);
  const post = async (url, sdp) => {
    const r = await fetch(url, { method: "POST", body: sdp, headers: { "content-type": "application/sdp" } });
    const body = await r.text();
    if (r.status !== 201) fail(url + ": " + r.status + " " + body);
    return { answer: body, location: new URL(r.headers.get("location"), url).href };
  };
  const streams = async () => (await (await fetch(`http://${addr}/streams`)).text()).split("\n");
  const publish = async (path, codec, w, h, scale = 1) => {
    const offer = await p.evaluate(`pubOffer(${JSON.stringify(path)}, ${JSON.stringify(codec)}, ${w}, ${h}, ${scale})`);
    const { answer, location } = await post(`http://${addr}/whip/${path}`, offer);
    await p.evaluate(`(async () => {
      const pc = pcs[${JSON.stringify(path)}];
      await pc.setRemoteDescription({ type: "answer", sdp: ${JSON.stringify(answer)} });
      await waitFor(() => pc.connectionState === "connected", 15000, "WHIP connected (" + pc.connectionState + ")");
      return true;
    })()`);
    // The hub stream goes live with the codec and the picture size of the first keyframe.
    let line = "";
    for (let i = 0; i < 100 && !/packets=[1-9]\d{2}/.test(line); i++) {
      await new Promise((r) => setTimeout(r, 100));
      line = (await streams()).find((l) => l.startsWith(path + " ")) || "";
    }
    const sentCodec = await p.evaluate(`sent(${JSON.stringify(path)})`);
    const want = { VP8: "VP8", VP9: "VP9", AV1: "AV1", H264: "H264" }[codec];
    if (!line.includes("tracks=" + want + ",Opus") && !line.includes("tracks=Opus," + want)) {
      fail(`${path}: hub has '${line}', Chrome sends ${sentCodec}`);
    }
    if (!line.includes(`size=${w}x${h}`)) fail(`${path}: hub has '${line}', want size ${w}x${h}`);
    return { line, location };
  };
  const results = [];
  for (const codec of ["VP8", "VP9", "AV1", "H264"]) {
    const path = "live/chrome_" + codec.toLowerCase();
    const { line, location } = await publish(path, codec, 320, 240);
    const viewer = path + "#whep";
    const offer = await p.evaluate(`playOffer(${JSON.stringify(viewer)})`);
    const { answer, location: wloc } = await post(`http://${addr}/whep/${path}`, offer);
    const st = await p.evaluate(`(async () => {
      const pc = pcs[${JSON.stringify(viewer)}];
      await pc.setRemoteDescription({ type: "answer", sdp: ${JSON.stringify(answer)} });
      const t0 = Date.now();
      let st = await inbound(${JSON.stringify(viewer)});
      while (Date.now() - t0 < 20000 && !(st.v >= 30 && st.a >= 50)) {
        await new Promise((r) => setTimeout(r, 200));
        st = await inbound(${JSON.stringify(viewer)});
      }
      return st;
    })()`);
    if (!(st.v >= 30 && st.a >= 50)) fail(`${codec} over WHEP: ${JSON.stringify(st)}`);
    if (st.codec.toLowerCase() !== "video/" + codec.toLowerCase()) fail(`${codec} over WHEP came as ${st.codec}`);
    for (const loc of [wloc, location]) await fetch(loc, { method: "DELETE" });
    await p.evaluate(`closePc(${JSON.stringify(viewer)}) && closePc(${JSON.stringify(path)})`);
    results.push(`${codec}: hub '${line.split(" subscribers")[0]}', WHEP ${st.v} frames decoded (${st.kf} keyframes) ${st.w}px, ${st.a} Opus packets`);
  }
  for (const r of results) console.log("ok: Chrome WHIP -> hub -> Chrome WHEP " + r);

  // Multivariant fMP4 LL-HLS: an AV1 ladder of two renditions (640x360, 320x180) published
  // from Chrome, played by Chrome's own HLS player (and hls.js when its CDN is reachable).
  // Players switch renditions of one codec (Chrome's own refuses a codec change).
  await publish("live/abr_hi", "AV1", 640, 360);
  await publish("live/abr_lo", "AV1", 320, 180, 2);
  const master = await (await fetch(`http://${addr}/live/abr.m3u8`)).text();
  const infs = master.split("\n").filter((l) => l.startsWith("#EXT-X-STREAM-INF:"));
  if (infs.length !== 2 || infs.some((l) => !/CODECS="av01\.[^"]*,opus"/.test(l))
      || !master.includes("RESOLUTION=640x360") || !master.includes("RESOLUTION=320x180")) {
    fail("multivariant playlist:\n" + master);
  }
  console.log("ok: multivariant playlist\n" + master.trim().split("\n").map((l) => "    " + l).join("\n"));
  const playNative = await p.evaluate(`(async () => {
    const v = document.createElement("video");
    if (!v.canPlayType("application/vnd.apple.mpegurl")) return "no native HLS";
    v.muted = true; v.autoplay = true;
    document.body.appendChild(v);
    let err = null;
    v.onerror = () => { err = v.error && (v.error.code + " " + v.error.message); };
    v.src = "http://${addr}/live/abr.m3u8";
    v.play().catch((e) => { err = String(e); });
    const t0 = Date.now();
    while (Date.now() - t0 < 25000 && !err && !(v.currentTime > 3 && v.videoWidth > 0)) await new Promise((r) => setTimeout(r, 200));
    const q = v.getVideoPlaybackQuality ? v.getVideoPlaybackQuality() : {};
    const r = { t: v.currentTime, w: v.videoWidth, h: v.videoHeight, frames: q.totalVideoFrames, err };
    v.remove();
    return r;
  })()`);
  // Chrome's built-in HLS player (new on desktop) is informational: on live playlists started
  // a few seconds earlier it often ends with "Segment queue never had any data" (its start
  // position), while hls.js below plays the same playlist.
  if (typeof playNative === "string") console.log("   Chrome native HLS: " + playNative);
  else if (playNative.err || !(playNative.t > 3 && playNative.w > 0)) console.log("   Chrome native HLS (informational): " + JSON.stringify(playNative));
  else console.log(`ok: Chrome native HLS played live/abr.m3u8: ${playNative.t.toFixed(1)} s, ${playNative.w}x${playNative.h}, ${playNative.frames} frames`);
  const hlsjs = await p.evaluate(`(async () => {
    try {
      await new Promise((res, rej) => {
        const s = document.createElement("script");
        s.src = "https://cdn.jsdelivr.net/npm/hls.js@1.5.20/dist/hls.min.js";
        s.onload = res; s.onerror = () => rej(new Error("unreachable"));
        document.head.appendChild(s);
        setTimeout(() => rej(new Error("timeout")), 10000);
      });
    } catch (e) { return "hls.js not loaded (" + e.message + "): skipped"; }
    if (!Hls.isSupported()) return "hls.js: no MSE";
    const v = document.createElement("video");
    v.muted = true;
    document.body.appendChild(v);
    const hls = new Hls({ lowLatencyMode: true });
    let err = null;
    hls.on(Hls.Events.ERROR, (_e, d) => { if (d.fatal) err = d.type + " " + d.details; });
    hls.loadSource("http://${addr}/live/abr.m3u8");
    hls.attachMedia(v);
    v.play().catch(() => {});
    const t0 = Date.now();
    while (Date.now() - t0 < 25000 && !err && !(v.currentTime > 3 && v.videoWidth > 0)) await new Promise((r) => setTimeout(r, 200));
    const levels = hls.levels.map((l) => l.width + "x" + l.height + " " + l.attrs.CODECS);
    const r = { t: v.currentTime, w: v.videoWidth, levels, level: hls.currentLevel, err };
    // Switch to the other rendition and keep playing.
    if (!err && levels.length === 2) {
      const t1 = v.currentTime;
      hls.currentLevel = 1 - Math.max(0, hls.currentLevel);
      const t2 = Date.now();
      while (Date.now() - t2 < 15000 && !err && !(v.currentTime > t1 + 3 && v.videoWidth === hls.levels[hls.currentLevel].width)) await new Promise((r) => setTimeout(r, 200));
      r.switched = { t: v.currentTime - t1, w: v.videoWidth, level: hls.currentLevel, err };
    }
    hls.destroy();
    return r;
  })()`);
  if (typeof hlsjs === "string") console.log("   " + hlsjs);
  else if (hlsjs.err || !(hlsjs.t > 3 && hlsjs.w > 0) || hlsjs.levels.length !== 2
           || !hlsjs.switched || hlsjs.switched.err || !(hlsjs.switched.t > 3)) fail("hls.js: " + JSON.stringify(hlsjs));
  else console.log(`ok: hls.js played live/abr.m3u8 (levels ${JSON.stringify(hlsjs.levels)}): ${hlsjs.t.toFixed(1)} s at ${hlsjs.w}px, then switched to level ${hlsjs.switched.level} (${hlsjs.switched.w}px) for ${hlsjs.switched.t.toFixed(1)} s`);
  p.close();
}

await mediaMode();
