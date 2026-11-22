// Headless Chrome against the AES-128 HLS renditions with I-frame playlists that
// hls-iframes.sh serves (MPEG-TS on one address, fMP4 on the other), driven over the Chrome
// DevTools Protocol like browser.mjs (no npm packages: Node >= 22 has fetch and WebSocket).
//
//   node hls-iframes.mjs <cdp-port> <mpegts-addr> <fmp4-addr>
//
// Per format: the multivariant playlist live/cam.m3u8 must list an EXT-X-I-FRAME-STREAM-INF
// per rendition and its I-frame playlists must name `iframe-<n>` resources after an AES-128
// EXT-X-KEY; hls.js plays the multivariant playlist, then the H.264 I-frame playlist on its own
// as a media playlist (every I-frame decrypted and appended, frames decoded in MPEG-TS); Shaka
// Player plays the multivariant playlist and, in trick play (backwards: the playlists are live),
// fetches I-frames from its I-frame track, decrypts and decodes them (required for H.264 in
// fMP4; H.265 and MPEG-TS reported, see shaka()). Players come from jsDelivr: skipped when
// unreachable.
import http from "node:http";

const [port, tsAddr, mp4Addr] = process.argv.slice(2);
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

const load = (src, global) => `(async () => {
  if (window.${global}) return true;
  try {
    await new Promise((res, rej) => {
      const s = document.createElement("script");
      s.src = ${JSON.stringify(src)};
      s.onload = res; s.onerror = () => rej(new Error("unreachable"));
      document.head.appendChild(s);
      setTimeout(() => rej(new Error("timeout")), 10000);
    });
  } catch (e) { return e.message; }
  return true;
})()`;

// The playlists themselves.
async function playlists(addr, fmt) {
  const master = await (await fetch(`http://${addr}/live/cam.m3u8`)).text();
  const infs = master.split("\n").filter((l) => l.startsWith("#EXT-X-I-FRAME-STREAM-INF:"));
  if (infs.length !== 2) fail(`${fmt}: multivariant playlist:\n${master}`);
  for (const path of ["cam_avc", "cam_hevc"]) {
    const pl = await (await fetch(`http://${addr}/live/${path}/iframes.m3u8`)).text();
    const n = pl.split("\n").filter((l) => /^iframe-\d+\.(ts|m4s)$/.test(l)).length;
    if (!pl.includes("#EXT-X-I-FRAMES-ONLY") || !pl.includes("#EXT-X-KEY:METHOD=AES-128,URI=") || n < 3 || pl.includes("BYTERANGE")) {
      fail(`${fmt}: ${path}/iframes.m3u8:\n${pl}`);
    }
  }
  console.log(`ok: ${fmt} playlists: ${infs.length} I-frame streams, AES-128 I-frame resources`);
}

// hls.js: the multivariant playlist, then the I-frame playlist as a media playlist.
async function hlsjs(p, addr, fmt) {
  const r = await p.evaluate(`(async () => {
    const play = async (url, want) => {
      const v = document.createElement("video");
      v.muted = true;
      document.body.appendChild(v);
      const hls = new Hls();
      let err = null, decrypted = 0, buffered = 0;
      hls.on(Hls.Events.ERROR, (_e, d) => { if (d.fatal) err = d.type + " " + d.details; });
      // Buffered fragments that were AES-128 encrypted (hls.js decrypts them with WebCrypto).
      hls.on(Hls.Events.FRAG_BUFFERED, (_e, d) => {
        buffered++;
        if (d.frag.type === "main" && d.frag.decryptdata && d.frag.decryptdata.method === "AES-128") decrypted++;
      });
      hls.loadSource(url);
      hls.attachMedia(v);
      v.play().catch(() => {});
      const t0 = Date.now();
      while (Date.now() - t0 < 30000 && !err && !want(v, decrypted)) await new Promise((r) => setTimeout(r, 200));
      const q = v.getVideoPlaybackQuality();
      const r = { t: v.currentTime, w: v.videoWidth, frames: q.totalVideoFrames, decrypted, buffered, err };
      hls.destroy();
      v.remove();
      return r;
    };
    const main = await play("http://${addr}/live/cam.m3u8", (v) => v.currentTime > 3 && v.videoWidth > 0);
    const iframes = await play("http://${addr}/live/cam_avc/iframes.m3u8",
      (v, d) => d >= 4 && (${fmt === "fMP4"} || v.getVideoPlaybackQuality().totalVideoFrames >= 3));
    return { main, iframes };
  })()`);
  const { main, iframes } = r;
  if (main.err || !(main.t > 3 && main.w > 0) || main.decrypted < 1) fail(`hls.js ${fmt} live/cam.m3u8: ${JSON.stringify(main)}`);
  console.log(`ok: hls.js ${fmt} played live/cam.m3u8 (AES-128): ${main.t.toFixed(1)} s at ${main.w}px, ${main.decrypted} segments decrypted`);
  // fMP4 fragments go to MSE as they are (one 40 ms video sample per I-frame, gaps between
  // them in the video buffer), and Chrome does not render such a buffer as a slideshow: there
  // the check is that every I-frame decrypted and was appended (a wrong key or IV fails the
  // fragment's parsing); hls.js transmuxes MPEG-TS and the frames are decoded.
  const needFrames = fmt === "fMP4" ? 0 : 3;
  if (iframes.err || iframes.decrypted < 4 || !(iframes.frames >= needFrames) || !(iframes.w > 0)) {
    fail(`hls.js ${fmt} cam_avc/iframes.m3u8: ${JSON.stringify(iframes)}`);
  }
  console.log(`ok: hls.js ${fmt} played cam_avc/iframes.m3u8: ${iframes.decrypted} I-frames decrypted, ${iframes.frames} frames decoded at ${iframes.w}px`);
}

// Shaka Player: the multivariant playlist (the rendition of `codec`), then trick play
// backwards (the playlists are live) from the I-frame track.
async function shaka(p, addr, fmt, codec) {
  const r = await p.evaluate(`(async () => {
    shaka.polyfill.installAll();
    if (!shaka.Player.isBrowserSupported()) return "no MSE";
    if (!MediaSource.isTypeSupported('video/mp4; codecs="${codec === "avc1" ? "avc1.64000D" : "hvc1.1.6.L60.90"}"')) return "no ${codec} in this browser";
    const v = document.createElement("video");
    v.muted = true;
    document.body.appendChild(v);
    const player = new shaka.Player();
    await player.attach(v);
    player.configure({ preferredVideoCodecs: ["${codec}"] });
    let err = null;
    const fetched = [];
    player.addEventListener("error", (e) => { err = e.detail && (e.detail.code + " " + JSON.stringify(e.detail.data).slice(0, 300)); });
    player.getNetworkingEngine().registerResponseFilter((_type, resp) => { fetched.push(resp.uri); });
    try { await player.load("http://${addr}/live/cam.m3u8"); } catch (e) { return { err: "load " + e.code + " " + JSON.stringify(e.data).slice(0, 300) }; }
    v.play().catch(() => {});
    let t0 = Date.now();
    while (Date.now() - t0 < 30000 && !err && !(v.currentTime > 3 && v.videoWidth > 0)) await new Promise((r) => setTimeout(r, 200));
    const variant = player.getManifest().variants.find((x) => x.video && x.video.codecs.startsWith("${codec}"));
    const r = { t: v.currentTime, w: v.videoWidth, err, trickTrack: !!(variant && variant.video.trickModeVideo) };
    if (err || !variant) return r;
    const before = fetched.length;
    const f0 = v.getVideoPlaybackQuality().totalVideoFrames;
    player.trickPlay(-2);
    t0 = Date.now();
    const iframes = () => fetched.slice(before).filter((u) => /iframe-\\d+\\./.test(u)).length;
    while (Date.now() - t0 < 20000 && !err && iframes() < 1) await new Promise((r) => setTimeout(r, 200));
    await new Promise((r) => setTimeout(r, 1500));
    r.iframes = iframes();
    r.trickFrames = v.getVideoPlaybackQuality().totalVideoFrames - f0;
    r.err = err;
    player.cancelTrickPlay();
    await player.destroy();
    v.remove();
    return r;
  })()`);
  const what = `Shaka ${fmt} ${codec}`;
  if (typeof r === "string") { console.log(`   ${what}: ${r}: skipped`); return; }
  // Required for H.264 in fMP4. Reported for H.265 (Chrome's decoding of it depends on the
  // platform; on macOS VideoToolbox rejects this x265 sample in plain playback too) and for
  // MPEG-TS: Shaka 4.12.6's TS transmuxer fails (error 3018, in H264.parseInfo) on one of the
  // sample's two keyframes as a lone I-frame (AUD, SPS, PPS, IDR, no SEI), encrypted or not
  // (ADR-070's byte ranges of clear segments too), which ffmpeg decodes and Shaka plays
  // inside whole segments; and it often fetches no I-frame before reaching the live window's
  // start.
  const required = codec === "avc1" && fmt === "fMP4";
  const bad = (m) => (required ? fail(m) : console.log(`   (informational) ${m}`));
  if (r.err || !(r.t > 3 && r.w > 0) || !r.trickTrack) return bad(`${what} live/cam.m3u8: ${JSON.stringify(r)}`);
  console.log(`ok: ${what} played live/cam.m3u8 (AES-128): ${r.t.toFixed(1)} s at ${r.w}px, an I-frame track`);
  if (!(r.iframes >= 1) || !(r.trickFrames > 0)) return bad(`${what} trick play: ${JSON.stringify(r)}`);
  console.log(`ok: ${what} trick play: ${r.iframes} I-frames fetched from the I-frame track and decrypted, ${r.trickFrames} frames decoded`);
}

const p = await page();
// The first request starts the renditions' muxers: let them cut a few segments.
for (const addr of [tsAddr, mp4Addr]) await fetch(`http://${addr}/live/cam.m3u8`);
await new Promise((r) => setTimeout(r, 7000));
for (const [addr, fmt] of [[tsAddr, "MPEG-TS"], [mp4Addr, "fMP4"]]) await playlists(addr, fmt);
const hj = await p.evaluate(load("https://cdn.jsdelivr.net/npm/hls.js@1.5.20/dist/hls.min.js", "Hls"));
if (hj !== true) console.log(`   hls.js not loaded (${hj}): skipped`);
else for (const [addr, fmt] of [[tsAddr, "MPEG-TS"], [mp4Addr, "fMP4"]]) await hlsjs(p, addr, fmt);
const sk = await p.evaluate(load("https://cdn.jsdelivr.net/npm/shaka-player@4.12.6/dist/shaka-player.compiled.js", "shaka"));
if (sk !== true) console.log(`   Shaka Player not loaded (${sk}): skipped`);
else {
  for (const [addr, fmt] of [[tsAddr, "MPEG-TS"], [mp4Addr, "fMP4"]]) {
    for (const codec of ["avc1", "hvc1"]) await shaka(p, addr, fmt, codec);
  }
}
p.close();
