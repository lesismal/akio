// Headless Chrome <-> only-webrtc, driven over the Chrome DevTools Protocol (no npm packages:
// Node >= 22 has fetch and WebSocket). Used by browser.sh.
//
//   node browser.mjs <cdp-port> offer <http-signalling-addr>   Chrome offers (data channel echo,
//                                                               fake camera + microphone, media
//                                                               echoed back must decode)
//   node browser.mjs <cdp-port> answer <listen-addr>            Chrome answers offers POSTed to
//                                                               http://<listen-addr>/ and echoes
//                                                               data channel messages
import http from "node:http";

const [port, mode, addr] = process.argv.slice(2);
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
    r.end("<!doctype html><title>only-webrtc</title>");
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

async function offerMode() {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  const offer = await p.evaluate(`(async () => {
    const pc = new RTCPeerConnection();
    window.pc = pc;
    const media = await navigator.mediaDevices.getUserMedia({ audio: true, video: { width: 320, height: 240 } });
    for (const t of media.getTracks()) pc.addTrack(t, media);
    window.remoteTracks = [];
    pc.ontrack = (e) => window.remoteTracks.push(e.track);
    const dc = pc.createDataChannel("chrome");
    window.dc = dc; window.got = [];
    dc.onmessage = (m) => window.got.push(typeof m.data === "string" ? m.data : "bin:" + m.data.byteLength);
    const lossy = pc.createDataChannel("chrome-lossy", { ordered: false, maxRetransmits: 0 });
    window.lossy = lossy; window.lossyGot = [];
    lossy.onmessage = (m) => window.lossyGot.push(m.data);
    await pc.setLocalDescription(await pc.createOffer());
    await gather(pc);
    return pc.localDescription.sdp;
  })()`);
  const resp = await fetch(`http://${addr}/`, { method: "POST", body: offer, headers: { "content-type": "application/sdp" } });
  const answer = await resp.text();
  if (!resp.ok) fail("signalling: " + answer);
  const r = await p.evaluate(`(async () => {
    await pc.setRemoteDescription({ type: "answer", sdp: ${JSON.stringify(answer)} });
    await waitFor(() => dc.readyState === "open", 15000, "data channel open (ICE " + pc.iceConnectionState + ")");
    for (let i = 0; i < 100; i++) dc.send("chrome message " + i);
    dc.send(new Uint8Array(70000));
    await waitFor(() => got.length >= 101, 15000, "echoes (" + got.length + ")");
    for (let i = 0; i < 100; i++) if (got[i] !== "chrome message " + i) throw new Error("echo " + i + ": " + got[i]);
    if (got[100] !== "bin:70000") throw new Error("binary echo: " + got[100]);
    await waitFor(() => lossy.readyState === "open", 5000, "lossy open");
    lossy.send("lossy");
    await waitFor(() => lossyGot.length > 0, 10000, "lossy echo");
    // Media: the server echoes our audio and video samples; Chrome must decode them.
    const decoded = async () => {
      let v = 0, a = 0, pli = 0, nack = 0;
      (await pc.getStats()).forEach((s) => {
        if (s.type === "inbound-rtp" && s.kind === "video") v = s.framesDecoded || 0;
        if (s.type === "inbound-rtp" && s.kind === "audio") a = s.packetsReceived || 0;
        if (s.type === "outbound-rtp" && s.kind === "video") { pli += s.pliCount || 0; nack += s.nackCount || 0; }
      });
      return { v, a, pli, nack };
    };
    let st;
    const t0 = Date.now();
    while (Date.now() - t0 < 20000) { st = await decoded(); if (st.v >= 30 && st.a >= 50) break; await new Promise((r) => setTimeout(r, 200)); }
    if (!(st.v >= 30 && st.a >= 50)) throw new Error("media echo: " + JSON.stringify(st));
    return "ok: Chrome offers: 100 ordered messages + a 70000-byte binary one + an unordered/unreliable one echoed; " +
      st.v + " echoed VP8 frames decoded, " + st.a + " echoed Opus packets received (Chrome sent " + st.pli + " PLI, " + st.nack + " NACK it got)";
  })()`);
  console.log(r);
  p.close();
}

async function answerMode() {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  const [host, hport] = addr.split(":");
  const srv = http.createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    try {
      const answer = await p.evaluate(`(async () => {
        const pc = new RTCPeerConnection();
        window.pc2 = pc;
        pc.ondatachannel = (e) => { const dc = e.channel; dc.onmessage = (m) => dc.send(m.data); };
        await pc.setRemoteDescription({ type: "offer", sdp: ${JSON.stringify(body)} });
        await pc.setLocalDescription(await pc.createAnswer());
        await gather(pc);
        return pc.localDescription.sdp;
      })()`);
      res.writeHead(201, { "content-type": "application/sdp", "content-length": Buffer.byteLength(answer) });
      res.end(answer);
    } catch (e) {
      res.writeHead(400);
      res.end(String(e));
    }
  });
  srv.listen(Number(hport), host, () => console.error("chrome answerer on " + addr));
}

if (mode === "offer") await offerMode();
else if (mode === "answer") await answerMode();
else fail("usage: browser.mjs <cdp-port> offer|answer <addr>");
