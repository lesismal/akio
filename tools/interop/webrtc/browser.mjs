// Headless Chrome <-> only-webrtc, driven over the Chrome DevTools Protocol (no npm packages:
// Node >= 22 has fetch and WebSocket). Used by browser.sh.
//
//   node browser.mjs <cdp-port> offer <http-signalling-addr>   Chrome offers (data channel echo,
//                                                               fake camera + microphone, media
//                                                               echoed back must decode)
//   node browser.mjs <cdp-port> answer <listen-addr> [tcp|relay|mdns]
//                                                               Chrome answers offers POSTed to
//                                                               http://<listen-addr>/ and echoes
//                                                               data channel messages (tcp: drops
//                                                               its UDP candidates; relay: checks
//                                                               the pair it used is the offer's
//                                                               relayed one; mdns: checks it is
//                                                               host to host, both sides' host
//                                                               candidates being mDNS names)
//   node browser.mjs <cdp-port> offer-maxcompat <http-addr>     Chrome offers with bundlePolicy
//                                                               "max-compat" and a "high"
//                                                               priority channel to a server
//                                                               that refuses BUNDLE: a transport
//                                                               per section (checked in Chrome's
//                                                               statistics), data and media echo
//   node browser.mjs <cdp-port> offer-tcp <http-addr>           Chrome offers, the answer's UDP
//                                                               candidates are dropped: ICE-TCP
//                                                               only, media and data
//   node browser.mjs <cdp-port> offer-relay <http-addr> <turn-url>
//                                                               Chrome offers with
//                                                               iceTransportPolicy "relay" through
//                                                               the TURN server at <turn-url>
//                                                               (alice/wonderland)
//   node browser.mjs <cdp-port> simulcast <http-addr>           Chrome publishes three VP8
//                                                               simulcast layers to the only SFU
//                                                               (sfu mode), then views: the
//                                                               simulcast line and the selected
//                                                               layer, switched l -> m -> h
//   node browser.mjs <cdp-port> fec <http-addr> [nack] [secs]   Chrome offers VP8 video (with
//                                                               its FEC payload types) to the
//                                                               fec-server, the server echoes it;
//                                                               without "nack" NACK is removed
//                                                               from the offer (FEC is the only
//                                                               repair); prints the answer's
//                                                               FEC / feedback lines and the
//                                                               video statistics as JSON
//                                                               (DUMP_SDP=1: both SDPs too)
//   node browser.mjs <cdp-port> red <http-addr> [secs]          the same with Opus audio (and
//                                                               Chrome's RED) instead of video
//   node browser.mjs <cdp-port> simulcast-fec <http-addr> [secs]
//                                                               Chrome publishes three VP8
//                                                               simulcast layers (with its
//                                                               red/ulpfec, NACK removed) to the
//                                                               fec-server; prints per-layer
//                                                               sending statistics as JSON
//
// PC_CONFIG (JSON) is passed to Chrome's RTCPeerConnection in every mode (e.g.
// {"rtpHeaderEncryptionPolicy":"require"} for cryptex, which needs
// --enable-experimental-web-platform-features in Chrome 157). The offer modes print the DTLS
// version Chrome reports (tlsVersion: FEFD = DTLS 1.2, FEFC = DTLS 1.3); answer mode "media"
// sends the fake microphone to the offerer and prints "chrome: audio <packets received>
// <packets sent> <DTLS transport>".
import http from "node:http";

const [port, mode, addr] = process.argv.slice(2);
const PC = process.env.PC_CONFIG || "{}";
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
  // A fresh tab per run: a page left over from the previous run (its peer connections still
  // open) must not race this run's navigation.
  const t = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
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
  return {
    evaluate,
    close: async () => {
      await fetch(`http://127.0.0.1:${port}/json/close/${t.id}`, { signal: AbortSignal.timeout(2000) }).catch(() => {});
      ws.close();
      blank.close();
    },
  };
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

// The selected candidate pair, as getStats reports it.
const PAIR_LIB = `
window.selectedPair = async (pc) => {
  const st = await pc.getStats();
  let pair;
  st.forEach((s) => { if (s.type === "transport" && s.selectedCandidatePairId) pair = st.get(s.selectedCandidatePairId); });
  if (!pair) st.forEach((s) => { if (s.type === "candidate-pair" && s.nominated && s.state === "succeeded") pair = s; });
  if (!pair) return null;
  const l = st.get(pair.localCandidateId), r = st.get(pair.remoteCandidateId);
  return { local: l.candidateType + "/" + l.protocol + (l.relayProtocol ? "/" + l.relayProtocol : "") + " " + l.address + ":" + l.port,
           remote: r.candidateType + "/" + r.protocol + " " + r.address + ":" + r.port,
           localType: l.candidateType, localProtocol: l.protocol, relayProtocol: l.relayProtocol || "", remoteProtocol: r.protocol };
};
true`;

// The DTLS transport as Chrome reports it.
const DTLS_LIB = `
window.dtlsInfo = async (pc) => {
  let t = null;
  (await pc.getStats()).forEach((s) => { if (s.type === "transport" && s.tlsVersion) t = s; });
  return t ? { tlsVersion: t.tlsVersion, dtlsCipher: t.dtlsCipher, srtpCipher: t.srtpCipher, dtlsRole: t.dtlsRole } : null;
};
true`;

const onlyTcp = (sdp) => sdp.split("\r\n").filter((l) => !l.startsWith("a=candidate") || l.includes(" tcp ")).join("\r\n");

async function offerMode(how, turnUrl) {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  await p.evaluate(PAIR_LIB);
  await p.evaluate(DTLS_LIB);
  const config = how === "relay"
    ? { iceServers: [{ urls: turnUrl, username: "alice", credential: "wonderland" }], iceTransportPolicy: "relay" }
    : how === "maxcompat" ? { bundlePolicy: "max-compat" } : {};
  const dcInit = how === "maxcompat" ? { priority: "high" } : {};
  Object.assign(config, JSON.parse(PC));
  const offer = await p.evaluate(`(async () => {
    const pc = new RTCPeerConnection(${JSON.stringify(config)});
    window.pc = pc;
    const media = await navigator.mediaDevices.getUserMedia({ audio: true, video: { width: 320, height: 240 } });
    for (const t of media.getTracks()) pc.addTrack(t, media);
    window.remoteTracks = [];
    pc.ontrack = (e) => window.remoteTracks.push(e.track);
    const dc = pc.createDataChannel("chrome", ${JSON.stringify(dcInit)});
    window.dc = dc; window.got = [];
    dc.onmessage = (m) => window.got.push(typeof m.data === "string" ? m.data : "bin:" + m.data.byteLength);
    const lossy = pc.createDataChannel("chrome-lossy", { ordered: false, maxRetransmits: 0 });
    window.lossy = lossy; window.lossyGot = [];
    lossy.onmessage = (m) => window.lossyGot.push(m.data);
    await pc.setLocalDescription(await pc.createOffer());
    await gather(pc);
    return pc.localDescription.sdp;
  })()`);
  if (how === "relay" && !/ typ relay/.test(offer)) fail("Chrome gathered no relayed candidate through " + turnUrl);
  const resp = await fetch(`http://${addr}/`, { method: "POST", body: offer, headers: { "content-type": "application/sdp" } });
  let answer = await resp.text();
  if (!resp.ok) fail("signalling: " + answer);
  if (how === "maxcompat" && /a=group:BUNDLE/.test(answer)) fail("the answer bundles:\n" + answer);
  if (how === "tcp") {
    answer = onlyTcp(answer);
    if (!/ tcp .*tcptype passive/.test(answer)) fail("no passive TCP candidate in the answer:\n" + answer);
  }
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
    const sel = await selectedPair(pc);
    const dtls = await dtlsInfo(pc);
    const how = ${JSON.stringify(how || "")};
    if (how === "tcp" && !(sel && sel.localProtocol === "tcp" && sel.remoteProtocol === "tcp")) throw new Error("not over TCP: " + JSON.stringify(sel));
    if (how === "relay" && !(sel && sel.localType === "relay")) throw new Error("not relayed: " + JSON.stringify(sel));
    let transports = 0, connected = 0;
    (await pc.getStats()).forEach((s) => { if (s.type === "transport") { transports++; if (s.dtlsState === "connected") connected++; } });
    if (how === "maxcompat" && !(transports >= 3 && connected >= 3)) throw new Error("transports: " + transports + ", connected " + connected);
    if (how === "maxcompat") st.transports = transports + " (Chrome's channel priority: " + dc.priority + ")";
    return "ok: Chrome offers" + (how ? " (" + how + " only)" : "") + ": 100 ordered messages + a 70000-byte binary one + an unordered/unreliable one echoed; " +
      st.v + " echoed VP8 frames decoded, " + st.a + " echoed Opus packets received (Chrome sent " + st.pli + " PLI, " + st.nack + " NACK it got); " +
      (st.transports ? st.transports + " transports; " : "") + "pair " +
      (sel ? sel.local + " -> " + sel.remote : "?") + "; dtls " + JSON.stringify(dtls);
  })()`);
  console.log(r);
  await p.close();
  process.exit(0);
}

async function answerMode(how) {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  await p.evaluate(PAIR_LIB);
  await p.evaluate(DTLS_LIB);
  const [host, hport] = addr.split(":");
  const srv = http.createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    try {
      const answer = await p.evaluate(`(async () => {
        const pc = new RTCPeerConnection(${PC});
        window.pc2 = pc;
        pc.ondatachannel = (e) => { const dc = e.channel; window.dcPriority = dc.priority; dc.onmessage = (m) => dc.send(m.data); };
        await pc.setRemoteDescription({ type: "offer", sdp: ${JSON.stringify(body)} });
        if (${JSON.stringify(how || "")} === "media" || ${JSON.stringify(how || "")} === "nobundle") {
          // Our microphone to the offerer's audio line.
          const mic = (await navigator.mediaDevices.getUserMedia({ audio: true })).getAudioTracks()[0];
          for (const t of pc.getTransceivers()) if (t.receiver.track.kind === "audio") { t.direction = "sendrecv"; await t.sender.replaceTrack(mic); }
        }
        await pc.setLocalDescription(await pc.createAnswer());
        await gather(pc);
        const sdp = pc.localDescription.sdp;
        return ${JSON.stringify(how || "")} === "tcp" ? sdp.split("\\r\\n").filter((l) => !l.startsWith("a=candidate") || l.includes(" tcp ")).join("\\r\\n") : sdp;
      })()`);
      res.writeHead(201, { "content-type": "application/sdp", "content-length": Buffer.byteLength(answer) });
      res.end(answer);
      if (how === "media") {
        let st = null;
        for (let i = 0; i < 100; i++) {
          await new Promise((r) => setTimeout(r, 200));
          st = await p.evaluate(`(async () => { let r = 0, s = 0; (await pc2.getStats()).forEach((x) => { if (x.type === "inbound-rtp" && x.kind === "audio") r = x.packetsReceived; if (x.type === "outbound-rtp" && x.kind === "audio") s = x.packetsSent; }); return [r, s]; })()`);
          if (st[0] > 100 && st[1] > 100) break;
        }
        console.log("chrome: audio " + st[0] + " " + st[1] + " " + JSON.stringify(await p.evaluate("dtlsInfo(window.pc2)")));
      } else if (how === "nobundle") {
        // A transport per section of an offer without BUNDLE, and the channel's priority.
        // (Chrome 157 has no RTCDataChannel.priority: it prints "undefined".)
        let r = null;
        for (let i = 0; i < 75; i++) {
          await new Promise((r) => setTimeout(r, 100));
          r = await p.evaluate(`(async () => { let t = 0, c = 0; (await pc2.getStats()).forEach((s) => { if (s.type === "transport") { t++; if (s.dtlsState === "connected") c++; } }); return [t, c, String(window.dcPriority)]; })()`);
          if (r[1] >= 2) break;
        }
        const ok = r && r[1] >= 2 && !/a=group:BUNDLE/.test(answer);
        console.log((ok ? "chrome: nobundle ok" : "FAIL chrome: nobundle") + ": transports " + r[0] + ", connected " + r[1] + ", channel priority " + r[2]);
      } else if (how) {
        // The pair Chrome uses: over TCP ("tcp"), to the offer's relayed candidate ("relay"),
        // or host to host, the offer's host candidate being an mDNS name ("mdns").
        let sel = null;
        for (let i = 0; i < 50 && !sel; i++) {
          await new Promise((r) => setTimeout(r, 200));
          sel = await p.evaluate("selectedPair(window.pc2)");
        }
        const ok = how === "tcp" ? sel && sel.localProtocol === "tcp"
          // Chrome's host candidate (an mDNS name), to ours: a host candidate it resolved, or
          // peer-reflexive when our check arrived first.
          : how === "mdns" ? sel && sel.localType === "host" && /^(host|prflx)\/udp/.test(sel.remote)
          : sel && sel.remote.startsWith("relay");
        console.log((ok ? "chrome: pair ok (" : "FAIL chrome: pair (") + how + "): " + JSON.stringify(sel));
      }
    } catch (e) {
      res.writeHead(400);
      res.end(String(e));
    }
  });
  srv.listen(Number(hport), host, () => console.error("chrome answerer on " + addr));
}

async function simulcastMode() {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  const post = async (path, body) => {
    const r = await fetch(`http://${addr}${path}`, { method: "POST", body, headers: { "content-type": "application/sdp" } });
    const t = await r.text();
    if (!r.ok) fail("signalling " + path + ": " + t);
    return t;
  };
  // Publish: three VP8 layers of a 1280x720 fake camera.
  const offer = await p.evaluate(`(async () => {
    const pc = new RTCPeerConnection(${PC});
    window.pub = pc;
    const media = await navigator.mediaDevices.getUserMedia({ video: { width: 1280, height: 720 } });
    const tr = pc.addTransceiver(media.getVideoTracks()[0], { direction: "sendonly", sendEncodings: [
      { rid: "l", scaleResolutionDownBy: 4 }, { rid: "m", scaleResolutionDownBy: 2 }, { rid: "h" } ] });
    const vp8 = RTCRtpSender.getCapabilities("video").codecs.filter((c) => c.mimeType === "video/VP8");
    tr.setCodecPreferences(vp8);
    await pc.setLocalDescription(await pc.createOffer());
    await gather(pc);
    return pc.localDescription.sdp;
  })()`);
  const answer = await post("/publish", offer);
  if (!/a=simulcast:recv/.test(answer)) fail("the SFU's answer accepts no simulcast:\n" + answer);
  const pubStats = await p.evaluate(`(async () => {
    await pub.setRemoteDescription({ type: "answer", sdp: ${JSON.stringify(answer)} });
    await waitFor(() => pub.connectionState === "connected", 15000, "publisher connected (" + pub.connectionState + ")");
    const sent = async () => { const m = {}; (await pub.getStats()).forEach((s) => { if (s.type === "outbound-rtp" && s.rid) m[s.rid] = { frames: s.framesSent || 0, w: s.frameWidth || 0 }; }); return m; };
    let m; const t0 = Date.now();
    while (Date.now() - t0 < 15000) { m = await sent(); if (["l","m","h"].every((r) => m[r] && m[r].frames > 30)) break; await new Promise((r) => setTimeout(r, 200)); }
    if (!["l","m","h"].every((r) => m[r] && m[r].frames > 30)) throw new Error("layers not all sent: " + JSON.stringify(m));
    return m;
  })()`);
  // View: the SFU offers a simulcast line and a plain one.
  const viewOffer = await post("/view", "");
  const viewAnswer = await p.evaluate(`(async () => {
    const pc = new RTCPeerConnection(${PC});
    window.view = pc;
    window.ctlGot = [];
    pc.ondatachannel = (e) => { window.ctl = e.channel; e.channel.onmessage = (m) => ctlGot.push(m.data); };
    await pc.setRemoteDescription({ type: "offer", sdp: ${JSON.stringify(viewOffer)} });
    const ans = await pc.createAnswer();
    // NO_NACK: FEC is the only repair of what the SFU sends (munged before
    // setLocalDescription, so Chrome does not NACK either).
    if (${!!process.env.NO_NACK}) ans.sdp = ans.sdp.split("\\r\\n").filter((l) => !/^a=rtcp-fb:\\d+ nack$/.test(l)).join("\\r\\n");
    await pc.setLocalDescription(ans);
    await gather(pc);
    return pc.localDescription.sdp;
  })()`);
  if (process.env.DUMP_SDP) console.log("view offer:\n" + viewOffer + "\nview answer:\n" + viewAnswer);
  const chromeSimulcast = /a=simulcast:recv/.test(viewAnswer);
  await post("/view-answer", viewAnswer);
  const r = await p.evaluate(`(async () => {
    await waitFor(() => view.connectionState === "connected", 15000, "viewer connected (" + view.connectionState + ")");
    await waitFor(() => window.ctl && ctl.readyState === "open", 10000, "ctl channel");
    const mids = view.getTransceivers().map((t) => t.mid);
    const inbound = async () => { const m = {}; (await view.getStats()).forEach((s) => { if (s.type === "inbound-rtp" && s.kind === "video") m[s.mid] = { dec: s.framesDecoded || 0, w: s.frameWidth || 0 }; }); return m; };
    const [simMid, plainMid] = mids;
    const out = [];
    // The simulcast line: Chrome does not receive simulcast, so it gets the first layer.
    let m; let t0 = Date.now();
    while (Date.now() - t0 < 15000) { m = await inbound(); if (m[simMid] && m[simMid].dec > 30) break; await new Promise((r) => setTimeout(r, 200)); }
    if (!(m[simMid] && m[simMid].dec > 30)) throw new Error("simulcast line not decoded: " + JSON.stringify(m));
    let simIn = {};
    (await view.getStats()).forEach((s) => { if (s.type === "inbound-rtp" && s.mid === simMid) simIn = s; });
    out.push("simulcast line " + m[simMid].dec + " frames " + m[simMid].w + "px, " + (simIn.fecPacketsReceived || 0) + " FEC packets (" +
      (simIn.fecPacketsDiscarded || 0) + " discarded), " + (simIn.packetsReceived || 0) + " packets");
    // The plain line: layer selection.
    const widths = {};
    for (const layer of ["l", "m", "h"]) {
      ctl.send("layer " + layer);
      const before = (await inbound())[plainMid]?.dec || 0;
      let w = 0; t0 = Date.now();
      while (Date.now() - t0 < 15000) {
        m = await inbound();
        const x = m[plainMid];
        if (x && x.dec > before + 20 && x.w && (layer === "l" || x.w > widths[layer === "m" ? "l" : "m"])) { w = x.w; break; }
        await new Promise((r) => setTimeout(r, 200));
      }
      if (!w) throw new Error("layer " + layer + " not decoded: " + JSON.stringify(m) + " " + JSON.stringify(widths));
      widths[layer] = w;
      out.push("layer " + layer + " " + w + "px");
    }
    // VIEW_SECS: how much of the simulcast line (the first layer, h) decodes over that time.
    const secs = ${Number(process.env.VIEW_SECS || 0)};
    if (secs) {
      const sim = async () => { let x = {}; (await view.getStats()).forEach((s) => { if (s.type === "inbound-rtp" && s.mid === simMid) x = s; }); return x; };
      const sentH = async () => { let f = 0; (await pub.getStats()).forEach((s) => { if (s.type === "outbound-rtp" && s.rid === "h") f = s.framesSent; }); return f; };
      const [a0, h0] = [await sim(), await sentH()];
      await new Promise((r) => setTimeout(r, secs * 1000));
      const [a1, h1] = [await sim(), await sentH()];
      window.viewStats = { decoded: a1.framesDecoded - a0.framesDecoded, sent: h1 - h0, lost: a1.packetsLost - a0.packetsLost,
        freezes: (a1.freezeCount || 0) - (a0.freezeCount || 0), nack: a1.nackCount, pli: (a1.pliCount || 0) - (a0.pliCount || 0) };
      out.push("view " + JSON.stringify(window.viewStats));
    }
    return out.join(", ");
  })()`);
  console.log("ok: simulcast: Chrome sent " + JSON.stringify(pubStats) + "; the SFU's simulcast offer " +
    (chromeSimulcast ? "was accepted" : "fell back to its first layer (Chrome does not receive simulcast)") + "; " + r);
  await p.close();
  process.exit(0);
}

async function fecMode(nack, secs, kind = "video") {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  const offer = await p.evaluate(`(async () => {
    const pc = new RTCPeerConnection(${PC});
    window.pc = pc;
    const kind = ${JSON.stringify(kind)};
    // Received audio must be played out for Chrome to count (and conceal) samples.
    pc.ontrack = (e) => { const a = new Audio(); a.srcObject = new MediaStream([e.track]); a.play().catch(() => {}); window.player = a; };
    const media = await navigator.mediaDevices.getUserMedia(kind === "audio" ? { audio: true } : { video: { width: 640, height: 480 } });
    const tr = pc.addTransceiver(media.getTracks()[0], { direction: "sendrecv" });
    const keep = kind === "audio" ? ["audio/opus", "audio/red"] : ["video/VP8", "video/rtx", "video/red", "video/ulpfec", "video/flexfec-03"];
    tr.setCodecPreferences(RTCRtpReceiver.getCapabilities(kind).codecs.filter((c) => keep.includes(c.mimeType)));
    const o = await pc.createOffer();
    // Without NACK (munged before setLocalDescription, so Chrome does not NACK either).
    if (${!nack}) o.sdp = o.sdp.split("\\r\\n").filter((l) => !/^a=rtcp-fb:\\d+ nack$/.test(l)).join("\\r\\n");
    await pc.setLocalDescription(o);
    await gather(pc);
    return pc.localDescription.sdp;
  })()`);
  const resp = await fetch(`http://${addr}/`, { method: "POST", body: offer, headers: { "content-type": "application/sdp" } });
  const answer = await resp.text();
  if (!resp.ok) fail("signalling: " + answer);
  if (process.env.DUMP_SDP) console.log("offer:\n" + offer + "\nanswer:\n" + answer);
  const neg = answer.split("\r\n").filter((l) => /red\/|ulpfec|flexfec|FEC-FR|ccfb|tmmbr|rtcp-xr|rrtr| nack$|^m=|cryptex/.test(l));
  const r = await p.evaluate(`(async () => {
    await pc.setRemoteDescription({ type: "answer", sdp: ${JSON.stringify(answer)} });
    await waitFor(() => pc.connectionState === "connected", 15000, "connected (" + pc.connectionState + ")");
    const stats = async () => {
      const o = { in: {}, out: {}, pair: {} };
      (await pc.getStats()).forEach((s) => {
        if (s.type === "inbound-rtp" && s.kind === "audio") o.audioIn = { packetsReceived: s.packetsReceived, packetsLost: s.packetsLost, concealedSamples: s.concealedSamples,
          totalSamplesReceived: s.totalSamplesReceived, concealmentEvents: s.concealmentEvents, fecPacketsReceived: s.fecPacketsReceived, fecPacketsDiscarded: s.fecPacketsDiscarded };
        if (s.type === "outbound-rtp" && s.kind === "audio") o.audioOut = { packetsSent: s.packetsSent, bytesSent: s.bytesSent, codec: s.codecId };
        if (s.type === "inbound-rtp" && s.kind === "video") o.in = { framesDecoded: s.framesDecoded, packetsReceived: s.packetsReceived, packetsLost: s.packetsLost,
          fecPacketsReceived: s.fecPacketsReceived, fecPacketsDiscarded: s.fecPacketsDiscarded, fecBytesReceived: s.fecBytesReceived, nackCount: s.nackCount, pliCount: s.pliCount,
          freezeCount: s.freezeCount, totalFreezesDuration: s.totalFreezesDuration, framesDropped: s.framesDropped, retransmittedPacketsReceived: s.retransmittedPacketsReceived,
          packetsReceivedWithEct1: s.packetsReceivedWithEct1, packetsReceivedWithCe: s.packetsReceivedWithCe };
        if (s.type === "transport" && s.tlsVersion) o.dtls = { tlsVersion: s.tlsVersion, srtpCipher: s.srtpCipher };
        if (s.type === "outbound-rtp" && s.kind === "video") o.out = { packetsSent: s.packetsSent, bytesSent: s.bytesSent, retransmittedPacketsSent: s.retransmittedPacketsSent,
          nackCount: s.nackCount, pliCount: s.pliCount, targetBitrate: s.targetBitrate, framesSent: s.framesSent };
        if (s.type === "candidate-pair" && s.nominated) o.pair = { availableOutgoingBitrate: s.availableOutgoingBitrate, currentRoundTripTime: s.currentRoundTripTime };
        if (s.type === "remote-inbound-rtp" && s.kind === "video") o.remoteIn = { fractionLost: s.fractionLost, packetsLost: s.packetsLost, roundTripTime: s.roundTripTime };
      });
      return o;
    };
    const t0 = Date.now();
    let mid = null;
    while (Date.now() - t0 < ${secs} * 1000) {
      await new Promise((r) => setTimeout(r, 1000));
      if (!mid && Date.now() - t0 > ${secs} * 500) mid = await stats();
    }
    const end = await stats();
    end.lastHalfBitrate = mid && end.out.bytesSent ? Math.round((end.out.bytesSent - mid.out.bytesSent) * 8 / (${secs} / 2)) : null;
    return end;
  })()`);
  console.log("answer: " + JSON.stringify(neg));
  console.log("stats: " + JSON.stringify(r));
  await p.close();
  process.exit(0);
}

async function simulcastFecMode(secs) {
  const p = await page();
  await p.evaluate(PAGE_LIB);
  const offer = await p.evaluate(`(async () => {
    const pc = new RTCPeerConnection(${PC});
    window.pc = pc;
    const media = await navigator.mediaDevices.getUserMedia({ video: { width: 1280, height: 720 } });
    const tr = pc.addTransceiver(media.getVideoTracks()[0], { direction: "sendonly", sendEncodings: [
      { rid: "l", scaleResolutionDownBy: 4 }, { rid: "m", scaleResolutionDownBy: 2 }, { rid: "h" } ] });
    const keep = ["video/VP8", "video/rtx", "video/red", "video/ulpfec"];
    tr.setCodecPreferences(RTCRtpSender.getCapabilities("video").codecs.filter((c) => keep.includes(c.mimeType)));
    const o = await pc.createOffer();
    o.sdp = o.sdp.split("\\r\\n").filter((l) => !/^a=rtcp-fb:\\d+ nack$/.test(l)).join("\\r\\n");
    await pc.setLocalDescription(o);
    await gather(pc);
    return pc.localDescription.sdp;
  })()`);
  const resp = await fetch(`http://${addr}/`, { method: "POST", body: offer, headers: { "content-type": "application/sdp" } });
  const answer = await resp.text();
  if (!resp.ok) fail("signalling: " + answer);
  const neg = answer.split("\r\n").filter((l) => /red\/|ulpfec|simulcast| nack$/.test(l));
  const r = await p.evaluate(`(async () => {
    await pc.setRemoteDescription({ type: "answer", sdp: ${JSON.stringify(answer)} });
    await waitFor(() => pc.connectionState === "connected", 15000, "connected (" + pc.connectionState + ")");
    await new Promise((r) => setTimeout(r, ${secs} * 1000));
    const o = {};
    (await pc.getStats()).forEach((s) => { if (s.type === "outbound-rtp" && s.rid) o[s.rid] = { framesSent: s.framesSent, packetsSent: s.packetsSent, fecPacketsSent: s.fecPacketsSent, nackCount: s.nackCount }; });
    return o;
  })()`);
  console.log("answer: " + JSON.stringify(neg));
  console.log("stats: " + JSON.stringify(r));
  await p.close();
  process.exit(0);
}

// The one-shot modes exit when done (a closing DevTools socket must not keep Node alive).
if (mode === "offer") await offerMode();
else if (mode === "offer-tcp") await offerMode("tcp");
else if (mode === "offer-maxcompat") await offerMode("maxcompat");
else if (mode === "offer-relay") await offerMode("relay", process.argv[5]);
else if (mode === "answer") await answerMode(process.argv[5]);
else if (mode === "simulcast") await simulcastMode();
else if (mode === "fec") await fecMode(process.argv[5] === "nack", Number(process.argv[6] || 20));
else if (mode === "red") await fecMode(false, Number(process.argv[5] || 20), "audio");
else if (mode === "simulcast-fec") await simulcastFecMode(Number(process.argv[5] || 15));
else fail("usage: browser.mjs <cdp-port> offer|offer-tcp|offer-relay|answer|simulcast|fec|red|simulcast-fec <addr> ...");
