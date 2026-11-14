#!/usr/bin/env python3
"""libtorrent-rasterbar (python3-libtorrent) side of tools/interop/bittorrent/run.sh.

  lt.py seed  <torrent> <dir> <port> [options]     seed until killed
  lt.py leech <torrent|magnet> <dir> <port> [options]   download, exit 0 once complete
  options: --peer host:port  --utp-only  --tcp-only  --enc forced|enabled|disabled
           --dht host:port (enable the DHT, bootstrapping there)  --timeout secs
"""
import sys
import time

import libtorrent as lt

# peer_info::utp_socket (bit 17), which the 2.0 bindings do not export.
UTP_SOCKET = int(getattr(lt.peer_info, "utp_socket", 1 << 17))


def main():
    cmd, src, save, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    peers, dht, enc, timeout = [], None, "enabled", 120
    utp_only = tcp_only = False
    a = sys.argv[5:]
    i = 0
    while i < len(a):
        if a[i] == "--peer":
            h, p = a[i + 1].rsplit(":", 1)
            peers.append((h, int(p)))
            i += 1
        elif a[i] == "--dht":
            dht = a[i + 1]
            i += 1
        elif a[i] == "--enc":
            enc = a[i + 1]
            i += 1
        elif a[i] == "--timeout":
            timeout = int(a[i + 1])
            i += 1
        elif a[i] == "--utp-only":
            utp_only = True
        elif a[i] == "--tcp-only":
            tcp_only = True
        else:
            sys.exit("unknown option " + a[i])
        i += 1

    policy = {"forced": lt.enc_policy.forced, "enabled": lt.enc_policy.enabled,
              "disabled": lt.enc_policy.disabled}[enc]
    s = {
        "listen_interfaces": "127.0.0.1:%d" % port,
        "enable_dht": dht is not None,
        "enable_lsd": False,
        "enable_upnp": False,
        "enable_natpmp": False,
        "allow_multiple_connections_per_ip": True,
        "enable_outgoing_tcp": not utp_only,
        "enable_incoming_tcp": not utp_only,
        "enable_outgoing_utp": not tcp_only,
        "enable_incoming_utp": not tcp_only,
        "out_enc_policy": policy,
        "in_enc_policy": policy,
        "allowed_enc_level": lt.enc_level.rc4 if enc == "forced" else lt.enc_level.both,
        "alert_mask": lt.alert.category_t.error_notification | lt.alert.category_t.status_notification,
        "user_agent": "libtorrent-interop",
    }
    if dht:
        s["dht_bootstrap_nodes"] = dht
    sess = lt.session(s)
    if dht:
        # Everything runs on 127.0.0.1: let the DHT keep many nodes of one address.
        extra = {}
        for k in ("dht_restrict_routing_ips", "dht_restrict_search_ips", "dht_enforce_node_id",
                  "dht_prefer_verified_node_ids"):
            extra[k] = False
        try:
            sess.apply_settings(extra)
        except Exception as e:  # older bindings
            print("settings:", e, flush=True)
    if src.startswith("magnet:"):
        params = lt.parse_magnet_uri(src)
    else:
        params = lt.add_torrent_params()
        params.ti = lt.torrent_info(src)
    params.save_path = save
    h = sess.add_torrent(params)
    for p in peers:
        h.connect_peer(p)
    start = time.time()
    seen = set()
    last_connect = time.time()
    while True:
        for al in sess.pop_alerts():
            if al.category() & lt.alert.category_t.error_notification:
                print("lt alert:", al.message(), flush=True)
        st = h.status()
        for pi in h.get_peer_info():
            key = (pi.ip, bool(int(pi.flags) & UTP_SOCKET), bool(int(pi.flags) & int(lt.peer_info.rc4_encrypted)))
            if key not in seen:
                seen.add(key)
                print("lt peer %s:%d client=%r utp=%s rc4=%s" % (pi.ip[0], pi.ip[1], pi.client, key[1], key[2]), flush=True)
        if cmd == "leech":
            if st.is_seeding:
                print("lt complete: %d bytes in %.2fs, peers %s" % (st.total_wanted, time.time() - start, sorted(seen)), flush=True)
                return
            if time.time() - start > timeout:
                sys.exit("lt timed out: state=%s progress=%.3f peers=%d" % (st.state, st.progress, st.num_peers))
        elif st.is_seeding and time.time() - start < 1.0:
            print("lt seeding", flush=True)
        if peers and time.time() - last_connect > 5:
            last_connect = time.time()
            for p in peers:
                h.connect_peer(p)
        time.sleep(0.05)


if __name__ == "__main__":
    main()
