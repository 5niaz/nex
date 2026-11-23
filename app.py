# -*- coding: utf-8 -*-
"""Nexus — lightweight service status and endpoint gateway.
Standard Python, no external dependencies.
Builds live endpoint descriptors from the Host header,
relays WebSocket upgrades to the local core process,
and provides basic health checks.
"""
import base64
import json
import os
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
CREDS = json.load(open(os.path.join(BASE, "creds.json"), encoding="utf-8"))

RELAY = {"/s1": 10001, "/s2": 10002, "/s3": 10003}
ACCESS_KEY = CREDS["access_key"]

STATUS_CACHE = {"t": 0.0, "data": None}
STATUS_LOCK = threading.Lock()


def clean_host(h):
    if not h:
        return ""
    h = h.strip().split(",")[0]
    if ":" in h and "]" not in h:
        h = h.rsplit(":", 1)[0]
    return h


def live_uris(host):
    """Generate three live endpoint descriptors for this host."""
    ep1 = (
        f"vless://{CREDS['id1']}@{host}:443"
        f"?encryption=none&security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=%2Fs1"
        "#Nexus-1"
    )
    ep2_json = {
        "v": "2", "ps": "Nexus-2", "add": host, "port": "443",
        "id": CREDS["id2"], "aid": "0", "net": "ws", "type": "none",
        "host": host, "path": "/s2", "tls": "tls", "sni": host,
    }
    ep2 = "vmess://" + base64.b64encode(json.dumps(ep2_json).encode()).decode()
    ep3 = (
        f"trojan://{CREDS['secret3']}@{host}:443"
        f"?security=tls&sni={host}&fp=chrome&type=ws&host={host}&path=%2Fs3"
        "#Nexus-3"
    )
    return {"ep1": ep1, "ep2": ep2, "ep3": ep3}


# ------------------------------------------------------------ health probes

def _readline(sock):
    buf = b""
    while b"\r\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace").strip()


def probe_dns(host):
    t0 = time.time()
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return round((time.time() - t0) * 1000), infos[0][4][0]


def probe_tls(host):
    t0 = time.time()
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host):
            pass
    return round((time.time() - t0) * 1000)


def probe_edge_http(host):
    t0 = time.time()
    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as s:
            s.sendall(req.encode())
            line = _readline(s)
    return round((time.time() - t0) * 1000), line


def probe_ws(host, path):
    t0 = time.time()
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as s:
            s.sendall(req.encode())
            line = _readline(s)
    return round((time.time() - t0) * 1000), line


def probe_local(port):
    t0 = time.time()
    with socket.create_connection(("127.0.0.1", port), timeout=3):
        pass
    return round((time.time() - t0) * 1000)


def run_status(host):
    checks = []

    def add(name, fn, expect=None):
        try:
            out = fn()
            ms, *rest = out
            detail = rest[0] if rest else ""
            ok = True
            if expect == "101":
                ok = detail.startswith("HTTP/1.1 101")
            elif expect == "200":
                ok = " 200" in detail
            checks.append({"name": name, "ok": ok, "ms": ms, "detail": detail[:90]})
        except Exception as exc:
            checks.append({"name": name, "ok": False, "ms": 0, "detail": f"{type(exc).__name__}: {exc}"[:90]})

    add("dns", lambda: probe_dns(host))
    add("tls-443", lambda: (probe_tls(host),))
    add("edge-http", lambda: probe_edge_http(host), expect="200")
    for path, name in [("/s1", "ws-1"), ("/s2", "ws-2"), ("/s3", "ws-3")]:
        add(name, lambda p=path: probe_ws(host, p), expect="101")
    for port, name in [(10001, "local-1"), (10002, "local-2"), (10003, "local-3")]:
        add(name, lambda pp=port: (probe_local(pp),))
    return {"host": host, "ts": int(time.time()), "checks": checks}


def get_status(host):
    with STATUS_LOCK:
        now = time.time()
        if STATUS_CACHE["data"] and STATUS_CACHE["data"]["host"] == host and now - STATUS_CACHE["t"] < 60:
            return STATUS_CACHE["data"]
        data = run_status(host)
        STATUS_CACHE["t"] = now
        STATUS_CACHE["data"] = data
        return data


# ------------------------------------------------------------ page template

TEMPLATES = [
    ("Template-A", "ss://" + base64.b64encode(f"aes-256-gcm:{CREDS['secret4']}".encode()).decode() + "@YOUR_SERVER:8388#Nexus-A"),
    ("Template-B", "hysteria2://" + CREDS["secret3"] + "@YOUR_SERVER:443/?sni=YOUR_SERVER&insecure=0#Nexus-B"),
    ("Template-C", "tuic://" + CREDS["id1"] + ":" + CREDS["secret3"] + "@YOUR_SERVER:443?sni=YOUR_SERVER&congestion_control=bbr&alpn=h3#Nexus-C"),
    ("Template-D", "vless://" + CREDS["id1"] + "@YOUR_SERVER:443?encryption=none&security=reality&sni=YOUR_SNI&pbk=YOUR_PUBLIC_KEY&fp=chrome&type=tcp&flow=xtls-rprx-vision#Nexus-D"),
]
TEMPLATE_NOTE = "These are placeholder templates. Replace YOUR_SERVER and related values with your own dedicated server details. On this host only WebSocket over HTTP is available."


def render_page(host):
    uris = live_uris(host)
    rows = ""
    for name, key, uri in [("Endpoint 1", "ep1", uris["ep1"]), ("Endpoint 2", "ep2", uris["ep2"]), ("Endpoint 3", "ep3", uris["ep3"])]:
        rows += f"""
        <div class="card"><div class="row"><b>{name}</b><span class="badge" id="b_{key}">…</span></div>
        <textarea readonly rows="3" onclick="cp(this)">{uri}</textarea></div>"""
    trows = ""
    for name, uri in TEMPLATES:
        trows += f'<div class="card"><div class="row"><b>{name}</b><span class="badge gray">template</span></div><textarea readonly rows="2" onclick="cp(this)">{uri}</textarea></div>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Nexus Status</title>
<style>
body{{background:#0b1020;color:#dfe6f5;font-family:system-ui,sans-serif;margin:0;padding:clamp(12px,4vw,32px)}}
h1{{font-size:clamp(1.2rem,5vw,1.7rem);margin:.2rem 0}} .sub{{color:#8fa0c5;font-size:.85rem;margin-bottom:1rem}}
.card{{background:#121a33;border:1px solid #22304f;border-radius:10px;padding:10px;margin:10px 0}}
.row{{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:6px}}
textarea{{width:100%;background:#0b1020;color:#9fd7ff;border:1px solid #22304f;border-radius:8px;padding:8px;font-family:monospace;font-size:.78rem;direction:ltr;white-space:nowrap;overflow:auto;box-sizing:border-box}}
.badge{{font-size:.72rem;padding:3px 9px;border-radius:99px;background:#123f2a;color:#69e59a;white-space:nowrap}}
.badge.gray{{background:#26314d;color:#9fb0d4}}
a{{color:#7fb3ff}} .note{{font-size:.8rem;color:#8fa0c5;line-height:1.8}} h2{{font-size:1.05rem;margin:1.2rem 0 .2rem}}
</style></head><body>
<h1>Nexus Status</h1><div class="sub">Live endpoints — click a box to copy · paste into a compatible client</div>
{rows}
<div class="card"><div class="row"><b>Subscription link</b><span class="badge" id="b_sub">…</span></div>
<textarea readonly rows="2" onclick="cp(this)">https://{host}/sub/{ACCESS_KEY}</textarea>
<div class="note">Copy the link above and add it in your client as a subscription / profile from clipboard</div></div>
<h2>Additional templates</h2><div class="note">{TEMPLATE_NOTE}</div>
{trows}
<h2>Service health</h2><div class="note" id="st">Checking…</div>
<script>
function cp(el){{el.select();navigator.clipboard&&navigator.clipboard.writeText(el.value.trim());}}
fetch('/status').then(r=>r.json()).then(d=>{{
const map={{'ws-1':'b_ep1','ws-2':'b_ep2','ws-3':'b_ep3','edge-http':'b_sub'}};
let st='';d.checks.forEach(c=>{{const id=map[c.name];if(id){{const b=document.getElementById(id);b.textContent=(c.ok?'✓ ':'✗ ')+c.ms+'ms';b.style.background=c.ok?'#123f2a':'#3f1220';b.style.color=c.ok?'#69e59a':'#ff8aa5';}}
st+=c.ok?'✓ ':'✗ ';st+=c.name+' '+c.ms+'ms  ';}});
document.getElementById('st').textContent=st;}});
</script></body></html>"""


# ------------------------------------------------------------ server

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Nexus"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def do_GET(self):
        path = urlparse(self.path).path

        if self.headers.get("Upgrade", "").lower() == "websocket" and path in RELAY:
            return self.relay(RELAY[path])

        host = clean_host(self.headers.get("Host", ""))

        if path == "/healthz":
            return self._send(200, "ok")
        if path == "/status":
            try:
                return self._send(200, json.dumps(get_status(host), ensure_ascii=False), "application/json; charset=utf-8")
            except Exception as exc:
                return self._send(500, json.dumps({"error": str(exc)}), "application/json; charset=utf-8")
        if path == "/":
            return self._send(404, "Private service. Use the full link provided by the owner.")
        if path == f"/s/{ACCESS_KEY}":
            return self._send(200, render_page(host), "text/html; charset=utf-8")
        if path == f"/sub/{ACCESS_KEY}":
            uris = live_uris(host)
            payload = "\n".join(uris.values()).encode()
            return self._send(200, base64.b64encode(payload).decode())
        if path == f"/sub/{ACCESS_KEY}/plain":
            uris = live_uris(host)
            return self._send(200, "\n".join(uris.values()))
        return self._send(404, "not found")

    def relay(self, port):
        try:
            backend = socket.create_connection(("127.0.0.1", port), timeout=10)
        except Exception:
            return self._send(502, "core unavailable")
        raw = (self.requestline + "\r\n").encode()
        for k, v in self.headers.items():
            raw += f"{k}: {v}\r\n".encode()
        raw += b"\r\n"
        backend.sendall(raw)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 16384:
            chunk = backend.recv(4096)
            if not chunk:
                break
            head += chunk
        split = head.find(b"\r\n\r\n")
        resp_head, rest = head[:split], head[split + 4:]
        try:
            self.wfile.write(resp_head + b"\r\n\r\n")
            self.wfile.flush()
        except Exception:
            backend.close()
            self.close_connection = True
            return
        self.close_connection = True

        def pump(src, dst):
            try:
                while True:
                    b = src.recv(65536)
                    if not b:
                        break
                    dst.sendall(b)
            except Exception:
                pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

        t = threading.Thread(target=pump, args=(self.connection, backend), daemon=True)
        t.start()
        if rest:
            try:
                self.wfile.write(rest)
                self.wfile.flush()
            except Exception:
                pass
        pump(backend, self.connection)
        t.join(timeout=5)
        try:
            backend.close()
        except Exception:
            pass


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    srv.daemon_threads = True
    print("Nexus listening on :8000")
    srv.serve_forever()


if __name__ == "__main__":
    main()
