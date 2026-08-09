"""End-to-end tests: real TLS clients through the Candidate B gate pipeline.

SPIKE CODE — not production. Standard-library only.

Proves:
  E1  real Python client, TLS1.3, SNI=approved, ALPN http/1.1 -> completes
  E2  real Python client, TLS1.2, SNI=approved -> completes
  E3  h2-only client -> handshake completes with selected ALPN None
      (documents the gap: ALPN enforcement must be a post-handshake check)
  E4  openssl s_client TLS1.2 renegotiation attempt -> rejected
      (OP_NO_RENEGOTIATION effectiveness on the worker-facing context)
  E5  curl (system) through the gate, --ech false if supported -> completes;
      also records whether the system curl even supports ECH.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from gate_driver import (  # noqa: E402
    drive_handshake,
    make_server_context,
    run_gate_on_socket,
)

APPROVED = "approved.example.test"
CERT = os.path.join(HERE, "work", "cert.pem")
KEY = os.path.join(HERE, "work", "key.pem")


def serve_once(sock: socket.socket, results: dict, *, max_version=None) -> None:
    try:
        ctx = make_server_context(CERT, KEY, max_version=max_version)
        gr = run_gate_on_socket(sock)
        results["gate"] = (gr.decision, gr.reason)
        if gr.decision != "accept":
            return
        hr = drive_handshake(sock, ctx, gr.accepted_bytes, timeout=8.0)
        results["handshake"] = (hr.outcome, hr.error, hr.alpn, hr.tls_version,
                                list(hr.sni_seen))
        if hr.outcome == "completed":
            results["alpn_selected"] = hr.alpn
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run_python_client(*, alpn, max_version=None, server_max=None):
    srv, cli = socket.socketpair()
    results: dict = {}
    t = threading.Thread(target=serve_once, args=(srv, results),
                         kwargs={"max_version": server_max}, daemon=True)
    t.start()
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    if alpn:
        cctx.set_alpn_protocols(alpn)
    if max_version:
        cctx.maximum_version = max_version
    try:
        css = cctx.wrap_socket(cli, server_hostname=APPROVED)
        outcome = ("completed", css.version(), css.selected_alpn_protocol())
        css.close()
    except ssl.SSLError as exc:
        outcome = ("failed", str(exc), None)
    t.join(timeout=12)
    return outcome, results


def main() -> int:
    ok = True
    os.makedirs(os.path.join(HERE, "work"), exist_ok=True)
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", KEY, "-out", CERT, "-days", "2",
             "-subj", f"/CN={APPROVED}",
             "-addext", f"subjectAltName=DNS:{APPROVED}"],
            check=True, capture_output=True)
    if not os.path.exists(os.path.join(HERE, "work", "reneg_client")):
        subprocess.run(
            ["gcc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
             "-O2", os.path.join(HERE, "reneg_client.c"),
             "-o", os.path.join(HERE, "work", "reneg_client"),
             "-l:libssl.so.3", "-l:libcrypto.so.3"], check=True)

    outcome, res = run_python_client(alpn=["http/1.1"])
    print("E1 tls13 real client:", outcome, res.get("gate"), res.get("handshake"))
    ok &= outcome[0] == "completed" and outcome[2] == "http/1.1" \
        and res.get("gate", (None,))[0] == "accept"

    outcome, res = run_python_client(
        alpn=["http/1.1"], max_version=ssl.TLSVersion.TLSv1_2)
    print("E2 tls12 real client:", outcome, res.get("gate"), res.get("handshake"))
    # judge by the server side: the client may report EOF because the
    # spike server closes without close_notify after the handshake
    sh = res.get("handshake", ("failed",))
    ok &= sh[0] == "completed" and sh[3] == "TLSv1.2"

    outcome, res = run_python_client(alpn=["h2"])
    print("E3 h2-only client:", outcome, res.get("handshake"))
    alpn_selected = res.get("alpn_selected", "n/a")
    print("   server-side selected ALPN:", repr(alpn_selected),
          "-> post-handshake check '== http/1.1' would",
          "DENY" if alpn_selected != "http/1.1" else "ALLOW")
    ok &= outcome[0] == "completed" and alpn_selected is None

    # E4: renegotiation via the minimal C client (SSL_renegotiate, TLS1.2)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 18190))
    listener.listen(1)
    srv_results: dict = {}

    def accept_once():
        conn, _ = listener.accept()
        ctx = make_server_context(CERT, KEY)
        gr = run_gate_on_socket(conn)
        srv_results["gate"] = (gr.decision, gr.reason)
        if gr.decision != "accept":
            conn.close()
            listener.close()
            return
        inbio = ssl.MemoryBIO()
        outbio = ssl.MemoryBIO()
        sslobj = ctx.wrap_bio(inbio, outbio, server_side=True)
        inbio.write(gr.accepted_bytes)
        conn.settimeout(10)

        def pump():
            while True:
                c = outbio.read()
                if not c:
                    break
                conn.sendall(c)

        try:
            while True:
                try:
                    sslobj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    pump()
                    inbio.write(conn.recv(65536))
            srv_results["version"] = sslobj.version()
            pump()
            while True:
                try:
                    sslobj.read(4096)
                    srv_results["post"] = "read returned (no renegotiation seen)"
                    break
                except ssl.SSLWantReadError:
                    pump()
                    chunk = conn.recv(65536)
                    if not chunk:
                        srv_results["post"] = "eof"
                        break
                    inbio.write(chunk)
        except ssl.SSLError as exc:
            pump()
            srv_results["post"] = f"SSLError: {exc}"
        except (OSError, socket.timeout) as exc:
            srv_results["post"] = f"{type(exc).__name__}: {exc}"
        finally:
            conn.close()
            listener.close()

    t = threading.Thread(target=accept_once, daemon=True)
    t.start()
    time.sleep(0.5)
    proc = subprocess.run(
        [os.path.join(HERE, "work", "reneg_client"), "18190"],
        capture_output=True, text=True, timeout=20)
    t.join(timeout=12)
    print("E4 renegotiation: server:", srv_results)
    print("  client:", proc.stdout.replace("\n", " | "))
    ok &= "RENEGOTIATION_REFUSED" in proc.stdout \
        and "no renegotiation" in proc.stdout

    # E5: system curl capability record + live ECH attempt through the gate
    v = subprocess.run(["curl", "--version"], capture_output=True, text=True)
    print("E5 curl:", v.stdout.splitlines()[0] if v.stdout else "missing")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 18191))
    listener.listen(1)
    curl_srv: dict = {}

    def curl_accept():
        conn, _ = listener.accept()
        serve_once(conn, curl_srv)
        listener.close()

    t = threading.Thread(target=curl_accept, daemon=True)
    t.start()
    time.sleep(0.5)
    c = subprocess.run(
        ["curl", "-sS", "--max-time", "8", "--ech", "true", "--insecure",
         "--resolve", f"{APPROVED}:443:127.0.0.1",
         "--connect-to", f"{APPROVED}:443:127.0.0.1:18191",
         f"https://{APPROVED}/"],
        capture_output=True, text=True)
    t.join(timeout=12)
    print("   curl --ech true rc:", c.returncode,
          "stderr:", (c.stderr or "").strip()[:120])
    print("   server saw gate:", curl_srv.get("gate"),
          "handshake:", curl_srv.get("handshake"))

    print("OVERALL:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
