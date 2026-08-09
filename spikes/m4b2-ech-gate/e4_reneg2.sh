#!/bin/bash
set -e
cd ~/src/AgenticOS/spikes/m4b2-ech-gate
cp /mnt/c/AgenticOS/spikes/m4b2-ech-gate/reneg_client.c .
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 reneg_client.c -o work/reneg_client -l:libssl.so.3 -l:libcrypto.so.3
echo "build ok"

python3 - <<'EOF' &
import socket, sys, ssl, time
sys.path.insert(0, ".")
from gate_driver import make_server_context, run_gate_on_socket

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 18198))
listener.listen(1)
print("PYREADY", flush=True)
conn, _ = listener.accept()
ctx = make_server_context("work/cert.pem", "work/key.pem")
gr = run_gate_on_socket(conn)
print("gate:", gr.decision, gr.reason, flush=True)
inbio = ssl.MemoryBIO(); outbio = ssl.MemoryBIO()
sslobj = ctx.wrap_bio(inbio, outbio, server_side=True)
inbio.write(gr.accepted_bytes)
conn.settimeout(10)
def pump():
    while True:
        c = outbio.read()
        if not c: break
        conn.sendall(c)
try:
    while True:
        try:
            sslobj.do_handshake(); break
        except ssl.SSLWantReadError:
            pump()
            d = conn.recv(65536)
            if not d: raise ssl.SSLError("eof")
            inbio.write(d)
    print("handshake completed:", sslobj.version(), flush=True)
    pump()
    t0 = time.monotonic()
    while time.monotonic() - t0 < 8:
        try:
            d = sslobj.read(4096)
            print("appdata:", d[:40], flush=True)
        except ssl.SSLWantReadError:
            pump()
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                print("eof", flush=True); break
            inbio.write(chunk)
except ssl.SSLError as e:
    pump()
    print("server SSLError:", str(e)[:140], flush=True)
except Exception as e:
    print("server error:", str(e)[:140], flush=True)
conn.close(); listener.close()
EOF
PYPID=$!
sleep 2
./work/reneg_client 18198
wait $PYPID || true
