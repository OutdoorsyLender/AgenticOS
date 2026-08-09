#!/bin/bash
cd ~/src/AgenticOS/spikes/m4b2-ech-gate
for mode in log deny-ech; do
  for m in ech1 noech hrr; do
    echo "=== $mode / $m"
    ./work/ech_cb_probe "$mode" 18160 work/cert.pem work/key.pem > /tmp/p.txt 2>&1 &
    P=$!
    for i in $(seq 1 50); do
      grep -q READY /tmp/p.txt 2>/dev/null && break
      sleep 0.1
    done
    python3 manual_probe_client.py "$m" 18160 || true
    wait $P || true
    grep -E "CUSTEXT|CHCB|SNICB|PROBE|RESULT" /tmp/p.txt
  done
done
