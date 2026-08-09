# M4B-2 ECH enforcement spike

Experimental, non-production spike. Nothing here is integrated into the
AgenticOS broker or runner; `pyproject.toml` and production dependencies
are untouched; no packages were installed.

Purpose: determine whether AgenticOS can deterministically reject TLS
Encrypted ClientHello (extension 0xfe0d) before trusting SNI for
exact-hostname authorization, and choose between:

- A: native OpenSSL ClientHello-callback shim (`ech_cb_probe.c`)
- B: bounded pure-Python ClientHello gate (`ech_gate.py`)

Read `results.md` for the measured evidence and the verdict inputs.

## Layout

- `results.md` — evidence, bounds, review resolutions, claim wording
- `results.json`, `full-run.log` — recorded 50-case corpus output
- `ech_gate.py` — Candidate B gate parser (the recommended mechanism)
- `gate_driver.py` — bounded socket driver + verbatim MemoryBIO replay
- `chgen.py` — synthetic ClientHello generator (wire fixtures)
- `run_corpus.py` — conformance + differential corpus (50 cases, 4 targets)
- `e2e_tests.py` — real-client E2E: Python TLS1.2/1.3, h2-only ALPN gap,
  TLS1.2 renegotiation refusal, curl ECH capability record
- `ech_cb_probe.c` — Candidate A native probe (client_hello_cb / custom ext)
- `reneg_client.c` — minimal TLS1.2 renegotiation client
- `startup_probe.py` — fail-closed broker startup self-test prototype
- `manual_probe_client.py`, `probe_matrix.sh`, `e4_reneg2.sh` — drivers
  used to produce the native-probe and renegotiation evidence

## Reproduce (Linux/WSL2, stdlib + gcc only)

```bash
python3 run_corpus.py     # 50-case corpus; exits nonzero on any finding
python3 e2e_tests.py      # real-client end-to-end
python3 startup_probe.py  # fail-closed startup self-test prototype
```
