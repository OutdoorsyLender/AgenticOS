# M4B-3 Slice 4 — Connected Build: pip qualification

Status: qualified against a two-grant PyPI-shaped fixture, 2026-08-10.
Proof corpus: `tests/conformance/test_m4b3_pip_integration.py` (14 tests,
`m4b_linux`, all passing), worker scenario `M4B3-PIP-01` in
`tests/fixtures/hostile_worker.py`. Dependency review:
`docs/phase-zero/dependency-review-m4b3.md`.

## Provisioning model (no production runner change)

- The worker view's system python3 has **no pip and no ensurepip**
  (verified).
- The conformance harness stages a **SHA-256-pinned pip wheel**
  (`pip-26.2.1-py3-none-any.whl`, hash cross-verified against PyPI's
  official metadata) into the task-owned worktree at
  `/workspace/.aos-pip/`, re-verifying the hash before the launch.
- The worker runs pip **directly from the wheel zip**:
  `python3 /workspace/.aos-pip/pip-26.2.1-py3-none-any.whl/pip ...`
  (the wheel ships `pip/__main__.py`; verified).
- pip's environment is the committed Connected Build profile
  (`https_proxy=http://127.0.0.1:18080`, `REQUESTS_CA_BUNDLE`/
  `SSL_CERT_FILE`/`CURL_CA_BUNDLE` = `/opt/agenticos/network-ca.pem`).

## Two-grant authority map

| Host | Purpose | Serves |
| --- | --- | --- |
| `pypi.example` | GENERAL_DOWNLOAD | PEP 503 simple pages (`/simple/`, `/simple/<pkg>/` with anchor hrefs carrying `#sha256=` fragments) |
| `files.example` | GENERAL_DOWNLOAD | wheel artifacts (`/packages/<name>.whl`) |

Both are exact-host grants; every operation crosses both, and evidence
shows a verified identity chain per granted host. The served artifact is
the repo-committed `pycparser-3.0-py3-none-any.whl` (hash-pinned in
`requirements/m4b2-cert-helper.txt`).

## Qualified workflow commands

```sh
# hash-pinned binary-wheel install (the qualified form)
python3 /workspace/.aos-pip/pip-26.2.1-py3-none-any.whl/pip install \
    --no-deps --require-hashes --only-binary=:all: \
    --target /workspace/pylibs \
    --index-url https://pypi.example/simple/ \
    -r requirements.txt        # pycparser==3.0 --hash=sha256:b7274141...

# download variant
python3 /workspace/.aos-pip/pip-26.2.1-py3-none-any.whl/pip download \
    --no-deps -d /workspace/dl \
    --index-url https://pypi.example/simple/ \
    pycparser==3.0
```

## Measured pip behavior (pip 26.2.1, this stack)

- **install / download**: exactly 2 broker connections — `GET
  /simple/pycparser/` (322 B page) and `GET /packages/…whl` (48254 B
  incl. response head). No pip self-version-check request fired in this
  flow (weekly-cached check; measured absent). The qualified profile
  therefore needs no `PIP_DISABLE_PIP_VERSION_CHECK`, though a build
  script may set it for belt-and-braces determinism.
- **ALPN**: `worker_alpn == origin_alpn == "http/1.1"` on every record.
- **Retries**: pip hammers a truncated artifact host with read-error
  retries even under `--retries 0` (5 download attempts observed). With
  the default policy `connection_limit=8` the bound correctly TERMINATES
  the whole serve (the launch then fails closed — observed during
  qualification and documented as intended bound behavior, not a bug);
  the corpus uses `connection_limit=16` to observe the per-attempt
  evidence: first attempt `origin_read_failed` truncation, later
  attempts `origin_fixture_spent` denials.
- **extra-index**: pip queries ALL indexes, skips a failed one with a
  warning, and resolves from the granted primary — the broker denial,
  not pip, contains the authority expansion.
- **Write confinement**: default flow wrote ONLY into the task worktree
  (`/tmp` and `/home/tool` censuses empty); with explicit
  `PIP_CACHE_DIR=/home/tool/.cache/pip`, cache writes stay under that
  root. Host-side worktree diff shows only staging, requirements, and
  install outputs.
- **PIP_CERT**: names a CLIENT certificate for mutual TLS (inert here —
  the broker never requests client certificates); it is NOT a CA
  override. The CA override knobs are `REQUESTS_CA_BUNDLE` and
  `SSL_CERT_FILE`.

## Per-case results

| Case | Outcome | Evidence |
| --- | --- | --- |
| Two-host hash-pinned install | exit 0, pycparser installed | verified records for BOTH granted hosts |
| `pip download` variant | exit 0, host-side SHA-256 of wheel == repo pin | 2 verified records |
| Index-url to ungranted host | fails | `authorization_no_match` (no grant; `no_grant` identity) |
| `http://` index-url | fails | zero connections — pip's is_secure_origin gate rejects the untrusted http:// origin URL-side before any connection attempt; absent `http_proxy` is a second independent layer |
| `--trusted-host <ungranted>` | ungranted still fails broker-side; granted flow with its own host trusted succeeds | denial + 2 verified records |
| `--extra-index-url <ungranted>` | install succeeds from granted primary; pip skips the failed index | broker `authorization_no_match` for the ungranted host |
| Artifact 302 → ungranted host | install fails | 302 relayed verified + re-CONNECT denied |
| Package page 302 → artifact host (both granted) | install succeeds | cross-host redirect inside the grant set stays inside authority |
| CA census | only `/opt/agenticos/network-ca.pem`; no PIP_CERT/PIP_INDEX_URL/PIP_EXTRA_INDEX_URL/PIP_TRUSTED_HOST/PIP_CONFIG_FILE/NETRC; no ~/.netrc | env census + file stat |
| Bogus CA override | requests raises pre-connection | zero broker connections |
| Worker DNS | `getaddrinfo` fails (`gaierror`) while install succeeds | broker-side resolution proof in pip context |
| Corrupt artifact (transport-valid, content-wrong) | pip hash verification rejects; nothing installed | verified chain; `hash` in stderr; target absent |
| Partial download (origin closes early) | pip fails; no partial artifact | truncation + `origin_fixture_spent` denials on retries |

## Limitations

- `--no-deps --only-binary=:all:` hash-pinned wheels ONLY. No sdist
  builds, no build isolation, no dependency resolution beyond the
  qualified shape, no authenticated indexes, no keyring.
- Protocol is smart HTTP/1.1 through the broker; the offline repo
  wheelhouse (`requirements/wheelhouse` + `--no-index`) remains the
  PREFERRED deterministic provisioning path for real builds.
- Qualification uses the conformance fixture path
  (`synthetic_origin=True` evidence); production origin TLS/DNS/SSRF
  posture is the M4B-2 path, unchanged by this slice.
- pip self-version-check was measured silent in this flow; a build
  script targeting long-lived profiles should still pin
  `PIP_DISABLE_PIP_VERSION_CHECK=1` if request-count determinism is
  required.
