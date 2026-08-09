# M4B-2 Dependency Review — Task-Scoped Certificate Helper (Slice 2)

Date: 2026-08-09
Milestone: M4B-2 (Authenticated HTTPS Policy), Slice 2
Reviewer: implementation subagent (recorded for human security review)
Status: proposed pins, helper-only scope

## Scope statement

The packages below are approved **only** for the short-lived, trusted
certificate-helper subprocess (`agenticos.sandbox.cert_helper` child entry
point). The helper generates a per-task CA keypair and a distinct leaf
keypair, writes certificate material into sealed memfds, destroys the CA
private key in its own address space, and exits **before** any hostile worker
execution. The long-lived broker runtime and the controller remain
standard-library-only: `pyproject.toml` runtime dependencies are unchanged
(empty), and `src/agenticos/sandbox/cert_helper.py` imports `cryptography`
only inside the helper child code path, never at module import time (proven by
`test_broker_module_import_is_stdlib_only` in
`tests/conformance/test_m4b_certs_unit.py`).

`h11`, `idna`, and every other M4B-2 candidate class are **not** part of this
slice and are not installed.

## Process-model decision (CA key memory boundary)

The helper runs as a **short-lived subprocess** (`sys.executable -m
agenticos.sandbox.cert_helper`), not as an in-process function. Rationale:

- The `cryptography` package and the CA private key never exist in the
  controller's long-lived address space; process teardown is the clean memory
  boundary required by the per-task-CA design section.
- Sealed-fd handback is solved without SCM_RIGHTS: the controller creates the
  four memfds (`MFD_ALLOW_SEALING | MFD_CLOEXEC`) and passes them via
  `subprocess.Popen(pass_fds=...)`, which preserves the controller-side
  CLOEXEC flag while making the child copies inheritable. Seals are
  per-file, so the child's `F_ADD_SEALS` is authoritative for the parent's
  descriptors.
- Strict parent-child contract: bounded stdin JSON request, exact field set,
  empty stdout/stderr on success, exit status 0, controller-side timeout with
  fail-closed kill, and post-exit re-verification of seals and binding before
  the material is accepted.

## Approved packages

### cryptography 46.0.2 (direct dependency)

- Name / exact version: `cryptography==46.0.2`
- Upstream provenance: PyPI project <https://pypi.org/project/cryptography/>;
  source <https://github.com/pyca/cryptography> (pyca project)
- License: Apache-2.0 OR BSD-3-Clause (wheel metadata `License-Expression`)
- Wheel: `cryptography-46.0.2-cp311-abi3-manylinux_2_34_x86_64.whl`
- SHA-256: `be939b99d4e091eec9a2bcf41aaf8f351f312cd19ff74b5c83480f08a8a43e0b`
- Transitive closure: `cffi>=2.0.0` (CPython ≥ 3.9), which requires
  `pycparser` (non-PyPy). Both pinned below. No native build required:
  manylinux_2_34 wheel bundles its OpenSSL bindings.
- Supported platform: CPython 3.11+ via the abi3 tag (verified installed and
  exercised on CPython 3.14.4 / Ubuntu 26.04 WSL2 / x86_64); backend reported
  as `openssl`.
- Known-advisory posture: pip-audit (or any advisory database) is not
  available in the offline build environment, so no advisory-DB check was
  possible at pin time. Mitigations: exact `==` pin with SHA-256 hash
  verification, offline wheelhouse (no resolver or index at install time),
  helper-only scope with a subprocess memory boundary, and the pyca project's
  active security-maintenance track record. Re-check against the pyca
  security advisories (<https://github.com/pyca/cryptography/security>) at
  the next gate review before any broader use.
- Pin location: `requirements/m4b2-cert-helper.txt`
- Used for: CA/leaf EC key generation (SECP256R1) and X.509 certificate
  construction/signing inside the helper child only.

### cffi 2.1.1 (transitive, required by cryptography on CPython)

- Name / exact version: `cffi==2.1.1`
- Upstream provenance: PyPI project <https://pypi.org/project/cffi/>;
  source <https://github.com/python-cffi/cffi>
- License: MIT-0 (wheel metadata `License-Expression`)
- Wheel: `cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`
- SHA-256: `b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96`
- Transitive closure: `pycparser` (pinned below).
- Known-advisory posture: same offline constraint as above; same mitigations.
- Pin location: `requirements/m4b2-cert-helper.txt`

### pycparser 3.0 (transitive, required by cffi)

- Name / exact version: `pycparser==3.0`
- Upstream provenance: PyPI project <https://pypi.org/project/pycparser/>;
  source <https://github.com/eliben/pycparser>
- License: BSD-3-Clause (wheel metadata `License-Expression`)
- Wheel: `pycparser-3.0-py3-none-any.whl` (pure Python)
- SHA-256: `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992`
- Transitive closure: none.
- Known-advisory posture: same offline constraint as above; same mitigations.
- Pin location: `requirements/m4b2-cert-helper.txt`

## Deterministic pinning and offline reproduction

- Wheelhouse: `requirements/wheelhouse/` (exactly the three wheels above,
  committed to the repository; binary wheels only).
- Hash-pinned requirements: `requirements/m4b2-cert-helper.txt` (`==` pins
  with `--hash=sha256:` for every wheel, computed with `sha256sum`).
- Hashes were recorded from the exact artifacts downloaded once from PyPI
  with `pip download --only-binary=:all:`; all later installs are offline.

Offline reproduction (no index, hashes enforced, wheels only):

```bash
pip install --no-index --find-links requirements/wheelhouse \
    --require-hashes --only-binary=:all: \
    -r requirements/m4b2-cert-helper.txt --target <tmpdir>
```

Proven on 2026-08-09 with proxy environment unset; the same command (without
`--target`) installs into the development venv for tests, additionally with
`--force-reinstall` so the installed artifacts are exactly the pinned wheels.

## Runtime filesystem closure

- The wheels install only into the helper's Python environment (development
  venv for tests; a helper-dedicated `--target` directory for the offline
  reproduction). No system paths, CA stores, or broker runtime paths are
  modified.
- The helper writes no filesystem artifacts at all: certificates and the leaf
  private key are emitted only into sealed memfds; the CA private key is
  never serialized.
- Host/global CA stores and the sandbox runtime trust store are untouched.

## Behavioral conformance

- `tests/conformance/test_m4b_certs_unit.py` proves, with the pinned stack:
  distinct CA/leaf keypairs, exact-hostname single-SAN leaves, chain
  verification against the task CA, digest-bound sealed transport,
  fail-closed binding verification, `/proc/self/fd/N` TLS context loading
  with the standard library, and a real end-to-end TLS handshake in which a
  stdlib client trusting only the task CA validates the exact approved
  hostname (and rejects any other).


---

# M4B-2 Dependency Review — Strict HTTP/1.1 Broker Parser (Slice 5)

Date: 2026-08-09
Milestone: M4B-2 (Authenticated HTTPS Policy), Slice 5
Reviewer: implementation subagent (recorded for human security review)
Status: proposed pin, broker-runtime scope behind the raw-byte prevalidator

## Scope statement

Unlike the Slice 2 certificate-helper closure, `h11` is approved for the
**long-lived broker runtime**. The scope of trust is deliberately narrow:

- `h11` enters the broker runtime **only** behind the strict raw-byte
  prevalidator in `src/agenticos/sandbox/network_http.py`. The prevalidator
  is the security envelope: it rejects ambiguous wire syntax (framing
  ambiguity, obs-fold, bare LF, duplicate/conflicting Content-Length,
  TE/CL mixing, transfer codings other than exactly `chunked`, chunk
  extensions, trailers, control bytes, obs-text, malformed targets,
  oversized anything) **before** any byte reaches h11.
- h11 is used solely as the structured event parser for bytes the
  prevalidator has already accepted, and the prevalidator cross-checks
  h11's structural agreement (method / request-target / version / headers)
  on every request. Any disagreement fails the connection closed. The
  prevalidator is intentionally **stricter** than h11; conformance tests
  (`tests/conformance/test_m4b_http_unit.py`) verify with h11 directly that
  every fixture the prevalidator rejects and h11 would have accepted is
  rejected by the prevalidator first.
- h11 is **never** the security envelope: policy decisions (method grants,
  bounds, framing) are made by the prevalidator alone.
- `pyproject.toml` runtime dependencies remain unchanged (empty); the pin
  lives only in `requirements/m4b2-broker.txt` and is installed into the
  broker's environment from the committed wheelhouse.

## Approved package

### h11 0.16.0 (direct dependency)

- Name / exact version: `h11==0.16.0`
- Upstream provenance: PyPI project <https://pypi.org/project/h11/>;
  source <https://github.com/python-hyper/h11> (python-hyper project,
  author Nathaniel J. Smith)
- License: MIT (wheel metadata `License: MIT`)
- Wheel: `h11-0.16.0-py3-none-any.whl` (pure Python, no native code)
- SHA-256: `63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86`
- Transitive closure: **none** (zero runtime dependencies; `Requires-Dist`
  absent in wheel metadata).
- Supported platform: CPython 3.8+ per `Requires-Python: >=3.8`; verified
  installed and exercised on CPython 3.14.4 / Ubuntu 26.04 WSL2 / x86_64.
- Known-advisory posture: pip-audit (or any advisory database) is not
  available in the offline build environment, so no advisory-DB check was
  possible at pin time. Manual review of the python-hyper/h11 security
  advisories (<https://github.com/python-hyper/h11/security/advisories>):
  the project's single published advisory, GHSA-vqfr-h8mv-ghfj /
  CVE-2025-43859 (lenient acceptance of malformed chunked-encoding
  terminators, a request-smuggling primitive), is **fixed in 0.16.0** —
  the version pinned here. This advisory class is exactly why h11 is
  deployed behind the prevalidator: even if a future h11 acceptance is
  more permissive than policy, the prevalidator rejects ambiguous framing
  first. Mitigations: exact `==` pin with SHA-256 hash verification,
  offline wheelhouse (no resolver or index at install time), pure-Python
  package (no native code), prevalidator-first architecture with h11
  cross-checking, and fail-closed semantics on any divergence. Re-check
  the advisory feed at the next gate review.
- Pin location: `requirements/m4b2-broker.txt`
- Used for: structured HTTP/1.1 event parsing (Request, Data, EndOfMessage)
  inside the broker's strict HTTP security envelope, on prevalidated bytes
  only.

## Deterministic pinning and offline reproduction

- Wheelhouse: `requirements/wheelhouse/` (the `h11-0.16.0-py3-none-any.whl`
  artifact above added to the existing Slice 2 closure; committed to the
  repository; binary wheels only).
- Hash-pinned requirements: `requirements/m4b2-broker.txt` (`==` pin with
  `--hash=sha256:`, hash computed with `sha256sum` on the exact artifact
  downloaded once from PyPI with `pip download --only-binary=:all:`).
  The helper closure (`requirements/m4b2-cert-helper.txt`) is untouched.

Offline reproduction (no index, hashes enforced, wheels only):

```bash
pip install --no-index --find-links requirements/wheelhouse \
    --require-hashes --only-binary=:all: \
    -r requirements/m4b2-broker.txt --target <tmpdir>
```

Proven on 2026-08-09 with no index access; the same command (without
`--target`, with `--force-reinstall`) installs into the development venv
for tests, so the installed artifact is exactly the pinned wheel.

## Runtime filesystem closure

- The wheel installs only into the broker's Python environment (development
  venv for tests; a broker-dedicated `--target` directory for the offline
  reproduction). No system paths, CA stores, or controller paths are
  modified.
- h11 is pure Python and performs no I/O itself; the broker feeds it bytes
  through `h11.Connection.receive_data` only after prevalidation.

## Behavioral conformance

- `tests/conformance/test_m4b_http_unit.py` (Corpus C) proves, with the
  pinned h11 behind the prevalidator: positive request flows (clean GET,
  HEAD, purpose-granted POST with Content-Length, purpose-granted chunked
  POST) are accepted end-to-end THROUGH h11; ~65 adversarial fixtures
  (smuggling pairs, framing ambiguity, obs-fold, control bytes, obs-text,
  chunk extensions, trailers, oversized fields, HTTP/2 preface, nested
  CONNECT, Upgrade, absolute/authority/asterisk-form targets, pipelined
  second-request revalidation) are rejected by the prevalidator, with
  h11-acceptance cross-checks proving the prevalidator rejects FIRST on
  every fixture h11 alone would have accepted, and byte-drip equivalence
  property tests proving identical verdicts for one-write versus
  one-byte-at-a-time delivery.
