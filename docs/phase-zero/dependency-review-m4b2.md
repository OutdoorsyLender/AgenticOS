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
