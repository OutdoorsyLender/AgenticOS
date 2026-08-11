# M4B-3 dependency review — Connected Build conformance tooling

Scope of this review: dependencies added for the M4B-3 Connected Build
qualification slices. It extends, and does not modify, the M4B-2 broker
and certificate-helper dependency gates
(`docs/phase-zero/dependency-review-m4b2.md`). Nothing in this review
enters the broker, certificate-helper, or controller runtime closures;
`pyproject.toml` runtime dependencies are unchanged.

## pip 26.2.1 wheel (conformance-staged build tooling)

- **Artifact**: `requirements/wheelhouse/pip-26.2.1-py3-none-any.whl`
- **Version**: 26.2.1 (pure-Python wheel, `py3-none-any`)
- **SHA-256**: `71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e`
- **Pin file**: `requirements/m4b3-pip.txt`
- **Source**: downloaded from the canonical PyPI file host
  (`files.pythonhosted.org`, path `packages/py3/p/pip/`); the recorded
  hash was cross-verified against PyPI's official JSON metadata
  (`pypi.org/pypi/pip/26.2.1/json`) at staging time — the two agree.
- **Purpose**: the worker view's system python3 has neither pip nor
  ensurepip (verified: `No module named pip` / `No module named
  ensurepip`). The pip qualification slice needs the REAL pip inside the
  hostile worker. The conformance harness stages this wheel into the
  task-owned worktree after re-verifying its hash against the pin, and
  the worker executes pip directly from the wheel zip
  (`python3 /workspace/.aos-pip/pip-26.2.1-py3-none-any.whl/pip ...` —
  the wheel contains `pip/__main__.py`; verified working).
- **Scope**: test/harness-staged BUILD TOOLING ONLY. The wheel is never
  installed into any AgenticOS runtime environment, never imported by
  production code, and never leaves the per-task worktree it is staged
  into (worktree cleanup removes it with the task).
- **Stack**: pip 26.2.1 vendors requests/urllib3 and uses the system
  OpenSSL 3.5.5 through the interpreter's `ssl` module. Through the
  broker, its ALPN is exactly `http/1.1` (measured in the qualification
  corpus).
- **Offline reproduction**:
  `pip install --no-index --find-links requirements/wheelhouse
  --require-hashes --only-binary=:all: -r requirements/m4b3-pip.txt
  --target <tmpdir>`

## pycparser 3.0 wheel (served artifact, pre-existing)

The pip-qualification fixture serves the repo's PRE-EXISTING
hash-pinned `requirements/wheelhouse/pycparser-3.0-py3-none-any.whl`
(SHA-256 `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992`,
already pinned in `requirements/m4b2-cert-helper.txt`) as the artifact
under test. No new dependency: it is repo-committed ground truth used
as installable content only inside the conformance fixtures.
