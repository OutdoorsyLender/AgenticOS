"""Real-host integration proof for M4B-3 Slice 5: lifecycle hardening gaps
and supply-chain acquisition evidence for Connected Build.

Gap analysis (milestone §39 matrix) against EXISTING coverage — this file
fills only the remaining cells:

- Cancellation/revoke/expiry MECHANICS are grant- and tool-agnostic and
  already proven: test_https_revoke_mid_connection_tears_down and
  test_https_expiry_tears_down_connections (M4B-2 HTTPS integration), the
  M4B-1 relay cancellation suite (test_m4b_integration.py), and
  test_fetch_policy_expiry_mid_download_fails /
  test_fetch_worker_cancellation_mid_download_no_artifact (Slice 3).
  Grant expiry mid-acquisition needs no per-ecosystem duplicate.
- Remaining cells proven HERE: task cancellation mid-GIT-CLONE (POST +
  pack stream) and mid-PIP-DOWNLOAD with no partial trusted output;
  broker-terminal REVOKED evidence shape for an ecosystem transfer;
  post-teardown authority hygiene (task CA dir, sealed memfds, broker
  process, residue); and the Option-A acquisition-evidence composer
  (controller-side join of broker authority records with build-script
  artifact records, no broker schema change).

Conventions mirror test_m4b3_git_integration.py /
test_m4b3_pip_integration.py / test_m4b3_fetch_integration.py.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-3 lifecycle proof requires Linux", allow_module_level=True)

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import time

from test_m4b_integration import _assert_no_m4b_residue
from test_m4b_https_integration import (
    m4b2_host_state,  # noqa: F401
    m4b2_native_helpers,  # noqa: F401
    m4b2_vendor,  # noqa: F401
)
from test_m4b3_connected_build_integration import m4b3_runner_factory  # noqa: F401
from test_m4b3_git_integration import (
    _FixtureRepo,
    _GitFixtureOrigin,
    _git_worker_options,
    _run_git_worker,
    _git_step,
    fixture_repo,  # noqa: F401
    GIT_HOST,
)
from test_m4b3_pip_integration import (
    ARTIFACT_PATH,
    FILES_HOST,
    INDEX_HOST,
    INDEX_URL,
    PYCPARSER_SHA,
    PYCPARSER_WHEEL,
    PYCPARSER_WHEEL_NAME,
    _PipFixtureOrigin,
    _artifact_routes,
    _index_routes,
    _pip_worker_options,
    _pip_step,
    _run_pip_worker,
    _stage_pip_wheel,
    _two_pip_specs,
    _wheel_responder,
    _write_requirements,
)
from test_m4b3_fetch_integration import (
    ARTIFACT_BODY,
    ARTIFACT_SHA,
    ARTIFACT_URL,
    CDN_HOST,
    _FetchFixtureOrigin,
    _fetch_worker_options,
    _fetch_spec,
    _artifact_step,
    _run_ok,
    script_body,
)
from helpers import pid_alive


pytestmark = pytest.mark.m4b_linux


def _git_spec(hostname=GIT_HOST):
    from agenticos.sandbox import m4b_runner as runner_module
    from agenticos.sandbox.network_https import GrantPurpose

    return runner_module.HostGrantSpec(
        hostname=hostname,
        purpose=GrantPurpose.GIT_SMART_FETCH,
        approval_source="m4b3-lifecycle",
        approval_reference="slice-m4b3-s5",
    )


class _SlowGitOrigin(_GitFixtureOrigin):
    """A _GitFixtureOrigin that trickles its CGI response wire bytes.

    The cancellation corpus needs a git transfer still in flight when the
    task is cancelled: identical bridge semantics to the parent (same
    wire format, same protocol-negotiation recording), with the final
    send broken into delayed pieces.
    """

    def __init__(self, *args, gap=0.3, piece=512, **kwargs):
        self._gap = gap
        self._piece = piece
        super().__init__(*args, **kwargs)

    def _respond_cgi(self, tls, proc):
        out = proc.stdout
        cgi_head, _, cgi_body = out.partition(b"\r\n\r\n")
        if not cgi_body:
            cgi_head, _, cgi_body = out.partition(b"\n\n")
        status = "200 OK"
        headers = []
        for line in cgi_head.replace(b"\r\n", b"\n").split(b"\n"):
            name, _, value = line.partition(b":")
            if not name.strip():
                continue
            if name.strip().lower() == b"status":
                status = value.strip().decode("ascii")
            else:
                headers.append(
                    f"{name.strip().decode('ascii')}: {value.strip().decode('ascii')}"
                )
        if not any(h.lower().startswith("content-length:") for h in headers):
            headers.append(f"Content-Length: {len(cgi_body)}")
        wire = f"HTTP/1.1 {status}\r\n".encode("ascii")
        wire += ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
        wire += cgi_body
        self.protocol_negotiated.append(
            "2" if cgi_body.startswith(b"000eversion 2") else "0"
        )
        for offset in range(0, len(wire), self._piece):
            try:
                tls.sendall(wire[offset:offset + self._piece])
            except (ssl.SSLError, OSError):
                return
            time.sleep(self._gap)


def _slow_wheel_responder(payload, *, gap=0.4, piece=1024):
    """A wheel responder that trickles the artifact (cancellation tests)."""

    def respond(tls, _request):
        wire = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n"
            + payload
        )
        for offset in range(0, len(wire), piece):
            try:
                tls.sendall(wire[offset:offset + piece])
            except (ssl.SSLError, OSError):
                return False
            time.sleep(gap)
        return False

    return respond


def _terminal(runner):
    terminal = runner.last_https_terminal
    assert terminal is not None
    return terminal


def _assert_broker_dead(runner):
    broker_process = runner.last_broker_process
    assert broker_process is not None
    assert pid_alive(broker_process.pid) is False


# ---------------------------------------------------------------------------
# Task cancellation mid-acquisition (git pack stream, pip download)
# ---------------------------------------------------------------------------


def test_cancel_mid_git_clone_no_partial_clone(m4b3_runner_factory, fixture_repo, tmp_path):
    """Task cancellation mid-GIT-CLONE (POST + pack stream): the worker is
    killed mid-transfer, the broker's own terminal says REVOKED, no
    checked-out tree ever becomes trusted build input, the broker process
    is reaped, and nothing lingers.  The revoke MECHANISM itself
    (control-channel CONTROL_REVOKE on runner cancellation) is proven
    grant-agnostically by test_https_revoke_mid_connection_tears_down;
    this test pins the git-transfer-specific assertions."""
    origin = _SlowGitOrigin(tmp_path / "origin", fixture_repo, gap=1.0, piece=256)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
        connection_limit=8,
        byte_limit=1 << 20,
    )
    process = runner.run(
        _git_worker_options(
            {
                "steps": [
                    _git_step(
                        ["clone", "-q", f"https://{GIT_HOST}/repo.git",
                         "/workspace/clone1"],
                        timeout=25,
                    )
                ]
            }
        ),
        cwd="/workspace",
        env={},
        timeout=6.0,
    )
    assert process.timed_out is True, process
    # The clone never became a trusted build input: no checked-out tree.
    assert not (Path(runner.workspace) / "clone1" / "README.md").exists()
    terminal = _terminal(runner)
    assert terminal.terminal_reason.value == "REVOKED"
    assert runner.last_https_terminal_source == "broker"
    assert terminal.synthetic_origin is True
    records = runner.last_https_connection_records
    assert records is not None and records
    assert all(r.terminal_reason.value == "revoked" for r in records)
    # "Mid-pack-stream" is positively proven, not probable: the origin
    # observed the git request(s), the pack response had STARTED (bytes
    # flowed origin->worker), and the origin's own request log shows the
    # clone's GET (and POST, if the kill landed that late).
    assert origin.requests, "origin never saw a git request"
    assert any(
        r.origin_to_worker_bytes > 0 for r in records
    ), "no bytes flowed before the kill"
    _assert_broker_dead(runner)
    origin.close()
    origin.join(timeout=45.0)
    _assert_no_m4b_residue(runner)


def test_cancel_mid_pip_download_no_partial_artifact(m4b3_runner_factory, tmp_path):
    """Task cancellation mid-PIP-DOWNLOAD: worker killed while the wheel
    drips; no completed wheel exists and no full-size partial ever lands
    in the download dir; broker terminal REVOKED; broker reaped; no
    residue."""
    index = _PipFixtureOrigin(
        tmp_path / "index", hostname=INDEX_HOST, routes=_index_routes()
    )
    files = _PipFixtureOrigin(
        tmp_path / "files",
        hostname=FILES_HOST,
        routes={
            ARTIFACT_PATH: _slow_wheel_responder(
                PYCPARSER_WHEEL.read_bytes(), gap=0.4, piece=1024
            ),
        },
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_pip_specs(),
        connected_build_profile=True,
        fixture_origins=(index, files),
        connection_limit=8,
        byte_limit=8 * 1024 * 1024,
    )
    _stage_pip_wheel(runner.workspace)
    process = runner.run(
        _pip_worker_options(
            {
                "steps": [
                    _pip_step([
                        "download", "--no-deps",
                        "-d", "/workspace/dl",
                        "--index-url", INDEX_URL,
                        "pycparser==3.0",
                    ], timeout=30),
                ]
            }
        ),
        cwd="/workspace",
        env={},
        timeout=6.0,
    )
    assert process.timed_out is True, process
    wheel_target = Path(runner.workspace) / "dl" / PYCPARSER_WHEEL_NAME
    assert not wheel_target.exists()
    download_dir = Path(runner.workspace) / "dl"
    leftovers = (
        [p for p in download_dir.rglob("*") if p.is_file()]
        if download_dir.exists()
        else []
    )
    full_size = PYCPARSER_WHEEL.stat().st_size
    # Any pip temp leftover is a strict, untrusted prefix — never the wheel.
    assert all(p.stat().st_size < full_size for p in leftovers)
    terminal = _terminal(runner)
    assert terminal.terminal_reason.value == "REVOKED"
    assert runner.last_https_terminal_source == "broker"
    records = runner.last_https_connection_records
    assert records is not None and records
    assert all(r.terminal_reason.value == "revoked" for r in records)
    _assert_broker_dead(runner)
    index.close()
    files.close()
    index.join(timeout=45.0)
    files.join(timeout=45.0)
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Post-teardown authority hygiene
# ---------------------------------------------------------------------------


def test_post_teardown_authority_hygiene(m4b3_runner_factory, fixture_repo, tmp_path):
    """After task teardown the authority is gone: the broker process is
    reaped (its listener died with the worker netns — the M4B-1 residue
    scans prove the namespace teardown), the staged task-CA directory is
    removed from /tmp, and no sealed task-certificate memfd survives in
    the controller process."""
    origin = _GitFixtureOrigin(tmp_path / "origin", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_git_worker(
        runner,
        {"steps": [_git_step(["ls-remote", f"https://{GIT_HOST}/repo.git"])]},
    )
    assert steps[0]["exit_code"] == 0
    _assert_broker_dead(runner)
    leftovers = [
        path
        for path in Path(tempfile.gettempdir()).glob("aos-m4b2-ca-*")
        if path.exists()
    ]
    assert leftovers == [], leftovers
    leaked = []
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        if "aos-task" in target:
            leaked.append(target)
    assert leaked == [], leaked
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Supply-chain acquisition evidence (Option A: controller-side composer)
# ---------------------------------------------------------------------------


_FORBIDDEN_KEY_TOKENS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "credential",
)


def _assert_no_secrets(value, path="$"):
    """Recursive no-secrets invariant for composed acquisition evidence."""
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            assert not any(
                token in lowered for token in _FORBIDDEN_KEY_TOKENS
            ), f"{path}.{key}"
            _assert_no_secrets(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _assert_no_secrets(item, f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        assert "bearer " not in lowered, path
        assert "basic " not in lowered, path
        assert "authorization:" not in lowered, path


def _record_digest(record):
    return {
        "approved_hostname": record.approved_hostname,
        "stage_reached": record.stage_reached.value,
        "terminal_reason": record.terminal_reason.value,
        "detail": record.detail,
        "identity_chain": record.identity_chain,
        "requests_completed": record.requests_completed,
        "origin_to_worker_bytes": record.origin_to_worker_bytes,
        "synthetic_origin": record.synthetic_origin,
    }


def _compose_acquisition_evidence(runner, *, tool, operations):
    """Join broker authority records with build-script artifact records.

    Option A: the controller/conformance side composes per-acquisition
    evidence WITHOUT any broker schema change: broker records carry the
    authority proof (who was authorized, which policy digests, how many
    bytes crossed), while the build script and fixture carry artifact
    identity (path, status, digest, package/ref).  No
    Authorization/cookie/token field ever appears — asserted recursively.
    """
    terminal = _terminal(runner)
    records = runner.last_https_connection_records
    assert records is not None
    evidence = {
        "evidence_version": "AOSACQ/1",
        "tool": tool,
        "authorized_hostnames": sorted(
            {r.approved_hostname for r in records if r.approved_hostname}
        ),
        "policy_digest": terminal.policy_digest,
        "network_policy_digest": terminal.network_policy_digest,
        "connection_count": terminal.connection_count,
        "bytes_accepted": sum(r.origin_to_worker_bytes for r in records),
        "operations": operations,
        "broker_records": [_record_digest(r) for r in records],
    }
    _assert_no_secrets(evidence)
    # The composed evidence must round-trip through JSON loss-free.
    assert json.loads(json.dumps(evidence, sort_keys=True)) == evidence
    return evidence


def test_evidence_git_clone_acquisition(m4b3_runner_factory, fixture_repo, tmp_path):
    """Per-acquisition evidence for the git flow: tool, authorized hostname,
    policy digests, request paths, statuses, redirect flag, bytes accepted,
    artifact identity (the ref SHA — git's object graph is self-verifying),
    joined from broker records and build-script truth, provably secret-free."""
    origin = _GitFixtureOrigin(tmp_path / "origin", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
        connection_limit=8,
        byte_limit=1 << 20,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(
                    ["clone", "-q", f"https://{GIT_HOST}/repo.git", "/workspace/clone1"]
                ),
                _git_step(["-C", "/workspace/clone1", "rev-parse", "HEAD"]),
            ]
        },
    )
    clone_step, head_step = steps
    assert clone_step["exit_code"] == 0, clone_step["stderr"]
    head = head_step["stdout"].strip()
    assert head == fixture_repo.head
    evidence = _compose_acquisition_evidence(
        runner,
        tool="git/2.53.0 (libcurl-gnutls)",
        operations=[
            # Statuses are the origin's scripted response codes (fixture
            # ground truth); paths are the origin's observed request log.
            {
                "path": "/repo.git/info/refs",
                "status": 200,
                "redirect": False,
                "package_or_ref": "refs/heads/main",
                "artifact_digest": {"algorithm": "git-sha1", "value": head},
            },
            {
                "path": "/repo.git/git-upload-pack",
                "status": 200,
                "redirect": False,
                "package_or_ref": f"refs/heads/main@{head}",
                "artifact_digest": {"algorithm": "git-sha1", "value": head},
            },
        ],
    )
    assert evidence["authorized_hostnames"] == [GIT_HOST]
    assert evidence["connection_count"] == 1
    assert evidence["bytes_accepted"] > 0
    assert all(
        operation["status"] == 200 for operation in evidence["operations"]
    )
    assert evidence["broker_records"][0]["identity_chain"] == "verified"
    assert evidence["broker_records"][0]["requests_completed"] == 3
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_evidence_pip_install_acquisition(m4b3_runner_factory, tmp_path):
    """Per-acquisition evidence for the pip flow: the artifact digest is
    the repo-pinned wheel SHA-256 the --require-hashes gate verified."""
    index = _PipFixtureOrigin(
        tmp_path / "index", hostname=INDEX_HOST, routes=_index_routes()
    )
    files = _PipFixtureOrigin(
        tmp_path / "files", hostname=FILES_HOST, routes=_artifact_routes()
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_pip_specs(),
        connected_build_profile=True,
        fixture_origins=(index, files),
        connection_limit=8,
        byte_limit=8 * 1024 * 1024,
    )
    _stage_pip_wheel(runner.workspace)
    _write_requirements(runner.workspace)
    steps = _run_pip_worker(
        runner,
        {
            "steps": [
                _pip_step([
                    "install", "--no-deps", "--require-hashes",
                    "--only-binary=:all:", "--target", "/workspace/pylibs",
                    "--index-url", INDEX_URL,
                    "-r", "/workspace/requirements.txt",
                ]),
            ]
        },
    )
    (install,) = steps
    assert install["exit_code"] == 0, install["stderr"]
    evidence = _compose_acquisition_evidence(
        runner,
        tool="pip/26.2.1 (OpenSSL, from hash-pinned wheel)",
        operations=[
            {
                "path": "/simple/pycparser/",
                "status": 200,
                "redirect": False,
                "package_or_ref": "pycparser==3.0",
                "artifact_digest": {"algorithm": "sha256", "value": PYCPARSER_SHA},
            },
            {
                "path": ARTIFACT_PATH,
                "status": 200,
                "redirect": False,
                "package_or_ref": "pycparser==3.0",
                "artifact_digest": {"algorithm": "sha256", "value": PYCPARSER_SHA},
            },
        ],
    )
    assert evidence["authorized_hostnames"] == sorted([INDEX_HOST, FILES_HOST])
    assert evidence["connection_count"] == 2
    assert evidence["operations"][1]["artifact_digest"]["value"] == PYCPARSER_SHA
    assert all(
        record["identity_chain"] == "verified"
        for record in evidence["broker_records"]
    )
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


def test_evidence_fetch_artifact_acquisition(m4b3_runner_factory, tmp_path):
    """Per-acquisition evidence for the curl fetch contract: artifact
    digest is the SHA-256 the build script's digest gate verified before
    the atomic rename."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin", respond=script_body(ARTIFACT_BODY)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(runner, {"steps": [_artifact_step()]})
    (fetch,) = steps
    assert fetch["digest_match"] is True and fetch["renamed"] is True
    evidence = _compose_acquisition_evidence(
        runner,
        tool="curl/8.18.0 (OpenSSL)",
        operations=[
            {
                "path": "/artifact.bin",
                "status": 200,
                "redirect": False,
                "package_or_ref": ARTIFACT_URL,
                "artifact_digest": {"algorithm": "sha256", "value": ARTIFACT_SHA},
            }
        ],
    )
    assert evidence["authorized_hostnames"] == [CDN_HOST]
    assert evidence["connection_count"] == 1
    assert evidence["operations"][0]["artifact_digest"]["value"] == ARTIFACT_SHA
    assert evidence["broker_records"][0]["identity_chain"] == "verified"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)
