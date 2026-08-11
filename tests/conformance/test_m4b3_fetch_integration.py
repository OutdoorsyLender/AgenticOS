"""Real-host integration proof for M4B-3 Slice 3: bounded artifact acquisition.

The REAL curl binary (8.18.0, OpenSSL) inside the hostile worker performs
bounded artifact downloads through the M4B broker against adversarial local
fixture origins (stdlib TLS HTTP/1.1 scripted responders, in-process CA,
socketpair fixture model — same pattern as the Slice 2 git origins).  The
qualified build-script contract — fetch to staging, verify an explicit
SHA-256 over the staged bytes, atomically rename only on match — is
executed literally by the worker scenario's fetch_artifact step.
Conventions mirror test_m4b3_git_integration.py.

Measured curl behavior through the broker is recorded per test in comments
and in docs/phase-zero/connected-build-fetch.md.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-3 fetch proof requires Linux", allow_module_level=True)

import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time

from agenticos.sandbox import m4b_runner as runner_module
from agenticos.sandbox.network_https import GrantPurpose

from test_m4b_integration import _assert_no_m4b_residue
from test_m4b_https_integration import (
    _worker_argv,
    m4b2_host_state,  # noqa: F401
    m4b2_native_helpers,  # noqa: F401
    m4b2_vendor,  # noqa: F401
)
from test_m4b3_connected_build_integration import m4b3_runner_factory  # noqa: F401
from test_m4b_origin_unit import _custom_material, _server_context


pytestmark = pytest.mark.m4b_linux

CDN_HOST = "cdn.example.com"
CDN_HOST_OTHER = "other.example.com"
ARTIFACT_URL = f"https://{CDN_HOST}/artifact.bin"
ARTIFACT_URL_OTHER = f"https://{CDN_HOST_OTHER}/artifact.bin"
ARTIFACT_BODY = b"m4b3-artifact-payload-v1: the quick brown artifact\n"
ARTIFACT_SHA = hashlib.sha256(ARTIFACT_BODY).hexdigest()
MAX_REQUESTS_PER_ORIGIN = 4


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _fetch_spec(hostname=CDN_HOST, **changes):
    values = {
        "hostname": hostname,
        "purpose": GrantPurpose.GENERAL_DOWNLOAD,
        "approval_source": "m4b3-fetch-integration",
        "approval_reference": "slice-m4b3-s3",
    }
    values.update(changes)
    return runner_module.HostGrantSpec(**values)


class _FetchFixtureOrigin:
    """A scripted stdlib TLS HTTP/1.1 adversarial origin (fixture pair).

    Same model as the Slice 2 git origins: an already-connected socketpair
    whose server end terminates TLS with an in-process CA leaf for the
    approved hostname; a per-test ``respond`` hook then scripts the exact
    response bytes (including deliberately malformed ones).
    """

    def __init__(self, cert_dir, *, hostname=CDN_HOST, respond, request_bound=MAX_REQUESTS_PER_ORIGIN):
        cert_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.pems = _custom_material(
            now - datetime.timedelta(minutes=2),
            now + datetime.timedelta(hours=1),
            hostname=hostname,
        )
        self.requests = []
        self.errors = []
        broker_end, server_end = socket.socketpair()
        # Pin both ends above the fixed native FD window: the launch chain
        # vacates low descriptors and the origin thread runs across it.
        for index, sock in enumerate((broker_end, server_end)):
            pinned = fcntl.fcntl(sock.fileno(), fcntl.F_DUPFD_CLOEXEC, 300 + index)
            sock.close()
            if index == 0:
                broker_end = socket.socket(fileno=pinned)
            else:
                server_end = socket.socket(fileno=pinned)
        self.broker_sock = broker_end
        self._context = _server_context(cert_dir, self.pems)
        self._thread = threading.Thread(
            target=self._run,
            args=(server_end, respond, request_bound),
            daemon=True,
        )
        self._thread.start()

    def _read_request(self, tls):
        # A reset/EOF at a request boundary is a CLEAN end of session: the
        # broker aborts the spent origin leg after the last relay.
        try:
            first = tls.recv(4096)
        except (ssl.SSLError, OSError):
            return None
        if not first:
            return None
        data = first
        while b"\r\n\r\n" not in data:
            chunk = tls.recv(4096)
            if not chunk:
                return None
            data += chunk
            if len(data) > 65536:
                raise RuntimeError("fetch origin request head exceeded test bound")
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        method, target, _version = lines[0].decode("ascii").split(" ")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(b":")
            headers[name.strip().lower().decode("ascii")] = value.strip().decode(
                "ascii"
            )
        length = int(headers.get("content-length", "0"))
        body = rest
        while len(body) < length:
            chunk = tls.recv(min(65536, length - len(body)))
            if not chunk:
                break
            body += chunk
        return method, target, headers, body

    def _run(self, sock, respond, request_bound):
        try:
            tls = self._context.wrap_socket(sock, server_side=True)
            tls.settimeout(90.0)
            for index in range(request_bound):
                parsed = self._read_request(tls)
                if parsed is None:
                    break
                self.requests.append((parsed[0], parsed[1]))
                if not respond(tls, parsed, index):
                    break
            tls.close()
        except (ssl.SSLError, OSError) as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
        except RuntimeError as exc:
            self.errors.append(str(exc))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def join(self, timeout=10.0):
        self._thread.join(timeout)
        assert not self._thread.is_alive(), "fetch origin thread stuck"

    def close(self):
        try:
            self.broker_sock.close()
        except OSError:
            pass


# -- response scripts ------------------------------------------------------------


def _head(status, headers=()):
    lines = [b"HTTP/1.1 " + status]
    lines.extend(headers)
    return b"\r\n".join(lines) + b"\r\n\r\n"


def script_body(body, *, status=b"200 OK", headers=()):
    """Valid Content-Length exact body (baseline)."""

    def respond(tls, _request, _index):
        tls.sendall(
            _head(
                status,
                (
                    (b"Content-Length: " + str(len(body)).encode("ascii")),)
                + tuple(headers),
            )
            + body
        )
        return False

    return respond


def script_short_body(declared, body):
    """Content-Length larger than delivered, then close (premature EOF)."""

    def respond(tls, _request, _index):
        tls.sendall(
            _head(b"200 OK", (b"Content-Length: " + str(declared).encode("ascii"),))
            + body
        )
        return False

    return respond


def script_long_body(declared, body):
    """More bytes on the wire than the declared Content-Length."""

    def respond(tls, _request, _index):
        tls.sendall(
            _head(b"200 OK", (b"Content-Length: " + str(declared).encode("ascii"),))
            + body
        )
        return False

    return respond


def script_duplicate_content_length(body, first, second):
    """Duplicate/conflicting Content-Length headers."""

    def respond(tls, _request, _index):
        tls.sendall(
            _head(
                b"200 OK",
                (
                    b"Content-Length: " + str(first).encode("ascii"),
                    b"Content-Length: " + str(second).encode("ascii"),
                ),
            )
            + body
        )
        return False

    return respond


def script_chunked(chunks, *, malformed_size=False):
    """Transfer-Encoding: chunked — valid, or with a broken chunk-size line."""

    def respond(tls, _request, _index):
        tls.sendall(_head(b"200 OK", (b"Transfer-Encoding: chunked",)))
        for index, chunk in enumerate(chunks):
            if malformed_size and index == 0:
                tls.sendall(b"ZZZNOTHEX\r\n")
                return False
            tls.sendall(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
        tls.sendall(b"0\r\n\r\n")
        return False

    return respond


def script_drip(body, *, chunk_size, gap):
    """Trickle the body in small chunks with per-chunk delays."""

    def respond(tls, _request, _index):
        tls.sendall(
            _head(b"200 OK", (b"Content-Length: " + str(len(body)).encode("ascii"),))
        )
        offset = 0
        while offset < len(body):
            tls.sendall(body[offset:offset + chunk_size])
            offset += chunk_size
            time.sleep(gap)
        return False

    return respond


def script_big_headers(body, *, pad_bytes):
    """A response header block beyond h11's 16 KiB incomplete-event bound."""

    def respond(tls, _request, _index):
        pad = b"x" * pad_bytes
        tls.sendall(
            _head(
                b"200 OK",
                (
                    b"X-Pad: " + pad,
                    b"Content-Length: " + str(len(body)).encode("ascii"),
                ),
            )
            + body
        )
        return False

    return respond


def script_no_content(status):
    """204/304 semantics: no response body at all."""

    def respond(tls, _request, _index):
        tls.sendall(_head(status, (b"Content-Length: 0",)))
        return False

    return respond


def script_redirect(location):
    def respond(tls, _request, _index):
        tls.sendall(
            _head(
                b"302 Found",
                (b"Location: " + location, b"Content-Length: 0"),
            )
        )
        return False

    return respond


# -- worker drivers ---------------------------------------------------------------


def _fetch_worker_options(options):
    return _worker_argv(
        "--scenario",
        "M4B3-FETCH-01",
        "--target",
        "fetch",
        "--canary",
        json.dumps(options, separators=(",", ":")),
    )


def _run_fetch_worker(runner, options, **run_kwargs):
    process = runner.run(
        _fetch_worker_options(options), cwd="/workspace", env={}, **run_kwargs
    )
    return process


def _run_ok(runner, options):
    process = _run_fetch_worker(runner, options)
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is True, result
    return result["details"]["steps"]


def _records(runner, count=None):
    records = runner.last_https_connection_records
    assert records is not None, "no broker evidence records"
    if count is not None:
        assert len(records) == count, records
    return records


def _artifact_step(url=ARTIFACT_URL, sha=ARTIFACT_SHA, dest="/workspace/artifact.bin",
                   **changes):
    step = {"op": "fetch_artifact", "url": url, "sha256": sha, "dest": dest}
    step.update(changes)
    return step


# ---------------------------------------------------------------------------
# Baseline: fetch -> verify -> atomic rename; large artifact within bounds
# ---------------------------------------------------------------------------


def test_fetch_baseline_digest_verify_atomic_rename(m4b3_runner_factory, tmp_path):
    """The qualified workflow end-to-end: curl to a ``.partial`` staging
    name next to the destination (same filesystem), SHA-256 over the
    staged bytes, atomic rename into /workspace only on match."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin", respond=script_body(ARTIFACT_BODY)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(
        runner, {"steps": [_artifact_step(), {"op": "fd_census"}]}
    )
    fetch, census = steps
    assert "curl_exit" in fetch, fetch
    assert fetch["curl_exit"] == 0, fetch["stderr"]
    assert fetch["staged_bytes"] == len(ARTIFACT_BODY)
    assert fetch["digest"] == ARTIFACT_SHA
    assert fetch["digest_match"] is True
    assert fetch["renamed"] is True
    assert fetch["dest_exists"] is True
    assert all(fd <= 2 for fd in census["fds"]), census["fds"]

    origin.join()
    assert origin.requests == [("GET", "/artifact.bin")]
    assert origin.errors == []
    (record,) = _records(runner, 1)
    assert record.approved_hostname == CDN_HOST
    assert record.identity_chain == "verified"
    assert record.origin_tls_name == CDN_HOST
    # curl (OpenSSL) ALPN through the broker is exactly http/1.1.
    assert record.worker_alpn == "http/1.1"
    assert record.origin_alpn == "http/1.1"
    # Relayed origin bytes are the exact response head plus body.
    expected_wire = len(
        _head(b"200 OK", (b"Content-Length: " + str(len(ARTIFACT_BODY)).encode("ascii"),))
    ) + len(ARTIFACT_BODY)
    assert record.origin_to_worker_bytes == expected_wire
    origin.close()
    _assert_no_m4b_residue(runner)


def test_fetch_large_artifact_within_bounds(m4b3_runner_factory, tmp_path):
    """4 MiB artifact inside explicit limits; measured connections/bytes."""
    body = os.urandom(4 * 1024 * 1024)
    origin = _FetchFixtureOrigin(tmp_path / "origin", respond=script_body(body))
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
        connection_limit=8,
        byte_limit=8 * 1024 * 1024,
    )
    steps = _run_ok(
        runner,
        {
            "steps": [
                _artifact_step(sha=_sha(body), timeout=60),
                {"op": "fd_census"},
            ]
        },
    )
    fetch, census = steps
    assert fetch["curl_exit"] == 0, fetch["stderr"]
    assert fetch["digest_match"] is True and fetch["renamed"] is True
    assert fetch["staged_bytes"] == len(body)
    (record,) = _records(runner, 1)
    # Measured: one connection, one GET; relayed origin bytes are the exact
    # response head plus the 4 MiB body.
    assert record.identity_chain == "verified"
    expected_wire = len(
        _head(b"200 OK", (b"Content-Length: " + str(len(body)).encode("ascii"),))
    ) + len(body)
    assert record.origin_to_worker_bytes == expected_wire
    assert record.accounted_bytes == (
        record.total_bytes + record.discarded_unsent_bytes
    )
    assert all(fd <= 2 for fd in census["fds"]), census["fds"]
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Framing adversaries: the digest gate + broker bounds reject every one
# ---------------------------------------------------------------------------


def test_fetch_short_body_premature_eof_rejected(m4b3_runner_factory, tmp_path):
    """Content-Length larger than delivered, then close: curl fails (exit 56
    measured — CURLE_RECV_ERROR on the truncated stream), the staged
    partial fails the digest gate, nothing is renamed."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_short_body(len(ARTIFACT_BODY) + 100, ARTIFACT_BODY),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(runner, {"steps": [_artifact_step()]})
    (fetch,) = steps
    # Measured: curl reports exit 56 (CURLE_RECV_ERROR) on the truncated
    # stream; either way the staged partial fails the digest gate.
    assert fetch["curl_exit"] != 0, fetch
    assert fetch["staged_bytes"] == len(ARTIFACT_BODY)  # short of declared
    assert fetch["digest_match"] is False
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_long_body_digest_gate_rejects(m4b3_runner_factory, tmp_path):
    """More bytes than declared: curl's measured behavior is a clean exit
    with the file truncated at Content-Length (exit 0); the digest gate —
    expecting the FULL wire body's identity — rejects the truncated
    artifact and nothing is renamed."""
    full_body = ARTIFACT_BODY + b"EXTRA-BYTES"
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_long_body(len(ARTIFACT_BODY), full_body),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(
        runner, {"steps": [_artifact_step(sha=_sha(full_body))]}
    )
    (fetch,) = steps
    # Measured: curl reports success on the Content-Length prefix; the
    # contract's digest gate is what rejects the truncated artifact.
    assert fetch["curl_exit"] == 0, fetch["stderr"]
    assert fetch["staged_bytes"] == len(ARTIFACT_BODY)
    assert fetch["digest"] == ARTIFACT_SHA  # the truncated prefix
    assert fetch["digest_match"] is False
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_duplicate_content_length_rejected(m4b3_runner_factory, tmp_path):
    """Conflicting duplicate Content-Length: the BROKER's h11 response
    framer refuses to delimit it — typed `response_remote_unframeable`
    detail, connection terminated fail-closed, ZERO post-violation bytes
    relayed (the violation trips on the first received chunk, before any
    write), curl exits non-zero, nothing is staged.  This is the
    regression anchor for the RemoteProtocolError evidence typing."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_duplicate_content_length(
            ARTIFACT_BODY, len(ARTIFACT_BODY), len(ARTIFACT_BODY) + 1
        ),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(runner, {"steps": [_artifact_step()]})
    (fetch,) = steps
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    (record,) = _records(runner, 1)
    assert record.detail == "response_remote_unframeable"
    assert record.terminal_reason.value == "peer_error"
    # The violation trips h11 on the FIRST received chunk: exactly zero
    # response bytes were ever relayed to the worker.
    assert record.origin_to_worker_bytes == 0
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_valid_chunked_succeeds(m4b3_runner_factory, tmp_path):
    """Valid chunked response: the broker relays verbatim (h11 frames it),
    curl de-chunks, and the digest gate verifies the DE-CHUNKED bytes."""
    chunks = [ARTIFACT_BODY[:17], ARTIFACT_BODY[17:33], ARTIFACT_BODY[33:]]
    origin = _FetchFixtureOrigin(
        tmp_path / "origin", respond=script_chunked(chunks)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(runner, {"steps": [_artifact_step()]})
    (fetch,) = steps
    assert fetch["curl_exit"] == 0, fetch["stderr"]
    assert fetch["staged_bytes"] == len(ARTIFACT_BODY)
    assert fetch["digest"] == ARTIFACT_SHA
    assert fetch["digest_match"] is True
    assert fetch["renamed"] is True
    (record,) = _records(runner, 1)
    assert record.identity_chain == "verified"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_malformed_chunked_rejected(m4b3_runner_factory, tmp_path):
    """A broken chunk-size line: the broker's h11 framer cannot delimit the
    response (fail-closed RemoteProtocolError); curl exits non-zero,
    nothing staged."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_chunked([ARTIFACT_BODY], malformed_size=True),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(runner, {"steps": [_artifact_step()]})
    (fetch,) = steps
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    (record,) = _records(runner, 1)
    # Measured: the VALID response head is relayed, then the malformed
    # chunk-size line trips the typed fail-closed detail — nothing after
    # the violation is relayed.
    assert record.detail == "response_remote_unframeable"
    assert record.origin_to_worker_bytes == len(
        _head(b"200 OK", (b"Transfer-Encoding: chunked",))
    )
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_oversized_response_headers_bounded(m4b3_runner_factory, tmp_path):
    """Response-header bound, measured: h11's incomplete-event limit is
    16384 bytes per buffered event and the broker relays in 16384-byte
    chunks, so a 20 KiB head PASSES intact (digest gate verifies it) while
    a 40 KiB head trips the broker's framer fail-closed — curl exits
    non-zero and nothing is staged.  (curl itself imposes no tighter
    bound; the protection is broker-side plus the digest gate.)"""
    origin_pass = _FetchFixtureOrigin(
        tmp_path / "origin-pass",
        respond=script_big_headers(ARTIFACT_BODY, pad_bytes=20 * 1024),
    )
    origin_trip = _FetchFixtureOrigin(
        tmp_path / "origin-trip",
        respond=script_big_headers(ARTIFACT_BODY, pad_bytes=40 * 1024),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin_pass, origin_trip),
    )
    steps = _run_ok(
        runner,
        {
            "steps": [
                _artifact_step(dest="/workspace/artifact-pass.bin"),
                _artifact_step(dest="/workspace/artifact-trip.bin"),
            ]
        },
    )
    pass_leg, trip_leg = steps
    assert pass_leg["curl_exit"] == 0, pass_leg["stderr"]
    assert pass_leg["digest_match"] is True and pass_leg["renamed"] is True
    assert trip_leg["curl_exit"] != 0
    assert trip_leg["renamed"] is False
    assert trip_leg["dest_exists"] is False
    records = _records(runner, 2)
    # Identity chain (hostname) holds on BOTH legs — framing denial is
    # orthogonal.  Measured: the trip leg relayed exactly one 16384-byte
    # chunk (the head fragment) before h11's next chunk tripped the bound.
    assert all(r.identity_chain == "verified" for r in records)
    tripped = [r for r in records if r.detail == "response_remote_unframeable"]
    assert len(tripped) == 1
    assert tripped[0].terminal_reason.value == "peer_error"
    assert tripped[0].origin_to_worker_bytes == 16384
    completed = [r for r in records if r.terminal_reason.value == "completed"]
    assert len(completed) == 1
    origin_pass.close()
    origin_trip.close()
    origin_pass.join()
    origin_trip.join()
    _assert_no_m4b_residue(runner)


def test_fetch_oversized_body_trips_grant_byte_limit(m4b3_runner_factory, tmp_path):
    """A body beyond the grant's own byte_limit terminates the relay
    mid-body with grant_byte_limit (Slice 1 per-grant bound); curl gets a
    truncated stream and the partial is never renamed."""
    body = os.urandom(128 * 1024)
    origin = _FetchFixtureOrigin(tmp_path / "origin", respond=script_body(body))
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(byte_limit=64 * 1024),),
        connected_build_profile=True,
        fixture_origins=(origin,),
        byte_limit=1024 * 1024,
    )
    steps = _run_ok(runner, {"steps": [_artifact_step()]})
    (fetch,) = steps
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    (record,) = _records(runner, 1)
    assert record.detail == "grant_byte_limit"
    assert record.terminal_reason.value == "byte_limit"
    # The POLICY aggregate (1 MiB) was never tripped — the per-grant bound
    # fired alone.
    assert runner.last_https_terminal.terminal_reason.value != "BYTE_LIMIT"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Timing adversaries: drip inside/outside the broker idle bound; expiry;
# worker cancellation
# ---------------------------------------------------------------------------


def test_fetch_slow_drip_inside_idle_bound_succeeds(m4b3_runner_factory, tmp_path):
    """A drip with per-chunk gaps WELL inside the broker's 30 s idle bound
    succeeds; total transfer time is irrelevant — only byte progress gaps
    count.  Measured: 8 chunks x 0.4 s ≈ 3.2 s for 48 bytes."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_drip(ARTIFACT_BODY, chunk_size=6, gap=0.4),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(runner, {"steps": [_artifact_step(timeout=30)]})
    (fetch,) = steps
    assert fetch["curl_exit"] == 0, fetch["stderr"]
    assert fetch["digest_match"] is True and fetch["renamed"] is True
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_drip_exceeding_idle_bound_terminated(m4b3_runner_factory, tmp_path):
    """A 35 s byte-progress gap exceeds the broker's
    HTTPS_RESPONSE_IDLE_TIMEOUT_SECONDS=30: the BROKER gives up first with
    origin_response_timeout; curl sees a truncated stream (non-zero exit
    measured) and the partial is never renamed.  (~40 s runtime.)"""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_drip(ARTIFACT_BODY, chunk_size=6, gap=35.0),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
        lifetime=90.0,
    )
    steps = _run_fetch_worker(
        runner, {"steps": [_artifact_step(timeout=55)]}, timeout=75.0
    )
    assert steps.exit_code == 0, steps.stderr
    result = json.loads(steps.stdout)
    assert result["succeeded"] is True, result
    (fetch,) = result["details"]["steps"]
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    (record,) = _records(runner, 1)
    assert record.detail == "origin_response_timeout"
    assert record.terminal_reason.value == "peer_error"
    origin.close()
    origin.join(timeout=45.0)
    _assert_no_m4b_residue(runner)


def test_fetch_policy_expiry_mid_download_fails(m4b3_runner_factory, tmp_path):
    """Broker death mid-transfer (policy expiry at ~12 s while the origin
    drips for ~20 s): the relay terminates EXPIRED, curl fails, the staged
    partial is rejected, and no residue remains."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_drip(os.urandom(64 * 1024), chunk_size=4096, gap=1.2),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
        lifetime=12.0,
    )
    steps = _run_ok(runner, {"steps": [_artifact_step(timeout=40)]})
    (fetch,) = steps
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    (record,) = _records(runner, 1)
    assert record.terminal_reason.value == "expired"
    origin.close()
    origin.join(timeout=45.0)
    _assert_no_m4b_residue(runner)


def test_fetch_worker_cancellation_mid_download_no_artifact(
    m4b3_runner_factory, tmp_path
):
    """Task cancellation mid-download (run timeout kills the scope while
    the origin drips): no partial ever becomes a trusted artifact and the
    launch leaves no residue."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_drip(os.urandom(64 * 1024), chunk_size=2048, gap=1.0),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
        lifetime=60.0,
    )
    process = _run_fetch_worker(
        runner,
        {"steps": [_artifact_step(timeout=55)]},
        timeout=6.0,
    )
    # The scope was cancelled: the worker did not complete its script.
    assert process.exit_code != 0
    origin.close()
    origin.join(timeout=45.0)
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Redirect corpus
# ---------------------------------------------------------------------------


def test_fetch_same_host_redirect_succeeds(m4b3_runner_factory, tmp_path):
    """302 to a different path on the SAME granted host: curl -L follows
    (authority unchanged) and the digest gate verifies the final bytes."""

    def respond(tls, request, _index):
        if request[1] == "/artifact.bin":
            script_redirect(b"https://cdn.example.com/real/artifact.bin")(
                tls, request, _index
            )
            return True  # keep the session for the follow-up request
        return script_body(ARTIFACT_BODY)(tls, request, _index)

    origin = _FetchFixtureOrigin(tmp_path / "origin", respond=respond)
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(
        runner,
        {"steps": [_artifact_step(curl_extra=["-L"])]},
    )
    (fetch,) = steps
    assert fetch["curl_exit"] == 0, fetch["stderr"]
    assert fetch["digest_match"] is True and fetch["renamed"] is True
    records = _records(runner)
    # curl reuses the tunnel for the same-host follow.
    assert len(records) == 1, records
    (record,) = records
    assert record.identity_chain == "verified"
    assert record.requests_completed == 2
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_unapproved_redirect_denied(m4b3_runner_factory, tmp_path):
    """302 to an UNGRANTED host: the broker relays the 302 byte-exact, curl
    -L follows, and the re-CONNECT is denied — no artifact, and the denied
    CONNECT is on the evidence."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_redirect(b"https://other.example.com/artifact.bin"),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(
        runner,
        {"steps": [_artifact_step(curl_extra=["-L"])]},
    )
    (fetch,) = steps
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    records = _records(runner, 2)
    relayed = [r for r in records if r.identity_chain == "verified"]
    denied = [r for r in records if r.detail == "authorization_no_match"]
    assert len(relayed) == 1 and relayed[0].approved_hostname == CDN_HOST
    assert len(denied) == 1
    assert denied[0].connect_authority == CDN_HOST_OTHER
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_downgrade_redirect_fails(m4b3_runner_factory, tmp_path):
    """302 HTTPS->HTTP downgrade: curl -L follows onto a scheme with no
    proxy authority (http_proxy is absent from the fixed profile); direct
    egress is dead — the fetch fails and the only broker connection is the
    byte-exact relayed 302."""
    origin = _FetchFixtureOrigin(
        tmp_path / "origin",
        respond=script_redirect(b"http://cdn.example.com/artifact.bin"),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(
        runner,
        {"steps": [_artifact_step(curl_extra=["-L"])]},
    )
    (fetch,) = steps
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    (record,) = _records(runner, 1)
    assert record.identity_chain == "verified"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Authority corpus: wrong host, direct egress, HEAD/204/304, digest mismatch
# ---------------------------------------------------------------------------


def test_fetch_wrong_host_denied(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
    )
    steps = _run_ok(
        runner, {"steps": [_artifact_step(url=ARTIFACT_URL_OTHER)]}
    )
    (fetch,) = steps
    assert fetch["curl_exit"] != 0
    assert fetch["renamed"] is False
    (record,) = _records(runner, 1)
    assert record.detail == "authorization_no_match"
    # Single-grant sole-fallback evidence: divergent CONNECT authority.
    assert record.connect_authority == CDN_HOST_OTHER
    assert record.identity_chain == "identity_divergence:connect_authority"
    _assert_no_m4b_residue(runner)


def test_fetch_direct_egress_scrub_fails(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
    )
    steps = _run_ok(
        runner,
        {
            "steps": [
                {
                    "op": "curl",
                    "argv": ["-fsS", "-o", "/tmp/x.bin", ARTIFACT_URL],
                    "env_scrub": ["https_proxy", "HTTPS_PROXY"],
                }
            ]
        },
    )
    (step,) = steps
    assert step["exit_code"] != 0
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


def test_fetch_head_and_204_semantics(m4b3_runner_factory, tmp_path):
    """HEAD, 204, and 304 characterization: all succeed with no body; the
    digest gate is N/A (nothing is ever staged for a bodiless response)."""
    origin_head = _FetchFixtureOrigin(
        tmp_path / "origin-head", respond=script_body(b"", headers=())
    )
    origin_204 = _FetchFixtureOrigin(
        tmp_path / "origin-204", respond=script_no_content(b"204 No Content")
    )
    origin_304 = _FetchFixtureOrigin(
        tmp_path / "origin-304", respond=script_no_content(b"304 Not Modified")
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin_head, origin_204, origin_304),
    )
    steps = _run_ok(
        runner,
        {
            "steps": [
                {"op": "curl", "argv": ["-fsS", "-I", ARTIFACT_URL]},
                {"op": "curl", "argv": ["-fsS", "-o", "/tmp/x204.bin", ARTIFACT_URL]},
                {"op": "curl", "argv": ["-fsS", "-o", "/tmp/x304.bin", ARTIFACT_URL]},
            ]
        },
    )
    head_step, get_204, get_304 = steps
    # Measured: HEAD succeeds with headers on stdout and no body; 204/304
    # succeed with an empty download (zero staged bytes is not an artifact).
    assert head_step["exit_code"] == 0, head_step["stderr"]
    assert get_204["exit_code"] == 0, get_204["stderr"]
    assert get_304["exit_code"] == 0, get_304["stderr"]
    assert get_204["stdout_hex"] == "" and get_304["stdout_hex"] == ""
    records = _records(runner, 3)
    assert all(r.identity_chain == "verified" for r in records)
    for origin in (origin_head, origin_204, origin_304):
        origin.close()
        origin.join()
    _assert_no_m4b_residue(runner)


def test_fetch_digest_mismatch_on_complete_download_rejected(
    m4b3_runner_factory, tmp_path
):
    """The headline proof: a COMPLETE, transport-authentic download whose
    bytes differ from the expected artifact identity is rejected by the
    digest gate.  Transport authenticity is NOT artifact identity."""
    wrong_body = b"TROJANED>" + ARTIFACT_BODY[9:]
    assert len(wrong_body) == len(ARTIFACT_BODY)
    assert wrong_body != ARTIFACT_BODY
    origin = _FetchFixtureOrigin(
        tmp_path / "origin", respond=script_body(wrong_body)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_fetch_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_ok(
        runner,
        {"steps": [_artifact_step(), {"op": "file_stat", "path": "/workspace/artifact.bin"}]},
    )
    fetch, stat_step = steps
    # The TRANSPORT succeeded perfectly — verified identity chain, full body.
    assert fetch["curl_exit"] == 0, fetch["stderr"]
    assert fetch["staged_bytes"] == len(ARTIFACT_BODY)
    assert fetch["digest"] == _sha(wrong_body)
    # ...and the ARTIFACT gate still rejects it.
    assert fetch["digest_match"] is False
    assert fetch["renamed"] is False
    assert fetch["dest_exists"] is False
    assert stat_step["exists"] is False
    (record,) = _records(runner, 1)
    assert record.identity_chain == "verified"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)
