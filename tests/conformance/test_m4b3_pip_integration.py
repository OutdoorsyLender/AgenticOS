"""Real-host integration proof for M4B-3 Slice 4: pip qualification.

The REAL pip 26.2.1 (run from a hash-verified wheel zip; the worker's
system python3 has neither pip nor ensurepip) performs hash-pinned
binary-wheel installs/downloads through the M4B broker against a two-grant
PyPI-shaped fixture: pypi.example serving PEP 503 simple pages and
files.example serving the repo-committed pycparser wheel.  The staged
wheel and the served artifact are both SHA-256-pinned to repo-committed
ground truth (requirements/wheelhouse).  Conventions mirror
test_m4b3_fetch_integration.py.

Measured pip request behavior is recorded per test in comments and in
docs/phase-zero/connected-build-pip.md.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-3 pip proof requires Linux", allow_module_level=True)

import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
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

REPO_ROOT = Path(__file__).resolve().parents[2]
WHEELHOUSE = REPO_ROOT / "requirements" / "wheelhouse"
PIP_WHEEL = WHEELHOUSE / "pip-26.2.1-py3-none-any.whl"
PIP_WHEEL_SHA = (
    "71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e"
)
PYCPARSER_WHEEL_NAME = "pycparser-3.0-py3-none-any.whl"
PYCPARSER_WHEEL = WHEELHOUSE / PYCPARSER_WHEEL_NAME
PYCPARSER_SHA = (
    "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"
)
INDEX_HOST = "pypi.example"
FILES_HOST = "files.example"
OTHER_HOST = "files-other.example"
INDEX_URL = f"https://{INDEX_HOST}/simple/"
ARTIFACT_PATH = f"/packages/{PYCPARSER_WHEEL_NAME}"
ARTIFACT_URL = f"https://{FILES_HOST}{ARTIFACT_PATH}"

MAX_REQUESTS_PER_ORIGIN = 8


def _pip_spec(hostname):
    return runner_module.HostGrantSpec(
        hostname=hostname,
        purpose=GrantPurpose.GENERAL_DOWNLOAD,
        approval_source="m4b3-pip-integration",
        approval_reference="slice-m4b3-s4",
    )


def _two_pip_specs():
    return (_pip_spec(INDEX_HOST), _pip_spec(FILES_HOST))


def _stage_pip_wheel(workspace):
    """Stage the hash-verified pip wheel into the task worktree (harness)."""
    payload = PIP_WHEEL.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == PIP_WHEEL_SHA, (
        "pip wheel hash diverged from the repo pin"
    )
    staging = Path(workspace) / ".aos-pip"
    staging.mkdir(exist_ok=True)
    target = staging / PIP_WHEEL.name
    target.write_bytes(payload)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == PIP_WHEEL_SHA
    return target


class _PipFixtureOrigin:
    """A routed stdlib TLS HTTP/1.1 fixture origin (socketpair model).

    ``routes`` maps path prefixes to responder callables
    ``respond(tls, request) -> bool`` (False closes after the response).
    """

    def __init__(self, cert_dir, *, hostname, routes):
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
            args=(server_end, tuple(routes.items())),
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
                raise RuntimeError("pip origin request head exceeded test bound")
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

    def _run(self, sock, routes):
        try:
            tls = self._context.wrap_socket(sock, server_side=True)
            tls.settimeout(60.0)
            for _ in range(MAX_REQUESTS_PER_ORIGIN):
                parsed = self._read_request(tls)
                if parsed is None:
                    break
                method, target, headers, body = parsed
                self.requests.append((method, target))
                path = target.partition("?")[0]
                responder = next(
                    (respond for prefix, respond in routes
                     if path.startswith(prefix)),
                    None,
                )
                if responder is None:
                    payload = b"not found"
                    tls.sendall(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: "
                        + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
                    )
                    continue
                if not responder(tls, parsed):
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
        assert not self._thread.is_alive(), "pip origin thread stuck"

    def close(self):
        try:
            self.broker_sock.close()
        except OSError:
            pass


def _html(body_text):
    return (
        "<!DOCTYPE html>\n<html><head><title>i</title></head><body>\n"
        + body_text
        + "\n</body></html>\n"
    ).encode("ascii")


def _page(body):
    def respond(tls, _request):
        tls.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
        )
        return True

    return respond


def _wheel_responder(payload, *, declared=None):
    declared = len(payload) if declared is None else declared

    def respond(tls, _request):
        tls.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(declared).encode("ascii") + b"\r\n\r\n"
            + payload
        )
        return False

    return respond


def _redirect_responder(location):
    def respond(tls, _request):
        tls.sendall(
            b"HTTP/1.1 302 Found\r\nLocation: " + location
            + b"\r\nContent-Length: 0\r\n\r\n"
        )
        return True

    return respond


def _simple_root_page():
    return _html(f'<a href="/simple/pycparser/">pycparser</a><br/>')


def _simple_pkg_page():
    return _html(
        f'<a href="{ARTIFACT_URL}#sha256={PYCPARSER_SHA}">'
        f"{PYCPARSER_WHEEL_NAME}</a><br/>"
    )


def _index_routes(**overrides):
    routes = {
        "/simple/pycparser/": _page(_simple_pkg_page()),
        "/simple/pip/": _page(_html("<b>pip</b>")),
        "/simple/": _page(_simple_root_page()),
    }
    routes.update(overrides)
    return routes


def _artifact_routes(payload=None, **overrides):
    payload = PYCPARSER_WHEEL.read_bytes() if payload is None else payload
    routes = {ARTIFACT_PATH: _wheel_responder(payload)}
    routes.update(overrides)
    return routes


def _pip_worker_options(options):
    return _worker_argv(
        "--scenario",
        "M4B3-PIP-01",
        "--target",
        "pip",
        "--canary",
        json.dumps(options, separators=(",", ":")),
    )


def _run_pip_worker(runner, options, **run_kwargs):
    process = runner.run(
        _pip_worker_options(options), cwd="/workspace", env={}, **run_kwargs
    )
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


def _pip_step(argv, **changes):
    # pip's denial/retry backoff far exceeds the worker's 5 s default
    # operation timeout; give every step a generous explicit bound.
    step = {"op": "pip", "argv": argv, "timeout": 60}
    step.update(changes)
    return step


def _install_argv(target="/workspace/pylibs", req="/workspace/requirements.txt"):
    return [
        "install",
        # Harness bound on denial retry backoff (runtime only; the
        # qualified workflow itself is canonical pip behavior).
        "--retries", "1",
        "--no-deps",
        "--require-hashes",
        "--only-binary=:all:",
        "--target", target,
        "--index-url", INDEX_URL,
        "-r", req,
    ]


def _install_argv_no_retry(target="/workspace/pylibs", req="/workspace/requirements.txt"):
    argv = _install_argv(target, req)
    argv[argv.index("1")] = "0"
    return argv


def _write_requirements(workspace):
    path = Path(workspace) / "requirements.txt"
    path.write_text(f"pycparser==3.0 --hash=sha256:{PYCPARSER_SHA}\n")
    return path


# ---------------------------------------------------------------------------
# Baseline: two-host hash-pinned install + download variant + confinement
# ---------------------------------------------------------------------------


def test_pip_two_host_install_baseline(m4b3_runner_factory, tmp_path):
    """The qualified two-grant flow: index page from pypi.example, wheel
    from files.example, hash-pinned --require-hashes install.  Measured:
    exactly 2 broker connections (GET /simple/pycparser/ = 322 B page,
    GET wheel = 48254 B), NO pip self-version-check request from pip
    26.2.1 in this flow (weekly-cached check did not fire; the qualified
    profile therefore needs no PIP_DISABLE_PIP_VERSION_CHECK, though a
    build script may set it for belt-and-braces determinism)."""
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
                _pip_step(_install_argv()),
                {"op": "file_stat", "path": "/workspace/pylibs/pycparser/__init__.py"},
                {"op": "tree_census"},
            ]
        },
    )
    install, stat_step, census = steps
    assert install["exit_code"] == 0, install["stderr"]
    assert stat_step["exists"] is True

    index.join()
    files.join()
    assert index.requests == [("GET", "/simple/pycparser/")]
    assert files.requests == [("GET", ARTIFACT_PATH)]
    assert index.errors == [] and files.errors == []
    records = _records(runner, 2)
    assert {r.approved_hostname for r in records} == {INDEX_HOST, FILES_HOST}
    assert all(r.identity_chain == "verified" for r in records)
    assert all(r.synthetic_origin is True for r in records)
    assert all(r.worker_alpn == "http/1.1" for r in records)
    assert all(r.origin_alpn == "http/1.1" for r in records)
    assert all(r.requests_completed == 1 for r in records)

    # Write confinement: pip touched ONLY the task worktree.
    assert census["census"]["/tmp"] == []
    assert census["census"]["/home/tool"] == []
    workspace_paths = [path for path, _size in census["census"]["/workspace"]]
    assert all(
        path.startswith(("pylibs/", ".aos-pip/"))
        or path in ("allowed.txt", "requirements.txt")
        for path in workspace_paths
    ), workspace_paths
    index.close()
    files.close()
    _assert_no_m4b_residue(runner)


def test_pip_download_variant(m4b3_runner_factory, tmp_path):
    """pip download variant: same two-host flow; the wheel lands in the
    download dir with the repo-pinned SHA-256 (host-side digest check)."""
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
    steps = _run_pip_worker(
        runner,
        {
            "steps": [
                _pip_step([
                    "download", "--no-deps",
                    "-d", "/workspace/dl",
                    "--index-url", INDEX_URL,
                    "pycparser==3.0",
                ]),
                {"op": "file_stat", "path": f"/workspace/dl/{PYCPARSER_WHEEL_NAME}"},
            ]
        },
    )
    download, stat_step = steps
    assert download["exit_code"] == 0, download["stderr"]
    assert stat_step["exists"] is True
    assert stat_step["size"] == PYCPARSER_WHEEL.stat().st_size
    downloaded = Path(runner.workspace) / "dl" / PYCPARSER_WHEEL_NAME
    assert hashlib.sha256(downloaded.read_bytes()).hexdigest() == PYCPARSER_SHA
    records = _records(runner, 2)
    assert {r.approved_hostname for r in records} == {INDEX_HOST, FILES_HOST}
    assert all(r.identity_chain == "verified" for r in records)
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Authority corpus: wrong host, HTTP index, trusted-host, extra-index
# ---------------------------------------------------------------------------


def test_pip_wrong_host_denied(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=_two_pip_specs(),
        connected_build_profile=True,
    )
    _stage_pip_wheel(runner.workspace)
    _write_requirements(runner.workspace)
    steps = _run_pip_worker(
        runner,
        {
            "steps": [
                _pip_step([
                    "install", "--retries", "0", "--no-deps", "--require-hashes",
                    "--only-binary=:all:", "--target", "/workspace/pylibs",
                    "--index-url", f"https://{OTHER_HOST}/simple/",
                    "-r", "/workspace/requirements.txt",
                ]),
            ]
        },
    )
    (install,) = steps
    assert install["exit_code"] != 0
    (record,) = _records(runner, 1)
    assert record.stage_reached.value == "authorization"
    assert record.detail == "authorization_no_match"
    assert record.connect_authority == OTHER_HOST
    # Two-grant policy: denied-before-selection evidence has no grant.
    assert record.approved_hostname is None
    assert record.identity_chain == "no_grant"
    _assert_no_m4b_residue(runner)


def test_pip_http_index_fails(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=_two_pip_specs(),
        connected_build_profile=True,
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
                    "--index-url", f"http://{INDEX_HOST}/simple/",
                    "-r", "/workspace/requirements.txt",
                ]),
            ]
        },
    )
    (install,) = steps
    assert install["exit_code"] != 0
    # Two independent refusal layers, URL-side first: pip 26.2.1's
    # is_secure_origin gate rejects the untrusted http:// origin BEFORE
    # any connection attempt (no proxy consulted, no egress attempted);
    # absent http_proxy in the fixed profile is a second layer that would
    # kill any residual direct-egress path anyway.  Measured: zero broker
    # connections.
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


def test_pip_trusted_host_cannot_widen(m4b3_runner_factory, tmp_path):
    """--trusted-host affects ONLY worker-side TLS verification against the
    broker leaf: the ungranted host still fails broker-side; the granted
    flow still succeeds with its own host trusted."""
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
                    "install", "--retries", "0", "--no-deps", "--require-hashes",
                    "--only-binary=:all:", "--target", "/workspace/pylibs-bad",
                    "--index-url", f"https://{OTHER_HOST}/simple/",
                    "--trusted-host", OTHER_HOST,
                    "-r", "/workspace/requirements.txt",
                ]),
                _pip_step([
                    "install", "--no-deps", "--require-hashes",
                    "--only-binary=:all:", "--target", "/workspace/pylibs",
                    "--index-url", INDEX_URL,
                    "--trusted-host", INDEX_HOST,
                    "--trusted-host", FILES_HOST,
                    "-r", "/workspace/requirements.txt",
                ]),
            ]
        },
    )
    bad, good = steps
    assert bad["exit_code"] != 0
    assert good["exit_code"] == 0, good["stderr"]
    records = _records(runner, 3)
    denied = [r for r in records if r.detail == "authorization_no_match"]
    verified = [r for r in records if r.identity_chain == "verified"]
    assert len(denied) == 1 and denied[0].connect_authority == OTHER_HOST
    assert len(verified) == 2
    assert {r.approved_hostname for r in verified} == {INDEX_HOST, FILES_HOST}
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


def test_pip_extra_index_url_cannot_expand_authority(m4b3_runner_factory, tmp_path):
    """An ungranted --extra-index-url cannot silently widen authority.
    Measured pip behavior: pip queries ALL indexes, skips the failed extra
    with a warning, and the install SUCCEEDS from the granted primary —
    while the broker denial of the ungranted host is on the evidence.  The
    security property is the broker-side denial, never pip's skip."""
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
                    "install", "--retries", "1", "--no-deps", "--require-hashes",
                    "--only-binary=:all:", "--target", "/workspace/pylibs",
                    "--index-url", INDEX_URL,
                    "--extra-index-url", f"https://{OTHER_HOST}/simple/",
                    "-r", "/workspace/requirements.txt",
                ]),
            ]
        },
    )
    (install,) = steps
    # Measured: pip skips the failed extra index with a warning and
    # resolves from the granted primary — the broker denial is what
    # contains the authority expansion.
    assert install["exit_code"] == 0, install["stderr"]
    assert (Path(runner.workspace) / "pylibs" / "pycparser" / "__init__.py").exists()
    records = _records(runner)
    denied = [r for r in records if r.detail == "authorization_no_match"]
    assert denied
    assert all(r.connect_authority == OTHER_HOST for r in denied)
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Redirect corpus
# ---------------------------------------------------------------------------


def test_pip_unapproved_artifact_redirect_fails(m4b3_runner_factory, tmp_path):
    """Artifact host 302 -> ungranted host: pip/requests follows redirects
    by default; the redirect target re-enters authorization and is denied,
    so the install fails."""
    index = _PipFixtureOrigin(
        tmp_path / "index", hostname=INDEX_HOST, routes=_index_routes()
    )
    files = _PipFixtureOrigin(
        tmp_path / "files",
        hostname=FILES_HOST,
        routes={
            ARTIFACT_PATH: _redirect_responder(
                f"https://{OTHER_HOST}/stolen.whl".encode("ascii")
            )
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
    _write_requirements(runner.workspace)
    steps = _run_pip_worker(
        runner, {"steps": [_pip_step(_install_argv())]}
    )
    (install,) = steps
    assert install["exit_code"] != 0
    records = _records(runner)
    verified = [r for r in records if r.identity_chain == "verified"]
    denied = [r for r in records if r.detail == "authorization_no_match"]
    assert {r.approved_hostname for r in verified} == {INDEX_HOST, FILES_HOST}
    # Every follow attempt on the redirect target denies identically
    # (measured: --retries 1 yields two denied CONNECTs).
    assert denied
    assert all(r.connect_authority == OTHER_HOST for r in denied)
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


def test_pip_cross_host_redirect_inside_grant_set_succeeds(
    m4b3_runner_factory, tmp_path
):
    """Approved cross-host redirect: the package PAGE lives behind a 302
    from the index host to the artifact host — both granted — and the
    install succeeds.  Cross-host redirects inside the explicit grant set
    stay inside authority."""
    index = _PipFixtureOrigin(
        tmp_path / "index",
        hostname=INDEX_HOST,
        routes={
            "/simple/pycparser/": _redirect_responder(
                f"https://{FILES_HOST}/redirect/pycparser-page".encode("ascii")
            ),
            "/simple/": _page(_simple_root_page()),
        },
    )
    files = _PipFixtureOrigin(
        tmp_path / "files",
        hostname=FILES_HOST,
        routes={
            "/redirect/pycparser-page": _page(_simple_pkg_page()),
            ARTIFACT_PATH: _wheel_responder(PYCPARSER_WHEEL.read_bytes()),
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
    _write_requirements(runner.workspace)
    steps = _run_pip_worker(
        runner,
        {
            "steps": [
                _pip_step(_install_argv()),
                {"op": "file_stat", "path": "/workspace/pylibs/pycparser/__init__.py"},
            ]
        },
    )
    install, stat_step = steps
    assert install["exit_code"] == 0, install["stderr"]
    assert stat_step["exists"] is True
    files.join()
    assert files.requests == [
        ("GET", "/redirect/pycparser-page"),
        ("GET", ARTIFACT_PATH),
    ]
    records = _records(runner, 2)
    assert {r.approved_hostname for r in records} == {INDEX_HOST, FILES_HOST}
    assert all(r.identity_chain == "verified" for r in records)
    index.close()
    files.close()
    index.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Isolation corpus: CA/credentials/DNS/cache confinement
# ---------------------------------------------------------------------------


def test_pip_ca_and_credential_census(m4b3_runner_factory, tmp_path):
    """The only trust root is the task CA; no ambient pip indexes, trusted
    hosts, netrc, or credential config exist in the fixed environment."""
    runner = m4b3_runner_factory(
        grant_specs=_two_pip_specs(),
        connected_build_profile=True,
    )
    steps = _run_pip_worker(
        runner,
        {
            "steps": [
                {"op": "env_census"},
                {"op": "file_stat", "path": "/home/tool/.netrc"},
            ]
        },
    )
    env_step, netrc_step = steps
    environment = env_step["environment"]
    assert environment["REQUESTS_CA_BUNDLE"] == "/opt/agenticos/network-ca.pem"
    assert environment["SSL_CERT_FILE"] == "/opt/agenticos/network-ca.pem"
    assert environment["CURL_CA_BUNDLE"] == "/opt/agenticos/network-ca.pem"
    for name in (
        "PIP_CERT",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_TRUSTED_HOST",
        "PIP_CONFIG_FILE",
        "NETRC",
    ):
        assert name not in environment
    assert netrc_step["exists"] is False
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


def test_pip_bogus_ca_override_fails_worker_side_only(m4b3_runner_factory, tmp_path):
    """CA override pointed at a nonexistent PEM: requests raises while
    loading the CA bundle BEFORE any connection — measured: zero broker
    connections, the failure is worker-side only, nothing is widened.
    (Note: PIP_CERT is NOT a CA override — it names a CLIENT certificate
    for mutual TLS, which the broker never requests, so it is inert here;
    the CA override knobs are REQUESTS_CA_BUNDLE and SSL_CERT_FILE.)"""
    runner = m4b3_runner_factory(
        grant_specs=_two_pip_specs(),
        connected_build_profile=True,
    )
    _stage_pip_wheel(runner.workspace)
    _write_requirements(runner.workspace)
    steps = _run_pip_worker(
        runner,
        {
            "steps": [
                _pip_step(
                    _install_argv(),
                    env_extra={
                        "REQUESTS_CA_BUNDLE": "/nonexistent/attacker.pem",
                        "SSL_CERT_FILE": "/nonexistent/attacker.pem",
                    },
                ),
            ]
        },
    )
    (install,) = steps
    assert install["exit_code"] != 0
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


def test_pip_worker_dns_unavailable(m4b3_runner_factory, tmp_path):
    """pip-context resolver/SSRF non-regression: worker DNS is dead while
    the broker-side resolution path still completes the install."""
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
                {"op": "dns_probe", "hostname": INDEX_HOST},
                _pip_step(_install_argv()),
            ]
        },
    )
    dns_step, install = steps
    assert dns_step["resolved"] is False
    assert dns_step["error_type"] == "gaierror"
    assert install["exit_code"] == 0, install["stderr"]
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


def test_pip_cache_confined_to_task_roots(m4b3_runner_factory, tmp_path):
    """With an explicit PIP_CACHE_DIR under the profile HOME, every write
    stays inside the three task-owned writable roots (/workspace, /tmp,
    /home/tool); the worktree itself is the host-side diff ground truth."""
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
                _pip_step(
                    _install_argv(),
                    env_extra={"PIP_CACHE_DIR": "/home/tool/.cache/pip"},
                ),
                {"op": "tree_census"},
            ]
        },
    )
    install, census = steps
    assert install["exit_code"] == 0, install["stderr"]
    workspace_paths = [path for path, _s in census["census"]["/workspace"]]
    assert all(
        path.startswith(("pylibs/", ".aos-pip/"))
        or path in ("allowed.txt", "requirements.txt")
        for path in workspace_paths
    ), workspace_paths
    # pip wrote only into its designated cache root (or nowhere); never /tmp
    # or any other path inside the census roots.
    assert census["census"]["/tmp"] == []
    home_paths = [path for path, _s in census["census"]["/home/tool"]]
    assert all(path.startswith(".cache/pip/") for path in home_paths), home_paths
    # Host-side worktree diff: only the staging, requirements, and install
    # outputs exist.
    worktree_paths = sorted(
        str(path.relative_to(runner.workspace))
        for path in Path(runner.workspace).rglob("*")
        if path.is_file()
    )
    assert all(
        path.startswith(("pylibs/", ".aos-pip/"))
        or path in ("allowed.txt", "requirements.txt")
        for path in worktree_paths
    ), worktree_paths
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Integrity corpus: corrupt artifact, partial download
# ---------------------------------------------------------------------------


def test_pip_corrupt_artifact_hash_mismatch(m4b3_runner_factory, tmp_path):
    """Transport-authentic but content-wrong wheel bytes (same length):
    pip's own hash verification rejects the artifact and installs
    nothing.  Transport authenticity is NOT artifact identity."""
    genuine = PYCPARSER_WHEEL.read_bytes()
    trojaned = b"\x00" + genuine[1:]
    assert len(trojaned) == len(genuine) and trojaned != genuine
    index = _PipFixtureOrigin(
        tmp_path / "index", hostname=INDEX_HOST, routes=_index_routes()
    )
    files = _PipFixtureOrigin(
        tmp_path / "files",
        hostname=FILES_HOST,
        routes=_artifact_routes(payload=trojaned),
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
                _pip_step(_install_argv()),
                {"op": "file_stat", "path": "/workspace/pylibs/pycparser/__init__.py"},
            ]
        },
    )
    install, stat_step = steps
    assert install["exit_code"] != 0
    assert "hash" in install["stderr"].lower()
    assert stat_step["exists"] is False
    records = _records(runner, 2)
    assert all(r.identity_chain == "verified" for r in records)
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)


def test_pip_partial_download_fails(m4b3_runner_factory, tmp_path):
    """The artifact host closes early (half the declared Content-Length):
    requests raises mid-download, pip fails, and no partial artifact ever
    lands in the target.  Measured: pip retries the truncated download
    aggressively (read-error retries fire even under --retries 0 — 5
    attempts observed); at the default connection_limit=8 the bound
    correctly terminates the whole serve (the launch then fails closed —
    intended behavior), so this test sizes the bound at 16 to observe
    the per-attempt evidence."""
    genuine = PYCPARSER_WHEEL.read_bytes()
    half = genuine[: len(genuine) // 2]
    index = _PipFixtureOrigin(
        tmp_path / "index", hostname=INDEX_HOST, routes=_index_routes()
    )
    files = _PipFixtureOrigin(
        tmp_path / "files",
        hostname=FILES_HOST,
        routes={
            ARTIFACT_PATH: _wheel_responder(half, declared=len(genuine)),
        },
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_pip_specs(),
        connected_build_profile=True,
        fixture_origins=(index, files),
        connection_limit=16,
        byte_limit=8 * 1024 * 1024,
    )
    _stage_pip_wheel(runner.workspace)
    _write_requirements(runner.workspace)
    steps = _run_pip_worker(
        runner,
        {
            "steps": [
                _pip_step(_install_argv_no_retry()),
                {"op": "file_stat", "path": "/workspace/pylibs/pycparser/__init__.py"},
            ]
        },
    )
    install, stat_step = steps
    assert install["exit_code"] != 0
    assert stat_step["exists"] is False
    assert not (Path(runner.workspace) / "pylibs").exists() or not list(
        (Path(runner.workspace) / "pylibs").rglob("*.whl")
    )
    records = _records(runner)
    # Measured: one index page request, then pip HAMMERS the truncated
    # artifact host (read-error retries even under --retries 0: 5 download
    # attempts observed).  The first files connection truncates mid-relay;
    # every later attempt denies at the spent fixture — both fail-closed.
    # connection_limit=16 keeps the serve alive to observe the evidence
    # (at 8, the bound correctly terminated the whole serve).
    index_records = [r for r in records if r.approved_hostname == INDEX_HOST]
    files_records = [r for r in records if r.approved_hostname == FILES_HOST]
    assert len(index_records) == 1
    assert index_records[0].identity_chain == "verified"
    truncated = [r for r in files_records if r.detail == "origin_read_failed"]
    spent = [r for r in files_records if r.detail == "origin_fixture_spent"]
    assert len(truncated) == 1
    assert truncated[0].identity_chain == "verified"
    assert truncated[0].terminal_reason.value == "peer_error"
    assert spent
    assert all(r.stage_reached.value == "origin_connect" for r in spent)
    assert all(r.terminal_reason.value == "denied" for r in spent)
    assert all(
        r.identity_chain == "stage_absent:origin_tls_name" for r in spent
    )
    index.close()
    files.close()
    index.join()
    files.join()
    _assert_no_m4b_residue(runner)
