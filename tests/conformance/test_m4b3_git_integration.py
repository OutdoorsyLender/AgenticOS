"""Real-host integration proof for M4B-3 Slice 2: Git HTTPS qualification.

The REAL git binary (2.53.0, libcurl-gnutls) inside the hostile worker
performs approved git operations (ls-remote / clone / fetch / checkout)
through the M4B broker against controlled local fixture origins.  Each
origin is a stdlib-only TLS HTTP/1.1 CGI bridge in front of the real
/usr/lib/git-core/git-http-backend, serving a bare fixture repository
created per test in tmp_path.  Broker-side origin TLS authenticates the
approved hostname against the fixture trust roots exactly as in the
M4B-2/M4B-3 fixture model.  Conventions mirror
test_m4b3_connected_build_integration.py.

Measured behavior of this git/curl stack through the broker (recorded from
passing runs; see docs/phase-zero/connected-build-git.md):
- ls-remote: 1 broker connection, 1 GET request (~0.6 KiB response).
- clone/fetch: 2 broker connections (GET info/refs, POST git-upload-pack),
  a few KiB each way for the small fixture repo.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-3 git proof requires Linux", allow_module_level=True)

import datetime
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
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

GIT_HOST = "git.example.com"
GIT_HOST_OTHER = "other.example.com"
GIT_URL = f"https://{GIT_HOST}/repo.git"
GIT_URL_OTHER = f"https://{GIT_HOST_OTHER}/repo.git"
GIT_HTTP_URL = f"http://{GIT_HOST}/repo.git"
MAX_REQUESTS_PER_ORIGIN = 8


def _sh(argv, cwd=None, check=True):
    return subprocess.run(
        [str(a) for a in argv],
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


class _FixtureRepo:
    """A bare fixture repository plus its expected identities."""

    def __init__(self, root, submodule_url=None):
        self.src = root / "src"
        self.bare = root / "repo.git"
        self.project_root = root
        self.src.mkdir(parents=True)
        _sh(["git", "init", "-q", "-b", "main"], cwd=self.src)
        _sh(["git", "config", "user.email", "fixture@example.com"], cwd=self.src)
        _sh(["git", "config", "user.name", "Fixture"], cwd=self.src)
        (self.src / "README.md").write_text("fixture one\n")
        _sh(["git", "add", "."], cwd=self.src)
        _sh(["git", "commit", "-qm", "initial commit"], cwd=self.src)
        self.sha_initial = _sh(["git", "rev-parse", "HEAD"], cwd=self.src).stdout.strip()
        _sh(["git", "branch", "dev", self.sha_initial], cwd=self.src)
        (self.src / "tool.py").write_text("print('two')\n")
        _sh(["git", "add", "."], cwd=self.src)
        _sh(["git", "commit", "-qm", "add tool"], cwd=self.src)
        self.sha_tagged = _sh(["git", "rev-parse", "HEAD"], cwd=self.src).stdout.strip()
        _sh(["git", "tag", "-a", "-m", "release", "v1.0"], cwd=self.src)
        (self.src / "tool.py").write_text("print('three')\n")
        _sh(["git", "add", "."], cwd=self.src)
        _sh(["git", "commit", "-qm", "third commit"], cwd=self.src)
        if submodule_url is not None:
            # An ABSOLUTE-URL submodule registered without cloning it:
            # .gitmodules plus a gitlink index entry at a real commit SHA.
            (self.src / ".gitmodules").write_text(
                '[submodule "sub"]\n\tpath = sub\n\turl = ' + submodule_url + "\n"
            )
            _sh(["git", "add", ".gitmodules"], cwd=self.src)
            pinned = _sh(["git", "rev-parse", "HEAD"], cwd=self.src).stdout.strip()
            _sh(
                ["git", "update-index", "--add", "--cacheinfo",
                 f"160000,{pinned},sub"],
                cwd=self.src,
            )
            _sh(["git", "commit", "-qm", "register submodule"], cwd=self.src)
        self.head = _sh(["git", "rev-parse", "HEAD"], cwd=self.src).stdout.strip()
        _sh(["git", "clone", "-q", "--bare", str(self.src), str(self.bare)])
        (self.bare / "git-daemon-export-ok").touch()

    def add_commit(self, name, content):
        """Append one commit on main and push it into the bare origin."""
        (self.src / "tool.py").write_text(content)
        _sh(["git", "add", "."], cwd=self.src)
        _sh(["git", "commit", "-qm", name], cwd=self.src)
        sha = _sh(["git", "rev-parse", "HEAD"], cwd=self.src).stdout.strip()
        _sh(["git", "push", "-q", str(self.bare), "main"], cwd=self.src)
        return sha


@pytest.fixture
def fixture_repo(tmp_path):
    return _FixtureRepo(tmp_path / "repo-root")


def _git_spec(hostname=GIT_HOST):
    return runner_module.HostGrantSpec(
        hostname=hostname,
        purpose=GrantPurpose.GIT_SMART_FETCH,
        approval_source="m4b3-git-integration",
        approval_reference="slice-m4b3-s2",
    )


def _git_http_backend(env_extra, body):
    """Run the real git-http-backend CGI binary (stdlib bridge leg)."""
    return subprocess.run(
        ["/usr/lib/git-core/git-http-backend"],
        env=env_extra,
        input=body,
        capture_output=True,
        timeout=25,
    )


class _GitFixtureOrigin:
    """A stdlib TLS HTTP/1.1 CGI bridge to git-http-backend (fixture pair).

    Mirrors the M4B-3 fixture-origin model: an already-connected socketpair
    whose server end terminates TLS with an in-process CA leaf for the
    approved hostname, then translates each HTTP/1.1 request into a
    git-http-backend CGI invocation against the bare fixture repo and
    relays the response with Content-Length framing.  ``redirects`` maps a
    path prefix to a Location prefix for the redirect corpus items.
    """

    def __init__(self, cert_dir, repo, *, hostname=GIT_HOST, redirects=()):
        cert_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.pems = _custom_material(
            now - datetime.timedelta(minutes=2),
            now + datetime.timedelta(hours=1),
            hostname=hostname,
        )
        self.requests = []
        self.protocol_negotiated = []
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
            args=(server_end, repo, tuple(redirects)),
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
                raise RuntimeError("git origin request head exceeded test bound")
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        method, target, _version = lines[0].decode("ascii").split(" ")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(b":")
            headers[name.strip().lower().decode("ascii")] = value.strip().decode(
                "ascii"
            )
        if headers.get("expect", "").lower() == "100-continue":
            tls.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        length = int(headers.get("content-length", "0"))
        body = rest
        while len(body) < length:
            chunk = tls.recv(min(65536, length - len(body)))
            if not chunk:
                break
            body += chunk
        return method, target, headers, body

    def _respond_redirect(self, tls, location):
        tls.sendall(
            b"HTTP/1.1 302 Found\r\nLocation: " + location.encode("ascii")
            + b"\r\nContent-Length: 0\r\n\r\n"
        )

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
        # Record the negotiated protocol version from the advertisement:
        # v2 opens with "000eversion 2", v0 with "001e# service=".
        negotiated = (
            "2" if cgi_body.startswith(b"000eversion 2") else "0"
        )
        self.protocol_negotiated.append(negotiated)
        tls.sendall(wire)

    def _run(self, sock, repo, redirects):
        try:
            tls = self._context.wrap_socket(sock, server_side=True)
            tls.settimeout(25.0)
            for _ in range(MAX_REQUESTS_PER_ORIGIN):
                parsed = self._read_request(tls)
                if parsed is None:
                    break
                method, target, headers, body = parsed
                # git 2.53 sends Git-Protocol: version=2 by default; map it
                # to the CGI variable so http-backend negotiates protocol v2
                # (what real hosting serves) instead of silently serving v0.
                self.requests.append(
                    (method, target, headers.get("git-protocol"))
                )
                path, _, query = target.partition("?")
                redirect = next(
                    (location for prefix, location in redirects
                     if path.startswith(prefix)),
                    None,
                )
                if redirect is not None:
                    location = redirect + path[len(
                        next(p for p, _l in redirects if path.startswith(p))
                    ):]
                    if query:
                        location = f"{location}?{query}"
                    self._respond_redirect(tls, location)
                    continue
                env = {
                    "REQUEST_METHOD": method,
                    "PATH_INFO": path,
                    "QUERY_STRING": query,
                    "GIT_PROJECT_ROOT": str(repo.project_root),
                    "GIT_HTTP_EXPORT_ALL": "1",
                    "PATH": "/usr/bin:/bin",
                }
                if "content-type" in headers:
                    env["CONTENT_TYPE"] = headers["content-type"]
                if "git-protocol" in headers:
                    env["HTTP_GIT_PROTOCOL"] = headers["git-protocol"]
                if body:
                    env["CONTENT_LENGTH"] = str(len(body))
                self._respond_cgi(tls, _git_http_backend(env, body))
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

    def join(self, timeout=8.0):
        self._thread.join(timeout)
        assert not self._thread.is_alive(), "git origin thread stuck"

    def close(self):
        try:
            self.broker_sock.close()
        except OSError:
            pass


def _git_worker_options(options):
    return _worker_argv(
        "--scenario",
        "M4B3-GIT-01",
        "--target",
        "git",
        "--canary",
        json.dumps(options, separators=(",", ":")),
    )


def _run_git_worker(runner, options):
    process = runner.run(_git_worker_options(options), cwd="/workspace", env={})
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


def _git_step(argv, **changes):
    step = {"op": "git", "argv": argv}
    step.update(changes)
    return step


# ---------------------------------------------------------------------------
# 1. Approved ls-remote succeeds (and is the ALPN-fallback proof, item 17)
# ---------------------------------------------------------------------------


def test_git_ls_remote_approved_succeeds(m4b3_runner_factory, fixture_repo, tmp_path):
    origin_a = _GitFixtureOrigin(tmp_path / "origin-a", fixture_repo)
    origin_b = _GitFixtureOrigin(tmp_path / "origin-b", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin_a, origin_b),
        byte_limit=1 << 20,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(["ls-remote", GIT_URL]),
                # Item 17 offer-side proof: capture curl's ALPN lines.
                _git_step(
                    ["ls-remote", GIT_URL],
                    env_extra={"GIT_CURL_VERBOSE": "1"},
                    stderr_filter=["ALPN"],
                ),
            ]
        },
    )
    step, verbose_step = steps
    assert step["exit_code"] == 0, step["stderr"]
    assert fixture_repo.head in step["stdout"]
    assert "refs/heads/dev" in step["stdout"]
    assert "refs/heads/main" in step["stdout"]
    assert "refs/tags/v1.0" in step["stdout"]
    assert verbose_step["exit_code"] == 0, verbose_step["stderr"]
    # The real libcurl-gnutls offers h2+http/1.1; the broker's worker
    # context negotiates exactly http/1.1 — corpus-backed offer-side proof.
    assert "offers h2" in verbose_step["stderr"]
    assert "accepted http/1.1" in verbose_step["stderr"]

    origin_a.join()
    origin_b.join()
    served = origin_a.requests + origin_b.requests
    # Measured under protocol v2 (the git 2.53 default): each ls-remote is
    # GET info/refs PLUS a POST ls-refs on the same tunnel.
    assert served == [
        ("GET", "/repo.git/info/refs?service=git-upload-pack", "version=2"),
        ("POST", "/repo.git/git-upload-pack", "version=2"),
        ("GET", "/repo.git/info/refs?service=git-upload-pack", "version=2"),
        ("POST", "/repo.git/git-upload-pack", "version=2"),
    ]
    assert origin_a.errors == [] and origin_b.errors == []
    records = _records(runner, 2)
    assert all(record.approved_hostname == GIT_HOST for record in records)
    assert all(record.identity_chain == "verified" for record in records)
    assert all(record.origin_tls_name == GIT_HOST for record in records)
    assert all(record.synthetic_origin is True for record in records)
    # The successful operation plus this evidence IS the ALPN fallback
    # proof with the real binary.
    assert all(record.worker_alpn == "http/1.1" for record in records)
    assert all(record.origin_alpn == "http/1.1" for record in records)
    assert all(record.requests_completed == 2 for record in records)
    origin_a.close()
    origin_b.close()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 1b. Git protocol v2 negotiated end-to-end (v0 path kept working)
# ---------------------------------------------------------------------------


def test_git_protocol_v2_negotiated_and_v0_kept(m4b3_runner_factory, fixture_repo, tmp_path):
    """git 2.53 sends Git-Protocol: version=2 by default; the bridge maps it
    to HTTP_GIT_PROTOCOL so http-backend negotiates v2 (what real hosting
    serves).  A forced protocol.version=0 leg proves the v0 path too."""
    origin_a = _GitFixtureOrigin(tmp_path / "origin-a", fixture_repo)
    origin_b = _GitFixtureOrigin(tmp_path / "origin-b", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin_a, origin_b),
        byte_limit=1 << 20,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(["ls-remote", GIT_URL]),
                _git_step(["-c", "protocol.version=0", "ls-remote", GIT_URL]),
            ]
        },
    )
    v2_step, v0_step = steps
    assert v2_step["exit_code"] == 0, v2_step["stderr"]
    assert fixture_repo.head in v2_step["stdout"]
    assert v0_step["exit_code"] == 0, v0_step["stderr"]
    assert fixture_repo.head in v0_step["stdout"]

    origin_a.join()
    origin_b.join()
    served = origin_a.requests + origin_b.requests
    negotiated = origin_a.protocol_negotiated + origin_b.protocol_negotiated
    # The default leg negotiated protocol v2 end-to-end through the broker.
    assert (
        "GET",
        "/repo.git/info/refs?service=git-upload-pack",
        "version=2",
    ) in served
    assert "2" in negotiated
    # The forced v0 leg sent no Git-Protocol header and was served v0.
    assert ("GET", "/repo.git/info/refs?service=git-upload-pack", None) in served
    assert "0" in negotiated
    records = _records(runner, 2)
    assert all(record.identity_chain == "verified" for record in records)
    origin_a.close()
    origin_b.close()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 2. Wrong host fails
# ---------------------------------------------------------------------------


def test_git_ls_remote_ungranted_host_fails(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
    )
    steps = _run_git_worker(
        runner, {"steps": [_git_step(["ls-remote", GIT_URL_OTHER])]}
    )
    (step,) = steps
    assert step["exit_code"] != 0
    (record,) = _records(runner, 1)
    assert record.stage_reached.value == "authorization"
    assert record.detail == "authorization_no_match"
    # Single-grant policy: the sole-grant evidence fallback records the one
    # approved hostname and the observed divergent CONNECT authority.
    assert record.approved_hostname == GIT_HOST
    assert record.connect_authority == GIT_HOST_OTHER
    assert record.identity_chain == "identity_divergence:connect_authority"
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 3. Direct network bypass fails (proxy env scrubbed)
# ---------------------------------------------------------------------------


def test_git_direct_bypass_fails(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(
                    ["ls-remote", GIT_URL],
                    env_scrub=["https_proxy", "HTTPS_PROXY"],
                ),
                # no_proxy named the granted host while https_proxy remains:
                # curl bypasses the broker for it, direct egress is dead.
                _git_step(
                    ["ls-remote", GIT_URL],
                    env_extra={"no_proxy": GIT_HOST, "NO_PROXY": GIT_HOST},
                ),
            ]
        },
    )
    scrub_step, no_proxy_step = steps
    assert scrub_step["exit_code"] != 0
    assert no_proxy_step["exit_code"] != 0
    # Nothing ever reached the broker: no connection, no DNS, no authority.
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 4. Clone succeeds; objects verified
# ---------------------------------------------------------------------------


def test_git_clone_succeeds_and_fsck_clean(m4b3_runner_factory, fixture_repo, tmp_path):
    origin_a = _GitFixtureOrigin(tmp_path / "origin-a", fixture_repo)
    origin_b = _GitFixtureOrigin(tmp_path / "origin-b", fixture_repo)
    origin_c = _GitFixtureOrigin(tmp_path / "origin-c", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin_a, origin_b, origin_c),
        connection_limit=8,
        byte_limit=1 << 20,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(["clone", "-q", GIT_URL, "/workspace/clone1"]),
                _git_step(["-C", "/workspace/clone1", "rev-parse", "HEAD"]),
                _git_step(["-C", "/workspace/clone1", "fsck", "--strict"]),
            ]
        },
    )
    clone_step, head_step, fsck_step = steps
    assert clone_step["exit_code"] == 0, clone_step["stderr"]
    assert head_step["exit_code"] == 0
    assert head_step["stdout"].strip() == fixture_repo.head
    assert fsck_step["exit_code"] == 0, fsck_step["stderr"]

    terminal = runner.last_https_terminal
    assert terminal is not None and terminal.synthetic_origin is True
    records = _records(runner)
    # Measured: this libcurl reuses ONE tunnel for the whole clone; under
    # protocol v2 that is 3 requests (GET advertisement, POST ls-refs,
    # POST fetch).
    assert len(records) == 1, records
    (record,) = records
    assert record.approved_hostname == GIT_HOST
    assert record.identity_chain == "verified"
    assert record.requests_completed == 3
    for origin in (origin_a, origin_b, origin_c):
        origin.close()
        origin.join()
    served = origin_a.requests + origin_b.requests + origin_c.requests
    assert (
        "GET",
        "/repo.git/info/refs?service=git-upload-pack",
        "version=2",
    ) in served
    assert ("POST", "/repo.git/git-upload-pack", "version=2") in served
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 5. Fetch retrieves a commit added to the origin mid-run
# ---------------------------------------------------------------------------


def test_git_fetch_retrieves_new_origin_commit(m4b3_runner_factory, fixture_repo, tmp_path):
    origins = tuple(
        _GitFixtureOrigin(tmp_path / f"origin-{index}", fixture_repo)
        for index in range(4)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=origins,
        connection_limit=8,
        byte_limit=1 << 20,
    )
    marker = "/workspace/.m4b3-fetch-go"
    result_holder = {}

    def run():
        result_holder["steps"] = _run_git_worker(
            runner,
            {
                "steps": [
                    _git_step(["clone", "-q", GIT_URL, "/workspace/clone1"]),
                    {"op": "wait_path", "path": marker, "timeout": 25},
                    _git_step(["-C", "/workspace/clone1", "fetch", "-q", "origin"]),
                    _git_step(
                        ["-C", "/workspace/clone1", "rev-parse", "origin/main"]
                    ),
                ]
            },
        )

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    # The clone lands in the host-visible assigned worktree; once it exists,
    # add the new origin commit and release the worker to fetch it.
    clone_readme = Path(runner.workspace) / "clone1" / "README.md"
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline and not clone_readme.exists():
        time.sleep(0.1)
    assert clone_readme.exists(), "clone never appeared in the worktree"
    new_sha = fixture_repo.add_commit("fourth commit", "print('four')\n")
    (Path(runner.workspace) / ".m4b3-fetch-go").write_text("go\n")
    thread.join(60)
    assert not thread.is_alive(), "worker run stuck"
    steps = result_holder["steps"]
    clone_step, wait_step, fetch_step, parse_step = steps
    assert clone_step["exit_code"] == 0, clone_step["stderr"]
    assert wait_step["found"] is True
    assert fetch_step["exit_code"] == 0, fetch_step["stderr"]
    assert parse_step["stdout"].strip() == new_sha
    records = _records(runner)
    assert len(records) >= 2
    assert all(record.identity_chain == "verified" for record in records)
    for origin in origins:
        origin.close()
        origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 6. Pinned ref retrieval (exact tag identity)
# ---------------------------------------------------------------------------


def test_git_checkout_exact_tag_identity(m4b3_runner_factory, fixture_repo, tmp_path):
    origins = tuple(
        _GitFixtureOrigin(tmp_path / f"origin-{index}", fixture_repo)
        for index in range(3)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=origins,
        connection_limit=8,
        byte_limit=1 << 20,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(["clone", "-q", GIT_URL, "/workspace/clone1"]),
                _git_step(["-C", "/workspace/clone1", "checkout", "-q", "v1.0"]),
                _git_step(["-C", "/workspace/clone1", "rev-parse", "HEAD"]),
            ]
        },
    )
    clone_step, checkout_step, head_step = steps
    assert clone_step["exit_code"] == 0, clone_step["stderr"]
    assert checkout_step["exit_code"] == 0, checkout_step["stderr"]
    # The exact pinned identity: the annotated tag's commit, byte-exact.
    assert head_step["stdout"].strip() == fixture_repo.sha_tagged
    for origin in origins:
        origin.close()
        origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 7. Custom unapproved proxy cannot escape (env and -c variants)
# ---------------------------------------------------------------------------


def test_git_custom_proxy_cannot_escape(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(
                    ["ls-remote", GIT_URL],
                    env_extra={"https_proxy": "http://127.0.0.1:9"},
                ),
                _git_step(
                    ["-c", "http.proxy=http://127.0.0.1:9", "ls-remote", GIT_URL]
                ),
            ]
        },
    )
    env_step, config_step = steps
    assert env_step["exit_code"] != 0
    assert config_step["exit_code"] != 0
    # Neither variant ever produced a broker connection.
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 8. GIT_SSL_NO_VERIFY cannot widen authority
# ---------------------------------------------------------------------------


def test_git_ssl_no_verify_cannot_widen(m4b3_runner_factory, fixture_repo, tmp_path):
    origin = _GitFixtureOrigin(tmp_path / "origin", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(
                    ["ls-remote", GIT_URL_OTHER],
                    env_extra={"GIT_SSL_NO_VERIFY": "1"},
                ),
                _git_step(
                    ["ls-remote", GIT_URL],
                    env_extra={"GIT_SSL_NO_VERIFY": "1"},
                ),
            ]
        },
    )
    other_step, approved_step = steps
    # Worker-side verification is the worker's own concern: with
    # GIT_SSL_NO_VERIFY the worker skips verifying the task CA, but the
    # broker-side authorization and origin TLS authentication are unchanged.
    assert other_step["exit_code"] != 0
    assert approved_step["exit_code"] == 0, approved_step["stderr"]
    assert fixture_repo.head in approved_step["stdout"]
    record_other, record_approved = _records(runner, 2)
    assert record_other.detail == "authorization_no_match"
    assert record_other.connect_authority == GIT_HOST_OTHER
    assert record_other.identity_chain == "identity_divergence:connect_authority"
    assert record_approved.approved_hostname == GIT_HOST
    assert record_approved.identity_chain == "verified"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 9. Unapproved CA override cannot widen authority
# ---------------------------------------------------------------------------


def test_git_unapproved_ca_override_cannot_widen(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(
                    ["ls-remote", GIT_URL_OTHER],
                    env_extra={
                        "GIT_SSL_CAINFO": "/nonexistent/attacker.pem",
                        "SSL_CERT_FILE": "/nonexistent/attacker.pem",
                    },
                ),
                _git_step(
                    ["ls-remote", GIT_URL],
                    env_extra={
                        "GIT_SSL_CAINFO": "/nonexistent/attacker.pem",
                        "SSL_CERT_FILE": "/nonexistent/attacker.pem",
                    },
                ),
            ]
        },
    )
    other_step, approved_step = steps
    # Unapproved still fails broker-side; the approved host fails only
    # WORKER-side (its own trust decision) — nothing escapes either way.
    assert other_step["exit_code"] != 0
    assert approved_step["exit_code"] != 0
    record_other, record_approved = _records(runner, 2)
    assert record_other.detail == "authorization_no_match"
    assert record_approved.stage_reached.value == "worker_tls"
    assert record_approved.terminal_reason.value == "denied"
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 10. HTTP downgrade fails
# ---------------------------------------------------------------------------


def test_git_http_downgrade_fails(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
    )
    steps = _run_git_worker(
        runner, {"steps": [_git_step(["ls-remote", GIT_HTTP_URL])]}
    )
    (step,) = steps
    assert step["exit_code"] != 0
    # A plain http:// URL consults http_proxy — ABSENT from the fixed
    # profile by construction — so the downgrade attempt attempts direct
    # egress (impossible in the worker) and never reaches the broker at
    # all; even a CONNECT would be denied before any trust stage.
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 11. Unapproved redirect host fails
# ---------------------------------------------------------------------------


def test_git_unapproved_redirect_fails(m4b3_runner_factory, fixture_repo, tmp_path):
    origin = _GitFixtureOrigin(
        tmp_path / "origin",
        fixture_repo,
        redirects=(
            ("/repo.git", f"https://{GIT_HOST_OTHER}/repo.git"),
        ),
    )
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_git_worker(
        runner, {"steps": [_git_step(["ls-remote", GIT_URL])]}
    )
    (step,) = steps
    assert step["exit_code"] != 0
    records = _records(runner, 2)
    # The 302 is relayed byte-exact (never followed by the broker)...
    relayed = [r for r in records if r.identity_chain == "verified"]
    denied = [r for r in records if r.detail == "authorization_no_match"]
    assert len(relayed) == 1 and relayed[0].approved_hostname == GIT_HOST
    # ...and the redirect target re-enters authorization and is denied.
    assert len(denied) == 1
    assert denied[0].stage_reached.value == "authorization"
    assert denied[0].connect_authority == GIT_HOST_OTHER
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 12. Same-host redirect stays inside authority
# ---------------------------------------------------------------------------


def test_git_same_host_redirect_succeeds(m4b3_runner_factory, fixture_repo, tmp_path):
    origin_a = _GitFixtureOrigin(
        tmp_path / "origin-a",
        fixture_repo,
        redirects=(("/redir/", f"https://{GIT_HOST}/"),),
    )
    origin_b = _GitFixtureOrigin(tmp_path / "origin-b", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin_a, origin_b),
    )
    steps = _run_git_worker(
        runner,
        {"steps": [_git_step(["ls-remote", f"https://{GIT_HOST}/redir/repo.git"])]},
    )
    (step,) = steps
    assert step["exit_code"] == 0, step["stderr"]
    assert fixture_repo.head in step["stdout"]
    records = _records(runner)
    # Measured: curl REUSES the existing tunnel for a same-host redirect —
    # one broker connection relaying the 302 GET, the followed GET, and the
    # v2 POST ls-refs.
    assert len(records) == 1, records
    (record,) = records
    assert record.approved_hostname == GIT_HOST
    assert record.identity_chain == "verified"
    assert record.requests_completed == 3
    origin_a.close()
    origin_b.close()
    origin_a.join()
    origin_b.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 12b. Absolute-URL submodule to an unapproved host fails at its fetch
# ---------------------------------------------------------------------------


def test_git_unapproved_submodule_fetch_fails(m4b3_runner_factory, tmp_path):
    """A .gitmodules ABSOLUTE URL naming an ungranted host: the parent repo
    clones clean through the broker, then the submodule fetch re-enters
    authorization and is denied.  (The same-host submodule case is the
    same-host grant class, covered by items 1/12 — see the doc.)"""
    repo = _FixtureRepo(
        tmp_path / "repo-root", submodule_url=f"https://{GIT_HOST_OTHER}/repo.git"
    )
    origins = tuple(
        _GitFixtureOrigin(tmp_path / f"origin-{index}", repo)
        for index in range(3)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=origins,
        connection_limit=8,
        byte_limit=1 << 20,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(
                    ["clone", "-q", "--recurse-submodules", GIT_URL,
                     "/workspace/clone1"]
                )
            ]
        },
    )
    (clone_step,) = steps
    assert clone_step["exit_code"] != 0
    assert "sub" in clone_step["stderr"].lower() or "submodule" in (
        clone_step["stderr"].lower()
    )
    records = _records(runner)
    verified = [r for r in records if r.identity_chain == "verified"]
    denied = [r for r in records if r.detail == "authorization_no_match"]
    # The parent clone crossed the broker with a verified chain...
    assert verified and all(r.approved_hostname == GIT_HOST for r in verified)
    # ...and the submodule's unapproved host was denied at authorization
    # (git retries the submodule clone; every attempt denies identically).
    assert denied
    assert all(r.connect_authority == GIT_HOST_OTHER for r in denied)
    for origin in origins:
        origin.close()
        origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 13. Credential helper leakage absent
# ---------------------------------------------------------------------------


def test_git_credential_isolation(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                {"op": "env_census"},
                {"op": "home_census"},
                {"op": "git_config_list"},
            ]
        },
    )
    env_step, home_step, config_step = steps
    environment = env_step["environment"]
    assert "GIT_ASKPASS" not in environment
    assert "SSH_ASKPASS" not in environment
    assert home_step["gitconfig_present"] is False
    assert home_step["git_credentials_present"] is False
    assert ".gitconfig" not in home_step["entries"]
    assert ".git-credentials" not in home_step["entries"]
    config_text = config_step["stdout"].lower()
    assert "credential" not in config_text
    assert "http.proxy" not in config_text
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 14. SSH transport unavailable
# ---------------------------------------------------------------------------


def test_git_ssh_transport_unavailable(m4b3_runner_factory, tmp_path):
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(["ls-remote", f"ssh://git@{GIT_HOST}/repo.git"]),
                _git_step(["ls-remote", f"git@{GIT_HOST}:repo.git"]),
            ]
        },
    )
    ssh_url_step, scp_style_step = steps
    assert ssh_url_step["exit_code"] != 0
    assert scp_style_step["exit_code"] != 0
    # No SSH path ever touches the broker: zero connections.
    _records(runner, 0)
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 15. Worker DNS remains unavailable while git succeeds
# ---------------------------------------------------------------------------


def test_git_worker_dns_unavailable(m4b3_runner_factory, fixture_repo, tmp_path):
    origin = _GitFixtureOrigin(tmp_path / "origin", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                {"op": "dns_probe", "hostname": GIT_HOST},
                _git_step(["ls-remote", GIT_URL]),
            ]
        },
    )
    dns_step, git_step = steps
    assert dns_step["resolved"] is False
    assert dns_step["error_type"] == "gaierror"
    assert git_step["exit_code"] == 0, git_step["stderr"]
    assert fixture_repo.head in git_step["stdout"]
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 16. No unexpected worker FDs after git operations
# ---------------------------------------------------------------------------


def test_git_worker_fd_census_clean(m4b3_runner_factory, fixture_repo, tmp_path):
    origin = _GitFixtureOrigin(tmp_path / "origin", fixture_repo)
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(["ls-remote", GIT_URL]),
                {"op": "fd_census"},
            ]
        },
    )
    git_step, fd_step = steps
    assert git_step["exit_code"] == 0, git_step["stderr"]
    fds = fd_step["fds"]
    # The git subprocess is dead and its descriptors reaped: only the
    # worker's own small fixed descriptor set remains.
    assert all(fd <= 2 for fd in fds), fds
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# 18. Shallow clone and specific-branch clone succeed
# ---------------------------------------------------------------------------


def test_git_shallow_and_branch_clones(m4b3_runner_factory, fixture_repo, tmp_path):
    origins = tuple(
        _GitFixtureOrigin(tmp_path / f"origin-{index}", fixture_repo)
        for index in range(4)
    )
    runner = m4b3_runner_factory(
        grant_specs=(_git_spec(),),
        connected_build_profile=True,
        fixture_origins=origins,
        connection_limit=8,
        byte_limit=1 << 20,
    )
    steps = _run_git_worker(
        runner,
        {
            "steps": [
                _git_step(
                    ["clone", "-q", "--depth", "1", GIT_URL, "/workspace/shallow"]
                ),
                _git_step(["-C", "/workspace/shallow", "rev-parse", "HEAD"]),
                _git_step(
                    ["-C", "/workspace/shallow", "rev-list", "--count", "HEAD"]
                ),
                _git_step(
                    ["clone", "-q", "--branch", "dev", GIT_URL, "/workspace/brdev"]
                ),
                _git_step(["-C", "/workspace/brdev", "rev-parse", "HEAD"]),
                _git_step(["-C", "/workspace/brdev", "branch", "--show-current"]),
            ]
        },
    )
    shallow_clone, shallow_head, shallow_count, dev_clone, dev_head, dev_branch = steps
    assert shallow_clone["exit_code"] == 0, shallow_clone["stderr"]
    assert shallow_head["stdout"].strip() == fixture_repo.head
    assert shallow_count["stdout"].strip() == "1"
    assert dev_clone["exit_code"] == 0, dev_clone["stderr"]
    assert dev_head["stdout"].strip() == fixture_repo.sha_initial
    assert dev_branch["stdout"].strip() == "dev"
    records = _records(runner)
    assert all(record.identity_chain == "verified" for record in records)
    for origin in origins:
        origin.close()
        origin.join()
    _assert_no_m4b_residue(runner)
