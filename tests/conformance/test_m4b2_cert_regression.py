"""Regression tests for M4B-2 adversarial-review findings in cert_helper.py.

CERT-01: the helper subprocess previously inherited the controller's full
environment and cwd (``env = dict(os.environ)`` + ``-m`` module load), so a
caller-controlled PYTHONPATH sitecustomize.py or a cwd-shadowed package
executed inside the CA-key-holding child. The spawn must use a fixed minimal
environment, ``-I`` interpreter isolation, an absolute-path module load, and
RLIMIT_CORE=0.

CERT-03: the helper kill path did an unbounded ``wait()`` after ``kill()``;
the reap must be bounded and fail closed on reap timeout.

Hostname F2: ``_require_hostname`` was a parallel hostname grammar that
accepted forms the canonical grammar rejects (``xn--`` labels, all-digit /
hex-numeric labels). It must reuse ``network_https.canonicalize_hostname``
and reject raw non-canonical input.

All tests require Linux (memfd sealing); the module skips elsewhere.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 certificate helper requires Linux", allow_module_level=True)

import subprocess

from agenticos.sandbox import cert_helper as ch


TASK_CONTEXT = {
    "task_id": "task-cert-regression",
    "task_generation": 3,
    "launch_nonce": "ab" * 16,
    "hostname": "approved.example.test",
    "policy_digest": "cd" * 32,
}


def _verify(generated):
    return ch.verify_task_material(
        ca_cert_fd=generated.ca_cert_fd,
        leaf_cert_fd=generated.leaf_cert_fd,
        leaf_key_fd=generated.leaf_key_fd,
        binding_fd=generated.binding_fd,
        **TASK_CONTEXT,
    )


# -- CERT-01: helper spawn isolation ---------------------------------------------


def test_helper_environment_is_fixed_and_minimal(monkeypatch):
    """The child must not inherit caller-controlled environment variables."""
    monkeypatch.setenv("PYTHONPATH", "/tmp/attacker-controlled")
    monkeypatch.setenv("ATTACKER_JUNK", "1")
    env = ch._helper_environment()
    assert "PYTHONPATH" not in env
    assert "ATTACKER_JUNK" not in env
    assert env == {}


def test_helper_ignores_poisoned_pythonpath_and_cwd(tmp_path, monkeypatch):
    """The reviewer's injection probe must not execute inside the helper.

    A sitecustomize.py on the inherited PYTHONPATH and an ``agenticos``
    package shadowing the real one from the inherited cwd both ran inside
    the pre-fix helper. After the fix, neither marker may appear and the
    helper must still produce fully valid sealed material.
    """
    poison = tmp_path / "pythonpath-poison"
    poison.mkdir()
    site_marker = tmp_path / "sitecustomize-ran.marker"
    (poison / "sitecustomize.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(site_marker)!r}).write_text('pwned')\n"
    )
    cwd_poison = tmp_path / "cwd-poison"
    (cwd_poison / "agenticos").mkdir(parents=True)
    shadow_marker = tmp_path / "shadow-agenticos-ran.marker"
    (cwd_poison / "agenticos" / "__init__.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(shadow_marker)!r}).write_text('pwned')\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(poison))
    monkeypatch.chdir(cwd_poison)

    generated = ch.generate_task_material(**TASK_CONTEXT)
    try:
        assert not site_marker.exists(), "injected sitecustomize executed in helper"
        assert not shadow_marker.exists(), (
            "cwd-shadowed agenticos package executed in helper"
        )
        verified = _verify(generated)
        assert verified.binding.hostname == TASK_CONTEXT["hostname"]
    finally:
        generated.close()


def test_helper_spawn_disables_core_dumps():
    """The child preexec must zero RLIMIT_CORE (CA key must never hit disk)."""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import resource; print(resource.getrlimit(resource.RLIMIT_CORE))",
        ],
        env=ch._helper_environment(),
        preexec_fn=ch._helper_preexec,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.decode("ascii").strip() == "(0, 0)"


# -- CERT-03: bounded kill/reap path ----------------------------------------------


class _StubHelperProcess:
    """Minimal subprocess stand-in for the helper timeout/kill path."""

    def __init__(self, reap_raises: bool):
        self._reap_raises = reap_raises
        self.kill_calls = 0
        self.wait_timeouts: list = []
        self.returncode = None
        self.pid = 424242

    def communicate(self, payload, timeout=None):
        raise subprocess.TimeoutExpired(cmd="cert-helper", timeout=timeout)

    def kill(self):
        self.kill_calls += 1

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        if self._reap_raises:
            raise subprocess.TimeoutExpired(cmd="cert-helper", timeout=timeout)
        self.returncode = -9
        return self.returncode


def test_helper_kill_path_uses_bounded_reap(monkeypatch):
    """kill() must be followed by a BOUNDED wait, then fail closed."""
    stub = _StubHelperProcess(reap_raises=False)
    monkeypatch.setattr(ch, "_spawn_helper", lambda request, fds: stub)
    with pytest.raises(ch.CertHelperError, match="exceeded its time bound"):
        ch.generate_task_material(**TASK_CONTEXT)
    assert stub.kill_calls == 1
    assert stub.wait_timeouts, "wait() was never called after kill()"
    assert all(
        timeout is not None and timeout > 0 for timeout in stub.wait_timeouts
    ), "wait() after kill() must carry a bound"


def test_helper_reap_timeout_fails_closed(monkeypatch):
    """A helper that ignores kill() must abort the launch in bounded time."""
    stub = _StubHelperProcess(reap_raises=True)
    monkeypatch.setattr(ch, "_spawn_helper", lambda request, fds: stub)
    with pytest.raises(ch.CertHelperError, match="reaped in bounded time"):
        ch.generate_task_material(**TASK_CONTEXT)
    assert stub.kill_calls == 1
    assert stub.wait_timeouts and all(
        timeout is not None for timeout in stub.wait_timeouts
    )


# -- Hostname F2: canonical grammar at the cert layer ------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "EXAMPLE.com",  # uppercase: canonical form differs from the raw input
        "Example.COM",
        "ex_ample.com",  # underscore is outside LDH
        "xn--nxasmq6b.example",  # punycode label
        "example.123",  # all-digit final label
        "127.0.0.1",  # IP literal (all-digit labels)
        "2130706433",  # inet_aton legacy numeric
        "0x7f.1",  # hex numeric label
        "example.com.",  # trailing dot / empty label
        "a..b",  # empty label
        "-bad.example",  # leading hyphen
        "bad-.example",  # trailing hyphen
        "",  # empty
    ],
)
def test_require_hostname_rejects_noncanonical(raw):
    with pytest.raises(ch.CertHelperError):
        ch._require_hostname(raw)


@pytest.mark.parametrize("raw", [None, 123, b"example.com", ["example.com"]])
def test_require_hostname_rejects_non_string(raw):
    with pytest.raises(ch.CertHelperError):
        ch._require_hostname(raw)


@pytest.mark.parametrize(
    "canonical",
    [
        "approved.example.test",
        "a",
        "x-y.example",
        "a1.b2-c3.example",
    ],
)
def test_require_hostname_accepts_canonical(canonical):
    ch._require_hostname(canonical)


def test_cert_binding_rejects_noncanonical_hostname():
    with pytest.raises(ch.CertHelperError):
        ch.CertBinding(
            version=ch._BINDING_VERSION,
            task_id=TASK_CONTEXT["task_id"],
            task_generation=TASK_CONTEXT["task_generation"],
            launch_nonce=TASK_CONTEXT["launch_nonce"],
            hostname="xn--nxasmq6b.example",
            policy_digest=TASK_CONTEXT["policy_digest"],
            ca_cert_sha256="ab" * 32,
            leaf_cert_sha256="ab" * 32,
            leaf_key_sha256="ab" * 32,
        )
