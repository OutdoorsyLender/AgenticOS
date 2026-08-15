from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from agenticos.providers.kimi_runtime import (
    KimiRuntimeError,
    KimiRuntimeSpec,
    build_runtime_spec,
    run_passive_kimi,
)


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    executable = tmp_path / "runtime" / "bin" / "kimi"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"not-run")
    executable.chmod(0o555)
    bundle = tmp_path / "qualification"
    (bundle / "agents").mkdir(parents=True)
    for relative in ("artifact.json", "config.toml", "agents/agent.md"):
        (bundle / relative).write_text("fixture", encoding="utf-8")
    return executable, bundle


def test_runtime_argv_is_minimal_network_denied_checkout_free_and_read_only(tmp_path: Path) -> None:
    executable, bundle = _paths(tmp_path)
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    argv = spec.bwrap_argv(("--version",))
    joined = "\n".join(argv)
    assert argv[0] == "/usr/bin/bwrap"
    for required in (
        "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc",
        "--unshare-uts", "--die-with-parent", "--new-session", "--clearenv",
    ):
        assert required in argv
    assert str(executable) in argv
    assert str(bundle / "config.toml") in argv
    assert str(bundle / "agents") in argv
    assert "/opt/agenticos/kimi/bin/kimi" in argv
    assert "--ro-bind" in argv
    assert "--bind" not in argv
    assert "/workspace" in argv
    assert "/mnt/c" not in joined
    assert "/home/brand/src/AgenticOS" not in joined
    assert ".git" not in joined
    assert "/home/aos/kimi/credentials" not in joined


def test_runtime_environment_is_exact_and_never_inherits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable, bundle = _paths(tmp_path)
    monkeypatch.setenv("KIMI_API_KEY", "secret")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/secret.sock")
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    argv = spec.bwrap_argv(("--version",))
    pairs = [(argv[index + 1], argv[index + 2]) for index, item in enumerate(argv) if item == "--setenv"]
    assert dict(pairs) == spec.environment
    assert "KIMI_API_KEY" not in dict(pairs)
    assert "SSH_AUTH_SOCK" not in dict(pairs)
    assert "secret" not in repr(argv)


@pytest.mark.parametrize(
    "args",
    [(), ("login",), ("--login",), ("-p", "hello"), ("acp", "--login"), ("server", "run")],
)
def test_runtime_rejects_login_prompt_and_unapproved_modes(tmp_path: Path, args: tuple[str, ...]) -> None:
    executable, bundle = _paths(tmp_path)
    with pytest.raises(KimiRuntimeError, match="COMMAND_NOT_QUALIFICATION_SAFE"):
        KimiRuntimeSpec(executable=executable, bundle=bundle).bwrap_argv(args)


def test_runtime_allows_only_passive_introspection_and_acp(tmp_path: Path) -> None:
    executable, bundle = _paths(tmp_path)
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    for args in (("--version",), ("--help",), ("acp",), ("acp", "--help")):
        assert spec.bwrap_argv(args)[-len(args) :] == list(args)


def test_synthetic_fixture_stays_in_same_network_namespace_and_uses_no_real_config(tmp_path: Path) -> None:
    executable, bundle = _paths(tmp_path)
    fixture = tmp_path / "fixture.py"
    fixture.write_text("print('fixture')\n", encoding="utf-8")
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    argv = spec.synthetic_fixture_argv(fixture, "plan")
    joined = "\n".join(argv)
    assert "--unshare-net" in argv
    assert str(fixture) in argv
    assert "/opt/agenticos/qualification/kimi_loopback_fixture.py" in argv
    assert str(bundle / "config.toml") not in argv
    assert str(bundle / "agents") in argv
    assert argv[-3:] == ["/usr/bin/python3", "/opt/agenticos/qualification/kimi_loopback_fixture.py", "plan"]
    assert "login" not in joined
    assert "--share-net" not in argv


def test_build_runtime_spec_requires_absolute_non_symlink_paths(tmp_path: Path) -> None:
    executable, bundle = _paths(tmp_path)
    link = tmp_path / "kimi-link"
    link.symlink_to(executable)
    with pytest.raises(KimiRuntimeError, match="RUNTIME_EXECUTABLE_SYMLINK"):
        build_runtime_spec(link, bundle)
    with pytest.raises(KimiRuntimeError, match="BUNDLE_PATH"):
        build_runtime_spec(executable, Path("relative"))


def test_run_uses_empty_host_environment_closed_fds_and_bounded_capture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable, bundle = _paths(tmp_path)
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = b"0.36.1\n"
        stderr = b""

    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        captured["argv"] = argv
        captured.update(kwargs)
        return Completed()

    monkeypatch.setattr("agenticos.providers.kimi_runtime._run_bounded", fake_run)
    monkeypatch.setattr("agenticos.providers.kimi_runtime._verify_spec_identity", lambda _: None)
    observation = run_passive_kimi(spec, ("--version",), timeout_seconds=2)
    assert observation.returncode == 0
    assert observation.stdout == b"0.36.1\n"
    assert captured["timeout_seconds"] == 2
    assert captured["stdout_limit"] == 65_536
    assert captured["stderr_limit"] == 65_536
    assert captured["overflow_code"] == "RUNTIME_OUTPUT_LIMIT"


def test_output_and_timeout_are_fail_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable, bundle = _paths(tmp_path)
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    monkeypatch.setattr("agenticos.providers.kimi_runtime._verify_spec_identity", lambda _: None)

    class Huge:
        returncode = 0
        stdout = b"x" * 65_537
        stderr = b""

    monkeypatch.setattr("agenticos.providers.kimi_runtime._run_bounded", lambda *a, **k: Huge())
    with pytest.raises(KimiRuntimeError, match="RUNTIME_OUTPUT_LIMIT"):
        run_passive_kimi(spec, ("--version",))

    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("kimi", 1)

    monkeypatch.setattr("agenticos.providers.kimi_runtime._run_bounded", timeout)
    with pytest.raises(KimiRuntimeError, match="RUNTIME_TIMEOUT"):
        run_passive_kimi(spec, ("--version",), timeout_seconds=1)


def test_every_launch_reverifies_the_exact_pinned_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable, bundle = _paths(tmp_path)
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    calls: list[KimiRuntimeSpec] = []

    def reject(item: KimiRuntimeSpec) -> None:
        calls.append(item)
        raise KimiRuntimeError("PIN_RECHECK_FAILED")

    monkeypatch.setattr("agenticos.providers.kimi_runtime._verify_spec_identity", reject)
    monkeypatch.setattr(
        "agenticos.providers.kimi_runtime._run_bounded",
        lambda *args, **kwargs: pytest.fail("process launch must not occur"),
    )
    with pytest.raises(KimiRuntimeError, match="PIN_RECHECK_FAILED"):
        run_passive_kimi(spec, ("--version",))
    with pytest.raises(KimiRuntimeError, match="PIN_RECHECK_FAILED"):
        from agenticos.providers.kimi_runtime import run_synthetic_acp_fixture

        fixture = tmp_path / "fixture.py"
        fixture.write_text("pass\n", encoding="utf-8")
        run_synthetic_acp_fixture(spec, fixture, "plan")
    assert calls == [spec, spec]


def test_bubblewrap_identity_drift_is_rejected_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agenticos.providers.kimi_runtime import _verify_spec_identity

    executable, bundle = _paths(tmp_path)
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    monkeypatch.setattr("agenticos.providers.kimi_runtime.sha256_file", lambda _: "0" * 64)
    with pytest.raises(KimiRuntimeError, match="BWRAP_IDENTITY_DRIFT"):
        _verify_spec_identity(spec)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_bounded_reader_kills_an_actual_overproducing_child(stream: str) -> None:
    from agenticos.providers.kimi_runtime import _run_bounded

    descriptor = 1 if stream == "stdout" else 2
    command = [
        sys.executable,
        "-c",
        f"import os; os.write({descriptor}, b'x' * 1000000)",
    ]
    with pytest.raises(KimiRuntimeError, match="TEST_OUTPUT_LIMIT"):
        _run_bounded(
            command,
            timeout_seconds=5,
            stdout_limit=1_024,
            stderr_limit=1_024,
            overflow_code="TEST_OUTPUT_LIMIT",
        )
