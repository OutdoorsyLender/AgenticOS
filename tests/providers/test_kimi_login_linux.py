"""Native WSL qualification for the owner-login containment boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from agenticos.providers.kimi_login import (
    AuthRelayResult,
    KimiAuthRelay,
    KimiLoginSpec,
    build_login_bwrap_argv,
    default_login_spec,
    open_validated_credential_root,
    provision_empty_credential_root,
    receive_listener_fd,
    validate_login_spec,
)


RUNTIME = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not RUNTIME.exists(), reason="pinned native WSL runtime required"
)


def test_real_pinned_login_spec_revalidates_without_running_login(tmp_path: Path) -> None:
    """The real executable/config/profile pass while the credential leaf remains empty."""

    spec = default_login_spec()
    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    validate_login_spec(
        KimiLoginSpec(spec.executable, spec.bundle, state_root, spec.namespace_launcher),
        expected_uid=os.getuid(),
    )
    assert list((state_root / "credentials").iterdir()) == []


def test_real_bwrap_netns_handoff_denies_api_without_kimi_or_oauth(tmp_path: Path) -> None:
    """The actual namespace listener reaches only the opaque relay's denied API branch."""

    executable = tmp_path / "unused-kimi"
    executable.write_bytes(b"synthetic executable never invoked")
    executable.chmod(0o555)
    bundle = tmp_path / "bundle"
    (bundle / "agents").mkdir(parents=True)
    (bundle / "config.toml").write_text("synthetic\n", encoding="utf-8")
    (bundle / "agents" / "agent.md").write_text("synthetic\n", encoding="utf-8")
    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    fixture = (
        Path(__file__).parent / "fixtures" / "kimi_login_namespace_fixture.py"
    ).resolve()
    spec = KimiLoginSpec(executable, bundle, state_root, fixture)
    parent, child = socket.socketpair()
    credential_fd = open_validated_credential_root(state_root, expected_uid=os.getuid())
    process = subprocess.Popen(
        build_login_bwrap_argv(
            spec, handoff_fd=child.fileno(), credential_fd=credential_fd
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        close_fds=True,
        pass_fds=(child.fileno(), credential_fd),
        start_new_session=True,
    )
    os.close(credential_fd)
    child.close()
    relay = None
    try:
        parent.settimeout(5)
        listener = receive_listener_fd(parent)
        relay = KimiAuthRelay(listener)
        relay.start()
        stdout, stderr = process.communicate(timeout=10)
    finally:
        parent.close()
        if relay is not None:
            relay.stop()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
    assert process.returncode == 0
    assert stderr == b""
    report = json.loads(stdout)
    assert report["schema"] == "AOS_KIMI_LOGIN_NAMESPACE_FIXTURE/1"
    assert report["api_denied"] is True
    assert report["net_namespace"] != os.readlink("/proc/self/ns/net")
    assert relay is not None
    assert len(relay.observations) == 1
    assert relay.observations[0].result is AuthRelayResult.DENIED
    assert relay.observations[0].hostname == "api.kimi.com"
    assert list((state_root / "credentials").iterdir()) == []
