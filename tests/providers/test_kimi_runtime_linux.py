from __future__ import annotations

import os
from pathlib import Path

import pytest

from agenticos.providers.kimi_policy import validate_qualification_bundle, verify_pinned_runtime, verify_reported_version
from agenticos.providers.kimi_runtime import build_runtime_spec, run_passive_kimi


RUNTIME = Path("/home/brand/.local/share/agenticos/provider-qualification/kimi-code/0.36.1/runtime/bin/kimi")
BUNDLE = Path(__file__).resolve().parents[2] / "qualification" / "kimi-code" / "0.36.1"


@pytest.mark.skipif(not RUNTIME.exists() or os.name != "posix", reason="pinned WSL runtime required")
def test_pinned_native_runtime_reports_exact_version_inside_network_namespace() -> None:
    artifact = validate_qualification_bundle(BUNDLE)
    verify_pinned_runtime(RUNTIME, artifact, expected_uid=os.getuid())
    spec = build_runtime_spec(RUNTIME, BUNDLE)
    observation = run_passive_kimi(spec, ("--version",), timeout_seconds=15)
    assert observation.returncode == 0
    assert observation.stderr == b""
    verify_reported_version(observation.stdout.decode("utf-8"))
    assert observation.network_denied is True
    assert observation.workspace_mount == "/workspace"
    assert observation.inherited_fd_names == ("stdin", "stdout", "stderr")
