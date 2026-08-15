from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "kimi_loopback_fixture.py"


@pytest.mark.parametrize("canary_name", ["CANARY", "REFRESH_CANARY"])
def test_every_early_fixture_failure_redacts_all_credential_canaries(
    canary_name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = runpy.run_path(str(FIXTURE))
    canary = fixture[canary_name]
    with pytest.raises(SystemExit) as stopped:
        fixture["fail"]("EARLY_FIXTURE_ERROR", f"prefix:{canary}:suffix")
    assert stopped.value.code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["error"] == "CREDENTIAL_CANARY_LEAK"
    assert canary not in json.dumps(report)
    assert report["detail"] == "prefix:<synthetic-credential-canary-redacted>:suffix"
