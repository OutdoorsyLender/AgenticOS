"""Tests that the JSON schemas stay in sync with the harness wire formats."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from agenticos.sandbox.policy import default_policy
from helpers import run_worker

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


def load_schema(name: str) -> dict:
    return json.loads((SCHEMAS_DIR / name).read_text())


def test_policy_conforms_to_schema():
    policy = default_policy()
    jsonschema.validate(policy.to_dict(), load_schema("sandbox-policy.schema.json"))


def test_worker_result_conforms_to_schema(layout, fixture_env):
    res = run_worker("FS-01", target=layout.allowed_file, env=fixture_env,
                     cwd=layout.assigned_worktree)
    jsonschema.validate(res, load_schema("probe-result.schema.json"))


def test_worker_error_result_conforms_to_schema(layout):
    from helpers import minimal_env

    res = run_worker("ENV-02", env_name=layout.env_secret_name, env=minimal_env())
    assert res["succeeded"] is False
    jsonschema.validate(res, load_schema("probe-result.schema.json"))
