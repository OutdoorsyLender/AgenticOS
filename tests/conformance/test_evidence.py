"""Tests for evidence collection, serialization, and policy comparison."""

from __future__ import annotations

import json
import os

from agenticos.sandbox.evidence import EVIDENCE_SCHEMA_VERSION, EvidenceCollector
from agenticos.sandbox.models import (
    AttackResult,
    TEMP_ROOT_PLACEHOLDER,
    utc_now_iso,
)
from agenticos.sandbox.policy import default_policy, evaluate_run


def test_record_fields(layout):
    collector = EvidenceCollector(normalize_root=layout.root)
    rec = collector.record("scenario_result", {"ok": True}, scenario_id="FS-01")
    assert rec.schema_version == EVIDENCE_SCHEMA_VERSION
    assert rec.event_id.startswith("evt-")
    assert rec.run_id == collector.run_id
    assert rec.scenario_id == "FS-01"
    assert rec.kind == "scenario_result"
    assert rec.timestamp  # RFC-3339 / ISO-8601 with UTC offset
    assert rec.payload == {"ok": True}


def test_event_ids_unique(layout):
    collector = EvidenceCollector(normalize_root=layout.root)
    ids = {collector.record("x", {"i": i}).event_id for i in range(50)}
    assert len(ids) == 50


def test_path_normalization(layout):
    collector = EvidenceCollector(normalize_root=layout.root)
    collector.record(
        "scenario_result",
        {
            "target": str(layout.denied_sibling_file),
            "nested": {"paths": [str(layout.allowed_file), "literal"]},
        },
        scenario_id="FS-02",
    )
    line = collector.to_jsonl()
    assert str(layout.root) not in line
    assert TEMP_ROOT_PLACEHOLDER in line
    payload = collector.records[0].payload
    assert payload["target"].startswith(TEMP_ROOT_PLACEHOLDER)
    assert payload["target"].endswith("secret-canary.txt")
    assert payload["nested"]["paths"][1] == "literal"


def test_evidence_does_not_embed_real_home(layout):
    collector = EvidenceCollector(normalize_root=layout.root)
    collector.record("run_summary", {"runner": "unsafe-local"})
    blob = collector.to_jsonl()
    real_home = os.path.expanduser("~")
    if len(real_home) > 3:  # only meaningful when it is a real path
        assert real_home not in blob


def test_write_and_read_back(layout):
    collector = EvidenceCollector(run_id="run-test", normalize_root=layout.root)
    collector.record("scenario_result", {"succeeded": True}, scenario_id="FS-01")
    collector.record("run_summary", {"passed": False})
    out = collector.write(layout.task_tmp / "evidence.jsonl")
    lines = out.read_text().splitlines()
    assert len(lines) == 2
    docs = [json.loads(line) for line in lines]
    assert all(d["run_id"] == "run-test" for d in docs)
    assert all(d["schema_version"] == EVIDENCE_SCHEMA_VERSION for d in docs)
    assert docs[0]["scenario_id"] == "FS-01"
    assert docs[1]["kind"] == "run_summary"


def test_conformance_run_serialization_roundtrip():
    policy = default_policy()
    results = [
        AttackResult(
            scenario_id="FS-01", attempted=True, succeeded=True,
            started_at=utc_now_iso(), finished_at=utc_now_iso(),
        ),
        AttackResult(
            scenario_id="FS-02", attempted=True, succeeded=True,
            started_at=utc_now_iso(), finished_at=utc_now_iso(),
        ),
    ]
    run = evaluate_run(results, policy, runner_name="unsafe-local")
    blob = json.dumps(run.to_dict())  # must be JSON-serializable
    doc = json.loads(blob)
    assert doc["conformance"] == {"FS-01": "PASS", "FS-02": "FAIL"}
    assert doc["passed"] is False
    assert doc["policy_version"] == policy.version
    assert len(doc["results"]) == 2


def test_full_run_against_default_policy_covers_catalog(layout, fixture_env):
    """Every catalog scenario id must have an expectation (catalog sanity)."""
    policy = default_policy()
    expected_ids = {
        "FS-01", "FS-02", "FS-03", "FS-04", "FS-05",
        "ENV-01", "ENV-02",
        "PROC-01", "PROC-02", "PROC-03", "PROC-04", "PROC-05",
        "PROC-06", "PROC-07", "PROC-08",
        "NET-01", "NET-02", "SOCK-01",
        "WRITE-01", "WRITE-02",
    }
    assert set(policy.expectations) == expected_ids
