from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from agenticos.orchestration.board import BoardSnapshot
from agenticos.orchestration.protocol import EventKind
from tests.orchestration.test_models import project, task
from tests.orchestration.test_protocol import event, request, result

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"


def schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def test_authoritative_board_conforms_to_strict_schema() -> None:
    jsonschema.validate(
        BoardSnapshot.create(project(), (task(),)).to_dict(),
        schema("orchestration-board.schema.json"),
    )


def test_request_event_and_result_conform_to_protocol_schema() -> None:
    protocol = schema("agent-protocol.schema.json")
    jsonschema.validate(request().to_dict(), protocol)
    jsonschema.validate(event(1, EventKind.STARTED).to_dict(), protocol)
    jsonschema.validate(result().to_dict(), protocol)


def test_schemas_reject_authority_smuggling_and_unknown_fields() -> None:
    board = BoardSnapshot.create(project(), (task(),)).to_dict()
    board["model_decision"] = "DONE"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(board, schema("orchestration-board.schema.json"))
    protocol = request().to_dict()
    protocol["credential_locator"] = "ambient"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(protocol, schema("agent-protocol.schema.json"))


def test_board_schema_rejects_project_failure_with_non_failure_reason() -> None:
    board = BoardSnapshot.create(project(), (task(),)).to_dict()
    board["project"]["status"] = "FAILED"
    board["project"]["terminal_reason"] = "COMPLETED"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(board, schema("orchestration-board.schema.json"))
