"""Strict ACP v1 client boundary for passive Kimi Planner qualification.

The module accepts a deliberately tiny subset of the ACP surface.  It never
spawns Kimi and cannot turn the passive checkpoint into real provider use.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from itertools import islice
from typing import Any, Final, Iterable, cast

from agenticos.orchestration.canonical import canonical_json_line
from agenticos.orchestration.models import Role
from agenticos.orchestration.proposals import PlannerProposal, ProposalCompilationError
from agenticos.orchestration.protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentEvent,
    AgentEventPayload,
    AgentExitClass,
    AgentResult,
    AgentStreamValidator,
    AgentTaskRequest,
    EventKind,
    ProtocolRejection,
    ResultStatus,
    Retryability,
)


MAX_ACP_FRAME_BYTES: Final = 65_536
MAX_MODEL_OUTPUT_BYTES: Final = 262_144
MAX_ACP_TRANSCRIPT_FRAMES: Final = 1_024
_EXPECTED_KIMI_AGENT_INFO: Final = {
    "name": "Kimi Code CLI",
    "version": "0.36.1",
}
_EXPECTED_KIMI_AGENT_CAPABILITIES: Final = {
    "loadSession": True,
    "promptCapabilities": {
        "image": True,
        "audio": False,
        "embeddedContext": True,
    },
    "sessionCapabilities": {
        "list": {},
        "resume": {},
        "close": {},
        "delete": {},
        "fork": {},
        "additionalDirectories": {},
    },
    "mcpCapabilities": {"http": True, "sse": True},
    "auth": {"logout": {}},
}
_EXPECTED_KIMI_AUTH_METHOD: Final = {
    "id": "login",
    "type": "terminal",
    "name": "Login with Kimi account",
    "description": "Open the device-code login flow in a terminal.",
    "args": ["--login"],
    "env": {"KIMI_CODE_HOME": "/home/aos/kimi"},
    "_meta": {
        "terminal-auth": {
            "type": "terminal",
            "label": "Login with Kimi account",
            "command": "/opt/agenticos/kimi/bin/kimi",
            "args": ["login"],
            "env": {"KIMI_CODE_HOME": "/home/aos/kimi"},
        }
    },
}


class KimiAcpError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


class RealProviderDisabledError(PermissionError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise KimiAcpError("DUPLICATE_JSON_KEY", name)
        result[name] = value
    return result


def decode_acp_line(raw: bytes, *, max_bytes: int = MAX_ACP_FRAME_BYTES) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise KimiAcpError("INVALID_FRAME_TYPE")
    if len(raw) > max_bytes:
        raise KimiAcpError("FRAME_TOO_LARGE")
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise KimiAcpError("TRUNCATED_FRAME")
    try:
        text = raw[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise KimiAcpError("INVALID_UTF8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_unique_object)
    except KimiAcpError:
        raise
    except json.JSONDecodeError as exc:
        raise KimiAcpError("MALFORMED_JSON") from exc
    if type(value) is not dict or value.get("jsonrpc") != "2.0":
        raise KimiAcpError("MALFORMED_JSON_RPC")
    is_callback = "method" in value
    is_response = "id" in value and ("result" in value or "error" in value)
    if not is_callback and not is_response:
        raise KimiAcpError("MALFORMED_JSON_RPC")
    if is_callback and is_response:
        raise KimiAcpError("MALFORMED_JSON_RPC")
    if is_callback:
        expected = {"jsonrpc", "method", "params"} | ({"id"} if "id" in value else set())
        if set(value) != expected or type(value["method"]) is not str or type(value["params"]) is not dict:
            raise KimiAcpError("MALFORMED_JSON_RPC")
        if "id" in value and (type(value["id"]) not in (str, int) or isinstance(value["id"], bool)):
            raise KimiAcpError("MALFORMED_JSON_RPC")
    else:
        if type(value["id"]) not in (str, int) or isinstance(value["id"], bool):
            raise KimiAcpError("MALFORMED_JSON_RPC")
        expected_fields = {"jsonrpc", "id", "error" if "error" in value else "result"}
        if set(value) != expected_fields:
            raise KimiAcpError("MALFORMED_JSON_RPC")
    return value


def _encode(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def encode_acp_request(method: str, request_id: int, params: dict[str, object]) -> bytes:
    if type(method) is not str or type(request_id) is not int or type(params) is not dict:
        raise KimiAcpError("OUTBOUND_REQUEST_SHAPE")
    return _encode({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})


def _exact_json_value(value: object, expected: object) -> bool:
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        actual_dict = cast(dict[Any, Any], value)
        expected_dict = cast(dict[Any, Any], expected)
        return set(actual_dict) == set(expected_dict) and all(
            _exact_json_value(actual_dict[name], expected_dict[name])
            for name in expected_dict
        )
    if type(expected) is list:
        actual_list = cast(list[Any], value)
        expected_list = cast(list[Any], expected)
        return len(actual_list) == len(expected_list) and all(
            _exact_json_value(item, expected_item)
            for item, expected_item in zip(actual_list, expected_list, strict=True)
        )
    return value == expected


def validate_kimi_initialize_result(result: object) -> dict[str, object]:
    if type(result) is not dict or set(result) != {"protocolVersion", "agentCapabilities", "authMethods", "agentInfo"}:
        raise KimiAcpError("INITIALIZE_SHAPE")
    if type(result["protocolVersion"]) is not int or result["protocolVersion"] != 1:
        raise KimiAcpError("WRONG_ACP_VERSION")
    info = result["agentInfo"]
    if not _exact_json_value(info, _EXPECTED_KIMI_AGENT_INFO):
        raise KimiAcpError("WRONG_AGENT_IDENTITY")
    methods = result["authMethods"]
    if type(methods) is not list or len(methods) != 1 or type(methods[0]) is not dict:
        raise KimiAcpError("AUTH_METHOD_SHAPE")
    method = methods[0]
    if not _exact_json_value(method, _EXPECTED_KIMI_AUTH_METHOD):
        raise KimiAcpError("AUTH_METHOD_SHAPE")
    if not _exact_json_value(
        result["agentCapabilities"],
        _EXPECTED_KIMI_AGENT_CAPABILITIES,
    ):
        raise KimiAcpError("CAPABILITIES_SHAPE")
    return result


class KimiAcpSession:
    """Closed ACP v1 state machine for exactly one new Planner session/turn."""

    _FORBIDDEN_CALLBACKS = frozenset(
        {
            "fs/read_text_file",
            "fs/write_text_file",
            "session/request_permission",
            "session/request_input",
            "terminal/create",
            "terminal/output",
            "terminal/release",
            "elicitation/create",
        }
    )

    def __init__(self, *, max_frame_bytes: int = MAX_ACP_FRAME_BYTES, max_output_bytes: int = MAX_MODEL_OUTPUT_BYTES) -> None:
        if type(max_frame_bytes) is not int or not 256 <= max_frame_bytes <= MAX_ACP_FRAME_BYTES:
            raise KimiAcpError("INVALID_FRAME_LIMIT")
        if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_MODEL_OUTPUT_BYTES:
            raise KimiAcpError("INVALID_OUTPUT_LIMIT")
        self.max_frame_bytes = max_frame_bytes
        self.max_output_bytes = max_output_bytes
        self.state = "NEW"
        self.session_id: str | None = None
        self._chunks: list[str] = []
        self._output_bytes = 0
        self._cancelled = False
        self._terminal = False
        self._proposal: PlannerProposal | None = None
        self.advertised_capabilities: dict[str, object] | None = None

    def initialize_request(self) -> bytes:
        if self.state != "NEW":
            raise KimiAcpError("INITIALIZE_ORDER")
        self.state = "INITIALIZING"
        return _encode(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": 1, "clientCapabilities": {}},
            }
        )

    def new_session_request(self) -> bytes:
        if self.state != "INITIALIZED":
            raise KimiAcpError("NEW_SESSION_ORDER")
        self.state = "CREATING"
        return _encode(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/new",
                "params": {"cwd": "/workspace", "mcpServers": []},
            }
        )

    def prompt_request(self, text: str) -> bytes:
        if self.state != "READY" or self.session_id is None:
            raise KimiAcpError("PROMPT_ORDER")
        if type(text) is not str or not text or len(text.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
            raise KimiAcpError("PROMPT_LIMIT")
        self.state = "PROMPTING"
        return _encode(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {
                    "sessionId": self.session_id,
                    "prompt": [{"type": "text", "text": text}],
                },
            }
        )

    def cancel_notification(self) -> bytes:
        if self.state != "PROMPTING" or self.session_id is None:
            raise KimiAcpError("CANCEL_ORDER")
        if self._cancelled:
            raise KimiAcpError("DUPLICATE_CANCEL")
        self._cancelled = True
        return _encode(
            {
                "jsonrpc": "2.0",
                "method": "session/cancel",
                "params": {"sessionId": self.session_id},
            }
        )

    def accept(self, raw: bytes) -> None:
        message = decode_acp_line(raw, max_bytes=self.max_frame_bytes)
        if "method" in message:
            self._accept_callback(message)
            return
        if self._terminal:
            raise KimiAcpError("DUPLICATE_TERMINAL")
        response_id = message["id"]
        expected_id = {"INITIALIZING": 1, "CREATING": 2, "PROMPTING": 3}.get(self.state)
        if response_id != expected_id:
            raise KimiAcpError("UNEXPECTED_RESPONSE_ID")
        if "error" in message:
            raise KimiAcpError("ACP_ERROR_RESPONSE")
        result = message["result"]
        if type(result) is not dict:
            raise KimiAcpError("MALFORMED_RESPONSE")
        if self.state == "INITIALIZING":
            self._accept_initialize(result)
        elif self.state == "CREATING":
            self._accept_new(result)
        elif self.state == "PROMPTING":
            self._accept_prompt(result)
        else:
            raise KimiAcpError("UNEXPECTED_RESPONSE")

    def _accept_initialize(self, result: dict[str, object]) -> None:
        validated = validate_kimi_initialize_result(result)
        self.advertised_capabilities = validated["agentCapabilities"]
        self.state = "INITIALIZED"

    def _accept_new(self, result: dict[str, object]) -> None:
        if set(result) != {"sessionId", "configOptions", "modes"}:
            raise KimiAcpError("NEW_SESSION_SHAPE")
        session_id = result["sessionId"]
        if type(session_id) is not str or not session_id.startswith("session_") or len(session_id) > 128:
            raise KimiAcpError("INVALID_SESSION_ID")
        if type(result["configOptions"]) is not list or type(result["modes"]) is not dict:
            raise KimiAcpError("NEW_SESSION_SHAPE")
        self.session_id = session_id
        self.state = "READY"

    def _accept_prompt(self, result: dict[str, object]) -> None:
        if set(result) != {"stopReason"}:
            raise KimiAcpError("PROMPT_RESULT_SHAPE")
        reason = result["stopReason"]
        if self._cancelled:
            if reason != "cancelled":
                raise KimiAcpError("CANCEL_RACE")
            self._terminal = True
            self.state = "CANCELLED"
            return
        if reason != "end_turn":
            raise KimiAcpError("WRONG_STOP_REASON")
        text = "".join(self._chunks)
        try:
            value = json.loads(text, object_pairs_hook=_unique_object)
            self._proposal = PlannerProposal.from_dict(value)
        except (json.JSONDecodeError, KimiAcpError, ProposalCompilationError, TypeError, ValueError) as exc:
            raise KimiAcpError("INVALID_AOSPLAN") from exc
        self._terminal = True
        self.state = "FINISHED"

    def _accept_callback(self, message: dict[str, object]) -> None:
        method = message["method"]
        if method in self._FORBIDDEN_CALLBACKS or str(method).startswith("fs/"):
            raise KimiAcpError("FORBIDDEN_CALLBACK", str(method))
        if method != "session/update":
            raise KimiAcpError("UNKNOWN_CALLBACK", str(method))
        if self.state not in {"READY", "PROMPTING", "FINISHED"}:
            raise KimiAcpError("UPDATE_ORDER")
        params = message["params"]
        if params.get("sessionId") != self.session_id:
            raise KimiAcpError("SESSION_ID_MISMATCH")
        update = params.get("update")
        if type(update) is not dict:
            raise KimiAcpError("UPDATE_SHAPE")
        kind = update.get("sessionUpdate")
        if kind == "agent_message_chunk" and self.state == "PROMPTING" and not self._cancelled:
            content = update.get("content")
            if type(content) is not dict or content.get("type") != "text" or set(content) != {"type", "text"} or type(content.get("text")) is not str:
                raise KimiAcpError("MESSAGE_CHUNK_SHAPE")
            text = content["text"]
            size = len(text.encode("utf-8"))
            if self._output_bytes + size > self.max_output_bytes:
                raise KimiAcpError("MODEL_OUTPUT_LIMIT")
            self._chunks.append(text)
            self._output_bytes += size
            return
        if kind == "available_commands_update" and self.state == "READY":
            commands = update.get("availableCommands", update.get("available_commands", []))
            if type(commands) is not list:
                raise KimiAcpError("AVAILABLE_COMMANDS_SHAPE")
            if any(type(item) is dict and str(item.get("name", "")).startswith("skill:") for item in commands):
                raise KimiAcpError("SKILL_COMMAND_SURVIVED")
            return
        if kind == "usage_update" and self.state in {"PROMPTING", "FINISHED"}:
            return
        raise KimiAcpError("FORBIDDEN_SESSION_UPDATE", str(kind))

    def finish(self) -> PlannerProposal:
        if self.state == "CANCELLED":
            raise KimiAcpError("CANCELLED")
        if self.state != "FINISHED" or self._proposal is None:
            raise KimiAcpError("INCOMPLETE_TRANSCRIPT")
        return self._proposal


@dataclass(frozen=True, slots=True)
class KimiPassiveOutcome:
    proposal: PlannerProposal
    events: tuple[AgentEvent, ...]
    result: AgentResult


class KimiPassiveAdapter:
    """Transcript-only adapter. Real provider execution is a hard error."""

    def execute_real(self, request: AgentTaskRequest) -> None:
        del request
        raise RealProviderDisabledError("REAL_PROVIDER_DISABLED: NOT_AUTHENTICATED")

    def consume_transcript(self, request: AgentTaskRequest, frames: Iterable[bytes]) -> KimiPassiveOutcome:
        required_caps = {AgentCapability.READ_CONTEXT, AgentCapability.PROPOSE_TASKS}
        if (
            not isinstance(request, AgentTaskRequest)
            or request.role is not Role.PLANNER
            or request.provider_id != "kimi-code-passive"
            or request.model_id != "kimi-for-coding"
            or set(request.capabilities) != required_caps
        ):
            raise KimiAcpError("REQUEST_AUTHORITY")
        items = tuple(islice(frames, MAX_ACP_TRANSCRIPT_FRAMES + 1))
        if len(items) > MAX_ACP_TRANSCRIPT_FRAMES:
            raise KimiAcpError("TRANSCRIPT_FRAME_LIMIT")
        if len(items) < 4:
            raise KimiAcpError("INCOMPLETE_TRANSCRIPT")
        session = KimiAcpSession(max_output_bytes=min(MAX_MODEL_OUTPUT_BYTES, request.limits.max_output_bytes))
        session.initialize_request()
        session.accept(items[0])
        session.new_session_request()
        session.accept(items[1])
        context = {
            "owner_goal": request.instructions,
            "acceptance_criteria": list(request.acceptance_criteria),
            "context_manifest": [item.to_dict() for item in request.context_manifest],
        }
        session.prompt_request(json.dumps(context, ensure_ascii=False, separators=(",", ":")))
        for frame in items[2:]:
            session.accept(frame)
        proposal = session.finish()
        proposal_text = json.dumps(proposal.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        events = (
            AgentEvent(AGENT_PROTOCOL_SCHEMA, request.identity, 1, EventKind.STARTED, AgentEventPayload("Passive Kimi ACP transcript started.", ())),
            AgentEvent(AGENT_PROTOCOL_SCHEMA, request.identity, 2, EventKind.PROPOSAL, AgentEventPayload(proposal_text, ())),
            AgentEvent(AGENT_PROTOCOL_SCHEMA, request.identity, 3, EventKind.SUCCEEDED, AgentEventPayload("Controller validated one untrusted AOSPLAN/1 proposal.", ())),
        )
        validator = AgentStreamValidator(request)
        encoded = tuple(canonical_json_line(event.to_dict()) for event in events)
        try:
            for line in encoded:
                validator.accept(line)
            validator.finish()
        except ProtocolRejection as exc:
            raise KimiAcpError("AOSAGENT_STREAM_REJECTED", exc.code) from exc
        stream = b"".join(encoded)
        result = AgentResult(
            schema=AGENT_PROTOCOL_SCHEMA,
            identity=request.identity,
            status=ResultStatus.SUCCEEDED,
            exit_class=AgentExitClass.SUCCESS,
            event_count=len(events),
            byte_count=len(stream),
            stream_digest=hashlib.sha256(stream).hexdigest(),
            evidence_refs=(),
            workspace_handoff_ref=None,
            usage=None,
            retryability=Retryability.NOT_RETRYABLE,
        )
        try:
            validator.accept_result(result)
        except ProtocolRejection as exc:
            raise KimiAcpError("AOSAGENT_STREAM_REJECTED", exc.code) from exc
        return KimiPassiveOutcome(proposal=proposal, events=events, result=result)
