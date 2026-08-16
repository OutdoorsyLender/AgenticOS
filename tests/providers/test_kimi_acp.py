from __future__ import annotations

import json
from dataclasses import replace

import pytest

from agenticos.orchestration.models import Role
from agenticos.orchestration.protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentExitClass,
    AgentTaskRequest,
    ContextItem,
    ContextKind,
    DispatchIdentity,
    ProtocolLimits,
    ResultStatus,
)
from agenticos.providers.kimi_acp import (
    KimiAcpError,
    KimiAcpSession,
    KimiPassiveAdapter,
    RealProviderDisabledError,
    decode_acp_line,
    encode_acp_request,
    validate_kimi_initialize_result,
)


def _line(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _request(**changes: object) -> AgentTaskRequest:
    values: dict[str, object] = {
        "schema": AGENT_PROTOCOL_SCHEMA,
        "identity": DispatchIdentity(
            project_id="project-1",
            task_id="task-plan",
            task_generation=1,
            attempt=1,
            controller_epoch=1,
            lease_epoch=0,
            dispatch_nonce="a" * 32,
            repository_id="repo-1",
            baseline_commit="b" * 40,
            workspace_id="workspace-1",
            workspace_generation=1,
            reservation_id="reservation-1",
            checkpoint_digest="c" * 64,
        ),
        "role": Role.PLANNER,
        "provider_id": "kimi-code-passive",
        "model_id": "kimi-for-coding",
        "workspace_mount": "/workspace",
        "instructions": "Plan from bounded controller context only.",
        "acceptance_criteria": ("Return one strict AOSPLAN/1 proposal.",),
        "context_manifest": (
            ContextItem(ContextKind.PLAN_INPUT, "context-1", "d" * 64, 12),
        ),
        "capabilities": (AgentCapability.READ_CONTEXT, AgentCapability.PROPOSE_TASKS),
        "limits": ProtocolLimits(max_event_bytes=65_536, max_output_bytes=1_048_576),
    }
    values.update(changes)
    return AgentTaskRequest(**values)  # type: ignore[arg-type]


def _plan() -> dict[str, object]:
    return {
        "schema": "AOSPLAN/1",
        "tasks": [
            {
                "local_id": "local-1",
                "title": "Bounded build",
                "description": "Implement the controller-selected change.",
                "task_type": "BUILD",
                "dependencies": [],
                "acceptance_criteria": ["Provider suggestion only."],
                "preferred_role": "BUILDER",
                "priority": 50,
            }
        ],
    }


def _initialize_result(*, version: str = "0.36.1") -> bytes:
    # Protocol fixture only; the exact packaged binary is exercised natively.
    return _line(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": 1,
                "agentCapabilities": {
                    "loadSession": True,
                    "promptCapabilities": {"image": True, "audio": False, "embeddedContext": True},
                    "sessionCapabilities": {
                        "list": {}, "resume": {}, "close": {}, "delete": {}, "fork": {},
                        "additionalDirectories": {},
                    },
                    "mcpCapabilities": {"http": True, "sse": True},
                    "auth": {"logout": {}},
                },
                "authMethods": [
                    {
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
                ],
                "agentInfo": {"name": "Kimi Code CLI", "version": version},
            },
        }
    )


def _new_result(session_id: str = "session_abc") -> bytes:
    return _line({"jsonrpc": "2.0", "id": 2, "result": {"sessionId": session_id, "configOptions": [], "modes": {}}})


def _message(text: str, session_id: str = "session_abc") -> bytes:
    return _line(
        {
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": session_id,
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": text},
                },
            },
        }
    )


def _prompt_result(stop_reason: str = "end_turn") -> bytes:
    return _line({"jsonrpc": "2.0", "id": 3, "result": {"stopReason": stop_reason}})


def test_decode_acp_line_rejects_duplicate_keys_invalid_utf8_bounds_and_truncation() -> None:
    with pytest.raises(KimiAcpError, match="DUPLICATE_JSON_KEY"):
        decode_acp_line(b'{"jsonrpc":"2.0","id":1,"id":2}\n')
    with pytest.raises(KimiAcpError, match="INVALID_UTF8"):
        decode_acp_line(b"\xff\n")
    with pytest.raises(KimiAcpError, match="FRAME_TOO_LARGE"):
        decode_acp_line(b"x" * 65_537 + b"\n")
    with pytest.raises(KimiAcpError, match="TRUNCATED_FRAME"):
        decode_acp_line(b'{"jsonrpc":"2.0"}')
    with pytest.raises(KimiAcpError, match="MALFORMED_JSON_RPC"):
        decode_acp_line(b"[]\n")


def test_shared_outbound_encoder_rejects_wrong_method_construction() -> None:
    with pytest.raises(KimiAcpError, match="OUTBOUND_REQUEST_SHAPE"):
        encode_acp_request(None, 1, {})  # type: ignore[arg-type]
    with pytest.raises(KimiAcpError, match="OUTBOUND_REQUEST_SHAPE"):
        encode_acp_request("initialize", True, {})
    with pytest.raises(KimiAcpError, match="OUTBOUND_REQUEST_SHAPE"):
        encode_acp_request("initialize", 1, [])  # type: ignore[arg-type]
    assert decode_acp_line(encode_acp_request("authenticate", 2, {"methodId": "login"})) == {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "authenticate",
        "params": {"methodId": "login"},
    }


def test_shared_initialize_validator_preserves_pinned_identity_checks() -> None:
    result = decode_acp_line(_initialize_result())["result"]
    assert validate_kimi_initialize_result(result) == result
    wrong_identity = dict(result)
    wrong_identity["agentInfo"] = {"name": "Kimi Code CLI", "version": "0.36.2"}
    with pytest.raises(KimiAcpError, match="WRONG_AGENT_IDENTITY"):
        validate_kimi_initialize_result(wrong_identity)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("boolean-protocol-version", "WRONG_ACP_VERSION"),
        ("empty-capabilities", "CAPABILITIES_SHAPE"),
        ("extra-capability", "CAPABILITIES_SHAPE"),
        ("numeric-capability-boolean", "CAPABILITIES_SHAPE"),
        ("wrong-method-name", "AUTH_METHOD_SHAPE"),
        ("wrong-method-description", "AUTH_METHOD_SHAPE"),
        ("extra-method-field", "AUTH_METHOD_SHAPE"),
        ("extra-meta-field", "AUTH_METHOD_SHAPE"),
        ("wrong-terminal-type", "AUTH_METHOD_SHAPE"),
        ("wrong-terminal-label", "AUTH_METHOD_SHAPE"),
        ("extra-terminal-field", "AUTH_METHOD_SHAPE"),
    ],
)
def test_shared_initialize_validator_rejects_every_nonexact_contract_shape(
    mutation: str,
    code: str,
) -> None:
    result = json.loads(json.dumps(decode_acp_line(_initialize_result())["result"]))
    method = result["authMethods"][0]
    terminal = method["_meta"]["terminal-auth"]

    if mutation == "boolean-protocol-version":
        result["protocolVersion"] = True
    elif mutation == "empty-capabilities":
        result["agentCapabilities"] = {}
    elif mutation == "extra-capability":
        result["agentCapabilities"]["unexpected"] = {}
    elif mutation == "numeric-capability-boolean":
        result["agentCapabilities"]["loadSession"] = 1
    elif mutation == "wrong-method-name":
        method["name"] = "Different login"
    elif mutation == "wrong-method-description":
        method["description"] = "Different description"
    elif mutation == "extra-method-field":
        method["unexpected"] = None
    elif mutation == "extra-meta-field":
        method["_meta"]["unexpected"] = None
    elif mutation == "wrong-terminal-type":
        terminal["type"] = "relative"
    elif mutation == "wrong-terminal-label":
        terminal["label"] = "Different login"
    elif mutation == "extra-terminal-field":
        terminal["unexpected"] = None
    else:  # pragma: no cover - parameter table exhaustiveness guard
        raise AssertionError(mutation)

    with pytest.raises(KimiAcpError, match=code):
        validate_kimi_initialize_result(result)


def test_outbound_surface_is_exact_and_contains_no_checkout_or_auth_material() -> None:
    session = KimiAcpSession()
    initialize = decode_acp_line(session.initialize_request())
    assert initialize == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": 1, "clientCapabilities": {}},
    }
    session.accept(_initialize_result())
    new = decode_acp_line(session.new_session_request())
    assert new["params"] == {"cwd": "/workspace", "mcpServers": []}
    session.accept(_new_result())
    prompt = decode_acp_line(session.prompt_request("bounded context"))
    assert prompt["params"] == {
        "sessionId": "session_abc",
        "prompt": [{"type": "text", "text": "bounded context"}],
    }
    encoded = repr((initialize, new, prompt))
    assert ".git" not in encoded and "api_key" not in encoded and "token" not in encoded


def test_valid_transcript_requires_exact_identity_login_only_and_one_plan() -> None:
    session = KimiAcpSession()
    session.initialize_request()
    session.accept(_initialize_result())
    session.new_session_request()
    session.accept(_new_result())
    session.prompt_request("bounded context")
    plan_text = json.dumps(_plan(), separators=(",", ":"))
    session.accept(_message(plan_text[:30]))
    session.accept(_message(plan_text[30:]))
    session.accept(_prompt_result())
    proposal = session.finish()
    assert proposal.schema == "AOSPLAN/1"
    assert proposal.tasks[0].local_id == "local-1"


@pytest.mark.parametrize(
    ("frame", "code"),
    [
        (_initialize_result(version="0.36.2"), "WRONG_AGENT_IDENTITY"),
        (_line({"jsonrpc": "2.0", "id": 9, "result": {}}), "UNEXPECTED_RESPONSE_ID"),
        (_line({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "no"}}), "ACP_ERROR_RESPONSE"),
        (_line({"jsonrpc": "2.0", "method": "fs/read_text_file", "params": {}}), "FORBIDDEN_CALLBACK"),
        (_line({"jsonrpc": "2.0", "method": "fs/write_text_file", "params": {}}), "FORBIDDEN_CALLBACK"),
        (_line({"jsonrpc": "2.0", "method": "fs/list_directory", "params": {}}), "FORBIDDEN_CALLBACK"),
        (_line({"jsonrpc": "2.0", "method": "fs/read_binary", "params": {}}), "FORBIDDEN_CALLBACK"),
        (_line({"jsonrpc": "2.0", "method": "session/request_permission", "params": {}}), "FORBIDDEN_CALLBACK"),
        (_line({"jsonrpc": "2.0", "method": "unknown", "params": {}}), "UNKNOWN_CALLBACK"),
    ],
)
def test_unexpected_identity_ids_errors_and_callbacks_fail_closed(frame: bytes, code: str) -> None:
    session = KimiAcpSession()
    session.initialize_request()
    with pytest.raises(KimiAcpError, match=code):
        session.accept(frame)


def test_wrong_session_tool_updates_duplicates_and_terminal_races_are_rejected() -> None:
    session = KimiAcpSession()
    session.initialize_request()
    session.accept(_initialize_result())
    session.new_session_request()
    session.accept(_new_result())
    session.prompt_request("bounded context")
    with pytest.raises(KimiAcpError, match="SESSION_ID_MISMATCH"):
        session.accept(_message("x", "session_wrong"))

    forbidden = _line(
        {
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "session_abc",
                "update": {"sessionUpdate": "tool_call", "toolCallId": "call-1"},
            },
        }
    )
    with pytest.raises(KimiAcpError, match="FORBIDDEN_SESSION_UPDATE"):
        session.accept(forbidden)

    fresh = KimiAcpSession()
    fresh.initialize_request(); fresh.accept(_initialize_result())
    fresh.new_session_request(); fresh.accept(_new_result())
    fresh.prompt_request("bounded context")
    fresh.accept(_message(json.dumps(_plan())))
    fresh.accept(_prompt_result())
    with pytest.raises(KimiAcpError, match="DUPLICATE_TERMINAL"):
        fresh.accept(_prompt_result())


def test_wrong_stop_reason_malformed_plan_and_oversized_output_are_rejected() -> None:
    session = KimiAcpSession(max_output_bytes=80)
    session.initialize_request(); session.accept(_initialize_result())
    session.new_session_request(); session.accept(_new_result())
    session.prompt_request("bounded context")
    with pytest.raises(KimiAcpError, match="MODEL_OUTPUT_LIMIT"):
        session.accept(_message("x" * 81))

    for text, terminal, code in [
        ("not-json", _prompt_result(), "INVALID_AOSPLAN"),
        (json.dumps(_plan()), _prompt_result("cancelled"), "WRONG_STOP_REASON"),
    ]:
        item = KimiAcpSession()
        item.initialize_request(); item.accept(_initialize_result())
        item.new_session_request(); item.accept(_new_result())
        item.prompt_request("bounded context"); item.accept(_message(text))
        with pytest.raises(KimiAcpError, match=code):
            item.accept(terminal)


def test_cancel_is_one_notification_and_finishes_only_as_cancelled() -> None:
    session = KimiAcpSession()
    session.initialize_request(); session.accept(_initialize_result())
    session.new_session_request(); session.accept(_new_result())
    session.prompt_request("bounded context")
    assert decode_acp_line(session.cancel_notification()) == {
        "jsonrpc": "2.0",
        "method": "session/cancel",
        "params": {"sessionId": "session_abc"},
    }
    with pytest.raises(KimiAcpError, match="DUPLICATE_CANCEL"):
        session.cancel_notification()
    session.accept(_prompt_result("cancelled"))
    with pytest.raises(KimiAcpError, match="CANCELLED"):
        session.finish()


def test_passive_adapter_maps_only_existing_abi_and_real_execution_stays_disabled() -> None:
    adapter = KimiPassiveAdapter()
    plan_text = json.dumps(_plan(), separators=(",", ":"))
    outcome = adapter.consume_transcript(
        _request(),
        (_initialize_result(), _new_result(), _message(plan_text), _prompt_result()),
    )
    assert outcome.proposal.schema == "AOSPLAN/1"
    assert [event.kind.value for event in outcome.events] == ["STARTED", "PROPOSAL", "SUCCEEDED"]
    assert outcome.result.status is ResultStatus.SUCCEEDED
    assert outcome.result.exit_class is AgentExitClass.SUCCESS
    with pytest.raises(RealProviderDisabledError, match="REAL_PROVIDER_DISABLED"):
        adapter.execute_real(_request())


@pytest.mark.parametrize(
    "changes",
    [
        {"role": Role.BUILDER},
        {"provider_id": "kimi-live"},
        {"model_id": "other"},
        {"capabilities": (AgentCapability.READ_CONTEXT, AgentCapability.RUN_BOUNDED_COMMANDS)},
    ],
)
def test_adapter_rejects_authority_drift(changes: dict[str, object]) -> None:
    with pytest.raises(KimiAcpError, match="REQUEST_AUTHORITY"):
        KimiPassiveAdapter().consume_transcript(_request(**changes), ())


def test_adapter_obeys_controller_output_limit() -> None:
    limited = _request(limits=replace(ProtocolLimits(), max_output_bytes=800))
    with pytest.raises(KimiAcpError, match="AOSAGENT_STREAM_REJECTED"):
        KimiPassiveAdapter().consume_transcript(
            limited,
            (_initialize_result(), _new_result(), _message(json.dumps(_plan())), _prompt_result()),
        )


def test_adapter_bounds_transcript_frame_count_before_protocol_processing() -> None:
    frames = (_line({"jsonrpc": "2.0", "method": "unknown", "params": {}}) for _ in range(1_025))
    with pytest.raises(KimiAcpError, match="TRANSCRIPT_FRAME_LIMIT"):
        KimiPassiveAdapter().consume_transcript(_request(), frames)
