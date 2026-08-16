from __future__ import annotations

import json

import pytest

from agenticos.providers.kimi_local_auth import (
    KimiLocalAuthError,
    KimiLocalAuthSession,
    LocalCredentialState,
    QualificationState,
)


def _line(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


INITIALIZE_SUCCESS = _line(
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
            "agentInfo": {"name": "Kimi Code CLI", "version": "0.36.1"},
        },
    }
)


def _initialized_session() -> KimiLocalAuthSession:
    session = KimiLocalAuthSession()
    session.initialize_request()
    session.accept(INITIALIZE_SUCCESS)
    return session


def test_la_p01_exact_two_request_surface_and_no_level2_promotion() -> None:
    session = KimiLocalAuthSession()
    assert json.loads(session.initialize_request()) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": 1, "clientCapabilities": {}},
    }
    session.accept(INITIALIZE_SUCCESS)
    assert json.loads(session.authenticate_request()) == {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "authenticate",
        "params": {"methodId": "login"},
    }
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": None}))
    outcome = session.finish()
    assert outcome.qualification is QualificationState.COMPLETE
    assert outcome.credential_state is LocalCredentialState.LOADABLE
    assert outcome.auth_state == "LOCAL_ONLY"
    assert outcome.level2_status == "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
    assert outcome.reason_code == "ACP_LOCAL_AUTH_SUCCESS"


def test_la_p02_rejects_empty_initialize_result() -> None:
    session = KimiLocalAuthSession()
    session.initialize_request()
    with pytest.raises(KimiLocalAuthError, match="INITIALIZE_SHAPE"):
        session.accept(_line({"jsonrpc": "2.0", "id": 1, "result": {}}))


def test_la_p03_accepts_empty_authenticate_result_as_loadable() -> None:
    session = _initialized_session()
    session.authenticate_request()
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": {}}))
    assert session.finish().credential_state is LocalCredentialState.LOADABLE


def test_la_p04_maps_only_exact_login_rejection_to_rejected() -> None:
    session = _initialized_session()
    session.authenticate_request()
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "declined"}}))
    outcome = session.finish()
    assert outcome.qualification is QualificationState.COMPLETE
    assert outcome.credential_state is LocalCredentialState.REJECTED
    assert outcome.level2_status == "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"


def test_la_p05_rejects_nonexact_authentication_error() -> None:
    session = _initialized_session()
    session.authenticate_request()
    with pytest.raises(KimiLocalAuthError, match="ACP_ERROR_RESPONSE"):
        session.accept(_line({"jsonrpc": "2.0", "id": 2, "error": {"code": -32001, "message": "unknown"}}))


def test_la_p06_rejects_wrong_response_id() -> None:
    session = KimiLocalAuthSession()
    session.initialize_request()
    with pytest.raises(KimiLocalAuthError, match="UNEXPECTED_RESPONSE_ID"):
        session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": {}}))


def test_la_p07_rejects_duplicate_terminal_response() -> None:
    session = _initialized_session()
    session.authenticate_request()
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": None}))
    with pytest.raises(KimiLocalAuthError, match="DUPLICATE_TERMINAL"):
        session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": None}))


def test_la_p08_rejects_callbacks() -> None:
    session = KimiLocalAuthSession()
    session.initialize_request()
    with pytest.raises(KimiLocalAuthError, match="UNEXPECTED_CALLBACK"):
        session.accept(_line({"jsonrpc": "2.0", "method": "session/update", "params": {}}))


@pytest.mark.parametrize(
    "frame, code",
    [
        (b"not-json\n", "MALFORMED_JSON"),
        (b"x" * 65_537 + b"\n", "FRAME_TOO_LARGE"),
    ],
)
def test_la_p09_rejects_malformed_and_oversized_frames(frame: bytes, code: str) -> None:
    session = KimiLocalAuthSession()
    with pytest.raises(KimiLocalAuthError, match=code):
        session.accept(frame)


def test_la_p10_initialize_only_transcript_is_incomplete() -> None:
    session = _initialized_session()
    with pytest.raises(KimiLocalAuthError, match="INCOMPLETE_TRANSCRIPT"):
        session.finish()
