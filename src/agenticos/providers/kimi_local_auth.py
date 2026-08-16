"""Closed Level-1 ACP local-authentication checkpoint for Kimi qualification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from agenticos.providers.kimi_acp import (
    KimiAcpError,
    decode_acp_line,
    encode_acp_request,
    validate_kimi_initialize_result,
)


class KimiLocalAuthError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class LocalCredentialState(str, Enum):
    LOADABLE = "LOADABLE"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"


class QualificationState(str, Enum):
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class LocalAuthProtocolOutcome:
    qualification: QualificationState
    credential_state: LocalCredentialState
    auth_state: str = "LOCAL_ONLY"
    level2_status: str = "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
    reason_code: str = "ACP_LOCAL_AUTH_SUCCESS"


class KimiLocalAuthSession:
    """Accept exactly initialize and authenticate ACP responses, then stop."""

    def __init__(self) -> None:
        self._state = "NEW"
        self._terminal = False
        self._outcome: LocalAuthProtocolOutcome | None = None

    def initialize_request(self) -> bytes:
        if self._state != "NEW":
            raise KimiLocalAuthError("INITIALIZE_ORDER")
        self._state = "INITIALIZING"
        return encode_acp_request("initialize", 1, {"protocolVersion": 1, "clientCapabilities": {}})

    def authenticate_request(self) -> bytes:
        if self._state != "INITIALIZED":
            raise KimiLocalAuthError("AUTHENTICATE_ORDER")
        self._state = "AUTHENTICATING"
        return encode_acp_request("authenticate", 2, {"methodId": "login"})

    def accept(self, raw: bytes) -> None:
        try:
            message = decode_acp_line(raw)
        except KimiAcpError as exc:
            raise KimiLocalAuthError(exc.code) from exc
        if "method" in message:
            raise KimiLocalAuthError("UNEXPECTED_CALLBACK")
        if self._terminal:
            raise KimiLocalAuthError("DUPLICATE_TERMINAL")
        expected_id = {"INITIALIZING": 1, "AUTHENTICATING": 2}.get(self._state)
        if message["id"] != expected_id:
            raise KimiLocalAuthError("UNEXPECTED_RESPONSE_ID")
        if self._state == "INITIALIZING":
            self._accept_initialize(message)
            return
        if self._state == "AUTHENTICATING":
            self._accept_authenticate(message)
            return
        raise KimiLocalAuthError("UNEXPECTED_RESPONSE")

    def finish(self) -> LocalAuthProtocolOutcome:
        if not self._terminal or self._outcome is None:
            raise KimiLocalAuthError("INCOMPLETE_TRANSCRIPT")
        return self._outcome

    def _accept_initialize(self, message: dict[str, object]) -> None:
        if "error" in message:
            raise KimiLocalAuthError("ACP_ERROR_RESPONSE")
        try:
            validate_kimi_initialize_result(message["result"])
        except KimiAcpError as exc:
            raise KimiLocalAuthError(exc.code) from exc
        self._state = "INITIALIZED"

    def _accept_authenticate(self, message: dict[str, object]) -> None:
        if "error" in message:
            error = message["error"]
            if type(error) is dict and set(error) == {"code", "message"} and type(error["code"]) is int and error["code"] == -32000 and type(error["message"]) is str:
                credential_state = LocalCredentialState.REJECTED
            else:
                raise KimiLocalAuthError("ACP_ERROR_RESPONSE")
        elif message["result"] is None or message["result"] == {}:
            credential_state = LocalCredentialState.LOADABLE
        else:
            raise KimiLocalAuthError("MALFORMED_RESPONSE")
        reason_code = (
            "ACP_LOCAL_AUTH_REJECTED"
            if credential_state is LocalCredentialState.REJECTED
            else "ACP_LOCAL_AUTH_SUCCESS"
        )
        self._outcome = LocalAuthProtocolOutcome(
            (
                QualificationState.BLOCKED
                if credential_state is LocalCredentialState.REJECTED
                else QualificationState.COMPLETE
            ),
            credential_state,
            reason_code=reason_code,
        )
        self._terminal = True
        self._state = "FINISHED"
