"""Controller-side out-of-process provider authentication helper."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

from .provider_models import ProviderAuthCapability, SecretValue, SubscriptionAuthCapability


class ControllerAuthHelper:
    """Manages synthetic provider authentication state out-of-process in the controller domain."""

    def __init__(self, auth_json_path_or_dict: str | Dict[str, Any]) -> None:
        if isinstance(auth_json_path_or_dict, str):
            if not os.path.exists(auth_json_path_or_dict):
                raise FileNotFoundError(f"Auth file not found: {auth_json_path_or_dict}")
            with open(auth_json_path_or_dict, "r", encoding="utf-8") as f:
                data = json.load(f)
        elif isinstance(auth_json_path_or_dict, dict):
            data = auth_json_path_or_dict
        else:
            raise TypeError("auth_json_path_or_dict must be a file path string or a dict")

        self._validate_schema(data)
        tokens = data.get("tokens", {})
        self._auth_mode: str = data.get("auth_mode", "chatgpt")
        self._access_token: str = tokens.get("access_token", "")
        self._refresh_token: str = tokens.get("refresh_token", "")
        self._account_id: str | None = tokens.get("account_id")
        self._expires_at: int = tokens.get("expires_at", int(time.time()) + 3600)

    def __repr__(self) -> str:
        return f"ControllerAuthHelper(auth_mode={self._auth_mode!r}, account_id={self._account_id!r})"

    def __str__(self) -> str:
        return f"ControllerAuthHelper(mode={self._auth_mode})"

    def _validate_schema(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("Auth data must be a dictionary")
        if "tokens" not in data or not isinstance(data["tokens"], dict):
            raise ValueError("Auth data missing required 'tokens' dictionary")
        tokens = data["tokens"]
        if "access_token" not in tokens or not isinstance(tokens["access_token"], str):
            raise ValueError("Auth tokens missing required 'access_token' string")

    @property
    def auth_mode(self) -> str:
        return self._auth_mode

    @property
    def account_id(self) -> str | None:
        return self._account_id

    @property
    def is_expired(self) -> bool:
        return time.time() >= self._expires_at

    def get_auth_capability(self, task_id: str, generation: int) -> ProviderAuthCapability:
        """Return a task-scoped SubscriptionAuthCapability instance."""
        return SubscriptionAuthCapability(access_token=self._access_token, account_id=self._account_id)

    def refresh_access_token(self, new_access_token: str, new_expires_in: int = 3600) -> None:
        """Update synthetic access token out-of-process when refreshed."""
        if not isinstance(new_access_token, str) or not new_access_token.strip():
            raise ValueError("new_access_token must be a non-empty string")
        self._access_token = new_access_token
        self._expires_at = int(time.time()) + new_expires_in


__all__ = [
    "ControllerAuthHelper",
]
