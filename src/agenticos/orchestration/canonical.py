"""Single authoritative JSON representation for hashes, records, and protocol data."""

from __future__ import annotations

import json
from typing import Any

MAX_CANONICAL_DEPTH = 16
DEFAULT_MAX_CANONICAL_BYTES = 4 * 1024 * 1024


class CanonicalDataError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _validate(value: object, depth: int = 0) -> None:
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalDataError("NESTING_LIMIT_EXCEEDED")
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is list:
        for item in value:
            _validate(item, depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalDataError("INVALID_JSON_KEY")
            _validate(item, depth + 1)
        return
    if type(value) is float:
        raise CanonicalDataError("NON_INTEGER_NUMBER")
    raise CanonicalDataError("INVALID_JSON_TYPE", type(value).__name__)


def canonical_json_bytes(value: object, *, max_bytes: int = DEFAULT_MAX_CANONICAL_BYTES) -> bytes:
    _validate(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalDataError("CANONICAL_ENCODING_FAILED") from exc
    if len(encoded) > max_bytes:
        raise CanonicalDataError("BYTE_LIMIT_EXCEEDED")
    return encoded


def canonical_json_line(value: object, *, max_bytes: int = DEFAULT_MAX_CANONICAL_BYTES) -> bytes:
    encoded = canonical_json_bytes(value, max_bytes=max_bytes - 1)
    return encoded + b"\n"


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalDataError("DUPLICATE_JSON_KEY", key)
        result[key] = value
    return result


def _reject_number(_: str) -> None:
    raise CanonicalDataError("NON_INTEGER_NUMBER")


def load_canonical_json(raw: bytes, *, max_bytes: int = DEFAULT_MAX_CANONICAL_BYTES) -> object:
    if type(raw) is not bytes:
        raise CanonicalDataError("INVALID_BYTE_INPUT")
    if len(raw) > max_bytes:
        raise CanonicalDataError("BYTE_LIMIT_EXCEEDED")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CanonicalDataError("INVALID_UTF8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except CanonicalDataError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalDataError("MALFORMED_JSON") from exc
    _validate(value)
    return value
