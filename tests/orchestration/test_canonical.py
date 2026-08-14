from __future__ import annotations

import pytest

from agenticos.orchestration.canonical import (
    CanonicalDataError,
    canonical_json_bytes,
    canonical_json_line,
    load_canonical_json,
)


def test_canonical_json_has_one_representation() -> None:
    left = {"z": [2, 1], "a": {"b": "utf8-\u2603", "a": True}}
    right = {"a": {"a": True, "b": "utf8-\u2603"}, "z": [2, 1]}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes(left).startswith(b'{"a"')
    assert canonical_json_line(left) == canonical_json_bytes(left) + b"\n"
    assert load_canonical_json(canonical_json_bytes(left)) == left


@pytest.mark.parametrize(
    "raw,code",
    [
        (b'{"a":1,"a":2}', "DUPLICATE_JSON_KEY"),
        (b'{"a":1.0}', "NON_INTEGER_NUMBER"),
        (b'{"a":NaN}', "NON_INTEGER_NUMBER"),
        (b'\xff', "INVALID_UTF8"),
    ],
)
def test_non_authoritative_json_forms_fail_closed(raw: bytes, code: str) -> None:
    with pytest.raises(CanonicalDataError) as caught:
        load_canonical_json(raw)
    assert caught.value.code == code


def test_byte_limit_is_applied_before_buffer_acceptance() -> None:
    with pytest.raises(CanonicalDataError, match="BYTE_LIMIT_EXCEEDED"):
        load_canonical_json(b'{"value":"oversize"}', max_bytes=5)
