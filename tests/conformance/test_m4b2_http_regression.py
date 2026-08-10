"""M4B-2 adversarial-review regression tests for the strict HTTP envelope.

Covers the fixes for three findings against
:mod:`agenticos.sandbox.network_http`:

* HTTP-1 (HIGH): GET/HEAD request bodies enable CL.0 request desync — the
  prevalidator now rejects Content-Length > 0 and ANY Transfer-Encoding on
  GET/HEAD with a typed code; a bare ``Content-Length: 0`` stays accepted
  (no body bytes follow, so no desync boundary ambiguity is possible).
* HTTP-4 (LOW): request targets starting with ``//`` (network-path
  references per RFC 3986) were treated as origin-form; now rejected.
* HTTP-2 (prevalidator half): ``Connection: close`` was forwarded and only
  surfaced later as a misleading H11_DISAGREEMENT; the prevalidator now
  rejects the ``close`` connection-token case-insensitively (including
  multi-token values) because the broker owns connection lifetime.

Self-contained: mirrors the harness style of
``tests/conformance/test_m4b_http_unit.py`` but imports nothing from the
conformance conftest/helpers.  Pure parser tests: no Linux-only resources,
no network, no sleeps.
"""

from __future__ import annotations

import pytest

from agenticos.sandbox.network_http import (
    BodyData,
    HttpPolicy,
    RejectionCode,
    RequestComplete,
    RequestHead,
    StrictHttpParser,
)

H = b"Host: x\r\n"


def _feed_all(wire: bytes, policy: HttpPolicy, chunk_size: int | None = None):
    """Feed wire in chunk_size pieces (None = one write); return (events, rejection)."""
    parser = StrictHttpParser(policy)
    events: list = []
    if chunk_size is None:
        result = parser.feed(wire)
        return list(result.events), result.rejection
    rejection = None
    for start in range(0, len(wire), chunk_size):
        result = parser.feed(wire[start : start + chunk_size])
        events.extend(result.events)
        if result.rejection is not None:
            rejection = result.rejection
            break
    return events, rejection or parser.rejection


def _assert_rejected(wire: bytes, code: RejectionCode, policy: HttpPolicy | None = None):
    events, rejection = _feed_all(wire, policy or HttpPolicy.general_download())
    assert rejection is not None, "fixture was ACCEPTED"
    assert rejection.code == code, f"{rejection.code} != {code}"
    # Rejection at the prevalidator: nothing may have been validated/forwarded.
    assert not [e for e in events if isinstance(e, (RequestHead, RequestComplete, BodyData))]
    return rejection


def _assert_accepted(wire: bytes, policy: HttpPolicy | None = None):
    events, rejection = _feed_all(wire, policy or HttpPolicy.general_download())
    assert rejection is None, f"unexpected rejection: {rejection}"
    heads = [e for e in events if isinstance(e, RequestHead)]
    completes = [e for e in events if isinstance(e, RequestComplete)]
    assert len(heads) == len(completes) >= 1
    body = b"".join(e.data for e in events if isinstance(e, BodyData))
    return heads, body


# -- HTTP-1: GET/HEAD request bodies (CL.0 request desync) --------------------

def test_get_with_content_length_rejected() -> None:
    """The verified CL.0 attack: a 'GET body' that is a smuggled request."""
    wire = (
        b"GET / HTTP/1.1\r\n" + H + b"Content-Length: 34\r\n\r\n"
        b"DELETE /repo HTTP/1.1\r\n" + H + b"\r\n"
    )
    rejection = _assert_rejected(wire, RejectionCode.BODILESS_METHOD_WITH_BODY)
    assert rejection.request_index == 0


def test_get_with_chunked_transfer_encoding_rejected() -> None:
    wire = b"GET / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    _assert_rejected(wire, RejectionCode.BODILESS_METHOD_WITH_BODY)


def test_get_with_any_transfer_encoding_rejected() -> None:
    """TE on GET is rejected whatever its form: non-chunked codings still die
    at the header stage; the canonical chunked form dies at head completion."""
    gzip_wire = b"GET / HTTP/1.1\r\n" + H + b"Transfer-Encoding: gzip\r\n\r\n"
    _assert_rejected(gzip_wire, RejectionCode.TRANSFER_ENCODING_UNSUPPORTED)
    chunked_wire = b"GET / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\n\r\n"
    _assert_rejected(chunked_wire, RejectionCode.BODILESS_METHOD_WITH_BODY)


def test_head_with_content_length_rejected() -> None:
    wire = b"HEAD / HTTP/1.1\r\n" + H + b"Content-Length: 7\r\n\r\nxxxxxxx"
    _assert_rejected(wire, RejectionCode.BODILESS_METHOD_WITH_BODY)


def test_head_with_chunked_transfer_encoding_rejected() -> None:
    wire = b"HEAD / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    _assert_rejected(wire, RejectionCode.BODILESS_METHOD_WITH_BODY)


def test_get_with_zero_content_length_accepted() -> None:
    """Documented decision: a bare Content-Length: 0 on GET/HEAD is ACCEPTED —
    no body bytes follow, so both parsers agree on the message boundary."""
    heads, body = _assert_accepted(
        b"GET / HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n"
    )
    assert [h.method for h in heads] == ["GET"]
    assert heads[0].content_length == 0
    assert body == b""


def test_head_with_zero_content_length_accepted() -> None:
    heads, body = _assert_accepted(
        b"HEAD / HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n"
    )
    assert [h.method for h in heads] == ["HEAD"]
    assert body == b""


def test_post_with_body_still_works() -> None:
    policy = HttpPolicy.git_smart_fetch()
    heads, body = _assert_accepted(
        b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 5\r\n\r\nhello", policy
    )
    assert [h.method for h in heads] == ["POST"]
    assert body == b"hello"
    heads, body = _assert_accepted(
        b"POST / HTTP/1.1\r\n" + H + b"Transfer-Encoding: chunked\r\n\r\n"
        b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n",
        policy,
    )
    assert [h.method for h in heads] == ["POST"]
    assert body == b"abcdef"


@pytest.mark.parametrize("chunk_size", [1, 7])
def test_get_body_rejection_byte_drip_equivalence(chunk_size: int) -> None:
    """The CL.0 attack verdict is identical under one-byte-at-a-time delivery."""
    wire = (
        b"GET / HTTP/1.1\r\n" + H + b"Content-Length: 34\r\n\r\n"
        b"DELETE /repo HTTP/1.1\r\n" + H + b"\r\n"
    )
    _, one_rej = _feed_all(wire, HttpPolicy.general_download())
    _, drip_rej = _feed_all(wire, HttpPolicy.general_download(), chunk_size)
    assert one_rej is not None and one_rej.code == RejectionCode.BODILESS_METHOD_WITH_BODY
    assert drip_rej is not None and drip_rej.code == one_rej.code


# -- HTTP-4: network-path reference request targets ----------------------------

def test_network_path_reference_target_rejected() -> None:
    """//evil.example/path is a network-path reference (RFC 3986), not origin-form."""
    _assert_rejected(
        b"GET //evil.example/path HTTP/1.1\r\n" + H + b"\r\n",
        RejectionCode.TARGET_NETWORK_PATH_REFERENCE,
    )


def test_network_path_reference_bare_rejected() -> None:
    _assert_rejected(
        b"GET // HTTP/1.1\r\n" + H + b"\r\n",
        RejectionCode.TARGET_NETWORK_PATH_REFERENCE,
    )


def test_origin_form_target_still_accepted() -> None:
    heads, _ = _assert_accepted(b"GET /x?q=1 HTTP/1.1\r\n" + H + b"\r\n")
    assert heads[0].target == b"/x?q=1"


# -- Connection: close policy (HTTP-2 prevalidator half) -----------------------

def test_connection_close_rejected() -> None:
    rejection = _assert_rejected(
        b"GET / HTTP/1.1\r\n" + H + b"Connection: close\r\n\r\n",
        RejectionCode.CONNECTION_CLOSE_REJECTED,
    )
    assert rejection.request_index == 0


def test_connection_close_case_insensitive_rejected() -> None:
    """h11 parses connection tokens case-insensitively; reject identically."""
    _assert_rejected(
        b"GET / HTTP/1.1\r\n" + H + b"Connection: Close\r\n\r\n",
        RejectionCode.CONNECTION_CLOSE_REJECTED,
    )
    _assert_rejected(
        b"GET / HTTP/1.1\r\n" + H + b"Connection: CLOSE\r\n\r\n",
        RejectionCode.CONNECTION_CLOSE_REJECTED,
    )


def test_connection_close_multi_token_rejected() -> None:
    _assert_rejected(
        b"GET / HTTP/1.1\r\n" + H + b"Connection: keep-alive, close\r\n\r\n",
        RejectionCode.CONNECTION_CLOSE_REJECTED,
    )


def test_connection_keep_alive_accepted() -> None:
    """Unchanged behavior: a bare keep-alive token carries no lifetime
    negotiation the broker does not already control, and stays accepted."""
    heads, _ = _assert_accepted(
        b"GET / HTTP/1.1\r\n" + H + b"Connection: keep-alive\r\n\r\n"
    )
    assert (b"Connection", b"keep-alive") in heads[0].headers
