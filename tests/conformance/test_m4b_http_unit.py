"""Corpus C — adversarial HTTP/1.1 request-smuggling fixtures for Slice 5.

Covers the M4B-2 strict-HTTP parser (:mod:`agenticos.sandbox.network_http`):
a strict raw-byte prevalidator in front of the gated h11 dependency.  Every
rejection fixture asserts the exact typed RejectionCode; every fixture h11
alone would ACCEPT (verified live against h11 in this file) additionally
asserts that the prevalidator rejects FIRST — h11 is never the security
envelope.  Byte-drip property tests prove identical verdicts for one-write
versus one-byte-at-a-time delivery.  Pure parser tests: no Linux-only
resources, no network, no sleeps.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

h11 = pytest.importorskip("h11")  # gated broker dependency; wheelhouse-pinned

from agenticos.sandbox.network_http import (
    BodyData,
    HttpPolicy,
    RejectionCode,
    RequestComplete,
    RequestHead,
    StrictHttpParser,
)

H = b"Host: x\r\n"
GIT = "git"      # git_smart_fetch policy: GET/HEAD + purpose-granted POST
TINY = "tiny"    # POST allowed, 16-byte body bound


def _policy(kind: str) -> HttpPolicy:
    if kind == GIT:
        return HttpPolicy.git_smart_fetch()
    if kind == TINY:
        return HttpPolicy(allowed_methods=frozenset({"GET", "HEAD", "POST"}), max_body_bytes=16)
    return HttpPolicy.general_download()


@dataclass(frozen=True)
class Case:
    id: str
    wire: bytes
    expect: RejectionCode | None          # None = accepted end-to-end
    policy: str = "default"
    h11_accepts: bool | None = None       # standalone-h11 verdict (reject cases)
    methods: tuple = ()                   # expected methods, accept cases
    body: bytes = b""                     # expected concatenated body, accept cases


_POST = b"POST / HTTP/1.1\r\n" + H
_TE = _POST + b"Transfer-Encoding: chunked\r\n\r\n"

CASES = [
    # -- CRLF-only framing ---------------------------------------------------
    Case("bare-lf-request-line", b"GET / HTTP/1.1\nHost: x\r\n\r\n",
         RejectionCode.BARE_LF, h11_accepts=True),
    Case("bare-lf-header-line", b"GET / HTTP/1.1\r\nHost: x\nX-A: 1\r\n\r\n",
         RejectionCode.BARE_LF, h11_accepts=True),
    Case("cr-not-followed-by-lf", b"GET / HTTP/1.1\r\nHost: x\rX-A: 1\r\n\r\n",
         RejectionCode.CR_NOT_FOLLOWED_BY_LF, h11_accepts=False),
    Case("cr-inside-header-value", b"GET / HTTP/1.1\r\n" + H + b"X-A: a\rb\r\n\r\n",
         RejectionCode.CR_NOT_FOLLOWED_BY_LF, h11_accepts=False),
    Case("nul-in-request-target", b"GET /\x00x HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.TARGET_MALFORMED, h11_accepts=False),
    Case("nul-in-header-value", b"GET / HTTP/1.1\r\n" + H + b"X-A: a\x00b\r\n\r\n",
         RejectionCode.HEADER_VALUE_INVALID, h11_accepts=False),
    Case("nul-in-header-name", b"GET / HTTP/1.1\r\n" + H + b"X-\x00A: 1\r\n\r\n",
         RejectionCode.HEADER_NAME_INVALID, h11_accepts=False),
    Case("vt-whitespace-trick-in-method", b"GE\x0bT / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_INVALID, h11_accepts=False),
    Case("ff-whitespace-trick-in-method", b"GE\x0cT / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_INVALID, h11_accepts=False),
    Case("htab-in-method", b"GET\t / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_INVALID, h11_accepts=False),
    Case("leading-empty-line", b"\r\nGET / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.LEADING_EMPTY_LINE, h11_accepts=False),
    # -- request line ---------------------------------------------------------
    Case("double-space-separator", b"GET  / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.REQUEST_LINE_MALFORMED, h11_accepts=False),
    Case("http09-bare-request-line", b"GET /\r\n",
         RejectionCode.REQUEST_LINE_MALFORMED, h11_accepts=True),
    Case("http-1.0-version", b"GET / HTTP/1.0\r\n" + H + b"\r\n",
         RejectionCode.VERSION_REJECTED, h11_accepts=True),
    Case("http2-connection-preface",
         b"PRI * HTTP/2.0\r\n\r\n",  # first line of the HTTP/2 client preface
         RejectionCode.VERSION_REJECTED, h11_accepts=True),
    Case("lowercase-http-version", b"GET / http/1.1\r\n" + H + b"\r\n",
         RejectionCode.VERSION_REJECTED, h11_accepts=False),
    Case("method-invalid-tchar", b"G@T / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_INVALID, h11_accepts=False),
    Case("lowercase-method", b"get / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_NOT_ALLOWED, h11_accepts=True),
    Case("oversized-request-line",
         b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.REQUEST_LINE_TOO_LONG, h11_accepts=True),
    # -- method policy (default grant: GET/HEAD only) -------------------------
    Case("nested-connect", b"CONNECT x:443 HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_NOT_ALLOWED, h11_accepts=True),
    Case("trace-method", b"TRACE / HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_NOT_ALLOWED, h11_accepts=True),
    Case("put-method", b"PUT /x HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n",
         RejectionCode.METHOD_NOT_ALLOWED, h11_accepts=True),
    Case("post-denied-by-default-policy",
         b"POST / HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n",
         RejectionCode.METHOD_NOT_ALLOWED, h11_accepts=True),
    # -- request-target forms ---------------------------------------------------
    Case("asterisk-form", b"GET * HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.TARGET_ASTERISK_FORM, h11_accepts=True),
    Case("authority-form", b"GET example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
         RejectionCode.TARGET_AUTHORITY_FORM, h11_accepts=True),
    Case("absolute-form-authority-match", b"GET http://x/ HTTP/1.1\r\n" + H + b"\r\n",
         None, methods=("GET",)),
    Case("absolute-form-authority-mismatch", b"GET http://evil/ HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.TARGET_AUTHORITY_MISMATCH, h11_accepts=True),
    Case("absolute-form-empty-authority", b"GET http:/// HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.TARGET_MALFORMED, h11_accepts=True),
    Case("target-with-del-byte", b"GET /a\x7fb HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.TARGET_MALFORMED, h11_accepts=False),
    # -- header syntax ------------------------------------------------------------
    Case("space-before-colon", b"GET / HTTP/1.1\r\n" + H + b"X-A : 1\r\n\r\n",
         RejectionCode.HEADER_NAME_INVALID, h11_accepts=False),
    Case("empty-header-name", b"GET / HTTP/1.1\r\n" + H + b": 1\r\n\r\n",
         RejectionCode.HEADER_NAME_INVALID, h11_accepts=False),
    Case("header-name-invalid-tchar", b"GET / HTTP/1.1\r\n" + H + b"X@A: 1\r\n\r\n",
         RejectionCode.HEADER_NAME_INVALID, h11_accepts=False),
    Case("obs-fold-space", b"GET / HTTP/1.1\r\n" + H + b"X-A: 1\r\n 2\r\n\r\n",
         RejectionCode.OBS_FOLD_REJECTED, h11_accepts=True),
    Case("obs-fold-tab", b"GET / HTTP/1.1\r\n" + H + b"X-A: 1\r\n\t2\r\n\r\n",
         RejectionCode.OBS_FOLD_REJECTED, h11_accepts=True),
    Case("htab-after-colon", b"GET / HTTP/1.1\r\n" + H + b"X-V:\t1\r\n\r\n",
         RejectionCode.HEADER_VALUE_INVALID, h11_accepts=True),
    Case("obs-text-in-value", b"GET / HTTP/1.1\r\n" + H + b"X-V: \xc3\xa9\r\n\r\n",
         RejectionCode.HEADER_VALUE_INVALID, h11_accepts=True),
    Case("control-char-in-value", b"GET / HTTP/1.1\r\n" + H + b"X-V: a\x01b\r\n\r\n",
         RejectionCode.HEADER_VALUE_INVALID, h11_accepts=True),
    Case("trailing-space-in-value", b"GET / HTTP/1.1\r\n" + H + b"X-V: 1 \r\n\r\n",
         RejectionCode.HEADER_VALUE_INVALID, h11_accepts=True),
    Case("oversized-header-line",
         b"GET / HTTP/1.1\r\n" + H + b"X-A: " + b"a" * 9000 + b"\r\n\r\n",
         RejectionCode.HEADER_LINE_TOO_LONG, h11_accepts=True),
    Case("oversized-header-block",
         b"GET / HTTP/1.1\r\n" + H
         + b"".join(b"X-H%02d: " % i + b"v" * 180 + b"\r\n" for i in range(90)) + b"\r\n",
         RejectionCode.HEADER_BLOCK_TOO_LARGE, h11_accepts=True),
    Case("oversized-header-count",
         b"GET / HTTP/1.1\r\n" + H
         + b"".join(b"X-H%03d: v\r\n" % i for i in range(101)) + b"\r\n",
         RejectionCode.TOO_MANY_HEADERS, h11_accepts=True),
    Case("oversized-single-complete-write",
         b"GET / HTTP/1.1\r\n" + H
         + b"".join(b"X-H%04d: " % i + b"v" * 195 + b"\r\n" for i in range(4000)) + b"\r\n",
         RejectionCode.HEADER_BLOCK_TOO_LARGE, h11_accepts=True),
    Case("header-line-without-colon", b"GET / HTTP/1.1\r\n" + H + b"X-A 1\r\n\r\n",
         RejectionCode.HEADER_MALFORMED, h11_accepts=False),
    # -- Host ---------------------------------------------------------------------
    Case("host-missing", b"GET / HTTP/1.1\r\nX-A: 1\r\n\r\n",
         RejectionCode.HOST_MISSING, h11_accepts=False),
    Case("host-duplicate", b"GET / HTTP/1.1\r\n" + H + b"Host: y\r\n\r\n",
         RejectionCode.HOST_DUPLICATE, h11_accepts=False),
    Case("host-with-space", b"GET / HTTP/1.1\r\nHost: ex ample\r\n\r\n",
         RejectionCode.HOST_MALFORMED, h11_accepts=True),
    Case("host-empty", b"GET / HTTP/1.1\r\nHost:\r\n\r\n",
         RejectionCode.HOST_MALFORMED, h11_accepts=True),
    # -- Content-Length -------------------------------------------------------------
    Case("cl-duplicate-identical",
         _POST + b"Content-Length: 4\r\nContent-Length: 4\r\n\r\nabcd",
         RejectionCode.CONTENT_LENGTH_DUPLICATE, policy=GIT, h11_accepts=True),
    Case("cl-duplicate-conflicting",
         _POST + b"Content-Length: 4\r\nContent-Length: 5\r\n\r\nabcd",
         RejectionCode.CONTENT_LENGTH_DUPLICATE, policy=GIT, h11_accepts=False),
    Case("cl-non-numeric", _POST + b"Content-Length: 4x\r\n\r\n",
         RejectionCode.CONTENT_LENGTH_INVALID, policy=GIT, h11_accepts=False),
    Case("cl-negative", _POST + b"Content-Length: -4\r\n\r\n",
         RejectionCode.CONTENT_LENGTH_INVALID, policy=GIT, h11_accepts=False),
    Case("cl-leading-zero", _POST + b"Content-Length: 04\r\n\r\nabcd",
         RejectionCode.CONTENT_LENGTH_INVALID, policy=GIT, h11_accepts=True),
    Case("cl-exceeds-policy-bound", _POST + b"Content-Length: 17\r\n\r\n" + b"b" * 17,
         RejectionCode.CONTENT_LENGTH_TOO_LARGE, policy=TINY, h11_accepts=True),
    Case("cl-zero-smuggled-post",
         b"GET / HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n"
         b"POST /evil HTTP/1.1\r\n" + H + b"Content-Length: 0\r\n\r\n",
         RejectionCode.METHOD_NOT_ALLOWED, h11_accepts=True),
    # -- Transfer-Encoding -----------------------------------------------------------
    Case("te-with-content-length",
         _POST + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
         RejectionCode.TE_WITH_CONTENT_LENGTH, policy=GIT, h11_accepts=True),
    Case("te-gzip-coding", _POST + b"Transfer-Encoding: gzip\r\n\r\n0\r\n\r\n",
         RejectionCode.TRANSFER_ENCODING_UNSUPPORTED, policy=GIT, h11_accepts=False),
    Case("te-multiple-codings", _POST + b"Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
         RejectionCode.TRANSFER_ENCODING_UNSUPPORTED, policy=GIT, h11_accepts=False),
    Case("te-multiple-headers",
         _POST + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
         RejectionCode.TRANSFER_ENCODING_DUPLICATE, policy=GIT, h11_accepts=False),
    Case("te-cl-classic-smuggling-pair",
         _POST + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
         b"GET /evil HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.TE_WITH_CONTENT_LENGTH, policy=GIT, h11_accepts=True),
    Case("te-coding-not-byte-exact",
         _POST + b"Transfer-Encoding: Chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
         RejectionCode.TRANSFER_ENCODING_UNSUPPORTED, policy=GIT, h11_accepts=True),
    # -- chunked framing -----------------------------------------------------------------
    Case("chunk-extension", _TE + b"4;foo=bar\r\nabcd\r\n0\r\n\r\n",
         RejectionCode.CHUNK_EXTENSION_REJECTED, policy=GIT, h11_accepts=True),
    Case("chunk-extension-invisible", _TE + b"4;\r\nabcd\r\n0\r\n\r\n",
         RejectionCode.CHUNK_EXTENSION_REJECTED, policy=GIT, h11_accepts=True),
    Case("chunk-size-bad-hex", _TE + b"Z\r\nabcd\r\n0\r\n\r\n",
         RejectionCode.CHUNK_SIZE_INVALID, policy=GIT, h11_accepts=False),
    Case("chunk-size-negative-looking", _TE + b"-1\r\nabcd\r\n0\r\n\r\n",
         RejectionCode.CHUNK_SIZE_INVALID, policy=GIT, h11_accepts=False),
    Case("chunk-size-nine-hex-digits", _TE + b"123456789\r\n",
         RejectionCode.CHUNK_SIZE_INVALID, policy=GIT, h11_accepts=True),
    Case("chunk-exceeds-body-budget", _TE + b"11\r\n" + b"b" * 17 + b"\r\n0\r\n\r\n",
         RejectionCode.BODY_TOO_LARGE, policy=TINY, h11_accepts=True),
    Case("chunk-data-missing-crlf", _TE + b"4\r\nabcdXX0\r\n\r\n",
         RejectionCode.CHUNK_DATA_CRLF_MISSING, policy=GIT, h11_accepts=False),
    Case("forbidden-trailer-header", _TE + b"0\r\nX-T: 1\r\n\r\n",
         RejectionCode.TRAILER_REJECTED, policy=GIT, h11_accepts=True),
    Case("forbidden-trailer-garbage", _TE + b"0\r\nGARBAGE\r\n",
         RejectionCode.TRAILER_REJECTED, policy=GIT, h11_accepts=True),
    # -- pipelining / sequential revalidation -----------------------------------------------
    Case("pipelined-second-request-valid",
         b"GET /1 HTTP/1.1\r\n" + H + b"\r\nHEAD /2 HTTP/1.1\r\n" + H + b"\r\n",
         None, methods=("GET", "HEAD")),
    Case("pipelined-second-request-bad-method",
         b"GET /1 HTTP/1.1\r\n" + H + b"\r\nTRACE /2 HTTP/1.1\r\n" + H + b"\r\n",
         RejectionCode.METHOD_NOT_ALLOWED, h11_accepts=True),
    Case("pipelined-second-request-smuggling",
         b"GET /1 HTTP/1.1\r\n" + H + b"\r\n"
         b"POST /2 HTTP/1.1\r\n" + H + b"Content-Length: 4\r\nContent-Length: 4\r\n\r\n",
         RejectionCode.CONTENT_LENGTH_DUPLICATE, policy=GIT, h11_accepts=True),
    # -- negotiation that policy forbids -----------------------------------------------------
    Case("upgrade-websocket",
         b"GET / HTTP/1.1\r\n" + H + b"Upgrade: websocket\r\nConnection: upgrade\r\n\r\n",
         RejectionCode.UPGRADE_REJECTED, h11_accepts=True),
    Case("expect-100-continue", _POST + b"Content-Length: 4\r\nExpect: 100-continue\r\n\r\n",
         RejectionCode.EXPECT_REJECTED, policy=GIT, h11_accepts=True),
    # -- positive cases (accepted end-to-end THROUGH h11) --------------------------------------
    Case("clean-get", b"GET /x?q=1 HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n",
         None, methods=("GET",)),
    Case("clean-head", b"HEAD / HTTP/1.1\r\n" + H + b"\r\n", None, methods=("HEAD",)),
    Case("host-header-name-case", b"GET / HTTP/1.1\r\nHOST: x\r\n\r\n", None, methods=("GET",)),
    Case("post-with-content-length",
         _POST + b"Content-Length: 5\r\n\r\nhello", None, policy=GIT,
         methods=("POST",), body=b"hello"),
    Case("post-with-zero-content-length",
         _POST + b"Content-Length: 0\r\n\r\n", None, policy=GIT, methods=("POST",)),
    Case("post-chunked", _TE + b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n", None, policy=GIT,
         methods=("POST",), body=b"abcdef"),
]

_REJECT_CASES = [c for c in CASES if c.expect is not None]
_ACCEPT_CASES = [c for c in CASES if c.expect is None]
_H11_STRICTER_THAN_POLICY = [c for c in _REJECT_CASES if c.h11_accepts]

# Representative subset for the byte-drip equivalence property: positives,
# pipelining, smuggling pairs, framing tricks, and policy rejects.
_DRIP_IDS = {
    "clean-get", "post-with-content-length", "post-chunked",
    "pipelined-second-request-valid", "bare-lf-request-line", "obs-fold-space",
    "cl-duplicate-identical", "te-with-content-length", "chunk-extension",
    "forbidden-trailer-header", "oversized-request-line", "http2-connection-preface",
    "nested-connect", "cl-zero-smuggled-post", "absolute-form-authority-mismatch",
    "te-cl-classic-smuggling-pair", "upgrade-websocket", "expect-100-continue",
    "chunk-data-missing-crlf", "host-duplicate",
}
_DRIP_CASES = [c for c in CASES if c.id in _DRIP_IDS]


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


def _normalized(events: list):
    """Arrival-independent event summary (BodyData segmentation is merged)."""
    out = []
    body = bytearray()
    for event in events:
        if isinstance(event, BodyData):
            body += event.data
            continue
        if isinstance(event, RequestHead):
            out.append(("head", event.request_index, event.method, event.target,
                        event.host, event.headers, event.content_length, event.chunked))
        elif isinstance(event, RequestComplete):
            out.append(("complete", event.request_index, event.body_bytes))
        else:  # pragma: no cover - unknown event type is a bug
            raise AssertionError(f"unexpected event {event!r}")
    return out, bytes(body)


def h11_alone_accepts(wire: bytes) -> bool:
    """Standalone-h11 verdict: True if h11 consumes the wire without error.

    Advances h11's keep-alive state machine exactly as a cooperating server
    would (100-continue, response, next cycle) so the verdict measures h11's
    wire acceptance, not its application API discipline.
    """
    conn = h11.Connection(h11.SERVER)
    try:
        conn.receive_data(wire)
        for _ in range(10000):
            event = conn.next_event()
            if event is h11.NEED_DATA:
                return True
            if event is h11.PAUSED:
                if conn.they_are_waiting_for_100_continue:
                    conn.send(h11.InformationalResponse(status_code=100, headers=[]))
                elif conn.our_state is h11.SEND_RESPONSE:
                    conn.send(h11.Response(status_code=200, headers=[], reason=b""))
                    if conn.our_state is h11.SWITCHED_PROTOCOL:
                        # CONNECT accepted and a tunnel established: the wire
                        # was consumed without a protocol error — acceptance.
                        return True
                    conn.send(h11.EndOfMessage())
                if conn.our_state is h11.DONE and conn.their_state is h11.DONE:
                    try:
                        conn.start_next_cycle()
                    except Exception:
                        # must-close or tunnel end-state (HTTP/2.0 preface
                        # version, CONNECT): the wire was consumed without a
                        # protocol error, which is acceptance for our purpose.
                        return True
                continue
        return False
    except Exception:
        return False


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_corpus_verdict(case: Case) -> None:
    events, rejection = _feed_all(case.wire, _policy(case.policy))
    if case.expect is None:
        assert rejection is None, f"unexpected rejection: {rejection}"
        summary, body = _normalized(events)
        heads = [e for e in events if isinstance(e, RequestHead)]
        completes = [e for e in events if isinstance(e, RequestComplete)]
        assert [h.method for h in heads] == list(case.methods)
        assert [h.request_index for h in heads] == list(range(len(heads)))
        assert len(completes) == len(heads) >= 1
        assert body == case.body
        assert sum(c.body_bytes for c in completes) == len(case.body)
        assert summary  # sanity
    else:
        assert rejection is not None, "fixture was ACCEPTED"
        assert rejection.code == case.expect, f"{rejection.code} != {case.expect}"


@pytest.mark.parametrize("case", _REJECT_CASES, ids=lambda c: c.id)
def test_h11_standalone_verdict_matches_record(case: Case) -> None:
    """Pin the recorded standalone-h11 verdict for every rejection fixture."""
    assert h11_alone_accepts(case.wire) is case.h11_accepts


@pytest.mark.parametrize("case", _H11_STRICTER_THAN_POLICY, ids=lambda c: c.id)
def test_prevalidator_rejects_first_where_h11_is_more_permissive(case: Case) -> None:
    """Ordering proof: h11 alone accepts the bytes; the prevalidator rejects."""
    assert h11_alone_accepts(case.wire), "h11 must accept this fixture standalone"
    events, rejection = _feed_all(case.wire, _policy(case.policy))
    assert rejection is not None and rejection.code == case.expect


def test_h11_more_permissive_class_has_real_coverage() -> None:
    """The 'h11 accepts, policy rejects' class must be a large share of the corpus."""
    assert len(_H11_STRICTER_THAN_POLICY) >= 20


@pytest.mark.parametrize("chunk_size", [1, 7])
@pytest.mark.parametrize("case", _DRIP_CASES, ids=lambda c: c.id)
def test_byte_drip_equivalence(case: Case, chunk_size: int) -> None:
    """Identical verdict and normalized event stream for chunked delivery."""
    one_events, one_rej = _feed_all(case.wire, _policy(case.policy))
    drip_events, drip_rej = _feed_all(case.wire, _policy(case.policy), chunk_size)
    assert (drip_rej.code if drip_rej else None) == (one_rej.code if one_rej else None)
    assert _normalized(drip_events) == _normalized(one_events)


def test_oversized_single_complete_write_rejected() -> None:
    """Bounds hold on the RAW byte stream: one ~1 MB write cannot bypass them."""
    case = next(c for c in CASES if c.id == "oversized-single-complete-write")
    assert len(case.wire) > 800_000
    _, rejection = _feed_all(case.wire, _policy(case.policy))
    assert rejection is not None
    assert rejection.code == RejectionCode.HEADER_BLOCK_TOO_LARGE


def test_pipelined_requests_across_separate_feeds() -> None:
    parser = StrictHttpParser(_policy("default"))
    first = parser.feed(b"GET /1 HTTP/1.1\r\n" + H + b"\r\n")
    assert first.rejection is None
    second = parser.feed(b"HEAD /2 HTTP/1.1\r\n" + H + b"\r\n")
    assert second.rejection is None
    heads = [e for e in second.events if isinstance(e, RequestHead)]
    assert [h.request_index for h in heads] == [1]


def test_rejection_is_terminal_and_typed() -> None:
    parser = StrictHttpParser(_policy("default"))
    result = parser.feed(b"TRACE / HTTP/1.1\r\n" + H + b"\r\n")
    assert result.rejection is not None
    again = parser.feed(b"GET / HTTP/1.1\r\n" + H + b"\r\n")
    assert again.rejection == result.rejection
    assert again.events == ()


def test_feed_never_raises_across_the_boundary() -> None:
    parser = StrictHttpParser()
    result = parser.feed("GET / HTTP/1.1\r\n")  # wrong type: typed rejection, no raise
    assert result.rejection is not None


def test_policy_refuses_non_buildable_methods() -> None:
    with pytest.raises(ValueError):
        HttpPolicy(allowed_methods=frozenset({"GET", "HEAD", "PUT"}))
    with pytest.raises(ValueError):
        HttpPolicy(allowed_methods=frozenset({"GET", "HEAD", "CONNECT"}))
    with pytest.raises(ValueError):
        HttpPolicy(allowed_methods=frozenset({"GET"}))
    with pytest.raises(ValueError):
        HttpPolicy(max_body_bytes=0)


def test_accepted_head_exposes_host_for_slice6() -> None:
    events, rejection = _feed_all(
        b"GET http://example.test:443/p HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
        _policy("default"),
    )
    assert rejection is None
    head = next(e for e in events if isinstance(e, RequestHead))
    assert head.host == b"example.test:443"
    assert head.target == b"http://example.test:443/p"
