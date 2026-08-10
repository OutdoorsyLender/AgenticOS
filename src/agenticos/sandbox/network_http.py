"""Strict raw-byte HTTP/1.1 security envelope for the M4B-2 broker.

This module is the third enforcement stage of the M4B-2 worker-facing path:
the ClientHello gate (:mod:`agenticos.sandbox.network_clienthello`) and the
TLS terminator (:mod:`agenticos.sandbox.network_tls`) establish an
authenticated ``http/1.1``-only channel; this module is the parser that
decides which request bytes may cross the broker boundary.

Architecture: h11 0.16.0 (the gated dependency, see
``docs/phase-zero/dependency-review-m4b2.md``) is used as the structured
HTTP event parser ONLY behind a stricter raw-byte prevalidation layer.  The
prevalidator owns every security decision and rejects ambiguous wire syntax
BEFORE h11 sees it; h11 is never the security envelope.  Only fully
prevalidated bytes are fed to h11, and on every request the prevalidator
cross-checks h11's structural agreement (method, request-target, version,
headers, body byte totals, message completion).  ANY disagreement fails the
connection closed.  The prevalidator is intentionally stricter than h11;
``tests/conformance/test_m4b_http_unit.py`` proves with h11 directly that
every fixture h11 alone would accept is rejected by the prevalidator first.

Documented byte-class policy decisions (stricter than RFC 9110 permits, all
in the safe direction):

* CRLF-only framing: no bare LF anywhere; no CR not followed by LF.
* Header values: visible ASCII (0x20-0x7E) ONLY.  HTAB is REJECTED
  everywhere (after the colon, inside values, as folding whitespace) —
  allowing it only in some positions creates cross-parser ambiguity.
  obs-text (0x80-0xFF) is REJECTED, never passed through or normalized.
  A single optional SP after the colon is consumed; any further leading SP
  or any trailing SP is REJECTED (ambiguous surrounding whitespace).
* obs-fold is REJECTED outright (any head line starting with SP/HTAB).
* Content-Length must be canonical decimal: digits only, no sign, no
  leading zeros except the literal ``0``.  Duplicates are REJECTED even
  when identical.
* Transfer-Encoding must be exactly one header whose value is exactly
  ``chunked`` (BYTE-EXACT — RFC 9110 codings are case-insensitive, but the
  broker admits only the canonical form; h11 normalizes the value, and
  cross-parser casing differences are exactly the ambiguity class this
  envelope exists to remove); TE+CL together
  is REJECTED; any other coding or coding list is REJECTED.
* GET/HEAD never carry a request body: ``Content-Length`` > 0 and ANY
  Transfer-Encoding on GET/HEAD are REJECTED.  A 'GET body' is a CL.0
  request-desync primitive: if the origin does not consume it, those bytes
  become a smuggled next request that bypasses method policy.  A bare
  ``Content-Length: 0`` on GET/HEAD is ACCEPTED — no body bytes follow, so
  the prevalidator and h11 agree on the message boundary and no desync is
  possible.  Bodies remain possible only on POST.
* Request targets starting with ``//`` (network-path references per
  RFC 3986) are REJECTED; origin-form starts with exactly one ``/``.
* Chunk extensions are REJECTED (no ``;`` after the chunk size — "no
  invisible chunk extensions"); the chunk-size line is bare hex (1-8
  digits).  Trailers are FORBIDDEN: any trailer section after the final
  chunk is REJECTED.
* ``Upgrade`` / ``Connection: upgrade`` and ``Expect`` (100-continue
  negotiation) are REJECTED by policy default; WebSocket and nested CONNECT
  are unreachable (CONNECT is outside every method allowlist).
* The ``close`` connection-token is REJECTED (case-insensitive token match,
  including multi-token values such as ``keep-alive, close``): the broker
  controls connection lifetime via grant expiry, so workers must not
  negotiate it.  A bare ``keep-alive`` token stays accepted.
* Leading empty lines before the request line are REJECTED (RFC 9110 says
  a server SHOULD ignore at least one; ambiguity is not tolerated here).

Bounds are enforced on the RAW BYTE STREAM before/while parsing, so a
single oversized complete write cannot bypass any size cap:

* request line <= 8192 bytes; single header/chunk-size line <= 8192
* total head block (request line + header lines, incl. CRLF) <= 16384
* header count <= 100; in-flight unparsed bytes <= 65536
* message body <= policy bound (default 1 MiB), enforced for BOTH
  Content-Length and cumulative chunked framing

Pipelining: requests are processed strictly sequentially.  Bytes after a
complete request head+body are parsed as a NEXT request and fully
revalidated from the request line up; :class:`RequestComplete` events are
the hook where Slice 6 attaches per-request re-authorization.  No parser
state carries across requests except the byte stream itself.

Fail-closed contract: wire-facing entry points never raise.  ``feed``
returns a typed :class:`FeedResult`; once a :class:`Rejection` is terminal
the parser stays rejected and every later ``feed`` returns the same typed
outcome.  Rejecting input h11 might have accepted costs compatibility only;
the parser must never ACCEPT bytes whose framing is ambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import h11

# -- bounds (raw byte stream, enforced before parsing) ---------------------

MAX_REQUEST_LINE_BYTES = 8192
MAX_HEADER_LINE_BYTES = 8192        # also bounds the chunk-size line
MAX_HEADER_BLOCK_BYTES = 16384      # request line + header lines, incl. CRLF
MAX_HEADER_COUNT = 100
MAX_IN_FLIGHT_BYTES = 65536         # unparsed buffered residual bound
DEFAULT_MAX_BODY_BYTES = 1 << 20    # 1 MiB default message-body bound
MAX_CHUNK_SIZE_HEX_DIGITS = 8       # bare hex; 8 digits >> any policy bound

# RFC 9110 tchar (header names and methods)
_TCHAR = frozenset(
    b"!#$%&'*+-.^_`|~0123456789"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
# Host-authority bytes admitted here; the Slice 6 equality check against the
# approved hostname is a separate, stricter stage.
_HOST_BYTES = frozenset(
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-.:[]"
)

# Methods the policy layer may ever allowlist.  Publication/mutation methods
# (PUT, DELETE, PATCH, ...), CONNECT, TRACE, and OPTIONS are not buildable
# policy — they are denied at construction time, not on the wire.
_POLICY_BUILDABLE_METHODS = frozenset({"GET", "HEAD", "POST"})

_HTTP11 = b"HTTP/1.1"
_ABSOLUTE_SCHEMES = (b"http://", b"https://")


class RejectionCode(str, Enum):
    """Terminal fail-closed verdict of the HTTP security envelope."""

    BARE_LF = "bare_lf"
    CR_NOT_FOLLOWED_BY_LF = "cr_not_followed_by_lf"
    LEADING_EMPTY_LINE = "leading_empty_line"
    REQUEST_LINE_TOO_LONG = "request_line_too_long"
    REQUEST_LINE_MALFORMED = "request_line_malformed"
    METHOD_INVALID = "method_invalid"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    VERSION_REJECTED = "version_rejected"
    TARGET_MALFORMED = "target_malformed"
    TARGET_NETWORK_PATH_REFERENCE = "target_network_path_reference"
    TARGET_ASTERISK_FORM = "target_asterisk_form"
    TARGET_AUTHORITY_FORM = "target_authority_form"
    TARGET_AUTHORITY_MISMATCH = "target_authority_mismatch"
    HEADER_LINE_TOO_LONG = "header_line_too_long"
    HEADER_BLOCK_TOO_LARGE = "header_block_too_large"
    TOO_MANY_HEADERS = "too_many_headers"
    OBS_FOLD_REJECTED = "obs_fold_rejected"
    HEADER_MALFORMED = "header_malformed"
    HEADER_NAME_INVALID = "header_name_invalid"
    HEADER_VALUE_INVALID = "header_value_invalid"
    HOST_MISSING = "host_missing"
    HOST_DUPLICATE = "host_duplicate"
    HOST_MALFORMED = "host_malformed"
    CONTENT_LENGTH_DUPLICATE = "content_length_duplicate"
    CONTENT_LENGTH_INVALID = "content_length_invalid"
    CONTENT_LENGTH_TOO_LARGE = "content_length_too_large"
    TRANSFER_ENCODING_DUPLICATE = "transfer_encoding_duplicate"
    TRANSFER_ENCODING_UNSUPPORTED = "transfer_encoding_unsupported"
    TE_WITH_CONTENT_LENGTH = "te_with_content_length"
    UPGRADE_REJECTED = "upgrade_rejected"
    CONNECTION_CLOSE_REJECTED = "connection_close_rejected"
    EXPECT_REJECTED = "expect_rejected"
    BODILESS_METHOD_WITH_BODY = "bodiless_method_with_body"
    CHUNK_SIZE_INVALID = "chunk_size_invalid"
    CHUNK_EXTENSION_REJECTED = "chunk_extension_rejected"
    BODY_TOO_LARGE = "body_too_large"
    CHUNK_DATA_CRLF_MISSING = "chunk_data_crlf_missing"
    TRAILER_REJECTED = "trailer_rejected"
    IN_FLIGHT_BOUND_EXCEEDED = "in_flight_bound_exceeded"
    H11_PROTOCOL_ERROR = "h11_protocol_error"
    H11_DISAGREEMENT = "h11_disagreement"


class _Reject(Exception):
    """Internal reject signal; converted into a typed fail-closed outcome."""

    __slots__ = ("code", "detail")

    def __init__(self, code: RejectionCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class HttpPolicy:
    """Method-grant and body-bound policy for one authorized connection.

    ``allowed_methods`` is the Slice 5 wiring point for purpose-specific
    method grants: general downloads hold GET/HEAD only; a Git smart-fetch
    purpose adds POST.  Construction refuses anything outside
    {GET, HEAD, POST} so publication/mutation methods are not buildable
    policy.  GET/HEAD are always present.
    """

    allowed_methods: frozenset = frozenset({"GET", "HEAD"})
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    allow_upgrade: bool = False

    def __post_init__(self) -> None:
        methods = frozenset(self.allowed_methods)
        object.__setattr__(self, "allowed_methods", methods)
        bad = methods - _POLICY_BUILDABLE_METHODS
        if bad:
            raise ValueError(f"methods not buildable policy: {sorted(bad)}")
        if not {"GET", "HEAD"} <= methods:
            raise ValueError("GET and HEAD must always be allowed")
        if type(self.max_body_bytes) is not int or not (0 < self.max_body_bytes <= 1 << 30):
            raise ValueError("max_body_bytes must be an int in (0, 1 GiB]")

    @classmethod
    def general_download(cls, **kw) -> "HttpPolicy":
        """General-download grant: GET and HEAD only."""
        return cls(allowed_methods=frozenset({"GET", "HEAD"}), **kw)

    @classmethod
    def git_smart_fetch(cls, **kw) -> "HttpPolicy":
        """Git smart-fetch grant: GET/HEAD plus the required POST."""
        return cls(allowed_methods=frozenset({"GET", "HEAD", "POST"}), **kw)


@dataclass(frozen=True)
class RequestHead:
    """A fully prevalidated request head (the Slice 6 authorization input).

    ``host`` is the parsed, byte-exact Host header value, exposed for the
    Slice 6 Host-authority equality check against the approved hostname.
    Exactly one of ``content_length`` / ``chunked`` describes the body
    framing (both absent means no body).
    """

    request_index: int
    method: str
    target: bytes
    host: bytes
    headers: tuple  # tuple[tuple[bytes, bytes], ...] in wire order
    content_length: "int | None"
    chunked: bool


@dataclass(frozen=True)
class BodyData:
    """One prevalidated body fragment (segmentation is arrival-dependent)."""

    request_index: int
    data: bytes


@dataclass(frozen=True)
class RequestComplete:
    """End of a fully validated request; the Slice 6 re-authorization hook."""

    request_index: int
    body_bytes: int


@dataclass(frozen=True)
class Rejection:
    """Terminal fail-closed verdict."""

    code: RejectionCode
    detail: str
    request_index: int


@dataclass(frozen=True)
class FeedResult:
    """Typed outcome of one ``feed``: validated events plus terminal state."""

    events: tuple = ()
    rejection: "Rejection | None" = None


# parser states
_ST_REQUEST_LINE = "request_line"
_ST_HEADERS = "headers"
_ST_BODY_CL = "body_content_length"
_ST_CHUNK_SIZE = "chunk_size"
_ST_CHUNK_DATA = "chunk_data"
_ST_CHUNK_DATA_CRLF = "chunk_data_crlf"
_ST_FINAL_CRLF = "final_crlf"


class StrictHttpParser:
    """Incremental strict HTTP/1.1 prevalidator + h11 cross-checker.

    Feed connection plaintext in arbitrary chunkings; every rejection fires
    identically for one-write and one-byte-at-a-time delivery (proven by
    the byte-drip equivalence property tests).  h11 receives ONLY
    prevalidated bytes and is cross-checked on every request; any
    divergence fails closed.
    """

    def __init__(self, policy: HttpPolicy | None = None) -> None:
        self._policy = policy if policy is not None else HttpPolicy()
        self._buf = bytearray()
        self._state = _ST_REQUEST_LINE
        self._request_index = 0
        self._events: list = []
        self._rejection: Rejection | None = None
        # per-request parse state
        self._reset_request_state()
        # h11 cross-check machinery (h11 sees prevalidated bytes only)
        self._h11 = h11.Connection(h11.SERVER)
        self._h11_events: list = []
        self._head_pending = bytearray()   # head wire bytes, fed to h11 on accept
        self._wire_out = bytearray()       # validated body wire bytes for h11
        self._checks: list = []            # pending structural cross-checks
        self._completed_wire: list = []    # exact wire bytes per completed request

    @property
    def rejection(self) -> Rejection | None:
        return self._rejection

    @property
    def policy(self) -> HttpPolicy:
        return self._policy

    def pop_completed_wire(self) -> tuple:
        """Exact validated wire bytes of completed requests, in order.

        Slice 9b forwarding boundary: the broker forwards exactly these
        bytes to the origin — the prevalidated request, byte for byte.
        Reading clears the completed set; a rejected or partial request
        leaves no completed wire behind.
        """
        completed = tuple(self._completed_wire)
        self._completed_wire.clear()
        return completed

    def _reset_request_state(self) -> None:
        self._method = ""
        self._method_bytes = b""
        self._target = b""
        self._headers: list = []
        self._host: bytes | None = None
        self._content_length: int | None = None
        self._chunked = False
        self._head_bytes = 0
        self._body_seen = 0
        self._body_remaining = 0
        self._chunk_remaining = 0
        self._request_wire = bytearray()   # exact wire bytes, current request

    # -- public boundary ----------------------------------------------------

    def feed(self, data: bytes) -> FeedResult:
        """Feed raw bytes.  Typed outcome only; never raises across the boundary."""
        if self._rejection is not None:
            return FeedResult((), self._rejection)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            return self._fail(
                RejectionCode.REQUEST_LINE_MALFORMED, "feed requires a bytes-like object"
            )
        self._buf += bytes(data)
        try:
            self._parse_available()
            if len(self._buf) > MAX_IN_FLIGHT_BYTES:
                raise _Reject(
                    RejectionCode.IN_FLIGHT_BOUND_EXCEEDED,
                    f"unparsed residual {len(self._buf)} exceeds {MAX_IN_FLIGHT_BYTES}",
                )
            self._cross_check_h11()
        except _Reject as exc:
            return self._fail(exc.code, exc.detail)
        except Exception as exc:  # fail closed on ANY internal surprise
            return self._fail(RejectionCode.H11_DISAGREEMENT, f"internal: {exc!r}")
        events = tuple(self._events)
        self._events.clear()
        return FeedResult(events, None)

    def _fail(self, code: RejectionCode, detail: str) -> FeedResult:
        self._rejection = Rejection(code, detail, self._request_index)
        events = tuple(self._events)
        self._events.clear()
        return FeedResult(events, self._rejection)

    # -- line layer (CRLF-only framing) --------------------------------------

    def _next_line(self, limit: int, limit_code: RejectionCode, what: str) -> bytes | None:
        """Pop one CRLF-terminated line; None means more bytes are needed.

        Enforces CRLF-only framing: a bare LF rejects, a CR not followed by
        LF rejects, and the length bound applies to the raw bytes whether or
        not the line arrived in a single write.
        """
        buf = self._buf
        nl = buf.find(b"\n")
        if nl == -1:
            cr = buf.find(b"\r")
            if cr != -1 and cr < len(buf) - 1:
                raise _Reject(
                    RejectionCode.CR_NOT_FOLLOWED_BY_LF, f"CR not followed by LF in {what}"
                )
            if len(buf) > limit:
                raise _Reject(limit_code, f"{what} exceeds {limit} bytes")
            return None
        if nl == 0 or buf[nl - 1] != 0x0D:
            raise _Reject(RejectionCode.BARE_LF, f"bare LF in {what}")
        if nl - 1 > limit:
            raise _Reject(limit_code, f"{what} exceeds {limit} bytes")
        line = bytes(buf[: nl - 1])
        if b"\r" in line:
            raise _Reject(
                RejectionCode.CR_NOT_FOLLOWED_BY_LF, f"CR not followed by LF in {what}"
            )
        del self._buf[: nl + 1]
        return line

    # -- parse loop ------------------------------------------------------------

    def _parse_available(self) -> None:
        while True:
            if self._state == _ST_REQUEST_LINE:
                line = self._next_line(
                    MAX_REQUEST_LINE_BYTES, RejectionCode.REQUEST_LINE_TOO_LONG, "request line"
                )
                if line is None:
                    return
                self._parse_request_line(line)
            elif self._state == _ST_HEADERS:
                line = self._next_line(
                    MAX_HEADER_LINE_BYTES, RejectionCode.HEADER_LINE_TOO_LONG, "header line"
                )
                if line is None:
                    return
                if line == b"":
                    self._finish_head()
                else:
                    self._parse_header_line(line)
            elif self._state == _ST_BODY_CL:
                if not self._buf:
                    return
                take = min(len(self._buf), self._body_remaining)
                self._emit_body(bytes(self._buf[:take]))
                del self._buf[:take]
                self._body_remaining -= take
                if self._body_remaining == 0:
                    self._complete_request()
            elif self._state == _ST_CHUNK_SIZE:
                line = self._next_line(
                    MAX_HEADER_LINE_BYTES, RejectionCode.CHUNK_SIZE_INVALID, "chunk-size line"
                )
                if line is None:
                    return
                self._parse_chunk_size(line)
            elif self._state == _ST_CHUNK_DATA:
                if not self._buf:
                    return
                take = min(len(self._buf), self._chunk_remaining)
                self._emit_body(bytes(self._buf[:take]))
                del self._buf[:take]
                self._chunk_remaining -= take
                if self._chunk_remaining == 0:
                    self._state = _ST_CHUNK_DATA_CRLF
            elif self._state == _ST_CHUNK_DATA_CRLF:
                if len(self._buf) < 2:
                    if self._buf and self._buf != b"\r":
                        raise _Reject(
                            RejectionCode.CHUNK_DATA_CRLF_MISSING,
                            "chunk data not followed by CRLF",
                        )
                    return
                if bytes(self._buf[:2]) != b"\r\n":
                    raise _Reject(
                        RejectionCode.CHUNK_DATA_CRLF_MISSING, "chunk data not followed by CRLF"
                    )
                del self._buf[:2]
                self._wire_out += b"\r\n"
                self._request_wire += b"\r\n"
                self._state = _ST_CHUNK_SIZE
            elif self._state == _ST_FINAL_CRLF:
                line = self._next_line(
                    MAX_HEADER_LINE_BYTES, RejectionCode.TRAILER_REJECTED, "trailer section"
                )
                if line is None:
                    return
                if line != b"":
                    raise _Reject(
                        RejectionCode.TRAILER_REJECTED, "trailers are forbidden by policy"
                    )
                self._wire_out += b"\r\n"
                self._request_wire += b"\r\n"
                self._complete_request()
            else:  # unreachable; fail closed
                raise _Reject(RejectionCode.H11_DISAGREEMENT, f"bad state {self._state}")

    # -- request head ----------------------------------------------------------

    def _parse_request_line(self, line: bytes) -> None:
        if line == b"":
            raise _Reject(
                RejectionCode.LEADING_EMPTY_LINE, "empty line before the request line"
            )
        parts = line.split(b" ")
        if len(parts) != 3 or any(p == b"" for p in parts):
            raise _Reject(
                RejectionCode.REQUEST_LINE_MALFORMED,
                "request line must be exactly 'METHOD SP target SP version'",
            )
        method, target, version = parts
        if not method or any(b not in _TCHAR for b in method):
            raise _Reject(RejectionCode.METHOD_INVALID, "method is not an RFC 9110 token")
        if version != _HTTP11:
            raise _Reject(
                RejectionCode.VERSION_REJECTED, f"version {version!r} is not HTTP/1.1"
            )
        if not target or any(b < 0x21 or b > 0x7E for b in target):
            raise _Reject(RejectionCode.TARGET_MALFORMED, "target has disallowed bytes")
        if target == b"*":
            raise _Reject(RejectionCode.TARGET_ASTERISK_FORM, "asterisk-form is rejected")
        text = method.decode("ascii")
        if text not in self._policy.allowed_methods:
            raise _Reject(
                RejectionCode.METHOD_NOT_ALLOWED, f"method {text!r} denied by policy"
            )
        self._method = text
        self._method_bytes = method
        self._target = target
        self._head_bytes = len(line) + 2
        self._head_pending += line + b"\r\n"
        self._state = _ST_HEADERS

    def _parse_header_line(self, line: bytes) -> None:
        self._head_bytes += len(line) + 2
        if self._head_bytes > MAX_HEADER_BLOCK_BYTES:
            raise _Reject(
                RejectionCode.HEADER_BLOCK_TOO_LARGE,
                f"head block exceeds {MAX_HEADER_BLOCK_BYTES} bytes",
            )
        if len(self._headers) >= MAX_HEADER_COUNT:
            raise _Reject(
                RejectionCode.TOO_MANY_HEADERS, f"more than {MAX_HEADER_COUNT} headers"
            )
        if line[0] in (0x20, 0x09):
            raise _Reject(RejectionCode.OBS_FOLD_REJECTED, "obs-fold is rejected")
        colon = line.find(b":")
        if colon == -1:
            raise _Reject(RejectionCode.HEADER_MALFORMED, "header line has no colon")
        name = line[:colon]
        if not name or any(b not in _TCHAR for b in name):
            raise _Reject(
                RejectionCode.HEADER_NAME_INVALID, "header name is not an RFC 9110 token"
            )
        rest = line[colon + 1 :]
        if rest.startswith(b" "):
            rest = rest[1:]
        if (
            any(b < 0x20 or b > 0x7E for b in rest)
            or rest.startswith(b" ")
            or rest.endswith(b" ")
        ):
            raise _Reject(
                RejectionCode.HEADER_VALUE_INVALID,
                "header value must be visible ASCII without ambiguous whitespace",
            )
        lname = name.lower()
        if lname == b"host":
            if self._host is not None:
                raise _Reject(RejectionCode.HOST_DUPLICATE, "duplicate Host header")
            if not rest or any(b not in _HOST_BYTES for b in rest):
                raise _Reject(RejectionCode.HOST_MALFORMED, "malformed Host authority")
            self._host = rest
        elif lname == b"content-length":
            if self._content_length is not None:
                raise _Reject(
                    RejectionCode.CONTENT_LENGTH_DUPLICATE,
                    "duplicate Content-Length (even identical) is rejected",
                )
            if (
                not rest
                or any(b < 0x30 or b > 0x39 for b in rest)
                or (len(rest) > 1 and rest.startswith(b"0"))
            ):
                raise _Reject(
                    RejectionCode.CONTENT_LENGTH_INVALID,
                    "Content-Length must be canonical decimal",
                )
            value = int(rest)
            if value > self._policy.max_body_bytes:
                raise _Reject(
                    RejectionCode.CONTENT_LENGTH_TOO_LARGE,
                    f"Content-Length {value} exceeds the policy body bound",
                )
            self._content_length = value
        elif lname == b"transfer-encoding":
            if self._chunked or any(h[0].lower() == b"transfer-encoding" for h in self._headers):
                raise _Reject(
                    RejectionCode.TRANSFER_ENCODING_DUPLICATE,
                    "multiple Transfer-Encoding headers are rejected",
                )
            if rest != b"chunked":
                raise _Reject(
                    RejectionCode.TRANSFER_ENCODING_UNSUPPORTED,
                    "only exactly 'chunked' is supported on requests",
                )
            self._chunked = True
        elif lname == b"upgrade" and not self._policy.allow_upgrade:
            raise _Reject(RejectionCode.UPGRADE_REJECTED, "Upgrade is denied by policy")
        elif lname == b"connection":
            # The 'close' token lets the worker negotiate connection lifetime,
            # which the broker owns via grant expiry; forwarding it also
            # strands h11 in MUST_CLOSE and surfaces only later as a
            # misleading disagreement.  Tokens are matched case-insensitively
            # because h11 parses connection tokens case-insensitively.
            tokens = [t.strip(b" ") for t in rest.lower().split(b",")]
            if b"close" in tokens:
                raise _Reject(
                    RejectionCode.CONNECTION_CLOSE_REJECTED,
                    "the 'close' connection-token is denied: "
                    "the broker controls connection lifetime",
                )
            if b"upgrade" in rest.lower() and not self._policy.allow_upgrade:
                raise _Reject(
                    RejectionCode.UPGRADE_REJECTED, "Connection: upgrade is denied by policy"
                )
        elif lname == b"expect":
            raise _Reject(
                RejectionCode.EXPECT_REJECTED, "100-continue negotiation is not supported"
            )
        self._headers.append((name, rest))
        self._head_pending += line + b"\r\n"

    def _finish_head(self) -> None:
        if self._host is None:
            raise _Reject(RejectionCode.HOST_MISSING, "exactly one Host header is required")
        if self._chunked and self._content_length is not None:
            raise _Reject(
                RejectionCode.TE_WITH_CONTENT_LENGTH,
                "Transfer-Encoding with Content-Length is rejected",
            )
        # GET/HEAD never carry a body: a 'GET body' is a CL.0 desync
        # primitive — if the origin does not consume it, those bytes become a
        # smuggled next request that bypasses method policy.  A bare
        # Content-Length: 0 stays accepted: no body bytes follow, so the
        # prevalidator and h11 agree on the message boundary.
        if self._method in ("GET", "HEAD") and (
            self._chunked or (self._content_length is not None and self._content_length > 0)
        ):
            raise _Reject(
                RejectionCode.BODILESS_METHOD_WITH_BODY,
                f"{self._method} must not carry a request body",
            )
        self._validate_target_form()
        self._head_pending += b"\r\n"
        head = RequestHead(
            request_index=self._request_index,
            method=self._method,
            target=self._target,
            host=self._host,
            headers=tuple(self._headers),
            content_length=self._content_length,
            chunked=self._chunked,
        )
        self._events.append(head)
        self._wire_out += self._head_pending
        self._request_wire += self._head_pending
        self._head_pending = bytearray()
        self._checks.append(("head", head))
        if self._chunked:
            self._state = _ST_CHUNK_SIZE
        elif self._content_length:
            self._body_remaining = self._content_length
            self._state = _ST_BODY_CL
        else:
            self._complete_request()

    def _validate_target_form(self) -> None:
        target = self._target
        # A target starting with '//' is a network-path reference (RFC 3986
        # section 4.2), NOT origin-form: '//evil.example/path' would re-aim
        # the request at an attacker-chosen authority downstream.
        if target.startswith(b"//"):
            raise _Reject(
                RejectionCode.TARGET_NETWORK_PATH_REFERENCE,
                "network-path reference targets ('//authority/...') are rejected",
            )
        if target.startswith(b"/"):
            return  # origin-form
        for scheme in _ABSOLUTE_SCHEMES:
            if target.startswith(scheme):
                rest = target[len(scheme) :]
                slash = rest.find(b"/")
                authority = rest if slash == -1 else rest[:slash]
                if not authority:
                    raise _Reject(
                        RejectionCode.TARGET_MALFORMED, "absolute-form with empty authority"
                    )
                if authority.lower() != self._host.lower():
                    raise _Reject(
                        RejectionCode.TARGET_AUTHORITY_MISMATCH,
                        "absolute-form authority differs from the Host header",
                    )
                return
        raise _Reject(
            RejectionCode.TARGET_AUTHORITY_FORM, "authority-form targets are rejected"
        )

    # -- body ------------------------------------------------------------------

    def _parse_chunk_size(self, line: bytes) -> None:
        if b";" in line:
            raise _Reject(
                RejectionCode.CHUNK_EXTENSION_REJECTED, "chunk extensions are rejected"
            )
        if (
            not line
            or len(line) > MAX_CHUNK_SIZE_HEX_DIGITS
            or any(b not in b"0123456789abcdefABCDEF" for b in line)
        ):
            raise _Reject(
                RejectionCode.CHUNK_SIZE_INVALID, "chunk-size line must be bare hex"
            )
        size = int(line, 16)
        if size > self._policy.max_body_bytes - self._body_seen:
            raise _Reject(
                RejectionCode.BODY_TOO_LARGE, "chunked body exceeds the policy body bound"
            )
        self._wire_out += line + b"\r\n"
        self._request_wire += line + b"\r\n"
        if size == 0:
            self._state = _ST_FINAL_CRLF
        else:
            self._chunk_remaining = size
            self._state = _ST_CHUNK_DATA

    def _emit_body(self, data: bytes) -> None:
        self._body_seen += len(data)
        self._wire_out += data
        self._request_wire += data
        self._events.append(BodyData(self._request_index, data))

    def _complete_request(self) -> None:
        self._events.append(RequestComplete(self._request_index, self._body_seen))
        self._checks.append(("complete", self._request_index, self._body_seen))
        self._completed_wire.append(bytes(self._request_wire))
        self._request_index += 1
        self._reset_request_state()
        self._state = _ST_REQUEST_LINE

    # -- h11 cross-check (h11 sees prevalidated bytes only) --------------------

    def _cross_check_h11(self) -> None:
        if self._wire_out:
            wire = bytes(self._wire_out)
            self._wire_out = bytearray()
            try:
                self._h11.receive_data(wire)
            except h11.LocalProtocolError as exc:
                raise _Reject(
                    RejectionCode.H11_PROTOCOL_ERROR, f"h11 rejected prevalidated bytes: {exc}"
                )
        checks, self._checks = self._checks, []
        for check in checks:
            # Drain per check: h11 PAUSEs after EndOfMessage until the
            # server-side state advances (see _check_complete), so a
            # pipelined next request only becomes visible after the
            # previous request's completion check has run.
            self._drain_h11_events()
            if check[0] == "head":
                self._check_head(check[1])
            else:
                self._check_complete(check[2])

    def _drain_h11_events(self) -> None:
        try:
            while True:
                ev = self._h11.next_event()
                if ev is h11.NEED_DATA or ev is h11.PAUSED:
                    return
                self._h11_events.append(ev)
        except h11.LocalProtocolError as exc:
            raise _Reject(
                RejectionCode.H11_PROTOCOL_ERROR, f"h11 rejected prevalidated bytes: {exc}"
            )

    def _h11_pop(self, what: str):
        if not self._h11_events:
            raise _Reject(
                RejectionCode.H11_DISAGREEMENT, f"h11 produced no event for {what}"
            )
        return self._h11_events.pop(0)

    def _check_head(self, head: RequestHead) -> None:
        ev = self._h11_pop("request head")
        if not isinstance(ev, h11.Request):
            raise _Reject(
                RejectionCode.H11_DISAGREEMENT,
                f"h11 emitted {type(ev).__name__} where a Request was expected",
            )
        expected_headers = [(n.lower(), v) for n, v in head.headers]
        if (
            ev.method != head.method.encode("ascii")
            or ev.target != head.target
            or ev.http_version != b"1.1"
            or [tuple(h) for h in ev.headers] != expected_headers
        ):
            raise _Reject(
                RejectionCode.H11_DISAGREEMENT,
                "h11 disagrees with the prevalidator on the request structure",
            )

    def _check_complete(self, body_total: int) -> None:
        seen = 0
        while True:
            ev = self._h11_pop("message completion")
            if isinstance(ev, h11.Data):
                seen += len(ev.data)
                continue
            if isinstance(ev, h11.EndOfMessage):
                break
            raise _Reject(
                RejectionCode.H11_DISAGREEMENT,
                f"h11 emitted {type(ev).__name__} where EndOfMessage was expected",
            )
        if seen != body_total:
            raise _Reject(
                RejectionCode.H11_DISAGREEMENT,
                f"h11 body total {seen} != prevalidator total {body_total}",
            )
        # h11 enforces strict request/response ordering: after EndOfMessage
        # its SERVER state machine PAUSEs until a response is sent and the
        # next keep-alive cycle is started, which would block cross-checking
        # a pipelined next request.  Advance its state with a synthetic
        # internal response; the produced bytes are DISCARDED (nothing here
        # ever touches the wire — the broker owns real responses) and only
        # h11's keep-alive state machine moves.
        try:
            self._h11.send(h11.Response(status_code=200, headers=[], reason=b""))
            self._h11.send(h11.EndOfMessage())
            self._h11.start_next_cycle()
        except h11.LocalProtocolError as exc:
            raise _Reject(
                RejectionCode.H11_DISAGREEMENT,
                f"h11 refused internal state advancement: {exc}",
            )
