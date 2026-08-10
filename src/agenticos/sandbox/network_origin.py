"""M4B-2 authenticated origin connection: numeric connect + origin TLS.

This module owns the ONE production path from a validated resolution set to
an established, authenticated origin TLS channel (design doc "DNS ownership
and all-address policy", steps 7-9, and "Worker-side TLS and exact hostname
proof": the broker establishes a SEPARATE origin TLS connection whose SNI
and certificate verification name is the independently approved canonical
hostname, never anything derived from the connection address).

Separation of the two concepts is structural:

* The CONNECTION ADDRESS is numeric only.
  :func:`connect_validated_sockaddr` accepts ONLY the validated
  ``ResolvedAddress`` set produced by
  :mod:`agenticos.sandbox.network_resolution` — there is NO hostname
  parameter anywhere in its signature, so a second resolution between
  validation and connection is impossible to express.  The function never
  calls ``getaddrinfo`` (directly or via helpers such as
  ``socket.create_connection``); the numeric 2-tuple is passed straight to
  ``socket.connect``.  Anything that is not a ``ResolvedAddress`` carrying
  an ``ipaddress`` object — including a hostname-looking string — is a
  typed fail-closed denial, not a repair opportunity.
* The AUTHENTICATION NAME is the approved canonical hostname from the
  grant (:mod:`agenticos.sandbox.network_https`), preserved unchanged and
  used ONLY for TLS SNI and certificate hostname verification.

Address-selection policy across a multi-address validated set (deliberate,
fixed, documented): addresses are tried strictly in RESOLVER ORDER (the
order Slice 7 produced after dedup), one at a time, each with its own
bounded connect timeout (default 10 s, injectable by construction), up to
``max_attempts`` attempts (default 4, injectable).  There is NO Happy
Eyeballs racing, NO reordering by family, and NO retry of a failed
address.  If every permitted attempt fails, the outcome is a fail-closed
CONNECT_FAILED listing every per-attempt error.  There is NEVER a fallback
to hostname resolution: when the validated set is exhausted, the connection
is denied, full stop.

Origin TLS hardening (never weakened for the numeric connection):

* ``verify_mode = CERT_REQUIRED`` and ``check_hostname = True`` — always.
* minimum TLS 1.2 (``minimum_version = TLSv1_2``), re-verified on the
  established channel as defense in depth.
* ``OP_NO_RENEGOTIATION`` set on the context AND verified present in the
  resulting options (mirrors the worker leg): a TLS 1.2 origin cannot
  drive a renegotiation handshake on this channel.
* ALPN offers EXACTLY ``["http/1.1"]``; after the handshake the channel is
  accepted only when ``selected_alpn_protocol() == "http/1.1"``.  An
  origin negotiating h2 or nothing is a fail-closed ALPN_FAILED — HTTP/2
  parsing can never enter this path.
* trust roots come from an explicit, injectable :class:`OriginTrustRoots`:
  ``ca_certs_pem=None`` selects the system default CA store
  (``ssl.create_default_context``); an explicit PEM bundle selects EXACTLY
  those roots.  :func:`build_origin_ssl_context` builds a FRESH
  ``SSLContext`` per origin connection from that source — no context (and
  therefore no CA trust state) is shared, persisted, or switchable across
  policies or connections.  Conformance tests inject the Slice 2 task CA;
  no system-trust mutation is needed or performed.

Every stage returns a typed outcome; bare exceptions never cross the module
boundary (programming errors such as wrong argument TYPES raise TypeError,
mirroring the established slice conventions).

Standard library only.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from enum import Enum

from .network_https import NetworkGrant, canonicalize_hostname
from .network_resolution import (
    RESOLUTION_POLICY_VERSION,
    ResolutionCode,
    ResolutionOutcome,
    ResolvedAddress,
)
from .special_addresses import AddressDecision, AddressVerdict

# Evidence-binding version for this stage, chained to the resolution policy
# version (which itself chains the frozen address-policy version).
ORIGIN_POLICY_VERSION = "AOSORIGIN/1+" + RESOLUTION_POLICY_VERSION

CONNECT_TIMEOUT_SECONDS = 10.0
HANDSHAKE_TIMEOUT_SECONDS = 10.0
# Address-selection bound: at most this many validated addresses are tried,
# in resolver order, before failing closed.
MAX_CONNECT_ATTEMPTS = 4

_ONLY_ALPN = "http/1.1"
_MINIMUM_TLS = ssl.TLSVersion.TLSv1_2
_ACCEPTED_TLS_VERSIONS = frozenset({"TLSv1.2", "TLSv1.3"})


class ConnectCode(str, Enum):
    """Machine-readable outcome class of one numeric connect attempt set."""

    CONNECTED = "connected"
    INVALID_ADDRESS_SET = "invalid_address_set"
    CONNECT_FAILED = "connect_failed"


class OriginTLSCode(str, Enum):
    """Machine-readable outcome class of one origin TLS establishment."""

    ESTABLISHED = "established"
    INVALID_ARGUMENT = "invalid_argument"
    TLS_FAILED = "tls_failed"
    VERIFICATION_FAILED = "verification_failed"
    ALPN_FAILED = "alpn_failed"
    PROTOCOL_FAILED = "protocol_failed"


class OriginHTTPSCode(str, Enum):
    """Machine-readable stage code of the composed origin HTTPS open."""

    ESTABLISHED = "established"
    RESOLUTION_DENIED = "resolution_denied"
    HOSTNAME_MISMATCH = "hostname_mismatch"
    INVALID_ADDRESS_SET = "invalid_address_set"
    CONNECT_FAILED = "connect_failed"
    TLS_FAILED = "tls_failed"
    VERIFICATION_FAILED = "verification_failed"
    ALPN_FAILED = "alpn_failed"
    PROTOCOL_FAILED = "protocol_failed"


_TLS_STAGE_CODES = {
    OriginTLSCode.INVALID_ARGUMENT: OriginHTTPSCode.TLS_FAILED,
    OriginTLSCode.TLS_FAILED: OriginHTTPSCode.TLS_FAILED,
    OriginTLSCode.VERIFICATION_FAILED: OriginHTTPSCode.VERIFICATION_FAILED,
    OriginTLSCode.ALPN_FAILED: OriginHTTPSCode.ALPN_FAILED,
    OriginTLSCode.PROTOCOL_FAILED: OriginHTTPSCode.PROTOCOL_FAILED,
}


@dataclass(frozen=True)
class OriginTrustRoots:
    """The explicit trust-root source for ONE origin TLS connection.

    ``ca_certs_pem=None`` selects the system default CA store (the
    production default).  An explicit ASCII PEM bundle selects EXACTLY
    those roots — this is the conformance-test injection path, so tests
    never touch the system trust store or its environment variables.
    """

    ca_certs_pem: str | None = None

    def __post_init__(self) -> None:
        if self.ca_certs_pem is not None and (
            type(self.ca_certs_pem) is not str
            or not self.ca_certs_pem
            or not self.ca_certs_pem.isascii()
        ):
            raise ValueError(
                "ca_certs_pem must be None or a non-empty ASCII PEM bundle"
            )


def build_origin_ssl_context(
    trust_roots: OriginTrustRoots | None = None,
) -> ssl.SSLContext:
    """Build a FRESH, fully hardened client context for ONE origin connection.

    A new context per call guarantees trust roots can never persist or
    switch across policies: the only roots loaded are the ones named by
    ``trust_roots`` for THIS connection.  Hardening (CERT_REQUIRED,
    check_hostname, TLS>=1.2, ALPN http/1.1 only, OP_NO_RENEGOTIATION) is
    applied unconditionally AFTER root loading, so no injection path can
    weaken it.  OP_NO_RENEGOTIATION mirrors the worker leg
    (:mod:`agenticos.sandbox.network_tls`): the bit is set AND verified
    present in the resulting options, raising (fail-closed via the
    caller) if the interpreter's ssl module cannot guarantee it.
    """
    if trust_roots is None:
        trust_roots = OriginTrustRoots()
    if type(trust_roots) is not OriginTrustRoots:
        raise TypeError("trust_roots must be an OriginTrustRoots")
    if trust_roots.ca_certs_pem is None:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=trust_roots.ca_certs_pem)
    # Hardening is unconditional and comes last: never weakened, never skipped.
    if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
        raise ValueError("ssl.OP_NO_RENEGOTIATION is not exposed")
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = _MINIMUM_TLS
    context.set_alpn_protocols([_ONLY_ALPN])
    context.options |= ssl.OP_NO_RENEGOTIATION
    if not (context.options & ssl.OP_NO_RENEGOTIATION):
        raise ValueError(
            "OP_NO_RENEGOTIATION not present in context options after set"
        )
    return context


@dataclass(frozen=True)
class ConnectOutcome:
    """Typed outcome of :func:`connect_validated_sockaddr`; never raises.

    ``sock`` is the connected plain TCP socket (non-None only when
    ``code`` is CONNECTED); ownership passes to the caller.  ``peer`` is
    the exact ``ResolvedAddress`` the connection landed on.  ``errors``
    records one ``(address, error)`` string pair per attempt made.
    """

    code: ConnectCode
    reason: str
    attempts: int
    sock: socket.socket | None = None
    peer: ResolvedAddress | None = None
    errors: tuple[tuple[str, str], ...] = ()

    @property
    def connected(self) -> bool:
        return self.code is ConnectCode.CONNECTED

    def __post_init__(self) -> None:
        if type(self.code) is not ConnectCode:
            raise ValueError("code must be a ConnectCode")
        if self.connected and (self.sock is None or self.peer is None):
            raise ValueError("a connected outcome must carry sock and peer")
        if not self.connected and (self.sock is not None or self.peer is not None):
            raise ValueError("a failed outcome carries no sock or peer")


def _invalid_address_set(reason: str) -> ConnectOutcome:
    return ConnectOutcome(
        code=ConnectCode.INVALID_ADDRESS_SET,
        reason=reason + "; failing closed without any socket operation",
        attempts=0,
    )


def _validate_address_set(
    addresses: object,
) -> tuple[ResolvedAddress, ...] | ConnectOutcome:
    """Structural type enforcement: ONLY a non-empty ResolvedAddress set.

    This is what makes a hostname-typed input impossible: anything that is
    not a ``ResolvedAddress`` whose ``address`` is an ``ipaddress`` object
    consistent with its ``family`` — including plain strings, (host, port)
    tuples, or bytes — is rejected BEFORE any socket is created.  Every
    entry must also carry an :class:`AddressVerdict` whose decision is
    ALLOWED: a non-ALLOWED verdict (one that somehow survived or bypassed
    Slice 7's deny-the-whole-resolution rule) is a fail-closed rejection,
    never a filter-and-continue.
    """
    if not isinstance(addresses, (tuple, list)):
        return _invalid_address_set(
            f"addresses must be a tuple/list of ResolvedAddress, got "
            f"{type(addresses).__name__}"
        )
    if len(addresses) == 0:
        return _invalid_address_set("the validated address set is empty")
    validated: list[ResolvedAddress] = []
    for item in addresses:
        if type(item) is not ResolvedAddress:
            return _invalid_address_set(
                f"address set entry is {type(item).__name__}, not a "
                "ResolvedAddress (hostnames and raw strings are not "
                "connectable here by construction)"
            )
        if not isinstance(
            item.address, (ipaddress.IPv4Address, ipaddress.IPv6Address)
        ):
            return _invalid_address_set(
                f"ResolvedAddress.address is {type(item.address).__name__}, "
                "not an ipaddress object"
            )
        expected_family = (
            socket.AF_INET
            if isinstance(item.address, ipaddress.IPv4Address)
            else socket.AF_INET6
        )
        if item.family != expected_family:
            return _invalid_address_set(
                f"family {item.family!r} is inconsistent with address "
                f"{item.address} (expected {expected_family})"
            )
        if type(item.port) is not int or not 1 <= item.port <= 65535:
            return _invalid_address_set(
                f"port {item.port!r} is not a valid TCP port"
            )
        if type(item.verdict) is not AddressVerdict:
            return _invalid_address_set(
                f"ResolvedAddress.verdict is "
                f"{type(item.verdict).__name__}, not an AddressVerdict"
            )
        if item.verdict.decision is not AddressDecision.ALLOWED:
            return _invalid_address_set(
                f"ResolvedAddress for {item.address} carries a "
                f"{item.verdict.decision.value!r} verdict, not allowed; a "
                "prohibited address can never enter the connect path"
            )
        validated.append(item)
    return tuple(validated)


def connect_validated_sockaddr(
    addresses: tuple[ResolvedAddress, ...],
    *,
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
    max_attempts: int = MAX_CONNECT_ATTEMPTS,
) -> ConnectOutcome:
    """Connect to ONE numeric sockaddr from the validated resolution set.

    There is deliberately NO hostname parameter: the connection address and
    the authentication name are separate concepts, and this function owns
    only the former.  Selection policy: addresses are tried strictly in
    resolver order, one bounded attempt each, at most ``max_attempts``
    attempts; when all permitted attempts fail the outcome is a fail-closed
    CONNECT_FAILED.  No DNS, no retries of a failed address, no fallback.
    Never raises for connection failures.
    """
    validated = _validate_address_set(addresses)
    if isinstance(validated, ConnectOutcome):
        return validated
    if (
        type(connect_timeout) not in (int, float)
        or isinstance(connect_timeout, bool)
        or not 0 < connect_timeout <= 120
    ):
        return _invalid_address_set(
            f"connect_timeout must be a positive bounded number, got "
            f"{connect_timeout!r}"
        )
    if (
        type(max_attempts) is not int
        or isinstance(max_attempts, bool)
        or not 1 <= max_attempts <= 64
    ):
        return _invalid_address_set(
            f"max_attempts must be an integer in [1, 64], got "
            f"{max_attempts!r}"
        )

    errors: list[tuple[str, str]] = []
    for resolved in validated[:max_attempts]:
        target = str(resolved.address)
        sock: socket.socket | None = None
        try:
            sock = socket.socket(resolved.family, socket.SOCK_STREAM)
            sock.settimeout(connect_timeout)
            # The numeric 2-tuple goes straight to connect(): no name
            # resolution can occur on this path.
            sock.connect((target, resolved.port))
        except OSError as exc:
            errors.append((f"{target}:{resolved.port}", f"{type(exc).__name__}: {exc}"))
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            continue
        return ConnectOutcome(
            code=ConnectCode.CONNECTED,
            reason=(
                f"connected to validated numeric sockaddr "
                f"{target}:{resolved.port} on attempt "
                f"{len(errors) + 1} (resolver order, bounded attempts)"
            ),
            attempts=len(errors) + 1,
            sock=sock,
            peer=resolved,
            errors=tuple(errors),
        )
    detail = "; ".join(f"{target} -> {err}" for target, err in errors)
    return ConnectOutcome(
        code=ConnectCode.CONNECT_FAILED,
        reason=(
            f"all {len(errors)} permitted attempt(s) failed "
            f"(resolver order, bound {max_attempts}); failing closed with "
            f"NO fallback to hostname resolution: {detail}"
        ),
        attempts=len(errors),
        errors=tuple(errors),
    )


class OriginChannel:
    """One established, authenticated origin TLS channel plus its evidence.

    Exposes exactly what evidence needs: the negotiated TLS version, the
    peer certificate identity (the verified approved hostname and the SAN
    set it was proven against), the selected ALPN protocol, and the numeric
    peer address actually connected.  The wrapped ``SSLSocket`` is the
    transport for the strict HTTP/1.1 layer; it keeps the handshake-timeout
    the caller set, and ownership passes to the holder of this channel.
    """

    __slots__ = (
        "tls_socket",
        "tls_version",
        "verified_hostname",
        "peer_cert_san_dns",
        "alpn_protocol",
        "peer_address",
        "peer_port",
    )

    def __init__(
        self,
        *,
        tls_socket: ssl.SSLSocket,
        tls_version: str,
        verified_hostname: str,
        peer_cert_san_dns: tuple[str, ...],
        alpn_protocol: str,
        peer_address: str,
        peer_port: int,
    ) -> None:
        self.tls_socket = tls_socket
        self.tls_version = tls_version
        self.verified_hostname = verified_hostname
        self.peer_cert_san_dns = peer_cert_san_dns
        self.alpn_protocol = alpn_protocol
        self.peer_address = peer_address
        self.peer_port = peer_port

    def close(self) -> None:
        try:
            self.tls_socket.close()
        except OSError:
            pass


@dataclass(frozen=True)
class OriginTLSOutcome:
    """Typed outcome of :func:`open_origin_tls`; never raises."""

    code: OriginTLSCode
    reason: str
    channel: OriginChannel | None = None

    @property
    def established(self) -> bool:
        return self.code is OriginTLSCode.ESTABLISHED

    def __post_init__(self) -> None:
        if type(self.code) is not OriginTLSCode:
            raise ValueError("code must be an OriginTLSCode")
        if self.established and self.channel is None:
            raise ValueError("an established outcome must carry the channel")
        if not self.established and self.channel is not None:
            raise ValueError("a failed outcome carries no channel")


def _tls_deny(
    code: OriginTLSCode, reason: str, sock: socket.socket | None
) -> OriginTLSOutcome:
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
    return OriginTLSOutcome(code=code, reason=reason)


def _peer_san_dns(tls: ssl.SSLSocket) -> tuple[str, ...]:
    peer = tls.getpeercert()
    if not isinstance(peer, dict):
        return ()
    return tuple(
        value
        for kind, value in peer.get("subjectAltName", ())
        if kind == "DNS"
    )


def open_origin_tls(
    sock: socket.socket,
    hostname: str,
    *,
    trust_roots: OriginTrustRoots | None = None,
    handshake_timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
) -> OriginTLSOutcome:
    """Wrap ONE connected numeric socket in authenticated origin TLS.

    ``hostname`` is the preserved, independently approved canonical
    hostname — used for SNI and certificate hostname verification ONLY;
    it is never resolved and never influences the connection address.
    Verification is always on (CERT_REQUIRED, check_hostname, TLS>=1.2,
    ALPN http/1.1 only).  Fail-closed typed outcome on every failure;
    the socket is closed on any denial.  Never raises for TLS failures.
    """
    if not isinstance(sock, socket.socket) or isinstance(sock, ssl.SSLSocket):
        raise TypeError("sock must be a connected plain socket.socket")
    if type(hostname) is not str:
        return _tls_deny(
            OriginTLSCode.INVALID_ARGUMENT,
            f"hostname must be the approved canonical str, got "
            f"{type(hostname).__name__}",
            sock,
        )
    try:
        canonical = canonicalize_hostname(hostname)
    except Exception as exc:  # grammar rejection — fail closed
        return _tls_deny(
            OriginTLSCode.INVALID_ARGUMENT,
            f"hostname rejected by the canonical grammar: {exc}",
            sock,
        )
    if hostname != canonical:
        return _tls_deny(
            OriginTLSCode.INVALID_ARGUMENT,
            "hostname is not in canonical form; the approved name flows "
            "here unchanged from the grant and is never normalized at "
            "this boundary",
            sock,
        )
    if (
        type(handshake_timeout) not in (int, float)
        or isinstance(handshake_timeout, bool)
        or not 0 < handshake_timeout <= 120
    ):
        return _tls_deny(
            OriginTLSCode.INVALID_ARGUMENT,
            f"handshake_timeout must be a positive bounded number, got "
            f"{handshake_timeout!r}",
            sock,
        )

    try:
        context = build_origin_ssl_context(trust_roots)
    except (ssl.SSLError, ValueError, OSError) as exc:
        return _tls_deny(
            OriginTLSCode.TLS_FAILED,
            f"could not build the per-connection origin TLS context from "
            f"the injected trust roots: {exc}; failing closed",
            sock,
        )

    sock.settimeout(handshake_timeout)
    try:
        tls = context.wrap_socket(sock, server_hostname=hostname)
    except ssl.SSLCertVerificationError as exc:
        return _tls_deny(
            OriginTLSCode.VERIFICATION_FAILED,
            f"origin certificate verification failed closed for "
            f"{hostname!r} (verify_mode=CERT_REQUIRED, check_hostname "
            f"on, TLS>=1.2): {exc}",
            sock,
        )
    except (ssl.SSLError, OSError) as exc:
        return _tls_deny(
            OriginTLSCode.TLS_FAILED,
            f"origin TLS handshake failed closed against {hostname!r}: "
            f"{type(exc).__name__}: {exc}",
            sock,
        )

    alpn = tls.selected_alpn_protocol()
    if alpn != _ONLY_ALPN:
        return _tls_deny(
            OriginTLSCode.ALPN_FAILED,
            f"origin selected ALPN {alpn!r}, but exactly {_ONLY_ALPN!r} "
            "is required; failing closed (HTTP/2 or no-ALPN origins can "
            "never enter the HTTP/1.1 path)",
            tls,
        )
    version = tls.version()
    if version not in _ACCEPTED_TLS_VERSIONS:
        return _tls_deny(
            OriginTLSCode.PROTOCOL_FAILED,
            f"origin negotiated {version!r}, below the TLS 1.2 floor; "
            "failing closed",
            tls,
        )
    san_dns = _peer_san_dns(tls)
    if hostname not in san_dns:
        return _tls_deny(
            OriginTLSCode.VERIFICATION_FAILED,
            f"peer certificate SAN set {san_dns!r} does not contain the "
            f"approved hostname {hostname!r} after a verified handshake; "
            "failing closed (defense in depth)",
            tls,
        )
    peer = tls.getpeername()
    if (
        isinstance(peer, tuple)
        and len(peer) >= 2
        and isinstance(peer[1], int)
    ):
        peer_address, peer_port = str(peer[0]), int(peer[1])
    else:
        # A non-INET transport (the conformance fixture's already-connected
        # socketpair) carries no numeric peer; evidence records "unknown"
        # here and the validated declared address set instead.
        peer_address, peer_port = "unknown", 0
    return OriginTLSOutcome(
        code=OriginTLSCode.ESTABLISHED,
        reason=(
            f"origin TLS established: {version}, ALPN {alpn}, verified "
            f"hostname {hostname!r}, peer {peer_address}:{peer_port}"
        ),
        channel=OriginChannel(
            tls_socket=tls,
            tls_version=str(version),
            verified_hostname=hostname,
            peer_cert_san_dns=san_dns,
            alpn_protocol=alpn,
            peer_address=peer_address,
            peer_port=peer_port,
        ),
    )


@dataclass(frozen=True)
class OriginHTTPSOutcome:
    """Typed outcome of :func:`open_origin_https`; never raises.

    ``code`` names the exact failure stage, so CONNECT_FAILED, TLS_FAILED,
    ALPN_FAILED, and VERIFICATION_FAILED are always distinguishable.
    """

    code: OriginHTTPSCode
    reason: str
    policy_version: str = ORIGIN_POLICY_VERSION
    channel: OriginChannel | None = None
    connect_attempts: int = 0
    connect_errors: tuple[tuple[str, str], ...] = ()
    resolution_code: ResolutionCode | None = None

    @property
    def established(self) -> bool:
        return self.code is OriginHTTPSCode.ESTABLISHED

    def __post_init__(self) -> None:
        if type(self.code) is not OriginHTTPSCode:
            raise ValueError("code must be an OriginHTTPSCode")
        if self.established and self.channel is None:
            raise ValueError("an established outcome must carry the channel")
        if not self.established and self.channel is not None:
            raise ValueError("a failed outcome carries no channel")


def open_origin_https(
    resolution: ResolutionOutcome,
    grant: NetworkGrant,
    *,
    trust_roots: OriginTrustRoots | None = None,
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
    handshake_timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
    max_attempts: int = MAX_CONNECT_ATTEMPTS,
) -> OriginHTTPSOutcome:
    """Compose validated numeric set -> numeric connect -> origin TLS.

    ``resolution`` must be a RESOLVED Slice 7 outcome FOR THE GRANT'S
    hostname (byte equality; the resolution of a different name is a
    fail-closed HOSTNAME_MISMATCH).  The connection lands on a numeric
    sockaddr from that set only; authentication uses ``grant.hostname``
    unchanged.  Every failure stage maps to a distinct typed code.
    Never raises for resolution/connect/TLS failures.
    """
    if type(resolution) is not ResolutionOutcome:
        raise TypeError("resolution must be a ResolutionOutcome")
    if type(grant) is not NetworkGrant:
        raise TypeError("grant must be a NetworkGrant")
    if resolution.code is not ResolutionCode.RESOLVED:
        return OriginHTTPSOutcome(
            code=OriginHTTPSCode.RESOLUTION_DENIED,
            reason=(
                f"resolution outcome is {resolution.code.value}, not "
                f"resolved: {resolution.reason}"
            ),
            resolution_code=resolution.code,
        )
    if resolution.hostname != grant.hostname:
        return OriginHTTPSOutcome(
            code=OriginHTTPSCode.HOSTNAME_MISMATCH,
            reason=(
                f"resolution was made for {resolution.hostname!r} but the "
                f"grant approves {grant.hostname!r}; the validated address "
                "set is bound to its resolution name and is never reused "
                "across identities"
            ),
            resolution_code=resolution.code,
        )

    connect = connect_validated_sockaddr(
        resolution.addresses,
        connect_timeout=connect_timeout,
        max_attempts=max_attempts,
    )
    if not connect.connected:
        code = (
            OriginHTTPSCode.INVALID_ADDRESS_SET
            if connect.code is ConnectCode.INVALID_ADDRESS_SET
            else OriginHTTPSCode.CONNECT_FAILED
        )
        return OriginHTTPSOutcome(
            code=code,
            reason=connect.reason,
            connect_attempts=connect.attempts,
            connect_errors=connect.errors,
            resolution_code=resolution.code,
        )
    assert connect.sock is not None
    tls = open_origin_tls(
        connect.sock,
        grant.hostname,
        trust_roots=trust_roots,
        handshake_timeout=handshake_timeout,
    )
    if not tls.established:
        return OriginHTTPSOutcome(
            code=_TLS_STAGE_CODES[tls.code],
            reason=tls.reason,
            connect_attempts=connect.attempts,
            connect_errors=connect.errors,
            resolution_code=resolution.code,
        )
    return OriginHTTPSOutcome(
        code=OriginHTTPSCode.ESTABLISHED,
        reason=tls.reason,
        channel=tls.channel,
        connect_attempts=connect.attempts,
        connect_errors=connect.errors,
        resolution_code=resolution.code,
    )


__all__ = [
    "CONNECT_TIMEOUT_SECONDS",
    "ConnectCode",
    "ConnectOutcome",
    "HANDSHAKE_TIMEOUT_SECONDS",
    "MAX_CONNECT_ATTEMPTS",
    "ORIGIN_POLICY_VERSION",
    "OriginChannel",
    "OriginHTTPSCode",
    "OriginHTTPSOutcome",
    "OriginTLSCode",
    "OriginTLSOutcome",
    "OriginTrustRoots",
    "build_origin_ssl_context",
    "connect_validated_sockaddr",
    "open_origin_https",
    "open_origin_tls",
]
