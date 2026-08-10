"""M4B-2 bounded resolver: one-shot getaddrinfo with fail-closed policy.

This module owns the ONE DNS resolution path for the M4B-2 broker
(design doc "DNS ownership and all-address policy", steps 2-6 and 10).
Resolution is strictly separated from authorization: the caller passes an
ALREADY-AUTHORIZED canonical hostname produced by
:mod:`agenticos.sandbox.network_https`; this module never re-authorizes,
never canonicalizes, and never accepts an IP literal (the Slice 6 grammar
already guarantees both).

Resolution contract — every ``resolve_all_once`` call:

* issues EXACTLY ONE ``getaddrinfo(host + ".", 443, AF_UNSPEC,
  SOCK_STREAM, IPPROTO_TCP, flags=0)`` call.  The terminal dot suppresses
  resolver search-suffix expansion; it is not a second hostname identity
  (the approved identity remains the dotted-quad-less canonical name).
  ``flags=0`` always: NEVER ``AI_ADDRCONFIG`` (would silently suppress
  AAAA results and break the all-address rule), NEVER ``AI_V4MAPPED``
  (would synthesize mapped transition addresses), NEVER ``AI_CANONNAME``
  (the canonical name is already owned by the grant chain).
* is bounded by a 10 s resolver deadline.  CPython cannot cancel a stuck
  blocking ``getaddrinfo`` (no interruption API), so the call runs in a
  daemon worker thread and the deadline is a ``join`` timeout.  On timeout
  the outcome is a fail-closed denial; the orphan thread may linger until
  the stuck call returns or the process exits.  The leak is bounded by
  construction: one thread per denied resolution, its result written to a
  per-call box that is discarded unread, no retry, and resolution
  frequency itself bounded by the active grant's monotonic expiry.
* bounds the result set at 64 entries; 65+ is an amplification/ambiguity
  signal and the entire resolution is denied BEFORE validation.
* denies on: empty result, any ``gaierror`` (NXDOMAIN, temporary failure
  such as EAI_AGAIN, or anything else — DNS errors NEVER fail open),
  unexpected address family, socket type, or protocol, malformed
  sockaddr, wrong port, non-zero flowinfo/scope-id (zone-scoped or
  flow-labeled results are policy ambiguity), host strings carrying an
  IPv6 zone-id (``%`` — the frozen policy never evaluates link scopes),
  unparseable or family-mismatched address strings, and any non-list
  resolver return.
* deduplicates identical (family, address) results deterministically
  (first occurrence wins), then validates EVERY address against the
  frozen IANA special-address policy
  (:mod:`agenticos.sandbox.special_addresses`).  ANY prohibited address
  denies the ENTIRE resolution — no silent substitution of a different
  address, which would let an attacker-controlled DNS response steer the
  broker past the policy.
* returns the validated set for ONE immediate use.  There is NO cache and
  no TTL handling (design doc: "There is no AgenticOS DNS cache in the
  MVP"): the caller discards the outcome after the single connection
  attempt and re-resolves from scratch for every new origin connection.

The resolver callable is injectable (``getaddrinfo_fn``) so conformance
tests are deterministic without any network access.  ``deadline_seconds``
is likewise injectable so the timeout path can be tested fast.

Standard library only.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .special_addresses import (
    ADDRESS_POLICY_VERSION,
    AddressDecision,
    AddressVerdict,
    validate_address,
)

# Evidence-binding version for this resolution stage, chained to the
# frozen address-policy version so an evidence record pins both.
RESOLUTION_POLICY_VERSION = "AOSRESOLVE/1+" + ADDRESS_POLICY_VERSION

RESOLVER_DEADLINE_SECONDS = 10.0
MAX_RESOLUTION_RESULTS = 64
_HTTPS_PORT = 443

GetaddrinfoFn = Callable[..., Any]


class ResolutionCode(str, Enum):
    """Machine-readable outcome class of one bounded resolution."""

    RESOLVED = "resolved"
    INVALID_HOSTNAME = "invalid_hostname"
    RESOLVER_ERROR = "resolver_error"
    RESOLVER_TIMEOUT = "resolver_timeout"
    EMPTY_RESULT = "empty_result"
    TOO_MANY_RESULTS = "too_many_results"
    MALFORMED_RESULT = "malformed_result"
    PROHIBITED_ADDRESS = "prohibited_address"


@dataclass(frozen=True)
class ResolvedAddress:
    """One deduplicated, policy-validated destination address."""

    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    family: int
    port: int
    verdict: AddressVerdict


@dataclass(frozen=True)
class ResolutionOutcome:
    """Typed outcome of :func:`resolve_all_once`; never raises.

    ``addresses`` is non-empty only when ``code`` is
    :attr:`ResolutionCode.RESOLVED`.  The whole object is single-use and
    discardable: nothing here is cached anywhere.
    """

    code: ResolutionCode
    hostname: str
    # The exact name sent to the resolver (canonical name + root dot).
    query_name: str
    addresses: tuple[ResolvedAddress, ...]
    reason: str
    policy_version: str
    resolver_error: str | None = None
    prohibited_verdicts: tuple[AddressVerdict, ...] = ()


def _deny(
    code: ResolutionCode,
    hostname: str,
    query_name: str,
    reason: str,
    *,
    resolver_error: str | None = None,
    prohibited_verdicts: tuple[AddressVerdict, ...] = (),
) -> ResolutionOutcome:
    return ResolutionOutcome(
        code=code,
        hostname=hostname,
        query_name=query_name,
        addresses=(),
        reason=reason,
        policy_version=RESOLUTION_POLICY_VERSION,
        resolver_error=resolver_error,
        prohibited_verdicts=prohibited_verdicts,
    )


def _invoke_resolver(
    getaddrinfo_fn: GetaddrinfoFn,
    query_name: str,
    box: dict[str, Any],
) -> None:
    """Run the one resolver call inside the deadline worker thread.

    The result (or the error) is written into a per-call box so a timed-out
    orphan thread can never touch shared state.
    """
    try:
        box["results"] = getaddrinfo_fn(
            query_name,
            _HTTPS_PORT,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            flags=0,
        )
    except socket.gaierror as exc:
        box["gaierror"] = exc
    except Exception as exc:  # noqa: BLE001 — fail closed, never fail open
        box["error"] = exc


_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _validate_entry(
    entry: Any,
) -> tuple[_Address | None, int, int, str | None]:
    """Validate one raw getaddrinfo 5-tuple.

    Returns ``(address, family, port, None)`` on success or
    ``(None, 0, 0, reason)`` on any malformation.
    """
    if not isinstance(entry, tuple) or len(entry) != 5:
        return None, 0, 0, f"result entry is not a 5-tuple: {entry!r}"
    family, socktype, proto, _canonname, sockaddr = entry
    if family not in (socket.AF_INET, socket.AF_INET6):
        return None, 0, 0, f"unexpected address family: {family!r}"
    if socktype != socket.SOCK_STREAM:
        return None, 0, 0, f"unexpected socket type: {socktype!r}"
    if proto != socket.IPPROTO_TCP:
        return None, 0, 0, f"unexpected protocol: {proto!r}"
    if family == socket.AF_INET:
        if not (isinstance(sockaddr, tuple) and len(sockaddr) == 2):
            return None, 0, 0, f"malformed AF_INET sockaddr: {sockaddr!r}"
        host, port = sockaddr
        extra_ok = True
    else:
        if not (isinstance(sockaddr, tuple) and len(sockaddr) == 4):
            return None, 0, 0, f"malformed AF_INET6 sockaddr: {sockaddr!r}"
        host, port, flowinfo, scope_id = sockaddr
        extra_ok = flowinfo == 0 and scope_id == 0
    if not extra_ok:
        return None, 0, 0, (
            f"non-zero flowinfo/scope-id is policy ambiguity: {sockaddr!r}"
        )
    if not isinstance(host, str) or not isinstance(port, int):
        return None, 0, 0, f"malformed sockaddr fields: {sockaddr!r}"
    if "%" in host:
        # IPv6 zone-ids ("fe80::1%eth0", "%25"-encoded) parse in
        # ipaddress but bind an address to a link/scope the frozen
        # policy never evaluated — policy ambiguity, fail closed.
        return None, 0, 0, f"address string carries a zone-id: {host!r}"
    if port != _HTTPS_PORT:
        return None, 0, 0, (
            f"resolver returned port {port}, expected {_HTTPS_PORT}"
        )
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None, 0, 0, f"unparseable address string: {host!r}"
    if family == socket.AF_INET and not isinstance(
        address, ipaddress.IPv4Address
    ):
        return None, 0, 0, (
            f"AF_INET result carries non-IPv4 address: {host!r}"
        )
    if family == socket.AF_INET6 and not isinstance(
        address, ipaddress.IPv6Address
    ):
        return None, 0, 0, (
            f"AF_INET6 result carries non-IPv6 address: {host!r}"
        )
    return address, family, port, None


def resolve_all_once(
    canonical_hostname: str,
    *,
    getaddrinfo_fn: GetaddrinfoFn = socket.getaddrinfo,
    deadline_seconds: float = RESOLVER_DEADLINE_SECONDS,
) -> ResolutionOutcome:
    """Resolve an ALREADY-AUTHORIZED canonical hostname, fail closed.

    Exactly one bounded ``getaddrinfo`` call; every returned address is
    validated against the frozen special-address policy; any violation
    denies the entire resolution.  Never raises and never fails open.
    """
    if (
        not isinstance(canonical_hostname, str)
        or not canonical_hostname
        or canonical_hostname.endswith(".")
    ):
        return _deny(
            ResolutionCode.INVALID_HOSTNAME,
            repr(canonical_hostname),
            "",
            "input must be a non-empty canonical hostname without a "
            "trailing dot (authorization and the root dot are owned "
            "elsewhere); failing closed",
        )
    if not isinstance(deadline_seconds, (int, float)) or (
        deadline_seconds <= 0
    ):
        return _deny(
            ResolutionCode.INVALID_HOSTNAME,
            canonical_hostname,
            "",
            f"resolver deadline must be positive, got "
            f"{deadline_seconds!r}; failing closed",
        )
    query_name = canonical_hostname + "."

    box: dict[str, Any] = {}
    worker = threading.Thread(
        target=_invoke_resolver,
        args=(getaddrinfo_fn, query_name, box),
        name=f"m4b2-resolve-{canonical_hostname}",
        daemon=True,
    )
    worker.start()
    worker.join(deadline_seconds)
    if worker.is_alive():
        return _deny(
            ResolutionCode.RESOLVER_TIMEOUT,
            canonical_hostname,
            query_name,
            f"resolver did not answer within {deadline_seconds} s; "
            "failing closed (the stuck getaddrinfo cannot be cancelled "
            "in CPython; the orphaned daemon thread's late result is "
            "discarded unread)",
        )
    if "gaierror" in box:
        exc = box["gaierror"]
        return _deny(
            ResolutionCode.RESOLVER_ERROR,
            canonical_hostname,
            query_name,
            f"resolver failed (gaierror errno={exc.errno}): {exc}; "
            "DNS errors never fail open",
            resolver_error=f"gaierror errno={exc.errno}: {exc.strerror}",
        )
    if "error" in box:
        exc = box["error"]
        return _deny(
            ResolutionCode.RESOLVER_ERROR,
            canonical_hostname,
            query_name,
            f"resolver raised {type(exc).__name__}: {exc}; failing closed",
            resolver_error=f"{type(exc).__name__}: {exc}",
        )
    results = box.get("results")
    if not isinstance(results, (list, tuple)):
        return _deny(
            ResolutionCode.MALFORMED_RESULT,
            canonical_hostname,
            query_name,
            f"resolver returned a non-sequence result: "
            f"{type(results).__name__}; failing closed",
        )
    if len(results) == 0:
        return _deny(
            ResolutionCode.EMPTY_RESULT,
            canonical_hostname,
            query_name,
            "resolver returned zero results; failing closed",
        )
    if len(results) > MAX_RESOLUTION_RESULTS:
        return _deny(
            ResolutionCode.TOO_MANY_RESULTS,
            canonical_hostname,
            query_name,
            f"resolver returned {len(results)} results, limit is "
            f"{MAX_RESOLUTION_RESULTS}; failing closed",
        )

    # Structural validation + dedup (first occurrence wins, stable order).
    seen: set[tuple[int, str]] = set()
    parsed: list[tuple[_Address, int, int]] = []
    for entry in results:
        address, family, port, error = _validate_entry(entry)
        if error is not None:
            return _deny(
                ResolutionCode.MALFORMED_RESULT,
                canonical_hostname,
                query_name,
                f"malformed resolver result: {error}; failing closed",
            )
        assert address is not None
        key = (family, str(address))
        if key in seen:
            continue
        seen.add(key)
        parsed.append((address, family, port))

    # Policy validation of EVERY address; any prohibition denies all.
    resolved: list[ResolvedAddress] = []
    prohibited: list[AddressVerdict] = []
    for address, family, port in parsed:
        verdict = validate_address(address)
        if verdict.decision is AddressDecision.ALLOWED:
            resolved.append(
                ResolvedAddress(
                    address=address, family=family, port=port,
                    verdict=verdict,
                )
            )
        else:
            prohibited.append(verdict)
    if prohibited:
        detail = "; ".join(v.reason for v in prohibited)
        return _deny(
            ResolutionCode.PROHIBITED_ADDRESS,
            canonical_hostname,
            query_name,
            f"{len(prohibited)} of {len(parsed)} resolved address(es) "
            f"violates the frozen special-address policy; the ENTIRE "
            f"resolution is denied (no silent substitution): {detail}",
            prohibited_verdicts=tuple(prohibited),
        )
    return ResolutionOutcome(
        code=ResolutionCode.RESOLVED,
        hostname=canonical_hostname,
        query_name=query_name,
        addresses=tuple(resolved),
        reason=(
            f"{len(resolved)} unique address(es) resolved and validated "
            f"against {ADDRESS_POLICY_VERSION}; single-use, uncached"
        ),
        policy_version=RESOLUTION_POLICY_VERSION,
    )
