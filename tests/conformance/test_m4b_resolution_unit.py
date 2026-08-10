"""Corpus E — bounded DNS resolution and SSRF address policy for M4B-2.

Covers :mod:`agenticos.sandbox.special_addresses` (Slice 7 Part 1: the
frozen IANA special-purpose address policy with embedded-IPv4 extraction
defense) and :mod:`agenticos.sandbox.network_resolution` (Slice 7 Part 2:
the one-shot bounded resolver with fail-closed validation of every
result).

Every case is deterministic: the resolver callable is injected, so no
test touches the network, DNS, or real timers beyond one short injected
deadline for the timeout case.
"""

from __future__ import annotations

import ipaddress
import socket
import threading

import pytest

from agenticos.sandbox.network_resolution import (
    MAX_RESOLUTION_RESULTS,
    RESOLUTION_POLICY_VERSION,
    RESOLVER_DEADLINE_SECONDS,
    ResolutionCode,
    resolve_all_once,
)
from agenticos.sandbox.special_addresses import (
    ADDRESS_POLICY_VERSION,
    AddressDecision,
    extract_embedded_ipv4,
    validate_address,
)

HOSTNAME = "example.com"

# Public addresses that must pass the frozen policy (global unicast).
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V4_B = "8.8.8.8"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
PUBLIC_V6_B = "2001:4860:4860::8888"


# --- transition-form address constructors (verified against
# extract_embedded_ipv4 in TestEmbeddedConstructors) --------------------


def _v6_from_packed(packed: bytes) -> str:
    return str(ipaddress.IPv6Address(packed))


def mapped(v4: str) -> str:
    """IPv4-mapped IPv6 (::ffff:0:0/96) carrying ``v4``."""
    return "::ffff:" + v4


def nat64_wkp(v4: str) -> str:
    """NAT64 well-known prefix (64:ff9b::/96, RFC 6052) carrying ``v4``."""
    packed = bytes.fromhex("0064ff9b") + b"\x00" * 8
    packed += ipaddress.IPv4Address(v4).packed
    return _v6_from_packed(packed)


def nat64_local(v4: str) -> str:
    """NAT64 local-use (64:ff9b:1::/48, RFC 6052 /48) carrying ``v4``."""
    packed = bytearray(bytes.fromhex("0064ff9b0001") + b"\x00" * 10)
    raw = ipaddress.IPv4Address(v4).packed
    packed[6:8] = raw[0:2]
    packed[9:11] = raw[2:4]
    return _v6_from_packed(bytes(packed))


def to4(v4: str) -> str:
    """6to4 (2002::/16, RFC 3056) carrying ``v4``."""
    packed = bytearray(16)
    packed[0:2] = bytes.fromhex("2002")
    packed[2:6] = ipaddress.IPv4Address(v4).packed
    return _v6_from_packed(bytes(packed))


def teredo(v4: str) -> str:
    """Teredo (2001::/32, RFC 4380) carrying obfuscated ``v4``."""
    packed = bytearray(16)
    packed[0:4] = bytes.fromhex("20010000")
    obscured = (
        int.from_bytes(ipaddress.IPv4Address(v4).packed, "big") ^ 0xFFFFFFFF
    )
    packed[12:16] = obscured.to_bytes(4, "big")
    return _v6_from_packed(bytes(packed))


# --- deterministic resolver fixtures ------------------------------------


def a(host: str, port: int = 443):
    """One well-formed AF_INET/SOCK_STREAM/TCP getaddrinfo 5-tuple."""
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (host, port),
    )


def aaaa(host: str, port: int = 443, flowinfo: int = 0, scope_id: int = 0):
    """One well-formed AF_INET6/SOCK_STREAM/TCP getaddrinfo 5-tuple."""
    return (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (host, port, flowinfo, scope_id),
    )


class FixtureResolver:
    """Injectable getaddrinfo replacement recording every invocation."""

    def __init__(self, results=(), error: BaseException | None = None):
        self.results = list(results)
        self.error = error
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return list(self.results)


class HangingResolver:
    """Injectable resolver that never answers (for the deadline test)."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        threading.Event().wait(3600)
        raise AssertionError("unreachable")


# =========================================================================
# Part 1 — frozen IANA special-address policy
# =========================================================================


class TestSpecialAddressPolicy:
    @pytest.mark.parametrize(
        "text",
        [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "169.254.1.1",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "239.255.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "198.19.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.9",
            "192.0.0.10",
            "192.31.196.1",
            "192.52.193.1",
            "192.175.48.1",
            "192.88.99.1",
        ],
    )
    def test_prohibited_ipv4(self, text: str):
        verdict = validate_address(ipaddress.IPv4Address(text))
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.entry is not None
        assert text in verdict.reason
        assert verdict.embedded_ipv4 is None

    @pytest.mark.parametrize(
        "text",
        [
            "::1",
            "::",
            "fe80::1",
            "fe80::ffff:ffff:ffff:ffff",
            "ff00::1",
            "ff02::1",
            "2001:db8::1",
            "2001:db8:ffff::1",
            "3fff::1",
            "100::1",
            "2001:2::1",
            "fc00::1",
            "fd00::1",
            "fdff:ffff:ffff:ffff::1",
            "2001:20::1",
            "2001:10::1",
            "2001:30::1",
            "2001:1::1",
            "2001:3::1",
            "2001:4:112::1",
            "2620:4f:8000::1",
            "5f00::1",
            "100:0:0:1::1",
        ],
    )
    def test_prohibited_ipv6(self, text: str):
        verdict = validate_address(ipaddress.IPv6Address(text))
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.entry is not None
        assert text in verdict.reason

    def test_loopback_v4_category(self):
        verdict = validate_address(ipaddress.IPv4Address("127.0.0.1"))
        assert verdict.entry is not None
        assert verdict.entry.category.value == "loopback"

    def test_private_v4_category(self):
        verdict = validate_address(ipaddress.IPv4Address("10.1.2.3"))
        assert verdict.entry is not None
        assert verdict.entry.category.value == "private"

    def test_cgnat_is_shared_address_space(self):
        verdict = validate_address(ipaddress.IPv4Address("100.64.0.1"))
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.entry is not None
        assert verdict.entry.category.value == "shared_address_space"

    def test_limited_broadcast(self):
        verdict = validate_address(
            ipaddress.IPv4Address("255.255.255.255")
        )
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.entry is not None
        assert verdict.entry.category.value == "broadcast"

    def test_benchmarking_range(self):
        verdict = validate_address(ipaddress.IPv4Address("198.18.0.1"))
        assert verdict.entry is not None
        assert verdict.entry.category.value == "benchmarking"

    def test_reserved_class_e(self):
        verdict = validate_address(ipaddress.IPv4Address("240.0.0.1"))
        assert verdict.entry is not None
        assert verdict.entry.category.value == "reserved"

    @pytest.mark.parametrize("text", [PUBLIC_V4, PUBLIC_V4_B])
    def test_global_ipv4_allowed(self, text: str):
        verdict = validate_address(ipaddress.IPv4Address(text))
        assert verdict.decision is AddressDecision.ALLOWED
        assert verdict.entry is None

    @pytest.mark.parametrize("text", [PUBLIC_V6, PUBLIC_V6_B])
    def test_global_ipv6_allowed(self, text: str):
        verdict = validate_address(ipaddress.IPv6Address(text))
        assert verdict.decision is AddressDecision.ALLOWED
        assert verdict.entry is None

    def test_non_address_input_fails_closed(self):
        verdict = validate_address("8.8.8.8")  # type: ignore[arg-type]
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.entry is None

    def test_none_input_fails_closed(self):
        verdict = validate_address(None)  # type: ignore[arg-type]
        assert verdict.decision is AddressDecision.PROHIBITED


class TestEmbeddedConstructors:
    """The fixture constructors must round-trip through the extractor."""

    @pytest.mark.parametrize(
        "ctor", [mapped, nat64_wkp, nat64_local, to4, teredo]
    )
    @pytest.mark.parametrize(
        "v4", ["127.0.0.1", "8.8.8.8", "10.0.0.1"]
    )
    def test_round_trip(self, ctor, v4: str):
        text = ctor(v4)
        extracted = extract_embedded_ipv4(ipaddress.IPv6Address(text))
        assert str(extracted) == v4


class TestTransitionForms:
    """Transition/embedded forms: prohibited outright, with the embedded
    IPv4 additionally extracted and re-checked as defense-in-depth."""

    def test_mapped_loopback_prohibited(self):
        verdict = validate_address(ipaddress.IPv6Address(mapped("127.0.0.1")))
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "127.0.0.1"
        assert verdict.embedded_decision is AddressDecision.PROHIBITED

    def test_mapped_global_prohibited_regardless_of_embedded(self):
        # Even though the embedded 8.8.8.8 would be allowed as a plain v4,
        # the mapped form itself is prohibited outright.
        verdict = validate_address(ipaddress.IPv6Address(mapped("8.8.8.8")))
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "8.8.8.8"
        assert verdict.embedded_decision is AddressDecision.ALLOWED
        assert verdict.entry is not None
        assert verdict.entry.category.value == "transition_embedded"

    def test_nat64_wkp_loopback(self):
        verdict = validate_address(
            ipaddress.IPv6Address(nat64_wkp("127.0.0.1"))
        )
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "127.0.0.1"
        assert verdict.embedded_decision is AddressDecision.PROHIBITED

    def test_nat64_wkp_global_still_prohibited(self):
        verdict = validate_address(
            ipaddress.IPv6Address(nat64_wkp("8.8.8.8"))
        )
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_decision is AddressDecision.ALLOWED

    def test_nat64_local_use_loopback(self):
        verdict = validate_address(
            ipaddress.IPv6Address(nat64_local("127.0.0.1"))
        )
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "127.0.0.1"
        assert verdict.embedded_decision is AddressDecision.PROHIBITED

    def test_6to4_private_embedded(self):
        verdict = validate_address(ipaddress.IPv6Address(to4("10.0.0.1")))
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "10.0.0.1"
        assert verdict.embedded_decision is AddressDecision.PROHIBITED

    def test_6to4_global_embedded_still_prohibited(self):
        verdict = validate_address(ipaddress.IPv6Address(to4("8.8.8.8")))
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "8.8.8.8"
        assert verdict.embedded_decision is AddressDecision.ALLOWED

    def test_teredo_private_embedded(self):
        verdict = validate_address(
            ipaddress.IPv6Address(teredo("192.168.1.1"))
        )
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "192.168.1.1"
        assert verdict.embedded_decision is AddressDecision.PROHIBITED

    def test_teredo_global_embedded_still_prohibited(self):
        verdict = validate_address(
            ipaddress.IPv6Address(teredo("8.8.8.8"))
        )
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_decision is AddressDecision.ALLOWED

    @pytest.mark.parametrize(
        "ctor", [mapped, nat64_wkp, nat64_local, to4, teredo]
    )
    def test_every_form_carrying_private_v4_prohibited(self, ctor):
        verdict = validate_address(
            ipaddress.IPv6Address(ctor("172.16.5.5"))
        )
        assert verdict.decision is AddressDecision.PROHIBITED
        assert verdict.embedded_ipv4 == "172.16.5.5"
        assert verdict.embedded_decision is AddressDecision.PROHIBITED


class TestPolicyVersion:
    def test_address_policy_version_binds_registry_revisions(self):
        assert ADDRESS_POLICY_VERSION.startswith("AOSADDR/1")
        assert "iana-ipv4-2025-10-09" in ADDRESS_POLICY_VERSION
        assert "iana-ipv6-2025-10-09" in ADDRESS_POLICY_VERSION

    def test_resolution_policy_version_chains_address_version(self):
        assert RESOLUTION_POLICY_VERSION.startswith("AOSRESOLVE/1+")
        assert ADDRESS_POLICY_VERSION in RESOLUTION_POLICY_VERSION

    def test_outcome_carries_policy_version(self):
        resolver = FixtureResolver([a(PUBLIC_V4)])
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.policy_version == RESOLUTION_POLICY_VERSION


# =========================================================================
# Part 2 — bounded resolver
# =========================================================================


class TestResolverCallContract:
    def test_terminal_dot_and_flags_and_parameters(self):
        resolver = FixtureResolver([a(PUBLIC_V4)])
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVED
        assert len(resolver.calls) == 1
        args, kwargs = resolver.calls[0]
        assert args == (
            HOSTNAME + ".",
            443,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
        assert kwargs == {"flags": 0}
        assert outcome.query_name == HOSTNAME + "."

    def test_called_exactly_once_on_success(self):
        resolver = FixtureResolver([a(PUBLIC_V4), aaaa(PUBLIC_V6)])
        resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert len(resolver.calls) == 1

    def test_called_exactly_once_on_error(self):
        resolver = FixtureResolver(
            error=socket.gaierror(socket.EAI_NONAME, "NXDOMAIN")
        )
        resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert len(resolver.calls) == 1

    def test_called_exactly_once_on_timeout(self):
        resolver = HangingResolver()
        outcome = resolve_all_once(
            HOSTNAME, getaddrinfo_fn=resolver, deadline_seconds=0.05
        )
        assert outcome.code is ResolutionCode.RESOLVER_TIMEOUT
        assert resolver.calls == 1

    def test_trailing_dot_input_rejected_before_resolution(self):
        resolver = FixtureResolver([a(PUBLIC_V4)])
        outcome = resolve_all_once(
            HOSTNAME + ".", getaddrinfo_fn=resolver
        )
        assert outcome.code is ResolutionCode.INVALID_HOSTNAME
        assert resolver.calls == []

    def test_empty_hostname_rejected_before_resolution(self):
        resolver = FixtureResolver([a(PUBLIC_V4)])
        outcome = resolve_all_once("", getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.INVALID_HOSTNAME
        assert resolver.calls == []

    def test_default_deadline_is_ten_seconds(self):
        assert RESOLVER_DEADLINE_SECONDS == 10.0


class TestResolverBounds:
    def test_empty_result_denied(self):
        resolver = FixtureResolver([])
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.EMPTY_RESULT
        assert outcome.addresses == ()

    def test_sixty_four_results_allowed(self):
        results = [
            a(f"93.184.{i // 256}.{i % 256}")
            for i in range(MAX_RESOLUTION_RESULTS)
        ]
        resolver = FixtureResolver(results)
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVED
        assert len(outcome.addresses) == MAX_RESOLUTION_RESULTS

    def test_sixty_five_results_denied(self):
        results = [
            a(f"93.184.{i // 256}.{i % 256}")
            for i in range(MAX_RESOLUTION_RESULTS + 1)
        ]
        resolver = FixtureResolver(results)
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.TOO_MANY_RESULTS
        assert outcome.addresses == ()

    def test_duplicates_deduplicated(self):
        resolver = FixtureResolver(
            [a(PUBLIC_V4), a(PUBLIC_V4), aaaa(PUBLIC_V6), aaaa(PUBLIC_V6)]
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVED
        assert [str(r.address) for r in outcome.addresses] == [
            PUBLIC_V4,
            PUBLIC_V6,
        ]

    def test_same_address_v4_v6_forms_not_merged(self):
        # An IPv4 result and an IPv6 result with the same text form cannot
        # collide: dedup keys on (family, address).
        resolver = FixtureResolver([a(PUBLIC_V4), aaaa(PUBLIC_V6)])
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVED
        assert len(outcome.addresses) == 2


class TestResolverErrors:
    def test_nxdomain_denied(self):
        resolver = FixtureResolver(
            error=socket.gaierror(socket.EAI_NONAME, "Name or service")
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVER_ERROR
        assert outcome.addresses == ()
        assert outcome.resolver_error is not None

    def test_temporary_failure_eai_again_denied(self):
        resolver = FixtureResolver(
            error=socket.gaierror(
                socket.EAI_AGAIN, "Temporary failure in name resolution"
            )
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVER_ERROR
        assert str(socket.EAI_AGAIN) in outcome.reason

    def test_timeout_denied_fail_closed(self):
        resolver = HangingResolver()
        outcome = resolve_all_once(
            HOSTNAME, getaddrinfo_fn=resolver, deadline_seconds=0.05
        )
        assert outcome.code is ResolutionCode.RESOLVER_TIMEOUT
        assert outcome.addresses == ()

    def test_non_gaierror_exception_denied(self):
        resolver = FixtureResolver(error=OSError("network unreachable"))
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVER_ERROR

    def test_non_sequence_return_denied(self):
        resolver = FixtureResolver()
        resolver.results = None  # type: ignore[assignment]

        def weird(*args, **kwargs):
            resolver.calls.append((args, kwargs))
            return None

        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=weird)
        assert outcome.code is ResolutionCode.MALFORMED_RESULT


class TestMalformedResults:
    def _deny_code(self, results) -> ResolutionCode:
        resolver = FixtureResolver(results)
        return resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver).code

    def test_wrong_family_af_unix(self):
        entry = (
            # getattr: AF_UNIX is absent on Windows; -1 is an invalid
            # family there, taking the same MALFORMED_RESULT path.
            getattr(socket, "AF_UNIX", -1),
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (PUBLIC_V4, 443),
        )
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_wrong_socktype_datagram(self):
        entry = (
            socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
            "",
            (PUBLIC_V4, 443),
        )
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_wrong_protocol(self):
        entry = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_UDP,
            "",
            (PUBLIC_V4, 443),
        )
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_sockaddr_not_a_tuple(self):
        entry = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            "93.184.216.34:443",
        )
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_sockaddr_wrong_length_v4(self):
        entry = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (PUBLIC_V4, 443, 0),
        )
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_sockaddr_wrong_length_v6(self):
        entry = (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (PUBLIC_V6, 443),
        )
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_entry_not_five_tuple(self):
        entry = (socket.AF_INET, socket.SOCK_STREAM, (PUBLIC_V4, 443))
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_unexpected_port_denied(self):
        assert (
            self._deny_code([a(PUBLIC_V4, port=8443)])
            is ResolutionCode.MALFORMED_RESULT
        )

    def test_unparseable_address_string(self):
        assert (
            self._deny_code([a("not-an-address")])
            is ResolutionCode.MALFORMED_RESULT
        )

    def test_family_address_mismatch(self):
        entry = (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (PUBLIC_V4, 443, 0, 0),
        )
        assert self._deny_code([entry]) is ResolutionCode.MALFORMED_RESULT

    def test_nonzero_scope_id_denied(self):
        assert (
            self._deny_code([aaaa(PUBLIC_V6, scope_id=3)])
            is ResolutionCode.MALFORMED_RESULT
        )

    def test_nonzero_flowinfo_denied(self):
        assert (
            self._deny_code([aaaa(PUBLIC_V6, flowinfo=1)])
            is ResolutionCode.MALFORMED_RESULT
        )

    def test_one_malformed_entry_denies_whole_resolution(self):
        resolver = FixtureResolver(
            [
                a(PUBLIC_V4),
                (
                    # getattr: AF_UNIX is absent on Windows; -1 is an
                    # invalid family there, same MALFORMED_RESULT path.
                    getattr(socket, "AF_UNIX", -1),
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("/tmp/x", 0),
                ),
            ]
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.MALFORMED_RESULT
        assert outcome.addresses == ()


class TestPolicyEnforcement:
    def test_clean_ipv4_resolution_allowed(self):
        resolver = FixtureResolver([a(PUBLIC_V4)])
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVED
        assert len(outcome.addresses) == 1
        resolved = outcome.addresses[0]
        assert str(resolved.address) == PUBLIC_V4
        assert resolved.family == socket.AF_INET
        assert resolved.port == 443
        assert resolved.verdict.decision is AddressDecision.ALLOWED

    def test_clean_dual_stack_resolution_allowed(self):
        resolver = FixtureResolver(
            [a(PUBLIC_V4), a(PUBLIC_V4_B), aaaa(PUBLIC_V6), aaaa(PUBLIC_V6_B)]
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.RESOLVED
        assert [str(r.address) for r in outcome.addresses] == [
            PUBLIC_V4,
            PUBLIC_V4_B,
            PUBLIC_V6,
            PUBLIC_V6_B,
        ]

    def test_one_prohibited_address_denies_entire_resolution(self):
        resolver = FixtureResolver(
            [a(PUBLIC_V4), a("10.0.0.1"), aaaa(PUBLIC_V6)]
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.PROHIBITED_ADDRESS
        # No silent substitution: the allowed addresses are NOT returned.
        assert outcome.addresses == ()
        assert len(outcome.prohibited_verdicts) == 1
        assert outcome.prohibited_verdicts[0].address == "10.0.0.1"

    def test_mapped_result_denies_resolution(self):
        resolver = FixtureResolver(
            [aaaa(mapped("8.8.8.8")), a(PUBLIC_V4)]
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.PROHIBITED_ADDRESS

    def test_nat64_result_denies_resolution(self):
        resolver = FixtureResolver([aaaa(nat64_wkp("127.0.0.1"))])
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.PROHIBITED_ADDRESS
        verdict = outcome.prohibited_verdicts[0]
        assert verdict.embedded_ipv4 == "127.0.0.1"

    def test_loopback_last_result_still_denied(self):
        # Position in the result set does not matter.
        resolver = FixtureResolver(
            [a(PUBLIC_V4), aaaa(PUBLIC_V6), a("127.0.0.1")]
        )
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.PROHIBITED_ADDRESS

    def test_multiple_prohibited_all_reported(self):
        resolver = FixtureResolver([a("127.0.0.1"), a("10.0.0.1")])
        outcome = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert outcome.code is ResolutionCode.PROHIBITED_ADDRESS
        assert len(outcome.prohibited_verdicts) == 2

    def test_no_caching_between_calls(self):
        # Every call re-resolves from scratch: the resolution set is
        # single-use and discardable, so two calls must invoke the
        # resolver twice.
        resolver = FixtureResolver([a(PUBLIC_V4)])
        first = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        second = resolve_all_once(HOSTNAME, getaddrinfo_fn=resolver)
        assert first.code is ResolutionCode.RESOLVED
        assert second.code is ResolutionCode.RESOLVED
        assert len(resolver.calls) == 2
        assert first.addresses is not second.addresses
