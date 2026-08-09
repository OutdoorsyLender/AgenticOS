"""M4B-2 frozen IANA special-purpose address policy (SSRF defense, Part 1).

This module owns the ONE destination-address policy for the M4B-2
broker-side DNS path.  It deliberately does NOT rely on
``ipaddress.IPv4Address.is_global`` / ``is_private``: those properties
implement IETF-forwarding semantics whose per-release revisions have
meaningfully disagreed with the SSRF policy this milestone requires (e.g.
shared/CGNAT space, documentation ranges, and reserved blocks have flipped
classification across CPython versions).  Instead the policy is an
explicit, VERSIONED, frozen table derived directly from the IANA
Special-Purpose Address Registries.

Provenance (deliberate data freeze — this is the only sanctioned network
use in this module's history):

* IPv4 source:
  https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
* IPv6 source:
  https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv
* Registry revision date (both registries, "Last Updated" on the registry
  pages): 2025-10-09
* Fetched (UTC): 2026-08-09
* SHA-256 of fetched IPv4 CSV:
  e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73
* SHA-256 of fetched IPv6 CSV:
  775feea0621dec8735a44fbf30f762e721e8f0a1b3ab7eb341961a88cfce2139
* A prior research snapshot was dated 2025-10-09.  The CURRENT registry
  revision is ALSO 2025-10-09 (unchanged); both facts are recorded here
  and in docs/phase-zero/host-capabilities.md.

Policy rule: PROHIBIT rather than interpret.  Every registry entry whose
IANA "Globally Reachable" column is False, N/A, or blank is prohibited.
Entries marked True were each reviewed deliberately (see
``_TRUE_DECISION_REVIEW`` below); NONE is a clearly global-unicast HTTPS
origin case, so the MVP prohibits them too.  Anything not listed in the
tables is ordinary global unicast and is allowed.  Multicast (224.0.0.0/4,
ff00::/8) is not in the special-purpose registries but is prohibited by
explicit milestone requirement, recorded as supplementary entries.

Transition/embedded forms are prohibited outright: IPv4-mapped
(::ffff:0:0/96), NAT64 (64:ff9b::/96 and 64:ff9b:1::/48), 6to4
(2002::/16), Teredo (2001::/32), and IPv4-compatible (::/96).  As
defense-in-depth, :func:`validate_address` additionally extracts any
embedded IPv4 address these forms could carry and re-checks it against
the IPv4 table; the extraction result is reported in the verdict for
evidence even though the enclosing block is already prohibited.

Lookup semantics: longest-prefix match, mirroring the IANA registry's own
structure (e.g. 192.0.0.9/32 inside 192.0.0.0/24, 2001::/32 inside
2001::/23).

Standard library only.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

ADDRESS_POLICY_VERSION = "AOSADDR/1+iana-ipv4-2025-10-09+iana-ipv6-2025-10-09"

IANA_IPV4_REGISTRY_URL = (
    "https://www.iana.org/assignments/iana-ipv4-special-registry/"
    "iana-ipv4-special-registry-1.csv"
)
IANA_IPV6_REGISTRY_URL = (
    "https://www.iana.org/assignments/iana-ipv6-special-registry/"
    "iana-ipv6-special-registry-1.csv"
)
IANA_IPV4_REGISTRY_REVISION = "2025-10-09"
IANA_IPV6_REGISTRY_REVISION = "2025-10-09"
IANA_REGISTRY_FETCH_DATE = "2026-08-09"
IANA_PRIOR_RESEARCH_SNAPSHOT_DATE = "2025-10-09"
IANA_IPV4_REGISTRY_CSV_SHA256 = (
    "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73"
)
IANA_IPV6_REGISTRY_CSV_SHA256 = (
    "775feea0621dec8735a44fbf30f762e721e8f0a1b3ab7eb341961a88cfce2139"
)


class AddressDecision(str, Enum):
    """Typed verdict of one destination-address policy decision."""

    ALLOWED = "allowed"
    PROHIBITED = "prohibited"


class ProhibitionCategory(str, Enum):
    """Machine-readable reason class for a prohibited address."""

    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link_local"
    UNSPECIFIED = "unspecified"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    DOCUMENTATION = "documentation"
    BENCHMARKING = "benchmarking"
    RESERVED = "reserved"
    SHARED_ADDRESS_SPACE = "shared_address_space"
    PROTOCOL_ASSIGNMENT = "protocol_assignment"
    TRANSITION_EMBEDDED = "transition_embedded"
    INVALID_TYPE = "invalid_type"


@dataclass(frozen=True)
class SpecialAddressEntry:
    """One frozen registry row with its per-entry policy decision."""

    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    name: str
    rfc: str
    # The IANA "Globally Reachable" column value, recorded verbatim
    # ("True", "False", "N/A", "" for blank, or "supplementary" for the
    # milestone-mandated multicast rows that are not in the registries).
    globally_reachable: str
    category: ProhibitionCategory
    decision_reason: str


@dataclass(frozen=True)
class AddressVerdict:
    """Typed outcome of :func:`validate_address`; never a bare exception."""

    decision: AddressDecision
    address: str
    entry: SpecialAddressEntry | None
    reason: str
    # Defense-in-depth extraction trace: the embedded IPv4 recovered from
    # a transition form (mapped/NAT64/6to4/Teredo/compatible), and its own
    # verdict against the IPv4 table.  None for non-transition addresses.
    embedded_ipv4: str | None
    embedded_decision: AddressDecision | None
    embedded_entry: SpecialAddressEntry | None


# --- Deliberate review of every registry entry marked Globally Reachable=True
#
# IPv4:
#   192.0.0.9/32   Port Control Protocol Anycast  — anycast signaling
#                  address, never an HTTPS origin: PROHIBIT.
#   192.0.0.10/32  TURN Anycast — anycast relay discovery, never an HTTPS
#                  origin: PROHIBIT.
#   192.31.196.0/24 AS112-v4 — anycast DNS sinkhole service, not an HTTPS
#                  origin: PROHIBIT.
#   192.52.193.0/24 AMT — anycast multicast relay gateway discovery:
#                  PROHIBIT.
#   192.175.48.0/24 Direct Delegation AS112 — globally routed DNS
#                  sinkhole service, not a general HTTPS origin: PROHIBIT.
# IPv6:
#   64:ff9b::/96   NAT64 Well-Known Prefix — transition/translation form;
#                  the milestone prohibits it outright: PROHIBIT.
#   2001:1::1/128, 2001:1::2/128, 2001:1::3/128 — PCP/TURN/DNS-SD anycast:
#                  PROHIBIT (same reasoning as the v4 anycast entries).
#   2001:3::/32    AMT relay anycast: PROHIBIT.
#   2001:4:112::/48 AS112-v6 anycast: PROHIBIT.
#   2001:20::/28   ORCHIDv2 — cryptographic identifier space, not routable
#                  hosting: PROHIBIT.
#   2001:30::/28   Drone Remote ID DETs — identifier space: PROHIBIT.
#   2620:4f:8000::/48 Direct Delegation AS112-v6: PROHIBIT.
# Teredo (2001::/32, "N/A [2]") and 6to4 (2002::/16, "N/A [3]") are treated
# as blank per the False-or-blank rule AND prohibited outright by the
# milestone as transition/embedded forms.
_TRUE_DECISION_REVIEW = (
    "192.0.0.9/32,192.0.0.10/32,192.31.196.0/24,192.52.193.0/24,"
    "192.175.48.0/24,64:ff9b::/96,2001:1::1/128,2001:1::2/128,"
    "2001:1::3/128,2001:3::/32,2001:4:112::/48,2001:20::/28,"
    "2001:30::/28,2620:4f:8000::/48: all reviewed; none is a clearly "
    "global-unicast HTTPS origin case; all prohibited in this MVP"
)


def _v4(cidr: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(cidr, strict=False)


def _v6(cidr: str) -> ipaddress.IPv6Network:
    return ipaddress.IPv6Network(cidr, strict=False)


def _entry(
    cidr: str,
    name: str,
    rfc: str,
    globally_reachable: str,
    category: ProhibitionCategory,
    reason: str,
) -> SpecialAddressEntry:
    network = _v4(cidr) if "." in cidr else _v6(cidr)
    return SpecialAddressEntry(
        network=network,
        name=name,
        rfc=rfc,
        globally_reachable=globally_reachable,
        category=category,
        decision_reason=reason,
    )


# Frozen IPv4 table — one entry per IANA iana-ipv4-special-registry-1.csv row
# (revision 2025-10-09), plus the milestone-mandated multicast supplement.
IPV4_SPECIAL_TABLE: tuple[SpecialAddressEntry, ...] = (
    _entry("0.0.0.0/8", "This network", "RFC791", "False",
           ProhibitionCategory.UNSPECIFIED, "source-only 'this network'"),
    _entry("0.0.0.0/32", "This host on this network", "RFC1122", "False",
           ProhibitionCategory.UNSPECIFIED, "source-only 'this host'"),
    _entry("10.0.0.0/8", "Private-Use", "RFC1918", "False",
           ProhibitionCategory.PRIVATE, "RFC1918 private"),
    _entry("100.64.0.0/10", "Shared Address Space", "RFC6598", "False",
           ProhibitionCategory.SHARED_ADDRESS_SPACE, "CGNAT shared space"),
    _entry("127.0.0.0/8", "Loopback", "RFC1122", "False",
           ProhibitionCategory.LOOPBACK, "loopback"),
    _entry("169.254.0.0/16", "Link Local", "RFC3927", "False",
           ProhibitionCategory.LINK_LOCAL, "link-local"),
    _entry("172.16.0.0/12", "Private-Use", "RFC1918", "False",
           ProhibitionCategory.PRIVATE, "RFC1918 private"),
    _entry("192.0.0.0/24", "IETF Protocol Assignments", "RFC6890", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "IETF protocol assignments"),
    _entry("192.0.0.0/29", "IPv4 Service Continuity Prefix", "RFC7335", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "service continuity prefix"),
    _entry("192.0.0.8/32", "IPv4 dummy address", "RFC7600", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "dummy address"),
    _entry("192.0.0.9/32", "Port Control Protocol Anycast", "RFC7723", "True",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast signaling, not an HTTPS origin"),
    _entry("192.0.0.10/32", "Traversal Using Relays around NAT Anycast",
           "RFC8155", "True", ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast relay discovery, not an HTTPS origin"),
    _entry("192.0.0.170/32", "NAT64/DNS64 Discovery", "RFC8880", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "NAT64/DNS64 discovery"),
    _entry("192.0.0.171/32", "NAT64/DNS64 Discovery", "RFC8880", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "NAT64/DNS64 discovery"),
    _entry("192.0.2.0/24", "Documentation (TEST-NET-1)", "RFC5737", "False",
           ProhibitionCategory.DOCUMENTATION, "documentation range"),
    _entry("192.31.196.0/24", "AS112-v4", "RFC7535", "True",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast DNS sinkhole, not an HTTPS origin"),
    _entry("192.52.193.0/24", "AMT", "RFC7450", "True",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast multicast relay discovery"),
    _entry("192.88.99.0/24", "Deprecated (6to4 Relay Anycast)", "RFC7526", "",
           ProhibitionCategory.RESERVED,
           "blank Globally Reachable; deprecated 6to4 relay anycast"),
    _entry("192.88.99.2/32", "6a44-relay anycast address", "RFC6751", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "6a44 relay anycast"),
    _entry("192.168.0.0/16", "Private-Use", "RFC1918", "False",
           ProhibitionCategory.PRIVATE, "RFC1918 private"),
    _entry("192.175.48.0/24", "Direct Delegation AS112 Service", "RFC7534",
           "True", ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: globally routed DNS sinkhole, "
           "not a general HTTPS origin"),
    _entry("198.18.0.0/15", "Benchmarking", "RFC2544", "False",
           ProhibitionCategory.BENCHMARKING, "benchmarking"),
    _entry("198.51.100.0/24", "Documentation (TEST-NET-2)", "RFC5737", "False",
           ProhibitionCategory.DOCUMENTATION, "documentation range"),
    _entry("203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC5737", "False",
           ProhibitionCategory.DOCUMENTATION, "documentation range"),
    _entry("240.0.0.0/4", "Reserved", "RFC1112", "False",
           ProhibitionCategory.RESERVED, "reserved (former Class E)"),
    _entry("255.255.255.255/32", "Limited Broadcast", "RFC8190", "False",
           ProhibitionCategory.BROADCAST, "limited broadcast"),
    _entry("224.0.0.0/4", "IPv4 Multicast", "RFC5771", "supplementary",
           ProhibitionCategory.MULTICAST,
           "supplementary milestone-mandated row (not in the special registry)"),
)

# Frozen IPv6 table — one entry per IANA iana-ipv6-special-registry-1.csv row
# (revision 2025-10-09), plus the milestone-mandated multicast supplement and
# the deprecated IPv4-compatible transition form.
IPV6_SPECIAL_TABLE: tuple[SpecialAddressEntry, ...] = (
    _entry("::1/128", "Loopback Address", "RFC4291", "False",
           ProhibitionCategory.LOOPBACK, "loopback"),
    _entry("::/128", "Unspecified Address", "RFC4291", "False",
           ProhibitionCategory.UNSPECIFIED, "unspecified"),
    _entry("::/96", "IPv4-compatible Address (deprecated)", "RFC4291",
           "supplementary", ProhibitionCategory.TRANSITION_EMBEDDED,
           "deprecated IPv4-compatible transition form; prohibited outright"),
    _entry("::ffff:0:0/96", "IPv4-mapped Address", "RFC4291", "False",
           ProhibitionCategory.TRANSITION_EMBEDDED,
           "IPv4-mapped transition form; prohibited outright"),
    _entry("64:ff9b::/96", "IPv4-IPv6 Translat. (NAT64 WKP)", "RFC6052",
           "True", ProhibitionCategory.TRANSITION_EMBEDDED,
           "reviewed True entry: NAT64 well-known prefix; transition form "
           "prohibited outright by milestone"),
    _entry("64:ff9b:1::/48", "IPv4-IPv6 Translat. (NAT64 local-use)",
           "RFC8215", "False", ProhibitionCategory.TRANSITION_EMBEDDED,
           "NAT64 local-use prefix; transition form prohibited outright"),
    _entry("100::/64", "Discard-Only Address Block", "RFC6666", "False",
           ProhibitionCategory.RESERVED, "discard-only"),
    _entry("100:0:0:1::/64", "Dummy IPv6 Prefix", "RFC9780", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "dummy prefix"),
    _entry("2001::/23", "IETF Protocol Assignments", "RFC2928", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "IETF protocol assignments (parent block; longest-prefix match "
           "applies for the specific sub-allocations below)"),
    _entry("2001::/32", "TEREDO", "RFC4380", "N/A",
           ProhibitionCategory.TRANSITION_EMBEDDED,
           "Teredo transition form; prohibited outright by milestone"),
    _entry("2001:1::1/128", "Port Control Protocol Anycast", "RFC7723", "True",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast signaling, not an HTTPS origin"),
    _entry("2001:1::2/128", "Traversal Using Relays around NAT Anycast",
           "RFC8155", "True", ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast relay discovery"),
    _entry("2001:1::3/128", "DNS-SD Service Registration Protocol Anycast",
           "RFC9665", "True", ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast service registration"),
    _entry("2001:2::/48", "Benchmarking", "RFC5180", "False",
           ProhibitionCategory.BENCHMARKING, "benchmarking"),
    _entry("2001:3::/32", "AMT", "RFC7450", "True",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast multicast relay discovery"),
    _entry("2001:4:112::/48", "AS112-v6", "RFC7535", "True",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: anycast DNS sinkhole"),
    _entry("2001:10::/28", "Deprecated (previously ORCHID)", "RFC4843", "",
           ProhibitionCategory.RESERVED,
           "blank Globally Reachable; deprecated ORCHID"),
    _entry("2001:20::/28", "ORCHIDv2", "RFC7343", "True",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: cryptographic identifier space, "
           "not routable hosting"),
    _entry("2001:30::/28", "Drone Remote ID Protocol Entity Tags Prefix",
           "RFC9374", "True", ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: identifier space, not routable hosting"),
    _entry("2001:db8::/32", "Documentation", "RFC3849", "False",
           ProhibitionCategory.DOCUMENTATION, "documentation range"),
    _entry("2002::/16", "6to4", "RFC3056", "N/A",
           ProhibitionCategory.TRANSITION_EMBEDDED,
           "6to4 transition form; prohibited outright by milestone"),
    _entry("2620:4f:8000::/48", "Direct Delegation AS112 Service", "RFC7534",
           "True", ProhibitionCategory.PROTOCOL_ASSIGNMENT,
           "reviewed True entry: globally routed DNS sinkhole"),
    _entry("3fff::/20", "Documentation", "RFC9637", "False",
           ProhibitionCategory.DOCUMENTATION, "documentation range"),
    _entry("5f00::/16", "Segment Routing (SRv6) SIDs", "RFC9602", "False",
           ProhibitionCategory.PROTOCOL_ASSIGNMENT, "SRv6 SID block"),
    _entry("fc00::/7", "Unique-Local", "RFC4193", "False",
           ProhibitionCategory.PRIVATE, "unique-local (ULA)"),
    _entry("fe80::/10", "Link-Local Unicast", "RFC4291", "False",
           ProhibitionCategory.LINK_LOCAL, "link-local"),
    _entry("ff00::/8", "IPv6 Multicast", "RFC4291", "supplementary",
           ProhibitionCategory.MULTICAST,
           "supplementary milestone-mandated row (not in the special registry)"),
)


def _longest_prefix_match(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    table: tuple[SpecialAddressEntry, ...],
) -> SpecialAddressEntry | None:
    best: SpecialAddressEntry | None = None
    for entry in table:
        if address in entry.network and (
            best is None or entry.network.prefixlen > best.network.prefixlen
        ):
            best = entry
    return best


def _rfc6052_extract(packed: bytes, prefix_len: int) -> bytes:
    """Extract the embedded IPv4 octets per RFC 6052 section 2.2.

    ``prefix_len`` is one of 32, 40, 48, 56, 64, 96.  The 'u' octet (byte 8)
    is skipped per the RFC.  Only /96 and /48 are used by this module
    (NAT64 well-known and NAT64 local-use); the general form is implemented
    so the encoding rule is stated once, completely.
    """
    if prefix_len == 96:
        return packed[12:16]
    prefix_octets = prefix_len // 8
    first_octets = (64 - prefix_len) // 8  # v4 octets before the 'u' octet
    return packed[prefix_octets : prefix_octets + first_octets] + packed[
        9 : 9 + (4 - first_octets)
    ]


_NAT64_WKP = _v6("64:ff9b::/96")
_NAT64_LOCAL = _v6("64:ff9b:1::/48")
_6TO4 = _v6("2002::/16")
_TEREDO = _v6("2001::/32")
_V4_COMPAT = _v6("::/96")
_V4_MAPPED = _v6("::ffff:0:0/96")


def extract_embedded_ipv4(
    address: ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Extract the IPv4 address an IPv6 transition form could carry.

    Covers IPv4-mapped (::ffff:0:0/96), NAT64 well-known (64:ff9b::/96),
    NAT64 local-use (64:ff9b:1::/48, RFC 6052 /48 encoding), 6to4
    (2002::/16), Teredo (2001::/32, deobfuscated per RFC 4380), and
    deprecated IPv4-compatible (::/96).  Returns None for addresses in no
    transition form.  Pure extraction — no policy decision is made here.
    """
    if not isinstance(address, ipaddress.IPv6Address):
        raise TypeError("address must be an IPv6Address")
    mapped = address.ipv4_mapped
    if mapped is not None:
        return mapped
    packed = address.packed
    if address in _NAT64_WKP:
        return ipaddress.IPv4Address(_rfc6052_extract(packed, 96))
    if address in _NAT64_LOCAL:
        return ipaddress.IPv4Address(_rfc6052_extract(packed, 48))
    if address in _6TO4:
        return ipaddress.IPv4Address(packed[2:6])
    if address in _TEREDO:
        obfuscated = int.from_bytes(packed[12:16], "big")
        return ipaddress.IPv4Address(obfuscated ^ 0xFFFFFFFF)
    if address in _V4_COMPAT:
        return ipaddress.IPv4Address(packed[12:16])
    return None


def _validate_ipv4(
    address: ipaddress.IPv4Address,
) -> tuple[AddressDecision, SpecialAddressEntry | None, str]:
    entry = _longest_prefix_match(address, IPV4_SPECIAL_TABLE)
    if entry is not None:
        return (
            AddressDecision.PROHIBITED,
            entry,
            f"{address} matches {entry.network} ({entry.name}, {entry.rfc}): "
            f"{entry.decision_reason}",
        )
    return (
        AddressDecision.ALLOWED,
        None,
        f"{address} is not in any frozen IANA special-purpose block",
    )


def validate_address(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> AddressVerdict:
    """Validate one resolved destination address against the frozen policy.

    Returns a typed :class:`AddressVerdict`; never raises across the module
    boundary and never fails open.  IPv6 transition forms are prohibited
    outright; the embedded IPv4 they carry is additionally extracted and
    re-checked against the IPv4 table as defense-in-depth, and the embedded
    trace is recorded in the verdict for evidence.
    """
    if isinstance(ip, ipaddress.IPv4Address):
        decision, entry, reason = _validate_ipv4(ip)
        return AddressVerdict(
            decision=decision,
            address=str(ip),
            entry=entry,
            reason=reason,
            embedded_ipv4=None,
            embedded_decision=None,
            embedded_entry=None,
        )
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = extract_embedded_ipv4(ip)
        embedded_decision: AddressDecision | None = None
        embedded_entry: SpecialAddressEntry | None = None
        embedded_reason = ""
        if embedded is not None:
            embedded_decision, embedded_entry, embedded_reason = _validate_ipv4(
                embedded
            )
        entry = _longest_prefix_match(ip, IPV6_SPECIAL_TABLE)
        if entry is not None:
            reason = (
                f"{ip} matches {entry.network} ({entry.name}, {entry.rfc}): "
                f"{entry.decision_reason}"
            )
            if embedded is not None:
                reason += (
                    f"; embedded IPv4 {embedded} defense-in-depth re-check: "
                    f"{embedded_decision.value} ({embedded_reason})"
                )
            return AddressVerdict(
                decision=AddressDecision.PROHIBITED,
                address=str(ip),
                entry=entry,
                reason=reason,
                embedded_ipv4=str(embedded) if embedded is not None else None,
                embedded_decision=embedded_decision,
                embedded_entry=embedded_entry,
            )
        if embedded is not None and embedded_decision is AddressDecision.PROHIBITED:
            # Unreachable with the current table (every transition form has a
            # covering entry) but kept as the documented fail-closed rule:
            # a prohibited embedded v4 prohibits the whole address.
            return AddressVerdict(
                decision=AddressDecision.PROHIBITED,
                address=str(ip),
                entry=None,
                reason=(
                    f"{ip} carries prohibited embedded IPv4 {embedded}: "
                    f"{embedded_reason}"
                ),
                embedded_ipv4=str(embedded),
                embedded_decision=embedded_decision,
                embedded_entry=embedded_entry,
            )
        return AddressVerdict(
            decision=AddressDecision.ALLOWED,
            address=str(ip),
            entry=None,
            reason=f"{ip} is not in any frozen IANA special-purpose block",
            embedded_ipv4=str(embedded) if embedded is not None else None,
            embedded_decision=embedded_decision,
            embedded_entry=embedded_entry,
        )
    return AddressVerdict(
        decision=AddressDecision.PROHIBITED,
        address=repr(ip),
        entry=None,
        reason=(
            f"destination must be an IPv4Address or IPv6Address, got "
            f"{type(ip).__name__}; failing closed"
        ),
        embedded_ipv4=None,
        embedded_decision=None,
        embedded_entry=None,
    )
