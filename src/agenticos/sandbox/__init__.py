"""AgenticOS sandbox conformance and Linux isolation backends.

The portable pieces provide a synthetic hostile-worker harness. Linux-only
backends additionally compose measured cgroup, namespace, and Landlock
boundaries and fail closed when their required host capabilities are absent.
"""

from .m4a_runner import NamespaceLandlockRunner
from .network_models import (
    BrokerProcessEvidence,
    BrokerReadyEvidence,
    ListenerEvidence,
    TransportMode,
    TransportPolicy,
    canonical_policy_bytes,
    policy_digest,
)


def __getattr__(name: str) -> object:
    """Load the Linux-only M4B runner only when callers request it."""

    if name != "CapabilityTransportRunner":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    from .m4b_runner import CapabilityTransportRunner

    globals()[name] = CapabilityTransportRunner
    return CapabilityTransportRunner

__all__ = [
    "BrokerProcessEvidence",
    "BrokerReadyEvidence",
    "CapabilityTransportRunner",
    "ListenerEvidence",
    "NamespaceLandlockRunner",
    "TransportMode",
    "TransportPolicy",
    "canonical_policy_bytes",
    "policy_digest",
]
