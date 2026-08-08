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

__all__ = [
    "BrokerProcessEvidence",
    "BrokerReadyEvidence",
    "ListenerEvidence",
    "NamespaceLandlockRunner",
    "TransportMode",
    "TransportPolicy",
    "canonical_policy_bytes",
    "policy_digest",
]
