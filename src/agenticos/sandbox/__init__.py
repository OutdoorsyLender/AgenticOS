"""AgenticOS sandbox conformance and Linux isolation backends.

The portable pieces provide a synthetic hostile-worker harness. Linux-only
backends additionally compose measured cgroup, namespace, and Landlock
boundaries and fail closed when their required host capabilities are absent.
"""

from .host_qualification import (
    HostQualificationError,
    HostQualificationMismatchError,
    canonical_manifest_bytes,
    compute_host_manifest,
    manifest_digest,
    verify_host_manifest,
)
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
from .provider_broker import TaskProviderBroker
from .provider_models import (
    NetworkAuthority,
    ProviderAuthCapability,
    ProviderBrokerEvidence,
    ProviderBrokerIdentity,
    ProviderBrokerPolicy,
    ProviderFailureClass,
    ProviderGrant,
    SecretValue,
    SyntheticBearerAuth,
    canonical_provider_policy_bytes,
    provider_policy_digest,
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
    "HostQualificationError",
    "HostQualificationMismatchError",
    "ListenerEvidence",
    "NamespaceLandlockRunner",
    "NetworkAuthority",
    "ProviderAuthCapability",
    "ProviderBrokerEvidence",
    "ProviderBrokerIdentity",
    "ProviderBrokerPolicy",
    "ProviderFailureClass",
    "ProviderGrant",
    "SecretValue",
    "SyntheticBearerAuth",
    "TaskProviderBroker",
    "TransportMode",
    "TransportPolicy",
    "canonical_manifest_bytes",
    "canonical_policy_bytes",
    "canonical_provider_policy_bytes",
    "compute_host_manifest",
    "manifest_digest",
    "policy_digest",
    "provider_policy_digest",
    "verify_host_manifest",
]
