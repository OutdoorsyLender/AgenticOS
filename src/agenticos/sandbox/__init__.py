"""AgenticOS sandbox conformance and Linux isolation backends.

The portable pieces provide a synthetic hostile-worker harness. Linux-only
backends additionally compose measured cgroup, namespace, and Landlock
boundaries and fail closed when their required host capabilities are absent.
"""

from .m4a_runner import NamespaceLandlockRunner

__all__ = ["NamespaceLandlockRunner"]
