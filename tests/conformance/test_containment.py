"""Deterministic tests for the containment cancellation state machine and
capability gating, using a scripted fake scope backend.

These tests prove the escalation logic on ANY host. Real systemd/cgroup
integration is covered separately (cgroup_linux marker) and only where the
host genuinely provides it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agenticos.sandbox.containment import (
    CgroupProcessRunner,
    ContainmentState,
    ContainmentUnavailableError,
    CancellationConfig,
    EV_CGROUP_EMPTY_VERIFIED,
    EV_CONTAINMENT_FAILURE,
    EV_FORCED_KILL_REQUESTED,
    EV_SIGNAL_SENT,
    cancel_contained,
    wait_cgroup_empty,
)
from agenticos.sandbox.evidence import EvidenceCollector
from helpers import WORKER_PATH, minimal_env

FAST = CancellationConfig(
    sigint_grace=0.15, sigterm_grace=0.15,
    empty_verify_timeout=0.3, poll_interval=0.01,
)
CG = Path("/fake/cgroup/aos-task-x.scope")


class FakeBackend:
    """Scripted ScopeBackend: returns queued populated() values."""

    def __init__(self, populated_script, kill_ok=True):
        self.signals: list[str] = []
        self.populated_script = list(populated_script)
        self.kill_ok = kill_ok
        self.kill_calls = 0
        self.stops: list[str] = []

    def signal_unit(self, unit: str, sig: str) -> None:
        self.signals.append(sig)

    def cgroup_kill(self, cgroup_path) -> bool:
        self.kill_calls += 1
        return self.kill_ok

    def cgroup_populated(self, cgroup_path):
        if self.populated_script:
            return self.populated_script.pop(0)
        return False

    def unit_active(self, unit: str) -> bool:
        return False

    def stop_unit(self, unit: str) -> None:
        self.stops.append(unit)


class TimedBackend:
    """Time-driven ScopeBackend: populated until ``empty_after`` seconds have
    elapsed — deterministic regardless of poll cadence."""

    def __init__(self, empty_after: float, kill_ok: bool = True):
        import time as _time

        self._time = _time
        self.t0 = _time.monotonic()
        self.empty_after = empty_after
        self.kill_ok = kill_ok
        self.signals: list[str] = []
        self.kill_calls = 0

    def signal_unit(self, unit: str, sig: str) -> None:
        self.signals.append(sig)

    def cgroup_kill(self, cgroup_path) -> bool:
        self.kill_calls += 1
        return self.kill_ok

    def cgroup_populated(self, cgroup_path):
        return self._time.monotonic() - self.t0 < self.empty_after

    def unit_active(self, unit: str) -> bool:
        return False

    def stop_unit(self, unit: str) -> None:
        pass


# --------------------------------------------------------------------------
# wait_cgroup_empty
# --------------------------------------------------------------------------

def test_wait_empty_immediate():
    backend = FakeBackend([False])
    assert wait_cgroup_empty(backend, CG, timeout=0.1, poll_interval=0.01) is True


def test_wait_empty_gone_cgroup_counts_as_empty():
    backend = FakeBackend([None])  # cgroup removed
    assert wait_cgroup_empty(backend, CG, timeout=0.1, poll_interval=0.01) is True


def test_wait_empty_times_out_when_populated():
    backend = FakeBackend([True] * 100)
    assert wait_cgroup_empty(backend, CG, timeout=0.05, poll_interval=0.01) is False


# --------------------------------------------------------------------------
# Escalation state machine
# --------------------------------------------------------------------------

def test_sigint_suffices():
    # empties 0.05s in — during the SIGINT grace window
    backend = TimedBackend(empty_after=0.05)
    state, details = cancel_contained(backend, "aos-task-x.scope", CG, FAST)
    assert state is ContainmentState.TERMINATED
    assert backend.signals == ["SIGINT"]
    assert backend.kill_calls == 0
    assert details["terminated_by"] == "SIGINT"


def test_escalation_to_sigterm():
    # stays populated past the SIGINT grace (0.15s), empties during the
    # SIGTERM grace window
    backend = TimedBackend(empty_after=FAST.sigint_grace + 0.05)
    state, details = cancel_contained(backend, "aos-task-x.scope", CG, FAST)
    assert state is ContainmentState.TERMINATED
    assert backend.signals == ["SIGINT", "SIGTERM"]
    assert backend.kill_calls == 0
    assert details["terminated_by"] == "SIGTERM"


def test_forced_kill_via_cgroup_kill():
    # outlives both signal graces; empties shortly after the forced kill
    backend = TimedBackend(
        empty_after=FAST.sigint_grace + FAST.sigterm_grace + 0.05, kill_ok=True
    )
    state, details = cancel_contained(backend, "aos-task-x.scope", CG, FAST)
    assert state is ContainmentState.TERMINATED
    assert backend.signals == ["SIGINT", "SIGTERM"]
    assert backend.kill_calls == 1
    assert details["terminated_by"] == "cgroup.kill"


def test_forced_kill_fallback_sigkill_when_cgroup_kill_denied():
    backend = TimedBackend(
        empty_after=FAST.sigint_grace + FAST.sigterm_grace + 0.05, kill_ok=False
    )
    state, details = cancel_contained(backend, "aos-task-x.scope", CG, FAST)
    assert state is ContainmentState.TERMINATED
    assert backend.signals == ["SIGINT", "SIGTERM", "SIGKILL"]
    assert "cgroup.kill unavailable" in details["terminated_by"]


def test_failed_when_hierarchy_stays_populated():
    backend = TimedBackend(empty_after=60.0, kill_ok=True)
    state, details = cancel_contained(backend, "aos-task-x.scope", CG, FAST)
    assert state is ContainmentState.FAILED
    assert details["terminated_by"] is None
    assert backend.kill_calls == 1


def test_evidence_events_emitted_in_order():
    collector = EvidenceCollector()
    backend = TimedBackend(
        empty_after=FAST.sigint_grace + FAST.sigterm_grace + 0.05, kill_ok=False
    )
    state, _ = cancel_contained(backend, "aos-task-x.scope", CG, FAST, collector)
    assert state is ContainmentState.TERMINATED
    kinds = [r.kind for r in collector.records]
    assert kinds[0] == ContainmentState.CANCEL_REQUESTED.value
    assert EV_SIGNAL_SENT in kinds
    assert EV_FORCED_KILL_REQUESTED in kinds
    assert kinds[-1] == EV_CGROUP_EMPTY_VERIFIED
    sig_events = [r for r in collector.records if r.kind == EV_SIGNAL_SENT]
    assert [r.payload["signal"] for r in sig_events] == ["SIGINT", "SIGTERM", "SIGKILL"]


def test_failure_event_emitted():
    collector = EvidenceCollector()
    backend = TimedBackend(empty_after=60.0, kill_ok=True)
    state, _ = cancel_contained(backend, "aos-task-x.scope", CG, FAST, collector)
    assert state is ContainmentState.FAILED
    kinds = [r.kind for r in collector.records]
    assert EV_CONTAINMENT_FAILURE in kinds
    assert EV_CGROUP_EMPTY_VERIFIED not in kinds


# --------------------------------------------------------------------------
# Runner capability gating (current host)
# --------------------------------------------------------------------------

def test_runner_gating_on_incapable_host(tmp_path):
    runner = CgroupProcessRunner(worker_path=WORKER_PATH)
    support = runner.check_support()
    if sys.platform.startswith("linux"):
        pytest.skip("gating assertion targets non-Linux hosts")
    assert support.supported is False
    assert support.reasons  # concrete reasons, not silence
    with pytest.raises(ContainmentUnavailableError) as excinfo:
        runner.run([sys.executable, "-c", "pass"], cwd=tmp_path, env=minimal_env())
    assert "unavailable" in str(excinfo.value)


def test_check_support_is_cached():
    runner = CgroupProcessRunner(worker_path=WORKER_PATH)
    first = runner.check_support()
    assert runner.check_support() is first
