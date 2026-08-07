"""Shared pytest fixtures for the Phase Zero conformance tests."""

from __future__ import annotations

import pytest

from agenticos.sandbox.fixtures import FixtureBuilder, synthetic_env


@pytest.fixture
def layout(tmp_path):
    """A fresh synthetic fixture layout per test; cleanup must succeed loudly."""
    builder = FixtureBuilder(root=tmp_path / "fixture-root")
    lay = builder.build()
    yield lay
    lay.cleanup()
    assert not lay.root.exists(), "fixture cleanup failed: root still exists"


@pytest.fixture
def fixture_env(layout):
    """Explicit synthetic environment for worker runs inside the fixture."""
    from helpers import minimal_env

    env = minimal_env()
    env.update(synthetic_env(layout))
    return env
