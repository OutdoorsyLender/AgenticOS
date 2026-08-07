"""Synthetic fixture builder for the Phase Zero conformance harness.

Builds a complete fake hostile-test environment under one temporary root:

    <temp-root>/
        assigned-worktree/      # the worker's "allowed" area
            allowed.txt
        sibling-worktree/       # a denied sibling worktree
            secret-canary.txt
        agenticos-private/      # fake AgenticOS private state
            state.sqlite.fake
            evidence-secret.txt
        fake-home/              # fake credential-like files
            .ssh/id_fake
            .config/provider/credentials.fake
        task-tmp/               # private temp directory
        sockets/                # fixture-controlled socket endpoints

Every secret-looking value is a randomized synthetic canary
(``AOS_CANARY_<tag>_<hex>``). Real user secrets are NEVER used as canaries.
Nothing is ever written outside the fixture root.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

from .models import FixtureLayout

CANARY_TAGS = ("permitted", "sibling", "credential", "state", "env")

ENV_SECRET_NAME = "AOS_FAKE_SECRET"
HARMLESS_ENV_NAME = "AOS_HARMLESS"
HARMLESS_ENV_VALUE = "harmless-fixture-value"


def make_canary(tag: str) -> str:
    """A unique, randomized, clearly-fake canary value."""
    return f"AOS_CANARY_{tag}_{secrets.token_hex(8)}"


class FixtureBuilder:
    """Creates and owns one synthetic fixture environment.

    If ``root`` is given the layout is created inside it (the directory is
    created if needed); otherwise a fresh ``tempfile.mkdtemp`` root is used.
    Use :meth:`build` and then :meth:`FixtureLayout.cleanup`, or the builder
    as a context manager.
    """

    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        self._requested_root = Path(root) if root is not None else None
        self.layout: FixtureLayout | None = None

    def build(self) -> FixtureLayout:
        if self._requested_root is not None:
            root = self._requested_root
            root.mkdir(parents=True, exist_ok=True)
        else:
            root = Path(tempfile.mkdtemp(prefix="agenticos-fixture-"))
        root = root.resolve()

        canaries = {tag: make_canary(tag) for tag in CANARY_TAGS}

        assigned = root / "assigned-worktree"
        sibling = root / "sibling-worktree"
        private = root / "agenticos-private"
        fake_home = root / "fake-home"
        task_tmp = root / "task-tmp"
        sockets = root / "sockets"
        for d in (
            assigned,
            sibling,
            private,
            fake_home / ".ssh",
            fake_home / ".config" / "provider",
            task_tmp,
            sockets,
        ):
            d.mkdir(parents=True, exist_ok=True)

        allowed_file = assigned / "allowed.txt"
        allowed_file.write_text(f"permitted worktree file\n{canaries['permitted']}\n")

        denied_sibling = sibling / "secret-canary.txt"
        denied_sibling.write_text(f"denied sibling worktree secret\n{canaries['sibling']}\n")

        state_file = private / "state.sqlite.fake"
        state_file.write_bytes(b"FAKE-SQLITE\n" + canaries["state"].encode() + b"\n")

        evidence_secret = private / "evidence-secret.txt"
        evidence_secret.write_text(f"fake agenticos evidence secret\n{canaries['state']}\n")

        ssh_key = fake_home / ".ssh" / "id_fake"
        ssh_key.write_text(f"-----BEGIN FAKE PRIVATE KEY-----\n{canaries['credential']}\n")

        credentials = fake_home / ".config" / "provider" / "credentials.fake"
        credentials.write_text(f"[fake-provider]\ntoken = {canaries['credential']}\n")

        symlink_supported = self._probe_symlink(root)

        self.layout = FixtureLayout(
            root=root,
            assigned_worktree=assigned,
            sibling_worktree=sibling,
            agenticos_private=private,
            fake_home=fake_home,
            task_tmp=task_tmp,
            sockets_dir=sockets,
            allowed_file=allowed_file,
            denied_sibling_file=denied_sibling,
            evidence_secret_file=evidence_secret,
            fake_state_file=state_file,
            fake_ssh_key=ssh_key,
            fake_credentials_file=credentials,
            env_secret_name=ENV_SECRET_NAME,
            harmless_env_name=HARMLESS_ENV_NAME,
            canaries=canaries,
            symlink_supported=symlink_supported,
        )
        return self.layout

    @staticmethod
    def _probe_symlink(root: Path) -> bool:
        probe_target = root / ".symlink-probe-target"
        probe_link = root / ".symlink-probe-link"
        try:
            probe_target.write_text("probe")
            os.symlink(probe_target, probe_link)
            return True
        except OSError:
            return False
        finally:
            probe_link.unlink(missing_ok=True)
            probe_target.unlink(missing_ok=True)

    def cleanup(self) -> None:
        if self.layout is not None:
            self.layout.cleanup()

    def __enter__(self) -> FixtureLayout:
        return self.build()

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()


def synthetic_env(layout: FixtureLayout, base: dict[str, str] | None = None) -> dict[str, str]:
    """Environment dictionary for a fixture run: explicit, minimal, synthetic.

    Contains the fake secret canary and one harmless value. Callers decide
    what (if anything) else to merge in — the harness never forwards the real
    process environment on its own.
    """
    env = dict(base) if base else {}
    env[layout.env_secret_name] = layout.canaries["env"]
    env[layout.harmless_env_name] = HARMLESS_ENV_VALUE
    return env
