"""Structured evidence collection for the Phase Zero conformance harness.

Evidence is newline-delimited JSON (JSONL): one :class:`EvidenceRecord` per
line. Records are meant to feed AgenticOS's future audit system, so they are
deliberately conservative about host detail:

- fixture paths are normalized to ``<TEMP_ROOT>/...`` when a root is given
- the harness never records the real process environment
- real usernames, home paths, and host secrets must not be put into payloads

Synthetic canary values MAY appear in evidence — they exist precisely so
leaks are detectable — but real credentials must never be recorded.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .models import (
    TEMP_ROOT_PLACEHOLDER,
    EvidenceRecord,
    new_event_id,
    new_run_id,
    utc_now_iso,
)

EVIDENCE_SCHEMA_VERSION = "0.1.0"


class EvidenceCollector:
    """Collects normalized, structured evidence records for one run."""

    def __init__(
        self,
        run_id: Optional[str] = None,
        normalize_root: str | Path | None = None,
    ) -> None:
        self.run_id = run_id or new_run_id()
        self._root = str(normalize_root) if normalize_root is not None else None
        self.records: list[EvidenceRecord] = []

    def _normalize(self, obj: Any) -> Any:
        if self._root is None:
            return obj
        if isinstance(obj, str):
            return obj.replace(self._root, TEMP_ROOT_PLACEHOLDER)
        if isinstance(obj, dict):
            return {self._normalize(k): self._normalize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._normalize(v) for v in obj]
        return obj

    def record(
        self,
        kind: str,
        payload: dict[str, Any],
        scenario_id: Optional[str] = None,
    ) -> EvidenceRecord:
        rec = EvidenceRecord(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            event_id=new_event_id(),
            run_id=self.run_id,
            scenario_id=scenario_id,
            timestamp=utc_now_iso(),
            kind=kind,
            payload=self._normalize(payload),
        )
        self.records.append(rec)
        return rec

    def to_jsonl(self) -> str:
        return "".join(rec.to_json() + "\n" for rec in self.records)

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_jsonl())
        return p
