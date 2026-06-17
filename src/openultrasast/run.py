from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .config import ResolvedConfig, write_resolved_config


@dataclass(frozen=True)
class ScanRun:
    scan_id: str
    root: Path
    target: Path


def create_scan_run(target: Path, config: ResolvedConfig) -> ScanRun:
    resolved_target = target.resolve()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    scan_id = f"{timestamp}-{uuid4().hex[:8]}"
    root = resolved_target / config.runs_dir / scan_id
    root.mkdir(parents=True, exist_ok=False)
    (root / "preprocess").mkdir()
    write_resolved_config(config, root / "resolved_config.json")
    return ScanRun(scan_id=scan_id, root=root, target=resolved_target)
