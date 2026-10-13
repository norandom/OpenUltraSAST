"""Run a hunt program over a frozen manifest and write records the benchmark scorer reads.

One record per change, in the shape `benchmarks/valid/hunter_arm.py` writes: the instrument proof (base and head
verified, bytes read per changed file), the defects under `push.admission.defects`, the status. Resumable by
change id, input digest, program id and mask. The pilot manifest is refused by digest unless the run is a pilot
report run, so the loop cannot tune on the held-out set by accident.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import source
from ..preprocess import detect_language
from .artifact import RunArtifact, UsageLedger
from .labels import label_rows
from .producers import compute_rows
from .table import FeatureTable

PILOT_FREEZE_DIGEST = "c866c0e812c0b54476c7168fdb0e4a20652de0d30485270afecbe51e5c35e424"


class InstrumentFailure(RuntimeError):
    """A bounded, secret-free reason the record could not be measured."""


def _git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", *args], capture_output=True, check=True)
    return done.stdout.decode("utf-8", errors="replace")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".partial")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def record_path(out: Path, change_id: str) -> Path:
    return Path(out) / (hashlib.sha256(change_id.encode("utf-8")).hexdigest() + ".json")


def input_digest(change: Mapping[str, Any], program_id: str, mask: Iterable[str]) -> str:
    payload = json.dumps({"change": change, "program": program_id, "mask": sorted(set(mask))}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def refuse_pilot(manifest: Path, *, pilot_report: bool) -> None:
    """The held-out pilot is never a training or tuning input (requirement 2.4)."""
    freeze = Path(manifest).with_name("freeze-" + Path(manifest).stem.removeprefix("pool-") + ".json")
    if freeze.is_file():
        digest = json.loads(freeze.read_text()).get("freeze_digest")
        if digest == PILOT_FREEZE_DIGEST and not pilot_report:
            raise ValueError("the pilot manifest is held out; pass pilot_report=True only for a report run")


def defect_from(finding: Mapping[str, Any], *, program_id: str, mask: tuple[str, ...]) -> dict[str, Any]:
    """The record's defect shape, with the program and mask that produced it."""
    path, line = str(finding.get("path", "")), int(finding.get("line", 0) or 0)
    return {
        "defect_id": f"hunt:{program_id[:12]}:{path}:{line}",
        "family": finding.get("family", "unknown"),
        "cwe": None,
        "function": finding.get("function"),
        "locations": [[path, line]],
        "source": "hunt",
        "title": f"{finding.get('family', 'unknown')} at {path}:{line}",
        "rationale": finding.get("rationale", ""),
        "confidence": finding.get("confidence"),
        "cited_lines": list(finding.get("cited_lines") or []),
        "reported_family": finding.get("reported_family"),
        "unknown_reason": finding.get("unknown_reason"),
        "program_id": program_id,
        "mask": list(mask),
    }


def hunt_change(
    change: Mapping[str, Any], repo_root: Path, *, program: Any, program_id: str, mask: tuple[str, ...], render: Any, tools_for: Any
) -> dict[str, Any]:
    """Check out the change's head, compute its feature rows, run the program once, return the record."""
    instrument: dict[str, Any] = {
        "hook_exit": 0,
        "hook_bytes_read": 0,
        "changed_bytes": {},
        "head_verified": False,
        "base_verified": False,
        "failure": None,
    }
    record: dict[str, Any] = {
        "id": change["id"],
        "done": True,
        "status": "hunt_covered",
        "instrument": instrument,
        "push": {"admission": {"defects": [], "dispositions": []}, "quick_tier": []},
        "rows": 0,
        "program_id": program_id,
        "mask": list(mask),
        "inputs_present": [],
        "seconds": 0.0,
    }
    started = time.monotonic()
    try:
        _git(repo_root, "cat-file", "-e", change["base"] + "^{commit}")
        instrument["base_verified"] = True
        with tempfile.TemporaryDirectory(prefix="ousast-hunt-") as temporary:
            root = Path(temporary) / "head"
            added = False
            try:
                _git(repo_root, "worktree", "add", "--detach", str(root), change["head"])
                added = True
                if _git(root, "rev-parse", "HEAD").strip() != change["head"]:
                    raise InstrumentFailure("head_mismatch")
                instrument["head_verified"] = True
                texts: dict[str, list[str]] = {}
                for relative in dict.fromkeys(file["path"] for file in change.get("files", [])):
                    target = root / relative
                    if not target.is_file():
                        continue
                    data = target.read_bytes()
                    print(f"{change['id']} {relative}: {len(data)} bytes read", flush=True)
                    instrument["changed_bytes"][relative] = len(data)
                    instrument["hook_bytes_read"] += len(data)
                    texts[relative] = data.decode("utf-8", errors="replace").splitlines()
                if not instrument["changed_bytes"]:
                    raise InstrumentFailure("no_readable_hotspots")
                rows = label_rows(compute_rows(root, change), change)
                FeatureTable(rows)  # validates the schema before anything is rendered
                record["rows"] = len(rows)
                inputs = render(change, rows, texts, mask=mask)
                record["inputs_present"] = sorted(inputs)
                if tools_for is not None and hasattr(program, "bind"):
                    program.bind(root)
                prediction = program(**inputs)
                record["parse_failed"] = bool(getattr(prediction, "parse_failed", False))
                for finding in prediction.findings:
                    if finding.get("path") in texts and not finding.get("function") and (span := _function_at(root, finding)):
                        finding["function"] = span
                    record["push"]["admission"]["defects"].append(defect_from(finding, program_id=program_id, mask=mask))
            finally:
                if added:
                    _git(repo_root, "worktree", "remove", "--force", str(root))
    except Exception as error:  # noqa: BLE001  (provider messages can carry a key: type only)
        reason = str(error) if isinstance(error, InstrumentFailure) else type(error).__name__
        instrument.update(hook_exit=2, failure=reason)
        record["status"] = "instrument_failure"
        record["push"]["admission"]["defects"] = []
        print(f"{change['id']}: instrument_failure ({reason})", file=sys.stderr, flush=True)
    record["seconds"] = round(time.monotonic() - started, 3)
    return record


def _function_at(root: Path, finding: Mapping[str, Any]) -> str | None:
    try:
        path = str(finding["path"])
        text = (root / path).read_text(errors="replace")
        language = source.canonical_language(detect_language(root / path))
        return source.enclosing(source.ranges(path, text, language), int(finding.get("line", 0) or 0))
    except Exception:  # noqa: BLE001
        return None


def run(
    manifest: Path,
    repos: Mapping[str, str],
    out: Path,
    *,
    program: Any,
    program_id: str,
    mask: Iterable[str] = (),
    only: str = "all",
    slice_id: str = "1",
    budget: Mapping[str, float] | None = None,
    pilot_report: bool = False,
    render: Any = None,
    tools_for: Any = None,
    load_changes: Any = None,
    versions: Mapping[str, str] | None = None,
) -> RunArtifact | None:
    """Run the program over every change of the manifest's slice; resumable; one artifact at the end."""
    manifest, out = Path(manifest), Path(out)
    refuse_pilot(manifest, pilot_report=pilot_report)
    mask = tuple(sorted(set(mask)))
    if render is None:
        from .program import render_rows as render  # noqa: PLC0415  (dspy import stays optional)
    changes = load_changes(manifest, slice_id)
    changes = [change for change in changes if only == "all" or change["kind"] == only]
    out.mkdir(parents=True, exist_ok=True)
    inputs_path = out / "inputs.json"
    entries = json.loads(inputs_path.read_text()) if inputs_path.is_file() else []
    indexed = {entry["item_id"]: entry for entry in entries}
    ledger = UsageLedger()
    started = time.monotonic()
    for change in changes:
        digest = input_digest(change, program_id, mask)
        entry = indexed.get(change["id"])
        if entry is None:
            entry = {"item_id": change["id"], "change": change, "input_digest": digest}
            entries.append(entry)
            indexed[change["id"]] = entry
        elif entry["input_digest"] != digest:
            entry.update(change=change, input_digest=digest)
        path = record_path(out, change["id"])
        if path.is_file():
            previous = json.loads(path.read_text())
            if previous.get("done") and previous.get("input_digest") == digest:
                continue
        if budget and ledger.exhausted(budget):
            print("budget exhausted; stopping before the next change", flush=True)
            break
        record = hunt_change(
            change,
            Path(repos[change["repo"]]).expanduser(),
            program=program,
            program_id=program_id,
            mask=mask,
            render=render,
            tools_for=tools_for,
        )
        record["input_digest"] = digest
        ledger.add({"calls": 1, "usd": 0.0})
        _write_json(path, record)
        _write_json(inputs_path, entries)
    _write_json(inputs_path, entries)
    usage = dict(ledger.usage)
    usage["wall_seconds"] = round(time.monotonic() - started, 1)
    artifact = RunArtifact(
        program_id=program_id,
        schema_version=1,
        mask=list(mask),
        data_digests={"manifest": hashlib.sha256(manifest.read_bytes()).hexdigest()},
        configurations=[{"only": only, "slice": slice_id, "changes": len(changes)}],
        usage=usage,
        versions=dict(versions or {}),
        created=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    written = artifact.write(out, budget=budget) if budget else artifact.write(out)
    return artifact if written is not None else None
