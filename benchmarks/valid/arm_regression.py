"""Four-arm development regression runner (Task 13.3, Reqs 5.1-5.7, 6.1, 7.3, 11.8, 12.9).

Runs the registered arms over the immutable development population with the
prover's strict judgment lane, proves nonzero input reads per change, writes
one resumable record per change carrying analyzer, fact-set, population and
input digests, adapts the immutable 2026-10-28 baseline records under an
explicit binary-vocabulary marker, registers cross arms only on digest-proven
input identity, masks repository identities in shared summaries, and publishes
budget results as development evidence without any admission claim.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from benchmarks.unseen.extract import InstrumentFailure
from benchmarks.unseen.replay import canonical
from benchmarks.valid.catalog import local_git
from benchmarks.valid.development_runner import AnalyzerBundle, stage_funnel
from benchmarks.valid.prover_arm import _write_json
from openultrasast.hunt.producers import Context, _Absent, _safe_path
from openultrasast.hunt.prover import prove_change

BundleDigests = AnalyzerBundle
BUDGET_SECONDS = 120.0


class FactIdentityMismatch(ValueError):
    """A cross arm was registered without digest-proven input identity."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def fact_manifest_disk(directory: Path) -> dict[str, str]:
    """Digest every TOML fact artifact under ``directory`` as it exists on disk."""
    manifest: dict[str, str] = {}
    for path in sorted(directory.rglob("*.toml")):
        if path.is_file():
            manifest[path.relative_to(directory).as_posix()] = _sha256_bytes(path.read_bytes())
    return manifest


def fact_manifest_ref(repo_root: Path, ref: str, subpath: str = "") -> dict[str, str]:
    """Digest the content of every TOML fact artifact recorded at ``ref`` under ``subpath``."""
    listing = subprocess.run(
        ["git", "-C", str(repo_root), "ls-tree", "-r", "--name-only", ref, "--", subpath],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    prefix = f"{subpath}/" if subpath else ""
    manifest: dict[str, str] = {}
    for path in listing:
        if not path.endswith(".toml"):
            continue
        blob = subprocess.run(["git", "-C", str(repo_root), "show", f"{ref}:{path}"], capture_output=True, check=True).stdout
        manifest[path.removeprefix(prefix)] = _sha256_bytes(blob)
    return manifest


def manifest_digest(manifest: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:12]


def fact_identity(baseline: dict[str, str], candidate: dict[str, str]) -> dict[str, Any]:
    """Register a cross-arm input identity only when the fact sets are byte-equal."""
    if baseline != candidate:
        raise FactIdentityMismatch("cross arms require digest-proven identical fact inputs")
    return {"identical": True, "fact_set_digest": manifest_digest(candidate)}


def adapt_baseline_record(record: dict[str, Any]) -> dict[str, Any]:
    """Adapt one immutable 2026-10-28 record under its honest binary vocabulary."""
    findings = record.get("findings")
    coverage = record.get("coverage")
    if findings is None or not isinstance(coverage, dict):
        raise ValueError(f"baseline record {record.get('case_id', '?')} lacks findings or coverage")
    return {
        "change_id": str(record.get("case_id", record.get("id", ""))),
        "repo": record.get("repo", ""),
        "kind": record.get("kind", ""),
        "vocabulary": "binary",
        "stage_funnel": {
            "entry_recognition": {"entry_points": int(coverage.get("entry_points", 0))},
            "resolution": {},
            "judgment": {
                "unguarded": len(findings),
                "discharged": int(coverage.get("operations_discharged", 0)),
                "indeterminate": 0,
            },
        },
        "seconds": float(record.get("seconds", 0.0)),
    }


def _input_digest(change: dict[str, Any], arm_name: str) -> str:
    return hashlib.sha256(canonical({"change": change, "arm": arm_name})).hexdigest()[:12]


def _population_digest(changes: tuple[dict[str, Any], ...]) -> str:
    joined = "\n".join(sorted(str(change.get("id", "")) for change in changes))
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def _prove_one(
    bundle: BundleDigests,
    arm_name: str,
    population: str,
    change: dict[str, Any],
    repo_path: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    instrument: dict[str, Any] = dict(
        hook_exit=0,
        hook_bytes_read=0,
        changed_bytes={},
        file_bytes={},
        head_verified=False,
        base_verified=False,
        suspect_fast=False,
        failure=None,
    )
    record: dict[str, Any] = {
        **change,
        "arm": arm_name,
        "analyzer_revision": bundle.analyzer_revision,
        "fact_set_digest": bundle.fact_set_digest,
        "acquisition_record_digest": bundle.acquisition_record_digest,
        "configuration_digest": bundle.configuration_digest,
        "population_digest": population,
        "input_digest": _input_digest(change, arm_name),
        "done": True,
        "status": "prover_covered",
        "vocabulary": "three-way",
        "instrument": instrument,
        "findings": [],
        "traces": [],
        "coverage": {},
        "degradations": [],
        "stage_funnel": {},
        "push": {"admission": {"defects": [], "dispositions": []}, "quick_tier": []},
    }
    try:
        git = local_git(repo_path)
        git.run("cat-file", "-e", change["base"] + "^{commit}")
        instrument["base_verified"] = True
        with tempfile.TemporaryDirectory(prefix="ousast-arm-") as temporary:
            root = Path(temporary) / "head"
            git.run("-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", str(root), change["head"])
            try:
                _verify_checkout(root)
                ctx = Context(root, change)
                ctx.verify_head()
                instrument["head_verified"] = True
                _instrument_reads(ctx, root, change, instrument)
                result = prove_change(root, change, ctx, judgment_mode=True)
                instrument["hook_bytes_read"] = sum(instrument["file_bytes"].values())
                record.update(
                    findings=list(result.findings),
                    traces=list(result.traces),
                    coverage=asdict(result.coverage),
                    degradations=list(result.degradations),
                    stage_funnel=stage_funnel(result),
                )
                record["push"]["admission"]["defects"] = [
                    {**finding, "defect_id": finding["id"], "source": "prover", "locations": [[finding["path"], finding["line"]]]}
                    for finding in result.findings
                ]
            finally:
                git.run("worktree", "remove", "--force", str(root))
    except Exception as error:  # noqa: BLE001 - the record must survive any instrument failure
        instrument.update(hook_exit=2, failure=type(error).__name__)
        record.update(status="instrument_failure", findings=[])
    record["seconds"] = time.monotonic() - started
    return record


def _verify_checkout(root: Path) -> None:
    checked_git = local_git(root)
    sparse = checked_git.runner(["git", "-C", str(root), "config", "--get", "core.sparseCheckout"], capture_output=True, text=True)
    if sparse.stdout.strip() == "true":
        checked_git.run("sparse-checkout", "disable")
    if checked_git.run("status", "--porcelain", "--untracked-files=no").strip():
        raise InstrumentFailure("incomplete checkout")


def _instrument_reads(ctx: Context, root: Path, change: dict[str, Any], instrument: dict[str, Any]) -> None:
    changed = {file["path"] for file in change.get("files", [])}
    for relative in sorted(changed | set(ctx.product_files)):
        path = _safe_path(root, relative)
        if not path.is_file():
            held = local_git(root).runner(["git", "-C", str(root), "cat-file", "-e", f"HEAD:{relative}"], capture_output=True)
            if held.returncode == 0:
                raise InstrumentFailure("unread tracked file")
            continue
        try:
            text = ctx.read(relative)
        except _Absent as error:
            # A file git holds empty is read, not unread; anything else absent is unread.
            held = local_git(root).runner(["git", "-C", str(root), "cat-file", "-s", f"HEAD:{relative}"], capture_output=True, text=True)
            if getattr(error, "reason", "") == "empty_source" and held.returncode == 0 and int(held.stdout.strip() or 0) == 0:
                instrument["empty_files"] = instrument.get("empty_files", 0) + 1
                continue
            raise InstrumentFailure("unread tracked file") from error
        size = len(text.encode("utf-8"))
        instrument["file_bytes"][relative] = size
        if relative in changed:
            instrument["changed_bytes"][relative] = size
        if not size:
            raise InstrumentFailure("zero-byte read")


def run_arm(
    *,
    arm_name: str,
    bundle: BundleDigests,
    changes: tuple[dict[str, Any], ...],
    repos: dict[str, str],
    out_dir: Path,
) -> tuple[dict[str, Any], ...]:
    """Prove every change on the strict judgment lane; records resume by input digest."""
    out_dir.mkdir(parents=True, exist_ok=True)
    population = _population_digest(changes)
    records: list[dict[str, Any]] = []
    for change in changes:
        path = out_dir / f"{change['id']}.json"
        if path.is_file():
            previous = json.loads(path.read_text(encoding="utf-8"))
            if previous.get("input_digest") == _input_digest(change, arm_name):
                records.append(previous)
                continue
            raise ValueError(f"existing record for {change['id']} does not match this arm's inputs")
        record = _prove_one(bundle, arm_name, population, change, Path(repos[change["repo"]]).expanduser())
        _write_json(path, record)
        records.append(record)
    return tuple(records)


def _masked(repo: str) -> str:
    return hashlib.sha256(repo.encode()).hexdigest()[:12]


def summarize_arm(records: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    """Aggregate one arm; refuse any zero-byte read, publish budget and masked coverage."""
    judgment = {"unguarded": 0, "discharged": 0, "indeterminate": 0}
    per_repository: dict[str, dict[str, Any]] = {}
    for record in records:
        instrument = record.get("instrument", {})
        if any(size == 0 for field in ("changed_bytes", "file_bytes") for size in instrument.get(field, {}).values()):
            raise InstrumentFailure(f"zero-byte read of a tracked file; summary refused: {record['id']}")
        funnel = record.get("stage_funnel", {})
        for kind, count in funnel.get("judgment", {}).items():
            judgment[kind] += int(count)
        row = per_repository.setdefault(
            _masked(record["repo"]),
            {"changes": 0, "unguarded": 0, "discharged": 0, "frameworks_recognised": 0},
        )
        row["changes"] += 1
        for kind in ("unguarded", "discharged"):
            row[kind] += int(funnel.get("judgment", {}).get(kind, 0))
        recognised = funnel.get("entry_recognition", {}).get("frameworks_recognised", {})
        row["frameworks_recognised"] += sum(recognised.values()) if isinstance(recognised, dict) else int(recognised)
    for row in per_repository.values():
        row["status"] = "uncovered" if not row["frameworks_recognised"] else "covered"
    uncovered = sorted(key for key, row in per_repository.items() if row["status"] == "uncovered")
    seconds = [float(record.get("seconds", 0.0)) for record in records]
    overruns = [
        {"id": record["id"], "seconds": float(record.get("seconds", 0.0))}
        for record in records
        if float(record.get("seconds", 0.0)) > BUDGET_SECONDS
    ]
    return {
        "population_role": "development",
        "development_only": True,
        "total_changes": len(records),
        "judgment_counts": judgment,
        "budget": {
            "gate": "failed" if overruns else "passed",
            "budget_seconds": BUDGET_SECONDS,
            "overruns": overruns,
        },
        "seconds_per_change": dict(
            n=len(seconds),
            mean=statistics.mean(seconds) if seconds else 0.0,
            median=statistics.median(seconds) if seconds else 0.0,
            maximum=max(seconds, default=0.0),
        ),
        "instrument_failures": sum(record.get("status") == "instrument_failure" for record in records),
        "per_repository": per_repository,
        "uncovered_repositories": uncovered,
    }


def four_arm_development(
    *,
    bab: tuple,
    bacf: tuple,
    cabf: tuple,
    cacfon: tuple,
    fact_identity: dict[str, Any],
) -> dict[str, Any]:
    """Publish attribution and transitions between compared arms (Req 11.8)."""
    from benchmarks.valid.development_runner import four_arm_report

    attribution = four_arm_report(bab, bacf, cabf, cacfon)
    return {
        "arms": attribution["arms"],
        "attribution": attribution,
        "fact_inputs_identical": bool(fact_identity.get("identical")),
    }


__all__ = [
    "BUDGET_SECONDS",
    "BundleDigests",
    "FactIdentityMismatch",
    "adapt_baseline_record",
    "fact_identity",
    "fact_manifest_disk",
    "fact_manifest_ref",
    "four_arm_development",
    "manifest_digest",
    "run_arm",
    "summarize_arm",
]
