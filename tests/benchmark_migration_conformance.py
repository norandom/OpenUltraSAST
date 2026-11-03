"""Executable owner conformance for the stable benchmark migration worklist."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from benchmark_migration_evidence import BENCHMARK_TERMINAL_EVIDENCE, migrated_owner_targets
from core_migration_inventory import LegacyInventoryEntry, LegacyMigrationInventory, MigrationDisposition

from benchmarks.valid.artifact_contract import (
    benchmark_payload,
    read_benchmark_artifact,
    read_benchmark_jsonl,
    read_benchmark_sequence,
    write_benchmark_artifact,
    write_benchmark_jsonl,
    write_benchmark_sequence,
)


class BenchmarkMigrationConformanceError(ValueError):
    """A terminal worklist entry lacks its exact executable owner."""


OWNER_TARGETS = migrated_owner_targets()


def _change() -> dict[str, Any]:
    return {"id": "case", "repo": "fixture/repo", "kind": "ordinary", "base": "a" * 40, "head": "b" * 40, "files": []}


def _record() -> dict[str, Any]:
    return {
        **_change(),
        "done": True,
        "status": "quick_only",
        "seconds": 0.1,
        "instrument": {
            "hook_exit": 0,
            "hook_bytes_read": 1,
            "head_verified": True,
            "base_verified": True,
            "changed_bytes": {"app.py": 1},
            "file_bytes": {"app.py": 1},
        },
        "push": {"admission": {"defects": []}, "quick_tier": []},
        "coverage": {},
    }


def _owner(entry: LegacyInventoryEntry) -> tuple[Any, Callable[..., Any]]:
    module_name, symbol = OWNER_TARGETS[entry.entry_id]
    module = importlib.import_module(module_name)
    owner = getattr(module, symbol, None)
    if not callable(owner):
        raise BenchmarkMigrationConformanceError(f"registered benchmark owner is absent: {entry.entry_id}")
    return module, owner


def _probe_engine(module: Any, owner: Callable[..., Any], root: Path) -> None:
    pin = {"pin": "fixture", "units": [], "questions": {}}

    def download(_url: str, path: Path, **_kwargs: Any) -> None:
        path.write_text(json.dumps(pin)) if path.name == "questions.json" else path.write_bytes(b"source")

    def run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        Path(command[command.index("--output") + 1]).write_text(json.dumps({"done": True, "units": []}))
        return SimpleNamespace(returncode=0)

    with ExitStack() as stack:
        stack.enter_context(patch.object(module, "download", download))
        stack.enter_context(patch.object(module, "unpack", lambda *_args: None))
        stack.enter_context(patch.object(module.subprocess, "run", run))
        stack.enter_context(patch.object(module, "transfer", lambda *_args, **_kwargs: None))
        stack.enter_context(patch.dict(os.environ, {"QUESTIONS_URL": "q", "SOURCE_URL": "s", "RESULT_URL": "r"}))
        owner(work_root=root)
    read_benchmark_artifact(root / "out/result.json", "engine-task-result")


def _probe_measurement(module: Any, owner: Callable[..., Any], root: Path) -> None:
    with ExitStack() as stack:
        stack.enter_context(patch.object(module, "discover_hunt_runner_context", lambda *_args, **_kwargs: object()))
        stack.enter_context(patch.object(module, "persist_hunt_runner_records", lambda *_args, **_kwargs: ()))
        stack.enter_context(patch.object(module.score, "load_records", lambda _path: []))
        stack.enter_context(patch.object(module, "arm_summary", lambda _records, arm: ({}, [{"id": arm}])))
        stack.enter_context(patch.object(module, "cost", lambda _path: None))
        stack.enter_context(patch.object(module, "load_slice", lambda *_args: ()))
        owner(root)
    read_benchmark_jsonl(root / "suspicions.jsonl", "access-control-suspicion")


def _probe_calibrate(module: Any, owner: Callable[..., Any], root: Path) -> None:
    argv = [
        "calibrate",
        "--manifest",
        str(root / "pool.toml"),
        "--image",
        "image",
        "--docker-image-bytes",
        "1",
        "--out",
        str(root / "runs"),
        "--record",
        str(root / "record.json"),
    ]
    with ExitStack() as stack:
        stack.enter_context(patch.object(sys, "argv", argv))
        stack.enter_context(patch.object(module, "load_slice", lambda *_args: (_change(),)))
        stack.enter_context(patch.object(module, "run_replays", lambda *_args, **_kwargs: False))
        stack.enter_context(patch.object(module, "load_records", lambda _path: [_record()]))
        stack.enter_context(patch.object(module, "calibration_record", lambda *_args: {"status": "ok"}))
        owner()
    read_benchmark_artifact(root / "record.json", "deadline-calibration")


def _probe_replay(module: Any, owner: Callable[..., Any], root: Path) -> None:
    class Transport:
        def __init__(self, *_args: Any):
            self.store = SimpleNamespace(_put=lambda *_values: None)

        def __call__(self, item: Any, _output: Path, _attempt: int) -> dict[str, Any]:
            return {"done": True, "status": "quick_only", "input_digest": item.input_digest}

    args = SimpleNamespace(arm="default", image="image", docker_image_bytes=1)
    with patch.object(module, "DockerLane", Transport):
        owner((_change(),), args, root, "docker")
    read_benchmark_sequence(root / "inputs.json", "benchmark-arm-inputs")
    result = next(path for path in root.glob("*.json") if '"artifact_kind": "benchmark-arm-record"' in path.read_text())
    read_benchmark_artifact(result, "benchmark-arm-record")


def _probe_score(module: Any, owner: Callable[..., Any], root: Path) -> None:
    records, output = root / "records.json", root / "score.json"
    write_benchmark_sequence(records, "benchmark-arm-records", (_record(),))
    with patch.object(sys, "argv", ["score", str(records), "--out", str(output)]):
        owner()
    read_benchmark_artifact(output, "unseen-score")


def _probe_instrument(module: Any, owner: Callable[..., Any], *, zero: bool) -> None:
    from openultrasast.core import coverage

    if zero:
        if owner is not coverage.validate_instrument or module.validate_instrument is not coverage.validate_instrument:
            raise ValueError("validate_instrument alias is not canonical")
        manifest = coverage.InputManifest(("input",), coverage.derive_input_manifest_digest(("input",)))
        owner(manifest, (coverage.InputReadReceipt("input", "input", True, 1, "a" * 64),))
        try:
            owner(manifest, (coverage.InputReadReceipt("input", "input", True, 0, "a" * 64),))
        except coverage.InstrumentFailure:
            return
        raise ValueError("canonical instrument accepted a zero-byte read")
    if module.CoreInstrumentFailure is not coverage.InstrumentFailure:
        raise ValueError("instrument failure alias is not canonical")
    owner({"file_bytes": {"input": 1}, "file_digests": {"input": "a" * 64}})


def _probe_development(module: Any, owner: Callable[..., Any], root: Path) -> None:
    bundle = module.AnalyzerBundle("a", "b", "c", "d")
    funnel = {"entry_recognition": {}, "resolution": {}, "judgment": {}}
    with (
        patch.object(module, "prove_change", lambda *_args, **_kwargs: object()),
        patch.object(module, "stage_funnel", lambda _result: funnel),
    ):
        owner(bundle, root, (_change(),), root / "out")
    read_benchmark_artifact(root / "out/case.json", "development-observation")


def _probe_run_arm(module: Any, owner: Callable[..., Any], root: Path) -> None:
    bundle = module.BundleDigests("a", "b", "c", "d")
    with patch.object(module, "_prove_one", lambda *_args, **_kwargs: _record()):
        owner(arm_name="arm", bundle=bundle, changes=(_change(),), repos={"fixture/repo": str(root)}, out_dir=root / "out")
    read_benchmark_artifact(root / "out/case.json", "development-arm-record")


def _arm_inputs(path: Path, record: dict[str, Any] | None = None) -> None:
    change = _change()
    entry = {"item_id": "case", "change": change, "input_digest": "d" * 64}
    write_benchmark_sequence(path / "inputs.json", "benchmark-arm-inputs", (entry,))
    if record is not None:
        from openultrasast.hunt.runner import record_path

        write_benchmark_artifact(record_path(path, "case"), "benchmark-arm-record", {**record, "input_digest": entry["input_digest"]})


def _probe_combine(module: Any, owner: Callable[..., Any], root: Path) -> None:
    left, right, output = root / "left", root / "right", root / "combined.json"
    left.mkdir()
    right.mkdir()
    _arm_inputs(left, _record())
    _arm_inputs(right, _record())
    owner(left, right, output)
    read_benchmark_sequence(output, "benchmark-arm-records")


def _probe_hunter(module: Any, owner: Callable[..., Any], root: Path) -> None:
    repos = root / "repos.json"
    repos.write_text(json.dumps({"fixture/repo": str(root)}))
    with ExitStack() as stack:
        stack.enter_context(patch.object(module, "load_slice", lambda *_args: [_change()]))
        stack.enter_context(patch.object(module, "load_config", lambda *_args, **_kwargs: object()))
        stack.enter_context(patch.object(module, "resolve_models", lambda _config: ("model",)))
        stack.enter_context(patch.object(module.tool_hunter, "resolve_hunter_client", lambda: object()))
        stack.enter_context(patch.object(module, "_hunt_change", lambda *_args, **_kwargs: _record()))
        owner(root / "pool", repos, root / "out")
    read_benchmark_sequence(root / "out/inputs.json", "benchmark-arm-inputs")
    read_benchmark_artifact(next(path for path in (root / "out").glob("*.json") if path.name != "inputs.json"), "benchmark-arm-record")


def _probe_judge_input(owner: Callable[..., Any]) -> None:
    result = owner("repo", {"trace": {}, "operation": {}, "missing": "guard"})
    start = result.rindex('{\n  "artifact_digest"')
    encoded = result[start:]
    benchmark_payload(json.loads(encoded), expected_kind="judge-pass-input")


def _probe_judge_run(module: Any, owner: Callable[..., Any], root: Path) -> None:
    fake_lm = SimpleNamespace(model="offline")
    program = importlib.import_module("openultrasast.hunt.program")
    with patch.object(program, "build_lm", lambda **_kwargs: fake_lm), patch.object(module, "_iter_findings", lambda _path: ()):
        owner(SimpleNamespace(out=root, prover_out=root / "prover"))
    read_benchmark_artifact(root / "run.json", "judge-pass-run")


def _probe_judge_summary(module: Any, owner: Callable[..., Any], root: Path) -> None:
    row = {"key": "one", "record_id": "case", "repo": "repo", "kind": "ordinary", "public": False, "status": "ok", "model": "offline"}
    write_benchmark_jsonl(root / "judgments.jsonl", "judge-pass", (row,))
    owner(SimpleNamespace(out=root))
    read_benchmark_artifact(root / "summary.json", "judge-pass-summary")


def _probe_metrics(module: Any, owner: Callable[..., Any], root: Path) -> None:
    records, output = root / "records.json", root / "metrics.json"
    write_benchmark_sequence(records, "benchmark-arm-records", (_record(),))
    owner([str(records), "--out", str(output)])
    read_benchmark_artifact(output, "valid-benchmark-metrics")


def _probe_prover(module: Any, owner: Callable[..., Any], root: Path, *, summary: bool) -> None:
    out = root / "out"
    if summary:
        out.mkdir()
        _arm_inputs(out, _record())
        base = {
            "headline": "On unseen app repos: fixture",
            "recall": {},
            "precision": {},
            "false_alarms_per_100_pushes": {},
            "exploit_verified": {},
        }
        with patch.object(module.metrics, "summarize", lambda *_args, **_kwargs: base):
            owner(out)
        read_benchmark_artifact(out / "summary.json", "benchmark-arm-summary")
        return
    repos = root / "repos.json"
    repos.write_text("{}")
    with (
        patch.object(module, "load_slice", lambda *_args: [_change()]),
        patch.object(module, "_prove", lambda *_args, **_kwargs: _record()),
    ):
        owner(root / "pool", repos, out)
    read_benchmark_artifact(next(path for path in out.glob("*.json") if path.name != "inputs.json"), "benchmark-arm-record")


def _git_fixture(root: Path) -> tuple[str, str]:
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
    (root / "app.py").write_text("print('base')\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    (root / "app.py").write_text("print('head')\n")
    subprocess.run(["git", "commit", "-qam", "head"], cwd=root, check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    return base, head


def _probe_semgrep(module: Any, owner: Callable[..., Any], root: Path) -> None:
    repo = root / "repo"
    base, head = _git_fixture(repo)
    change = {**_change(), "base": base, "head": head, "files": [{"path": "app.py"}]}
    repos, rules, binary = root / "repos.json", root / "rules", root / "fake-semgrep"
    repos.write_text(json.dumps({"fixture/repo": str(repo)}))
    rules.mkdir()
    binary.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"results":[],"errors":[],"paths":{"scanned":["app.py"]}}\'\n')
    binary.chmod(0o755)
    with patch.object(module, "load_slice", lambda *_args: [change]), patch.object(module, "MIN_PLAUSIBLE_SECONDS", 0.0):
        owner(root / "pool", repos, rules, root / "out", semgrep=str(binary))
    read_benchmark_artifact(next(path for path in (root / "out").glob("*.json") if path.name != "inputs.json"), "benchmark-arm-record")


def probe_benchmark_entry(entry: LegacyInventoryEntry, *, output_root: Path) -> None:
    """Invoke the exact registered owner and strict-read only its produced output."""
    module, owner = _owner(entry)
    root = output_root / entry.entry_id
    root.mkdir(parents=True, exist_ok=True)
    probes: dict[str, Callable[[], None]] = {
        "40465a45": lambda: _probe_engine(module, owner, root),
        "f0fd6f38": lambda: _probe_measurement(module, owner, root),
        "fd21a8b7": lambda: _probe_measurement(module, owner, root),
        "61d6e4cf": lambda: _probe_calibrate(module, owner, root),
        "c01d6865": lambda: _probe_replay(module, owner, root),
        "039988ff": lambda: _probe_score(module, owner, root),
        "ae8dd586": lambda: _probe_instrument(module, owner, zero=False),
        "f3ba25f4": lambda: _probe_instrument(module, owner, zero=True),
        "b2bee433": lambda: _probe_run_arm(module, owner, root),
        "2acb6086": lambda: _probe_development(module, owner, root),
        "c4fe7770": lambda: _probe_combine(module, owner, root),
        "880bbb68": lambda: _probe_hunter(module, owner, root),
        "6a962869": lambda: _probe_judge_input(owner),
        "dea8fd3d": lambda: _probe_judge_run(module, owner, root),
        "8bf0cd9c": lambda: _probe_judge_summary(module, owner, root),
        "c9906d43": lambda: _probe_metrics(module, owner, root),
        "bfeaa25d": lambda: _probe_prover(module, owner, root, summary=False),
        "c3e95086": lambda: _probe_prover(module, owner, root, summary=True),
        "8db722b9": lambda: _probe_semgrep(module, owner, root),
    }
    try:
        probes[entry.entry_id[:8]]()
    except Exception as error:
        raise BenchmarkMigrationConformanceError(f"benchmark owner probe failed: {entry.entry_id}: {error}") from error


def _validate_retired(entry: LegacyInventoryEntry) -> None:
    module = importlib.import_module(entry.path.removesuffix(".py").replace("/", "."))
    names = (
        (entry.symbol,)
        if entry.symbol != "<module>"
        else tuple(anchor.rsplit(":", 1)[-1] for anchor in entry.capability_anchors if anchor.startswith("import_from:"))
    )
    if any(hasattr(module, name) for name in names):
        raise BenchmarkMigrationConformanceError(f"retired benchmark entry remains live: {entry.entry_id}")


def _stable_fields(entry: LegacyInventoryEntry) -> tuple[str, str, str, str, tuple[str, ...], str]:
    return (
        entry.path,
        entry.symbol,
        entry.dependency_kind.value,
        entry.artifact_family,
        entry.capability_anchors,
        entry.owner_boundary,
    )


def validate_benchmark_terminal_conformance(inventory: LegacyMigrationInventory, *, output_root: Path) -> None:
    entries = tuple(entry for entry in inventory.entries if entry.path.startswith("benchmarks/"))
    migrated = {entry.entry_id for entry in entries if entry.disposition is MigrationDisposition.V2_MIGRATED}
    if not entries or {entry.entry_id for entry in entries} != set(BENCHMARK_TERMINAL_EVIDENCE) or migrated != set(OWNER_TARGETS):
        raise BenchmarkMigrationConformanceError("benchmark probe registry and terminal evidence do not exactly match inventory entries")
    for entry in entries:
        evidence = BENCHMARK_TERMINAL_EVIDENCE[entry.entry_id]
        if evidence.disposition != entry.disposition.value or evidence.stable_fields != _stable_fields(entry):
            raise BenchmarkMigrationConformanceError(f"benchmark terminal evidence mismatch: {entry.entry_id}")
        if entry.disposition is MigrationDisposition.OPEN:
            raise BenchmarkMigrationConformanceError(f"benchmark entry remains open: {entry.entry_id}")
        _validate_retired(entry) if entry.disposition is MigrationDisposition.RETIRED else probe_benchmark_entry(
            entry, output_root=output_root
        )


__all__ = ["BenchmarkMigrationConformanceError", "OWNER_TARGETS", "probe_benchmark_entry", "validate_benchmark_terminal_conformance"]
