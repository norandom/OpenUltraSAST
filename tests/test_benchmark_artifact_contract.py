"""Strict v2 persistence, ordered collections, and atomic collision behavior."""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.unseen import score  # noqa: E402
from benchmarks.valid import (
    artifact_contract,  # noqa: E402
    hunt_handoff,  # noqa: E402
)
from openultrasast.hunt.artifact import MAX_ATTEMPT_ORDINAL, RunArtifact  # noqa: E402
from openultrasast.hunt.runner import input_digest, record_path  # noqa: E402


def _rewrite(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def test_payload_requires_complete_metadata_expected_kind_schema_and_digest() -> None:
    artifact = artifact_contract.benchmark_artifact("record", {"id": "one"})
    assert artifact_contract.benchmark_payload(artifact, expected_kind="record") == {"id": "one"}

    with pytest.raises(ValueError, match="metadata"):
        artifact_contract.benchmark_payload({"id": "one"}, expected_kind="record")
    for field in ("schema_version", "artifact_kind", "artifact_digest"):
        stripped = dict(artifact)
        stripped.pop(field)
        with pytest.raises(ValueError, match="metadata"):
            artifact_contract.benchmark_payload(stripped, expected_kind="record")
    for field, value in (
        ("schema_version", "v1"),
        ("artifact_kind", "other"),
        ("artifact_digest", "0" * 64),
    ):
        tampered = dict(artifact)
        tampered[field] = value
        with pytest.raises(ValueError, match="metadata"):
            artifact_contract.benchmark_payload(tampered, expected_kind="record")


def test_ordered_sequence_rejects_reorder_truncate_duplicate_extra_and_row_tamper(tmp_path: Path) -> None:
    path = tmp_path / "inputs.json"
    rows = ({"id": "one"}, {"id": "two"})
    artifact_contract.write_benchmark_sequence(path, "inputs", rows)
    assert artifact_contract.read_benchmark_sequence(path, "inputs") == rows
    original = json.loads(path.read_text())

    mutations = []
    reordered = json.loads(json.dumps(original))
    reordered["rows"].reverse()
    mutations.append(reordered)
    truncated = json.loads(json.dumps(original))
    truncated["rows"].pop()
    mutations.append(truncated)
    duplicated = json.loads(json.dumps(original))
    duplicated["rows"][1] = duplicated["rows"][0]
    mutations.append(duplicated)
    extra = json.loads(json.dumps(original))
    extra["rows"].append(extra["rows"][0])
    mutations.append(extra)
    tampered = json.loads(json.dumps(original))
    tampered["rows"][0]["artifact"]["id"] = "changed"
    mutations.append(tampered)

    for mutation in mutations:
        _rewrite(path, mutation)
        with pytest.raises(ValueError):
            artifact_contract.read_benchmark_sequence(path, "inputs")


def test_jsonl_rejects_reorder_truncate_duplicate_extra_and_row_tamper(tmp_path: Path) -> None:
    path = tmp_path / "judgments.jsonl"
    rows = ({"id": "one"}, {"id": "two"})
    artifact_contract.write_benchmark_jsonl(path, "judgment", rows)
    assert artifact_contract.read_benchmark_jsonl(path, "judgment") == rows
    original = path.read_text().splitlines()
    mutations = (
        list(reversed(original)),
        original[:-1],
        [original[0], original[0]],
        [*original, original[0]],
        [original[0].replace('"one"', '"changed"'), original[1]],
    )
    for lines in mutations:
        path.write_text("\n".join(lines) + "\n")
        with pytest.raises(ValueError):
            artifact_contract.read_benchmark_jsonl(path, "judgment")


def test_atomic_writer_is_idempotent_and_refuses_conflicting_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    artifact_contract.write_benchmark_artifact(path, "record", {"id": "one"})
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    artifact_contract.write_benchmark_artifact(path, "record", {"id": "one"})
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before

    with pytest.raises(ValueError, match="conflict"):
        artifact_contract.write_benchmark_artifact(path, "record", {"id": "two"})
    with pytest.raises(ValueError, match="conflict"):
        artifact_contract.write_benchmark_artifact(path, "other", {"id": "one"})
    assert not list(tmp_path.glob("*.tmp"))


def test_concurrent_conflicting_writers_have_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "record.json"

    def write(identity: str) -> str:
        artifact_contract.write_benchmark_artifact(path, "record", {"id": identity})
        return identity

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write, identity) for identity in ("one", "two")]
    winners = [future.result() for future in futures if future.exception() is None]
    failures = [future.exception() for future in futures if future.exception() is not None]
    assert len(winners) == 1
    assert len(failures) == 1 and isinstance(failures[0], ValueError)
    assert artifact_contract.read_benchmark_artifact(path, "record") == {"id": winners[0]}


def test_concurrent_jsonl_appends_preserve_both_rows(tmp_path: Path) -> None:
    path = tmp_path / "judgments.jsonl"
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(artifact_contract.append_benchmark_jsonl, path, "judgment", {"id": identity}) for identity in ("one", "two")]
    assert all(future.exception() is None for future in futures)
    rows = artifact_contract.read_benchmark_jsonl(path, "judgment")
    assert len(rows) == 2
    assert {row["id"] for row in rows} == {"one", "two"}


def test_score_reader_refuses_stripped_v2_metadata(tmp_path: Path) -> None:
    path = tmp_path / "score.json"
    _rewrite(path, [{"id": "one"}])
    with pytest.raises(ValueError, match="metadata"):
        score.load_records(path)


def _hunt_change() -> dict[str, object]:
    return {
        "id": "change-1",
        "repo": "fixture/repo",
        "base": "a" * 40,
        "head": "b" * 40,
        "kind": "ordinary",
        "files": [{"path": "app.py", "head_lines": [[1, 1]]}],
    }


def _hunt_record(change: dict[str, object], program_id: str, mask: tuple[str, ...], digest: str) -> dict[str, object]:
    return {
        "id": change["id"],
        "done": True,
        "status": "hunt_covered",
        "instrument": {"head_verified": True, "base_verified": True, "changed_bytes": {"app.py": 10}},
        "push": {"admission": {"defects": [], "dispositions": []}, "quick_tier": []},
        "rows": 1,
        "program_id": program_id,
        "mask": list(mask),
        "inputs_present": ["function_text"],
        "seconds": 0.1,
        "input_digest": digest,
        "usd": 0.0,
    }


def _hunt_artifact(program_id: str, mask: tuple[str, ...]) -> RunArtifact:
    return RunArtifact(
        program_id=program_id,
        schema_version=1,
        mask=mask,
        data_digests={"manifest": "d" * 64},
        configurations=[{"only": "all", "slice": "1", "changes": 1}],
        usage={"usd": 0.0, "calls": 1.0, "replay_hits": 0.0, "wall_seconds": 0.1},
        versions={},
        created="2026-11-02T00:00:00+00:00",
    )


def _raw_hunt_run(root: Path) -> tuple[hunt_handoff.HuntRunContext, tuple[dict[str, object], ...]]:
    change = _hunt_change()
    program_id = "c" * 64
    mask = ("obligations",)
    digest = input_digest(change, program_id, mask)
    root.mkdir()
    _rewrite(root / "inputs.json", [{"item_id": change["id"], "change": change, "input_digest": digest}])
    _rewrite(record_path(root, str(change["id"])), _hunt_record(change, program_id, mask, digest))
    artifact = _hunt_artifact(program_id, mask)
    artifact.write(root, reserve_attempt=True)
    context = hunt_handoff.HuntRunContext(
        producer="openultrasast.hunt.runner.v1",
        program_id=program_id,
        mask=mask,
        manifest_digest="d" * 64,
        freeze_digest="e" * 64,
        only="all",
        slice_id="1",
        artifact_ids=(artifact.artifact_id,),
        versions=(),
    )
    return context, (change,)


def test_hunt_handoff_is_non_mutating_repeatable_and_persists_only_to_benchmark_destination(tmp_path: Path) -> None:
    source = tmp_path / "producer"
    destination = tmp_path / "benchmark-v2"
    context, changes = _raw_hunt_run(source)
    before = {path.name: path.read_bytes() for path in source.iterdir()}

    first = hunt_handoff.read_hunt_runner_records(source, context=context, changes=changes)
    second = hunt_handoff.read_hunt_runner_records(source, context=context, changes=changes)
    assert first == second and first[0]["id"] == "change-1"
    assert {path.name: path.read_bytes() for path in source.iterdir()} == before

    hunt_handoff.persist_hunt_runner_records(source, destination, context=context, changes=changes)
    persisted = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()}
    hunt_handoff.persist_hunt_runner_records(source, destination, context=context, changes=changes)
    assert {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()} == persisted
    assert score.load_records(destination) == list(first)
    assert {path.name: path.read_bytes() for path in source.iterdir()} == before


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("producer", "producer"),
        ("program", "program"),
        ("manifest", "manifest"),
        ("input", "input digest"),
        ("record", "record identity"),
        ("reserved", "reserved metadata"),
    ),
)
def test_hunt_handoff_refuses_unsupported_producer_schema_and_identity(tmp_path: Path, mutation: str, message: str) -> None:
    source = tmp_path / "producer"
    context, changes = _raw_hunt_run(source)
    if mutation == "producer":
        context = hunt_handoff.HuntRunContext(**{**context.__dict__, "producer": "arbitrary-json"})
    elif mutation == "program":
        context = hunt_handoff.HuntRunContext(**{**context.__dict__, "program_id": "f" * 64})
    elif mutation == "manifest":
        context = hunt_handoff.HuntRunContext(**{**context.__dict__, "manifest_digest": "f" * 64})
    elif mutation == "input":
        entries = json.loads((source / "inputs.json").read_text())
        entries[0]["input_digest"] = "0" * 64
        _rewrite(source / "inputs.json", entries)
    else:
        path = record_path(source, "change-1")
        record = json.loads(path.read_text())
        if mutation == "record":
            record["id"] = "other"
        else:
            record["schema_version"] = "forged"
        _rewrite(path, record)
    with pytest.raises(ValueError, match=message):
        hunt_handoff.read_hunt_runner_records(source, context=context, changes=changes)


def test_hunt_handoff_refuses_conflicting_benchmark_destination(tmp_path: Path) -> None:
    source = tmp_path / "producer"
    destination = tmp_path / "benchmark-v2"
    context, changes = _raw_hunt_run(source)
    hunt_handoff.persist_hunt_runner_records(source, destination, context=context, changes=changes)
    artifact_contract.write_benchmark_artifact(destination / "handoff.json", "hunt-runner-handoff", {"producer": "conflict"}, replace=True)
    with pytest.raises(ValueError, match="conflict"):
        hunt_handoff.persist_hunt_runner_records(source, destination, context=context, changes=changes)


@pytest.mark.parametrize("mutation", ("program", "manifest", "configuration", "versions"))
def test_hunt_handoff_refuses_mixed_attempt_invariants(tmp_path: Path, mutation: str) -> None:
    source = tmp_path / "producer"
    manifest = tmp_path / "pool-fixture.toml"
    manifest.write_text("status = 'fixture'\n")
    _context, _changes = _raw_hunt_run(source)
    path = next(candidate for candidate in source.glob("*.json") if "artifact_id" in candidate.read_text())
    original = RunArtifact.read(path)
    values = {
        "program_id": original.program_id,
        "schema_version": original.schema_version,
        "mask": tuple(original.mask),
        "data_digests": dict(original.data_digests),
        "configurations": list(original.configurations),
        "usage": {**original.usage, "calls": 2.0},
        "versions": dict(original.versions),
        "created": "2026-11-02T00:00:01+00:00",
    }
    if mutation == "program":
        values["program_id"] = "f" * 64
    elif mutation == "manifest":
        values["data_digests"] = {"manifest": "f" * 64}
    elif mutation == "configuration":
        values["configurations"] = [{"only": "ordinary", "slice": "1", "changes": 1}]
    else:
        values["versions"] = {"dspy": "different"}
    RunArtifact(**values).write(source, reserve_attempt=True)

    with pytest.raises(ValueError, match="invariant"):
        hunt_handoff.discover_hunt_runner_context(
            source,
            manifest,
            producer=hunt_handoff.HUNT_RUNNER_PRODUCER,
            freeze_digest="e" * 64,
        )


@pytest.mark.parametrize("attempt_ordinal", (-1, 0, 1, True, 1.5))
def test_hunt_handoff_refuses_nonpositive_or_duplicate_attempt_ordinals(tmp_path: Path, attempt_ordinal: int) -> None:
    source = tmp_path / "producer"
    context, changes = _raw_hunt_run(source)
    path = next(candidate for candidate in source.glob("*.json") if "artifact_id" in candidate.read_text())
    original = RunArtifact.read(path)
    duplicate = RunArtifact(
        program_id=original.program_id,
        schema_version=original.schema_version,
        mask=tuple(original.mask),
        data_digests=dict(original.data_digests),
        configurations=list(original.configurations),
        usage={**original.usage, "calls": 2.0},
        versions=dict(original.versions),
        created="2026-11-02T00:00:01+00:00",
        attempt_ordinal=attempt_ordinal,
    )
    duplicate.write(source)
    artifact_ids = tuple(sorted((original.artifact_id, duplicate.artifact_id)))

    with pytest.raises(ValueError, match="attempt ordinals"):
        hunt_handoff.read_hunt_runner_records(source, context=replace(context, artifact_ids=artifact_ids), changes=changes)


@pytest.mark.parametrize(("attempt_ordinal", "accepted"), ((MAX_ATTEMPT_ORDINAL, True), (MAX_ATTEMPT_ORDINAL + 1, False)))
def test_hunt_handoff_enforces_maximum_attempt_ordinal(tmp_path: Path, attempt_ordinal: int, accepted: bool) -> None:
    source = tmp_path / "producer"
    context, changes = _raw_hunt_run(source)
    path = next(candidate for candidate in source.glob("*.json") if "artifact_id" in candidate.read_text())
    original = RunArtifact.read(path)
    additional = RunArtifact(
        program_id=original.program_id,
        schema_version=original.schema_version,
        mask=tuple(original.mask),
        data_digests=dict(original.data_digests),
        configurations=list(original.configurations),
        usage={**original.usage, "calls": 2.0},
        versions=dict(original.versions),
        created="2026-11-02T00:00:01+00:00",
        attempt_ordinal=attempt_ordinal,
    )
    additional.write(source)
    artifact_ids = tuple(sorted((original.artifact_id, additional.artifact_id)))
    bound_context = replace(context, artifact_ids=artifact_ids)

    if accepted:
        assert hunt_handoff.read_hunt_runner_records(source, context=bound_context, changes=changes)
    else:
        with pytest.raises(ValueError, match="attempt ordinals"):
            hunt_handoff.read_hunt_runner_records(source, context=bound_context, changes=changes)


def test_score_reader_has_no_external_adoption_escape_hatch(tmp_path: Path) -> None:
    path = tmp_path / "raw.json"
    _rewrite(path, [{"id": "one"}])
    with pytest.raises(TypeError, match="adopt_external"):
        score.load_records(path, adopt_external=True)
