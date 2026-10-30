# Task 12.2 (access-control-prover): record provenance, stage funnel and judgment
# transitions for the development runner (Reqs 5.1, 5.3, 5.4, 7.1, 7.6, 9.7, 11.8).

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.valid import (
    development_runner,  # noqa: E402
    run_manifests,  # noqa: E402
)

GUARDED = """class Fixture extends Descriptor<Thing> {
    public Object doTestConnection() {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return CredentialsProvider.lookupCredentials(Thing.class);
    }
}
"""

FACTS = """[[operation]]
id = "protected-read"
kind = "protected_read"
language = "java"
calls = ["lookupCredentials"]
resource_arg = 0
requires = ["path_guard"]
sensitivity = "confidential"
"""


def _commit(work: Path, text: str) -> str:
    work.mkdir(parents=True, exist_ok=True)

    def run(*args: str) -> None:
        subprocess.run(["git", *args], cwd=work, check=True, stdout=subprocess.DEVNULL)

    run("init", "-q")
    run("config", "user.email", "fixture@example.invalid")
    run("config", "user.name", "Fixture")
    (work / "Fixture.java").write_text(text, encoding="utf-8")
    run("add", "Fixture.java")
    run("commit", "-qm", "fixture")
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=work, check=True, capture_output=True, text=True).stdout.strip()


def _workdir(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    work = tmp_path / "repo"
    base = _commit(work, "class Plain {}\n")
    head = _commit(work, GUARDED)
    change: dict[str, object] = {
        "id": "change-1",
        "repo": "fixture/repo",
        "kind": "vulnerability",
        "base": base,
        "head": head,
        "files": [{"path": "Fixture.java", "head_lines": [[1, 6]]}],
        "head_lines": {2: GUARDED.splitlines()[1]},
    }
    return work, change


def _facts_file(tmp_path: Path) -> Path:
    facts = tmp_path / "facts.toml"
    facts.write_text(FACTS, encoding="utf-8")
    return facts


def _changes_as_tuple(change: dict[str, object]) -> tuple[dict[str, object], ...]:
    return (change,)


def test_development_record_carries_all_six_digests(tmp_path: Path) -> None:
    work, change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path))
    records = development_runner.run_development(bundle, work, _changes_as_tuple(change), tmp_path / "out")
    assert len(records) == 1
    record = records[0]
    assert record.change_id == "change-1"
    assert record.analyzer_revision == bundle.analyzer_revision
    assert record.fact_set_digest == bundle.fact_set_digest
    assert record.acquisition_record_digest == bundle.acquisition_record_digest
    assert record.configuration_digest == bundle.configuration_digest
    for digest in (record.population_digest, record.input_digest):
        assert len(digest) == 12


def test_stage_funnel_accounts_every_stage(tmp_path: Path) -> None:
    work, change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path))
    records = development_runner.run_development(bundle, work, _changes_as_tuple(change), tmp_path / "out")
    funnel = records[0].stage_funnel
    assert set(funnel) == {"entry_recognition", "resolution", "judgment"}
    assert funnel["entry_recognition"]["entry_points"] >= 1
    assert "stapler" in funnel["entry_recognition"]["frameworks_recognised"]
    for key in ("complete_calls", "incomplete_calls", "unresolved_calls"):
        assert key in funnel["resolution"]
    for key in ("unguarded", "discharged", "indeterminate"):
        assert key in funnel["judgment"]


def test_fixture_run_accounts_for_every_record(tmp_path: Path) -> None:
    work, change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path))
    records = development_runner.run_development(bundle, work, _changes_as_tuple(change), tmp_path / "out")
    record = records[0]
    assert record.judgment_transition == "same"
    assert record.stage_funnel["judgment"]["indeterminate"] >= 1


def test_judgment_transition_same_is_same() -> None:
    assert development_runner.judgment_transition("indeterminate", "indeterminate") == "same"


def test_judgment_transition_arrow_direction() -> None:
    assert development_runner.judgment_transition("unguarded", "discharged") == "unguarded->discharged"


def test_judgment_transition_discharged_to_indeterminate() -> None:
    assert development_runner.judgment_transition("discharged", "indeterminate") == "discharged->indeterminate"


def test_run_development_persists_json_records(tmp_path: Path) -> None:
    work, change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path))
    out_dir = tmp_path / "out"
    records = development_runner.run_development(bundle, work, _changes_as_tuple(change), out_dir)
    written = sorted(out_dir.glob("*.json"))
    assert len(written) == 1
    payload = json.loads(written[0].read_text(encoding="utf-8"))
    assert payload["change_id"] == records[0].change_id
    assert payload["analyzer_revision"] == records[0].analyzer_revision
    assert payload["stage_funnel"] == records[0].stage_funnel


def test_development_record_is_frozen(tmp_path: Path) -> None:
    work, change = _workdir(tmp_path)
    bundle = run_manifests.bundle_from(work, _facts_file(tmp_path))
    records = development_runner.run_development(bundle, work, _changes_as_tuple(change), tmp_path / "out")
    with pytest.raises(Exception):  # noqa: B017
        records[0].change_id = "changed"  # type: ignore[misc]


def test_run_development_is_deterministic_across_runs(tmp_path: Path) -> None:
    work, change = _workdir(tmp_path)
    facts = _facts_file(tmp_path)
    bundle = run_manifests.bundle_from(work, facts)
    first = development_runner.run_development(bundle, work, _changes_as_tuple(change), tmp_path / "a")
    second = development_runner.run_development(bundle, work, _changes_as_tuple(change), tmp_path / "b")

    # seconds measure wall-clock noise; determinism covers every analytic field.
    def _normalized(records: tuple[development_runner.DevelopmentRecord, ...]) -> tuple[development_runner.DevelopmentRecord, ...]:
        return tuple(development_runner.DevelopmentRecord(**{**asdict(record), "seconds": 0.0}) for record in records)

    assert _normalized(first) == _normalized(second)
