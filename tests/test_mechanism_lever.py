"""corpus-seeded-mechanisms task 4.1: the `mechanisms` lever admits or retracts exporter records, nothing else."""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
from openultrasast.semantic.variants import Shape


def _record(store: MechanismStore, **overrides: object):
    base: dict[str, object] = {
        "language": "python",
        "sink_name": "system",
        "arity": 1,
        "source_positions": (0,),
        "source_kinds": ("parameter",),
        "guard": "allowlist_test",
        "mechanism": "source_reaches_sink",
    }
    base.update(overrides)
    return append_from_pair(store, Shape(**base), summary="s", cwe="CWE-78", pair="p1", provenance="human", tier="seeded")  # type: ignore[arg-type]


def test_mechanism_edit_is_a_bounded_lever_with_a_stable_key(tmp_path: Path) -> None:
    from openultrasast.improve.validator import VALID_LEVERS, MechanismEdit

    assert "mechanisms" in VALID_LEVERS
    edit = MechanismEdit(action="admit", mechanism_id="corpus:abc", source="loo", rationale="recovers holdout pair x")
    assert edit.lever == "mechanisms" and edit.key() == "mechanisms:admit:corpus:abc"


def test_validator_accepts_only_exporter_records_with_closed_guards(tmp_path: Path) -> None:
    from openultrasast.improve.validator import EvolveValidator, MechanismEdit, StrictValidationError

    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    good = _record(candidates)
    validator = EvolveValidator()
    by_id = {record.id: record for record in candidates.load()}
    validator.validate_mechanism(MechanismEdit(action="admit", mechanism_id=good.id, source="loo"), by_id)
    validator.validate_mechanism(MechanismEdit(action="retract", mechanism_id=good.id, source="loo"), by_id)
    with pytest.raises(StrictValidationError, match="unknown mechanism"):
        validator.validate_mechanism(MechanismEdit(action="admit", mechanism_id="corpus:not-exported", source="loo"), by_id)
    with pytest.raises(StrictValidationError, match="action"):
        validator.validate_mechanism(MechanismEdit(action="rewrite", mechanism_id=good.id, source="loo"), by_id)
    with pytest.raises(StrictValidationError, match="origin"):
        from openultrasast.semantic.mechanisms import append_mechanism

        sandbox = append_mechanism(candidates, summary="s", cwe="CWE-78", language="python", tags=(), what_made_it_exploitable="x")
        validator.validate_mechanism(
            MechanismEdit(action="admit", mechanism_id=sandbox.id, source="loo"), {r.id: r for r in candidates.load()}
        )
    # free-form shapes never pass: a record whose shape text is not a closed structure is rejected before it can be admitted
    from dataclasses import replace

    forged = replace(good, shape={**(good.shape or {}), "guard": "if user not in ALLOWED"})
    with pytest.raises(StrictValidationError, match="guard"):
        validator.validate_mechanism(MechanismEdit(action="admit", mechanism_id=forged.id, source="export"), {forged.id: forged})
    forged_text = replace(good, shape={**(good.shape or {}), "sink_name": "os.system(cmd + ' ')"})
    with pytest.raises(StrictValidationError, match="identifier"):
        validator.validate_mechanism(
            MechanismEdit(action="admit", mechanism_id=forged_text.id, source="export"), {forged_text.id: forged_text}
        )


def test_apply_mechanism_edits_admits_into_the_scan_store_and_reverts_byte_for_byte(tmp_path: Path) -> None:
    from openultrasast.improve.validator import MechanismEdit, apply_mechanism_edits

    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    a = _record(candidates)
    b = _record(candidates, sink_name="popen")
    scan_store = tmp_path / "scan" / "mechanisms.jsonl"
    scan_store.parent.mkdir()
    scan_store.write_text("")
    before = scan_store.read_bytes()
    snapshot = apply_mechanism_edits([MechanismEdit(action="admit", mechanism_id=a.id, source="loo")], candidates, scan_store)
    admitted = MechanismStore(scan_store).load()
    assert [r.id for r in admitted] == [a.id] and admitted[0].origin == "corpus"
    apply_mechanism_edits([MechanismEdit(action="retract", mechanism_id=a.id, source="loo")], candidates, scan_store)
    assert MechanismStore(scan_store).load() == ()  # retraction is a tombstone row; load() folds it away
    snapshot.restore()
    assert scan_store.read_bytes() == before  # byte-for-byte revert of the whole round
    assert b.id != a.id


def test_retract_is_allowed_for_an_admitted_record_that_left_the_candidate_set(tmp_path: Path) -> None:
    from openultrasast.improve.validator import EvolveValidator, MechanismEdit, StrictValidationError

    scan = MechanismStore(tmp_path / "scan.jsonl")
    stale = _record(scan, sink_name="popen")
    validator = EvolveValidator()
    with pytest.raises(StrictValidationError, match="unknown mechanism"):
        validator.validate_mechanism(MechanismEdit(action="admit", mechanism_id=stale.id), {}, admitted={stale.id: stale})
    validator.validate_mechanism(MechanismEdit(action="retract", mechanism_id=stale.id), {}, admitted={stale.id: stale})


def test_export_defaults_to_a_candidates_file_and_never_writes_the_scan_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    from contextlib import redirect_stdout

    from openultrasast.cli import main

    monkeypatch.chdir(tmp_path)
    (tmp_path / "benchmarks").symlink_to(Path(__file__).resolve().parents[1] / "benchmarks")
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["mechanisms", "export", "--slice", "vibe-py", "--json"]) == 0
    payload = __import__("json").loads(buf.getvalue())
    assert payload["store"].endswith("mechanism-candidates.jsonl")
    assert not (tmp_path / ".openultrasast" / "calibration" / "mechanisms.jsonl").exists()
