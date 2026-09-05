"""corpus-seeded-mechanisms task 4.2: the improve loop admits mechanisms that recover holdout pairs and retracts leakers."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.benchmark import ExpectedFinding, load_benchmark_manifest
from openultrasast.pairs import PairCase
from openultrasast.ruleset import PatternRule, write_ruleset
from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
from openultrasast.semantic.variants import Shape

EXEC_VULN = (
    "import sqlite3\n\n\ndef lookup(user):\n    c = sqlite3.connect('x').cursor()\n"
    + "    c.execute('SELECT * FROM t WHERE u = ' + user)\n"
)
EXEC_FIX = (
    "import sqlite3\n\n\ndef lookup(user):\n    c = sqlite3.connect('x').cursor()\n"
    + "    c.execute('SELECT * FROM t WHERE u = ?', (user,))\n"
)
SYS_VULN = "import os\n\n\ndef ping(host):\n    os.system('ping ' + host)\n"
SYS_LEAKY_FIX = (
    "import os\n\n\ndef ping(host):\n    log(host)\n    os.system('ping ' + host)\n"  # the 'fix' still calls the sink: a leaking shape
)


def _shape(sink: str, guard: str = "none") -> Shape:
    return Shape(
        language="python",
        sink_name=sink,
        arity=1,
        source_positions=(0,),
        source_kinds=("parameter",),
        guard=guard,
        mechanism="source_reaches_sink",
    )


def _pair(tmp_path: Path, name: str, vuln: str, fixed: str, *, function: str, cwe: str, provenance: str = "human") -> PairCase:
    (tmp_path / f"{name}-v.py").write_text(vuln)
    (tmp_path / f"{name}-f.py").write_text(fixed)
    return PairCase(
        name=name,
        slice="github",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}-v.py",
        fixed_file=tmp_path / f"{name}-f.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe=cwe, vulnerability_class="x", path="app.py", evidence="", function=function, mechanism="source_reaches_sink"
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        provenance=provenance,
        split="holdout",
        review_tier="reviewed",
        reviewer="t",
    )


def _round_env(tmp_path: Path) -> dict[str, object]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\n")
    rd = tmp_path / "ruleset" / "python"
    write_ruleset(
        rd / "rules.toml",
        [PatternRule(rule_id="good-eval", title="e", languages=("python",), cwe="CWE-95", tags=("injection",), pattern=r"\beval\s*\(")],
    )
    manifest_path = tmp_path / "bench.toml"
    manifest_path.write_text(
        'name = "t"\nlanguage = "python_web"\n\n[source]\npath = "repo"\n\n'
        '[[expected]]\ncwe = "CWE-95"\nclass = "code injection"\npath = "app.py"\n'
        'line = 2\nrule_id = "good-eval"\nsink = "eval"\nevidence = "eval executes input"\n'
    )
    return {"target": repo, "manifest": load_benchmark_manifest(manifest_path), "ruleset_dir": tmp_path / "ruleset"}


def test_proposer_admits_recovering_records_and_retracts_leakers(tmp_path: Path) -> None:
    from openultrasast.improve.evolve import evaluate_mechanism_profiles, propose_mechanism_edits

    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    exec_record = append_from_pair(
        candidates, _shape("execute"), summary="s", cwe="CWE-89", pair="teacher-a", provenance="human", tier="seeded"
    )
    sys_record = append_from_pair(
        candidates, _shape("system"), summary="s", cwe="CWE-78", pair="teacher-b", provenance="human", tier="seeded"
    )
    holdout = [
        _pair(tmp_path, "x", EXEC_VULN, EXEC_FIX, function="lookup", cwe="CWE-89"),
        _pair(tmp_path, "y", SYS_VULN, SYS_LEAKY_FIX, function="ping", cwe="CWE-78", provenance="agent"),
    ]
    scan_store = tmp_path / "scan" / "mechanisms.jsonl"
    edits = propose_mechanism_edits(holdout, candidates, scan_store)
    assert [(e.action, e.mechanism_id) for e in edits] == [("admit", exec_record.id)]  # sys leaks on y's fixed side: never proposed
    assert "x" in edits[0].rationale
    # once a leaking record is admitted (by a human or an earlier round), the proposer asks to retract it
    from openultrasast.improve.validator import MechanismEdit, apply_mechanism_edits

    apply_mechanism_edits([MechanismEdit(action="admit", mechanism_id=sys_record.id)], candidates, scan_store)
    edits = propose_mechanism_edits(holdout, candidates, scan_store)
    assert ("retract", sys_record.id) in [(e.action, e.mechanism_id) for e in edits]
    profiles = evaluate_mechanism_profiles(holdout, scan_store)
    assert profiles["agent"]["pairs"] == 1.0 and profiles["agent"]["pair_correct"] == 0.0  # y: detected but leaked


def test_round_accepts_a_recovering_admission_and_rejects_a_leaking_one_byte_for_byte(tmp_path: Path) -> None:
    from openultrasast.improve.evolve import run_round
    from openultrasast.improve.validator import MechanismEdit

    env = _round_env(tmp_path)
    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    exec_record = append_from_pair(
        candidates, _shape("execute"), summary="s", cwe="CWE-89", pair="teacher-a", provenance="human", tier="seeded"
    )
    sys_record = append_from_pair(
        candidates, _shape("system"), summary="s", cwe="CWE-78", pair="teacher-b", provenance="human", tier="seeded"
    )
    holdout = [
        _pair(tmp_path, "x", EXEC_VULN, EXEC_FIX, function="lookup", cwe="CWE-89"),
        _pair(tmp_path, "y", SYS_VULN, SYS_LEAKY_FIX, function="ping", cwe="CWE-78"),
    ]
    scan_store = tmp_path / "scan" / "mechanisms.jsonl"
    ledger = tmp_path / "rule_policy.json"
    journal = tmp_path / "journal.json"
    outcome = run_round(
        env["target"],
        env["manifest"],
        ledger_path=ledger,
        journal_path=journal,
        ruleset_dir=env["ruleset_dir"],  # type: ignore[arg-type]
        pair_cases=holdout,
        min_holdout_pairs=1,
        mechanism_candidates=candidates.log_path,
        mechanism_store=scan_store,
    )
    assert outcome.accepted and outcome.reason == "accepted"
    assert [r.id for r in MechanismStore(scan_store).load()] == [exec_record.id]
    entry = json.loads(journal.read_text())[0]
    mech_edits = [e for e in entry["edits"] if e["lever"] == "mechanisms"]
    assert mech_edits and mech_edits[0]["mechanism_id"] == exec_record.id and mech_edits[0]["pairs"] == ["teacher-a"]
    assert entry["mechanisms_before"]["human"]["pair_correct"] == 0.0 and entry["mechanisms_after"]["human"]["pair_correct"] == 1.0
    before = scan_store.read_bytes()
    forced = run_round(
        env["target"],
        env["manifest"],
        ledger_path=ledger,
        journal_path=journal,
        ruleset_dir=env["ruleset_dir"],  # type: ignore[arg-type]
        pair_cases=holdout,
        min_holdout_pairs=1,
        mechanism_candidates=candidates.log_path,
        mechanism_store=scan_store,
        scripted_mechanism_edits=[MechanismEdit(action="admit", mechanism_id=sys_record.id, source="export", rationale="scripted")],
    )
    assert not forced.accepted and forced.reason.startswith("mechanism_leak") or forced.reason.startswith("profile_regression")
    assert scan_store.read_bytes() == before  # byte-for-byte revert
