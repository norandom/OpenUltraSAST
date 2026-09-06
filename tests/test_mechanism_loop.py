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
    assert not forced.accepted and (forced.reason.startswith("mechanism_leak") or forced.reason.startswith("profile_regression"))
    assert scan_store.read_bytes() == before  # byte-for-byte revert


def test_no_gain_admission_is_rejected_and_reverted_mechanism_edits_are_not_reproposed(tmp_path: Path) -> None:
    from openultrasast.improve.evolve import run_round
    from openultrasast.improve.journal import reverted_edit_keys
    from openultrasast.improve.validator import MechanismEdit

    env = _round_env(tmp_path)
    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    unrelated = append_from_pair(
        candidates, _shape("popen"), summary="s", cwe="CWE-78", pair="teacher-c", provenance="human", tier="seeded"
    )
    holdout = [_pair(tmp_path, "x", EXEC_VULN, EXEC_FIX, function="lookup", cwe="CWE-89")]
    scan_store = tmp_path / "scan" / "mechanisms.jsonl"
    ledger = tmp_path / "rule_policy.json"
    journal = tmp_path / "journal.json"
    kwargs: dict[str, object] = {
        "ledger_path": ledger,
        "journal_path": journal,
        "ruleset_dir": env["ruleset_dir"],
        "pair_cases": holdout,
        "min_holdout_pairs": 1,
        "mechanism_candidates": candidates.log_path,
        "mechanism_store": scan_store,
    }
    edit = MechanismEdit(action="admit", mechanism_id=unrelated.id, source="export", rationale="scripted: recovers nothing")
    outcome = run_round(env["target"], env["manifest"], scripted_mechanism_edits=[edit], **kwargs)  # type: ignore[arg-type]
    assert not outcome.accepted and outcome.reason == "mechanism_no_gain"
    assert not scan_store.exists() or scan_store.read_bytes() == b""
    assert edit.key() in reverted_edit_keys(__import__("json").loads(journal.read_text()))
    # the same reverted edit, offered again with a rationale, is filtered before validation (novelty gate)
    again = run_round(env["target"], env["manifest"], scripted_mechanism_edits=[edit], **kwargs)  # type: ignore[arg-type]
    assert again.reason == "no_proposals" and again.mechanism_edits == []


def _holdout_catalog(tmp_path: Path) -> Path:
    """A train pair to teach and a holdout pair to recover.

    The catalog used to hold the holdout pair alone, so the only shape available was the one that pair
    taught about itself; learning-harness Req 5.1 refuses that, and rightly.
    """
    (tmp_path / "x-v.py").write_text(EXEC_VULN)
    (tmp_path / "x-f.py").write_text(EXEC_FIX)
    (tmp_path / "t-v.py").write_text(EXEC_VULN.replace("lookup", "search").replace("u = ", "name = "))
    (tmp_path / "t-f.py").write_text(EXEC_FIX.replace("lookup", "search").replace("u = ", "name = "))
    row = (
        '[[pair]]\nname = "{name}"\nslice = "github"\nlanguage = "python"\nvuln = "{name[0]}-v.py"\nfixed = "{name[0]}-f.py"\n'
        'relpath = "app.py"\nsplit = "{split}"\nreview_tier = "reviewed"\nreviewer = "t"\n\n'
        '[[pair.expected]]\ncwe = "CWE-89"\nclass = "sql injection"\npath = "app.py"\nfunction = "{function}"\n'
        'sink = "execute"\nmechanism = "source_reaches_sink"\n'
    )
    catalog = tmp_path / "pairs.toml"
    catalog.write_text(
        row.replace("{name}", "x").replace("{name[0]}", "x").replace("{split}", "holdout").replace("{function}", "lookup")
        + "\n"
        + row.replace("{name}", "t").replace("{name[0]}", "t").replace("{split}", "train").replace("{function}", "search")
    )
    return catalog


def test_ousast_improve_admits_candidates_into_the_scan_store_by_default(tmp_path: Path) -> None:
    """Req 5: the lever is reachable from the operator command; export -> candidates -> improve -> mechanisms.jsonl the scan reads."""
    from openultrasast.cli import main

    env = _round_env(tmp_path)
    repo = Path(str(env["target"]))
    calibration = repo / ".openultrasast" / "calibration"
    candidates = MechanismStore(calibration / "mechanism-candidates.jsonl")
    exec_record = append_from_pair(
        candidates, _shape("execute"), summary="s", cwe="CWE-89", pair="teacher-a", provenance="human", tier="seeded"
    )
    catalog = _holdout_catalog(tmp_path)
    manifest = tmp_path / "bench.toml"
    assert (
        main(
            ["improve", str(manifest), "--ruleset-dir", str(env["ruleset_dir"]), "--pair-catalog", str(catalog), "--min-holdout-pairs", "1"]
        )
        == 0
    )
    admitted = MechanismStore(calibration / "mechanisms.jsonl").load()
    assert [r.id for r in admitted] == [exec_record.id]
    journal = json.loads((calibration / "improve_journal.json").read_text())
    assert any(e["lever"] == "mechanisms" and e["mechanism_id"] == exec_record.id for entry in journal for e in entry["edits"])


def test_run_improvement_threads_mechanism_paths(tmp_path: Path) -> None:
    from openultrasast.improve.evolve import run_improvement
    from openultrasast.pairs import load_pair_catalog

    env = _round_env(tmp_path)
    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    exec_record = append_from_pair(
        candidates, _shape("execute"), summary="s", cwe="CWE-89", pair="teacher-a", provenance="human", tier="seeded"
    )
    cases = load_pair_catalog(_holdout_catalog(tmp_path))
    scan_store = tmp_path / "scan" / "mechanisms.jsonl"
    outcomes = run_improvement(
        env["target"],
        env["manifest"],
        ledger_path=tmp_path / "ledger.json",
        journal_path=tmp_path / "journal.json",  # type: ignore[arg-type]
        ruleset_dir=env["ruleset_dir"],
        pair_cases=cases,
        min_holdout_pairs=1,  # type: ignore[arg-type]
        mechanism_candidates=candidates.log_path,
        mechanism_store=scan_store,
        max_rounds=3,
    )
    assert any(o.accepted and o.mechanism_edits for o in outcomes)
    assert [r.id for r in MechanismStore(scan_store).load()] == [exec_record.id]
    assert outcomes[-1].reason == "no_proposals"  # converges once the candidate is admitted


def _cli_env(tmp_path: Path) -> tuple[dict[str, object], Path, Path]:
    env = _round_env(tmp_path)
    calibration = Path(str(env["target"])) / ".openultrasast" / "calibration"
    candidates = MechanismStore(calibration / "mechanism-candidates.jsonl")
    append_from_pair(candidates, _shape("execute"), summary="s", cwe="CWE-89", pair="teacher-a", provenance="human", tier="seeded")
    return env, calibration, _holdout_catalog(tmp_path)


def test_dry_run_and_no_mechanisms_never_write_the_scan_store(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    from openultrasast.cli import main

    env, calibration, catalog = _cli_env(tmp_path)
    base = [
        "improve",
        str(tmp_path / "bench.toml"),
        "--ruleset-dir",
        str(env["ruleset_dir"]),
        "--pair-catalog",
        str(catalog),
        "--min-holdout-pairs",
        "1",
    ]
    assert main([*base, "--dry-run"]) == 0
    assert not (calibration / "mechanisms.jsonl").exists()  # a dry run mutates nothing under the target
    assert main([*base, "--no-mechanisms"]) == 0
    assert not (calibration / "mechanisms.jsonl").exists()
    (calibration / "mechanism-candidates.jsonl").unlink()
    capsys.readouterr()  # the dry run legitimately reports its scratch admission; judge only the candidate-less round below
    assert main(base) == 0
    assert not (calibration / "mechanisms.jsonl").exists()  # no candidates file: the lever is inert, the round is a plain rule round
    out = capsys.readouterr().out
    assert "admit " not in out and "retract " not in out


def test_documented_default_flow_connects_export_to_improve(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    """README flow: `ousast mechanisms export` (cwd default) then `ousast improve --pair-catalog` admits into the target's store."""
    from openultrasast.cli import main

    env = _round_env(tmp_path)
    catalog = _holdout_catalog(tmp_path)
    monkeypatch.chdir(tmp_path)
    # export a candidates file exactly as documented (cwd default), seeded from a tiny trusted catalog of our own
    assert main(["mechanisms", "export", "--catalog", str(catalog), "--slice", "all"]) == 0
    exported = tmp_path / ".openultrasast" / "calibration" / "mechanism-candidates.jsonl"
    assert exported.is_file() and not (tmp_path / ".openultrasast" / "calibration" / "mechanisms.jsonl").exists()
    # the target is a different directory (the benchmark fixture); improve must still find the cwd candidates by default
    assert (
        main(
            ["improve", "bench.toml", "--ruleset-dir", str(env["ruleset_dir"]), "--pair-catalog", str(catalog), "--min-holdout-pairs", "1"]
        )
        == 0
    )
    target_store = Path(str(env["target"])) / ".openultrasast" / "calibration" / "mechanisms.jsonl"
    assert MechanismStore(target_store).load()  # admitted where the scan of that target reads
    out = capsys.readouterr().out
    assert "admit corpus:" in out  # the accepted round names its mechanism edits
