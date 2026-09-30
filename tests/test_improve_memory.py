"""Proposals from plane memory (harnessx-removal task 3, design section 5): rules M1/M2, the advisory M3 signal,
the train-on-test guard, provenance, and the unchanged default `improve`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from openultrasast.benchmark import load_benchmark_manifest
from openultrasast.cli import main
from openultrasast.improve import EvolveValidator, RuleStatusEdit, run_round
from openultrasast.improve.memory import (
    SIDECAR,
    Guard,
    MemoryProposal,
    disputed_families,
    outcome_of,
    outcome_rows,
    propose_from_memory,
    read_sidecar,
)
from openultrasast.pairs import PairCase
from openultrasast.plane.memory import FileStore, Record, row_id
from openultrasast.ruleset import PatternRule, read_rule_ledger, write_ruleset

P = {name: ch * 40 for name, ch in (("a", "a"), ("b", "b"), ("c", "c"), ("f", "f"))}
NO_GUARD = Guard()


def _rule(rule_id: str, pattern: str = r"\bexec\s*\(", status: str = "enabled") -> PatternRule:
    return PatternRule(
        rule_id=rule_id, title=rule_id, languages=("python",), cwe="CWE-95", tags=("injection",), pattern=pattern, status=status
    )


def _row(kind: str, repo: str, pin: str, subject: str, population: str = "dev", **fields: Any) -> dict[str, Any]:
    return {
        "id": row_id(kind, "run-1", f"{repo}-task", subject), "kind": kind, "repo": f"github.com/o/{repo}", "pin": pin,
        "run": "run-1", "task": f"{repo}-task", "population": population, "split": "validation", "image": "sha256:x", **fields,
    }  # fmt: skip


def verdict(repo: str, pin: str, fn: str, final: str, site_match: bool | None = None, **kw: Any) -> dict[str, Any]:
    cand = f"app.py::{fn}"
    return _row("verdict", repo, pin, cand, candidate=cand, family="injection", final=final, site_match=site_match, **kw)


def alert(rule: str, repo: str, pin: str, fn: str, role: str = "vulnerable", status: str = "enabled", **kw: Any) -> dict[str, Any]:
    fields = {"rule_id": rule, "rule_status": status, "path": "app.py", "line": 3, "function": fn, "pin_role": role}
    return _row("alert", repo, pin, f"{rule}:{fn}:{role}", **fields, **kw)


def recs(rows: list[dict[str, Any]]) -> list[Record]:
    return [Record(r, f"repos/{r['repo']}/{r['pin']}.jsonl", None) for r in rows]


def propose(rows: list[dict[str, Any]], rules: list[PatternRule], guard: Guard = NO_GUARD, ledger: Any = None) -> list[MemoryProposal]:
    return propose_from_memory(recs(rows), {r.rule_id: r for r in rules}, ledger or {}, [], excluded=guard)


def false_alerts(rule: str = "noisy", repos: tuple[str, ...] = ("r1", "r1", "r2"), population: str = "dev") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i, repo in enumerate(repos):
        rows.append(verdict(repo, P["a"], f"f{i}", "rejected", population=population))
        rows.append(alert(rule, repo, P["a"], f"f{i}", population=population))
    return rows


# ---- M1: repeated false alerts -------------------------------------------------------------------------------------


def test_m1_demotes_a_rule_with_false_alerts_across_repositories() -> None:
    [proposal] = propose(false_alerts(), [_rule("noisy")])
    assert (proposal.edit.from_status, proposal.edit.to_status) == ("enabled", "shadow")
    assert proposal.edit.rationale == f"memory:{proposal.proposal_id}"
    assert proposal.provenance["rule"] == "M1"
    assert proposal.provenance["counts"] == {"false_alerts": 3, "repos": 2, "agreed_hits": 0}
    assert len(proposal.provenance["evidence"]) == 6  # three alerts and the three rejected verdicts they sit at


@pytest.mark.parametrize("repos", [("r1", "r2"), ("r1", "r1", "r1")], ids=["two-alerts", "one-repository"])
def test_m1_stays_silent_below_threshold(repos: tuple[str, ...]) -> None:
    assert propose(false_alerts(repos=repos), [_rule("noisy")]) == []


def test_m1_never_demotes_a_rule_with_an_agreed_hit() -> None:
    rows = false_alerts() + [verdict("r3", P["b"], "hit", "agreed"), alert("noisy", "r3", P["b"], "hit")]
    assert propose(rows, [_rule("noisy")]) == []
    site = false_alerts() + [verdict("r3", P["b"], "site", "rejected", site_match=True), alert("noisy", "r3", P["b"], "site")]
    assert propose(site, [_rule("noisy")]) == []


def test_m1_counts_fixed_pin_alerts_in_the_fix_range_and_ignores_disputes() -> None:
    rows = [
        verdict("r1", P["a"], "sink", "agreed", site_match=True),
        verdict("r2", P["b"], "sink", "agreed", site_match=True),
        alert("noisy", "r1", P["f"], "sink", role="fixed"),  # the declared site's function on the fixed pin
        alert("noisy", "r2", P["f"], "sink", role="fixed"),
        alert("noisy", "r2", P["c"], "other", role="fixed", in_fix_range=True),
        verdict("r1", P["a"], "maybe", "disputed"),
        alert("noisy", "r1", P["a"], "maybe"),  # disputed: evidence in neither direction
    ]
    [proposal] = propose(rows, [_rule("noisy")])
    assert proposal.provenance["counts"]["false_alerts"] == 3


def test_m1_skips_rules_the_ruleset_does_not_know_or_that_are_not_enabled() -> None:
    assert propose(false_alerts(rule="ghost"), [_rule("noisy")]) == []
    assert propose(false_alerts(), [_rule("noisy")], ledger={"noisy": {"status": "shadow"}}) == []


# ---- M2: missed declared sites -------------------------------------------------------------------------------------


def site_hits(rule: str = "quiet") -> list[dict[str, Any]]:
    return [
        verdict("r1", P["a"], "s1", "agreed", site_match=True),
        verdict("r2", P["b"], "s2", "agreed", site_match=True),
        alert(rule, "r1", P["a"], "s1", status="shadow"),
        alert(rule, "r2", P["b"], "s2", status="shadow"),
    ]


def test_m2_promotes_a_shadow_rule_that_hits_declared_sites_nothing_else_catches() -> None:
    [proposal] = propose(site_hits(), [_rule("quiet", status="shadow"), _rule("other")])
    assert (proposal.edit.from_status, proposal.edit.to_status, proposal.provenance["rule"]) == ("shadow", "enabled", "M2")
    assert proposal.provenance["counts"]["site_hits"] == 2


def test_m2_stays_silent_below_threshold_or_when_already_caught() -> None:
    rules = [_rule("quiet", status="shadow"), _rule("other")]
    assert propose(site_hits()[:3], rules) == []  # one hit
    assert propose([*site_hits(), alert("other", "r1", P["a"], "s1")], rules) == []  # an enabled rule catches s1


def test_m2_stays_silent_on_a_fixed_pin_alert_or_rejected_candidates() -> None:
    rules = [_rule("quiet", status="shadow")]
    assert propose([*site_hits(), alert("quiet", "r1", P["f"], "s1", role="fixed", status="shadow")], rules) == []
    rejected = [
        verdict("r3", P["c"], "x1", "rejected"),
        verdict("r3", P["c"], "x2", "rejected"),
        alert("quiet", "r3", P["c"], "x1", status="shadow"),
        alert("quiet", "r3", P["c"], "x2", status="shadow"),
    ]
    assert propose([*site_hits(), *rejected[::2]], rules) != []  # one rejected alert is tolerated
    assert propose([*site_hits(), *rejected], rules) == []


# ---- coverage: no rule could fire, so no evidence either way -------------------------------------------------------


def covered(repo: str, pin: str, kind: str, language: str = "python", role: str = "vulnerable") -> dict[str, Any]:
    return _row("coverage", repo, pin, f"{language}:{role}:{kind}", language=language, coverage=kind, files=3, pin_role=role)


def test_m1_skips_a_repository_and_pin_whose_coverage_for_the_rules_language_is_none() -> None:
    blind = [*false_alerts(), covered("r2", P["a"], "none")]
    assert propose(blind, [_rule("noisy")]) == [], "r2's alert could not be evidence: one repository is left"
    wider = [*false_alerts(repos=("r1", "r1", "r2", "r3")), covered("r3", P["a"], "none")]
    [proposal] = propose(wider, [_rule("noisy")])
    assert proposal.provenance["counts"] == {"false_alerts": 3, "repos": 2, "agreed_hits": 0}
    assert proposal.provenance["excluded"]["coverage_none"] == {f"github.com/o/r3@{P['a']}": 1}


def test_coverage_none_of_another_language_or_beside_engine_coverage_is_no_skip() -> None:
    other = [*false_alerts(), covered("r2", P["a"], "none", language="php")]
    assert len(propose(other, [_rule("noisy")])) == 1, "the rule's language (python) was covered there"
    engine = [*false_alerts(), covered("r2", P["a"], "none"), covered("r2", P["a"], "engine")]
    assert len(propose(engine, [_rule("noisy")])) == 1, "a later run covered the pin: its alerts are evidence"


def test_m2_skips_a_blind_repository_and_pin() -> None:
    rules = [_rule("quiet", status="shadow"), _rule("other")]
    assert propose([*site_hits(), covered("r2", P["b"], "none")], rules) == []


# ---- M3: advisory only ---------------------------------------------------------------------------------------------


def test_disputed_families_are_advisory_and_never_reach_the_validator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [verdict("r1", P["a"], f"d{i}", "disputed" if i < 2 else "agreed") for i in range(5)]
    [signal] = disputed_families(recs(rows), NO_GUARD)
    assert signal["family"] == "injection" and signal["dispute_rate"] == 0.4
    assert disputed_families(recs(rows[1:]), NO_GUARD) == []  # four candidates: under the minimum
    assert propose(rows, [_rule("noisy")]) == []  # a dispute is no proposal

    seen: list[object] = []
    original = EvolveValidator.validate
    monkeypatch.setattr(EvolveValidator, "validate", lambda self, edit, *a: (seen.append(edit), original(self, edit, *a))[1])
    repo, rules_dir, manifest = _scaffold(tmp_path)
    [proposal] = propose(false_alerts(), [_rule("noisy")])
    run_round(
        repo, manifest, ledger_path=tmp_path / "l.json", journal_path=tmp_path / "j.json", ruleset_dir=rules_dir, proposals=[proposal]
    )
    assert seen and all(isinstance(edit, RuleStatusEdit) for edit in seen)


# ---- the train-on-test guard ---------------------------------------------------------------------------------------


def test_guard_drops_the_qualification_population_and_reports_it() -> None:
    rows = false_alerts(population="independent-v2/validation") + false_alerts(repos=("r4",), population="dev")
    guard = Guard.build(populations=["independent-v2/validation"])
    kept, excluded = guard.apply(recs(rows))
    assert len(kept) == 2 and excluded["rows"] == 6 and excluded["population"] == {"independent-v2/validation": 6}
    assert propose(rows, [_rule("noisy")], guard) == []  # the only evidence is excluded: no proposal
    assert propose(rows, [_rule("noisy")]) != []  # the same rows without the guard would propose


def test_guard_drops_holdout_pair_repositories_and_gated_cases() -> None:
    holdout = PairCase(
        name="h", slice="s", language="python", origin="o", vuln_file=Path("v"), fixed_file=Path("f"), relpath="app.py",
        expected=(), min_recall=1.0, fix_policy="silent", repo="O/R1", split="holdout",
    )  # fmt: skip
    guard = Guard.build(gated_cases=[("https://github.com/o/r2", P["a"])], holdout_pairs=[holdout])
    kept, excluded = guard.apply(recs(false_alerts()))
    assert kept == []
    assert excluded["holdout_pair"] == {f"github.com/o/r1@{P['a']}": 4}
    assert excluded["gated_case"] == {f"github.com/o/r2@{P['a']}": 2}
    [proposal] = propose(false_alerts(repos=("r1", "r2", "r3", "r3", "r4")), [_rule("noisy")], guard)
    assert {e["repo"] for e in proposal.provenance["evidence"]} == {"github.com/o/r3", "github.com/o/r4"}
    assert proposal.provenance["excluded"]["rows"] == 4


# ---- provenance, the round, and outcomes ---------------------------------------------------------------------------


def _scaffold(tmp_path: Path) -> tuple[Path, Path, Any]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\n")
    rules_dir = tmp_path / "ruleset"
    write_ruleset(rules_dir / "python" / "rules.toml", [_rule("good-eval", r"\beval\s*\("), _rule("noisy")])
    manifest = tmp_path / "bench.toml"
    manifest.write_text(
        'name = "t"\nlanguage = "python_web"\n\n[source]\npath = "repo"\n\n[[expected]]\ncwe = "CWE-95"\n'
        'class = "code injection"\npath = "app.py"\nline = 2\nrule_id = "good-eval"\nsink = "eval"\nevidence = "eval"\n'
    )
    return repo, rules_dir, load_benchmark_manifest(manifest)


def test_provenance_round_trips_journal_sidecar_store(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    store.ingest_rows("run-1", "t", false_alerts())
    records = store.rows()
    [proposal] = propose_from_memory(records, {"noisy": _rule("noisy")}, {}, [], excluded=NO_GUARD, index_digest="idx")
    repo, rules_dir, manifest = _scaffold(tmp_path)
    journal, ledger = tmp_path / "cal" / "journal.json", tmp_path / "cal" / "rule_policy.json"

    outcome = run_round(repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=rules_dir, proposals=[proposal])

    assert outcome.accepted and read_rule_ledger(ledger)["noisy"]["status"] == "shadow"
    [entry] = json.loads(journal.read_text())[0]["edits"]
    assert entry["evidence"] == proposal.proposal_id and entry["rationale"] == f"memory:{proposal.proposal_id}"
    side = read_sidecar(journal)[entry["evidence"]]
    assert side["edit_key"] == entry["key"] and side["index_digest"] == "idx" and side["round"] == 1
    by_id = {rec.row["id"]: rec for rec in records}
    for ev in side["evidence"]:  # every cited row is in the store, at the object and version recorded
        assert by_id[ev["id"]].key == ev["key"] and by_id[ev["id"]].version == ev["version"]
        assert ev["version"].startswith("sha256:")

    rows = outcome_rows(
        outcome.edits, outcome_of(outcome.reason, outcome.accepted) or "", 1, outcome.reason, {proposal.proposal_id: proposal}, "g"
    )
    store.put_rows(rows)
    back = store.rows(kind="proposal_outcome")
    assert {r.row["outcome"] for r in back} == {"accepted"} and {r.row["proposal_id"] for r in back} == {proposal.proposal_id}
    assert len(back) == 2  # one per (repository, pin) of the evidence

    again = run_round(repo, manifest, ledger_path=ledger, journal_path=journal, ruleset_dir=rules_dir, proposals=[proposal])
    assert again.reason == "no_proposals"  # the rule is shadow now: the proposal no longer applies


def test_a_reverted_memory_proposal_is_not_retried_on_the_same_evidence(tmp_path: Path) -> None:
    repo, rules_dir, manifest = _scaffold(tmp_path)
    rows = [verdict(r, P["a"], f"f{i}", "rejected") for i, r in enumerate(("r1", "r1", "r2"))]
    rows += [alert("good-eval", r, P["a"], f"f{i}") for i, r in enumerate(("r1", "r1", "r2"))]
    [proposal] = propose(rows, [_rule("good-eval", r"\beval\s*\(")])
    journal = tmp_path / "j.json"
    first = run_round(repo, manifest, ledger_path=tmp_path / "l.json", journal_path=journal, ruleset_dir=rules_dir, proposals=[proposal])
    assert first.reason == "reverted" and outcome_of(first.reason, first.accepted) == "reverted"  # shadowing drops recall
    second = run_round(repo, manifest, ledger_path=tmp_path / "l.json", journal_path=journal, ruleset_dir=rules_dir, proposals=[proposal])
    assert second.reason == "no_proposals"
    assert outcome_of("validation_failed: x", False) == "rejected" and outcome_of("no_proposals", False) is None


def test_default_round_journal_has_no_evidence_and_no_sidecar(tmp_path: Path) -> None:
    repo, rules_dir, manifest = _scaffold(tmp_path)
    (repo / "app.py").write_text("def f(x):\n    return eval(x)\ndef g(y):\n    exec(y)\n")
    journal = tmp_path / "j.json"
    outcome = run_round(repo, manifest, ledger_path=tmp_path / "l.json", journal_path=journal, ruleset_dir=rules_dir)
    assert outcome.edits  # the benchmark's own edit
    [entry] = json.loads(journal.read_text())[0]["edits"]
    assert set(entry) == {"key", "lever", "rule_id", "from", "to", "rationale"}
    assert not (tmp_path / SIDECAR).exists()


# ---- the CLI -------------------------------------------------------------------------------------------------------


def test_default_improve_output_matches_the_recorded_baseline(capsys: pytest.CaptureFixture[str]) -> None:
    root = Path(__file__).resolve().parents[1]
    baseline = root / "benchmarks/measurements/2026-09-30-harnessx-removal-baseline/improve/stdout.txt"
    manifest = "benchmarks/manifests/java-spring-boot-vulnerable.toml"
    import os

    cwd = Path.cwd()
    os.chdir(root)
    try:
        assert main(["improve", manifest, "--dry-run", "--no-pair-gate"]) == 0
    finally:
        os.chdir(cwd)
    assert capsys.readouterr().out.replace(str(root), "<ROOT>") == baseline.read_text()


def test_improve_memory_with_an_empty_store_has_no_proposals(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo, rules_dir, _ = _scaffold(tmp_path)
    store = tmp_path / "memory"
    store.mkdir()
    (store / "index.jsonl").write_text("")
    catalog = Path(__file__).resolve().parents[1] / "benchmarks/pairs/catalog.toml"
    args = ["improve", str(tmp_path / "bench.toml"), "--ruleset-dir", str(rules_dir), "--dry-run", "--pair-catalog", str(catalog)]
    assert main([*args, "--no-pair-gate", "--memory", str(store)]) == 0
    out = capsys.readouterr().out
    assert "rows=0" in out and "memory_proposals=0" in out and "round 1: no_proposals" in out
    with pytest.raises(SystemExit, match="no index.jsonl"):
        main([*args, "--memory", str(tmp_path / "absent")])
