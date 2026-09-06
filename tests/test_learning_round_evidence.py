"""What a round must prove before it is kept (learning-harness review round 3, Req 4.1, 5.2, 9.5, 9.6, 9.8).

The round loop was accepting and rejecting on numbers that did not mean what their names said: the
cross-family sweep counted every failing pair rather than the pairs this change broke, unscorable rows
voted against a round they cannot judge, cost was metered once after everything had been paid for, and a
stage that raised left no record at all. Each test here fails on exactly one of those.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.findings import StaticFinding
from openultrasast.learning.detectors import FamilyConfig, write_default_configs
from openultrasast.learning.families import load_families
from openultrasast.learning.journal import Archive, LearningJournal
from openultrasast.learning.proposer import Proposal, ScriptedProposer
from openultrasast.learning.rounds import NoiseFloor, run_learning_round
from openultrasast.pairs import PairCase

VULN = "from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = "from flask import request\nimport subprocess\n\n\ndef run():\n    subprocess.run(['echo', 'x'], check=False)\n"


def _case(tmp_path: Path, name: str, *, split: str, family: str = "injection", unscorable: str | None = None) -> PairCase:
    (tmp_path / f"{name}-v.py").write_text(VULN)
    (tmp_path / f"{name}-f.py").write_text(FIXED)
    return PairCase(
        name=name,
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}-v.py",
        fixed_file=tmp_path / f"{name}-f.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="run", mechanism="other", family=family
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        split=split,
        review_tier="seeded",
        unscorable=unscorable,
    )


def _finding(family: str) -> StaticFinding:
    return StaticFinding(
        finding_id="detector:app.py:6",
        path="app.py",
        title="t",
        severity="high",
        confidence="low",
        evidence_level="suspicion",
        rationale="r",
        line=6,
        function_name="run",
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[f"family:{family}", "detector:x@0"],
        ranking_priority=0.0,
    )


def _proposal(text: str = "- ask about quoting\n") -> Proposal:
    return Proposal(hypothesis="ask about quoting", lever="checklist", change={"checklist.md": text}, predicted_affected=("train-a",))


@pytest.fixture
def world(tmp_path: Path):  # type: ignore[no-untyped-def]
    configs = tmp_path / "configs"
    write_default_configs(configs, load_families(), prompt="p", version="0")
    (configs / "injection" / "checklist.md").write_text("- old\n")
    return {
        "configs": configs,
        "cases": [_case(tmp_path, "train-a", split="train"), _case(tmp_path, "hold-a", split="holdout")],
        "journal": LearningJournal(tmp_path / "journal.jsonl"),
        "archive": Archive(tmp_path / "archive.jsonl"),
        "out": tmp_path / "out",
        "floors": {"injection": NoiseFloor(family="injection", k_runs=5, pairs=1, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0)},
        "root": tmp_path,
    }


def _run(world, proposal, build, **kwargs):  # type: ignore[no-untyped-def]
    return run_learning_round(
        world["cases"],
        family="injection",
        taxonomy=load_families(),
        configs_dir=world["configs"],
        proposer=ScriptedProposer([proposal] if proposal else []),
        scan_factory=build,
        model="m",
        journal=world["journal"],
        archive=world["archive"],
        floors=world["floors"],
        out_dir=world["out"],
        **kwargs,
    )


def _injection_improves(config: FamilyConfig):  # type: ignore[no-untyped-def]
    """Injection detects only once the proposed checklist lands; every other family finds nothing, ever."""

    def scan(root: Path) -> list[StaticFinding]:
        if root.name != "vuln" or config.family != "injection":
            return []
        return [_finding("injection")] if config.checklist.strip() == "- ask about quoting" else []

    return scan


# --- the sweep ---------------------------------------------------------------


def test_a_family_that_was_already_failing_does_not_reject_the_round(world) -> None:  # type: ignore[no-untyped-def]
    """Req 9.5 counts *negative flips*, not absolute failures.

    On the real corpus most pairs fail at round zero, so counting failures rejects every round for damage it
    did not do — and the harness then reports that it cannot improve."""
    world["cases"].append(_case(world["root"], "other-hold", split="holdout", family="access_control"))
    world["floors"]["access_control"] = NoiseFloor(
        family="access_control", k_runs=5, pairs=1, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0
    )
    record = _run(world, _proposal(), _injection_improves, sweep_families=("access_control",))
    assert record.sweep["access_control"] == 0, "access control failed before and after; this change flipped nothing"
    assert record.outcome == "accepted" and record.reason == "improved"


def test_a_family_this_change_really_broke_still_rejects_the_round(world) -> None:  # type: ignore[no-untyped-def]
    """The other arm: a pair that was correct before and is not after is a flip, and one is over the budget."""
    world["cases"].append(_case(world["root"], "other-hold", split="holdout", family="access_control"))
    world["floors"]["access_control"] = NoiseFloor(
        family="access_control", k_runs=5, pairs=1, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0
    )
    landed = {"yes": False}

    def build(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            if root.name != "vuln":
                return []
            if config.family == "access_control":
                return [] if landed["yes"] else [_finding("access_control")]
            if config.checklist.strip() == "- ask about quoting":
                landed["yes"] = True
                return [_finding("injection")]
            return []

        return scan

    record = _run(world, _proposal(), build, sweep_families=("access_control",))
    assert record.sweep["access_control"] == 1
    assert record.outcome == "rejected" and record.reason == "collateral_regression"
    assert (world["configs"] / "injection" / "checklist.md").read_text() == "- old\n"


def test_an_unscorable_row_never_votes_in_the_sweep(world) -> None:  # type: ignore[no-untyped-def]
    """Req 4.1: an unscorable row leaves every denominator, and it certainly does not reject a round."""
    world["cases"].append(_case(world["root"], "other-hold", split="holdout", family="access_control", unscorable="identical_twin"))
    world["floors"]["access_control"] = NoiseFloor(
        family="access_control", k_runs=5, pairs=0, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0
    )
    record = _run(world, _proposal(), _injection_improves, sweep_families=("access_control",))
    assert record.sweep["access_control"] == 0 and record.outcome == "accepted"


def test_attribution_names_the_pairs_this_change_flipped_and_no_others(world) -> None:  # type: ignore[no-untyped-def]
    world["cases"].append(_case(world["root"], "other-hold", split="holdout", family="access_control"))
    world["floors"]["access_control"] = NoiseFloor(
        family="access_control", k_runs=5, pairs=1, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0
    )
    _run(world, _proposal(), _injection_improves, sweep_families=("access_control",))
    attribution = json.loads((world["out"] / "rounds" / "1" / "attribution.json").read_text())
    assert attribution["flipped_predicted"] == ["hold-a", "train-a"]
    assert attribution["flipped_unpredicted"] == [], "a pair that was already failing was never flipped by this round"


# --- cost, exceptions, the archive ------------------------------------------


def test_the_cap_stops_a_round_before_it_pays_for_the_next_stage(world) -> None:  # type: ignore[no-untyped-def]
    """Req 9.8 says stop, revert and record. Metering once, after every stage, can only ever record."""
    stages: list[str] = []

    def build(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            stages.append(f"{config.family}:{root.name}")
            return []

        return scan

    spend = {"usd": 0.0}

    def spent() -> float:
        spend["usd"] += 1.0
        return spend["usd"]

    world["cases"].append(_case(world["root"], "other-hold", split="holdout", family="access_control"))
    record = _run(world, _proposal(), build, cost_cap_usd=0.5, spent_usd=spent, sweep_families=("access_control",))
    assert record.outcome == "reverted_cost" and record.reason == "cost_cap_exceeded"
    assert "access_control:vuln" not in stages, "the sweep ran after the cap was already crossed"
    assert (world["configs"] / "injection" / "checklist.md").read_text() == "- old\n"


def test_a_stage_that_raises_is_reverted_journalled_and_re_raised(world) -> None:  # type: ignore[no-untyped-def]
    """An endpoint failure mid-round is an outcome. Losing the round record loses the money it already spent."""

    def build(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            if config.checklist.strip() == "- ask about quoting":
                raise RuntimeError("endpoint said no")
            return []

        return scan

    with pytest.raises(RuntimeError, match="endpoint said no"):
        _run(world, _proposal(), build)
    assert (world["configs"] / "injection" / "checklist.md").read_text() == "- old\n"
    outcomes = [(item.outcome, item.reason) for item in world["journal"].rounds()]
    assert outcomes == [("reverted", "stage_failed")]
    assert (world["out"] / "rounds" / "1" / "scores.json").is_file()


def test_a_rejected_version_is_archived_so_a_pair_it_alone_wins_is_not_lost(world) -> None:  # type: ignore[no-untyped-def]
    """Req 9.7: per-pair winners, or the loop collapses onto one lineage and forgets what a rejected try could do.

    This round wins both of its own pairs and is still rejected, because it broke another family. Version 1 is the
    only configuration that ever got those two pairs right; dropping it because the round as a whole lost is how a
    search collapses onto one lineage."""
    world["cases"].append(_case(world["root"], "other-hold", split="holdout", family="access_control"))
    world["floors"]["access_control"] = NoiseFloor(
        family="access_control", k_runs=5, pairs=1, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0
    )
    landed = {"yes": False}

    def build(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            if root.name != "vuln":
                return []
            if config.family == "access_control":
                return [] if landed["yes"] else [_finding("access_control")]
            if config.checklist.strip() == "- ask about quoting":
                landed["yes"] = True
                return [_finding("injection")]
            return []

        return scan

    record = _run(world, _proposal(), build, sweep_families=("access_control",))
    assert record.outcome == "rejected" and record.reason == "collateral_regression"
    assert world["archive"].winners("injection") == {"train-a": "1", "hold-a": "1"}
    assert 'version = "0"' in (world["configs"] / "injection" / "family.toml").read_text(), "a rejected round is not versioned"


# --- the holdout refusal -----------------------------------------------------


def test_a_proposal_that_names_a_holdout_pair_is_refused_by_name(world) -> None:  # type: ignore[no-untyped-def]
    """Req 5.2: a candidate that touches a holdout pair is refused and the refusal names the pairs."""
    record = _run(
        world,
        Proposal(
            hypothesis="memorize the answer",
            lever="memory",
            change={"hard_negatives.jsonl": json.dumps({"pair": "hold-a", "note": "always flag"}) + "\n"},
            predicted_affected=("hold-a",),
        ),
        _injection_improves,
    )
    assert record.outcome == "refused_holdout"
    assert "hold-a" in record.reason
    assert (world["configs"] / "injection" / "hard_negatives.jsonl").read_text() == ""


def test_a_proposal_that_only_names_train_pairs_is_not_refused(world) -> None:  # type: ignore[no-untyped-def]
    record = _run(
        world,
        Proposal(
            hypothesis="remember this shape",
            lever="memory",
            change={"hard_negatives.jsonl": json.dumps({"pair": "train-a", "note": "shape"}) + "\n"},
            predicted_affected=("train-a",),
        ),
        _injection_improves,
    )
    assert record.outcome != "refused_holdout"


# --- round zero --------------------------------------------------------------


def test_round_zero_measures_each_family_with_its_own_detector(tmp_path: Path) -> None:
    """Req 8.2. One detector for every family means the generalist scores them all, and abstention earns no credit
    (`related(X, "unknown")` is lateral), so every family but `unknown` baselines at a structural zero."""
    from openultrasast.learning.rounds import run_baseline

    configs = tmp_path / "configs"
    write_default_configs(configs, load_families(), prompt="p", version="0")
    seen: list[str] = []

    def factory(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            seen.append(config.family)
            return [_finding(config.family)] if root.name == "vuln" else []

        return scan

    cases = [_case(tmp_path, "inj", split="train"), _case(tmp_path, "acl", split="train", family="access_control")]
    report = run_baseline(
        cases,
        taxonomy=load_families(),
        configs_dir=configs,
        scan_factory=factory,
        model="m",
        out_dir=tmp_path / "out",
        k_runs=3,
    )
    assert set(seen) == {"injection", "access_control"}, "each family must be measured with its own configuration"
    assert report.metrics["injection"]["recall"] == 1.0 and report.metrics["access_control"]["recall"] == 1.0


def test_round_zero_reports_each_slice_separately(tmp_path: Path) -> None:
    """Req 8.4: vibe-py and agent-vfc are different worlds; one pooled number hides which one moved."""
    from openultrasast.learning.rounds import run_baseline

    configs = tmp_path / "configs"
    write_default_configs(configs, load_families(), prompt="p", version="0")
    web = _case(tmp_path, "web", split="train")
    agent = _case(tmp_path, "agent", split="train")
    object.__setattr__(agent, "slice", "agent-vfc")

    def factory(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            return [_finding(config.family)] if root.name == "vuln" else []

        return scan

    report = run_baseline(
        [web, agent],
        taxonomy=load_families(),
        configs_dir=configs,
        scan_factory=factory,
        model="m",
        out_dir=tmp_path / "out",
        k_runs=3,
    )
    assert set(report.per_slice) == {"vibe-py/injection", "agent-vfc/injection"}
    payload = json.loads((tmp_path / "out" / "baseline" / "m" / "report.json").read_text())
    assert set(payload["per_slice"]) == {"vibe-py/injection", "agent-vfc/injection"}


def test_round_zero_refuses_fewer_than_three_runs(tmp_path: Path) -> None:
    """The floor exists because a single run misses most real changes; a baseline measured at K=1 is a noise floor
    of zero and every later round then inherits a budget of nothing."""
    from openultrasast.learning.rounds import run_baseline

    configs = tmp_path / "configs"
    write_default_configs(configs, load_families(), prompt="p", version="0")
    with pytest.raises(ValueError, match="three runs"):
        run_baseline(
            [_case(tmp_path, "inj", split="train")],
            taxonomy=load_families(),
            configs_dir=configs,
            scan_factory=lambda config: lambda root: [],
            model="m",
            out_dir=tmp_path / "out",
            k_runs=1,
        )


def test_a_round_journals_why_the_proposer_had_nothing_to_say(world) -> None:  # type: ignore[no-untyped-def]
    """`no_proposal` covers two different worlds: a proposer with nothing to add, and one that could not start.

    Measured: the meta-agent round journalled `no_proposal` while the real cause was an authentication failure in a
    provider seam pointing at the wrong vendor. A round that failed for a fixable configuration reason must not
    look identical to a model that considered the facts and declined."""

    class Mute:
        reason = "meta_agent_failed: RuntimeError"

        def propose(self, facts):  # type: ignore[no-untyped-def]
            del facts
            return None

    from openultrasast.learning.rounds import run_learning_round

    record = run_learning_round(
        world["cases"],
        family="injection",
        taxonomy=load_families(),
        configs_dir=world["configs"],
        proposer=Mute(),
        scan_factory=_injection_improves,
        model="m",
        journal=world["journal"],
        archive=world["archive"],
        floors=world["floors"],
        out_dir=world["out"],
    )
    assert record.outcome == "rejected"
    assert record.reason == "no_proposal: meta_agent_failed: RuntimeError"
