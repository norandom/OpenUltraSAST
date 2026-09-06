"""learning-harness task 3.7: one evolve round, end to end (offline)."""

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
from openultrasast.learning.rounds import NoiseFloor
from openultrasast.pairs import PairCase

VULN = "from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = "from flask import request\nimport subprocess\n\n\ndef run():\n    subprocess.run(['echo', 'x'], check=False)\n"


def _case(tmp_path: Path, name: str, *, split: str, family: str = "injection") -> PairCase:
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


def _factory(finds: dict[str, bool]):  # type: ignore[no-untyped-def]
    """A detector whose behaviour depends on the configuration version it was built from."""

    def build(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            if root.name != "vuln":
                return []
            return [_finding(config.family)] if finds.get(config.checklist.strip(), False) else []

        return scan

    return build


def _proposal(text: str) -> Proposal:
    return Proposal(hypothesis="ask about quoting", lever="checklist", change={"checklist.md": text}, predicted_affected=("injection",))


@pytest.fixture
def world(tmp_path: Path):  # type: ignore[no-untyped-def]
    configs = tmp_path / "configs"
    write_default_configs(configs, load_families(), prompt="p", version="0")
    (configs / "injection" / "checklist.md").write_text("- old\n")
    cases = [_case(tmp_path, "train-a", split="train"), _case(tmp_path, "hold-a", split="holdout")]
    return {
        "configs": configs,
        "cases": cases,
        "journal": LearningJournal(tmp_path / "journal.jsonl"),
        "archive": Archive(tmp_path / "archive.jsonl"),
        "out": tmp_path / "out",
        "floors": {"injection": NoiseFloor(family="injection", k_runs=5, pairs=1, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0)},
    }


def _run(world, proposal: Proposal | None, finds: dict[str, bool], **kwargs):  # type: ignore[no-untyped-def]
    from openultrasast.learning.rounds import run_learning_round

    return run_learning_round(
        world["cases"],
        family="injection",
        taxonomy=load_families(),
        configs_dir=world["configs"],
        proposer=ScriptedProposer([proposal] if proposal else []),
        scan_factory=_factory(finds),
        model="m",
        journal=world["journal"],
        archive=world["archive"],
        floors=world["floors"],
        out_dir=world["out"],
        **kwargs,
    )


def test_a_change_that_helps_is_accepted_versioned_and_journalled(world) -> None:  # type: ignore[no-untyped-def]
    record = _run(world, _proposal("- ask about quoting\n"), {"- ask about quoting": True})
    assert record.outcome == "accepted" and record.family == "injection"
    assert record.target_train_delta > 0 and record.target_holdout_delta > 0
    assert (world["configs"] / "injection" / "checklist.md").read_text() == "- ask about quoting\n"
    assert 'version = "1"' in (world["configs"] / "injection" / "family.toml").read_text()
    assert [item.outcome for item in world["journal"].rounds()] == ["accepted"]
    assert world["archive"].winners("injection")


def test_a_change_that_helps_nothing_is_rejected_and_reverted(world) -> None:  # type: ignore[no-untyped-def]
    record = _run(world, _proposal("- useless\n"), {})
    assert record.outcome == "rejected" and record.reason == "tie"
    assert (world["configs"] / "injection" / "checklist.md").read_text() == "- old\n"
    assert 'version = "0"' in (world["configs"] / "injection" / "family.toml").read_text()
    assert world["journal"].rejected_buffer("injection") == ("ask about quoting",)


def test_a_round_is_rejected_when_the_sweep_finds_another_family_below_its_floor(world) -> None:  # type: ignore[no-untyped-def]
    """The sweep is a floor check over every other family, not a causal claim about this change.

    Per-family directories make a change that reaches another family structurally impossible, so what the
    sweep really guards is a family that is failing for any reason at the moment this round would land.
    """
    world["cases"].append(_case(world["configs"].parent, "other-hold", split="holdout", family="access_control"))
    world["floors"]["access_control"] = NoiseFloor(
        family="access_control", k_runs=5, pairs=1, flaky_pairs=0, negative_flip_rate=0.0, budget_flips=0
    )

    def build(config: FamilyConfig):  # type: ignore[no-untyped-def]
        def scan(root: Path) -> list[StaticFinding]:
            if root.name != "vuln" or config.family == "access_control":
                return []  # access control finds nothing, so its holdout pair is below its floor
            return [_finding("injection")] if config.checklist.strip() == "- ask about quoting" else []

        return scan

    from openultrasast.learning.rounds import run_learning_round

    record = run_learning_round(
        world["cases"],
        family="injection",
        taxonomy=load_families(),
        configs_dir=world["configs"],
        proposer=ScriptedProposer([_proposal("- ask about quoting\n")]),
        scan_factory=build,
        model="m",
        journal=world["journal"],
        archive=world["archive"],
        floors=world["floors"],
        out_dir=world["out"],
        sweep_families=("access_control",),
    )
    assert record.outcome == "rejected" and record.reason == "collateral_regression"
    assert record.sweep["access_control"] == 1
    assert (world["configs"] / "injection" / "checklist.md").read_text() == "- old\n"


def test_a_round_over_its_cost_cap_is_reverted_and_says_so(world) -> None:  # type: ignore[no-untyped-def]
    record = _run(world, _proposal("- ask about quoting\n"), {"- ask about quoting": True}, cost_cap_usd=0.0, spent_usd=lambda: 1.0)
    assert record.outcome == "reverted_cost" and record.cost_usd == 1.0
    assert (world["configs"] / "injection" / "checklist.md").read_text() == "- old\n"


def test_a_proposal_that_reaches_beyond_its_family_never_runs(world) -> None:  # type: ignore[no-untyped-def]
    record = _run(world, Proposal(hypothesis="h", lever="checklist", change={"../escape.md": "x"}), {})
    assert record.outcome == "refused_holdout" or record.outcome == "rejected"
    assert "outside" in record.reason
    assert not (world["configs"].parent / "escape.md").exists()


def test_a_round_with_no_proposal_is_recorded_rather_than_skipped(world) -> None:  # type: ignore[no-untyped-def]
    record = _run(world, None, {})
    assert record.outcome == "rejected" and record.reason == "no_proposal"
    assert [item.round for item in world["journal"].rounds()] == [1]


def test_the_round_directory_holds_what_a_replay_needs(world) -> None:  # type: ignore[no-untyped-def]
    record = _run(
        world,
        _proposal("- ask about quoting\n"),
        {"- ask about quoting": True},
        trajectories=lambda: [{"pair": "train-a", "prompt": "api_key = " + "'" + "B" * 24 + "'"}],
    )
    directory = world["out"] / "rounds" / "1"
    assert (directory / "proposal.json").is_file() and (directory / "scores.json").is_file()
    attribution = json.loads((directory / "attribution.json").read_text())
    assert attribution["flipped_predicted"] == ["hold-a"] or attribution["flipped_predicted"] == ["train-a", "hold-a"]
    assert attribution["flipped_unpredicted"] == []
    trajectories = (directory / "trajectories.jsonl").read_text()
    assert "REDACTED" in trajectories and "B" * 24 not in trajectories
    assert record.attribution.precision == 1.0


def test_a_round_number_is_never_reused(world) -> None:  # type: ignore[no-untyped-def]
    from openultrasast.learning.journal import JournalError

    _run(world, _proposal("- ask about quoting\n"), {"- ask about quoting": True})
    (world["out"] / "rounds" / "2").mkdir(parents=True)
    with pytest.raises(JournalError, match="2"):
        _run(world, _proposal("- another\n"), {})


def test_every_stage_scores_at_least_three_runs_per_pair(world) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="three"):
        _run(world, _proposal("- x\n"), {}, k_runs=2)
