"""learning-harness task 3.5: failure facts, the scripted proposer and the HarnessX proposer (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.learning.detectors import FamilyConfig
from openultrasast.learning.journal import LearningJournal, RoundRecord
from openultrasast.learning.scoring import PairFamilyScore


def _config(family: str = "access_control") -> FamilyConfig:
    return FamilyConfig(
        family=family,
        version="0",
        prompt="You hunt access control.",
        checklist="- did the handler check ownership?",
        tools=("read_definition", "obligations"),
        max_steps=3,
        max_cost_usd=0.5,
        max_chars=4000,
    )


def _score(pair: str, outcome: str, *, family: str = "access_control") -> PairFamilyScore:
    return PairFamilyScore(pair=pair, family=family, runs=(outcome,), outcome=outcome, slice="vibe-py")  # type: ignore[arg-type]


def test_failure_facts_carry_the_misses_the_leaks_and_the_rejected_buffer(tmp_path: Path) -> None:
    from openultrasast.learning.proposer import build_failure_facts

    journal = LearningJournal(tmp_path / "journal.jsonl")
    journal.append(
        RoundRecord(
            round=1,
            family="access_control",
            hypothesis="ask about ownership",
            levers=("checklist",),
            predicted_affected=("access_control",),
            predicted_at_risk=(),
            outcome="rejected",
            reason="tie",
        )
    )
    scores = [_score("miss-one", "both_silent"), _score("leak-one", "both_flagged"), _score("good", "pair_correct")]
    facts = build_failure_facts(
        scores, family="access_control", config=_config(), journal=journal, train_pairs={"miss-one", "leak-one", "good"}
    )
    assert [item.pair for item in facts.misses] == ["miss-one"]
    assert [item.pair for item in facts.leaks] == ["leak-one"]
    assert facts.rejected == ("ask about ownership",)
    assert facts.config.family == "access_control" and facts.family == "access_control"


def test_the_proposer_is_never_handed_a_holdout_pair(tmp_path: Path) -> None:
    from openultrasast.learning.proposer import build_failure_facts

    journal = LearningJournal(tmp_path / "journal.jsonl")
    scores = [_score("train-miss", "both_silent"), _score("holdout-miss", "both_silent")]
    facts = build_failure_facts(scores, family="access_control", config=_config(), journal=journal, train_pairs={"train-miss"})
    assert [item.pair for item in facts.misses] == ["train-miss"]
    assert "holdout-miss" not in json.dumps(facts.to_dict())


def test_the_scripted_proposer_returns_one_change_for_one_family(tmp_path: Path) -> None:
    from openultrasast.learning.proposer import Proposal, ScriptedProposer, build_failure_facts

    journal = LearningJournal(tmp_path / "journal.jsonl")
    facts = build_failure_facts([_score("a", "both_silent")], family="access_control", config=_config(), journal=journal, train_pairs={"a"})
    scripted = ScriptedProposer(
        [
            Proposal(
                hypothesis="h",
                lever="checklist",
                change={"checklist.md": "- ask about ownership\n"},
                predicted_affected=("access_control",),
            )
        ]
    )
    proposal = scripted.propose(facts)
    assert proposal is not None and proposal.lever == "checklist" and set(proposal.change) == {"checklist.md"}
    assert scripted.propose(facts) is None  # a scripted proposer runs out rather than repeating itself


@pytest.mark.parametrize(
    ("change", "lever", "needle"),
    [
        ({"../../etc/passwd": "x"}, "checklist", "outside"),
        ({"family.toml": "x", "prompt.md": "y"}, "prompt", "one file"),
        ({"secrets.md": "x"}, "checklist", "secrets.md"),
        ({"prompt.md": "x" * 9000}, "prompt", "cap"),
    ],
    ids=["escapes_the_family_directory", "two_files", "unknown_file", "over_the_cap"],
)
def test_a_proposal_that_reaches_beyond_its_family_is_refused_by_name(change: dict[str, str], lever: str, needle: str) -> None:
    from openultrasast.learning.proposer import Proposal, refuse_proposal

    refusal = refuse_proposal(Proposal(hypothesis="h", lever=lever, change=change), _config())  # type: ignore[arg-type]
    assert refusal is not None and needle in refusal


def test_a_well_formed_proposal_is_accepted_and_applies_inside_its_own_directory(tmp_path: Path) -> None:
    from openultrasast.learning.proposer import Proposal, apply_proposal, refuse_proposal

    directory = tmp_path / "access_control"
    directory.mkdir()
    (directory / "checklist.md").write_text("- old\n")
    proposal = Proposal(hypothesis="h", lever="checklist", change={"checklist.md": "- new\n"}, predicted_affected=("access_control",))
    assert refuse_proposal(proposal, _config()) is None
    apply_proposal(proposal, directory)
    assert (directory / "checklist.md").read_text() == "- new\n"


def test_the_write_roots_are_one_family_directory_and_exclude_the_checker_and_the_corpus(tmp_path: Path) -> None:
    from openultrasast.learning import canaries
    from openultrasast.learning.proposer import write_roots

    roots = write_roots(tmp_path / "configs", "access_control")
    assert roots == (tmp_path / "configs" / "access_control",)
    verifier_module = Path(canaries.__file__).resolve()
    assert not any(verifier_module.is_relative_to(root.resolve()) for root in roots)
    corpus = Path("benchmarks").resolve()
    assert not any(str(corpus).startswith(str(root.resolve())) for root in roots)


def test_the_harnessx_proposer_degrades_with_a_reason_when_the_extra_is_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.learning import proposer as proposer_module
    from openultrasast.learning.proposer import HarnessXProposer, build_failure_facts

    journal = LearningJournal(tmp_path / "journal.jsonl")
    facts = build_failure_facts([_score("a", "both_silent")], family="access_control", config=_config(), journal=journal, train_pairs={"a"})
    monkeypatch.setattr(proposer_module, "has_harnessx", lambda: False)
    agent = HarnessXProposer(configs_dir=tmp_path / "configs", model="m")
    assert agent.propose(facts) is None
    assert agent.reason == "harnessx_unavailable"
    assert agent.write_roots("access_control") == (tmp_path / "configs" / "access_control",)


# --- the meta-agent proposer (review round 3, task 3.5 finding 1) ------------


def test_the_meta_agent_proposer_reads_its_change_out_of_a_scratch_copy(tmp_path: Path) -> None:
    """The meta-agent never writes into the live family directory.

    A proposer that edited the tree directly would have changed the configuration before the round snapshotted
    it, so a rejection could not put it back. It gets a copy, and the proposal is the diff of that copy."""
    from openultrasast.learning.proposer import HarnessXProposer

    configs = tmp_path / "configs"
    (configs / "injection").mkdir(parents=True)
    (configs / "injection" / "checklist.md").write_text("- old\n")
    (configs / "injection" / "family.toml").write_text('family = "injection"\nversion = "0"\n')
    seen: dict[str, object] = {}

    def agent(*, workspace: Path, facts, model: str):  # type: ignore[no-untyped-def]
        seen["workspace"] = workspace
        seen["family"] = facts.family
        (workspace / "checklist.md").write_text("- ask about quoting\n")
        return "ask about quoting"

    proposer = HarnessXProposer(configs_dir=configs, model="m", agent=agent)
    proposal = proposer.propose(_facts(tmp_path, "injection"))
    assert proposal is not None
    assert proposal.lever == "checklist" and proposal.change == {"checklist.md": "- ask about quoting\n"}
    assert proposal.hypothesis == "ask about quoting"
    assert seen["workspace"] != configs / "injection"
    assert (configs / "injection" / "checklist.md").read_text() == "- old\n", "the live tree was edited"


def test_the_meta_agent_proposer_refuses_more_than_one_changed_file(tmp_path: Path) -> None:
    from openultrasast.learning.proposer import HarnessXProposer

    configs = tmp_path / "configs"
    (configs / "injection").mkdir(parents=True)
    (configs / "injection" / "checklist.md").write_text("- old\n")
    (configs / "injection" / "prompt.md").write_text("p\n")

    def agent(*, workspace: Path, facts, model: str):  # type: ignore[no-untyped-def]
        (workspace / "checklist.md").write_text("- a\n")
        (workspace / "prompt.md").write_text("- b\n")
        return "two at once"

    proposer = HarnessXProposer(configs_dir=configs, model="m", agent=agent)
    assert proposer.propose(_facts(tmp_path, "injection")) is None
    assert "one file" in proposer.reason


def test_the_meta_agent_proposer_refuses_a_file_no_lever_owns(tmp_path: Path) -> None:
    from openultrasast.learning.proposer import HarnessXProposer

    configs = tmp_path / "configs"
    (configs / "injection").mkdir(parents=True)
    (configs / "injection" / "checklist.md").write_text("- old\n")

    def agent(*, workspace: Path, facts, model: str):  # type: ignore[no-untyped-def]
        (workspace / "notes.txt").write_text("x\n")
        return "sideways"

    proposer = HarnessXProposer(configs_dir=configs, model="m", agent=agent)
    assert proposer.propose(_facts(tmp_path, "injection")) is None
    assert "notes.txt" in proposer.reason


def test_the_meta_agent_proposer_says_so_when_it_changed_nothing(tmp_path: Path) -> None:
    from openultrasast.learning.proposer import HarnessXProposer

    configs = tmp_path / "configs"
    (configs / "injection").mkdir(parents=True)
    (configs / "injection" / "checklist.md").write_text("- old\n")
    proposer = HarnessXProposer(configs_dir=configs, model="m", agent=lambda **_kwargs: "nothing to do")
    assert proposer.propose(_facts(tmp_path, "injection")) is None
    assert proposer.reason == "no_change_proposed"


def _facts(tmp_path: Path, family: str):  # type: ignore[no-untyped-def]
    from openultrasast.learning.proposer import FailureFacts

    del tmp_path
    return FailureFacts(family=family, config=_config(family))
