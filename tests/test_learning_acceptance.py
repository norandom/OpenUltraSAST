"""learning-harness task 3.6: the acceptance rule and the directory revert (offline)."""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.learning.rounds import NoiseFloor


def _floor(family: str, budget: int = 0, *, gates: bool = True) -> NoiseFloor:
    return NoiseFloor(family=family, k_runs=5, pairs=10, flaky_pairs=budget, negative_flip_rate=0.0, budget_flips=budget, gates=gates)


def _decide(train: float, holdout: float, sweep: dict[str, int], floors: dict[str, NoiseFloor]):  # type: ignore[no-untyped-def]
    from openultrasast.learning.acceptance import decide

    return decide(target="access_control", train_delta=train, holdout_delta=holdout, sweep=sweep, floors=floors)


def test_a_change_that_helps_and_hurts_nobody_is_accepted() -> None:
    verdict = _decide(0.1, 0.2, {"injection": 0}, {"injection": _floor("injection")})
    assert verdict.accepted and verdict.reason == "improved"


def test_one_side_may_stand_still_but_the_other_must_move() -> None:
    assert _decide(0.0, 0.2, {}, {}).accepted
    assert _decide(0.2, 0.0, {}, {}).accepted
    tie = _decide(0.0, 0.0, {}, {})
    assert not tie.accepted and tie.reason == "tie"  # a tie is rejected, or the loop drifts on noise


def test_a_decrease_on_either_side_is_rejected() -> None:
    train_down = _decide(-0.1, 0.5, {}, {})
    assert not train_down.accepted and train_down.reason == "train_regressed"
    holdout_down = _decide(0.5, -0.1, {}, {})
    assert not holdout_down.accepted and holdout_down.reason == "holdout_regressed"


def test_another_family_beyond_its_measured_budget_rejects_the_round() -> None:
    within = _decide(0.2, 0.2, {"injection": 2}, {"injection": _floor("injection", 2)})
    assert within.accepted  # inside the noise this family shows against itself
    beyond = _decide(0.2, 0.2, {"injection": 3}, {"injection": _floor("injection", 2)})
    assert not beyond.accepted and beyond.reason == "collateral_regression"
    assert beyond.offenders == ("injection",)


def test_a_family_that_never_gates_cannot_reject_a_round() -> None:
    verdict = _decide(0.2, 0.2, {"memory": 99}, {"memory": _floor("memory", 0, gates=False)})
    assert verdict.accepted and verdict.offenders == ()


def test_a_family_with_no_measured_floor_gets_no_budget() -> None:
    verdict = _decide(0.2, 0.2, {"path": 1}, {})
    assert not verdict.accepted and verdict.offenders == ("path",)  # unmeasured is not the same as unlimited


def test_a_snapshot_restores_a_family_directory_byte_for_byte(tmp_path: Path) -> None:
    from openultrasast.learning.acceptance import DirectorySnapshot

    directory = tmp_path / "access_control"
    directory.mkdir()
    (directory / "prompt.md").write_text("original\n")
    (directory / "family.toml").write_text('version = "0"\n')
    snapshot = DirectorySnapshot.of(directory)
    (directory / "prompt.md").write_text("changed\n")
    (directory / "extra.md").write_text("added by a round\n")
    (directory / "family.toml").unlink()
    snapshot.restore()
    assert (directory / "prompt.md").read_text() == "original\n"
    assert (directory / "family.toml").read_text() == 'version = "0"\n'
    assert not (directory / "extra.md").exists()  # a file the round added is not left behind
    assert sorted(path.name for path in directory.iterdir()) == ["family.toml", "prompt.md"]


def test_every_other_family_directory_is_untouched_across_a_round(tmp_path: Path) -> None:
    """Req 6.2: a round can only write its target, so the freeze is structural rather than promised."""
    from openultrasast.learning.acceptance import DirectorySnapshot, digest_configs
    from openultrasast.learning.detectors import write_default_configs
    from openultrasast.learning.families import load_families
    from openultrasast.learning.proposer import Proposal, apply_proposal

    configs = tmp_path / "configs"
    write_default_configs(configs, load_families(), prompt="p", version="0")
    before = digest_configs(configs)
    snapshot = DirectorySnapshot.of(configs / "access_control")
    apply_proposal(Proposal(hypothesis="h", lever="checklist", change={"checklist.md": "- new\n"}), configs / "access_control")
    after = digest_configs(configs)
    assert after["access_control"] != before["access_control"]
    assert {name: value for name, value in after.items() if name != "access_control"} == {
        name: value for name, value in before.items() if name != "access_control"
    }
    snapshot.restore()
    assert digest_configs(configs) == before  # a rejected round leaves the whole tree as it found it


def test_a_bumped_version_is_written_only_on_acceptance(tmp_path: Path) -> None:
    from openultrasast.learning.acceptance import bump_version
    from openultrasast.learning.detectors import load_family_configs, write_default_configs
    from openultrasast.learning.families import load_families

    configs = tmp_path / "configs"
    write_default_configs(configs, load_families(), prompt="p", version="0")
    bump_version(configs / "access_control", "1")
    taxonomy = load_families()
    assert load_family_configs(configs, taxonomy)["access_control"].version == "1"
    assert load_family_configs(configs, taxonomy)["injection"].version == "0"


@pytest.mark.parametrize(("spent", "cap", "expected"), [(0.5, 10.0, True), (10.0, 10.0, True), (10.01, 10.0, False)])
def test_a_round_over_its_cost_cap_is_reverted(spent: float, cap: float, expected: bool) -> None:
    from openultrasast.learning.acceptance import within_budget

    assert within_budget(spent, cap) is expected
