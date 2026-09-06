"""learning-harness task 3.3: round zero and the per-family noise floor (offline)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.findings import StaticFinding
from openultrasast.learning.families import load_families
from openultrasast.pairs import PairCase

VULN = "from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = "from flask import request\nimport subprocess\n\n\ndef run():\n    subprocess.run(['echo', 'x'], check=False)\n"


def _case(tmp_path: Path, name: str, *, family: str = "injection", slice_name: str = "vibe-py", unscorable: str | None = None) -> PairCase:
    (tmp_path / f"{name}-v.py").write_text(VULN)
    (tmp_path / f"{name}-f.py").write_text(FIXED)
    return PairCase(
        name=name,
        slice=slice_name,
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


def _is_vulnerable_side(root: Path) -> bool:
    """The materialized side, by directory name only.

    An earlier version also matched "-v" anywhere in the path, which the random temporary directory name
    sometimes contained, so the detector "found" the bug on the fixed side too and the pair flipped. A
    flaky harness is indistinguishable from a flaky detector, which is precisely what a noise floor must
    not measure.
    """
    return root.name == "vuln"


def _steady(root: Path) -> list[StaticFinding]:
    return [_finding("injection")] if _is_vulnerable_side(root) else []


def _always(scan):  # type: ignore[no-untyped-def]
    """Round zero asks for a detector per family; these tests deliberately give every family the same one so the
    noise-floor arithmetic is the only thing under test."""

    def build(_config):  # type: ignore[no-untyped-def]
        return scan

    return build


def _flaky(counter: list[int]):  # type: ignore[no-untyped-def]
    def scan(root: Path) -> list[StaticFinding]:
        if not _is_vulnerable_side(root):
            return []
        counter.append(1)
        return [_finding("injection")] if len(counter) % 2 else []

    return scan


def test_round_zero_writes_a_configuration_for_every_family(tmp_path: Path) -> None:
    from openultrasast.learning.detectors import load_family_configs
    from openultrasast.learning.rounds import run_baseline

    taxonomy = load_families()
    report = run_baseline(
        [_case(tmp_path, "a")],
        taxonomy=taxonomy,
        configs_dir=tmp_path / "configs",
        scan_factory=_always(_steady),
        model="m",
        out_dir=tmp_path / "out",
    )
    configs = load_family_configs(tmp_path / "configs", taxonomy)
    assert set(configs) == {family.id for family in taxonomy.families}
    assert all(config.version == "0" for config in configs.values())
    assert report.model == "m" and report.k_runs == 5


def test_a_steady_detector_has_a_zero_noise_floor_and_a_flaky_one_does_not(tmp_path: Path) -> None:
    from openultrasast.learning.rounds import run_baseline

    taxonomy = load_families()
    steady = run_baseline(
        [_case(tmp_path, "a"), _case(tmp_path, "b")],
        taxonomy=taxonomy,
        configs_dir=tmp_path / "c1",
        scan_factory=_always(_steady),
        model="m",
        out_dir=tmp_path / "o1",
    )
    floor = steady.floors["injection"]
    assert floor.k_runs == 5 and floor.negative_flip_rate == 0.0 and floor.budget_flips == 0 and floor.gates is True
    flaky = run_baseline(
        [_case(tmp_path, "a"), _case(tmp_path, "b")],
        taxonomy=taxonomy,
        configs_dir=tmp_path / "c2",
        scan_factory=_always(_flaky([])),
        model="m",
        out_dir=tmp_path / "o2",
    )
    assert flaky.floors["injection"].negative_flip_rate > 0.0 and flaky.floors["injection"].budget_flips >= 1


def test_the_memory_family_is_measured_but_never_gates(tmp_path: Path) -> None:
    from openultrasast.learning.rounds import run_baseline

    taxonomy = load_families()
    report = run_baseline(
        [_case(tmp_path, "m", family="memory", slice_name="vfc")],
        taxonomy=taxonomy,
        configs_dir=tmp_path / "configs",
        scan_factory=_always(_steady),
        model="m",
        out_dir=tmp_path / "out",
        slices=("vfc",),
    )
    assert "memory" in report.floors and report.floors["memory"].gates is False
    assert report.metrics["memory"]["scorable"] == 1


def test_the_default_selection_is_the_web_slices(tmp_path: Path) -> None:
    from openultrasast.learning.rounds import run_baseline

    taxonomy = load_families()
    cases = [_case(tmp_path, "web", slice_name="vibe-py"), _case(tmp_path, "c", family="memory", slice_name="vfc")]
    report = run_baseline(
        cases, taxonomy=taxonomy, configs_dir=tmp_path / "configs", scan_factory=_always(_steady), model="m", out_dir=tmp_path / "out"
    )
    assert set(report.metrics) == {"injection"} and "memory" not in report.floors


def test_artifacts_are_keyed_by_model_so_another_model_can_be_compared(tmp_path: Path) -> None:
    from openultrasast.learning.rounds import compare_baselines, run_baseline

    taxonomy = load_families()
    out = tmp_path / "out"
    for index, model in enumerate(("deepseek-v4-flash", "deepseek-v4-pro")):
        run_baseline(
            [_case(tmp_path, f"a{index}")],
            taxonomy=taxonomy,
            configs_dir=tmp_path / "configs",
            scan_factory=_always(_steady),
            model=model,
            out_dir=out,
        )
    written = sorted(path.name for path in (out / "baseline").iterdir())
    assert written == ["deepseek-v4-flash", "deepseek-v4-pro"]
    floors = json.loads((out / "baseline" / "deepseek-v4-flash" / "noise-floors.json").read_text())
    assert floors["model"] == "deepseek-v4-flash" and floors["floors"]["injection"]["k_runs"] == 5
    report = json.loads((out / "baseline" / "deepseek-v4-flash" / "report.json").read_text())
    assert report["metrics"]["injection"]["recall"] == 1.0 and report["taxonomy_version"]
    table = compare_baselines(out)
    assert set(table) == {"deepseek-v4-flash", "deepseek-v4-pro"}
    assert table["deepseek-v4-pro"]["injection"]["youden"] == 1.0
    # a second baseline never rewrites a configuration
    assert (tmp_path / "configs" / "injection" / "family.toml").read_text().count("version") == 1


def test_an_unscorable_pair_is_listed_and_never_run(tmp_path: Path) -> None:
    from openultrasast.learning.rounds import run_baseline

    calls: list[Path] = []

    def counting(root: Path) -> list[StaticFinding]:
        calls.append(root)
        return _steady(root)

    taxonomy = load_families()
    case = _case(tmp_path, "twin")
    twin = PairCase(**{**case.__dict__, "unscorable": "identical_twin"})
    report = run_baseline(
        [twin], taxonomy=taxonomy, configs_dir=tmp_path / "configs", scan_factory=_always(counting), model="m", out_dir=tmp_path / "out"
    )
    assert report.metrics["injection"]["scorable"] == 0
    assert report.metrics["injection"]["unscorable"] == {"identical_twin": 1}
    assert calls == []


def test_round_zero_records_what_it_spent(tmp_path: Path) -> None:
    """Publishing puts a cost beside every number, so the baseline has to know what it cost."""
    from openultrasast.learning.rounds import run_baseline

    report = run_baseline(
        [_case(tmp_path, "a")],
        taxonomy=load_families(),
        configs_dir=tmp_path / "configs",
        scan_factory=_always(_steady),
        model="m",
        out_dir=tmp_path / "out",
        spent_usd=lambda: 1.25,
    )
    assert report.cost_usd == 1.25
    assert json.loads((tmp_path / "out" / "baseline" / "m" / "report.json").read_text())["cost_usd"] == 1.25
