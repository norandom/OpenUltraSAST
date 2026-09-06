"""Three defects the round-4 review found, one test each (learning-harness, Req 3.2, 4.1, 9.1).

Two of them were the same shape as defects already rejected once: a proposer that cannot propose because the call
is wrong and the error is swallowed, and a K-run floor that turned a documented command into a traceback. The
third is the fixed-side half of the range defect — 28 rows resolve a span on the vulnerable side and none on the
fixed side, so every finding there reads as outside the labeled function and the pair scores as silence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.findings import StaticFinding
from openultrasast.harness_ext import has_harnessx
from openultrasast.learning.families import load_families
from openultrasast.pairs import DEFAULT_CATALOG, PairCase, load_pair_catalog, select_vendored
from openultrasast.semantic.extra import has_semantic_extra

VULN = "from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED_OTHER = "from flask import request\n\n\ndef unrelated():\n    return 'ok'\n"


def _finding(line: int) -> StaticFinding:
    return StaticFinding(
        finding_id=f"tool-hunter:app.py:{line}",
        path="app.py",
        title="t",
        severity="high",
        confidence="low",
        evidence_level="suspicion",
        rationale="r",
        line=line,
        function_name="run",
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=["tool-hunter", "family:injection"],
        ranking_priority=0.0,
    )


# --- the meta-agent call -----------------------------------------------------


@pytest.mark.skipif(not has_harnessx(), reason="the composition seam only runs when the extra is importable")
def test_the_meta_agent_is_built_with_a_model_config_not_a_model_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`MetaAgent(inner_model=...)` wants a `ModelConfig`; a string reaches `self.inner_model.agentic(...)` and dies.

    Every other HarnessX composition site in this repository builds the config properly. Here the mistake was
    invisible because a `# type: ignore` hid it from mypy and a bare `except Exception` turned it into the
    degradation reason `meta_agent_failed`, which reads exactly like the model declining."""
    from openultrasast.learning import proposer as proposer_module

    seen: dict[str, object] = {}

    class _Agent:
        def __init__(self, **kwargs: object) -> None:
            seen.update(kwargs)

        async def evolve(self, **kwargs: object) -> Path:
            seen["evolve"] = kwargs
            workspace = kwargs["current_config"]
            assert isinstance(workspace, Path)
            (workspace / "checklist.md").write_text("- from the meta agent\n")
            return workspace

    monkeypatch.setattr(proposer_module, "_meta_agent_class", lambda: _Agent)
    monkeypatch.setattr(proposer_module, "_model_config", lambda model: f"ModelConfig({model})")
    (tmp_path / "injection").mkdir()
    (tmp_path / "injection" / "checklist.md").write_text("- old\n")
    proposal = proposer_module.HarnessXProposer(configs_dir=tmp_path, model="m").propose(_facts())
    assert proposal is not None and proposal.change == {"checklist.md": "- from the meta agent\n"}
    assert seen["inner_model"] == "ModelConfig(m)", "the agent was handed a model name where it wanted a config"
    assert seen["allowed_write_roots"] != (tmp_path / "injection",), "the live family directory is never a write root"


@pytest.mark.skipif(not has_harnessx(), reason="the composition seam only runs when the extra is importable")
def test_a_meta_agent_built_wrongly_is_not_reported_as_a_declined_proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ "We called the agent wrong" and "the agent had nothing to propose" are different facts."""
    from openultrasast.learning import proposer as proposer_module

    def _boom() -> object:
        raise TypeError("inner_model must be a ModelConfig")

    monkeypatch.setattr(proposer_module, "_meta_agent_class", _boom)
    (tmp_path / "injection").mkdir()
    proposer = proposer_module.HarnessXProposer(configs_dir=tmp_path, model="m")
    with pytest.raises(TypeError, match="ModelConfig"):
        proposer.propose(_facts())


def _facts():  # type: ignore[no-untyped-def]
    from openultrasast.learning.detectors import FamilyConfig
    from openultrasast.learning.proposer import FailureFacts

    return FailureFacts(
        family="injection",
        config=FamilyConfig(
            family="injection",
            version="0",
            prompt="p",
            checklist="- old",
            tools=("read_file",),
            max_steps=1,
            max_cost_usd=0.1,
            max_chars=100,
        ),
    )


# --- the pairs command in its documented form --------------------------------


def test_the_pairs_hunter_path_runs_without_a_k_runs_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The floor is a default, not a trap: `ousast pairs --hunter` must work as documented."""
    from openultrasast.cli import main

    (tmp_path / "a-v.py").write_text(VULN)
    (tmp_path / "a-f.py").write_text(FIXED_OTHER)
    (tmp_path / "pairs.toml").write_text(
        '[[pair]]\nname = "a"\nslice = "vibe-py"\nlanguage = "python"\nvuln = "a-v.py"\nfixed = "a-f.py"\n'
        'relpath = "app.py"\nsplit = "train"\nreview_tier = "seeded"\n\n'
        '[[pair.expected]]\ncwe = "CWE-78"\nclass = "x"\npath = "app.py"\nfunction = "run"\nmechanism = "other"\nfamily = "injection"\n'
    )
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "scripted")
    assert main(["pairs", "--catalog", str(tmp_path / "pairs.toml"), "--hunter", "--hunter-model", "scripted"]) == 0


def test_a_k_below_the_floor_names_the_flag_instead_of_raising(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.cli import main

    (tmp_path / "pairs.toml").write_text("")
    monkeypatch.setenv("OPENULTRASAST_HUNTER_CLIENT", "scripted")
    with pytest.raises(SystemExit, match="k-runs"):
        main(["pairs", "--catalog", str(tmp_path / "pairs.toml"), "--hunter", "--hunter-model", "scripted", "--k-runs", "1"])


# --- the fixed side of a trap pair -------------------------------------------


def test_a_trap_pair_is_scored_against_the_function_its_fixed_side_really_holds(tmp_path: Path) -> None:
    """A Real-Vuln-Benchmark trap takes its fixed side from a different, correctly guarded handler.

    With no span for it, every fixed-side finding counts as outside the labeled function and the pair scores as
    silence — the same flattering direction as the range defect, for the 28 rows that resolve one side only."""
    from openultrasast.learning.scoring import score_pair_family

    (tmp_path / "v.py").write_text(VULN)
    (tmp_path / "f.py").write_text(FIXED_OTHER)
    case = PairCase(
        name="trap",
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / "v.py",
        fixed_file=tmp_path / "f.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="run", mechanism="other", family="injection"
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        fix_function="unrelated",
    )
    score = score_pair_family(
        case,
        "injection",
        [[_finding(6)]],
        [[_finding(5)]],
        ranges={"app.py": (("run", 5, 6),)},
        fixed_ranges={"app.py": (("unrelated", 4, 5),)},
        taxonomy=load_families(),
    )
    assert score.outcome == "both_flagged", "the finding is inside the fixed side's own handler; that is a leak"


def test_a_row_whose_fixed_side_resolves_no_span_says_so_instead_of_scoring_silent(tmp_path: Path) -> None:
    from openultrasast.learning.scoring import score_pair_family

    (tmp_path / "v.py").write_text(VULN)
    (tmp_path / "f.py").write_text(FIXED_OTHER)
    case = PairCase(
        name="orphan",
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / "v.py",
        fixed_file=tmp_path / "f.py",
        relpath="app.py",
        expected=(
            ExpectedFinding(
                cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="run", mechanism="other", family="injection"
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
    )
    score = score_pair_family(
        case,
        "injection",
        [[_finding(6)]],
        [[]],
        ranges={"app.py": (("run", 5, 6),)},
        fixed_ranges={"app.py": (("unrelated", 4, 5),)},
        taxonomy=load_families(),
    )
    assert score.outcome == "unscorable" and score.unscorable_reason == "unresolved_label:fixed"


def test_the_trap_rows_carry_their_fixed_side_function_in_the_catalog() -> None:
    """`fix_function` lived only in the recipes; the scorer could not see which handler the fixed side holds."""
    cases = {case.name: case for case in select_vendored(load_pair_catalog(DEFAULT_CATALOG))}
    assert cases["threatbyte-api-v1-get"].fix_function == "post"
    assert cases["threatbyte-api-v1-delete"].fix_function == "post"
    assert cases["vampi-users-update-password"].fix_function == "register_user"
    assert cases["vampi-books-get-by-title"].fix_function == "", "a row whose two sides are one function names none"


@pytest.mark.semantic
@pytest.mark.skipif(not has_semantic_extra(), reason="resolving a span on both sides needs the tree-sitter grammars")
def test_no_vendored_row_resolves_one_side_and_not_the_other() -> None:
    """The corpus-wide form of the same defect: 28 rows resolved a vulnerable span and no fixed-side span.

    Every one of them therefore scored the fixed side as silent by construction, whatever the detector said. The
    catalog generator now derives `fix_function` from the fixed excerpt itself, so the span exists and the leak is
    visible."""
    import tempfile

    from openultrasast.learning.scoring import _spans
    from openultrasast.pairs import _materialize_side, _overlay_scan

    orphans = []
    for case in select_vendored(load_pair_catalog(DEFAULT_CATALOG)):
        if case.unscorable:
            continue
        with tempfile.TemporaryDirectory() as scratch:
            vuln = _materialize_side(Path(scratch) / "vuln", case, side="vuln")
            fixed = _materialize_side(Path(scratch) / "fixed", case, side="fixed")
            vuln_ranges, fixed_ranges = _overlay_scan(vuln).ranges, _overlay_scan(fixed).ranges
        if _spans(case, vuln_ranges) and not _spans(case, fixed_ranges, function=case.fix_function):
            orphans.append(case.name)
    assert orphans == [], f"rows whose fixed side can only ever score as silence: {orphans}"
