"""What the pairs hunter path must prove (learning-harness review round 3, Req 3.2, 3.5).

Three defects, one test each: K was declared and never threaded, so every stage scored one run; the fixed
side was judged against the *vulnerable* side's function ranges, which differ on most of the corpus; and
the generalist hunter emitted findings with no family tag, which the class-aware scorer can never credit,
so `ousast pairs --hunter` reported recall zero by construction.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.benchmark import ExpectedFinding
from openultrasast.findings import StaticFinding
from openultrasast.learning.families import load_families
from openultrasast.pairs import PairCase, evaluate_catalog

# The fix inserts two guard lines above the handler, so `run` starts on a different line on each side.
VULN = "from flask import request\nimport os\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = (
    "from flask import request\nimport shlex\nimport os\n\n\n"
    "def _safe(value):\n    return shlex.quote(value or '')\n\n\n"
    "def run():\n    os.system(_safe(request.args.get('cmd')))\n"
)


def _case(tmp_path: Path, name: str = "p") -> PairCase:
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
                cwe="CWE-78",
                vulnerability_class="x",
                path="app.py",
                evidence="",
                function="run",
                mechanism="other",
                family="injection",
            ),
        ),
        min_recall=1.0,
        fix_policy="silent",
        review_tier="seeded",
    )


def _finding(line: int, *, family: str | None = "injection") -> StaticFinding:
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
        tags=["tool-hunter", *([f"family:{family}"] if family else [])],
        ranking_priority=0.0,
    )


def test_the_k_runs_flag_reaches_the_detector(tmp_path: Path) -> None:
    """Req 3.5: three runs per side, per pair. A parameter no caller can set is not a K-run floor."""
    calls: list[str] = []

    def scan(root: Path) -> list[StaticFinding]:
        calls.append(root.name)
        return [_finding(6)] if root.name == "vuln" else []

    evaluate_catalog([_case(tmp_path)], hunter=scan, k_runs=3)
    assert calls.count("vuln") == 3 and calls.count("fixed") == 3


def test_fewer_than_three_runs_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="three runs"):
        evaluate_catalog([_case(tmp_path)], hunter=lambda root: [], k_runs=1)


def test_the_fixed_side_is_judged_against_the_fixed_side_line_numbers(tmp_path: Path) -> None:
    """`run` sits at line 5 on the vulnerable side and line 10 on the fixed side.

    Scoring the fixed side against the vulnerable side's span reads a finding inside the fixed handler as
    outside it, so a detector that flags both sides is recorded as silent on the fix — a leak counted as a
    clean pass, and always in the direction that flatters the number."""

    def scan(root: Path) -> list[StaticFinding]:
        return [_finding(6)] if root.name == "vuln" else [_finding(11)]

    result = evaluate_catalog([_case(tmp_path)], hunter=scan, k_runs=3)
    hunter = result.scorers["vibe-py"]["hunter"]
    assert hunter.detected_vuln == 1
    assert hunter.silent_fix == 0, "the finding is inside `run` on the fixed side; that is a leak"
    assert hunter.pair_correct == 0


def test_a_generalist_finding_without_a_family_is_never_a_detection(tmp_path: Path) -> None:
    """The other half of the same defect: `pairs --hunter` used to feed the scorer untagged findings."""

    def scan(root: Path) -> list[StaticFinding]:
        return [_finding(6, family=None)] if root.name == "vuln" else []

    result = evaluate_catalog([_case(tmp_path)], hunter=scan, k_runs=3)
    assert result.scorers["vibe-py"]["hunter"].detected_vuln == 0


def test_the_hunter_reports_the_family_it_believes_and_that_is_what_is_credited(tmp_path: Path) -> None:
    """A generalist that must name the family is answerable; one that names nothing cannot be scored at all."""
    from openultrasast.tool_hunter import _findings_from_content

    findings = _findings_from_content(
        tmp_path,
        [],
        '[{"path": "app.py", "line": 6, "family": "injection", "title": "t", "rationale": "r"}]',
    )
    assert findings and "family:injection" in findings[0].tags
    untagged = _findings_from_content(tmp_path, [], '[{"path": "app.py", "line": 6, "title": "t"}]')
    assert untagged and not [tag for tag in untagged[0].tags if tag.startswith("family:")]


def test_the_pair_hunter_asks_for_a_family_from_the_closed_list(tmp_path: Path) -> None:
    """The prompt has to name the taxonomy, or the model invents family names and every finding is noise."""
    from openultrasast.pairs import make_hunter_scan

    seen: list[str] = []

    class Client:
        def complete(self, *, model: str, messages, tools=None, **options):  # type: ignore[no-untyped-def]
            seen.append("\n".join(str(message.get("content") or "") for message in messages))
            from openultrasast.tool_hunter import ChatResponse

            return ChatResponse(content="[]", tool_calls=())

    (tmp_path / "app.py").write_text(VULN)
    make_hunter_scan(Client(), "m", taxonomy=load_families())(tmp_path)
    prompt = "\n".join(seen)
    assert "injection" in prompt and "access_control" in prompt and "untrusted_destination" in prompt
    assert '"family"' in prompt
