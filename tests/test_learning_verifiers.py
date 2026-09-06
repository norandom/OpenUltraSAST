"""learning-harness task 2.6: the verifier registry and the oracle callback (offline)."""

from __future__ import annotations

from pathlib import Path

import pytest

from openultrasast.findings import StaticFinding
from openultrasast.learning.families import load_families
from openultrasast.regress.verdict import NOT_TRIGGERABLE, TRIGGERABLE, verdict_from_result
from openultrasast.sandbox import SandboxResult

APP = (
    "from flask import request\n\n\n"
    "@app.route('/books/<title>')\n@login_required\ndef guarded(title):\n"
    "    return Book.query.filter_by(book_title=title).first()\n\n\n"
    "@app.route('/books/any/<title>')\ndef leaky(title):\n"
    "    owner = request.args.get('owner')\n"
    "    return Book.query.filter_by(user_id=owner, book_title=title).first()\n\n\n"
    "@app.route('/health')\ndef health():\n    return {'ok': True}\n"
)


def _claim(function: str, line: int, family: str) -> StaticFinding:
    return StaticFinding(
        finding_id=f"detector:app.py:{line}",
        path="app.py",
        title="t",
        severity="medium",
        confidence="low",
        evidence_level="suspicion",
        rationale="r",
        line=line,
        function_name=function,
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[f"family:{family}"],
        ranking_priority=0.0,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(APP)
    return tmp_path


def test_an_oracle_decides_the_verdict_and_the_exit_code_no_longer_does() -> None:
    from openultrasast.learning.verifiers import token_oracle

    oracle = token_oracle("CANARY:9f2a")
    fired = SandboxResult(exit_code=0, stdout="ok\nCANARY:9f2a\n", stderr="", timed_out=False)
    quiet = SandboxResult(exit_code=1, stdout="boom", stderr="Traceback", timed_out=False)
    assert verdict_from_result(fired, oracle=oracle).verdict == TRIGGERABLE
    assert verdict_from_result(quiet, oracle=oracle).verdict == NOT_TRIGGERABLE  # a crash is not this family's oracle
    assert verdict_from_result(quiet).verdict == TRIGGERABLE  # without an oracle the exit code still decides
    assert verdict_from_result(fired, oracle=oracle).reason == "oracle_fired"


def test_an_oracle_never_overrides_an_inconclusive_run() -> None:
    from openultrasast.learning.verifiers import token_oracle

    oracle = token_oracle("CANARY:9f2a")
    timed_out = SandboxResult(exit_code=0, stdout="CANARY:9f2a", stderr="", timed_out=True)
    assert verdict_from_result(timed_out, oracle=oracle).verdict == "inconclusive"
    assert verdict_from_result(None, oracle=oracle).verdict == "inconclusive"
    assert verdict_from_result(sandbox_missing=True, oracle=oracle).reason == "sandbox_unavailable"


def test_the_registry_answers_by_the_family_s_declared_verifier_kind() -> None:
    from openultrasast.learning.verifiers import NoVerifier, StaticVerifier, verifier_for

    taxonomy = load_families()
    assert isinstance(verifier_for(taxonomy.by_id("access_control")), StaticVerifier)
    assert isinstance(verifier_for(taxonomy.by_id("memory")), NoVerifier)
    assert isinstance(verifier_for(taxonomy.by_id("output_encoding")), NoVerifier)
    # a canary family with no canary implementation registered yet reports at suspicion rather than pretending
    injection = verifier_for(taxonomy.by_id("injection"))
    assert isinstance(injection, NoVerifier) and injection.kind == "canary"


def test_a_family_with_no_verifier_leaves_the_claim_at_suspicion(repo: Path) -> None:
    from openultrasast.learning.verifiers import verifier_for

    taxonomy = load_families()
    verification = verifier_for(taxonomy.by_id("memory")).verify(_claim("leaky", 12, "memory"), root=repo, language="python")
    assert verification.rung == "suspicion" and verification.reason == "no_verifier"


def test_the_static_verifier_raises_an_access_control_claim_the_checker_agrees_with(repo: Path) -> None:
    from openultrasast.learning.verifiers import verifier_for

    taxonomy = load_families()
    verifier = verifier_for(taxonomy.by_id("access_control"))
    agreed = verifier.verify(_claim("leaky", 12, "access_control"), root=repo, language="python")
    assert agreed.rung == "static_corroboration" and "identity_constraint" in agreed.oracle_output
    # the checker owes nothing in a handler that touches no protected resource, so it refuses to corroborate
    healthy = verifier.verify(_claim("health", 16, "access_control"), root=repo, language="python")
    assert healthy.rung == "suspicion" and healthy.reason == "checker_disagrees"
    elsewhere = verifier.verify(_claim("missing", 99, "access_control"), root=repo, language="python")
    assert elsewhere.rung == "suspicion"


def test_a_verification_is_written_onto_the_claim_as_a_tag_and_nothing_else(repo: Path) -> None:
    """The evidence ladder belongs to another boundary; a verifier says what it saw with a tag."""
    from openultrasast.learning.verifiers import apply_verification, verifier_for

    taxonomy = load_families()
    claim = _claim("leaky", 12, "access_control")
    verified = apply_verification(claim, verifier_for(taxonomy.by_id("access_control")).verify(claim, root=repo, language="python"))
    assert "verifier:static_corroboration" in verified.tags
    assert verified.evidence_level == "suspicion" and claim.evidence_level == "suspicion"  # the ladder is untouched
    plain = apply_verification(claim, verifier_for(taxonomy.by_id("memory")).verify(claim, root=repo, language="python"))
    assert "verifier:suspicion" in plain.tags and plain.tags.count("verifier:suspicion") == 1


def test_a_rung_only_reaches_the_ladder_through_an_explicit_mapping() -> None:
    """Every rung must land on a level the project's ladder actually defines, or the report raises later."""
    from openultrasast.learning.verifiers import RUNGS, evidence_level_for
    from openultrasast.verification import EvidenceLevel

    assert {rung: evidence_level_for(rung) for rung in RUNGS} == {
        "suspicion": EvidenceLevel.SUSPICION,
        "static_corroboration": EvidenceLevel.STATIC_CORROBORATION,
        "proven": EvidenceLevel.EXPLOIT_DEMONSTRATED,
    }
    assert all(EvidenceLevel(evidence_level_for(rung).value) for rung in RUNGS)  # never a value outside the ladder


def test_a_verified_claim_still_passes_the_projects_own_verification_helpers(repo: Path) -> None:
    """The bug this pins: stamping a learning rung onto evidence_level raised ValueError in three call sites."""
    from openultrasast.learning.verifiers import Verification, apply_verification, raise_to
    from openultrasast.verification import VerificationStatus, is_report_verified, verify_finding

    claim = _claim("lookup", 3, "injection")
    proven = apply_verification(claim, Verification(rung="proven", reason="oracle_fired", oracle_output="CANARY x"))
    assert "verifier:proven" in proven.tags
    assert verify_finding(proven).evidence_level == "suspicion"  # would raise ValueError if the rung were stamped on
    assert is_report_verified(proven.evidence_level, VerificationStatus.ACCEPTED) is False
    raised = raise_to(proven, "proven")
    assert raised.evidence_level == "exploit_demonstrated"
    assert verify_finding(raised).evidence_level == "exploit_demonstrated"
    assert is_report_verified(raised.evidence_level, VerificationStatus.ACCEPTED) is True
