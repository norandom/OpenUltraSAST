"""model-grounded-detection task 6.1: the execution tier is deferred, adopted, and narrow (Req 10).

The rung this project does NOT build. Clearwing already runs sandboxes, container pools, sanitizer images and
PoC stability, and this session's own history says reimplementing that class of machinery is where we go
wrong. So `execution_confirmed` exists as a rung, the seam calls an adopted tool, and the eligibility rule is
deliberately narrow: only a finding the static model could not decide, in a family a static model genuinely
cannot arbitrate.

Everything here runs with Clearwing absent, which is the normal case.
"""

from __future__ import annotations

import pytest


def _finding(family="memory", rung="suspicion"):  # type: ignore[no-untyped-def]
    from openultrasast.model.execution import Candidate

    return Candidate(finding_id="f1", family=family, rung=rung, path="a.c", line=10)


def test_only_a_family_a_static_model_cannot_arbitrate_is_eligible() -> None:
    """Req 10.3: no web/logic class depends on this tier. They have taint, dominance and constant abstraction."""
    from openultrasast.model.execution import eligible

    assert eligible(_finding(family="memory")) is True
    for family in ("injection", "access_control", "path", "config_secrets", "output_encoding"):
        assert eligible(_finding(family=family)) is False, f"{family} must be arbitrated statically"


def test_a_finding_the_model_already_decided_is_not_escalated() -> None:
    """Req 10.1: the tier is reached only where the model could not decide -- never to double-check itself."""
    from openultrasast.model.execution import eligible

    assert eligible(_finding(rung="suspicion")) is True
    assert eligible(_finding(rung="model_entailed")) is False
    assert eligible(_finding(rung="model_corroborated")) is False


def test_without_clearwing_the_rung_is_never_reached_and_the_reason_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Req 11.3: an absent capability degrades to a recorded reason, never a traceback and never a verdict."""
    from openultrasast.model.execution import confirm, resolve_execution_backend

    monkeypatch.setenv("OPENULTRASAST_CLEARWING", "off")
    backend = resolve_execution_backend()
    assert backend.available() is False
    outcome = confirm(_finding(), backend=backend)
    assert outcome.rung is None, "no engine, no rung"
    assert "clearwing_unavailable" in outcome.reason


def test_an_ineligible_finding_is_not_sent_to_the_sandbox_even_when_one_exists() -> None:
    from openultrasast.model.execution import confirm

    class _Backend:
        def __init__(self) -> None:
            self.calls = 0

        def available(self) -> bool:
            return True

        def reproduce(self, candidate: object) -> bool:
            self.calls += 1
            return True

    backend = _Backend()
    outcome = confirm(_finding(family="injection"), backend=backend)
    assert outcome.rung is None and backend.calls == 0
    assert "not_eligible" in outcome.reason


def test_a_reproduced_candidate_reaches_execution_confirmed() -> None:
    from openultrasast.model.execution import confirm
    from openultrasast.model.ladder import Rung

    class _Backend:
        def available(self) -> bool:
            return True

        def reproduce(self, candidate: object) -> bool:
            return True

    assert confirm(_finding(), backend=_Backend()).rung is Rung.EXECUTION_CONFIRMED


def test_a_candidate_that_does_not_reproduce_stays_where_it_was() -> None:
    """Not reproducing is not a refutation: the sandbox failing to trigger a bug does not prove its absence."""
    from openultrasast.model.execution import confirm

    class _Backend:
        def available(self) -> bool:
            return True

        def reproduce(self, candidate: object) -> bool:
            return False

    outcome = confirm(_finding(), backend=_Backend())
    assert outcome.rung is None
    assert "not_reproduced" in outcome.reason and "refut" not in outcome.reason.lower()


def test_the_seam_reimplements_no_sandbox_machinery() -> None:
    """Req 10.2, asserted structurally. The one thing this module must not grow is a sandbox."""
    import ast
    from pathlib import Path

    source = Path("src/openultrasast/model/execution.py").read_text()
    tree = ast.parse(source)
    imported = {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    imported |= {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    for banned in ("docker", "podman", "subprocess", "container", "sandbox"):
        assert banned not in imported, f"the execution tier must adopt, not build: {banned}"
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for banned in ("build_image", "run_container", "compile_target", "apply_patch"):
        assert banned not in names, f"{banned} belongs to the adopted tool, not here"
