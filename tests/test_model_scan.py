"""contributor-scan task 1.2: the repository driver (Req 3).

Pair scoring built one CPG per pair and asked one region. A repository has thousands of regions, and the two
things that were free at pair scale are the two that dominate here:

* **CPG construction.** A build is 5-30s on a 40-line excerpt. Building one per region would make a
  repository scan unusable, so the driver builds ONE and reuses it.
* **Model calls.** The enumerator caps candidates at 8 per region, which says nothing about a scan with two
  thousand regions. The budget is therefore a total for the run, spent on the highest-ranked regions first,
  and whatever it does not reach is COUNTED rather than quietly dropped.
"""

from __future__ import annotations

from pathlib import Path


def _region(path="a.py", function="run", families=("injection",), rank=1.0):  # type: ignore[no-untyped-def]
    from openultrasast.model.regions import ScanRegion

    return ScanRegion(path=path, function=function, language="python", families=families, rank=rank, source="entry_point")


class _Backend:
    """Counts builds, so the one-CPG-per-scan promise is testable rather than asserted."""

    def __init__(self, fail: bool = False) -> None:
        self.builds = 0
        self._fail = fail

    def available(self) -> bool:
        return True

    def build(self, root):  # type: ignore[no-untyped-def]
        from openultrasast.cpg.backend import CpgResult

        self.builds += 1
        if self._fail:
            return None
        return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: [])


def test_one_cpg_is_built_for_the_whole_repository() -> None:
    from openultrasast.model.scan import scan_repository

    backend = _Backend()
    regions = tuple(_region(path=f"f{i}.py") for i in range(20))
    scan_repository(Path("/repo"), regions, backend=backend, client=None, model="")
    assert backend.builds == 1, "a build per region would make a repository scan unusable"


def test_a_failed_build_yields_an_empty_result_not_an_exception() -> None:
    from openultrasast.model.scan import scan_repository

    result = scan_repository(Path("/repo"), (_region(),), backend=_Backend(fail=True), client=None, model="")
    assert result.findings == ()
    assert any("cpg_build_failed" in str(d) for d in result.degradations)


def test_the_budget_is_a_total_for_the_run_and_the_remainder_is_counted(tmp_path) -> None:
    """Req 3.2, 3.3: silently truncating is the failure this exists to prevent.

    Real files on disk, because the driver enumerates candidates from them. A region pointing at a path that
    does not exist yields no candidates, no model calls, and a budget that never trips -- which would make
    this test pass for the wrong reason.
    """
    from openultrasast.model.scan import ScanBudget, scan_repository

    class _Client:
        def complete(self, **kw):  # type: ignore[no-untyped-def]
            from openultrasast.tool_hunter import ChatResponse

            return ChatResponse(content='{"vulnerable": true}')

    source = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
    for i in range(50):
        (tmp_path / f"f{i}.py").write_text(source)
    regions = tuple(_region(path=f"f{i}.py") for i in range(50))

    result = scan_repository(
        tmp_path,
        regions,
        backend=_Backend(),
        client=_Client(),
        model="m",
        budget=ScanBudget(max_model_calls=5, max_regions=50),
    )
    assert result.model_calls > 0, "the driver must enumerate candidates and ask the judge about them"
    assert result.regions_unjudged > 0
    assert result.regions_scanned + result.regions_unjudged == 50
    assert any("budget_exhausted" in str(d) for d in result.degradations)


def test_the_budget_is_spent_on_the_highest_ranked_regions_first() -> None:
    from openultrasast.model.scan import ScanBudget, scan_repository

    seen: list[str] = []

    class _Backend2(_Backend):
        def build(self, root):  # type: ignore[no-untyped-def]
            from openultrasast.cpg.backend import CpgResult

            self.builds += 1
            return CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: (seen.append(str(p.get("function"))), [])[1])

    regions = (_region(path="low.py", function="low", rank=0.1), _region(path="high.py", function="high", rank=1.0))
    scan_repository(Path("/repo"), regions, backend=_Backend2(), client=None, model="", budget=ScanBudget(max_regions=1))
    assert seen and seen[0] == "high", f"budget spent on the wrong region first: {seen}"


def test_findings_are_ordered_by_rung_before_rank() -> None:
    """Req 3.1: what the model established outranks what the LLM merely proposed."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import ModelFinding
    from openultrasast.model.scan import _ordered

    findings = [
        (ModelFinding(site="a", family="injection", rung=Rung.SUSPICION), 1.0),
        (ModelFinding(site="b", family="injection", rung=Rung.ENTAILED), 0.1),
        (ModelFinding(site="c", family="injection", rung=Rung.CORROBORATED), 0.5),
    ]
    assert [f.site for f in _ordered(findings)] == ["b", "c", "a"]


def test_the_result_reports_what_the_model_arbitrated() -> None:
    """Req 1.5: a user should see how much of the result the model established, not have to infer it."""
    from openultrasast.model.scan import scan_repository

    result = scan_repository(Path("/repo"), (_region(),), backend=_Backend(), client=None, model="")
    assert set(result.by_rung) >= {"model_entailed", "model_corroborated", "suspicion"}
    assert result.regions_scanned == 1


def test_a_region_is_only_asked_about_families_it_carries() -> None:
    from openultrasast.model.scan import scan_repository

    asked: list[str] = []

    class _B(_Backend):
        def build(self, root):  # type: ignore[no-untyped-def]
            from openultrasast.cpg.backend import CpgResult

            self.builds += 1
            return CpgResult(cpg_path=Path("c.bin"), run=lambda q, p: (asked.append(q), [])[1])

    scan_repository(Path("/repo"), (_region(families=("injection",)),), backend=_B(), client=None, model="")
    assert "dominance" not in asked and "config" not in asked


def test_the_driver_issues_one_query_invocation_per_kind_not_one_per_region(tmp_path) -> None:
    """Task 1.4: JVM startup, not CPG construction, is what dominates a repository scan.

    Before batching the driver issued one `joern --script` call per region per family. A ten-line Python file
    admits six families, so it cost six JVM launches and over four minutes; a thousand regions would have
    taken about fifty hours. The whole scan's questions now go in one invocation per query kind.
    """
    from openultrasast.model.scan import scan_repository

    invocations: list[str] = []

    class _CountingBackend:
        def available(self):  # type: ignore[no-untyped-def]
            return True

        def build(self, root):  # type: ignore[no-untyped-def]
            from openultrasast.cpg.backend import CpgResult

            def run(query, params):  # type: ignore[no-untyped-def]
                invocations.append(f"single:{query}")
                return []

            def run_batch(query, requests):  # type: ignore[no-untyped-def]
                invocations.append(f"batch:{query}")
                return {rid: [] for rid in requests}

            result = CpgResult(cpg_path=Path("c.bin"), run=run)
            object.__setattr__(result, "run_batch", run_batch)
            return result

    source = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
    for i in range(30):
        (tmp_path / f"f{i}.py").write_text(source)
    regions = tuple(_region(path=f"f{i}.py", families=("injection", "path")) for i in range(30))

    scan_repository(tmp_path, regions, backend=_CountingBackend(), client=None, model="")
    assert not any(i.startswith("single:") for i in invocations), f"unbatched calls remain: {invocations[:4]}"
    # 30 regions x 2 families would have been 60 invocations; batching makes it one per query kind.
    assert len(invocations) <= 3, f"expected one invocation per query kind, got {len(invocations)}"
