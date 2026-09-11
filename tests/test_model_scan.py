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


def test_an_exhausted_budget_withholds_the_judge_and_not_the_graph(tmp_path) -> None:
    """Req 3.2, 3.3: the budget bounds MODEL CALLS. Arbitration is free and must keep running.

    The driver used to break the region loop when the budget ran out, spending a paid limit to stop unpaid
    work. On VAmPI that left 16 of 22 regions unexamined and missed a BOLA the graph entails for nothing.

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
    assert result.regions_scanned == 50, "every region is still arbitrated; only the judge is withheld"
    assert result.regions_unjudged == 0
    assert result.regions_unasked > 0, "the regions the budget could not afford a judge for are counted"
    assert any("budget_exhausted" in str(d) for d in result.degradations)


def test_a_region_the_budget_could_not_afford_is_not_reported_as_clean(tmp_path) -> None:
    """`unasked` is the honesty counter: silent-because-decided and silent-because-unaffordable differ."""
    from openultrasast.model.scan import ScanBudget, scan_repository

    class _Client:
        def complete(self, **kw):  # type: ignore[no-untyped-def]
            from openultrasast.tool_hunter import ChatResponse

            return ChatResponse(content='{"vulnerable": true}')

    source = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
    for i in range(10):
        (tmp_path / f"f{i}.py").write_text(source)
    regions = tuple(_region(path=f"f{i}.py") for i in range(10))

    generous = scan_repository(
        tmp_path, regions, backend=_Backend(), client=_Client(), model="m", budget=ScanBudget(max_model_calls=500, max_regions=10)
    )
    starved = scan_repository(
        tmp_path, regions, backend=_Backend(), client=_Client(), model="m", budget=ScanBudget(max_model_calls=1, max_regions=10)
    )

    assert generous.regions_unasked == 0, "nothing went unasked when the budget covered the run"
    assert starved.regions_unasked > generous.regions_unasked
    assert starved.regions_scanned == generous.regions_scanned == 10


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


class _SlowBackend:
    """A backend whose build and whose queries each cost a measurable, distinguishable amount of time."""

    def __init__(self, build_cost: float, query_cost: float) -> None:
        self.build_cost = build_cost
        self.query_cost = query_cost

    def available(self) -> bool:
        return True

    def build(self, root):  # type: ignore[no-untyped-def]
        import time

        from openultrasast.cpg.backend import CpgResult

        time.sleep(self.build_cost)
        return CpgResult(cpg_path=Path("cpg.bin"), run=self._run)

    def _run(self, query, params):  # type: ignore[no-untyped-def]
        import time

        time.sleep(self.query_cost)
        return []


def test_the_scan_reports_where_its_wall_clock_went() -> None:
    """contributor-scan 2.2/2.3: build against query is a decision input, and a total cannot answer it.

    Whether a warm Joern server would buy anything depends on the ratio between a CPG build and the queries
    over it. Reporting one figure for the scan makes that question unanswerable from an artifact.
    """
    from openultrasast.model.scan import scan_repository

    result = scan_repository(
        Path("/repo"),
        (_region(),),
        backend=_SlowBackend(build_cost=0.30, query_cost=0.10),
        client=None,
        model="",
    )

    assert result.build_seconds >= 0.29, "the build was not timed"
    assert result.query_seconds >= 0.09, "the queries were not timed"
    assert result.seconds >= result.build_seconds + result.query_seconds
    assert result.arbitrate_seconds == round(max(result.seconds - result.build_seconds - result.query_seconds, 0.0), 2)


def test_a_failed_build_still_reports_what_the_build_cost() -> None:
    """A build that fails after two minutes is the most important timing in the artifact, not the least."""
    from openultrasast.model.scan import scan_repository

    result = scan_repository(Path("/repo"), (_region(),), backend=_Backend(fail=True), client=None, model="")

    assert result.build_seconds >= 0.0
    assert result.query_seconds == 0.0, "nothing was queried"


def test_only_an_entry_point_gets_the_interprocedural_question(tmp_path) -> None:
    """contributor-scan 2.4: the trust boundary decides, not convenience.

    An entry point's parameters ARE attacker input and a sink it reaches is its responsibility, so its
    question follows the call graph. A file the walker fell back to has neither property: treating an
    arbitrary helper's parameters as untrusted is what the repository default was protecting against.
    """
    from openultrasast.model.regions import ScanRegion
    from openultrasast.model.scan import ENTRY_POINT_CALL_DEPTH, _grouped, _spec_for

    def region(source: str, function: str | None) -> ScanRegion:
        return ScanRegion(path="a.py", function=function, language="python", families=("injection",), rank=1.0, source=source)

    spec = _spec_for("injection", "python")
    assert spec is not None
    handler = region("entry_point", "get_by_username")
    fallback = region("file_fallback", None)
    named_but_not_an_entry_point = region("file_fallback", "helper")

    grouped = _grouped((("0", handler, spec), ("1", fallback, spec), ("2", named_but_not_an_entry_point, spec)))["taint"]

    assert grouped["0"]["parameterSources"] == "true"
    assert grouped["0"]["callDepth"] == str(ENTRY_POINT_CALL_DEPTH)
    for rid in ("1", "2"):
        assert grouped[rid]["parameterSources"] == "false"
        assert grouped[rid]["callDepth"] == "0", "following calls from an arbitrary function is not sound"


def test_the_call_depth_is_bounded() -> None:
    """'Every method reachable from a handler' is most of a repository, and an unbounded question is slow."""
    from openultrasast.model.scan import ENTRY_POINT_CALL_DEPTH

    assert 0 < ENTRY_POINT_CALL_DEPTH <= 5


def test_the_scan_reports_query_time_per_kind() -> None:
    """contributor-scan 2.3: which query costs the time is the whole server-mode decision.

    On libpng the phase split taint 243.3s / config 10.7s over two invocations, against ~13s of fixed
    startup each. A single total cannot tell startup from evaluation, and the two lead to opposite answers.
    """
    from openultrasast.model.scan import scan_repository

    regions = (
        _region(path="a.py", families=("injection",)),
        _region(path="b.py", families=("config_secrets",)),
    )
    result = scan_repository(Path("/repo"), regions, backend=_Backend(), client=None, model="")

    assert set(result.query_seconds_by_kind) == {"taint", "config"}
    assert sum(result.query_seconds_by_kind.values()) <= result.query_seconds + 0.05


def test_one_defect_is_one_finding_however_many_regions_reach_it(tmp_path) -> None:
    """contributor-scan 2.9. Task 2.4 let a region's question follow the call graph, and the moment it did,
    many entry points could reach one shared sink: libpng reported the same site twenty-six times. A
    contributor shown the same defect twenty-six times learns to scroll past it."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import ModelFinding
    from openultrasast.model.scan import _deduplicated

    same = [
        (ModelFinding(site="wpng.c:335:main", family="memory", rung=Rung.SUSPICION, witness="w"), 0.2),
        (ModelFinding(site="wpng.c:335:main", family="memory", rung=Rung.ENTAILED, witness="w"), 1.0),
        (ModelFinding(site="wpng.c:335:main", family="memory", rung=Rung.SUSPICION, witness="w"), 0.5),
    ]

    kept = _deduplicated(same)

    assert len(kept) == 1
    finding, rank = kept[0]
    assert finding.rung is Rung.ENTAILED, "the strongest rung survives"
    assert finding.reached_from == 3, "and the count is what the duplication was worth"
    assert rank == 1.0


def test_two_families_at_one_site_stay_two_findings() -> None:
    """`echo $_GET[...]` is an injection question and an output-encoding question, with different answers."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import ModelFinding
    from openultrasast.model.scan import _deduplicated

    both = [
        (ModelFinding(site="app.php:9:show", family="injection", rung=Rung.ENTAILED), 1.0),
        (ModelFinding(site="app.php:9:show", family="output_encoding", rung=Rung.ENTAILED), 1.0),
    ]

    assert len(_deduplicated(both)) == 2


def test_a_query_the_engine_could_not_answer_is_recorded_not_ignored() -> None:
    """contributor-scan 5.7. A 117k-line PHP CPG threw while loading, so every query returned nothing -- and
    the scan reported 500 regions examined, no findings, and no degradation. A failed query and a clean
    repository looked identical.

    This is the failure mode the rung ladder cannot catch: every other honesty counter labels a VERDICT, and
    here none was produced to label.
    """
    from openultrasast.cpg.backend import CpgResult
    from openultrasast.model.scan import scan_repository

    class _Backend:
        def available(self) -> bool:
            return True

        def build(self, root, **kwargs):  # type: ignore[no-untyped-def]
            return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: [], run_batch=lambda q, r: None)

    result = scan_repository(Path("/repo"), (_region(),), backend=_Backend(), client=None, model="")

    failures = [d for d in result.degradations if d.get("reason") == "query_failed"]
    assert failures, "a query that could not be asked must be reported"
    kinds = {d["kind"] for d in failures}
    assert "taint" in kinds, "the taint failure is recorded"
    assert "evidence" in kinds, "and so is the evidence pass that runs before it -- phase 0 of flow-aware-ranking"
    assert result.findings == ()


def test_a_region_cap_that_hides_most_of_a_repository_is_reported() -> None:
    """Paid Memberships Pro yields 4,463 regions from 637 files. A default budget of 500 examines 11% of it,
    and a report that does not say so invites its silence to be read as a clean bill of health for the rest.
    """
    from openultrasast.model.regions import ScanRegion
    from openultrasast.model.scan import ScanBudget, scan_repository

    class _Backend:
        def available(self) -> bool:
            return True

        def build(self, root, *, language=""):  # type: ignore[no-untyped-def]
            from openultrasast.cpg.backend import CpgResult

            return CpgResult(cpg_path=Path("cpg.bin"), run=lambda query, params: [])

    regions = [
        ScanRegion(path=f"f{n}.py", function="handler", language="python", families=("injection",), rank=0.5, source="entry_point")
        for n in range(30)
    ]
    result = scan_repository(Path("."), regions, backend=_Backend(), budget=ScanBudget(max_model_calls=0, max_regions=10))

    truncated = [d for d in result.degradations if d.get("reason") == "regions_truncated"]
    assert truncated, "the cap hid two thirds of the regions and said nothing"
    assert truncated[0]["examined"] == 10 and truncated[0]["total"] == 30


def test_tier_zero_pairs_are_not_asked_and_nothing_else_is_skipped() -> None:
    """Phase 1 of flow-aware-ranking. A pair with no sink of its family in reach cannot yield a flow, so its
    taint request is never issued -- and every other pair's request still is."""
    from openultrasast.model.regions import ScanRegion
    from openultrasast.model.scan import ScanBudget, scan_repository

    issued: list[dict[str, object]] = []

    class _Backend:
        def available(self) -> bool:
            return True

        def build(self, root, *, language=""):  # type: ignore[no-untyped-def]
            from openultrasast.cpg.backend import CpgResult

            def batch(kind, requests):  # type: ignore[no-untyped-def]
                if any(p.get("evidenceOnly") == "true" for p in requests.values()):
                    # Every family but the first has no sink in reach.
                    return {
                        rid: [{"kind": "summary", "sinks": 1 if i == 0 else 0, "sourceLocal": True, "familyInRepo": True}]
                        + (
                            [
                                {
                                    "kind": "sink",
                                    "sink": "os.system(x)",
                                    "sinkLine": "4",
                                    "sinkMethod": "run",
                                    "sinkArity": 1,
                                    "sinkArg0Literal": False,
                                    "cleansedOnCall": False,
                                }
                            ]
                            if i == 0
                            else []
                        )
                        for i, rid in enumerate(requests)
                    }
                issued.append({"kind": kind, "count": len(requests)})
                return {rid: [] for rid in requests}

            return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: [], run_batch=batch)

    region = ScanRegion(
        path="a.py", function="run", language="python", families=("injection", "path", "deserialization"), rank=0.9, source="entry_point"
    )
    result = scan_repository(Path("."), [region], backend=_Backend(), budget=ScanBudget(max_model_calls=0))

    taint = next(i for i in issued if i["kind"] == "taint")
    assert taint["count"] == 1, "only the pair with a sink in reach is asked"
    assert result.requests_pruned == 2, "and the two tier-0 pairs are counted, not silently dropped"
    assert not any(d.get("reason") == "query_failed" for d in result.degradations)


def test_the_budget_is_spent_by_evidence_when_asked() -> None:
    """Phase 2 of flow-aware-ranking. With `order_by_evidence`, the evidence pass runs over every region and
    the region cap is cut from the (tier, score) order, so a low-ranked region with an open sink and a
    local source is examined before a top-ranked region with no sink in reach. Off, the static order holds."""
    from openultrasast.model.regions import ScanRegion
    from openultrasast.model.scan import ScanBudget, scan_repository

    class _Backend:
        def __init__(self) -> None:
            self.taint_files: list[list[str]] = []
            self.evidence_sizes: list[int] = []

        def available(self) -> bool:
            return True

        def build(self, root, *, language=""):  # type: ignore[no-untyped-def]
            from openultrasast.cpg.backend import CpgResult

            def batch(kind, requests):  # type: ignore[no-untyped-def]
                if any(p.get("evidenceOnly") == "true" for p in requests.values()):
                    self.evidence_sizes.append(len(requests))
                    out = {}
                    for rid, params in requests.items():
                        hot = str(params.get("file", "")).endswith("low.py")
                        out[rid] = [{"kind": "summary", "sinks": 1 if hot else 0, "sourceLocal": hot, "familyInRepo": True}] + (
                            [
                                {
                                    "kind": "sink",
                                    "sink": "os.system(x)",
                                    "sinkLine": "4",
                                    "sinkMethod": "run",
                                    "sinkArity": 1,
                                    "sinkArg0Literal": False,
                                    "cleansedOnCall": False,
                                }
                            ]
                            if hot
                            else []
                        )
                    return out
                if kind == "taint":
                    self.taint_files.append(sorted({str(p.get("file", "")) for p in requests.values()}))
                return {rid: [] for rid in requests}

            return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: [], run_batch=batch)

    top = ScanRegion(path="top.py", function="handle", language="python", families=("injection",), rank=1.0, source="entry_point")
    low = ScanRegion(path="low.py", function="run", language="python", families=("injection",), rank=0.3, source="entry_point")

    static = _Backend()
    scan_repository(Path("."), [top, low], backend=static, budget=ScanBudget(max_model_calls=0, max_regions=1))
    assert static.evidence_sizes == [1] and static.taint_files == [], (
        "static order: the budget holds `top`, whose pair is tier 0 and pruned"
    )

    ordered = _Backend()
    result = scan_repository(
        Path("."), [top, low], backend=ordered, budget=ScanBudget(max_model_calls=0, max_regions=1, order_by_evidence=True)
    )
    assert ordered.evidence_sizes == [2], "the evidence pass covers every region, not only the budget"
    assert ordered.taint_files == [["low.py"]], "and the budget is spent on the region the evidence points at"
    assert result.tier_counts == {0: 1, 4: 1}
