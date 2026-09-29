"""`agree` scores exactly as the reference measurement did (ai-service-plane Requirement 6).

The reference is `benchmarks/independent/score_batched.py` over the batched-check scans: sites anchored by
`score_batched.anchored`, matched by `evaluate.matches_v2` against `evaluate.hunks(case, "old")`. The plane cannot
ship the benchmark tree, so the generator resolves the ranges into `case.json` and `agree.matches_declared`
reproduces the rule. These tests run both on the recorded reference outputs of the 15 validation cases and
require identical verdicts, identical ranges, and the reference's own numbers (16 of 20, $0.022) back from `agree`.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from openultrasast.plane.manifests import load_manifests
from openultrasast.plane.tasks import agree

BENCH = Path("benchmarks/independent")
POPULATION = BENCH / "population-v2.toml"
SCANS = Path.home() / "ousast-results" / "independent-v2-batched-check" / "scans"
REPOS = Path.home() / ".cache" / "openultrasast" / "independent"
INPUTS = sorted(Path("plane/workspaces").glob("*-inputs.yaml"))

pytestmark = pytest.mark.skipif(
    not SCANS.is_dir() or not REPOS.is_dir(), reason="recorded batched-check scans or case clones not on this host"
)


def _load(name: str) -> ModuleType:
    sys.path.insert(0, str(BENCH.resolve()))  # score_batched imports evaluate by name
    try:
        spec = importlib.util.spec_from_file_location(f"parity_{name}", BENCH / f"{name}.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(BENCH.resolve()))


@pytest.fixture(scope="module")
def reference() -> tuple[ModuleType, ModuleType]:
    evaluate, score_batched = _load("evaluate"), _load("score_batched")
    evaluate.use(POPULATION.resolve())
    return evaluate, score_batched


def _inputs() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for workspace in load_manifests(INPUTS).workspaces.values():
        files = {f.path: json.loads(f.content) for f in workspace.files}
        out[files["case.json"]["id"]] = files
    assert len(out) == 15, sorted(out)
    return out


def _records() -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in tomllib.loads(POPULATION.read_text())["case"]}


def test_committed_ranges_are_the_reference_hunks(reference: tuple[ModuleType, ModuleType]) -> None:
    evaluate, _ = reference
    records = _records()
    for case_id, files in _inputs().items():
        hunks = {path: [list(span) for span in spans] for path, spans in evaluate.hunks(records[case_id], "old").items()}
        assert files["case.json"]["ranges"] == hunks, case_id


def test_matching_verdicts_are_identical_on_the_recorded_outputs(reference: tuple[ModuleType, ModuleType]) -> None:
    evaluate, score_batched = reference
    records = _records()
    compared = declared = matched = 0
    for case_id, files in _inputs().items():
        record, mine = records[case_id], files["case.json"]
        old = evaluate.hunks(record, "old")
        recorded = json.loads((SCANS / f"{case_id}--vulnerable_a.json").read_text())
        raw = [dict(f) for key in ("findings", "disputed") for f in recorded.get(key, [])]
        anchored = score_batched.anchored(json.loads(json.dumps({"findings": raw})))["findings"]
        assert [agree.anchor_site(f["candidate"], f["site"]) for f in raw] == [f["site"] for f in anchored], case_id
        family = record["family"]
        probes = [{"site": f["site"], "family": f["family"]} for f in anchored]
        probes += [{"site": f"{p}:{ln}:{fn}", "family": family} for p, fn, ln in files["triage.json"]["candidates"]]
        sites = [{"site": f"{s.partition('::')[0]}:0:{s.partition('::')[2]}", "family": family} for s in record.get("sites", [])]
        declared += len(sites)
        probes += sites
        probes += [dict(p, family="not-" + family) for p in probes]
        for probe in probes:
            theirs = evaluate.matches_v2(probe, record, old)
            assert agree.matches_declared(probe, mine, mine["ranges"]) == theirs, (case_id, probe)
            compared += 1
            matched += theirs
    assert declared == 22 and compared > 2 * (declared + 46)
    assert matched > 0


def _units(case_id: str, kept: list[list[Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], float]:
    """The recorded per-file hunts as two `verify` passes: a hunt's usd is the file's spend minus its triage."""
    from openultrasast.model.endpoint import price_of
    from openultrasast.plane.budget import cost_of

    prices = price_of("deepseek-flash")
    assert prices is not None
    passes: tuple[list[dict[str, Any]], list[dict[str, Any]]] = ([], [])
    triage = 0.0
    for text in (SCANS / f"{case_id}--vulnerable_a.jsonl").read_text().splitlines():
        row = json.loads(text)
        hunts = cost_of(row.get("usage") or {}, prices)
        triage += max(float(row["usd"]) - hunts, 0.0)
        asked = [c for c in kept if c[0] == row["path"]]
        if not asked:
            continue
        for index, flagged in enumerate(row["passes"]):
            passes[index].append({"path": row["path"], "candidates": asked, "flagged": flagged, "usd": hunts / 2, "turns": 0})
    return passes[0], passes[1], triage


def test_agree_on_the_reference_outputs_reproduces_the_reference_numbers(tmp_path: Path) -> None:
    score = json.loads((SCANS.parent / "score.json").read_text())
    detected = {c["id"]: len(c["detected_sites"]) for c in score["cases"] if "detected_sites" in c and c["detected_sites"] is not None}
    agreed = in_set = before = 0
    spend = with_triage = 0.0
    for case_id, files in _inputs().items():
        case = files["case.json"]
        pass_a, pass_b, triage = _units(case_id, files["candidates.json"]["candidates"])
        assert case["cost"]["recorded_triage_usd"] == pytest.approx(triage, abs=1e-6)
        summary = agree.run(tmp_path / case_id, files["candidates.json"], pass_a, pass_b, sites=case)
        metrics = summary["metrics"]
        assert metrics["site_matching"] == "assessed"
        assert metrics["declared_sites_matched_agreed"] == detected[case_id], case_id
        agreed += metrics["declared_sites_matched_agreed"]
        in_set += metrics["declared_sites_in_set"]
        before += metrics["candidates_before_triage"]
        spend += metrics["usd_total"]
        with_triage += metrics["usd_total_with_recorded_triage"]
    assert (agreed, in_set, before) == (16, 20, 46)
    assert with_triage == pytest.approx(1.0123, abs=1e-3)  # the recorded spend: the reference's $1.01
    assert round(with_triage / before, 3) == 0.022 and spend < with_triage
