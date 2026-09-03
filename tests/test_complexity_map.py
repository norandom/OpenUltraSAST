import json
from pathlib import Path

from openultrasast.complexity.map import build_complexity_map
from openultrasast.findings import StaticFinding
from openultrasast.preprocess import FileTarget

_HOTSPOT_FIELDS = {
    "path",
    "function_name",
    "score",
    "band",
    "signals",
    "rationale",
    "test_hint",
    "inventory_finding_ids",
}


def _target(
    path: str,
    *,
    loc: int,
    tags: list[str] | None = None,
    language: str = "python",
    hints: list[dict[str, object]] | None = None,
    has_fuzz_entry_point: bool = False,
) -> FileTarget:
    return FileTarget(
        path=path,
        absolute_path=f"/repo/{path}",
        language=language,
        loc=loc,
        tags=list(tags or []),
        has_fuzz_entry_point=has_fuzz_entry_point,
        reachability_hints=list(hints or []),
    )


def _hit(path: str, finding_id: str) -> StaticFinding:
    return StaticFinding(
        finding_id=finding_id,
        path=path,
        title="pattern hit",
        severity="low",
        confidence="medium",
        evidence_level="static_corroboration",
        rationale="inventory",
        line=1,
        function_name=None,
        reachability_status="unknown",
        reachability_evidence=[],
        reachability_conditions=[],
        tags=[],
        ranking_priority=1.0,
    )


def _parser_helper_fixture() -> tuple[list[FileTarget], list[StaticFinding], tuple[str, ...]]:
    parser = _target(
        "src/parser.c",
        loc=400,
        language="c",
        tags=["parser", "memory_unsafe"],
        hints=[{"kind": "parser", "access_level": "public", "function_name": "parse_header"}],
    )
    helper = _target("src/helper.py", loc=1, tags=[])
    findings = [_hit("src/helper.py", f"rule:helper:{index}") for index in range(8)]
    repo_files = ("src/parser.c", "src/helper.py", "tests/test_parser.c")
    return [parser, helper], findings, repo_files


def test_map_order_differs_from_inventory_hit_count(tmp_path: Path) -> None:
    targets, findings, repo_files = _parser_helper_fixture()
    artifact = tmp_path / "complexity_map.json"

    complexity_map = build_complexity_map(targets, findings, artifact, repo_files=repo_files)

    map_paths = [hotspot.path for hotspot in complexity_map.hotspots]
    hit_count_paths = [
        hotspot.path
        for hotspot in sorted(
            complexity_map.hotspots,
            key=lambda item: (-len(item.inventory_finding_ids), item.path),
        )
    ]
    parser = next(hotspot for hotspot in complexity_map.hotspots if hotspot.path == "src/parser.c")
    helper = next(hotspot for hotspot in complexity_map.hotspots if hotspot.path == "src/helper.py")

    assert map_paths != hit_count_paths
    assert map_paths[0] == "src/parser.c"
    assert parser.inventory_finding_ids == ()
    assert len(helper.inventory_finding_ids) == 8
    assert helper.inventory_finding_ids == tuple(f"rule:helper:{index}" for index in range(8))
    assert parser.score > helper.score
    assert parser.function_name == "parse_header"
    assert parser.band == "high"
    assert helper.band == "low"
    assert complexity_map.heuristic_only is True
    assert parser.test_hint is not None
    assert parser.test_hint.gap == "no_fuzz_entry"
    assert parser.test_hint.test_kind == "fuzz-harness"
    assert helper.test_hint is not None
    assert helper.test_hint.gap == "no_adjacent_test"
    assert helper.test_hint.test_kind == "unit"
    assert "verified" not in parser.rationale.lower()
    assert "worth fixing" not in parser.rationale.lower()
    assert "worth_fixing" not in parser.rationale.lower()


def test_complexity_map_json_has_required_fields(tmp_path: Path) -> None:
    targets, findings, repo_files = _parser_helper_fixture()
    artifact = tmp_path / "runs" / "complexity_map.json"

    complexity_map = build_complexity_map(targets, findings, artifact, repo_files=repo_files)
    raw = artifact.read_text()
    payload = json.loads(raw)

    assert raw == json.dumps(payload, indent=2, sort_keys=True) + "\n"
    assert payload["heuristic_only"] is True
    assert [item["path"] for item in payload["hotspots"]] == [hotspot.path for hotspot in complexity_map.hotspots]
    for hotspot in payload["hotspots"]:
        assert set(hotspot) >= _HOTSPOT_FIELDS
        assert hotspot["band"] in {"high", "medium", "low"}
        assert isinstance(hotspot["score"], float)
        assert isinstance(hotspot["rationale"], str) and hotspot["rationale"]
        assert isinstance(hotspot["signals"], dict)
        assert set(hotspot["signals"]) >= {"loc", "nesting", "reachability", "inventory_hit_count", "has_adjacent_test"}
        assert isinstance(hotspot["inventory_finding_ids"], list)
        hint = hotspot["test_hint"]
        assert isinstance(hint, dict)
        assert hint["gap"] in {"no_adjacent_test", "no_function_reference", "no_fuzz_entry", "covered"}
        if hint["gap"] == "covered":
            assert hint["test_kind"] is None
        else:
            assert hint["test_kind"] in {"unit", "property", "sanitizer", "http-contract", "fuzz-harness"}
        assert "6.0" in hotspot["rationale"]
        assert "3.0" in hotspot["rationale"]
    parser = next(item for item in payload["hotspots"] if item["path"] == "src/parser.c")
    helper = next(item for item in payload["hotspots"] if item["path"] == "src/helper.py")
    assert parser["signals"]["has_adjacent_test"] is True
    assert helper["signals"]["has_adjacent_test"] is False
    assert parser["test_hint"]["gap"] == "no_fuzz_entry"
    assert parser["test_hint"]["test_kind"] == "fuzz-harness"
    assert helper["test_hint"]["gap"] == "no_adjacent_test"
    assert helper["test_hint"]["test_kind"] == "unit"
    assert helper["inventory_finding_ids"] == [f"rule:helper:{index}" for index in range(8)]
    assert parser["inventory_finding_ids"] == []
