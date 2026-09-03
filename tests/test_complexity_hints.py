import json
from pathlib import Path

from openultrasast.complexity.hints import GAP_COVERED, KIND_FUZZ_HARNESS
from openultrasast.complexity.map import build_complexity_map
from openultrasast.findings import StaticFinding
from openultrasast.preprocess import FileTarget


def _target(
    path: str,
    *,
    loc: int,
    tags: list[str] | None = None,
    language: str = "python",
    hints: list[dict[str, object]] | None = None,
    has_fuzz_entry_point: bool = False,
    absolute_path: str | None = None,
) -> FileTarget:
    return FileTarget(
        path=path,
        absolute_path=absolute_path or f"/repo/{path}",
        language=language,
        loc=loc,
        tags=list(tags or []),
        has_fuzz_entry_point=has_fuzz_entry_point,
        reachability_hints=list(hints or []),
    )


def _hit(path: str, finding_id: str = "rule:helper:1") -> StaticFinding:
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


def _tree_snapshot(root: Path) -> dict[str, tuple[int, bytes]]:
    snapshot: dict[str, tuple[int, bytes]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            snapshot[path.relative_to(root).as_posix()] = (path.stat().st_mtime_ns, path.read_bytes())
    return snapshot


def test_covered_hotspot_emits_covered_and_no_test_kind(tmp_path: Path) -> None:
    widget = _target(
        "src/widget.py",
        loc=12,
        hints=[{"kind": "route", "access_level": "public", "function_name": "render"}],
    )
    artifact = tmp_path / "complexity_map.json"

    complexity_map = build_complexity_map(
        [widget],
        [_hit("src/widget.py")],
        artifact,
        repo_files=("src/widget.py", "tests/test_widget.py"),
        sources={
            "src/widget.py": "def render():\n    return 1\n",
            "tests/test_widget.py": "from widget import render\n\ndef test_render():\n    assert render() == 1\n",
        },
    )

    hotspot = complexity_map.hotspots[0]
    assert hotspot.test_hint is not None
    assert hotspot.test_hint.gap == GAP_COVERED
    assert hotspot.test_hint.gap == "covered"
    assert hotspot.test_hint.test_kind is None
    assert hotspot.test_hint.path == "src/widget.py"
    assert hotspot.test_hint.function_name == "render"
    payload = json.loads(artifact.read_text())
    hint = payload["hotspots"][0]["test_hint"]
    assert hint["gap"] == "covered"
    assert hint["test_kind"] is None


def test_fuzzable_c_parser_without_harness_emits_fuzz_harness(tmp_path: Path) -> None:
    parser = _target(
        "src/parser.c",
        loc=400,
        language="c",
        tags=["parser", "memory_unsafe"],
        hints=[{"kind": "parser", "access_level": "public", "function_name": "parse_header"}],
        has_fuzz_entry_point=False,
    )
    artifact = tmp_path / "complexity_map.json"

    complexity_map = build_complexity_map(
        [parser],
        [],
        artifact,
        repo_files=("src/parser.c", "tests/test_parser.c"),
        sources={
            "src/parser.c": "int parse_header(const char *buf) { return 0; }\n",
            "tests/test_parser.c": 'int test_parse_header(void) { return parse_header(""); }\n',
        },
    )

    hotspot = complexity_map.hotspots[0]
    assert hotspot.test_hint is not None
    assert hotspot.test_hint.gap == "no_fuzz_entry"
    assert hotspot.test_hint.test_kind == KIND_FUZZ_HARNESS
    assert hotspot.test_hint.test_kind == "fuzz-harness"
    assert hotspot.test_hint.path == "src/parser.c"
    assert hotspot.test_hint.function_name == "parse_header"
    assert hotspot.test_hint.reason
    payload = json.loads(artifact.read_text())
    hint = payload["hotspots"][0]["test_hint"]
    assert hint["gap"] == "no_fuzz_entry"
    assert hint["test_kind"] == "fuzz-harness"


def test_attach_test_hints_leaves_scanned_tree_unchanged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    src = repo / "src"
    tests_dir = repo / "tests"
    src.mkdir(parents=True)
    tests_dir.mkdir()
    parser = src / "parser.c"
    helper = src / "helper.py"
    parser_test = tests_dir / "test_parser.c"
    parser.write_text("int parse_header(const char *buf) {\n    return buf[0];\n}\n")
    helper.write_text("def ping():\n    return 1\n")
    parser_test.write_text("int test_parse_header(void) { return 0; }\n")
    before = _tree_snapshot(repo)

    artifact = tmp_path / "out" / "complexity_map.json"
    targets = [
        _target(
            "src/parser.c",
            loc=3,
            language="c",
            tags=["parser", "memory_unsafe"],
            hints=[{"kind": "parser", "access_level": "public", "function_name": "parse_header"}],
            absolute_path=str(parser),
        ),
        _target("src/helper.py", loc=2, tags=[], absolute_path=str(helper)),
    ]

    complexity_map = build_complexity_map(
        targets,
        [_hit("src/helper.py")],
        artifact,
        repo_files=("src/parser.c", "src/helper.py", "tests/test_parser.c"),
        sources={
            "src/parser.c": parser.read_text(),
            "src/helper.py": helper.read_text(),
            "tests/test_parser.c": parser_test.read_text(),
        },
    )

    assert complexity_map.hotspots
    assert all(hotspot.test_hint is not None for hotspot in complexity_map.hotspots)
    assert _tree_snapshot(repo) == before
    assert set(_tree_snapshot(repo)) == {"src/parser.c", "src/helper.py", "tests/test_parser.c"}
    assert not any(path.as_posix().endswith(".py") and "test" in path.name for path in src.rglob("*"))
    assert artifact.is_file()
    assert artifact.is_relative_to(tmp_path / "out")


def test_no_adjacent_test_recommends_closed_test_kind(tmp_path: Path) -> None:
    helper = _target("src/helper.py", loc=4, tags=[])
    route = _target(
        "src/api.py",
        loc=40,
        tags=["network_entry"],
        hints=[{"kind": "route", "access_level": "public", "function_name": "handle"}],
    )
    artifact = tmp_path / "complexity_map.json"

    complexity_map = build_complexity_map(
        [helper, route],
        [],
        artifact,
        repo_files=("src/helper.py", "src/api.py"),
        sources={
            "src/helper.py": "def ping():\n    return 1\n",
            "src/api.py": "def handle():\n    return {}\n",
        },
    )
    by_path = {hotspot.path: hotspot for hotspot in complexity_map.hotspots}

    assert by_path["src/helper.py"].test_hint is not None
    assert by_path["src/helper.py"].test_hint.gap == "no_adjacent_test"
    assert by_path["src/helper.py"].test_hint.test_kind == "unit"
    assert by_path["src/api.py"].test_hint is not None
    assert by_path["src/api.py"].test_hint.gap == "no_adjacent_test"
    assert by_path["src/api.py"].test_hint.test_kind == "http-contract"


def test_no_function_reference_when_adjacent_test_omits_function(tmp_path: Path) -> None:
    widget = _target(
        "src/widget.py",
        loc=12,
        hints=[{"kind": "route", "access_level": "public", "function_name": "render"}],
    )
    artifact = tmp_path / "complexity_map.json"

    complexity_map = build_complexity_map(
        [widget],
        [],
        artifact,
        repo_files=("src/widget.py", "tests/test_widget.py"),
        sources={
            "src/widget.py": "def render():\n    return 1\n",
            "tests/test_widget.py": "def test_placeholder():\n    assert True\n",
        },
    )

    hint = complexity_map.hotspots[0].test_hint
    assert hint is not None
    assert hint.gap == "no_function_reference"
    assert hint.test_kind == "unit"
    assert hint.function_name == "render"
