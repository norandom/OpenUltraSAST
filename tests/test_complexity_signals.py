from pathlib import Path

from openultrasast.complexity import ComplexitySignals, collect_signals
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


def _by_path(signals: tuple[ComplexitySignals, ...]) -> dict[str, ComplexitySignals]:
    return {signal.path: signal for signal in signals}


def test_parser_without_pattern_hit_outranks_one_line_helper_with_hit() -> None:
    parser = _target(
        "src/parser.c",
        loc=400,
        language="c",
        tags=["parser", "memory_unsafe"],
        hints=[{"kind": "parser", "access_level": "public", "function_name": "parse_header"}],
    )
    helper = _target("src/helper.py", loc=1, tags=[])
    findings = [_hit("src/helper.py")]

    signals = collect_signals([parser, helper], findings)
    by_path = _by_path(signals)

    assert by_path["src/parser.c"].inventory_hit_count == 0
    assert by_path["src/helper.py"].inventory_hit_count == 1
    assert by_path["src/parser.c"].score > by_path["src/helper.py"].score
    assert signals[0].path == "src/parser.c"


def test_function_identity_uses_entry_point_names_or_stays_empty() -> None:
    named = _target(
        "src/parser.c",
        loc=40,
        language="c",
        tags=["parser"],
        hints=[{"function_name": "parse_header", "kind": "parser", "access_level": "public"}],
    )
    named_alias = _target(
        "src/decode.c",
        loc=20,
        language="c",
        tags=["parser"],
        hints=[{"name": "decode_frame", "kind": "parser", "access_level": "public"}],
    )
    tag_only = _target(
        "src/App.java",
        loc=80,
        language="java",
        tags=["parser"],
        hints=[{"function_name": None, "name": "parser_input", "kind": "parser", "line": None}],
    )
    bare = _target("src/util.py", loc=4, tags=[])

    signals = collect_signals([named, named_alias, tag_only, bare])
    by_path = _by_path(signals)

    assert by_path["src/parser.c"].function_name == "parse_header"
    assert by_path["src/decode.c"].function_name == "decode_frame"
    assert by_path["src/App.java"].function_name is None
    assert by_path["src/util.py"].function_name is None


def test_nesting_from_source_text_otherwise_zero() -> None:
    nested = _target("src/nested.py", loc=4, tags=[])
    constructed = _target("src/flat.py", loc=12, tags=["parser"])
    source = "def outer():\n    if True:\n        while True:\n            return 1\n"

    with_text = collect_signals([nested], sources={"src/nested.py": source})
    without_text = collect_signals([constructed])

    assert with_text[0].nesting >= 3
    assert without_text[0].nesting == 0
    assert without_text[0].loc == 12


def test_nesting_reads_absolute_path_when_file_exists(tmp_path: Path) -> None:
    path = tmp_path / "braces.c"
    path.write_text("int f(void) {\n    if (1) {\n        while (1) {\n            return 0;\n        }\n    }\n}\n")
    target = _target("braces.c", loc=7, language="c", tags=[], absolute_path=str(path))

    assert collect_signals([target])[0].nesting >= 3


def test_adjacent_test_from_repo_relative_paths() -> None:
    parser = _target("src/parser.c", loc=40, language="c", tags=["parser"])
    helper = _target("pkg/helper.go", loc=8, language="go", tags=[])
    widget = _target("src/main/java/com/acme/Widget.java", loc=30, language="java", tags=[])
    lonely = _target("src/lonely.py", loc=5, tags=[])

    signals = collect_signals(
        [parser, helper, widget, lonely],
        repo_files=(
            "src/parser.c",
            "tests/test_parser.c",
            "pkg/helper.go",
            "pkg/helper_test.go",
            "src/main/java/com/acme/Widget.java",
            "src/test/java/com/acme/WidgetTest.java",
            "src/lonely.py",
            "tests/test_other.py",
        ),
    )
    by_path = _by_path(signals)

    assert by_path["src/parser.c"].has_adjacent_test is True
    assert by_path["pkg/helper.go"].has_adjacent_test is True
    assert by_path["src/main/java/com/acme/Widget.java"].has_adjacent_test is True
    assert by_path["src/lonely.py"].has_adjacent_test is False


def test_inventory_density_is_recorded_but_cannot_dominate_score() -> None:
    parser = _target(
        "src/parser.c",
        loc=250,
        language="c",
        tags=["parser"],
        hints=[{"kind": "parser", "access_level": "public", "function_name": "parse_header"}],
    )
    helper = _target("src/helper.py", loc=1, tags=[])
    findings = [_hit("src/helper.py", f"rule:helper:{index}") for index in range(12)]

    signals = collect_signals([parser, helper], findings)
    by_path = _by_path(signals)

    assert by_path["src/helper.py"].inventory_hit_count == 12
    assert by_path["src/parser.c"].inventory_hit_count == 0
    assert by_path["src/parser.c"].score > by_path["src/helper.py"].score
    assert "parser" in by_path["src/parser.c"].tags
    assert by_path["src/parser.c"].reachability > by_path["src/helper.py"].reachability
