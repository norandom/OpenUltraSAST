from pathlib import Path

from openultrasast.cpg.backend import CpgResult
from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ScanBudget, scan_repository


def test_polyglot_graph_inputs_and_single_scope(tmp_path: Path) -> None:
    sources = {
        "api.php": "<?php function f($x) { echo $x; }",
        "api.js": "function f(x) { return x; }",
        "vendor/bad.php": "<?php echo 1;",
        "node_modules/bad.js": "bad()",
        "tests/test.js": "test()",
        "other.rs": "fn main() {}",
    }
    for name, content in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    seen = []

    class Backend:
        def build(self, root, *, language="", **kwargs):
            files = tuple(sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()))
            assert all(p.read_bytes() for p in root.rglob("*") if p.is_file())
            seen.append((language, files))
            return CpgResult(Path("cpg.bin"), lambda q, p: [], run_batch=lambda q, requests: {rid: [] for rid in requests})

    regions = [
        ScanRegion(path=p, function="f", language=language, families=("injection",), rank=r, source="entry_point")
        for p, language, r in [
            ("api.php", "php", 1.0),
            ("api.js", "javascript", 0.9),
            ("vendor/bad.php", "php", 2.0),
            ("tests/test.js", "javascript", 3.0),
        ]
    ]
    result = scan_repository(
        tmp_path, regions, backend=Backend(), budget=ScanBudget(max_regions=1, tiering=False), population_complete=True
    )
    assert seen == [("javascript", ("api.js", "tests/test.js")), ("php", ("api.php",))]
    assert result.scope.selected[0].identity.path == "api.php"
    assert all(q.identity.path != "vendor/bad.php" for q in (*result.scope.selected, *result.scope.deferred))
    assert any(p.language == "rust" and p.status == "unsupported" for p in result.partitions)
    assert "cross_partition_semantics_unresolved" in result.scope.unresolved_boundaries


def test_file_patterns_symlinks_and_witness_paths(tmp_path, monkeypatch):
    import dataclasses

    from openultrasast.model import layout, partitions
    from openultrasast.preprocess import preprocess_repository
    from openultrasast.semantic.facts import LayoutFact

    facts = (LayoutFact(id="declared", language="javascript", vendored=("*.bundle.js", "bundled/lib/"), tests=("tests/",)),)
    monkeypatch.setattr(layout, "layout_facts", lambda *args: facts)
    monkeypatch.setattr(partitions, "layout_facts", lambda *args: facts)
    outside = tmp_path.parent / "external.js"
    outside.write_text("external_secret()")
    (tmp_path / "escape.js").symlink_to(outside)
    (tmp_path / "bad.bundle.js").write_text("vendor_secret()")
    (tmp_path / "app.js").write_text("function f(x) { return x; }")
    (tmp_path / "bundled/lib").mkdir(parents=True)
    (tmp_path / "bundled/lib/hidden.js").write_text("vendor_secret()")
    _, targets = preprocess_repository(tmp_path)
    assert [t.path for t in targets] == ["app.js"]
    roots = []

    def build(root, language):
        roots.append(root)
        assert [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()] == ["app.js"]
        return CpgResult(
            Path("graph"),
            lambda q, p: [],
            run_batch=lambda q, reqs: {rid: [{"file": str(root / "app.js"), "site": str(root / "app.js") + ":1"}] for rid in reqs},
        )

    graph = partitions.build_partitions(tmp_path, build, None)
    try:
        assert graph.partitions[0].source_bytes == len((tmp_path / "app.js").read_bytes())
        assert graph.run("taint", {"file": "app.js"}) == [{"file": "app.js", "site": "app.js:1"}]
        assert {"vendor_semantics_unresolved", "symlink_context_unresolved"} <= set(graph.boundaries)
        assert dataclasses.asdict(graph.partitions[0])["runtime"] == "unspecified"
    finally:
        graph.cleanup()
    assert all(not root.exists() for root in roots)


def test_shared_deadline_stops_later_frontend_and_no_false_clean(tmp_path):
    import time

    from openultrasast.model.contracts import ExecutionBudget
    from openultrasast.model.partitions import build_partitions

    for name in ("a.js", "b.php"):
        (tmp_path / name).write_text("readable")
    seen = []
    budget = ExecutionBudget(time.monotonic() + 0.1, 0.1)

    def build(root, language):
        seen.append(language)
        time.sleep(0.12)
        return CpgResult(Path("graph"), lambda q, p: [])

    graph = build_partitions(tmp_path, build, budget)
    try:
        assert seen == ["javascript"]
        assert [p.status for p in graph.partitions] == ["built", "build_failed"]
        assert graph.run("taint", {"file": "b.php"}) is None
    finally:
        graph.cleanup()


def test_evidence_ranker_selects_once_across_languages(tmp_path):
    from test_model_scope import vector

    for name in ("a.php", "b.js"):
        (tmp_path / name).write_text("readable source")
    executed = []

    class Backend:
        def build(self, root, *, language="", **kwargs):
            def batch(kind, requests):
                if any(p.get("evidenceOnly") for p in requests.values()):
                    return {rid: vector(language == "javascript") for rid in requests}
                executed.extend(p["file"] for p in requests.values())
                return {rid: [] for rid in requests}

            return CpgResult(Path("graph"), lambda q, p: [], run_batch=batch)

    regions = [
        ScanRegion(path=path, function="f", language=language, families=("injection",), rank=rank, source="entry_point")
        for path, language, rank in [("a.php", "php", 1.0), ("b.js", "javascript", 0.5)]
    ]
    result = scan_repository(tmp_path, regions, backend=Backend(), ranking_mode="evidence", budget=ScanBudget(max_regions=1))
    assert len(result.scope.selected) == 1
    assert result.scope.selected[0].identity.path == "b.js"
    assert executed == ["b.js"]
    assert result.question_outcomes[0].status == "unresolved"


def test_unsupported_only_population_is_named(tmp_path):
    (tmp_path / "main.go").write_text("package main")

    class Backend:
        def build(self, *args, **kwargs):
            raise AssertionError("unsupported frontend must not build")

    result = scan_repository(tmp_path, [], backend=Backend(), population_complete=True)
    assert result.partitions[0].language == "go"
    assert result.partitions[0].status == "unsupported"
    assert "frontend_unsupported" in result.scope.unresolved_boundaries


def test_partial_partition_census_never_completes_questions(tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("print('readable')")

    class Backend:
        def build(self, root, **kwargs):
            return CpgResult(
                Path("graph"),
                lambda q, p: [],
                run_batch=lambda q, reqs: {**{rid: [] for rid in reqs}, "__census__": [{"methods": 2, "files": 1}]},
            )

    region = ScanRegion(path="a.py", function="f", language="python", families=("injection",), rank=1.0, source="entry_point")
    result = scan_repository(tmp_path, [region], backend=Backend(), budget=ScanBudget(tiering=False))
    assert result.question_outcomes[0].status == "unresolved"
    assert "cpg_empty" in result.scope.unresolved_boundaries


def test_projection_refuses_substituted_ancestor(tmp_path):
    import os

    import pytest

    from openultrasast.model.partitions import _open_source

    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.js").write_bytes(b"must not enter the graph")
    (source / "nested").symlink_to(outside, target_is_directory=True)
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError):
            _open_source(descriptor, ("nested", "secret.js"))
    finally:
        os.close(descriptor)


def test_partition_records_reach_cli(tmp_path):
    from openultrasast.cli import _model_payload

    (tmp_path / "main.go").write_bytes(b"package main")
    result = scan_repository(tmp_path, [], backend=object())
    payload = _model_payload(result)
    assert payload["partitions"][0]["language"] == "go"
    assert payload["partitions"][0]["status"] == "unsupported"


def test_stale_region_cannot_bypass_vendor_graph_exclusion(tmp_path):
    (tmp_path / "api.php").write_bytes(b"<?php echo 1;")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor/bad.php").write_bytes(b"<?php vendor_secret();")
    seen = []

    class Backend:
        def build(self, root, **kwargs):
            seen.extend(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
            return CpgResult(Path("graph"), lambda q, p: [])

    region = ScanRegion(path="missing.php", function="f", language="php", families=("injection",), rank=1.0, source="entry_point")
    result = scan_repository(tmp_path, [region], backend=Backend())
    assert seen == ["api.php"]
    assert result.question_outcomes[0].status == "unanswered"


def test_unreadable_unknown_extension_reports_incomplete_without_crashing(tmp_path, monkeypatch):
    from openultrasast.model import partitions

    (tmp_path / "app.js").write_bytes(b"function handler(value) { return value; }\n")
    (tmp_path / "README.md").write_bytes(b"unreadable declaration candidate\n")
    original_open = partitions.os.open

    def unreadable_open(path, flags, *args, **kwargs):
        if str(path) == "README.md":
            raise PermissionError("controlled unreadable discovery input")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(partitions.os, "open", unreadable_open)

    class Backend:
        def build(self, root, **kwargs):
            assert (root / "app.js").read_bytes()
            return CpgResult(Path("graph"), lambda query, params: [])

    region = ScanRegion("app.js", "handler", "javascript", ("injection",), 1.0, "entry_point")
    result = scan_repository(tmp_path, [region], backend=Backend(), budget=ScanBudget(tiering=False))
    assert result.partitions[0].status == "built"
    assert "source_unreadable" in result.scope.unresolved_boundaries
    assert result.question_outcomes[0].status == "unresolved"


def test_declared_javascript_tests_remain_inputs_but_unshipped(tmp_path):
    from openultrasast.model.layout import with_layout
    from openultrasast.model.partitions import build_partitions

    names = ("unit.test.js", "unit.spec.mjs", "unit.mock.cjs", "unit.e2e.jsx", "unit.test.ts", "unit.spec.tsx", "__tests__/unit.js")
    for name in (*names, "app.js"):
        source = tmp_path / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("function readable() {}")
    graph = build_partitions(tmp_path, lambda root, language: CpgResult(Path("graph"), lambda q, p: []), None)
    try:
        assert set(names) <= {p for record in graph.partitions for p in record.paths}
        assert set(names) == {p for record in graph.partitions for p in record.unshipped_paths}
        regions = [
            ScanRegion(path=p, function="readable", language="javascript", families=("injection",), rank=1.0, source="entry_point")
            for p in (*names, "app.js")
        ]
        assert {r.path for r in with_layout(regions) if not r.shipped} == set(names)
    finally:
        graph.cleanup()


def test_synthetic_census_node_cannot_mask_missing_source(tmp_path):
    from openultrasast.model.partitions import build_partitions

    for name in ("a.php", "b.php"):
        (tmp_path / name).write_text("<?php echo 1;")

    def build(root, language):
        return CpgResult(
            Path("graph"),
            lambda q, p: [],
            run_batch=lambda q, reqs: {
                **{rid: [] for rid in reqs},
                "__census__": [{"methods": 3, "files": 2, "file_names": ["<unknown>", str(root / "a.php")]}],
            },
        )

    graph = build_partitions(tmp_path, build, None)
    try:
        result = graph.run_batch("taint", {"q": {"file": "a.php"}})
        assert result["__census__"][0]["files"] == 0
        assert "partition_file_census_incomplete" in graph.execution_diagnostics()
    finally:
        graph.cleanup()


def test_named_census_accepts_exact_paths_for_every_query_kind(tmp_path):
    from openultrasast.model.partitions import build_partitions

    (tmp_path / "app.php").write_text("<?php echo 1;")

    def build(root, language):
        return CpgResult(
            Path("graph"),
            lambda q, p: [],
            run_batch=lambda q, reqs: {
                **{rid: [] for rid in reqs},
                "__census__": [{"methods": 2, "files": 2, "file_names": ["<unknown>", str(root / "app.php")]}],
            },
        )

    graph = build_partitions(tmp_path, build, None)
    try:
        for kind in ("taint", "dominance", "config"):
            assert graph.run_batch(kind, {"q": {"file": "app.php"}})["__census__"][0]["files"] == 2
        assert not graph.execution_diagnostics()
    finally:
        graph.cleanup()


def test_unnamed_sharded_census_remains_explicitly_incomplete(tmp_path):
    from openultrasast.model.partitions import build_partitions

    (tmp_path / "app.php").write_text("<?php echo 1;")
    graph = build_partitions(
        tmp_path,
        lambda root, language: CpgResult(
            Path("graph"),
            lambda q, p: [],
            run_batch=lambda q, reqs: {**{rid: [] for rid in reqs}, "__census__": [{"methods": 20, "files": 20, "shards": 2}]},
        ),
        None,
    )
    try:
        result = graph.run_batch("taint", {"q": {"file": "app.php"}})
        assert result["__census__"] == [{"methods": 0, "files": 0, "shards": 2}]
        assert "partition_file_census_unavailable" in graph.execution_diagnostics()
    finally:
        graph.cleanup()
