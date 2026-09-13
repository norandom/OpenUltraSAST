"""Real mixed-language graph input and global ranker smoke; no hook quality claim."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ScanBudget, scan_repository


def main() -> None:
    include_tests = os.environ.get("OUSAST_SMOKE_INCLUDE_TESTS", "1") == "1"
    deadline = ExecutionBudget(time.monotonic() + 900, 2.0)
    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="ousast-partitions-smoke-") as temporary:
        base = Path(temporary)
        root = base / "source"
        queries = base / "queries"
        queries.mkdir()
        (queries / "partition_witness.sc").write_text("""@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Obj(
    "files" -> ujson.Arr.from(cpg.file.name.l),
    "methods" -> ujson.Arr.from(cpg.method.name.l)
  )))
  println("---OUSAST-CPG-END---")
}
""")
        sources = {
            "src/api.php": "<?php\nfunction php_handler($req) { eval($req); }\n",
            "server/api.js": "function js_handler(req) { eval(req.query.code); }\n",
            "tests/probe.php": "<?php\nfunction php_test_marker() { return 42; }\n",
            "tests/probe.js": "function js_test_marker() { return 42; }\n",
            "vendor/library.php": "<?php\nfunction vendor_php_marker($req) { eval($req); }\n",
            "node_modules/library.js": "function vendor_js_marker(req) { eval(req); }\n",
            "unsupported.go": "package example\nfunc Unmodeled() {}\n",
        }
        suffix_tests = {f"checks/probe.{suffix}.js": f"js_{suffix}_marker" for suffix in ("test", "spec", "mock", "e2e")}
        sources.update({path: f"function {method}() {{ return 42; }}\n" for path, method in suffix_tests.items()})
        inputs = {}
        for filename, content in sources.items():
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            data = path.read_bytes()
            assert data and data == content.encode(), f"unread input: {filename}"
            inputs[filename] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

        class RecordingBackend(JoernBackend):
            def build(self, root: Path, *, language: str = "", **kwargs):
                projected = {}
                for source in root.rglob("*"):
                    if source.is_file():
                        data = source.read_bytes()
                        filename = source.relative_to(root).as_posix()
                        projected[filename] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        assert projected[filename] == inputs[filename], f"projected input differs: {filename}"
                print(json.dumps({"frontend": language, "projected_inputs": projected}), file=sys.stderr, flush=True)
                graph = super().build(root, language=language, **kwargs)
                assert graph is not None, f"real {language} graph failed: {self.last_failure}"
                witness = JoernBackend(queries_dir=queries, heap_mb=1024, execution_budget=deadline).query(
                    graph.cpg_path, "partition_witness", {}
                )
                assert isinstance(witness, dict), f"{language} census unanswered"
                print(json.dumps({"frontend": language, "graph_witness": witness}), file=sys.stderr, flush=True)
                files = witness["files"]
                methods = witness["methods"]
                assert files and methods, f"{language} graph empty"
                assert not any("vendor" in str(path) or "node_modules" in str(path) for path in files), witness
                assert not any("vendor_" in str(method) for method in methods), witness
                if language == "php":
                    assert any(str(path).endswith("src/api.php") for path in files), witness
                    assert any(str(path).endswith("tests/probe.php") for path in files), witness
                    assert "php_handler" in methods and "php_test_marker" in methods, witness
                    assert "js_handler" not in methods, witness
                elif language == "javascript":
                    assert any(str(path).endswith("server/api.js") for path in files), witness
                    assert any(str(path).endswith("tests/probe.js") for path in files), witness
                    assert "js_handler" in methods and "js_test_marker" in methods, witness
                    for path, method in suffix_tests.items():
                        assert any(str(filename).endswith(path) for filename in files), witness
                        assert method in methods, witness
                    assert "php_handler" not in methods, witness
                else:
                    raise AssertionError(f"unexpected frontend: {language}")
                records.append({"frontend": language, "input_root": str(root), "graph_witness": witness})
                return graph

        regions = (
            ScanRegion("src/api.php", "php_handler", "php", ("injection",), 10.0, "entry_point"),
            ScanRegion("server/api.js", "js_handler", "javascript", ("injection",), 9.0, "entry_point"),
            ScanRegion("tests/probe.php", "php_test_marker", "php", ("injection",), 2.0, "entry_point"),
            ScanRegion("tests/probe.js", "js_test_marker", "javascript", ("injection",), 1.0, "entry_point"),
            ScanRegion("vendor/library.php", "vendor_php_marker", "php", ("injection",), 100.0, "entry_point"),
            ScanRegion("node_modules/library.js", "vendor_js_marker", "javascript", ("injection",), 100.0, "entry_point"),
        )
        result = scan_repository(
            root,
            regions,
            backend=RecordingBackend(heap_mb=1024, include_tests=include_tests),
            budget=ScanBudget(max_regions=1),
            execution_budget=deadline,
            ranking_mode="static",
            unit="partition-smoke",
            population_complete=True,
        )
        assert {record["frontend"] for record in records} == {"php", "javascript"}, records
        assert result.scope is not None
        assert [q.identity.function for q in result.scope.selected] == ["php_handler"], result.scope
        assert {q.identity.function for q in result.scope.deferred} == {"js_handler", "php_test_marker", "js_test_marker"}, result.scope
        assert len(result.question_outcomes) == 1, result.question_outcomes
        assert result.question_outcomes[0].identity == result.scope.selected[0].identity
        assert all("vendor" not in q.identity.path and "node_modules" not in q.identity.path for q in result.scope.selected), result.scope
        assert any(p.language == "go" and p.status == "unsupported" for p in result.partitions), result.partitions
        assert all(not Path(record["input_root"]).exists() for record in records), "partition scratch leaked"
        report = {
            "purpose": "Real mixed PHP/JavaScript graph census and one global ranker budget; no admission or latency claim",
            "shared_budget_seconds": 900,
            "include_tests": include_tests,
            "inputs": inputs,
            "graph_witnesses": records,
            "result": asdict(result),
        }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
