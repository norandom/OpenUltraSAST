"""Exercise the installed engine, not a mock. Run inside the shipped image as its non-root user."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from openultrasast.cpg.backend import DATAFLOW_OVERLAY, JoernBackend, joern_version
from openultrasast.model.contracts import ExecutionBudget


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    require(os.getuid() != 0, "run as the image's non-root user so unreadable-file checks are meaningful")
    budget_seconds = float(os.environ.get("OUSAST_ENGINE_SMOKE_BUDGET_SECONDS", "0"))
    execution_budget = ExecutionBudget(time.monotonic() + budget_seconds, 2.0) if budget_seconds > 0 else None
    version = joern_version()
    require(version, "installed Joern version is unknown")
    php = Path(shutil.which("php") or "/missing-php").resolve()
    require(php.read_bytes()[:4] == b"\x7fELF", "PHP must be a native executable, not a stdio wrapper")
    parser = Path(shutil.which("php2cpg") or "/missing-php2cpg").resolve().parent
    parser /= "frontends/php2cpg/bin/php-parser/php-parser.php"
    probe = "$s = file_get_contents($argv[1]); if ($s === false || strlen($s) === 0) exit(3); echo strlen($s);"

    def php_bytes(path: Path) -> int:
        result = subprocess.run([str(php), "-r", probe, str(path)], check=True, capture_output=True, text=True, timeout=15)
        return int(result.stdout)

    report: dict[str, object] = {
        "joern_version": ".".join(map(str, version)),
        "php_version": subprocess.run([str(php), "-v"], check=True, capture_output=True, text=True, timeout=15).stdout.splitlines()[0],
        "php_parser_bytes": php_bytes(parser),
        "purpose": "runtime and query smoke; does not qualify vulnerability detection or hook latency",
        "shared_budget_seconds": budget_seconds or None,
        "languages": {},
    }
    languages = report["languages"]
    assert isinstance(languages, dict)
    with tempfile.TemporaryDirectory(prefix="ousast-engine-smoke-") as temporary:
        root = Path(temporary)
        queries = root / "queries"
        queries.mkdir()
        (queries / "source_witness.sc").write_text("""@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("---OUSAST-CPG-BEGIN---")
  println(ujson.write(ujson.Obj(
    "files" -> ujson.Arr.from(cpg.file.name.l),
    "handlers" -> cpg.method.nameExact("handler").size,
    "evalCalls" -> cpg.call.nameExact("eval").size
  )))
  println("---OUSAST-CPG-END---")
}
""")
        for language, frontend, filename, content in (
            ("php", "php2cpg", "probe.php", "<?php\nfunction handler($req) { eval($req); }\n"),
            ("javascript", "jssrc2cpg", "probe.js", "function handler(req) { eval(req.query.code); }\n"),
        ):
            require(shutil.which(frontend), f"missing installed {frontend}")
            source_root = root / language
            source_root.mkdir()
            source = source_root / filename
            source.write_text(content)
            data = source.read_bytes()
            require(data, f"unreadable/empty {source}")
            if language == "php":
                require(php_bytes(source) == len(data), "PHP and host source byte counts differ")
            print(f"{language}: opened {filename}, {len(data)} bytes; building graph", file=sys.stderr, flush=True)
            backend = JoernBackend(build_timeout=180, query_timeout=180, heap_mb=1024, execution_budget=execution_budget)
            started = time.monotonic()
            graph = backend.build(source_root, language=language)
            require(graph, f"{language} graph build failed: {backend.last_failure}")
            assert graph is not None
            try:
                require(not graph.unparsed, f"{language} unparsed input: {graph.unparsed}")
                census = backend.query(graph.cpg_path, "census", {})
                require(isinstance(census, dict), f"{language} census returned no valid payload")
                assert isinstance(census, dict)
                require(int(census["files"]) > 0 and int(census["methods"]) > 0, f"empty {language} census")
                require(DATAFLOW_OVERLAY in str(census["overlays"]).split(","), f"{language} missing dataflow overlay: {census}")
                witness = JoernBackend(queries_dir=queries, query_timeout=180, heap_mb=1024, execution_budget=execution_budget).query(
                    graph.cpg_path, "source_witness", {}
                )
                require(isinstance(witness, dict), f"{language} source witness unanswered")
                assert isinstance(witness, dict)
                require(any(str(path).endswith(filename) for path in witness["files"]), f"{language} source absent from graph")
                require(witness["handlers"] > 0 and witness["evalCalls"] > 0, f"{language} expected source nodes missing: {witness}")
                languages[language] = {
                    "frontend": frontend,
                    "source_bytes": len(data),
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                    "graph_bytes": graph.cpg_path.stat().st_size,
                    "census": census,
                    "source_witness": witness,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                }
                print(f"{language}: census and source witness verified", file=sys.stderr, flush=True)
            finally:
                if graph.cleanup:
                    graph.cleanup()
            if language == "php":
                source.chmod(0)
                try:
                    refused = backend.build(source_root, language=language)
                    require(refused is None and "cannot read" in backend.last_failure, "unreadable source did not fail explicitly")
                    report["unreadable_source"] = {"status": "explicit_failure", "reason": backend.last_failure}
                finally:
                    source.chmod(0o600)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
