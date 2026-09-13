"""Real engine scope smoke with declared entry regions; not a hook quality benchmark."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ScanBudget, scan_repository


def main() -> None:
    budget = ExecutionBudget(time.monotonic() + 900, 2.0)
    report: dict[str, object] = {
        "purpose": "Real PHP/JavaScript scope smoke; declared entry regions, no admission or latency claim",
        "shared_budget_seconds": 900,
        "languages": {},
    }
    languages = report["languages"]
    assert isinstance(languages, dict)
    with tempfile.TemporaryDirectory(prefix="ousast-scope-smoke-") as temporary:
        for language, filename, content in (
            ("php", "api.php", "<?php\nfunction safe($req) { return 42; }\nfunction risky($req) { eval($req); }\n"),
            ("javascript", "api.js", "function safe(req) { return 42; }\nfunction risky(req) { eval(req); }\n"),
        ):
            root = Path(temporary) / language
            root.mkdir()
            source = root / filename
            source.write_text(content)
            data = source.read_bytes()
            assert data and data == content.encode(), "source input was not read"
            regions = tuple(
                ScanRegion(filename, function, language, ("injection",), rank, "entry_point")
                for function, rank in (("safe", 2.0), ("risky", 1.0))
            )
            result = scan_repository(
                root,
                regions,
                backend=JoernBackend(heap_mb=1024),
                budget=ScanBudget(max_regions=1),
                execution_budget=budget,
                ranking_mode="evidence",
                unit="scope-smoke",
                population_complete=True,
            )
            scope = result.scope
            assert scope is not None, "no scope decision"
            assert [item.identity.function for item in scope.selected] == ["risky"], scope
            assert [item.identity.function for item in scope.deferred] == ["safe"], scope
            selected_ids = [item.identity.question_id for item in scope.selected]
            assert [item.identity.question_id for item in result.question_outcomes] == selected_ids
            assert all(item.status == "completed" and item.raw_rows_json is not None for item in result.question_outcomes), result
            assert len(result.family_coverage) == 1
            coverage = result.family_coverage[0]
            assert (coverage.selected, coverage.completed, coverage.unanswered, coverage.deferred) == (1, 1, 0, 1), coverage
            languages[language] = {
                "source_bytes": len(data),
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "selected_question_ids": selected_ids,
                "result": asdict(result),
            }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
