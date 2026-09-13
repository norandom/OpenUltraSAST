"""Production-query regression: a known argument does not summarize an unknown callee."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.contracts import ChangeContext, ChangedSpan, ExecutionBudget
from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ScanBudget, scan_repository


def main() -> None:
    content = (
        b"function unknownSource(req) { unknown(req.body); }\n"
        b"function unknownSink(req) { unknown(eval(req.body)); }\n"
        b'function unknownSanitizer(req) { unknown("escape"); }\n'
        b"function knownSink(req) { eval(req.body); }\n"
        b"function knownSanitizer(req) { escape(req.body); }\n"
    )
    with tempfile.TemporaryDirectory(prefix="ousast-context-boundary-") as temporary:
        root = Path(temporary)
        source = root / "api.js"
        source.write_bytes(content)
        assert source.read_bytes() == content
        names = ("unknownSource", "unknownSink", "unknownSanitizer", "knownSink", "knownSanitizer")
        result = scan_repository(
            root,
            tuple(ScanRegion("api.js", name, "javascript", ("injection",), 1.0, "entry_point") for name in names),
            backend=JoernBackend(heap_mb=1024),
            budget=ScanBudget(max_regions=5),
            execution_budget=ExecutionBudget(time.monotonic() + 600, 2.0),
            ranking_mode="evidence",
            unit="context-boundaries",
            population_complete=True,
            change_context=ChangeContext("base", "head", ("api.js",), (), (ChangedSpan("api.js", 1, 5, "head"),), (), (), (), ()),
        )
        assert result.scope is not None
        outcomes = {item.identity.function: item for item in result.question_outcomes}
        for name in names[:3]:
            assert name in outcomes, (name, "unknown call was excluded", result.scope)
            assert outcomes[name].status == "unresolved", (name, outcomes[name])
            question_id = outcomes[name].identity.question_id
            assert any(
                "dynamic_external_or_depth_context_unresolved" in gap and question_id in gap for gap in result.scope.unresolved_boundaries
            )
        assert outcomes["knownSink"].status == "completed", outcomes["knownSink"]
        known_sanitizer = next(item for item in result.scope.deferred if item.identity.function == "knownSanitizer")
        assert known_sanitizer.reason == "tier_zero", known_sanitizer
        assert not any(known_sanitizer.identity.question_id in gap for gap in result.scope.unresolved_boundaries)
        print(
            json.dumps(
                {"source_bytes": len(content), "source_sha256": hashlib.sha256(content).hexdigest(), "result": asdict(result)}, indent=2
            )
        )


if __name__ == "__main__":
    main()
