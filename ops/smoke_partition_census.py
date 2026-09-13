"""Compile all production batch censuses on a readable real Python graph."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.contracts import ExecutionBudget


def main() -> None:
    budget = ExecutionBudget(time.monotonic() + 600, 2.0)
    results = {}
    with tempfile.TemporaryDirectory(prefix="ousast-census-smoke-") as temporary:
        root = Path(temporary)
        source = root / "probe.py"
        source.write_text("def handler(value):\n    return value\n")
        data = source.read_bytes()
        assert data, "source input unreadable"
        backend = JoernBackend(heap_mb=1024, execution_budget=budget)
        graph = backend.build(root, language="python")
        assert graph is not None and graph.run_batch is not None, "real Python graph unavailable"
        try:
            for kind in ("taint", "dominance", "config"):
                answer = graph.run_batch(kind, {"probe": {"file": "probe.py", "function": "handler"}})
                assert isinstance(answer, dict) and "probe" in answer, f"{kind} batch unanswered"
                census = answer.get("__census__")
                assert isinstance(census, list) and census, f"{kind} census missing"
                names = census[0].get("file_names")
                assert isinstance(names, list) and any(str(p).endswith("probe.py") for p in names), census
                assert int(census[0]["methods"]) > 0, census
                results[kind] = census
        finally:
            graph.cleanup()
    print(
        json.dumps(
            {
                "purpose": "Real Python batch schema and query compilation; no security property admission claim",
                "source_bytes": len(data),
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "shared_budget_seconds": 600,
                "censuses": results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
