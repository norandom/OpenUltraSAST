"""Real Git-to-engine change-context smoke; lexical attribution is not novelty proof."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from openultrasast.cpg.backend import JoernBackend
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.model.regions import ScanRegion
from openultrasast.model.scan import ScanBudget, scan_repository
from openultrasast.push.snapshot import SnapshotAdapter


def main() -> None:
    budget = ExecutionBudget(time.monotonic() + 900, 2.0)
    report: dict[str, object] = {
        "purpose": "Committed removed-guard context reaches real ranked questions; not semantic novelty or admission proof",
        "shared_budget_seconds": 900,
        "languages": {},
    }
    languages = report["languages"]
    assert isinstance(languages, dict)
    with tempfile.TemporaryDirectory(prefix="ousast-context-smoke-") as temporary:
        for language, filename, before, removed, helper_name, helper in (
            (
                "php",
                "api.php",
                b"<?php\nrequire_once 'helper.php';\nfunction handler($req) {\n  if (!authorized($req)) return;\n  helper($req);\n}\n",
                b"  if (!authorized($req)) return;\n",
                "helper.php",
                b"<?php\nfunction helper($value) { eval($value); }\n",
            ),
            (
                "javascript",
                "api.js",
                b"import { helper } from './helper.js';\nexport function handler(req) {\n"
                b"  if (!authorized(req)) return;\n  helper(req);\n}\n",
                b"  if (!authorized(req)) return;\n",
                "helper.js",
                b"export function helper(value) { eval(value); }\n",
            ),
        ):
            repo = Path(temporary) / language
            repo.mkdir()

            def git(*args: str, root: Path = repo) -> bytes:
                return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, timeout=10).stdout

            def commit(message: str, path: str = filename) -> str:
                git("add", path)
                git("commit", "-m", message)
                return git("rev-parse", "HEAD").decode().strip()

            git("init")
            git("config", "user.name", "Context smoke")
            git("config", "user.email", "context@example.invalid")
            git("config", "core.hooksPath", os.devnull)
            source = repo / filename
            source.write_bytes(before)
            (repo / helper_name).write_bytes(helper)
            git("add", helper_name)
            base = commit("base")
            after = before.replace(removed, b"")
            source.write_bytes(after)
            head = commit("removed guard")
            source.write_bytes(b"uncommitted content\n")
            index = (repo / ".git/index").read_bytes()
            status = git("status", "--porcelain=v1", "-z")
            adapter = SnapshotAdapter(repo)
            (comparison,) = adapter.resolve_updates(f"refs/heads/topic {head} refs/heads/topic {base}\n").comparisons
            context = adapter.compare(comparison, declaration_paths=(), budget=budget)
            assert any(span.side == "base" for span in context.spans), context
            with adapter.materialize(head, budget=budget) as snapshot:
                data = (snapshot.root / filename).read_bytes()
                assert data == after and data
                assert (snapshot.root / helper_name).read_bytes() == helper
                result = scan_repository(
                    snapshot.root,
                    (ScanRegion(filename, "handler", language, ("injection",), 1.0, "entry_point"),),
                    backend=JoernBackend(heap_mb=1024),
                    budget=ScanBudget(max_regions=1),
                    execution_budget=budget,
                    ranking_mode="evidence",
                    unit="context-smoke",
                    population_complete=True,
                    change_context=context,
                )
                enriched = result.change_context
                assert enriched is not None and enriched.relationships, "changed context did not reach any question"
                assert result.scope is not None and result.scope.selected
                invalid_census = {"cpg_empty", "files_unparsed", "partition_file_census_unavailable", "partition_file_census_incomplete"}
                assert not invalid_census.intersection(result.scope.unresolved_boundaries), result.scope
                assert not any(d.get("reason") in invalid_census for d in result.degradations), result.degradations
                assert result.question_outcomes and all(outcome.status == "completed" for outcome in result.question_outcomes), result
                selected = {question.identity for question in result.scope.selected}
                assert any(relation.target in selected for relation in enriched.relationships)
                assert result.findings, "controlled unchanged sink has no witness"
                assert any(Path(finding.site.split(":", 1)[0]).name == helper_name for finding in result.findings), result.findings
                languages[language] = {
                    "base_revision": base,
                    "head_revision": head,
                    "source_bytes": len(data) + len(helper),
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                    "helper_bytes": len(helper),
                    "helper_sha256": hashlib.sha256(helper).hexdigest(),
                    "input_context": context.to_payload(),
                    "result": asdict(result),
                }
            assert not snapshot.root.exists()
            assert source.read_bytes() == b"uncommitted content\n"
            assert (repo / ".git/index").read_bytes() == index
            assert git("status", "--porcelain=v1", "-z") == status
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
