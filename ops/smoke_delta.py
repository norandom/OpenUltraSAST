"""Real Git/Joern novelty controls; no hook admission or latency claim."""

from __future__ import annotations

import argparse
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
from openultrasast.push.policy import compare_targeted_base, semantics_digest
from openultrasast.push.snapshot import SnapshotAdapter


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("guard", "movement", "connection"), required=True)
    args = parser.parse_args()
    before = (
        b"export function handler(req) {\n"
        b"  if (!authenticate(req)) return;\n"
        b"  deleteUser(req.params.id);\n} // handler\n"
        b"export function sibling(other) {\n"
        b"  if (!authenticate(other)) return;\n"
        b"  deleteUser(other.params.id);\n} // sibling\n"
    )
    after = before.replace(b"  if (!authenticate(req)) return;\n", b"", 1)
    language, family, filename = "javascript", "access_control", "api.js"
    expected = "worsened"
    if args.case == "movement":
        before = after
        after = b"// documentation moved this existing operation\n\n" + before
        expected = "unchanged"
    elif args.case == "connection":
        language, family, filename = "php", "injection", "api.php"
        before = b'<?php\nfunction handler($req) {\n  $value = "fixed";\n  eval($value);\n}\n'
        after = before.replace(b'$value = "fixed";', b"$value = $req;")
        expected = "new"
    started = time.monotonic()
    budget = ExecutionBudget(started + 900, 2.0)
    report: dict[str, object] = {
        "case": args.case,
        "purpose": (
            "Real targeted comparison with declared regions and Git context; no automatic context projection, full replay or admission"
        ),
        "shared_budget_seconds": 900,
    }
    with tempfile.TemporaryDirectory(prefix="ousast-delta-smoke-") as temporary:
        repo = Path(temporary)

        def git(*parts: str) -> bytes:
            return subprocess.run(["git", "-C", str(repo), *parts], check=True, capture_output=True, timeout=10).stdout

        git("init")
        git("config", "user.name", "Delta smoke")
        git("config", "user.email", "delta@example.invalid")
        git("config", "core.hooksPath", os.devnull)
        source = repo / filename
        source.write_bytes(before)
        git("add", filename)
        git("commit", "-m", "base")
        base_oid = git("rev-parse", "HEAD").decode().strip()
        source.write_bytes(after)
        git("add", filename)
        git("commit", "-m", args.case)
        head_oid = git("rev-parse", "HEAD").decode().strip()
        source.write_bytes(b"uncommitted content\n")
        index = (repo / ".git/index").read_bytes()
        status = git("status", "--porcelain=v1", "-z")
        adapter = SnapshotAdapter(repo)
        (comparison,) = adapter.resolve_updates(f"refs/heads/topic {head_oid} refs/heads/topic {base_oid}\n").comparisons
        context = adapter.compare(comparison, declaration_paths=(), budget=budget)
        regions = (ScanRegion(filename, "handler", language, (family,), 1.0, "entry_point"),)
        backend = JoernBackend(heap_mb=1024)
        semantics = semantics_digest(engine_identity="joern-4.0.625/frontend-retention-v1", options={"max_regions": 1})
        with adapter.materialize(base_oid, budget=budget) as base_snapshot, adapter.materialize(head_oid, budget=budget) as head_snapshot:
            assert (base_snapshot.root / filename).read_bytes() == before and before
            assert (head_snapshot.root / filename).read_bytes() == after and after
            head = scan_repository(
                head_snapshot.root,
                regions,
                backend=backend,
                budget=ScanBudget(max_regions=1),
                execution_budget=budget,
                ranking_mode="evidence",
                unit="delta-smoke",
                population_complete=True,
            )
            assert head.findings and head.scope and head.question_outcomes, head
            assert not head.degradations and all(q.status == "completed" for q in head.question_outcomes), head
            delta = compare_targeted_base(
                base_snapshot.root,
                head=head,
                head_regions=regions,
                base_regions=regions,
                context=context,
                backend=backend,
                execution_budget=budget,
                scan_budget=ScanBudget(max_regions=1),
                head_semantics=semantics,
                base_semantics=semantics,
            )
            report.update(
                {
                    "comparison": comparison.to_payload(),
                    "context": context.to_payload(),
                    "base_input": {"bytes": len(before), "sha256": hashlib.sha256(before).hexdigest()},
                    "head_input": {"bytes": len(after), "sha256": hashlib.sha256(after).hexdigest()},
                    "head": asdict(head),
                    "delta": asdict(delta),
                    "expected_novelty": expected,
                }
            )
            # Emit evidence before assertions so a failed instrument cannot look like a clean zero.
            print(json.dumps(report, indent=2), flush=True)
            assert delta.base_scan and delta.base_scan.question_outcomes, delta
            assert not delta.base_scan.degradations, delta
            assert all(q.status == "completed" for q in delta.base_scan.question_outcomes), delta
            assert delta.candidates and all(c.novelty == expected for c in delta.candidates), delta
            assert not delta.coverage_reasons, delta
        assert not base_snapshot.root.exists() and not head_snapshot.root.exists()
        assert source.read_bytes() == b"uncommitted content\n"
        assert (repo / ".git/index").read_bytes() == index
        assert git("status", "--porcelain=v1", "-z") == status
    # A separate completion record distinguishes all assertions passing from partial JSON.
    print(json.dumps({"verified": True, "case": args.case, "elapsed_seconds": round(time.monotonic() - started, 2)}))


if __name__ == "__main__":
    main()
