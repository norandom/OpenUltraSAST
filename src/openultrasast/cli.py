from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_config
from .findings import quick_scan_findings, write_findings
from .harness import HarnessRuntime, HarnessTraceWriter, write_harness_config
from .hunter import run_hunter_pool, write_hunter_trajectories
from .index import build_code_chunks
from .mapping import analyze_entry_points, attach_reachability_hints, ingest_sarif, write_entry_points, write_static_hints
from .preprocess import preprocess_repository, write_preprocess_artifact
from .rank import rank_targets, write_rankings
from .reports import scan_exit_code, write_manifest, write_markdown_report, write_sarif_report
from .run import create_scan_run
from .verification import verify_findings, write_verification_results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ousast")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a local repository")
    scan.add_argument("path", type=Path)
    scan.add_argument("--mode", choices=("quick", "standard", "deep"), default="quick")
    scan.add_argument("--config", type=Path, default=Path("openultrasast.toml"))
    scan.add_argument("--fail-on", choices=("never", "findings", "verified"), default="never")

    index = subparsers.add_parser("index", help="chunk a local repository for embedding index construction")
    index.add_argument("path", type=Path)
    index.add_argument("--config", type=Path, default=Path("openultrasast.toml"))
    index.add_argument("--chunk-lines", type=int, default=80)

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path, args.config, args.mode, args.fail_on)
    if args.command == "index":
        return _index(args.path, args.config, args.chunk_lines)
    return 2


def _scan(path: Path, config_path: Path, mode: str, fail_on: str) -> int:
    if mode == "deep":
        raise SystemExit("mode 'deep' is specified but sandboxed dynamic analysis is not implemented")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"scan path is not a directory: {path}")

    config = load_config(config_path if config_path.exists() else None)
    run = create_scan_run(path, config)
    runtime = HarnessRuntime(
        scan_id=run.scan_id,
        config=config,
        trace_writer=HarnessTraceWriter(run.root / "trace" / "events.jsonl"),
    )
    write_harness_config(config=config, processors=[], contract_mode="strict", path=run.root / "harness.json")
    runtime.start(mode=mode, target=run.target)
    static_hints = runtime.run_stage("static_mapping", lambda: _load_static_hints(config.static_analysis.sarif_paths))
    write_static_hints(static_hints, run.root / "mapping" / "static_hints.json")
    snapshot, targets = runtime.run_stage(
        "preprocess",
        lambda: preprocess_repository(run.target, run.root / "preprocess" / "file_targets.json", static_hints),
    )
    entry_points = runtime.run_stage("entry_point_mapping", lambda: analyze_entry_points(run.target, targets))
    write_entry_points(entry_points, run.root / "mapping" / "entry_points.json")
    targets = attach_reachability_hints(targets, entry_points)
    write_preprocess_artifact(snapshot, targets, run.root / "preprocess" / "file_targets.json")
    rankings = runtime.run_stage("rank", lambda: rank_targets(targets))
    write_rankings(rankings, run.root / "rank" / "ranking.json")
    if mode == "standard":
        hunter_result = runtime.run_stage("hunter_pool", lambda: run_hunter_pool(run.target, targets, rankings, scan_id=run.scan_id))
        findings = hunter_result.findings
        trajectories = hunter_result.trajectories
    else:
        findings = runtime.run_stage("quick_findings", lambda: quick_scan_findings(run.target, targets, rankings))
        trajectories = []
    findings_path = run.root / "findings.json"
    verification_path = run.root / "verification.json"
    markdown_path = run.root / "report.md"
    sarif_path = run.root / "report.sarif"
    manifest_path = run.root / "manifest.json"
    trajectories_path = run.root / "traces" / "hunter_trajectories.jsonl"
    write_findings(findings, findings_path)
    if trajectories:
        write_hunter_trajectories(trajectories, trajectories_path)
    verifications = runtime.run_stage("verify", lambda: verify_findings(findings))
    write_verification_results(verifications, verification_path)
    runtime.run_stage("report", lambda: write_markdown_report(findings, markdown_path, verifications))
    runtime.run_stage("sarif", lambda: write_sarif_report(findings, verifications, sarif_path))
    runtime.run_stage(
        "manifest",
        lambda: write_manifest(
            run=run,
            findings=findings,
            verifications=verifications,
            artifact_paths=_artifact_paths(
                findings=findings_path,
                verification=verification_path,
                markdown=markdown_path,
                sarif=sarif_path,
                trajectories=trajectories_path if trajectories else None,
            ),
            path=manifest_path,
        ),
    )
    runtime.finish(status="succeeded")
    print(f"scan_id={run.scan_id}")
    print(f"run_dir={run.root}")
    print(f"file_targets={len(targets)}")
    print(f"ranked_targets={len(rankings)}")
    print(f"findings={len(findings)}")
    return scan_exit_code(findings, verifications, fail_on)


def _load_static_hints(sarif_paths: tuple[str, ...]) -> list[object]:
    hints: list[object] = []
    for sarif_path in sarif_paths:
        path = Path(sarif_path)
        if path.exists():
            hints.extend(ingest_sarif(path))
    return hints


def _artifact_paths(**paths: Path | None) -> dict[str, Path]:
    return {name: path for name, path in paths.items() if path is not None}


def _index(path: Path, config_path: Path, chunk_lines: int) -> int:
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"index path is not a directory: {path}")
    config = load_config(config_path if config_path.exists() else None)
    run = create_scan_run(path, config)
    snapshot, targets = preprocess_repository(run.target, run.root / "preprocess" / "file_targets.json")
    chunks = build_code_chunks(run.target, targets, max_lines=chunk_lines)
    payload = {
        "store": config.embeddings.store or "json-local",
        "embedding_model": config.embeddings.model,
        "repo_root": snapshot.root,
        "repo_commit": snapshot.commit,
        "chunk_count": len(chunks),
        "chunks": [chunk.__dict__ for chunk in chunks],
    }
    path_out = run.root / "index" / "chunks.json"
    path_out.parent.mkdir(parents=True, exist_ok=True)
    path_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"scan_id={run.scan_id}")
    print(f"run_dir={run.root}")
    print(f"chunks={len(chunks)}")
    print(f"index_artifact={path_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
