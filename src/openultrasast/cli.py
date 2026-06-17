from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_config
from .findings import quick_scan_findings, write_findings
from .index import build_code_chunks
from .preprocess import preprocess_repository
from .rank import rank_targets, write_rankings
from .reports import write_markdown_report
from .run import create_scan_run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ousast")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a local repository")
    scan.add_argument("path", type=Path)
    scan.add_argument("--mode", choices=("quick", "standard", "deep"), default="quick")
    scan.add_argument("--config", type=Path, default=Path("openultrasast.toml"))

    index = subparsers.add_parser("index", help="chunk a local repository for embedding index construction")
    index.add_argument("path", type=Path)
    index.add_argument("--config", type=Path, default=Path("openultrasast.toml"))
    index.add_argument("--chunk-lines", type=int, default=80)

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args.path, args.config, args.mode)
    if args.command == "index":
        return _index(args.path, args.config, args.chunk_lines)
    return 2


def _scan(path: Path, config_path: Path, mode: str) -> int:
    if mode != "quick":
        raise SystemExit(f"mode {mode!r} is specified but only quick preprocess artifacts are implemented")
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"scan path is not a directory: {path}")

    config = load_config(config_path if config_path.exists() else None)
    run = create_scan_run(path, config)
    _, targets = preprocess_repository(run.target, run.root / "preprocess" / "file_targets.json")
    rankings = rank_targets(targets)
    write_rankings(rankings, run.root / "rank" / "ranking.json")
    findings = quick_scan_findings(run.target, targets, rankings)
    write_findings(findings, run.root / "findings.json")
    write_markdown_report(findings, run.root / "report.md")
    print(f"scan_id={run.scan_id}")
    print(f"run_dir={run.root}")
    print(f"file_targets={len(targets)}")
    print(f"ranked_targets={len(rankings)}")
    print(f"findings={len(findings)}")
    return 0


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
