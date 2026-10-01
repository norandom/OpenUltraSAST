"""``ousast learn ...`` beyond ``labels``: the local memory and the compiled program (design sections 4-5).

Host only, maintainer surface. The parser is registered from :mod:`..cli`; every heavy import is lazy. No command
here spends money unless it is given a real client: ``compile``/``evaluate``/``curve`` and ``memory embed`` run under
an explicit ``--budget-usd`` ceiling through the metered clients.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def add_commands(learn_sub: Any) -> None:
    memory = learn_sub.add_parser("memory", help="the decision engine's local memory of labelled examples")
    memory_sub = memory.add_subparsers(dest="memory_command", required=True)
    build = memory_sub.add_parser("build", help="label + feature record + excerpt -> example rows (no model)")
    build.add_argument("--labels", type=Path, required=True, help="labels-<sha>.jsonl written by `ousast learn labels --out`")
    build.add_argument("--features", type=Path, action="append", default=[], help="feature records (JSONL with repo, pin); repeatable")
    build.add_argument("--sources", type=Path, help="the source list (default: the packaged learn/sources.toml)")
    build.add_argument("--root", type=Path, default=Path("."), help="the repository root the source paths are relative to")
    build.add_argument("--cache", type=Path, help="clones and checkouts (default ~/.cache/openultrasast)")
    build.add_argument("--memory", help="the store (default OUSAST_MEMORY, then results_root()/memory)")
    build.add_argument("--profile", choices=("static", "plane"), default="static")
    build.add_argument("--dry-run", action="store_true", help="count, write nothing")


def run(args: argparse.Namespace) -> int:
    if args.learn_command == "memory" and args.memory_command == "build":
        return _memory_build(args)
    print(f"learn: unknown command {args.learn_command}", file=sys.stderr)
    return 2


def _memory_build(args: argparse.Namespace) -> int:
    """Exit 2 on a refused label (``origin: user``, a source outside the list) or a source with >10% unread excerpts."""
    from ..plane.memory import open_store
    from .examples import ExampleBuildError, SideReader, build_examples, read_jsonl, records_by_key
    from .labels import DEFAULT_CACHE, DEFAULT_SOURCES, load_sources

    sources = load_sources(args.sources or DEFAULT_SOURCES)
    labels = read_jsonl(args.labels)
    store = None if args.dry_run else open_store(args.memory)
    rows = [row for path in args.features for row in read_jsonl(path)]
    if store is not None:
        rows += [r.row for r in store.rows(kind="features")]
    reader = SideReader(args.root, args.cache or DEFAULT_CACHE, sources, labels)
    try:
        build = build_examples(
            labels, records_by_key(rows), reader, sources=sources, store=store, profile=args.profile, license_of=reader.license,
            function_of=reader.function,
        )  # fmt: skip
    except ExampleBuildError as exc:
        print(f"learn memory build: {exc}", file=sys.stderr)
        return 2
    summary = build.summary()
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["failing_sources"]:
        print(
            f"learn memory build: more than 10% of the recorded candidates have no excerpt in {summary['failing_sources']}", file=sys.stderr
        )
        return 2
    return 0


__all__ = ["add_commands", "run"]
