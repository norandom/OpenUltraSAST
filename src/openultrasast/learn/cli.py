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
    embed = memory_sub.add_parser("embed", help="embed the stored excerpts (OpenRouter, metered; cached by excerpt sha)")
    embed.add_argument("--memory", help="the store (default OUSAST_MEMORY, then results_root()/memory)")
    embed.add_argument("--model", default="openai/text-embedding-3-small")
    embed.add_argument("--manifest", type=Path, default=Path("plane/models/openrouter-embedding.yaml"), help="the Model with the prices")
    embed.add_argument("--budget-usd", type=float, help="the ceiling; required unless --dry-run")
    embed.add_argument("--budget-calls", type=int)
    embed.add_argument("--batch", type=int, default=32)
    embed.add_argument("--dry-run", action="store_true", help="count and estimate the tokens; no call")
    for name, text in (
        ("compile", "compile the program on the compile split (bootstrap few-shot, instruction search)"),
        ("evaluate", "evaluate a compiled program on the outer folds: cross-fitted calibration, nested operating points"),
        ("curve", "the program's metric over memory size on a fixed candidate subset"),
    ):
        sub = learn_sub.add_parser(name, help=text)
        sub.add_argument("--memory", help="the store (default OUSAST_MEMORY, then results_root()/memory)")
        sub.add_argument("--profile", choices=("static", "plane"), default="static")
        sub.add_argument("--spec", type=Path, help="the pre-registered compile spec (default: the packaged learn/compile.toml)")
        sub.add_argument("--manifest", type=Path, default=Path("plane/models/deepseek-flash.yaml"), help="the chat Model with the prices")
        sub.add_argument("--budget-usd", type=float, help="the ceiling of a paid run; required unless --replay-only")
        sub.add_argument("--budget-calls", type=int)
        sub.add_argument("--replay-only", action="store_true", help="no client: every response must come from the cache")
        sub.add_argument("--out", type=Path, help="write the report (counts and intervals only) here")
        if name != "compile":
            sub.add_argument("--program", required=True, help="the compiled program id (programs/<id>.json in the store)")
        if name == "curve":
            sub.add_argument("--subset", type=int, default=200)

    leaks = learn_sub.add_parser("audit-leaks", help="how well each signal alone separates the sides of a pair (no model)")
    leaks.add_argument("--memory", help="the store (default OUSAST_MEMORY, then results_root()/memory)")
    leaks.add_argument("--units", type=Path, help="the harvest units.json (unit -> case and side) for feature rows without a side")
    leaks.add_argument("--profile", choices=("static", "plane"), default="plane")
    leaks.add_argument("--kind", default="features", help="the row kind to audit (features, or example)")
    leaks.add_argument("--threshold", type=float, help="flag a separation at least this (default 0.20)")
    leaks.add_argument("--min-pairs", type=int, help="over at least this many pairs (default 10)")
    leaks.add_argument("--out", type=Path, help="write the counts-only report here")


def run(args: argparse.Namespace) -> int:
    if args.learn_command == "audit-leaks":
        return _audit_leaks(args)
    if args.learn_command == "memory" and args.memory_command == "build":
        return _memory_build(args)
    if args.learn_command == "memory" and args.memory_command == "embed":
        return _memory_embed(args)
    if args.learn_command in ("compile", "evaluate", "curve"):
        return _program_command(args)
    print(f"learn: unknown command {args.learn_command}", file=sys.stderr)
    return 2


def _caller(args: argparse.Namespace, store: Any, model: str) -> Any:
    """The metered, cached caller; ``None`` client under --replay-only. Exits 2 without a ceiling or a key."""
    from ..plane.budget import MeteredClient
    from .program import Caller

    parameters = _model_parameters(args.manifest)
    if args.replay_only:
        return Caller(None, model, parameters, store=store)
    if args.budget_usd is None:
        raise SystemExit("learn: --budget-usd is required (a paid run starts only under a ceiling), or --replay-only")
    from ..config import load_config
    from ..model.endpoint import resolve_chat_endpoint

    resolved = resolve_chat_endpoint(load_config(None))
    if resolved is None:
        raise SystemExit("learn: no chat endpoint configured (DEEPSEEK_API_KEY); nothing was spent")
    client = MeteredClient(resolved[0], prices=parameters, budget_usd=args.budget_usd, budget_calls=args.budget_calls)
    return Caller(client, model, parameters, store=store)


def _identities(store: Any) -> dict[str, tuple[str, ...]]:
    """Per example id, the strings its demonstration's rationale must not name: group, repository and path parts."""
    from .compile import group_identities
    from .examples import EXAMPLE_KIND

    out: dict[str, tuple[str, ...]] = {}
    for record in store.rows(kind=EXAMPLE_KIND):
        row = record.row
        path = str(row.get("candidate", "")).partition("::")[0]
        out[str(row["id"])] = (*group_identities(str(row.get("group") or "")), str(row["repo"]), path, path.rsplit("/", 1)[-1])
    return out


def _program_command(args: argparse.Namespace) -> int:
    """compile | evaluate | curve. Exit 3 when the ceiling stops the run (``unfinished``, no artifact, no number)."""
    from datetime import date

    from ..plane.budget import BudgetExhausted
    from ..plane.memory import open_store
    from .compile import DEFAULT_SPEC, compile_program, load_program, load_spec, spec_of
    from .embeddings import EmbeddingCache
    from .evaluate import candidate_from_example, evaluate, learning_curve, predict, targets, unevaluable_families
    from .examples import load_examples
    from .folds import compile_split, outer_folds
    from .program import Program

    store = open_store(args.memory)
    spec = load_spec(args.spec or DEFAULT_SPEC)
    memory = load_examples(store, args.profile)
    cache = EmbeddingCache(store)
    vectors = {sha: v for sha in cache.names() if (v := cache.get(sha)) is not None} or None

    def excerpt_text(sha: str) -> str | None:
        data = store.get_blob("excerpts", sha)
        return data.decode("utf-8") if data is not None else None

    model = str(spec["classify"].get("model", "deepseek-flash"))
    caller = _caller(args, store, model)
    report: dict[str, Any]
    try:
        if args.learn_command == "compile":
            ids = _identities(store)
            result = compile_program(
                memory, caller, excerpt_text, spec=spec, profile=args.profile, vectors=vectors,
                identities=lambda e: ids.get(e.id, ()), store=store, created=date.today().isoformat(),
            )  # fmt: skip
            report = {"status": result.status, "program_id": result.program_id, "calls": result.calls, "replayed": result.replayed,
                      "reason": result.reason, "bootstrap": result.bootstrap}  # fmt: skip
        else:
            artifact = load_program(store, args.program)
            program = Program(spec_of(artifact), memory, excerpt_text, vectors)
            split = compile_split(memory, fraction=float(spec["split"].get("compile_fraction", 0.25)), seed=spec.seed)
            folds = outer_folds(memory, seed=spec.seed, exclude=split.groups)
            pairs = targets(folds, memory, skip=unevaluable_families(memory))
            candidate_of = candidate_from_example(excerpt_text, vectors)
            if args.learn_command == "evaluate":
                report = evaluate(predict(program, folds, caller, candidate_of, seed=spec.seed, pairs=pairs), seed=spec.seed)
            else:
                report = {"curve": learning_curve(program, pairs[: args.subset], caller, candidate_of, seed=spec.seed)}
            report["program_id"] = args.program
    except BudgetExhausted as exc:
        print(f"learn {args.learn_command}: unfinished -- {exc}", file=sys.stderr)
        return 3
    report["spend"] = {"usd": caller.usd(), "client_calls": caller.calls, "replayed": caller.replayed}
    text = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


def _model_parameters(path: Path) -> dict[str, Any]:
    from ..plane.manifests import load_manifests

    models = load_manifests([path]).models
    if len(models) != 1:
        raise SystemExit(f"{path}: expected one Model, found {sorted(models)}")
    return dict(next(iter(models.values())).parameters)


def _memory_embed(args: argparse.Namespace) -> int:
    """Exit 2 without a ceiling, 3 when the ceiling stops the run (``unfinished``; a rerun resumes from the cache)."""
    from ..plane.budget import BudgetExhausted, MeteredEmbeddingClient
    from ..plane.memory import open_store
    from .embeddings import embed_excerpts
    from .examples import EXAMPLE_KIND

    store = open_store(args.memory)
    shas = sorted({str(r.row["excerpt_sha"]) for r in store.rows(kind=EXAMPLE_KIND)})
    client = None
    if not args.dry_run:
        if args.budget_usd is None:
            print("learn memory embed: --budget-usd is required (a paid run starts only under a ceiling)", file=sys.stderr)
            return 2
        from ..provider.openrouter import OpenRouterEmbeddingClient

        client = MeteredEmbeddingClient(
            OpenRouterEmbeddingClient.from_env(), prices=_model_parameters(args.manifest), budget_usd=args.budget_usd,
            budget_calls=args.budget_calls,
        )  # fmt: skip
    try:
        report = embed_excerpts(store, shas, client, model=args.model, batch=args.batch)
    except BudgetExhausted as exc:
        print(f"learn memory embed: unfinished -- {exc}", file=sys.stderr)
        return 3
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0


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


def _audit_leaks(args: argparse.Namespace) -> int:
    """Exit 2 when the store holds no pair to audit (an unread store is not a clean one)."""
    from ..plane.memory import open_store
    from .leaks import MIN_PAIRS, THRESHOLD, audit, pair_rows, sides_from_units

    store = open_store(args.memory)
    rows = [r.row for r in store.rows(kind=args.kind)]
    units = json.loads(args.units.read_text(encoding="utf-8")) if args.units is not None else {}
    pairs, skipped = pair_rows(rows, sides_from_units(units), args.profile)
    if not pairs:
        print(f"learn audit-leaks: {len(rows)} {args.kind} rows in {store.describe()}, no pair to audit {skipped}", file=sys.stderr)
        return 2
    threshold = THRESHOLD if args.threshold is None else args.threshold
    report = audit(pairs, args.profile, threshold=threshold, min_pairs=MIN_PAIRS if args.min_pairs is None else args.min_pairs)
    report = {"rows_read": len(rows), "kind": args.kind, "skipped": skipped, **report}
    text = json.dumps(report, indent=1, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(json.dumps({"rows_read": len(rows), "pairs": report["pairs"], "flagged_signals": report["flagged_signals"]}, sort_keys=True))
    for cell in report["flagged"]:
        print(
            f"  {cell['separation']:.3f}  {cell['signal']}  [{cell['scope']}]  {cell['correct']}-{cell['wrong']} of {cell['pairs']} pairs"
        )
    return 0


__all__ = ["add_commands", "run"]
