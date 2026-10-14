"""Deterministic access-control verdicts from recognised entries and bounded paths."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .. import mapping, source
from ..preprocess import FileTarget, count_loc, detect_language, detect_tags
from ..semantic.facts import load_facts
from ..semantic.ir import FileIR, FunctionIR, trailing_name
from ..semantic.obligations.check import _on_caller_hop, _relevant, check_obligations
from ..semantic.obligations.dominance import OrderDominance
from ..semantic.obligations.facts import load_obligation_facts
from ..semantic.obligations.operations import Operation, find_operations, valid_witness
from ..semantic.obligations.paths import compose_paths
from ..semantic.obligations.policy import DEFAULT_POLICY_RELPATH, load_declared_policy
from .producers import Context, _safe_path


@dataclass(frozen=True)
class Coverage:
    files_by_language: dict[str, int]
    frameworks_recognised: dict[str, int]
    entry_points: int
    reached: int
    unreached: int
    operations_checked: int
    operations_discharged: int
    unchecked_by_reason: dict[str, int]


@dataclass(frozen=True)
class ProverResult:
    findings: tuple[dict[str, Any], ...]
    coverage: Coverage
    degradations: tuple[dict[str, Any], ...]


def prove_change(root: Path, change: Mapping[str, Any], ctx: Context | None = None, *, max_depth: int = 3) -> ProverResult:
    """Check touched head functions and their direct operation-bearing callees, with no model."""
    if max_depth < 0:
        raise ValueError("invalid path depth")
    root = Path(root)
    ctx = ctx if ctx is not None else Context(root, change)
    ctx.verify_head()
    facts, flow = load_obligation_facts(), load_facts()
    reasons: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    frameworks: Counter[str] = Counter()
    degradations: list[dict[str, Any]] = []
    touched: set[tuple[str, str]] = set()
    functions: dict[tuple[str, str], FunctionIR] = {}
    operations: dict[tuple[str, str], tuple[Operation, ...]] = {}
    irs: dict[str, tuple[FileIR, str]] = {}
    failed: set[str] = set()
    readable: list[str] = []
    targets: list[FileTarget] = []

    # Read each product file once through the shared cache. Build mapping targets from that text.
    for path in ctx.product_files:
        try:
            text = ctx.read(path)
            language = source.canonical_language(detect_language(root / path))
            languages[language] += 1
            targets.append(FileTarget(path, str(root / path), language, count_loc(text), detect_tags(path, language, text), False, [], []))
            readable.append(path)
        except Exception as error:
            failed.add(path)
            reasons[str(getattr(error, "reason", None) or type(error).__name__)] += 1
            degradations.append({"path": path, "reason": str(getattr(error, "reason", None) or type(error).__name__)})
    if "entry_points" not in ctx.__dict__:
        # External manifest enforcement is supplied by delivery B; this delivery uses source entries.
        mapped: list[mapping.EntryPointRecord] = []
        for target in targets:
            try:
                mapped.extend(mapping.analyze_entry_points(root, [target], texts=ctx.texts, include_manifests=False))
            except Exception as error:
                failed.add(target.path)
                reasons[str(getattr(error, "reason", None) or type(error).__name__)] += 1
                degradations.append({"path": target.path, "reason": str(getattr(error, "reason", None) or type(error).__name__)})
        ctx.__dict__["entry_points"] = mapped
    entries = [entry for entry in ctx.entry_points if entry.function_name and entry.defines_handler and entry.line is not None]
    recognised = {entry.path for entry in entries}
    for path in recognised:
        evidence = " ".join(item for entry in entries if entry.path == path for item in entry.access_evidence)
        framework = (
            "stapler"
            if "Stapler" in evidence
            else "jetty"
            if "Jetty" in evidence
            else "servlet"
            if "Servlet" in evidence
            else "jaxrs"
            if "JAX-RS" in evidence
            else source.canonical_language(detect_language(root / path))
        )
        frameworks[framework] += 1

    def read_ir(path: str) -> FileIR | None:
        if path in failed:
            return None
        if path in irs:
            return irs[path][0]
        try:
            ir, text = ctx.ir(path), ctx.read(path)
            if not ir.parse_ok:
                reasons["language_unsupported" if ir.reason == "language_unsupported" else "parse_failed"] += 1
                failed.add(path)
                return None
            if not facts.for_language(ir.language).operations:
                reasons["no_facts"] += 1
                failed.add(path)
                return None
            irs[path] = ir, text
            ctx.spans.setdefault(path, source.ranges_from_ir(ir, text))
            found = find_operations(ir, facts.for_language(ir.language), text=text)
            for fn in ir.functions:
                if fn.name != "<module>":
                    functions[path, fn.name] = fn
                    operations[path, fn.name] = tuple(op for op in found if op.function == fn.name)
            return ir
        except Exception as error:
            reasons[str(getattr(error, "reason", None) or type(error).__name__)] += 1
            failed.add(path)
            degradations.append({"path": path, "reason": str(getattr(error, "reason", None) or type(error).__name__)})
            return None

    for file in change.get("files", ()):
        path = str(file["path"])
        _safe_path(root, path)
        reason = source.generated_reason(root, path)
        if reason:
            reasons[reason] += 1
            continue
        ir = read_ir(path)
        if ir is None:
            continue
        selected = [
            fn
            for fn in ir.functions
            if fn.name != "<module>" and any(fn.start_line <= end and start <= fn.end_line for start, end in file.get("head_lines", ()))
        ]
        touched.update((path, fn.name) for fn in selected)
        if file.get("head_lines") and not selected:
            reasons["function_unavailable"] += 1

    # The existing name-based index supplies call sites; retain file-qualified enclosing functions.
    def callers(path: str, function: str) -> list[tuple[str, int]]:
        del path
        out = []
        for caller_path, line in source.callers_of(root, function, files=readable, texts=ctx.texts, index=ctx.call_index):
            ir = read_ir(caller_path)
            if ir is None:
                continue
            spans = [fn for fn in ir.functions if fn.name != "<module>" and fn.start_line <= line <= fn.end_line]
            if spans:
                fn = min(spans, key=lambda item: item.end_line - item.start_line)
                out.append((f"{caller_path}::{fn.name}", line))
        return out

    target_functions = set(touched)
    call_names = {trailing_name(call.name) for key in touched for call in functions[key].calls}
    if call_names:
        for path in readable:
            # Ranges are cached and avoid parsing unrelated files just to look for direct callees.
            try:
                if any(span.name in call_names for span in ctx.ranges(path)):
                    read_ir(path)
            except Exception as error:
                reasons[str(getattr(error, "reason", None) or type(error).__name__)] += 1
                degradations.append({"path": path, "reason": str(getattr(error, "reason", None) or type(error).__name__)})
        target_functions.update(key for key, ops in operations.items() if key[1] in call_names and ops)
    paths, unreached = compose_paths(
        callers=callers, entries={f"{e.path}::{e.function_name}" for e in entries}, targets=sorted(target_functions), max_depth=max_depth
    )
    path_nodes = {node for record in paths for node, _ in record.hops}
    for node in path_nodes:
        read_ir(node.rpartition("::")[0])
    for node in unreached:
        path = node.rpartition("::")[0]
        reasons["unreached" if path in recognised else "framework_unrecognised"] += 1
    entry_index = {f"{e.path}::{e.function_name}": e for e in entries}
    policy = load_declared_policy(_safe_path(root, DEFAULT_POLICY_RELPATH.as_posix()))
    dominance = OrderDominance(ctx.texts)
    findings: dict[str, dict[str, Any]] = {}
    checked: set[Operation] = set()
    undischarged: set[Operation] = set()
    for record in paths:
        needed_files = {path for path, _ in touched} | {node.rpartition("::")[0] for node, _ in record.hops}
        path_irs = {path: irs[path] for path in sorted(needed_files) if path in irs}
        if len(path_irs) != len(needed_files):
            continue
        result = check_obligations(
            irs=path_irs,
            entries=entries,
            facts=facts,
            flow_facts=flow,
            policy=policy,
            paths=[record],
            dominance=dominance,
            store_shapes=(),
            min_siblings=3,
            extra_witnesses=(),
            assume_entries_protected=True,
        )
        degradations.extend(result.degradations)
        target_path, _, target_name = record.hops[-1][0].rpartition("::")
        for op in operations.get((target_path, target_name), ()):
            checked.add(op)
            # Silence from a public premise is not evidence that a check dominated the operation.
            if not any(
                w.kind in op.requires
                and valid_witness(w)
                and dominance.dominates(w, op, record)
                and (_relevant(w, op) or _on_caller_hop(w, record, op, dominance))
                for w in result.discharges
            ):
                undischarged.add(op)
        for finding in result.findings:
            op = finding.operation
            identity = f"obligation:{op.kind}:{op.path}:{op.line}:{finding.missing}"
            op_fact = next(fact for fact in facts.operations if fact.id == op.fact_id)
            fn = functions[op.path, op.function]
            calls = sorted(
                {
                    trailing_name(call.name)
                    for call in fn.calls
                    if call.line == op.line and any(call.name == name or call.name.endswith("." + name) for name in op_fact.calls)
                }
            )
            entry = asdict(entry_index[record.entry])
            hops = [list(hop) for hop in record.hops]
            findings.setdefault(
                identity,
                dict(
                    path=op.path,
                    line=op.line,
                    family="access_control",
                    function=op.function,
                    evidence=[
                        *finding.evidence,
                        f"hops: {' -> '.join(node for node, _ in record.hops)}",
                        f"operation {op.fact_id} ({op.kind}) at {op.path}:{op.line}; missing {finding.missing}",
                    ],
                    id=identity,
                    entry=entry,
                    hops=hops,
                    operation=dict(id=op.fact_id, kind=op.kind, calls=calls, line=op.line),
                    missing=finding.missing,
                    label=finding.label,
                ),
            )
    coverage = Coverage(
        dict(languages),
        dict(frameworks),
        len(entries),
        len({record.hops[-1][0] for record in paths} & {f"{path}::{name}" for path, name in touched}),
        len(set(unreached) & {f"{path}::{name}" for path, name in touched}),
        len(checked),
        len(checked - undischarged),
        dict(reasons),
    )
    return ProverResult(tuple(findings.values()), coverage, tuple(degradations))
