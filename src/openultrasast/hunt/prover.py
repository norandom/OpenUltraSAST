"""Deterministic access-control verdicts from recognised entries and bounded paths."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from .. import mapping, source
from ..preprocess import FileTarget, count_loc, detect_language, detect_tags
from ..semantic.cfg import ControlContext, FunctionCfg
from ..semantic.cst import parse_function_nodes
from ..semantic.facts import load_facts
from ..semantic.ir import FileIR, FunctionIR, trailing_name
from ..semantic.obligations.abstract_domain import PairJudgmentCounts
from ..semantic.obligations.cfg_dominance import CfgDominance
from ..semantic.obligations.check import _on_caller_hop, _relevant, _route_path, check_obligations
from ..semantic.obligations.enforcement import witnesses
from ..semantic.obligations.facts import load_obligation_facts
from ..semantic.obligations.operations import Discharge, Operation, find_discharges, find_operations, valid_witness
from ..semantic.obligations.paths import compose_paths
from ..semantic.obligations.policy import DEFAULT_POLICY_RELPATH, load_declared_policy
from ..semantic.obligations.resolution import CallBindings, bind_calls
from ..semantic.obligations.trace import build_trace
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
    # Requirement 7.1/7.6 (access-control-prover): three-way pair judgment totals, additive and zero
    # until the prover opts into abstract judgment (task 10.6). Indeterminate pairs are counted
    # neither clean nor discharged.
    pair_judgments: PairJudgmentCounts = PairJudgmentCounts()
    # Requirement 3.3/3.4 (access-control-prover): call-resolution outcome totals. Prover-mode
    # resolution has no bare-name fallback; every call lands in exactly one bucket.
    resolution_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ProverResult:
    findings: tuple[dict[str, Any], ...]
    coverage: Coverage
    degradations: tuple[dict[str, Any], ...]
    traces: tuple[dict[str, Any], ...] = ()


def _resolution_bindings(
    readable: list[str],
    read_ir: Callable[[str], FileIR | None],
    functions: Mapping[tuple[str, str], FunctionIR],
    ctx: Context,
    reasons: Counter[str],
    degradations: list[dict[str, str]],
) -> CallBindings:
    """Parse every readable file and resolve all calls (Reqs 3.3/3.4)."""
    for path in readable:
        try:
            read_ir(path)
        except Exception as error:
            reasons[type(error).__name__] += 1
            degradations.append({"path": path, "reason": type(error).__name__})
    functions_by_module: dict[str, list[FunctionIR]] = {}
    for (module, _name), function_ir in functions.items():
        functions_by_module.setdefault(module, []).append(function_ir)
    return bind_calls(functions_by_module=functions_by_module, index=ctx.symbol_index)


def _exact_callers(bindings: CallBindings, ctx: Context, path: str, function: str) -> list[tuple[str, int]]:
    """Caller sites from exact bindings only; no bare-name fallback (Reqs 3.3/3.4)."""
    out = []
    for symbol in ctx.symbol_index.by_name.get(function, ()):
        if symbol.module != path:
            continue
        for binding in bindings.exact_callers(symbol):
            out.append((f"{binding.module}::{binding.function}", binding.line))
    return sorted(set(out))


def _targets_from_bindings(
    touched: set[tuple[str, str]],
    functions: Mapping[tuple[str, str], FunctionIR],
    bindings: CallBindings,
) -> set[tuple[str, str]]:
    """Targets join by resolved symbol identity, never by trailing name (Req 3.3)."""
    target_functions = set(touched)
    for key in touched:
        for call in functions[key].calls:
            for target_set in bindings.resolutions.get((key[0], key[1], call.line), ()):
                target_functions.update((symbol.module, symbol.name) for symbol in target_set.targets)
    return target_functions


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
            reasons[type(error).__name__] += 1
            degradations.append({"path": path, "reason": type(error).__name__})
    for config in mapping.framework_config_paths(root):
        try:
            ctx.read(config)
        except Exception as error:
            degradations.append({"path": config, "reason": type(error).__name__})
    if "entry_points" not in ctx.__dict__:
        ctx.__dict__["entry_points"] = mapping.analyze_entry_points(root, targets, texts=ctx.texts, include_manifests=False)
    entries = [
        entry
        for entry in ctx.entry_points
        if entry.function_name and entry.defines_handler and entry.line is not None and entry.kind == "route"
    ]
    recognised = {entry.path for entry in entries}
    handlers_of: dict[str, dict[str, str]] = {}
    framework_files: set[tuple[str, str]] = set()
    for entry in entries:
        framework = mapping.entry_framework(entry)
        if framework is None:
            framework = source.canonical_language(detect_language(root / entry.path))
        framework_files.add((entry.path, framework))
        handlers_of.setdefault(entry.path, {})[str(entry.function_name)] = framework
    frameworks.update(framework for _, framework in framework_files)

    def read_ir(path: str) -> FileIR | None:
        if path in failed:
            return None
        if path in irs:
            return irs[path][0]
        try:
            ir, text = ctx.ir(path), ctx.read(path)
            aliases = {e.line: e.function_name for e in entries if e.path == path and mapping.entry_framework(e) == "remix"}
            ir = replace(
                ir,
                functions=tuple(
                    replace(fn, name=str(aliases[fn.start_line])) if fn.name == "<anon>" and fn.start_line in aliases else fn
                    for fn in ir.functions
                ),
            )
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
            found = find_operations(ir, facts.for_language(ir.language), text=text, handlers_of=handlers_of.get(path))
            for fn in ir.functions:
                if fn.name != "<module>":
                    functions[path, fn.name] = fn
                    operations[path, fn.name] = tuple(op for op in found if op.function == fn.name)
            return ir
        except Exception as error:
            reasons[type(error).__name__] += 1
            failed.add(path)
            degradations.append({"path": path, "reason": type(error).__name__})
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

    # Full IR coverage first: conservative resolution (Req 3.3/3.4) needs every readable file parsed.
    bindings = _resolution_bindings(readable, read_ir, functions, ctx, reasons, degradations)

    # Conservative caller resolution: only exact (complete, single-target) bindings supply callers;
    # the global bare-name index fallback is removed from the prover path (Req 3.3/3.4).
    def callers(path: str, function: str) -> list[tuple[str, int]]:
        return _exact_callers(bindings, ctx, path, function)

    target_functions = _targets_from_bindings(touched, functions, bindings)
    paths, unreached = compose_paths(
        callers=callers, entries={f"{e.path}::{e.function_name}" for e in entries}, targets=sorted(target_functions), max_depth=max_depth
    )
    # Handler obligations fill gaps in the call inventory. Preserve the established call-site verdict
    # when that entry already reaches a listed operation, including one in a directly called helper.
    handler_ids = {fact.id for fact in facts.operations if fact.handlers}
    for record in paths:
        target_path, _, target_name = record.hops[-1][0].rpartition("::")
        if any(op.fact_id not in handler_ids for op in operations.get((target_path, target_name), ())):
            entry_path, _, entry_name = record.entry.rpartition("::")
            if handlers_of.get(entry_path, {}).get(entry_name) != "remix":
                handlers_of[entry_path].pop(entry_name, None)
    for (path, name), ops in operations.items():
        if name not in handlers_of.get(path, {}):
            operations[path, name] = tuple(op for op in ops if op.fact_id not in handler_ids)
    path_nodes = {node for record in paths for node, _ in record.hops}
    for node in path_nodes:
        read_ir(node.rpartition("::")[0])
    for node in unreached:
        path = node.rpartition("::")[0]
        reasons["unreached" if path in recognised else "framework_unrecognised"] += 1
    entry_index = {f"{e.path}::{e.function_name}": e for e in entries}
    policy = load_declared_policy(_safe_path(root, DEFAULT_POLICY_RELPATH.as_posix()))
    handler_ends: dict[Operation, int] = {}
    for (path, name), ops in operations.items():
        fn = functions[path, name]
        returns = [
            index
            for index, line in enumerate(ctx.texts[path].splitlines(), 1)
            if fn.start_line <= index <= fn.end_line and re.match(r"^\s*return\b", line)
        ]
        for op in ops:
            if op.fact_id in handler_ids:
                handler_ends[op] = returns[-1] if returns else fn.end_line + 1
    graphs = CfgDominance(ctx.texts, _Graphs(irs))
    dominance = _HandlerDominance(graphs, handler_ends)
    extra_witnesses: list[Discharge] = []
    for language in ("php", "python"):
        try:
            extra_witnesses.extend(witnesses(root=root, texts=ctx.texts, entries=entries, language=language))
        except Exception as error:
            degradations.append({"stage": "enforcement", "reason": type(error).__name__})
    # Boolean permission predicates need an exit; they are not throwing guards.
    for op in handler_ends:
        ir, text = irs[op.path]
        for witness in find_discharges(ir, facts.for_language(ir.language), flow.for_language(ir.language), text=text):
            if (
                witness.function == op.function
                and witness.kind == "ownership_check"
                and dominance.dominates(witness, op, None)
                and handlers_of.get(op.path, {}).get(op.function) == "stapler"
            ):
                extra_witnesses.append(replace(witness, kind="path_guard"))
    findings: dict[str, dict[str, Any]] = {}
    traces: list[dict[str, Any]] = []
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
            extra_witnesses=extra_witnesses,
            handlers_of=handlers_of,
            assume_entries_protected=True,
        )
        degradations.extend(result.degradations)
        target_path, _, target_name = record.hops[-1][0].rpartition("::")
        pair_traces: dict[Operation, dict[str, Any]] = {}
        for op in operations.get((target_path, target_name), ()):
            checked.add(op)
            # Silence from a public premise is not evidence that a check dominated the operation.
            dominated = {
                w.kind
                for w in result.discharges
                if w.kind in op.requires
                and valid_witness(w)
                and dominance.dominates(w, op, record)
                and (_relevant(w, op) or _on_caller_hop(w, record, op, dominance))
            }
            if (set(op.requires) - dominated) if op.fact_id in handler_ids else not dominated:
                undischarged.add(op)
            missing = next((finding.missing for finding in result.findings if finding.operation == op), None)
            trace_entry = entry_index[record.entry]
            route = _route_path(op, ctx.texts[op.path]) or trace_entry.name
            declared_access = policy.route_access(route) if policy is not None and route else None
            trace = build_trace(
                path=record,
                entry=trace_entry,
                access=declared_access,
                operation=op,
                irs=path_irs,
                facts=facts,
                witnesses=result.discharges,
                dominance=dominance,
                dominating=tuple(sorted(dominated)),
                missing=missing,
            ).record()
            traces.append(trace)
            pair_traces[op] = trace
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
            entry_payload = asdict(entry_index[record.entry])
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
                    entry=entry_payload,
                    hops=hops,
                    operation=dict(id=op.fact_id, kind=op.kind, calls=calls, line=op.line),
                    missing=finding.missing,
                    label=finding.label,
                    trace=pair_traces[op],
                ),
            )
    degradations.extend(graphs.degradations)
    coverage = Coverage(
        dict(languages),
        dict(frameworks),
        len(entries),
        len({record.hops[-1][0] for record in paths} & {f"{path}::{name}" for path, name in touched}),
        len(set(unreached) & {f"{path}::{name}" for path, name in touched}),
        len(checked),
        len(checked - undischarged),
        dict(reasons),
        resolution_counts=dict(bindings.counts),
    )
    return ProverResult(tuple(findings.values()), coverage, tuple(degradations), tuple(traces))


class _HandlerDominance:
    """Judge a handler's internal guard at the handler's end while retaining its declaration as the finding location.

    Call operations are judged as the inner dominance judges them. The checker default and OrderDominance are unchanged.
    """

    def __init__(self, inner: CfgDominance, handler_ends: Mapping[Operation, int]) -> None:
        self.inner = inner
        self.handler_ends = handler_ends

    def _measured(self, operation: Operation) -> Operation:
        end = self.handler_ends.get(operation)
        return replace(operation, line=end) if end is not None else operation

    def dominates(self, witness: Discharge, operation: Operation, path: object | None) -> bool:
        return self.inner.dominates(witness, self._measured(operation), path)

    def relation(self, witness: Discharge, operation: Operation) -> str:
        return self.inner.relation(witness, self._measured(operation))

    def effect(self, witness: Discharge, operation: Operation) -> str:
        return self.inner.effect(witness, self._measured(operation))

    def context(self, operation: Operation) -> ControlContext:
        return self.inner.context(self._measured(operation))


class _Graphs(Mapping[tuple[str, str], tuple[FunctionCfg, ...]]):
    """Control-flow graphs of the parsed files' functions, built on first use and keyed by (path, function)."""

    def __init__(self, irs: Mapping[str, tuple[FileIR, str]]) -> None:
        self._irs = irs
        self._built: dict[str, dict[str, tuple[FunctionCfg, ...]]] = {}

    def _file(self, path: str) -> dict[str, tuple[FunctionCfg, ...]]:
        if path not in self._built:
            graphs: dict[str, list[FunctionCfg]] = {}
            if path in self._irs:
                ir, text = self._irs[path]
                nodes = parse_function_nodes(path, text, ir.language)
                by_line: dict[int, list[Any]] = {}
                for node in nodes:
                    by_line.setdefault(int(node.start_point[0]) + 1, []).append(node)
                for fn in ir.functions:
                    found = [node for node in by_line.get(fn.start_line, ()) if int(node.end_point[0]) + 1 == fn.end_line]
                    if len(found) == 1:
                        graphs.setdefault(fn.name, []).append(FunctionCfg.from_cst(found[0], ir.language))
            self._built[path] = {name: tuple(items) for name, items in graphs.items()}
        return self._built[path]

    def __getitem__(self, key: tuple[str, str]) -> tuple[FunctionCfg, ...]:
        return self._file(key[0])[key[1]]

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter([(path, name) for path in self._irs for name in self._file(path)])

    def __len__(self) -> int:
        return sum(len(self._file(path)) for path in self._irs)
