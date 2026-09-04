"""Intra-file taint on FileIR. Incomplete flow is unadjudicated, never demote."""

from __future__ import annotations

from dataclasses import dataclass

from .facts import SemanticFacts, SinkFact, SourceFact
from .ir import CallSite, FileIR, FunctionIR, parse_file

TAINTED = "tainted"
CONSTANT = "constant"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class TaintPath:
    path: str
    source: str
    sink: str
    sink_line: int
    names: tuple[str, ...]
    sanitizer: str | None = None
    cwe: str = ""


@dataclass(frozen=True)
class Demotion:
    path: str
    sink: str
    sink_line: int
    dominating_fact: str
    sanitizers: tuple[str, ...] = ()
    cwe: str = ""


@dataclass(frozen=True)
class UnadjudicatedFlow:
    path: str
    reason: str
    engine: str = "none"


@dataclass(frozen=True)
class FileFlow:
    path: str
    language: str
    engine: str
    taint_paths: tuple[TaintPath, ...]
    demotions: tuple[Demotion, ...]
    incomplete: tuple[tuple[int, str], ...]


def analyze_file(path: str, text: str, language: str, facts: SemanticFacts) -> FileFlow | UnadjudicatedFlow:
    ir = parse_file(path, text, language)
    if not ir.parse_ok:
        return UnadjudicatedFlow(path=path, reason=ir.reason or "parse_failed", engine=ir.engine)
    return analyze_ir(ir, facts.for_language(language))


def analyze_ir(ir: FileIR, facts: SemanticFacts) -> FileFlow:
    paths: list[TaintPath] = []
    demotions: list[Demotion] = []
    incomplete: list[tuple[int, str]] = []
    for function in ir.functions:
        _analyze_function(ir.path, function, facts, paths, demotions, incomplete)
    return FileFlow(
        path=ir.path,
        language=ir.language,
        engine=ir.engine,
        taint_paths=tuple(paths),
        demotions=tuple(demotions),
        incomplete=tuple(incomplete),
    )


def _analyze_function(
    path: str,
    function: FunctionIR,
    facts: SemanticFacts,
    paths: list[TaintPath],
    demotions: list[Demotion],
    incomplete: list[tuple[int, str]],
) -> None:
    states: dict[str, str] = {param: TAINTED for param in function.params}
    sources: dict[str, str] = {param: "parameter" for param in function.params}
    for _ in range(8):
        changed = False
        for bind in function.binds:
            new_state, source = _bind_state(bind, states, sources, facts)
            if states.get(bind.name) != new_state or (source and sources.get(bind.name) != source):
                states[bind.name] = new_state
                if source:
                    sources[bind.name] = source
                changed = True
        if not changed:
            break
    for call in function.calls:
        _analyze_call(path, call, states, sources, facts, paths, demotions, incomplete)


def _bind_state(bind: object, states: dict[str, str], sources: dict[str, str], facts: SemanticFacts) -> tuple[str, str | None]:
    from .ir import Bind

    assert isinstance(bind, Bind)
    source = _source_in(bind.value_text, facts)
    if source:
        return TAINTED, source.id
    if bind.is_constant and not bind.names:
        return CONSTANT, None
    inherited = [_name_state(name, states) for name in bind.names]
    if TAINTED in inherited:
        tainted_name = next((name for name in bind.names if states.get(name) == TAINTED), None)
        return TAINTED, sources.get(tainted_name or "")
    if inherited and all(item == CONSTANT for item in inherited):
        return CONSTANT, None
    if bind.call_name and not _known_callee(bind.call_name, facts):
        return UNKNOWN, None
    if not bind.names and not bind.is_constant:
        return UNKNOWN, None
    return UNKNOWN, None


def _analyze_call(
    path: str,
    call: CallSite,
    states: dict[str, str],
    sources: dict[str, str],
    facts: SemanticFacts,
    paths: list[TaintPath],
    demotions: list[Demotion],
    incomplete: list[tuple[int, str]],
) -> None:
    sink = _sink_for(call.name, facts)
    sanitizer = _sanitizer_for(call, facts)
    arg_states = [_arg_state(call, index, states, facts) for index in range(len(call.arg_texts))]
    if sink is None:
        return
    if sanitizer is not None:
        demotions.append(
            Demotion(
                path=path,
                sink=sink.id,
                sink_line=call.line,
                dominating_fact=sanitizer,
                sanitizers=(sanitizer,),
                cwe=sink.cwe,
            )
        )
        return
    if TAINTED in arg_states:
        source_name = _source_label(call, states, sources, facts)
        paths.append(
            TaintPath(
                path=path,
                source=source_name,
                sink=sink.id,
                sink_line=call.line,
                names=_tainted_names(call, states),
                cwe=sink.cwe,
            )
        )
        return
    if arg_states and all(item == CONSTANT for item in arg_states):
        demotions.append(
            Demotion(
                path=path,
                sink=sink.id,
                sink_line=call.line,
                dominating_fact="constant",
                cwe=sink.cwe,
            )
        )
        return
    if not call.arg_texts:
        incomplete.append((call.line, "flow_incomplete"))
        return
    incomplete.append((call.line, "flow_incomplete"))


def _arg_state(call: CallSite, index: int, states: dict[str, str], facts: SemanticFacts) -> str:
    text = call.arg_texts[index]
    if _source_in(text, facts):
        return TAINTED
    if call.arg_is_constant[index]:
        return CONSTANT
    names = call.arg_names[index]
    inherited = [_name_state(name, states) for name in names]
    if TAINTED in inherited:
        return TAINTED
    if inherited and all(item == CONSTANT for item in inherited):
        return CONSTANT
    if not names:
        return UNKNOWN
    return UNKNOWN


def _source_label(call: CallSite, states: dict[str, str], sources: dict[str, str], facts: SemanticFacts) -> str:
    for text in call.arg_texts:
        found = _source_in(text, facts)
        if found is not None:
            return found.id
    for names in call.arg_names:
        for name in names:
            if states.get(name) == TAINTED:
                return sources.get(name, "parameter")
    return "parameter"


def _tainted_names(call: CallSite, states: dict[str, str]) -> tuple[str, ...]:
    names: list[str] = []
    for group in call.arg_names:
        for name in group:
            if states.get(name) == TAINTED:
                names.append(name)
    return tuple(names)


def _name_state(name: str, states: dict[str, str]) -> str:
    return states.get(name, UNKNOWN)


def _source_in(text: str, facts: SemanticFacts) -> SourceFact | None:
    for source in facts.sources:
        for pattern in source.patterns:
            if pattern and pattern in text:
                return source
    return None


def _sink_for(name: str, facts: SemanticFacts) -> SinkFact | None:
    for sink in facts.sinks:
        for call in sink.calls:
            if _call_matches(name, call):
                return sink
    return None


def _sanitizer_for(call: CallSite, facts: SemanticFacts) -> str | None:
    for sanitizer in facts.sanitizers:
        if not any(_call_matches(call.name, name) for name in sanitizer.calls):
            continue
        if sanitizer.parameterized and call.extra_arg_is_sequence:
            return sanitizer.id
        if sanitizer.literal_format_arg is not None:
            index = sanitizer.literal_format_arg
            if index < len(call.arg_is_constant) and call.arg_is_constant[index] and _looks_like_format(call.arg_texts[index]):
                return sanitizer.id
        if not sanitizer.parameterized and sanitizer.literal_format_arg is None:
            return sanitizer.id
    return None


def _looks_like_format(text: str) -> bool:
    stripped = text.strip()
    return len(stripped) >= 2 and stripped[0] in {"'", '"'} and stripped[-1] == stripped[0]


def _known_callee(name: str, facts: SemanticFacts) -> bool:
    if _sink_for(name, facts) is not None:
        return True
    if _source_in(name, facts) is not None:
        return True
    return any(any(_call_matches(name, call) for call in sanitizer.calls) for sanitizer in facts.sanitizers)


def _call_matches(name: str, fact_call: str) -> bool:
    if name == fact_call:
        return True
    if name.endswith("." + fact_call):
        return True
    if fact_call.endswith(name) and "." not in name:
        # "execute" matches "db.execute" via endswith .execute above; bare execute matches execute.
        return name == fact_call.split(".")[-1]
    return False


def merge_joern_paths(existing: tuple[TaintPath, ...], extra: tuple[TaintPath, ...]) -> tuple[TaintPath, ...]:
    seen = {(item.path, item.sink_line, item.sink) for item in existing}
    merged = list(existing)
    for item in extra:
        key = (item.path, item.sink_line, item.sink)
        if key not in seen:
            merged.append(item)
            seen.add(key)
    return tuple(merged)
