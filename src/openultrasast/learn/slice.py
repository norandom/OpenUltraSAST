"""Bounded, local def-use evidence, never a vulnerability verdict.

Uses the shipped FileIR and fact/taxonomy routing. Parameters are potential inputs,
as in semantic.taint; unknown call returns carry their arguments conservatively.
Sanitizers stay on paths (they do not erase connectivity). Facts currently scope
sanitizers by language, not family, so a sanitizer is not a discharge claim.
The flat IR has no branch edges or dominance: no guard is asserted, and branch
assignments are visited in textual order. No interprocedural or alias analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from textwrap import dedent
from typing import Literal

from ..model.specs import taint_specs
from ..semantic.facts import load_facts
from ..semantic.ir import Bind, CallSite, FunctionIR, parse_file
from ..semantic.taint import _call_matches, _sanitizer_for, _source_in
from .excerpt import redact

Role = Literal["source", "step", "sanitizer", "guard", "sink"]
# The renderer uses two spaces; normalization strips the suffix on blank lines.
_NUMBERED = re.compile(r"^\s*(\d+)(?:  (.*))?$")


@dataclass(frozen=True, order=True)
class Step:
    line: int
    role: Role
    code: str


@dataclass(frozen=True)
class Slice:
    steps: tuple[Step, ...] = ()


def function_slice(excerpt_text: str, language: str, family: str) -> Slice | None:
    """Return local paths, an empty slice, or None for an unsupported/unparseable excerpt.

    Numbered excerpts retain their displayed numbers; raw code uses 1-based lines.
    Diffs are never parsed. A truncated/malformed excerpt cannot establish no-flow.
    Nested functions are analysed separately and never share definitions.
    """
    raw = excerpt_text.split("\ndiff:\n", 1)[0].splitlines()
    matches = [_NUMBERED.match(line) for line in raw]
    if any(matches) and not all(matches):
        return None
    numbers = [int(m[1]) if m else i + 1 for i, m in enumerate(matches)]
    lines = [(m[2] or "") if m else line for m, line in zip(matches, raw, strict=True)]
    if len(set(numbers)) != len(numbers):
        return None
    code = dedent("\n".join(lines))
    ir = parse_file("excerpt", code, language)
    if not ir.parse_ok:
        return None
    spec = taint_specs(language=language).get(family)
    if spec is None:
        return Slice()
    shown = redact(lines, language)
    facts = load_facts().for_language(language)

    def step(line: int, role: Role) -> Step:
        return Step(numbers[line - 1], role, shown[line - 1].strip())

    def paths(function: FunctionIR) -> set[Step]:
        states = {name: {step(function.start_line, "source")} for name in function.params}
        found: set[Step] = set()

        def value(text: str, names: tuple[str, ...], constant: bool, line: int, end: int) -> set[Step]:
            if constant:
                return set()
            result = set().union(*(states.get(name, set()) for name in names))
            if _source_in(text, facts):
                result.add(step(line, "source"))
            if result:
                # Keep only sanitizers whose call is inside this expression, not
                # an unrelated call elsewhere on the same source line.
                for call in function.calls:
                    if (
                        call.line >= line
                        and (not end or call.order <= end)
                        and any(
                            re.search(r"(?<![\w$])" + re.escape(name) + r"\s*\(", text) and _call_matches(call.name, name)
                            for name in spec.sanitizers
                        )
                    ):
                        result.add(step(call.line, "sanitizer"))
            return result

        events: list[Bind | CallSite] = [*function.binds, *function.calls]
        # Tree-sitter supplies evaluation ends, including same-line statements.
        # The AST fallback supplies equivalent end-line/column positions.
        events.sort(key=lambda e: (e.order if e.order else e.line, isinstance(e, Bind)))
        for event in events:
            if isinstance(event, Bind):
                inherited = value(event.value_text, event.names, event.is_constant, event.line, event.order)
                states[event.name] = inherited | {step(event.line, "step")} if inherited else set()
                continue
            if not any(_call_matches(event.name, name) for name in spec.sinks):
                continue
            reached: set[Step] = set()
            for text, names, constant in zip(event.arg_texts, event.arg_names, event.arg_is_constant, strict=True):
                reached.update(value(text, names, constant, event.line, event.order))
            if reached:
                if _sanitizer_for(event, facts):
                    reached.add(step(event.line, "sanitizer"))
                found.update(reached | {step(event.line, "sink")})
        return found

    result: set[Step] = set()
    for function in ir.functions:
        result.update(paths(function))
    order = {"source": 0, "step": 1, "sanitizer": 2, "guard": 3, "sink": 4}
    return Slice(tuple(sorted(result, key=lambda s: (s.line, order[s.role]))))


def render_slice(slice_or_none: Slice | None, reason: str) -> str:
    """Fixed framing; reason is the language, never free-form provenance text."""
    prefix = "Data flow inside the function:"
    if slice_or_none is None:
        language = (
            reason
            if reason
            in {
                "python",
                "javascript",
                "typescript",
                "tsx",
                "c",
                "cpp",
                "java",
                "php",
                "go",
                "ruby",
                "rust",
                "csharp",
                "perl",
                "kotlin",
                "swift",
                "scala",
                "lua",
                "groovy",
                "shell",
                "other",
            }
            else "other"
        )
        return f"{prefix} not analysed ({language} is not supported)."
    if not slice_or_none.steps:
        return f"{prefix} no source reaches a sink of this family."
    return prefix + "\n" + "\n".join(f"L{s.line} {s.role}: {s.code}" for s in slice_or_none.steps)
