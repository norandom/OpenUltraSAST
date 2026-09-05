"""Structural mechanism shapes derived from labeled pairs (corpus-seeded-mechanisms, Req 2).

A shape is the closed, text-free description of how a known vulnerable call looked: the
sink's trailing callee name, its arity, which argument positions carried source-derived
values and of what kind, and the kind of guard the fix added. Shapes are derived from
``FileIR`` (never from regex over code) and compared structurally, so a variant in another
project matches even when every identifier differs. Stdlib plus ``.ir``, ``.facts`` and
``.functions`` only; never imports the overlay, the scorer, or the store.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .facts import SemanticFacts
from .functions import named_ranges_from_ir
from .ir import Bind, CallSite, FileIR, FunctionIR

GUARD_KINDS = ("null_test", "bounds_test", "allowlist_test", "auth_check", "parameterized_call", "type_change", "none")
SOURCE_KINDS = ("fact_source", "parameter", "container_read")
_MAX_BIND_DEPTH = 8

# Closed guard classification over the statements the fix added inside the labeled function.
# Order matters: the first matching kind wins. These classify the *fix*, they never detect.
_GUARD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("parameterized_call", re.compile(r"execute\w*\([^,]+,\s*[\(\[]|prepareStatement\(|\?\s*['\"]?\s*[,)]|\$\d\b|%s['\"]\s*,\s*[\(\[]")),
    (
        "auth_check",
        re.compile(
            r"\b(request\.user|req\.user|current_user|request\.state|session\[|is_authenticated|authoriz|require_auth"
            r"|login_required|verify_token|check_permission|owner_id\s*[!=]=)"
        ),
    ),
    (
        "allowlist_test",
        re.compile(
            r"\bnot in\b|\bin\s*[\(\{\[]|\.includes\(|\.has\(|\bstartswith\(|\bstartsWith\(|\bendswith\(|\bendsWith\("
            r"|re\.(?:match|fullmatch)\(|\.test\(|allow_?list|whitelist|\bALLOWED\b|\bsafe_join\(|secure_filename\("
            r"|\brealpath\(|\bnormpath\(|\bresolve\("
        ),
    ),
    ("bounds_test", re.compile(r"\blen\(|\.length\b|\bsizeof\(|\bstrn?len\(|\bsnprintf\(|\bstrlcpy\(|\bmin\(|\bmax\(|\s(?:<|>|<=|>=)\s")),
    (
        "null_test",
        re.compile(
            r"\bis None\b|\bis not None\b|[!=]= *NULL\b|[!=]==? *null\b|\bnullptr\b|\bif\s*\(\s*!\s*\w|\bif not \w+\s*:"
            r"|\bif\s+\w+\s+is\s+None|\?\?|\?\."
        ),
    ),
    (
        "type_change",
        re.compile(r"\bint\(|\bparseInt\(|\bNumber\(|\(int\)|\(size_t\)|\(unsigned\b|\bstr\(|\.toString\(|\bstatic_cast<|\bBigInt\("),
    ),
)
_CONTAINER_READ = re.compile(
    r"\[[^\]]+\]|\.get\(|\.getParameter\(|\.param\(|\.query\b|\.body\b|\.params\b|\.args\b|\.form\b|\.headers\b|\.cookies\b"
)


@dataclass(frozen=True)
class Shape:
    language: str
    sink_name: str  # trailing callee segment
    arity: int
    source_positions: tuple[int, ...]
    source_kinds: tuple[str, ...]
    guard: str  # GUARD_KINDS
    mechanism: str  # closed vocabulary id from the pair label

    def key(self) -> str:
        """Stable identity of the shape; carries no path, line, or literal."""
        positions = ",".join(str(p) for p in self.source_positions)
        kinds = ",".join(self.source_kinds)
        return f"{self.language}|{self.sink_name}/{self.arity}|pos={positions}|kinds={kinds}|guard={self.guard}|{self.mechanism}"

    def to_dict(self) -> dict[str, object]:
        return {
            "language": self.language,
            "sink_name": self.sink_name,
            "arity": self.arity,
            "source_positions": list(self.source_positions),
            "source_kinds": list(self.source_kinds),
            "guard": self.guard,
            "mechanism": self.mechanism,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> Shape:
        positions = payload.get("source_positions") or []
        kinds = payload.get("source_kinds") or []
        if not isinstance(positions, list) or not isinstance(kinds, list):
            raise ValueError("shape positions and kinds must be lists")
        guard = str(payload.get("guard", "none"))
        if guard not in GUARD_KINDS:
            raise ValueError(f"unknown guard kind {guard!r}")
        return cls(
            language=str(payload.get("language", "")),
            sink_name=str(payload.get("sink_name", "")),
            arity=int(str(payload.get("arity", 0))),
            source_positions=tuple(int(p) for p in positions),
            source_kinds=tuple(str(k) for k in kinds),
            guard=guard,
            mechanism=str(payload.get("mechanism", "other")),
        )


def trailing_name(callee: str) -> str:
    """``os.path.join`` -> ``join``; ``Runtime.getRuntime().exec`` -> ``exec``; keeps the last identifier segment."""
    tail = callee.rsplit(".", 1)[-1].rsplit("::", 1)[-1].rsplit("->", 1)[-1]
    match = re.search(r"[A-Za-z_$][\w$]*\s*$", tail)
    return match.group(0).strip() if match else tail


def derive_shape(
    vuln: FileIR,
    fixed: FileIR,
    *,
    function: str,
    sink: str | None,
    line: int | None,
    mechanism: str,
    facts: SemanticFacts,
    vuln_text: str = "",
    fixed_text: str = "",
) -> Shape | None:
    """The shape of the labeled sink call in ``function`` on the vulnerable side, with the guard the fixed side added.

    None when either side failed to parse, the function or the labeled call site is not found, or no argument of the
    call carries a source (a constant-only call teaches nothing).
    """
    if not vuln.parse_ok or not fixed.parse_ok:
        return None
    target = _function_named(vuln, function, vuln_text)
    if target is None:
        return None
    call = _labeled_call(target, sink, line)
    if call is None:
        return None
    kinds = [_source_kind_of_argument(target, call, index, facts) for index in range(len(call.arg_texts))]
    positions = tuple(index for index, kind in enumerate(kinds) if kind is not None)
    if not positions:
        return None
    guard = classify_guard(vuln, fixed, function=function, vuln_text=vuln_text, fixed_text=fixed_text)
    return Shape(
        language=vuln.language,
        sink_name=trailing_name(call.name),
        arity=len(call.arg_texts),
        source_positions=positions,
        source_kinds=tuple(kind for kind in kinds if kind is not None),
        guard=guard,
        mechanism=mechanism,
    )


def classify_guard(vuln: FileIR, fixed: FileIR, *, function: str, vuln_text: str, fixed_text: str) -> str:
    """Closed guard kind from the statements inside ``function`` that exist only on the fixed side (``none`` when unknown)."""
    before = _function_lines(vuln, function, vuln_text)
    after = _function_lines(fixed, function, fixed_text)
    added = [line for line in after if line not in set(before)]
    for kind, pattern in _GUARD_PATTERNS:
        if any(pattern.search(line) for line in added):
            return kind
    return "none"


def source_kind_of_name(function: FunctionIR, name: str, facts: SemanticFacts, *, before_line: int, depth: int = 0) -> str | None:
    """How ``name`` came to carry attacker data inside ``function``: a fact source, a parameter, or a container read."""
    if depth > _MAX_BIND_DEPTH:
        return None
    bind = _last_bind(function, name, before_line)
    if bind is not None:
        if _source_in(bind.value_text, facts):
            return "fact_source"
        if _CONTAINER_READ.search(bind.value_text):
            return "container_read"
        for inner in bind.names:
            if inner == name:
                continue
            kind = source_kind_of_name(function, inner, facts, before_line=bind.line, depth=depth + 1)
            if kind is not None:
                return kind
    if name in function.params:
        return "parameter"
    return None


def _source_kind_of_argument(function: FunctionIR, call: CallSite, index: int, facts: SemanticFacts) -> str | None:
    text = call.arg_texts[index]
    if _source_in(text, facts):
        return "fact_source"
    if call.arg_is_constant[index] and not call.arg_names[index]:
        return None
    if _CONTAINER_READ.search(text) and any(name in function.params for name in call.arg_names[index]):
        return "container_read"
    found: list[str] = []
    for name in call.arg_names[index]:
        kind = source_kind_of_name(function, name, facts, before_line=call.line + 1)
        if kind is not None:
            found.append(kind)
    for preferred in SOURCE_KINDS:
        if preferred in found:
            return preferred
    return None


def _source_in(text: str, facts: SemanticFacts) -> bool:
    return any(pattern and pattern in text for source in facts.sources for pattern in source.patterns)


def _last_bind(function: FunctionIR, name: str, before_line: int) -> Bind | None:
    candidates = [bind for bind in function.binds if bind.name == name and bind.line < before_line]
    return max(candidates, key=lambda bind: bind.line) if candidates else None


def _labeled_call(function: FunctionIR, sink: str | None, line: int | None) -> CallSite | None:
    if line is not None:
        by_line = [call for call in function.calls if call.line == line]
        if by_line:
            return by_line[0]
    if sink:
        wanted = trailing_name(sink)
        for call in function.calls:
            if trailing_name(call.name) == wanted:
                return call
    return None


def _function_named(ir: FileIR, function: str, text: str) -> FunctionIR | None:
    for item in ir.functions:
        if item.name == function:
            return item
    if text:  # labels use declarator names; the parser may name the function differently (or <anon>)
        for name, start, _end in named_ranges_from_ir(ir, text):
            if name == function:
                for item in ir.functions:
                    if item.start_line == start:
                        return item
    return None


def _function_lines(ir: FileIR, function: str, text: str) -> list[str]:
    target = _function_named(ir, function, text)
    if target is None or not text:
        return []
    lines = text.splitlines()
    body = lines[target.start_line - 1 : target.end_line]
    return [line.strip() for line in body if line.strip()]


def shapes_by_sink(shapes: Sequence[Shape]) -> dict[tuple[str, str], list[Shape]]:
    """Index for matching: (language, sink_name) -> shapes."""
    index: dict[tuple[str, str], list[Shape]] = {}
    for shape in shapes:
        index.setdefault((shape.language, shape.sink_name), []).append(shape)
    return index
