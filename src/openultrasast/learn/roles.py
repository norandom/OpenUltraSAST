"""Per-repository roles, inferred rather than written down (learned-decision-engine Req 8.1; design section 2).

Hand-written knowledge stops at the language: superglobals, built-ins, process execution, raw database drivers,
deserialisers (``ruleset/semantic/<lang>.toml`` entries without a ``framework``/``library`` tag). A framework's or an
application's own roles -- its query helpers, request accessors, escaping functions -- are inferred per repository
from its own source text, with no framework table:

- *Wrapper inference* (this module, deterministic, no model). A function whose parameter reaches, within its body, a
  call already in the role set becomes a derived **sink** (or **sanitizer**, when it also returns the cleaned value)
  of the same operation kind, at ``depth + 1``. A function that returns a source's value becomes a derived
  **source**. The role set starts from the language-level entries (``priors="off"`` by default; framework priors are
  optional) and grows over the call index to :data:`MAX_DEPTH`. Dependency source present in the checkout
  (``vendor/``, ``node_modules/``, ``site-packages``) is read the same way, so ``$wpdb->query`` becomes a sink because
  a vendored ``wpdb::query`` reaches ``mysqli_query``, not because a table says so.
- *Model roles* (the plane task :mod:`..plane.tasks.roles`): read here by :func:`from_model_roles`.

Both give :class:`Role` rows with an ``origin`` (:data:`.schema.ORIGINS`). They reach the engine through
:func:`vocabulary_overlay` -- a :class:`~..semantic.facts.SemanticFacts` of the language-level entries plus the
inferred ones, the shape ``taint_specs`` already takes -- and the feature record through the ``roles`` and
``model_sinks`` instruments (:func:`..learn.features.roles_part`). Roles are signals: a derived sink alone is never a
finding. A role's ``path``/``function`` are provenance, never features.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..plane.tasks.repo_facts import DECLARATION, GLOBAL, KEYWORDS, _declared_name, product_files
from ..preprocess import detect_language
from ..ruleset.frameworks import Priors, normalize_priors, tag_of
from ..semantic.facts import _LANGUAGE_ALIASES, FactLoadError, SanitizerFact, SemanticFacts, SinkFact, SourceFact, load_facts, with_priors
from .schema import OPERATIONS, ORIGINS, SOURCE_KINDS

ROLE_KINDS = ("sink", "source", "sanitizer")
MODEL_ROLE_KINDS = ("sink", "source", "sanitizer", "guard", "dispatch")
MAX_DEPTH = 3
MIN_NAME = 3  # shorter names are too generic to become a vocabulary entry
VERSION = "wrapper-v1"
# The operation a sink performs, by the CWE its semantic entry binds (a closed table; anything else is `other`).
CWE_OPERATION = {
    "CWE-89": "sql", "CWE-943": "sql", "CWE-78": "command", "CWE-77": "command", "CWE-94": "code_eval", "CWE-95": "code_eval",
    "CWE-502": "deserialize", "CWE-22": "file_path", "CWE-98": "file_inclusion", "CWE-918": "outbound_request",
    "CWE-601": "redirect", "CWE-79": "html_output",
}  # fmt: skip
# The CWE an inferred sink of an operation is filed under in the overlay (so the taxonomy groups it by family).
OPERATION_CWE = {
    "sql": "CWE-89", "command": "CWE-78", "code_eval": "CWE-95", "deserialize": "CWE-502", "file_path": "CWE-22",
    "file_inclusion": "CWE-98", "outbound_request": "CWE-918", "redirect": "CWE-601", "html_output": "CWE-79",
}  # fmt: skip
# A semantic source entry's id mapped to its kind; an unlisted id is `other`.
SOURCE_KIND = {
    "request": "request", "django-request": "request", "req": "request", "node-request": "request", "servlet": "request",
    "server": "server", "raw_body": "raw_body", "argv": "argv_stdin", "stdin": "argv_stdin", "input": "argv_stdin",
}  # fmt: skip
DEPENDENCY_DIRS = frozenset({"vendor", "node_modules", "site-packages", "bower_components", "third_party"})
MAX_DEPENDENCY_FILES = 5000
MAX_FILE_BYTES = 1_000_000
_NOT_PARAMS = frozenset({"self", "cls", "this", "$this"})
_IDENT = re.compile(r"\$?[A-Za-z_][\w$]*")
_ASSIGN = re.compile(r"(\$?[A-Za-z_][\w$]*)\s*(?:\[[^\]]*\])?\s*(?:\.=|\+=|:=|=)(?![=>~])\s*(.+)")
_RETURN = re.compile(r"(?<![\w$])return\b(.*)")


@dataclass(frozen=True, order=True)
class Role:
    """One vocabulary entry: ``name`` is the call (or, for a language-level source, the pattern) that plays ``kind``."""

    language: str
    kind: str  # ROLE_KINDS, or MODEL_ROLE_KINDS for a model role
    name: str
    operation: str  # OPERATIONS for a sink/sanitizer (`other` when unknown); SOURCE_KINDS for a source
    origin: str  # ORIGINS
    depth: int = 0  # 0: written down or said by the model; n: wraps a role of depth n - 1
    via: str = ""  # the role it wraps (provenance)
    path: str = ""  # where it is defined (provenance, never a feature)
    function: str = ""
    dependency: bool = False  # defined in dependency source in the checkout


@dataclass(frozen=True)
class RoleSet:
    """Inferred roles of one repository (language-level entries are not repeated here), and the model's gaps."""

    roles: tuple[Role, ...] = ()
    unclassified: tuple[str, ...] = ()  # paths with a chunk the model did not classify: never "no roles"
    sources: tuple[str, ...] = field(default=())  # which role sources ran: `inferred_wrapper`, `model_role`

    def of(self, language: str, kind: str) -> tuple[Role, ...]:
        key = language_key(language)
        return tuple(r for r in self.roles if language_key(r.language) == key and r.kind == kind)

    def merge(self, other: RoleSet) -> RoleSet:
        seen = {(r.language, r.kind, r.name, r.origin) for r in self.roles}
        extra = tuple(r for r in other.roles if (r.language, r.kind, r.name, r.origin) not in seen)
        return RoleSet(
            tuple(sorted(self.roles + extra)),
            tuple(sorted(set(self.unclassified) | set(other.unclassified))),
            tuple(sorted(set(self.sources) | set(other.sources))),
        )

    def counts(self) -> dict[str, Any]:
        """Roles per origin and kind, and inferred wrappers per depth (no names)."""
        out: dict[str, Any] = {"total": len(self.roles), "by_origin": {}, "by_depth": {}, "dependency": 0}
        for role in self.roles:
            kinds = out["by_origin"].setdefault(role.origin, {})
            kinds[role.kind] = kinds.get(role.kind, 0) + 1
            if role.origin == "inferred_wrapper":
                out["by_depth"][str(role.depth)] = out["by_depth"].get(str(role.depth), 0) + 1
            out["dependency"] += int(role.dependency)
        return out

    def to_json(self) -> dict[str, Any]:
        return {"roles": [asdict(r) for r in self.roles], "unclassified": list(self.unclassified), "sources": list(self.sources)}

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> RoleSet:
        roles = tuple(
            sorted(Role(**{k: v for k, v in row.items() if k in Role.__dataclass_fields__}) for row in payload.get("roles") or ())
        )
        return cls(roles, tuple(payload.get("unclassified") or ()), tuple(payload.get("sources") or ()))


def language_key(language: str) -> str:
    """The semantic-facts language of a detected language (TypeScript shares JavaScript's entries)."""
    return _LANGUAGE_ALIASES.get(language, language)


def _facts(language: str, priors: Priors, facts: SemanticFacts | None) -> SemanticFacts:
    chosen = normalize_priors(priors)
    try:
        loaded = with_priors(facts, chosen) if facts is not None else load_facts(priors=chosen)
    except FactLoadError:
        return SemanticFacts(version="", sources=(), sinks=(), sanitizers=())
    return loaded.for_language(language)


def base_roles(language: str, *, priors: Priors = "off", facts: SemanticFacts | None = None) -> tuple[Role, ...]:
    """The written-down roles of ``language``: language-level entries, plus the priors ``priors`` keeps (origin
    ``prior``). Shape-qualified and guard sanitizers are not cleansing calls and are left out."""
    scoped = _facts(language, priors, facts)
    roles: list[Role] = []
    for sink in scoped.sinks:
        origin = "prior" if tag_of(sink) else "language"
        roles += [Role(language, "sink", call, CWE_OPERATION.get(sink.cwe, "other"), origin) for call in sink.calls]
    for san in scoped.sanitizers:
        if san.parameterized or san.literal_format_arg is not None or san.guard:
            continue
        roles += [Role(language, "sanitizer", call, "other", "prior" if tag_of(san) else "language") for call in san.calls]
    for src in scoped.sources:
        kind = SOURCE_KIND.get(src.id, "other")
        roles += [Role(language, "source", pattern, kind, "prior" if tag_of(src) else "language") for pattern in src.patterns]
    return tuple(dict.fromkeys(roles))


# --- functions of a file ---------------------------------------------------------------------------------------------


@dataclass
class Function:
    """One declared function: its parameters and body lines (the declaration line first)."""

    path: str
    name: str
    language: str
    params: tuple[str, ...]
    body: list[str]
    dependency: bool = False
    _tainted: set[str] | None = None

    def tainted(self) -> set[str]:
        """The parameters and the local names assigned from them (two passes, in body order)."""
        if self._tainted is None:
            tainted = set(self.params)
            for _ in range(2):
                for line in self.body[1:]:
                    match = _ASSIGN.search(line)
                    if match and match.group(1) not in tainted and mentions(match.group(2), tainted):
                        tainted.add(match.group(1))
            self._tainted = tainted
        return self._tainted


def mentions(text: str, names: Iterable[str]) -> bool:
    """Whether ``text`` names any of ``names`` as a whole token."""
    pattern = _token_pattern(frozenset(names))
    return pattern is not None and pattern.search(text) is not None


@lru_cache(maxsize=4096)
def _token_pattern(names: frozenset[str]) -> re.Pattern[str] | None:
    wanted = sorted(names, key=len, reverse=True)
    if not wanted:
        return None
    return re.compile(r"(?<![\w$])(?:" + "|".join(re.escape(n) for n in wanted) + r")(?![\w])")


def _balanced(text: str, start: int) -> str:
    """The text inside the parenthesis opening at ``text[start]`` (to the end of ``text`` when unbalanced)."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    return text[start + 1 :]


def _split_top(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def parameters(declaration: str, name: str, language: str) -> tuple[str, ...]:
    """Parameter names of a declaration (its line and a few after): defaults, types, annotations and receivers
    stripped; ``self``/``cls``/``this`` dropped."""
    at = declaration.find(name)
    open_at = declaration.find("(", at + len(name) if at >= 0 else 0)
    if open_at < 0:
        return ()
    names: list[str] = []
    for piece in _split_top(_balanced(declaration, open_at)):
        piece = re.sub(r"@\w+(\([^)]*\))?\s*", "", piece.split("=", 1)[0]).strip()
        if language == "php":
            found = re.findall(r"\$\w+", piece)[:1]
        elif piece[:1] in "{[":
            found = _IDENT.findall(piece)
        elif language == "java":
            found = _IDENT.findall(piece.replace("...", " "))[-1:]
        elif language == "go":
            found = _IDENT.findall(piece)[:1]
        else:
            found = _IDENT.findall(piece.split(":", 1)[0].lstrip("*&. "))[:1]
        names += [n for n in found if n not in _NOT_PARAMS]
    return tuple(dict.fromkeys(names))


def functions_of(path: str, lines: Sequence[str], language: str, *, dependency: bool = False) -> list[Function]:
    """The functions ``lines`` declares, each with its body (lines whose enclosing declaration it is)."""
    pattern = DECLARATION.get(language)
    if pattern is None:
        return []
    starts: dict[str, int] = {}
    bodies: dict[str, list[str]] = {}
    current = GLOBAL
    stack: list[tuple[int, str]] = []  # Python: the open (indent, name) declarations, innermost last
    for index, line in enumerate(lines):
        declared = _declared_name(pattern, line)
        if declared and declared not in starts:
            starts[declared] = index
        if language == "python":
            stripped = line.lstrip(" \t")
            if stripped and not stripped.startswith("#"):
                indent = len(line) - len(stripped)
                while stack and indent <= stack[-1][0]:
                    stack.pop()
                if declared:
                    stack.append((indent, declared))
            owner = stack[-1][1] if stack else GLOBAL
        else:
            current = declared or current
            owner = current
        if owner != GLOBAL:
            bodies.setdefault(owner, []).append(line)
    out = []
    for name, start in sorted(starts.items(), key=lambda item: item[1]):
        declaration = " ".join(lines[start : start + 8])
        out.append(Function(path, name, language, parameters(declaration, name, language), bodies.get(name, []), dependency))
    return out


# --- wrapper inference -----------------------------------------------------------------------------------------------


def _call_pattern(names: Iterable[str]) -> re.Pattern[str] | None:
    wanted = sorted({n for n in names if n}, key=len, reverse=True)
    if not wanted:
        return None
    return re.compile(r"(?<![\w$])(" + "|".join(re.escape(n) for n in wanted) + r")\s*\(")


def _calls(function: Function, pattern: re.Pattern[str]) -> Iterable[tuple[str, str]]:
    """(called name, argument text) of every matching call in the body; the declaration line is skipped."""
    for index, line in enumerate(function.body[1:], start=1):
        for match in pattern.finditer(line):
            if match.group(1) == function.name:
                continue
            text = " ".join([line[match.end() - 1 :], *function.body[index + 1 : index + 4]])
            yield match.group(1), _balanced(text, 0)


def _returned(function: Function, test: Any) -> bool:
    """Whether a ``return`` hands back a value ``test`` accepts, directly or through a local assigned from one."""
    carried: set[str] = set()
    for line in function.body[1:]:
        match = _ASSIGN.search(line)
        if match and (test(match.group(2)) or mentions(match.group(2), carried)):
            carried.add(match.group(1))
    for line in function.body[1:]:
        match = _RETURN.search(line)
        if match and match.group(1).strip() and (test(match.group(1)) or mentions(match.group(1), carried)):
            return True
    return False


class _Frontier:
    """The roles of one derivation round, with their call patterns compiled once."""

    def __init__(self, roles: Sequence[Role]) -> None:
        self.by_name = {r.name: r for r in roles}
        self.sinks = _call_pattern(r.name for r in roles if r.kind == "sink")
        self.sanitizers = _call_pattern(r.name for r in roles if r.kind == "sanitizer")
        self.sources = [r for r in roles if r.kind == "source"]
        self.source_calls = _call_pattern(r.name for r in self.sources if r.origin in ("inferred_wrapper", "model_role"))
        self.source_patterns = [r for r in self.sources if r.origin not in ("inferred_wrapper", "model_role")]

    def source_in(self, text: str) -> Role | None:
        hit = next((r for r in self.source_patterns if r.name in text), None)
        if hit is None and self.source_calls is not None and (match := self.source_calls.search(text)):
            hit = self.by_name.get(match.group(1))
        return hit


def _derive(function: Function, frontier: _Frontier, depth: int) -> Role | None:
    """The role ``function`` plays by wrapping a role of ``frontier``, or None. Sink before sanitizer before source."""
    tainted = function.tainted() if function.params else set()
    if tainted and frontier.sinks is not None:
        for called, args in _calls(function, frontier.sinks):
            if mentions(args, tainted):
                return _wrapper(function, "sink", frontier.by_name[called], depth)
    if tainted and frontier.sanitizers is not None:
        for called, args in _calls(function, frontier.sanitizers):
            if mentions(args, tainted) and _returned(function, lambda text, c=called: re.search(re.escape(c) + r"\s*\(", text)):
                return _wrapper(function, "sanitizer", frontier.by_name[called], depth)
    if frontier.sources and _returned(function, frontier.source_in):
        return _wrapper(function, "source", frontier.source_in(" ".join(function.body[1:])) or frontier.sources[0], depth)
    return None


def _wrapper(function: Function, kind: str, role: Role, depth: int) -> Role:
    return Role(
        function.language, kind, function.name, role.operation, "inferred_wrapper", depth, role.name, function.path, function.name,
        function.dependency,
    )  # fmt: skip


def infer_wrappers(
    functions: Sequence[Function], *, priors: Priors = "off", facts: SemanticFacts | None = None, max_depth: int = MAX_DEPTH
) -> RoleSet:
    """Derived roles over ``functions``, to ``max_depth``. Round ``d`` looks only at the roles found in round
    ``d - 1`` (round 1: the written-down ones), so a function's depth is the shortest wrapping chain to a
    language-level role. A name already in the role set is never re-derived.

    A name the repository declares more than once is ambiguous: text cannot tell which definition a call reaches,
    and a generic method name (``get``, ``send``) would otherwise turn every call of it into a sink. Such a name
    becomes a role only when **every** definition of it derives the same kind (the first by path is kept)."""
    derived: list[Role] = []
    by_language: dict[str, list[Function]] = {}
    for function in sorted(functions, key=lambda f: (f.path, f.name)):
        if len(function.name) >= MIN_NAME and function.name not in KEYWORDS:
            by_language.setdefault(function.language, []).append(function)
    for language, members in sorted(by_language.items()):
        definitions = Counter(f.name for f in members)
        frontier: list[Role] = list(base_roles(language, priors=priors, facts=facts))
        claimed = {(r.kind, r.name) for r in frontier}
        partial: dict[tuple[str, str], dict[str, Role]] = {}
        for depth in range(1, max_depth + 1):
            found: list[Role] = []
            prepared = _Frontier(frontier)
            for function in members:
                role = _derive(function, prepared, depth)
                if role is None or (role.kind, role.name) in claimed:
                    continue
                seen = partial.setdefault((role.kind, role.name), {})
                seen.setdefault(role.path, role)
                if len(seen) >= definitions[role.name]:
                    claimed.add((role.kind, role.name))
                    first = seen[min(seen)]
                    found.append(replace(first, depth=depth) if first.depth != depth else first)
            if not found:
                break
            derived += found
            frontier = found
    return RoleSet(tuple(sorted(derived)), (), ("inferred_wrapper",))


def _read(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def dependency_files(root: Path, cap: int = MAX_DEPENDENCY_FILES) -> list[Path]:
    """Source files under dependency directories in the checkout (``vendor/``, ``node_modules/``, ...), sorted, capped."""
    files: list[Path] = []
    for base in sorted(p for p in Path(root).rglob("*") if p.is_dir() and p.name in DEPENDENCY_DIRS and not p.is_symlink()):
        if any(parent.name in DEPENDENCY_DIRS for parent in base.parents if parent != Path(root)):
            continue  # nested under another dependency directory: already walked
        for path in sorted(base.rglob("*")):
            if len(files) >= cap:
                return files
            if path.is_file() and not path.is_symlink() and detect_language(path) in DECLARATION and path.stat().st_size <= MAX_FILE_BYTES:
                files.append(path)
    return files


def infer_for_checkout(root: Path, *, priors: Priors = "off", dependencies: bool = True, max_depth: int = MAX_DEPTH) -> RoleSet:
    """Wrapper inference over a checkout's product files and, when present, its dependency source."""
    root = Path(root)
    functions: list[Function] = []
    for path in product_files(root):
        functions += functions_of(path.relative_to(root).as_posix(), _read(path), detect_language(path))
    for path in dependency_files(root) if dependencies else []:
        functions += functions_of(path.relative_to(root).as_posix(), _read(path), detect_language(path), dependency=True)
    return infer_wrappers(functions, priors=priors, max_depth=max_depth)


# --- model roles and the overlay -------------------------------------------------------------------------------------


def from_model_roles(payload: Mapping[str, Any]) -> RoleSet:
    """The plane task ``roles``' ``roles.json`` as a :class:`RoleSet` (origin ``model_role``). A sink/sanitizer/guard
    role's ``call`` is the vocabulary entry; a source's ``call`` is the expression that reads it."""
    roles: list[Role] = []
    for row in payload.get("roles") or ():
        kind, call, path = str(row.get("role") or ""), str(row.get("call") or "").strip(), str(row.get("path") or "")
        if kind not in MODEL_ROLE_KINDS or not call:
            continue
        name = re.split(r"\s*\(", call, maxsplit=1)[0].strip()
        vocabulary = SOURCE_KINDS if kind == "source" else OPERATIONS
        operation = str(row.get("operation") or "other")
        roles.append(
            Role(
                detect_language(Path(path)), kind, name or call, operation if operation in vocabulary else "other", "model_role",
                0, "", path, str(row.get("function") or GLOBAL),
            )
        )  # fmt: skip
    return RoleSet(tuple(sorted(set(roles))), tuple(sorted(set(payload.get("unclassified_paths") or ()))), ("model_role",))


def vocabulary_overlay(roles: RoleSet, language: str, *, priors: Priors = "off", facts: SemanticFacts | None = None) -> SemanticFacts:
    """The engine's vocabulary for one repository and language: the written-down entries ``priors`` keeps, plus the
    inferred roles as entries whose id names their origin (``inferred_wrapper:sql``, ``model_role:sanitizer``, ...).
    A sink of an operation with no CWE (``other``) stays a signal and is not added."""
    scoped = _facts(language, priors, facts)
    key = language_key(language)
    have_sinks = {c for s in scoped.sinks for c in s.calls}
    have_sans = {c for s in scoped.sanitizers for c in s.calls}
    have_sources = {p for s in scoped.sources for p in s.patterns}
    sinks: dict[tuple[str, str], set[str]] = {}
    sanitizers: dict[tuple[str, bool], set[str]] = {}
    sources: dict[str, set[str]] = {}
    for role in roles.of(language, "sink"):
        if role.operation in OPERATION_CWE and role.name not in have_sinks:
            sinks.setdefault((role.origin, role.operation), set()).add(role.name)
    for kind in ("sanitizer", "guard"):
        for role in roles.of(language, kind):
            if role.name not in have_sans:
                sanitizers.setdefault((role.origin, kind == "guard"), set()).add(role.name)
    for role in roles.of(language, "source"):
        pattern = role.name if role.origin == "model_role" else f"{role.name}("
        if pattern not in have_sources:
            sources.setdefault(role.origin, set()).add(pattern)
    return SemanticFacts(
        version=f"{scoped.version}+{VERSION}",
        sources=scoped.sources + tuple(SourceFact(f"{o}:source", tuple(sorted(p)), key) for o, p in sorted(sources.items())),
        sinks=scoped.sinks
        + tuple(SinkFact(f"{o}:{op}", OPERATION_CWE[op], tuple(sorted(c)), (), key) for (o, op), c in sorted(sinks.items())),
        sanitizers=scoped.sanitizers
        + tuple(
            SanitizerFact(f"{o}:{'guard' if g else 'sanitizer'}", tuple(sorted(c)), key, guard=g)
            for (o, g), c in sorted(sanitizers.items())
        ),
        dispatches=scoped.dispatches,
        layouts=scoped.layouts,
    )


def origin_of(entry_id: str, tagged: bool) -> str:
    """The :data:`.schema.ORIGINS` value of a semantic entry: ``prior`` when tagged, the overlay's id prefix, else
    ``language``."""
    if tagged:
        return "prior"
    prefix = entry_id.split(":", 1)[0]
    return prefix if prefix in ORIGINS and ":" in entry_id else "language"


def body_roles(
    function: Function | None, roles: RoleSet, language: str, *, priors: Priors = "off", facts: SemanticFacts | None = None
) -> tuple[float | None, bool]:
    """(sink confidence, source in function) of one function's body: the confidence of the strongest sink role it
    calls -- 1.0 for a written-down entry, ``1 / (depth + 1)`` for a wrapper, 0.5 for a model role -- ``None``
    when it calls none; whether it reads a source (a pattern, or a call of a derived source)."""
    if function is None:
        return None, False
    written = base_roles(language, priors=priors, facts=facts)
    sink_roles = [r for r in written if r.kind == "sink"] + list(roles.of(language, "sink"))
    confidence: float | None = None
    pattern = _call_pattern(r.name for r in sink_roles)
    if pattern is not None:
        best = {r.name: _confidence(r) for r in sorted(sink_roles, key=_confidence)}
        for called, _ in _calls(function, pattern):
            confidence = max(confidence or 0.0, best[called])
    text = "\n".join(function.body[1:])
    source_patterns = [r.name for r in written if r.kind == "source"]
    derived_sources = _call_pattern(r.name for r in roles.of(language, "source") if r.origin != "model_role")
    model_sources = [r.name for r in roles.of(language, "source") if r.origin == "model_role"]
    source = any(p in text for p in source_patterns + model_sources) or bool(derived_sources and derived_sources.search(text))
    return confidence, source


def _confidence(role: Role) -> float:
    if role.origin in ("language", "prior"):
        return 1.0
    if role.origin == "model_role":
        return 0.5
    return round(1.0 / (role.depth + 1), 6)


def load_roles(path: Path) -> RoleSet:
    return RoleSet.from_json(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = [
    "CWE_OPERATION", "DEPENDENCY_DIRS", "MAX_DEPTH", "MODEL_ROLE_KINDS", "OPERATION_CWE", "ROLE_KINDS", "SOURCE_KIND", "VERSION",
    "Function", "Role", "RoleSet", "base_roles", "body_roles", "dependency_files", "from_model_roles", "functions_of",
    "infer_for_checkout", "infer_wrappers", "language_key", "load_roles", "mentions", "origin_of", "parameters",
    "vocabulary_overlay",
]  # fmt: skip
