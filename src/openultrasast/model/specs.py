"""The security vocabularies the model layer arbitrates with (model-grounded-detection, Req 7.2-7.4).

Two kinds of knowledge live here, and they are held differently on purpose.

The **guard vocabulary** is ported verbatim from ``semantic/variants.py``, whose optimisation loop this
feature deleted. Nothing else holds it: it is the closed set of ways a fix discharges a flow, and it tells
the model what a *fixed* twin looks like. Order matters — first match wins.

The **taint and dominance specs** are *derived* from data that survives: the source/sink/sanitizer facts in
``ruleset/semantic`` and the obligated operations and dischargers in ``ruleset/obligations``. Copying them
here would create a second place to update, so this module reads them through the retained loaders and
groups them by family via the taxonomy's CWE map.

Read-only by construction (Req 7.4, the verifier boundary): this module exposes no writer, opens no file for
writing, and holds no mutable module state. An LLM or a future optimiser has nothing here to rewrite.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from ..semantic.facts import SemanticFacts, load_facts
from ..semantic.obligations.facts import ObligationFacts, load_obligation_facts
from .taxonomy import FamilyTaxonomy, load_families

# --- The guard vocabulary (ported verbatim; nothing else holds it) ----------------------------------------

GUARD_KINDS = ("null_test", "bounds_test", "allowlist_test", "auth_check", "parameterized_call", "type_change", "none")

# Closed guard classification over the statements a fix added inside the labeled function.
# Order matters: the first matching kind wins. These classify the *fix*, they never detect.
GUARD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
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


def classify_guard_text(text: str) -> str:
    """The guard kind the given statements express, or ``none`` when no known guard is recognised."""
    for kind, pattern in GUARD_PATTERNS:
        if pattern.search(text):
            return kind
    return "none"


# --- The specs the CPG queries are parameterised by ------------------------------------------------------


@dataclass(frozen=True)
class TaintSpec:
    """What a flow family's source-to-sink-minus-sanitizer query matches on, for one language.

    ``sanitizers`` holds only *cleansing calls* -- a node on the flow path that makes the value safe, such as
    ``ast.literal_eval``. It deliberately excludes every fact that carries a **shape qualifier**, because
    those describe a safe *form of the sink call*, not a call that cleans a value:

        parameterized        ``execute(sql, params)`` binds rather than interpolates
        literal_format_arg   ``printf("literal", x)`` has a constant format string

    Flattening either kind into the sanitizer list is actively wrong: the sink becomes its own sanitizer, so
    every flow through it reports as already-clean and nothing is ever entailed. Both were present in the
    shipped facts (`execute` for Python, the whole printf family for C) and both surfaced on the first live
    Joern run. The names are kept in ``safe_shape_sinks`` so the shape test can be modelled properly in task
    4.2 rather than silently mis-modelled here.
    """

    family: str
    language: str
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    sanitizers: tuple[str, ...]
    safe_shape_sinks: tuple[str, ...] = ()


@dataclass(frozen=True)
class DominanceSpec:
    """What an absence family's guard-dominates-operation query matches on, for one language.

    ``dischargers`` are every token that can evidence a discharge, drawn from four fields of a discharger
    fact and deliberately not from the other two:

        calls, decorators          an explicit guard: ``login_required``, ``check_owner``
        identity_sources           the authenticated context: ``current_user``, ``request.user``
        constraint_params          a field that constrains by identity: ``owner_id``, ``user_id``

    ``request_sources`` and ``permissive_values`` are excluded because they describe the NEGATIVE case -- a
    value that comes from the request discharges nothing, and a permissive literal is the bug rather than the
    guard. Including them would let the absence arbiter read a vulnerability as its own fix.
    """

    family: str
    language: str
    operations: tuple[str, ...]
    dischargers: tuple[str, ...]


def taint_specs(
    *,
    language: str,
    facts: SemanticFacts | None = None,
    taxonomy: FamilyTaxonomy | None = None,
) -> Mapping[str, TaintSpec]:
    """One ``TaintSpec`` per flow family that has a sink in this language, grouped through the taxonomy's CWE map.

    Sources and sanitizers are language-wide: a family does not get its own notion of what untrusted input is,
    and a sanitizer that breaks one flow breaks it whatever the sink's family.
    """
    scoped = (facts if facts is not None else load_facts()).for_language(language)
    families = taxonomy if taxonomy is not None else load_families()
    sources = tuple(sorted({pattern for fact in scoped.sources for pattern in fact.patterns}))
    # A shape qualifier means "this sink is safe in this form", never "this call cleans the value".
    def _is_shape(fact: object) -> bool:
        return bool(getattr(fact, "parameterized", False)) or getattr(fact, "literal_format_arg", None) is not None

    sanitizers = tuple(sorted({call for fact in scoped.sanitizers if not _is_shape(fact) for call in fact.calls}))
    safe_shapes = tuple(sorted({call for fact in scoped.sanitizers if _is_shape(fact) for call in fact.calls}))
    by_family: dict[str, set[str]] = {}
    for sink in scoped.sinks:
        family = families.family_of_cwe(sink.cwe)
        if family is None:
            continue
        by_family.setdefault(family.id, set()).update(sink.calls)
    return {
        family_id: TaintSpec(
            family=family_id,
            language=language,
            sources=sources,
            sinks=tuple(sorted(calls)),
            sanitizers=sanitizers,
            safe_shape_sinks=safe_shapes,
        )
        for family_id, calls in sorted(by_family.items())
    }


def dominance_specs(*, language: str, facts: ObligationFacts | None = None) -> Mapping[str, DominanceSpec]:
    """One ``DominanceSpec`` per absence family for this language.

    The obligation facts are authored for authorization, so every obligated operation routes to
    ``access_control``; the shape generalises when a second absence family is added to the taxonomy.
    """
    scoped = (facts if facts is not None else load_obligation_facts()).for_language(language)
    if not scoped.operations:
        return {}
    operations = tuple(sorted({call for fact in scoped.operations for call in fact.calls}))
    dischargers = tuple(
        sorted(
            {call for fact in scoped.dischargers for call in fact.calls}
            | {decorator for fact in scoped.dischargers for decorator in fact.decorators}
            | {source for fact in scoped.dischargers for source in fact.identity_sources}
            | {param for fact in scoped.dischargers for param in fact.constraint_params}
        )
    )
    return {"access_control": DominanceSpec(family="access_control", language=language, operations=operations, dischargers=dischargers)}


__all__ = [
    "GUARD_KINDS",
    "GUARD_PATTERNS",
    "DominanceSpec",
    "TaintSpec",
    "classify_guard_text",
    "dominance_specs",
    "taint_specs",
]
