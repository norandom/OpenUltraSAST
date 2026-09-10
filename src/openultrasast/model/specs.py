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
from dataclasses import dataclass, field

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


# Buffer-overflow classes: the danger is a length, so a bound that dominates the sink discharges it. Only
# CWE-121 is in the fact tables today, and it is C-only -- naming the family keeps a later fact from having
# to remember this rule exists.
OVERFLOW_CWES = frozenset(
    {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-126", "CWE-127", "CWE-787", "CWE-788", "CWE-805", "CWE-806"}
)


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
    # Sinks whose danger is a LENGTH, and which a bound that dominates them therefore discharges. Derived
    # from the sink fact's own CWE rather than asserted here: CWE-121 is a stack buffer overflow, and a
    # `strcpy` a `len > 250` check governs is not the same claim as one nothing governs. A sanitizer list
    # cannot express this -- `strlen` appears in the guarded and unguarded case alike -- which is why the
    # discharge is a guard and not a call.
    bounded_sinks: tuple[str, ...] = ()
    safe_shape_sinks: tuple[str, ...] = ()
    # The calls that read a value back out of a string-keyed registry (`apply_filters`, `do_action`). Facts,
    # not constants, so a second framework is a row in a TOML rather than an edit to the query.
    dispatch_apply: tuple[str, ...] = ()


@dataclass(frozen=True)
class DominanceSpec:
    """What an absence family's guard-dominates-operation query matches on, for one language.

    ``dischargers`` are every token that can evidence a discharge, drawn from four fields of a discharger
    fact and deliberately not from the other two:

        calls, decorators          an explicit guard: ``login_required``, ``check_owner``
        identity_sources           the authenticated context: ``current_user``, ``request.user``

    Three fields are deliberately excluded, and each for a different reason:

        constraint_params          NOT a discharge on its own. A field named ``user_id`` is what an IDOR is
                                   *made of* -- ``filter_by(id=user_id)`` with ``user_id`` off the request is
                                   the bug, not the fix. The original checker only counted a constraint whose
                                   value's provenance was the authenticated context, so the param name alone
                                   evidences nothing and treating it as a guard silences the whole family.
        request_sources            a value from the request discharges nothing, by definition.
        permissive_values          a permissive literal is the bug, not the guard.

    ``dischargers`` is the flat union, kept because a caller may not care which kind discharged what.
    ``requirements`` and ``dischargers_by_kind`` carry the relation the facts actually state: an operation
    names the obligation KINDS that would discharge it, and only a discharger of one of those kinds counts.

    Flattening that relation away was a false-negative engine. `orm-read` requires an ``identity_constraint``
    or an ``ownership_check``; `token_validator` is a ``path_guard``. Pooled together, authenticating the
    caller discharged an object-level obligation -- so a handler that authenticates and then looks the
    record up by a PATH parameter read as fully guarded. That is the shape of VAmPI's broken object-level
    authorization, and of most real IDORs.
    """

    family: str
    language: str
    operations: tuple[str, ...]
    dischargers: tuple[str, ...]
    requirements: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    dischargers_by_kind: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class ConfigSpec:
    """What a configuration family's constant-abstraction query matches on, for one language.

    A config bug has no flow and no guard: ``CORS(app, origins="*")`` is dangerous because of the value it is
    *set to*, not because anything reaches it. So the arbiter evaluates the argument against a closed
    permissive set — the third form beside taint reachability and guard dominance.
    """

    family: str
    language: str
    settings: tuple[str, ...]
    permissive: tuple[str, ...]
    # CWE-326/327. A weak algorithm is a different abstraction from a permissive flag: the danger is the
    # algorithm NAMED, not a setting left open. The data has been on the sink facts (`weak_literals`) since
    # before this feature and nothing read it.
    weak_algorithms: tuple[str, ...] = ()


def config_specs(
    *, language: str, facts: ObligationFacts | None = None, flow_facts: SemanticFacts | None = None
) -> Mapping[str, ConfigSpec]:
    """One ``ConfigSpec`` per configuration family, from the obligation facts' security-setting operations.

    ``permissive_values`` on a ``non_permissive_value`` discharger is the closed set of literals that leave a
    setting open — the one place in the facts where a value, rather than a call, is the evidence.
    """
    scoped = (facts if facts is not None else load_obligation_facts()).for_language(language)
    settings = tuple(sorted({call for fact in scoped.operations if fact.kind == "security_setting" for call in fact.calls}))
    permissive = tuple(sorted({value for fact in scoped.dischargers for value in fact.permissive_values}))
    # A sink carrying `weak_literals` names an algorithm choice, and the call that takes it is itself a
    # security setting: `hashlib.new("md5")` is dangerous because of the string, exactly as CORS is because
    # of the "*". Reading them here is what wires the second of config_secrets' three abstractions.
    flow = (flow_facts if flow_facts is not None else load_facts()).for_language(language)
    weak = tuple(sorted({literal for sink in flow.sinks for literal in sink.weak_literals}))
    weak_calls = tuple(sorted({call for sink in flow.sinks if sink.weak_literals for call in sink.calls}))
    if not settings or not permissive:
        return {}
    return {
        "config_secrets": ConfigSpec(
            family="config_secrets",
            language=language,
            settings=tuple(sorted(set(settings) | set(weak_calls))),
            permissive=permissive,
            weak_algorithms=weak,
        )
    }


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

    dispatch_apply = tuple(sorted({call for fact in scoped.dispatches for call in fact.apply}))
    sanitizers = tuple(sorted({call for fact in scoped.sanitizers if not _is_shape(fact) for call in fact.calls}))
    safe_shapes = tuple(sorted({call for fact in scoped.sanitizers if _is_shape(fact) for call in fact.calls}))
    by_family: dict[str, set[str]] = {}
    bounded: dict[str, set[str]] = {}
    for sink in scoped.sinks:
        family = families.family_of_cwe(sink.cwe)
        if family is None:
            continue
        by_family.setdefault(family.id, set()).update(sink.calls)
        # A sink whose CWE is a buffer-overflow class is dischargeable by a bound that dominates it. The CWE
        # is on the fact already, so which sinks these are is read from the data rather than declared here.
        if sink.cwe in OVERFLOW_CWES:
            bounded.setdefault(family.id, set()).update(sink.calls)
    return {
        family_id: TaintSpec(
            family=family_id,
            language=language,
            sources=sources,
            sinks=tuple(sorted(calls)),
            sanitizers=sanitizers,
            bounded_sinks=tuple(sorted(bounded.get(family_id, ()))),
            safe_shape_sinks=safe_shapes,
            dispatch_apply=dispatch_apply,
        )
        for family_id, calls in sorted(by_family.items())
    }


def dominance_specs(*, language: str, facts: ObligationFacts | None = None) -> Mapping[str, DominanceSpec]:
    """One ``DominanceSpec`` per absence family for this language.

    Not every obligation fact is an authorization one, and taking them all was wrong in both directions.

    * ``security_setting`` operations are configuration: a permissive CORS origin or a debug flag is
      discharged by a VALUE, which is what ``config_specs`` already claims them for and what this arbiter
      cannot decide. Pooled in here they made `app.run(...)` an operation requiring an authorization guard,
      and put thirteen tokens in both the operation and discharger lists -- an obligation that is its own
      discharge, the same shape as the taint sink that used to sanitize itself.
    * ``validated_input`` dischargers are schema checks. `jsonschema.validate` does not establish who the
      caller is, and no operation in the table requires it; counting it as a guard marked handlers with no
      authorization check at all as guarded.

    So both sides are filtered by kind, and the filter is derived from the facts' own ``requires`` relation
    rather than a list maintained here.
    """
    scoped = (facts if facts is not None else load_obligation_facts()).for_language(language)
    if not scoped.operations:
        return {}
    guarded = tuple(fact for fact in scoped.operations if fact.kind != "security_setting")
    if not guarded:
        return {}
    # What the retained operations actually ask for. A discharger of any other kind discharges nothing here.
    required = {kind for fact in guarded for kind in fact.requires}
    dischargers_for = tuple(fact for fact in scoped.dischargers if fact.kind in required)
    operations = tuple(sorted({call for fact in guarded for call in fact.calls}))
    dischargers = tuple(
        sorted(
            {call for fact in dischargers_for for call in fact.calls}
            | {decorator for fact in dischargers_for for decorator in fact.decorators}
            | {source for fact in dischargers_for for source in fact.identity_sources}
        )
    )
    if not operations or not dischargers:
        return {}
    # The relation the facts state, kept rather than flattened: which obligation kinds each operation call
    # would accept as a discharge, and which tokens evidence each kind.
    requirements = {call: tuple(sorted(set(fact.requires))) for fact in guarded for call in fact.calls}
    by_kind: dict[str, tuple[str, ...]] = {}
    for fact in dischargers_for:
        tokens = set(fact.calls) | set(fact.decorators) | set(fact.identity_sources)
        by_kind[fact.kind] = tuple(sorted(set(by_kind.get(fact.kind, ())) | tokens))
    return {
        "access_control": DominanceSpec(
            family="access_control",
            language=language,
            operations=operations,
            dischargers=dischargers,
            requirements=requirements,
            dischargers_by_kind=by_kind,
        )
    }


__all__ = [
    "GUARD_KINDS",
    "ConfigSpec",
    "config_specs",
    "GUARD_PATTERNS",
    "DominanceSpec",
    "TaintSpec",
    "classify_guard_text",
    "dominance_specs",
    "taint_specs",
]
