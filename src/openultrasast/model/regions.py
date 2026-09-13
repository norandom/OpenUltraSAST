"""Where to look, and what to look for there (contributor-scan, Req 2).

Pair scoring could rely on a labelled function: the corpus declares which function carries the bug and which
family it belongs to. A contributor has neither — *which code is risky* is the question they are asking. So a
repository scan derives its regions from the code itself: entry points where the mapper found them, whole
files where it did not, and each region carries only the families its shape and language actually admit.

Two restraints are deliberate:

* **The rank comes from what ``EntryPointRecord`` already carries**, not from a new signal invented here. The
  mapper has already decided whether a handler is public or local-only and whether it sits at a trust
  boundary; a second opinion computed from the same evidence would be a way of disagreeing with ourselves.
* **A family is offered only where its arbiter could answer.** An obligation needs a reachable operation, so
  ``access_control`` is offered where there is a handler and withheld from a library file that has none.
  Asking every family of every region is the unbounded version of this, and at repository scale the budget is
  the thing being spent.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from .contracts import AffectedRelationship, ChangeContext, ExecutionBudget, QuestionIdentity
from .specs import config_specs, dominance_specs, taint_specs

# From `mapping.AccessLevel`. A publicly reachable handler at a trust boundary is where a missing check costs
# most, so it is looked at first when the budget is finite.
_ACCESS_RANK: dict[str, float] = {
    "public": 1.0,
    "authenticated": 0.8,
    "role-restricted": 0.6,
    "contract-only/callback": 0.4,
    "review-required": 0.3,
    "local-only": 0.2,
}

# Languages whose facts the model layer carries. Anything else yields no region rather than an empty scan
# that looks like a clean bill of health.
_LANGUAGES = {"python", "javascript", "typescript", "java", "c", "c_cpp", "php"}
_NORMALISE = {"typescript": "javascript", "c_cpp": "c"}

# What a CPG calls a file's top-level code. A module body is a method like any other to the engine, and
# naming it here is what lets a region ask about the code that is not inside any function.
MODULE_SCOPE = "<module>"

# What the mapper emits for `if __name__ == '__main__':` -- a marker for a module-level entry point, not
# the name of a function. Sent to the engine as a function name it matched nothing, so a repository's
# module-level settings were unaskable: VAmPI's `host='0.0.0.0'` went unreported.
_MODULE_MARKERS = frozenset({"__main__"})


@dataclass(frozen=True)
class ScanRegion:
    """A place to arbitrate, and the families worth arbitrating there."""

    path: str
    function: str | None  # None for a file-level fallback: there is no labelled function on a scan path
    language: str
    families: tuple[str, ...]
    rank: float
    source: str  # "entry_point" | "module_scope" | "file_fallback"
    # Does the project's own build declaration name this file? True when it declares nothing at all --
    # silence is not exclusion, and no repository is penalised for a build system we cannot read.
    shipped: bool = True


def regions_for(entries: Sequence[object], targets: Sequence[object], *, shipped: frozenset[str] | None = None) -> tuple[ScanRegion, ...]:
    """Regions for a repository, strongest first.

    A file with an entry point yields regions for its handlers only — a fallback region beside them would
    scan the same code twice and spend the budget on duplicates.
    """
    by_path: dict[str, str] = {}
    for target in targets:
        language = _language_of(target)
        if language:
            by_path[str(getattr(target, "path", ""))] = language

    # One region per (path, function). The mapper can emit several entry points for a single file -- on a
    # ten-line Flask file it produced three, one named and two nameless -- and turning each into a region
    # scanned the same code repeatedly, multiplying Joern invocations for no new coverage. Where several
    # entries agree on a region, the highest access rank wins, because that is the one worth looking at first.
    best: dict[tuple[str, str | None], ScanRegion] = {}
    for entry in entries:
        path = str(getattr(entry, "path", ""))
        language = by_path.get(path)
        if language is None:
            continue
        # A handler its own contract declares OPEN carries no authorization obligation: there is nothing
        # for a guard to be missing from. The declaration is what makes this sound -- an OpenAPI operation
        # with no `security` block, a `wp_ajax_nopriv_` hook, a REST `permission_callback => __return_true`.
        # An INFERRED "public" is the opposite case and must keep the family, because for a decorator
        # framework it means only that no `@login_required` was found, which is the bug itself.
        declared_open = bool(getattr(entry, "access_declared", False)) and str(getattr(entry, "access_level", "")) == "public"
        families = _families(language, has_handler=not declared_open)
        if not families:
            continue
        function = getattr(entry, "function_name", None) or None
        module_body = function in _MODULE_MARKERS
        if module_body:
            # A module body is not a handler, whatever the mapper called it, so it is offered the families a
            # file gets rather than the families a handler gets. Carrying `access_control` here entailed a
            # missing authorization check on `if __name__ == '__main__':`.
            function, families = MODULE_SCOPE, _families(language, has_handler=False)
            if not families:
                continue
        rank = _ACCESS_RANK.get(str(getattr(entry, "access_level", "")), 0.5)
        key = (path, function)
        current = best.get(key)
        if current is None or rank > current.rank:
            best[key] = ScanRegion(
                path=path,
                function=function,
                language=language,
                families=families,
                rank=rank,
                source="module_scope" if module_body else "entry_point",
            )

    # A nameless entry point IS the file. Where a named region already covers that file it adds nothing but
    # a second full-file pass, so it is dropped -- unless the file has no named region at all.
    named_paths = {path for path, function in best if function is not None}
    regions = [region for (path, function), region in best.items() if function is not None or path not in named_paths]

    # Every file whose regions are all function-scoped still has code that is in no function: the settings, the
    # route registrations, the globals. Those regions cannot see it -- their queries filter by function name --
    # and there is no file-level region beside them, because one would duplicate every function's findings.
    # So the module body gets its own region, which partitions the file rather than overlapping it.
    #
    # This was cheap to add only after batching: before it, a region was a JVM.
    scoped = {region.path for region in regions if region.function is not None}
    have_module = {region.path for region in regions if region.function == MODULE_SCOPE}
    for path in sorted(scoped - have_module):
        language = by_path.get(path)
        if language is None:
            continue
        families = _families(language, has_handler=False)
        if families:
            regions.append(
                ScanRegion(path=path, function=MODULE_SCOPE, language=language, families=families, rank=0.15, source="module_scope")
            )

    covered = {region.path for region in regions}

    for path, language in by_path.items():
        if path in covered:
            continue
        families = _families(language, has_handler=False)
        if not families:
            continue
        regions.append(ScanRegion(path=path, function=None, language=language, families=families, rank=0.1, source="file_fallback"))

    # A total order: rank descending, then path and function, so two runs of one repository agree.
    if shipped is not None:
        regions = [replace(region, shipped=region.path in shipped) for region in regions]

    # Shipped first, then rank. A project's own build declaration outranks any score computed here: libpng's
    # twenty-five entry points were all `main()` in example programs and test tools, and they took the
    # interprocedural analysis with them.
    return tuple(sorted(regions, key=lambda r: (not r.shipped, -r.rank, r.path, r.function or "")))


def _language_of(target: object) -> str | None:
    language = str(getattr(target, "language", "") or "")
    if language not in _LANGUAGES:
        return None
    return _NORMALISE.get(language, language)


def _families(language: str, *, has_handler: bool) -> tuple[str, ...]:
    """The families this language has facts for, minus those whose arbiter needs a handler and has none."""
    families = set(taint_specs(language=language))
    families |= set(config_specs(language=language))
    if has_handler:
        families |= set(dominance_specs(language=language))
    return tuple(sorted(families))


def affected_context(
    context: ChangeContext,
    questions: Sequence[QuestionIdentity],
    rows_by_question: Mapping[QuestionIdentity, Sequence[Mapping[str, object]]],
    root: Path,
    execution_budget: ExecutionBudget | None = None,
) -> tuple[ChangeContext, set[QuestionIdentity]]:
    """Attach existing graph locations to changes; never select or reprioritize a question.

    Base spans are file-level hints unless an unchanged line anchors them in the head.
    A method relationship is context, not proof of taint, guard removal or novelty.
    """

    relationships = list(context.relationships)
    gaps = list(context.unresolved_boundaries)
    affected_gaps: set[QuestionIdentity] = set()
    changed = {context.decode_path(p) for p in context.changed_paths}
    if context.deleted_paths:
        gaps.append("deleted_dependency_projection_unavailable:contributor-scan")
    if changed.intersection(context.decode_path(p) for p in context.declaration_paths):
        gaps.append("configuration_dependency_projection_unavailable:contributor-scan")
    if context.base_revision is None:
        gaps.append("comparison_base_unavailable")
    inherited_gap = bool(gaps)
    renamed = {context.decode_path(r.base_path): context.decode_path(r.head_path) for r in context.renames}
    for identity in questions:
        if execution_budget is not None and time.monotonic() >= execution_budget.deadline_monotonic:
            gaps.append("change_context_deadline_exhausted")
            affected_gaps.update(questions)
            break
        rows = rows_by_question.get(identity, ())
        local_gaps = []
        if not any(r.get("kind") == "context_summary" for r in rows):
            local_gaps.append("context_projection_unavailable:contributor-scan")
        elif not any(r.get("kind") == "context_method" for r in rows):
            local_gaps.append("context_scope_empty:contributor-scan")
        for row in rows:
            if row.get("kind") == "context_boundary":
                local_gaps.append(str(row.get("reason", "context_unresolved")))
            if row.get("kind") != "context_method":
                continue
            path = Path(str(row.get("path", "")))
            try:
                absolute = path if path.is_absolute() else root / path
                path_text = absolute.resolve().relative_to(root.resolve()).as_posix()
                if not absolute.is_file():
                    raise ValueError("missing context source")
                start, end = int(str(row.get("startLine", 0))), int(str(row.get("endLine", 0)))
                if start < 1 or end < start:
                    raise ValueError("missing method extent")
            except (ValueError, TypeError, OSError):
                local_gaps.append("context_location_unavailable")
                continue
            evidence = []
            for span in context.spans:
                old_path = context.decode_path(span.path)
                match_path = renamed.get(old_path, old_path) if span.side == "base" else old_path
                if match_path != path_text:
                    continue
                if span.side == "base" or (span.start_line <= end and span.end_line >= start):
                    evidence.append(f"{span.side}_span:{old_path}:{span.start_line}-{span.end_line}")
            for anchor in context.line_correspondences:
                if context.decode_path(anchor.head_path) == path_text and start <= anchor.head_start_line <= end:
                    evidence.append(f"unchanged_line:{anchor.head_start_line};lexical_only")
            if not evidence or path_text not in changed | set(renamed.values()):
                continue
            function = str(row.get("function", "")) or None
            source = QuestionIdentity(identity.unit, identity.language, path_text, function, identity.family)
            relation = AffectedRelationship(source, identity, str(row.get("relationship", "method")), tuple(evidence))
            if relation not in relationships:
                relationships.append(relation)
        if local_gaps or inherited_gap:
            affected_gaps.add(identity)
        gaps.extend(reason + ":" + identity.question_id for reason in local_gaps)
    return replace(context, relationships=tuple(relationships), unresolved_boundaries=tuple(dict.fromkeys(gaps))), affected_gaps
