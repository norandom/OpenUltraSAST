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

import bisect
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
        if function is not None and not getattr(entry, "defines_handler", True):
            # The entry names a handler this file registers but does not define, which is what a
            # route-registration module does. Scoping a region to it asks the graph about a method
            # the file does not hold, and every question in that region is then unresolvable. The
            # handler's own module gets its own regions, so the route is scoped to the file here and
            # the record keeps the name for the authorization question, which is cross-file by nature.
            function = None
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


AMBIGUOUS_CORRESPONDENCE = "ambiguous_line_correspondence"
# Reachability from or through the scoped methods was bounded. It limits which further flows
# could be seen; it does not make this question's own answer or context ownership unknown, so
# it is recorded as a boundary without marking the question's context incomplete. The later
# comparison consults it for exactly the claims that rest on a flow not having been traced.
REACHABILITY_BOUNDED = "dynamic_external_or_depth_context_unresolved"


def _anchored_lines(anchors: list[tuple[int, int]] | None, start: int, end: int) -> list[int]:
    """Anchor lines within ``[start, end]``, in the order the change context listed them."""
    if not anchors:
        return []
    low = bisect.bisect_left(anchors, (start, -1))
    high = bisect.bisect_right(anchors, (end, float("inf")))
    return [line for line, _ in sorted(anchors[low:high], key=lambda item: item[1])]


def _context_path(raw: str, root: Path, resolved_root: Path) -> str | None:
    """A context location's path relative to the root, or ``None`` when it is not a real file under it."""
    try:
        path = Path(raw)
        absolute = path if path.is_absolute() else root / path
        text = absolute.resolve().relative_to(resolved_root).as_posix()
        return text if absolute.is_file() else None
    except (ValueError, OSError):
        return None


def _elsewhere_unusable(row: Mapping[str, object], root: Path, checked: dict[str, bool]) -> bool:
    """Whether a summarised set of locations holds one the itemised check would have rejected.

    The same rejections as an itemised `context_method` row: a file that is not a real file under the root,
    or an extent that is missing or inverted. Each file is checked once per call, because the summary for
    every family of a region names the same files.
    """
    try:
        if int(str(row.get("unusableExtents", 0))) > 0:
            return True
    except ValueError:
        return True
    paths = row.get("paths")
    if not isinstance(paths, list):
        return True
    resolved_root = root.resolve()
    for raw in paths:
        text = str(raw)
        if text not in checked:
            try:
                path = Path(text)
                absolute = path if path.is_absolute() else root / path
                absolute.resolve().relative_to(resolved_root)
                checked[text] = absolute.is_file()
            except (ValueError, OSError):
                checked[text] = False
        if not checked[text]:
            return True
    return False


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
    # Membership through a set, order through the list. `relation not in relationships` on the list alone was
    # quadratic -- 8 million comparisons for 4,000 relationships, 7 s -- and a push over a WordPress plugin
    # produces tens of thousands, which ran 82 minutes past the evidence pass and overran the deadline, because
    # the deadline is checked once per question and a single question could take minutes.
    known = set(relationships)
    gaps = list(context.unresolved_boundaries)
    affected_gaps: set[QuestionIdentity] = set()
    changed = {context.decode_path(p) for p in context.changed_paths}
    if context.deleted_paths:
        gaps.append("deleted_dependency_projection_unavailable:contributor-scan")
    if changed.intersection(context.decode_path(p) for p in context.declaration_paths):
        gaps.append("configuration_dependency_projection_unavailable:contributor-scan")
    if context.base_revision is None:
        gaps.append("comparison_base_unavailable")
    # Line-correspondence ambiguity is not a context gap: it says which base lines a head
    # line could map to, which only the later per-operation comparison consumes. Inheriting
    # it here made one file with repeated unchanged lines invalidate every question in the
    # repository. The mapping itself is still withheld, so an operation that needs an
    # ambiguous anchor remains uncomparable.
    inherited_gap = any(not gap.endswith(":" + AMBIGUOUS_CORRESPONDENCE) for gap in gaps)
    renamed = {context.decode_path(r.base_path): context.decode_path(r.head_path) for r in context.renames}
    checked: dict[str, bool] = {}
    # Decoded ONCE per call. Every row used to decode every span's and every line anchor's path -- a changed file
    # has one anchor per unchanged line -- and with the engine stubbed out that was 78% of a whole push. Anchors
    # are indexed by line so a row finds its own with two bisections, in their original order.
    attachable = changed | set(renamed.values())
    spans_by_path: dict[str, list[tuple[str, str, int, int]]] = {}
    for span in context.spans:
        old_path = context.decode_path(span.path)
        match_path = renamed.get(old_path, old_path) if span.side == "base" else old_path
        spans_by_path.setdefault(match_path, []).append((span.side, old_path, span.start_line, span.end_line))
    anchors_by_path: dict[str, list[tuple[int, int]]] = {}
    for index, anchor in enumerate(context.line_correspondences):
        anchors_by_path.setdefault(context.decode_path(anchor.head_path), []).append((anchor.head_start_line, index))
    for anchors in anchors_by_path.values():
        anchors.sort()
    # Resolved once per distinct path: the same few changed files recur in every question's rows, and resolving
    # them again per row was half of what `affected_context` cost once its quadratic was gone.
    resolved: dict[str, str | None] = {}
    resolved_root = root.resolve()
    for identity in questions:
        if execution_budget is not None and time.monotonic() >= execution_budget.deadline_monotonic:
            gaps.append("change_context_deadline_exhausted")
            affected_gaps.update(questions)
            break
        rows = rows_by_question.get(identity, ())
        local_gaps = []
        if not any(r.get("kind") == "context_summary" for r in rows):
            local_gaps.append("context_projection_unavailable:contributor-scan")
        elif not any(r.get("kind") in ("context_method", "context_elsewhere") for r in rows) and not any(
            r.get("kind") == "context_boundary" for r in rows
        ):
            # Only when the query offered no account of its own. A query that already said why its
            # scope is empty -- a named function this file does not define, most often -- has given
            # the specific reason, and adding a generic one on top buries it.
            local_gaps.append("context_scope_empty:contributor-scan")
        recorded_only: list[str] = []
        for row in rows:
            if row.get("kind") == "context_boundary":
                reason = str(row.get("reason", "context_unresolved"))
                (recorded_only if reason.startswith(REACHABILITY_BOUNDED) else local_gaps).append(reason)
            if row.get("kind") == "context_elsewhere":
                # Locations in files the change did not touch, summarised by the engine. None of them can be
                # attached to a change, so the only thing to do with them is what was always done before they
                # were discarded: check each names a real file under the root and had a usable extent.
                if _elsewhere_unusable(row, root, checked):
                    local_gaps.append("context_location_unavailable")
                continue
            if row.get("kind") != "context_method":
                continue
            raw_path = str(row.get("path", ""))
            if raw_path not in resolved:
                resolved[raw_path] = _context_path(raw_path, root, resolved_root)
            path_text = resolved[raw_path]
            try:
                if path_text is None:
                    raise ValueError("missing context source")
                start, end = int(str(row.get("startLine", 0))), int(str(row.get("endLine", 0)))
                if start < 1 or end < start:
                    raise ValueError("missing method extent")
            except (ValueError, TypeError, OSError):
                local_gaps.append("context_location_unavailable")
                continue
            if path_text not in attachable:
                continue
            evidence = [
                f"{side}_span:{old_path}:{span_start}-{span_end}"
                for side, old_path, span_start, span_end in spans_by_path.get(path_text, ())
                if side == "base" or (span_start <= end and span_end >= start)
            ]
            evidence += [f"unchanged_line:{line};lexical_only" for line in _anchored_lines(anchors_by_path.get(path_text), start, end)]
            if not evidence:
                continue
            function = str(row.get("function", "")) or None
            source = QuestionIdentity(identity.unit, identity.language, path_text, function, identity.family)
            relation = AffectedRelationship(source, identity, str(row.get("relationship", "method")), tuple(evidence))
            if relation not in known:
                known.add(relation)
                relationships.append(relation)
        if local_gaps or inherited_gap:
            affected_gaps.add(identity)
        gaps.extend(reason + ":" + identity.question_id for reason in (*local_gaps, *recorded_only))
    return replace(context, relationships=tuple(relationships), unresolved_boundaries=tuple(dict.fromkeys(gaps))), affected_gaps
