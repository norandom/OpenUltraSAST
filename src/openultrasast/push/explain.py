"""Plain-language lines for pre-push coverage reasons (Requirement 9.2).

The artifact keeps every raw reason exactly as recorded. The terminal gets one line per distinct
kind of skip, in words a first-time user can act on: hex-encoded repository paths are decoded,
per-question sha256 tokens are dropped and counted, and a reason this table does not know is
still printed rather than hidden.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

_HEX_PATH = re.compile(r"^((?:[0-9a-f]{2})+):(.+)$")
_TOKEN = re.compile(r"^(.+?):(?:[a-z][a-z0-9-]*:)?[0-9a-f]{64}$")

# Reasons that summarise others; printing them would only repeat a line already shown.
_SUMMARY = frozenset({"analysis_incomplete"})

_ENGINE_MISSING = (
    "engine did not run: the code graph could not be built (is Joern installed? 'joern-parse' must be on PATH, "
    "or run the hook through ops/ousast-docker)"
)
_NOVELTY = "whether this push introduced some engine findings could not be established ({detail})"

GLOSSARY: dict[str, str] = {
    "cpg_build_failed": _ENGINE_MISSING,
    "cpg_unavailable": _ENGINE_MISSING,
    "cpg_empty": "engine read no code: the code graph came back empty",
    "frontend_unsupported": "engine has no frontend for at least one language in this push",
    "deadline_exhausted": (
        "engine did not finish within the {deadline} s deadline; rerun with a longer --deadline, "
        "or set OUSAST_PUSH_ENGINE=background to finish it after the push"
    ),
    "change_context_deadline_exhausted": "the deadline ran out while relating the change to the code",
    "report_deadline_exhausted": "the deadline ran out while saving the details",
    "base_comparison_unavailable": "no base revision was analysed, so no engine finding can be called new or worsened",
    "base_counterpart_unresolved": "the changed code has no counterpart in the base revision to compare against",
    "base_unavailable": "the base revision is unavailable",
    "declaration_paths_unavailable": "project declaration files could not be listed",
    "ambiguous_line_correspondence": "changed lines could not be matched one-to-one to base lines in {paths}",
    "line_correspondence_unavailable": "changed lines could not be mapped to the base in {paths}",
    "ambiguous_path_rename_correspondence": "a renamed file could not be matched to one base file: {paths}",
    "unmatched_added_deleted_path_correspondence": (
        "files were both added and deleted, so a moved file cannot be told apart from a new one"
    ),
    "capability_unavailable": ("engine findings are not qualified as alerts yet: no capability has passed independent evaluation"),
    "capability_disabled": "an engine capability is declared but disabled",
    "capability_unevaluated": "an engine capability has not passed its evaluation",
    "capability_ambiguous": "more than one capability declaration matches a finding",
    "eligibility": "the capability registry does not match this build ({detail}), so no capability can be used",
    "comparison_unknown": _NOVELTY,
    "dynamic_external_or_depth_context_unresolved": ("{n} engine check(s) depend on dynamic or external code the engine cannot follow"),
    "query_failed": "an engine query failed, so some regions were not decided",
    "query_budget_reserved": "some engine questions were not asked, to keep time for the ones that were",
    "query_too_expensive": "some engine questions were too expensive to answer",
    "regions_truncated": "only the highest-ranked regions were examined (--max-regions)",
    "files_unparsed": "some files could not be parsed by the engine",
    "cross_partition_semantics_unresolved": "flows between languages in this repository are not followed",
    "resolution": "the pushed ref could not be resolved ({detail})",
    "push_input_failed": "the push input could not be read ({detail})",
    "snapshot": "some files could not be materialised for analysis ({detail})",
    "dependency_unresolved": "{n} engine finding(s) depend on code the comparison could not resolve",
    "change_unsupported": "{n} engine finding(s) have no supported relationship to the change",
}

# Comparison outcomes recorded per finding; each means novelty was not established.
_NOVELTY_REASONS = frozenset(
    {
        "base_incomplete",
        "head_context_incomplete",
        "witness_identity_unresolved",
        "semantics_mismatch",
        "change_context_unresolved",
        "operation_correspondence_unresolved",
        "base_reachability_bounded",
        "base_operation_inventory_unavailable",
        "base_enumeration_scope_reachability_derived",
        "operation_present_in_base_without_traced_flow",
        "operation_moved_within_change",
        "source_correspondence_unresolved",
    }
)

_RESOLUTION = {
    "missing_base": (
        "new branch: the remote has no base to compare against, so the engine comparison did not run "
        "(OUSAST_COMPARISON_BASE=<local branch> compares against a local branch instead)"
    ),
    "unsupported_base": "the remote's current commit is not available locally, so there is no base to compare against",
    "no_merge_base": "the pushed commit shares no history with the remote branch",
    "ambiguous_base": "more than one base could apply to the pushed ref",
    "missing_target": "the pushed commit could not be found locally",
    "unsupported_target": "the pushed object is not a commit",
    "resolution_error": "the pushed ref could not be resolved",
}


def _words(value: str) -> str:
    return value.replace("_", " ").replace(":", ": ")


def _decode(path_hex: str) -> str | None:
    try:
        text = os.fsdecode(bytes.fromhex(path_hex))
    except ValueError:
        return None
    return text if text and text.isprintable() else None


def _split(reason: str) -> tuple[str, str, str | None]:
    """(key, detail, decoded path) for one raw reason."""
    path = None
    match = _HEX_PATH.match(reason)
    if match and (decoded := _decode(match.group(1))) is not None:
        path, reason = decoded, match.group(2)
    token = _TOKEN.match(reason)
    if token:
        reason = token.group(1)
    if reason in GLOSSARY or reason in _NOVELTY_REASONS or reason in _SUMMARY:
        return reason, "", path
    head, _, rest = reason.partition(":")
    if head not in GLOSSARY and head.endswith("_failed") and rest:
        return "stage_failed", f"{head[: -len('_failed')]}:{rest}", path
    return head, rest, path


def language_reason(language: str, changed: int, total: int) -> str:
    """The raw reason recorded when a language has no engine frontend and no quick rules."""
    return f"language_not_covered:{language}:{changed}:{total}"


def explain(reasons: Sequence[str], *, deadline: float | None = None) -> list[str]:
    """One plain line per distinct kind of skipped or incomplete check, in first-seen order."""
    groups: dict[tuple[str, str], list[str | None]] = {}
    for reason in reasons:
        key, detail, path = _split(str(reason))
        if key in _SUMMARY:
            continue
        if key in _NOVELTY_REASONS:
            key, detail = "comparison_unknown", _words(key)
        groups.setdefault((key, detail), []).append(path)
    novelty_details = [detail for (key, detail) in groups if key == "comparison_unknown" and detail]
    lines: list[str] = []
    for (key, detail), paths in groups.items():
        if key == "comparison_unknown":
            if detail or not novelty_details:
                lines.append(_NOVELTY.format(detail=detail or "see the details file"))
            continue
        named = sorted({p for p in paths if p})
        shown = ", ".join(named[:3]) + (f" and {len(named) - 3} more" if len(named) > 3 else "")
        if key == "language_not_covered":
            language, _, counts = detail.partition(":")
            changed, _, total = counts.partition(":")
            lines.append(
                f"language not covered: {language} ({changed} changed file(s), {total} in the repository): "
                "no engine frontend and no quick rules, so silence here is not a clean result"
            )
        elif key == "resolution":
            lines.append(_RESOLUTION.get(detail, GLOSSARY["resolution"].format(detail=_words(detail))))
        elif key == "stage_failed":
            stage, _, error = detail.partition(":")
            lines.append(f"the {_words(stage)} step failed ({error})")
        elif key in GLOSSARY:
            text = GLOSSARY[key].format(
                n=len(paths),
                paths=shown or "some files",
                detail=_words(detail),
                deadline=f"{deadline:g}" if deadline is not None else "configured",
            )
            lines.append(text)
        else:
            suffix = f" in {shown}" if shown else ""
            lines.append(f"{_words(key if not detail else key + ':' + detail)}{suffix} (see the details file)")
    return lines
