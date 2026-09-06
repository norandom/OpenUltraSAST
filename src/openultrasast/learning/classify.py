"""The auto-classifier: which families a pair, a finding or a region belongs to (learning-harness, Req 2).

Three tiers, cheapest first. Tier one decides from what the repository already knows: a declared family
label, an obligation kind, a mechanism id, the rule a finding came from, or the labeled weakness. Tier
two asks the model one closed question in JSON mode, with thinking disabled so temperature applies, and
abstains when the answer is off-vocabulary or the reply's mean token log-probability is below the
threshold. Tier three is abstention. Every answer records which tier decided it, and answers are
multi-label because one function can owe more than one family.

The classifier proposes; it never writes a label. It also owns validation of the labels the corpus
carries, because the corpus stores a family as an opaque string and this module owns the taxonomy.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..findings import StaticFinding
from ..tool_hunter import ChatClient
from .families import FamilyTaxonomy

Tier = Literal["static", "model", "none"]
MIN_CONFIDENCE = -1.0  # mean token log-probability; below this the model is guessing, so we abstain
_SYSTEM = (
    "You classify a piece of code or a labeled bug into vulnerability families for a security tool. "
    'Answer with JSON only, of the form {"families": ["<id>", ...]}, using ids from the list you are given. '
    "Use an empty list when none of them fits. Do not explain and do not invent an id."
)


class FamilyLabelError(ValueError):
    """Raised when a catalog row carries a family id outside the taxonomy."""


@dataclass(frozen=True)
class Classification:
    families: tuple[str, ...]  # empty means unknown
    tier: Tier
    confidence: float | None = None  # mean token log-probability when the model answered


def classify_pair(case: object, taxonomy: FamilyTaxonomy, *, client: ChatClient | None, model: str = "") -> Classification:
    """The families a labeled pair belongs to: its declared label, else its mechanism, else its weakness."""
    families = _static_families_of_pair(case, taxonomy)
    if families:
        return Classification(families=families, tier="static")
    return _ask(client, model, taxonomy, _pair_question(case))


def classify_finding(finding: StaticFinding, taxonomy: FamilyTaxonomy, *, client: ChatClient | None, model: str = "") -> Classification:
    """The families a finding belongs to: its own family tag, else what produced it, else the model."""
    families = _static_families_of_finding(finding, taxonomy)
    if families:
        return Classification(families=families, tier="static")
    return _ask(client, model, taxonomy, _finding_question(finding))


def classify_region(
    root: Path, path: str, *, function: str | None, taxonomy: FamilyTaxonomy, client: ChatClient | None, model: str = ""
) -> Classification:
    """The families a code region belongs to, from what the static tools already see in it."""
    families = _static_families_of_region(root, path, function, taxonomy)
    if families:
        return Classification(families=families, tier="static")
    return _ask(client, model, taxonomy, _region_question(root, path, function))


def validate_family_labels(cases: Sequence[object], taxonomy: FamilyTaxonomy) -> None:
    """Every family a catalog row declares must be in the taxonomy. The corpus stores labels; this module owns them."""
    known = {family.id for family in taxonomy.families}
    for case in cases:
        for row in getattr(case, "expected", ()) or ():
            label = getattr(row, "family", None)
            if label and label not in known:
                name = getattr(case, "name", "?")
                raise FamilyLabelError(f"pair {name}: unknown family {label!r}; expected one of {', '.join(sorted(known))}")


def _static_families_of_pair(case: object, taxonomy: FamilyTaxonomy) -> tuple[str, ...]:
    declared: list[str] = []
    derived: list[str] = []
    for row in getattr(case, "expected", ()) or ():
        label = getattr(row, "family", None)
        if label and any(family.id == label for family in taxonomy.families):
            declared.append(str(label))
            continue
        obligation = getattr(row, "obligation", None)
        if obligation:
            derived.append("access_control")
        mechanism = getattr(row, "mechanism", None)
        by_mechanism = taxonomy.family_of_mechanism(str(mechanism)) if mechanism else None
        if by_mechanism is not None and by_mechanism.id != "unknown":
            derived.append(by_mechanism.id)
            continue
        by_cwe = taxonomy.family_of_cwe(str(getattr(row, "cwe", "") or ""))
        if by_cwe is not None and by_cwe.id != "unknown":
            derived.append(by_cwe.id)
    return _ordered(declared or derived, taxonomy)


def _static_families_of_finding(finding: StaticFinding, taxonomy: FamilyTaxonomy) -> tuple[str, ...]:
    known = {family.id for family in taxonomy.families}
    tagged = [tag.split(":", 1)[1] for tag in finding.tags if tag.startswith("family:") and tag.split(":", 1)[1] in known]
    if tagged:
        return _ordered(tagged, taxonomy)
    found: list[str] = []
    for tag in finding.tags:
        if tag.startswith("obligation:") or tag.startswith("discharger:"):
            found.append("access_control")
        elif tag.startswith("mechanism:"):
            family = taxonomy.family_of_mechanism(tag.split(":", 1)[1])
            if family is not None and family.id != "unknown":
                found.append(family.id)
    if finding.finding_id.startswith("obligation:"):
        found.append("access_control")
    rule_family = taxonomy.family_of_cwe(_rule_cwe(finding.finding_id.split(":", 1)[0]))
    if rule_family is not None and rule_family.id != "unknown":
        found.append(rule_family.id)
    return _ordered(found, taxonomy)


def _static_families_of_region(root: Path, path: str, function: str | None, taxonomy: FamilyTaxonomy) -> tuple[str, ...]:
    from ..hunter_tools import PathEscapesRepo, flows, obligations

    found: list[str] = []
    if function:
        try:
            if obligations(root, path=path, function=function):
                found.append("access_control")
            for record in flows(root, path=path, function=function):
                family = taxonomy.family_of_cwe(str(record.get("cwe") or ""))
                if family is not None and family.id != "unknown":
                    found.append(family.id)
        except (PathEscapesRepo, OSError):
            return ()
    return _ordered(found, taxonomy)


def _ask(client: ChatClient | None, model: str, taxonomy: FamilyTaxonomy, question: str) -> Classification:
    if client is None:
        return Classification(families=(), tier="none")
    catalog = "\n".join(f"- {family.id}: {family.description}" for family in taxonomy.families)
    messages: list[dict[str, object]] = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": f"Families:\n{catalog}\n\n{question}\n\nAnswer as JSON."},
    ]
    try:
        response = client.complete(model=model, messages=messages, tools=[], json_object=True, logprobs=True)  # type: ignore[call-arg]
    except TypeError:  # a client without the adapter's extras
        response = client.complete(model=model, messages=messages, tools=[])
    except Exception:  # noqa: BLE001 — the classifier is advisory; a failed call abstains
        return Classification(families=(), tier="none")
    confidence = response.mean_logprob
    if confidence is not None and confidence < MIN_CONFIDENCE:
        return Classification(families=(), tier="none", confidence=confidence)
    families = _ordered(_parse(response.content), taxonomy)
    if not families:
        return Classification(families=(), tier="none", confidence=confidence)
    return Classification(families=families, tier="model", confidence=confidence)


def _parse(content: str | None) -> list[str]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        payload = json.loads(content[content.index("{") : content.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        return []
    families = payload.get("families") if isinstance(payload, dict) else None
    if not isinstance(families, list):
        return []
    return [str(item) for item in families if isinstance(item, str)]


def _ordered(names: Sequence[str], taxonomy: FamilyTaxonomy) -> tuple[str, ...]:
    """Taxonomy order, de-duplicated, unknown ids dropped, so two runs compare equal."""
    wanted = set(names)
    return tuple(family.id for family in taxonomy.families if family.id in wanted and family.id != "unknown")


def _rule_cwe(rule_id: str) -> str:
    from ..ruleset import DEFAULT_RULESET_DIR, load_ruleset

    for rule in load_ruleset(DEFAULT_RULESET_DIR):
        if rule.rule_id == rule_id:
            return rule.cwe
    return ""


def _pair_question(case: object) -> str:
    row = next(iter(getattr(case, "expected", ()) or ()), None)
    parts = [f"Labeled bug in {getattr(case, 'relpath', '?')}"]
    if row is not None:
        parts.append(
            f"function {getattr(row, 'function', '?')}, weakness {getattr(row, 'cwe', '?')}, mechanism {getattr(row, 'mechanism', '?')}"
        )
    return "Which families does it belong to? " + "; ".join(parts)


def _finding_question(finding: StaticFinding) -> str:
    return f"Which families does this finding belong to? {finding.title}. {finding.rationale[:400]}"


def _region_question(root: Path, path: str, function: str | None) -> str:
    from ..hunter_tools import PathEscapesRepo, read_definition

    try:
        found = read_definition(root, function or "", max_chars=2000) if function else None
    except (PathEscapesRepo, OSError):
        found = None
    body = str(found["text"]) if found else ""
    return f"Which families does this code belong to?\n{path}::{function}\n{body}"


__all__ = [
    "MIN_CONFIDENCE",
    "Classification",
    "FamilyLabelError",
    "classify_finding",
    "classify_pair",
    "classify_region",
    "validate_family_labels",
]
