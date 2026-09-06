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
from dataclasses import dataclass, field
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


def classify_pair(
    case: object, taxonomy: FamilyTaxonomy, *, client: ChatClient | None, model: str = "", use_declared: bool = True
) -> Classification:
    """The families a labeled pair belongs to: its declared label, else its mechanism, else its weakness.

    ``use_declared`` is False when the classifier is being measured against those same labels, so that
    agreement is not the classifier reading back the answer it is scored on.
    """
    families = _static_families_of_pair(case, taxonomy, use_declared=use_declared)
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


def _static_families_of_pair(case: object, taxonomy: FamilyTaxonomy, *, use_declared: bool = True) -> tuple[str, ...]:
    declared: list[str] = []
    derived: list[str] = []
    for row in getattr(case, "expected", ()) or ():
        label = getattr(row, "family", None)
        if use_declared and label and any(family.id == label for family in taxonomy.families):
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


@dataclass(frozen=True)
class QueueEntry:
    """One disagreement between a maintainer label and the classifier, for a human to settle."""

    pair: str
    label: str
    classified: tuple[str, ...]
    tier: Tier
    confidence: float | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "pair": self.pair,
            "label": self.label,
            "classified": list(self.classified),
            "tier": self.tier,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ClassifierReport:
    """How the classifier did on its own: coverage over the whole corpus, agreement where a reference exists.

    ``labeled`` is how many rows carry a maintainer family label. Agreement, the confusion matrix and both
    baselines are computed over those rows only, so an unlabeled corpus reports coverage and says the
    reference set is empty rather than inventing a score.
    """

    taxonomy_version: str
    classified: int
    labeled: int
    agreement: float  # credit for the classifier's first answer
    oracle_router: float  # credit for the best of its answers
    random_router: float  # a uniform pick over the real families
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    per_tier: dict[str, int] = field(default_factory=dict)
    per_family: dict[str, int] = field(default_factory=dict)
    unknown: int = 0
    queue: tuple[QueueEntry, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "taxonomy_version": self.taxonomy_version,
            "classified": self.classified,
            "labeled": self.labeled,
            "agreement": self.agreement,
            "oracle_router": self.oracle_router,
            "random_router": self.random_router,
            "confusion": {label: dict(sorted(answers.items())) for label, answers in sorted(self.confusion.items())},
            "per_tier": dict(sorted(self.per_tier.items())),
            "per_family": dict(sorted(self.per_family.items())),
            "unknown": self.unknown,
            "queue": [entry.to_dict() for entry in self.queue],
        }


def measure_classifier(
    cases: Sequence[object],
    taxonomy: FamilyTaxonomy,
    *,
    client: ChatClient | None,
    model: str = "",
    reference_tiers: Sequence[str] = ("seeded", "reviewed"),
) -> ClassifierReport:
    """Classify every case and score the classifier against the labels a maintainer stands behind."""
    rows = list(cases)
    real = [family.id for family in taxonomy.families if family.id != "unknown"]
    per_tier: dict[str, int] = {}
    per_family: dict[str, int] = {}
    confusion: dict[str, dict[str, int]] = {}
    queue: list[QueueEntry] = []
    unknown = 0
    credits: list[float] = []
    oracles: list[float] = []
    for case in rows:
        answer = classify_pair(case, taxonomy, client=client, model=model, use_declared=False)
        per_tier[answer.tier] = per_tier.get(answer.tier, 0) + 1
        for family_id in answer.families:
            per_family[family_id] = per_family.get(family_id, 0) + 1
        if not answer.families:
            unknown += 1
        label = _reference_label(case, taxonomy, reference_tiers)
        if label is None:
            continue
        first = answer.families[0] if answer.families else "unknown"
        credits.append(_credit(taxonomy, label, (first,)))
        oracles.append(_credit(taxonomy, label, answer.families or ("unknown",)))
        confusion.setdefault(label, {})[first] = confusion.setdefault(label, {}).get(first, 0) + 1
        if credits[-1] < 1.0:
            queue.append(
                QueueEntry(
                    pair=str(getattr(case, "name", "?")),
                    label=label,
                    classified=answer.families,
                    tier=answer.tier,
                    confidence=answer.confidence,
                )
            )
    labeled = len(credits)
    return ClassifierReport(
        taxonomy_version=taxonomy.version,
        classified=len(rows),
        labeled=labeled,
        agreement=sum(credits) / labeled if labeled else 0.0,
        oracle_router=sum(oracles) / labeled if labeled else 0.0,
        random_router=(1.0 / len(real)) if real and labeled else 0.0,
        confusion=confusion,
        per_tier=per_tier,
        per_family=per_family,
        unknown=unknown,
        queue=tuple(queue),
    )


def write_review_queue(path: Path, entries: Sequence[QueueEntry]) -> int:
    """Append disagreements a human has not seen yet; a pair already queued is never duplicated."""
    path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    seen.add(str(json.loads(line).get("pair", "")))
                except json.JSONDecodeError:
                    continue
    written = 0
    with path.open("a", encoding="utf-8") as handle:
        for entry in entries:
            if entry.pair in seen:
                continue
            handle.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
            seen.add(entry.pair)
            written += 1
    return written


def _reference_label(case: object, taxonomy: FamilyTaxonomy, reference_tiers: Sequence[str]) -> str | None:
    """The family a maintainer stands behind for this pair, or None. Only trusted tiers are a reference."""
    if str(getattr(case, "review_tier", "")) not in reference_tiers:
        return None
    known = {family.id for family in taxonomy.families}
    for row in getattr(case, "expected", ()) or ():
        label = getattr(row, "family", None)
        if label and str(label) in known:
            return str(label)
    return None


def _credit(taxonomy: FamilyTaxonomy, label: str, answers: Sequence[str]) -> float:
    """1.0 for the same family, half for a parent or child, nothing for a lateral or fabricated answer."""
    best = 0.0
    for answer in answers:
        relation = taxonomy.related(label, answer)
        best = max(best, 1.0 if relation == "same" else 0.5 if relation == "parent_child" else 0.0)
    return best


__all__ = [
    "MIN_CONFIDENCE",
    "Classification",
    "ClassifierReport",
    "FamilyLabelError",
    "QueueEntry",
    "classify_finding",
    "classify_pair",
    "classify_region",
    "measure_classifier",
    "validate_family_labels",
    "write_review_queue",
]
