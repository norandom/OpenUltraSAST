from __future__ import annotations

import json
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from .frameworks import Priors, kept, normalize_priors, read_tag

DEFAULT_RULESET_DIR = Path(__file__).parent
VALID_STATUS = ("enabled", "shadow", "disabled")


class RulesetError(ValueError):
    """Raised when a ruleset data file is malformed."""


@dataclass(frozen=True)
class PatternRule:
    """A detection rule expressed as governed data (no rule-local severity).

    ``pattern`` is human-PR-only; the self-improvement loop may only change
    ``status``/``min_evidence_level``/``precision_estimate`` via the ledger.
    """

    rule_id: str
    title: str
    languages: tuple[str, ...]
    cwe: str
    tags: tuple[str, ...]
    pattern: str
    status: str = "enabled"
    min_evidence_level: str = "static_corroboration"
    precision_estimate: float = 0.0
    version: str = "1"
    # A prior (learned-decision-engine Req 8.2): the rule knows a framework or a library (`ruleset/frameworks.toml`).
    framework: str | None = None
    library: str | None = None
    # The language-level stand-in of a tagged rule: active only when that rule's prior is off.
    fallback_for: str | None = None


def load_ruleset(directory: Path = DEFAULT_RULESET_DIR, ledger: Path | None = None, *, priors: Priors = "all") -> tuple[PatternRule, ...]:
    """Load every ``*.toml`` rule file under ``directory`` and apply the loop ledger.

    Rules are returned sorted by ``rule_id`` for determinism. The optional ledger
    (``rule_policy.json``) overlays loop-owned ``status``/``min_evidence_level``/
    ``precision_estimate`` per ``rule_id``.

    ``priors`` keeps or drops the rules tagged ``framework``/``library``: ``"all"`` (the default, today's rules),
    ``"off"`` or a set of ids. A rule with ``fallback_for`` stands in for a tagged rule and is active exactly when
    that rule is dropped, so the language-level part of a mixed rule survives with its prior off.
    """
    rules: dict[str, PatternRule] = {}
    for path in sorted(directory.rglob("*.toml")):
        payload = tomllib.loads(path.read_text())
        for item in payload.get("rule", []):
            rule = _rule_from_dict(item, path)
            if rule.rule_id in rules:
                raise RulesetError(f"duplicate rule_id {rule.rule_id!r} in {path}")
            rules[rule.rule_id] = rule
    chosen = normalize_priors(priors)
    for rule in rules.values():
        target = rules.get(rule.fallback_for) if rule.fallback_for else None
        if rule.fallback_for and (target is None or not (target.framework or target.library)):
            raise RulesetError(f"rule {rule.rule_id}: fallback_for {rule.fallback_for!r} names no tagged rule")
        if rule.fallback_for and (rule.framework or rule.library):
            raise RulesetError(f"rule {rule.rule_id}: a fallback is language-level and carries no tag")
    active = {rule_id: rule for rule_id, rule in rules.items() if kept(rule.framework or rule.library, chosen)}
    selected = [rule for rule in active.values() if not (rule.fallback_for and rule.fallback_for in active)]
    overlay = _load_ledger(ledger)
    resolved = [_apply_overlay(rule, overlay.get(rule.rule_id)) for rule in selected]
    return tuple(sorted(resolved, key=lambda rule: rule.rule_id))


def write_ruleset(path: Path, rules: Iterable[PatternRule]) -> None:
    """Write rules as TOML. Patterns use literal multi-line strings (no escaping)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    blocks: list[str] = []
    for rule in rules:
        if "'''" in rule.pattern:
            raise RulesetError(f"rule {rule.rule_id} pattern cannot contain a triple single-quote")
        blocks.append(
            "\n".join(
                [
                    "[[rule]]",
                    f"rule_id = {_s(rule.rule_id)}",
                    f"title = {_s(rule.title)}",
                    f"languages = {_arr(rule.languages)}",
                    f"cwe = {_s(rule.cwe)}",
                    f"tags = {_arr(rule.tags)}",
                    f"status = {_s(rule.status)}",
                    f"min_evidence_level = {_s(rule.min_evidence_level)}",
                    f"precision_estimate = {float(rule.precision_estimate)}",
                    f"version = {_s(rule.version)}",
                    *(f"{name} = {_s(value)}" for name in ("framework", "library", "fallback_for") if (value := getattr(rule, name))),
                    f"pattern = '''{rule.pattern}'''",
                ]
            )
        )
    path.write_text("\n\n".join(blocks) + "\n")


def read_rule_ledger(path: Path) -> dict[str, dict[str, object]]:
    """Read the loop-owned ``rule_policy.json`` overlay (status/floors per rule_id)."""
    return _load_ledger(path)


def write_rule_ledger(path: Path, entries: dict[str, dict[str, object]]) -> None:
    """Write the loop-owned ``rule_policy.json`` overlay (used by the evolve loop)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n")


def _rule_from_dict(item: dict[str, object], path: Path) -> PatternRule:
    try:
        rule_id = str(item["rule_id"])
        cwe = str(item["cwe"])
        pattern = str(item["pattern"])
    except KeyError as exc:
        raise RulesetError(f"rule in {path} missing required field {exc}") from exc
    status = str(item.get("status", "enabled"))
    if status not in VALID_STATUS:
        raise RulesetError(f"rule {rule_id} has invalid status {status!r}")
    if not pattern:
        raise RulesetError(f"rule {rule_id} has an empty pattern")
    try:
        framework, library = read_tag(item, f"rule {rule_id} in {path}")
    except ValueError as exc:
        raise RulesetError(str(exc)) from exc
    return PatternRule(
        rule_id=rule_id,
        title=str(item.get("title", rule_id)),
        languages=_str_tuple(item.get("languages")),
        cwe=cwe,
        tags=_str_tuple(item.get("tags")),
        pattern=pattern,
        status=status,
        min_evidence_level=str(item.get("min_evidence_level", "static_corroboration")),
        precision_estimate=float(item.get("precision_estimate", 0.0)),  # type: ignore[arg-type]
        version=str(item.get("version", "1")),
        framework=framework,
        library=library,
        fallback_for=str(item["fallback_for"]) if item.get("fallback_for") else None,
    )


def _load_ledger(ledger: Path | None) -> dict[str, dict[str, object]]:
    if ledger is None or not ledger.exists():
        return {}
    payload = json.loads(ledger.read_text())
    return {str(key): value for key, value in payload.items() if isinstance(value, dict)}


def _apply_overlay(rule: PatternRule, overlay: dict[str, object] | None) -> PatternRule:
    if not overlay:
        return rule
    status = str(overlay.get("status", rule.status))
    if status not in VALID_STATUS:
        status = rule.status
    return replace(
        rule,
        status=status,
        min_evidence_level=str(overlay.get("min_evidence_level", rule.min_evidence_level)),
        precision_estimate=float(overlay.get("precision_estimate", rule.precision_estimate)),  # type: ignore[arg-type]
    )


def _str_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def _s(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _arr(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_s(value) for value in values) + "]"
