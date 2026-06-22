from __future__ import annotations

import json
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

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


def load_ruleset(directory: Path = DEFAULT_RULESET_DIR, ledger: Path | None = None) -> tuple[PatternRule, ...]:
    """Load every ``*.toml`` rule file under ``directory`` and apply the loop ledger.

    Rules are returned sorted by ``rule_id`` for determinism. The optional ledger
    (``rule_policy.json``) overlays loop-owned ``status``/``min_evidence_level``/
    ``precision_estimate`` per ``rule_id``.
    """
    rules: dict[str, PatternRule] = {}
    for path in sorted(directory.rglob("*.toml")):
        payload = tomllib.loads(path.read_text())
        for item in payload.get("rule", []):
            rule = _rule_from_dict(item, path)
            if rule.rule_id in rules:
                raise RulesetError(f"duplicate rule_id {rule.rule_id!r} in {path}")
            rules[rule.rule_id] = rule
    overlay = _load_ledger(ledger)
    resolved = [_apply_overlay(rule, overlay.get(rule.rule_id)) for rule in rules.values()]
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
                    f"pattern = '''{rule.pattern}'''",
                ]
            )
        )
    path.write_text("\n\n".join(blocks) + "\n")


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
