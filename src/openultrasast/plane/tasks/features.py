"""`features` (learned-decision-engine design section 1): one feature record per candidate of a case. No model.

Budget ``{usd: 0, calls: 0}``, one per case, after ``final`` (and ``alerts`` in a loop Run). A candidate is a
``(path, function, family)`` that the verify passes asked about or a vulnerable-pin alert named. It reads:

- ``facts.json`` (repo-facts callers), the verify passes' ``units.jsonl`` a, b, c and their ``summary.json`` (the
  model id is the verify instrument's version), the final ``agreed.json`` -- with ``site_match`` dropped on read;
- in a loop, ``alerts.jsonl`` -- vulnerable-pin rows only, ``in_fix_range`` dropped: a deployed scan has no fixed pin
  and no fix -- and the alerts' ``summary.json`` (coverage per language, the engine's questions and degradations);
- the bound checkout (``OUSAST_WORKSPACE_DIR``) for the function's span and its entry-point distance.

It writes ``features.jsonl`` (records validated by :func:`..learn.schema.validate_record`, the `plane` profile) and
``summary.json``; ``remember`` turns the records into ``features`` rows. An instrument without coverage for the
candidate's language is ``none``, one that did not read its input ``failed``: never a zero (Req 1.2). The task fails
when every instrument it could have used failed.

Env: ``OUSAST_OUTPUT_DIR``, ``OUSAST_INPUT_FACTS`` (and ``OUSAST_INPUT_FACTS_SUMMARY``), ``OUSAST_INPUT_PASS_A``/``_B``/``_C``,
``OUSAST_INPUT_SUMMARY_A``/``_B``/``_C``, ``OUSAST_INPUT_AGREED``, optional ``OUSAST_INPUT_ALERTS`` and
``OUSAST_INPUT_ALERTS_SUMMARY``, optional ``OUSAST_WORKSPACE_DIR``. Exit 0 done, 2 failed. On the host,
:func:`case_features` does the same over a recorded run directory.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...learn.features import (
    NONE,
    NOT_APPLICABLE,
    Part,
    SourceIndex,
    Vocabulary,
    agree_part,
    engine_part,
    entry_distance,
    entry_names,
    facts_part,
    quick_part,
    record,
    ruleset_digest,
    source_part,
    verify_part,
)
from ...model.taxonomy import load_families
from ...preprocess import detect_language
from ...ruleset import DEFAULT_RULESET_DIR, PatternRule, load_ruleset
from .alerts import covers
from .repo_facts import GLOBAL

OUTPUT = "features.jsonl"
PASSES = ("a", "b", "c")
ENGINE_PREFIX = "engine:"
# Read, never passed on: label information (the declared site, the fix) and the fixed pin.
DROPPED_ON_READ = ("site_match", "in_fix_range")


def _drop(row: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in DROPPED_ON_READ}


def _family(rule: PatternRule | None) -> str:
    family = load_families().family_of_cwe(rule.cwe) if rule is not None else None
    return family.id if family is not None else "unknown"


def _line(site: object) -> int | None:
    parts = str(site or "").split(":")
    return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None


def _final(row: Mapping[str, Any], disputed: set[str]) -> str:
    if row.get("agreed"):
        return "agreed"
    return "disputed" if str(row["candidate"]) in disputed else "rejected"


def _quick(
    summary: Mapping[str, Any] | None, language: str, hits: list[tuple[str, str]], rules: Mapping[str, PatternRule], version: str
) -> Part:
    if summary is None:
        return NONE
    if summary.get("status") not in (None, "done"):
        return Part("failed")
    if not covers(summary.get("quick_languages") or (), language):
        return NONE
    return quick_part(hits, rules, version)


def _engine(summary: Mapping[str, Any] | None, language: str, rows: list[dict[str, Any]], vocabulary: Vocabulary) -> Part:
    if summary is None or language not in (summary.get("engine_languages") or ()):
        return NONE
    run = (summary.get("engine") or {}).get("vulnerable")
    if not isinstance(run, Mapping):
        return NONE
    questions, completed = int(run.get("questions") or 0), int(run.get("completed") or 0)
    if questions <= 0 or int(run.get("files") or 0) <= 0:
        return Part("failed", version=summary.get("image"))
    return engine_part(
        rows, completion=completed / questions, degraded=bool(run.get("degradations")), vocabulary=vocabulary, version=summary.get("image")
    )


def case_features(
    *,
    facts: Mapping[str, Any] | None,
    passes: Mapping[str, Sequence[Mapping[str, Any]]],
    models: Mapping[str, str | None],
    agreed: Mapping[str, Any] | None,
    alerts: Sequence[Mapping[str, Any]] = (),
    alerts_summary: Mapping[str, Any] | None = None,
    workspace: Path | None = None,
    rules: Sequence[PatternRule] | None = None,
    facts_summary: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """The `plane` records of one case, sorted by (candidate, family). Versions: the ruleset digest (quick), the
    engine image (engine), the image the facts were computed on (facts), the verify model ids (verify)."""
    loaded = tuple(rules) if rules is not None else load_ruleset(DEFAULT_RULESET_DIR)
    by_id = {rule.rule_id: rule for rule in loaded}
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    verdicts = [_drop(c) for c in (agreed or {}).get("candidates") or []]
    disputed = {str(d["candidate"]) for d in (agreed or {}).get("disputed") or []}
    for row in verdicts:
        family = str((row.get("finding") or {}).get("family") or (agreed or {}).get("family") or "unknown")
        entry = candidates.setdefault((str(row["candidate"]), family), {"line": _line(row.get("site")), "quick": [], "engine": []})
        entry["final"] = _final(row, disputed)
    for alert in (_drop(a) for a in alerts):
        if alert.get("pin_role") != "vulnerable":
            continue  # a deployed scan has no fixed pin
        rule_id = str(alert.get("rule_id") or "")
        engine = rule_id.startswith(ENGINE_PREFIX)
        family = rule_id.removeprefix(ENGINE_PREFIX) if engine else _family(by_id.get(rule_id))
        key = (f"{alert.get('path')}::{alert.get('function') or GLOBAL}", family)
        entry = candidates.setdefault(key, {"line": alert.get("line"), "quick": [], "engine": []})
        if engine:
            entry["engine"].append({"site": f"{alert.get('path')}:{alert.get('line')}"})
        else:
            entry["quick"].append((rule_id, str(alert.get("rule_status") or "enabled")))
    callers = (facts or {}).get("callers") or {}
    index = SourceIndex(workspace) if workspace is not None and workspace.is_dir() else None
    entries: tuple[set[str], set[str]] | None = None
    quick_version = ruleset_digest(loaded)
    vocabularies: dict[str, Vocabulary] = {}
    reused = (facts_summary or {}).get("reused")
    facts_image = (reused.get("image") if isinstance(reused, Mapping) else None) or (facts_summary or {}).get("image")
    facts_version = str(facts_image) if facts_image else None
    verify_version = "+".join(sorted({m for m in models.values() if m})) or None
    out: list[dict[str, Any]] = []
    for (candidate, family), entry in sorted(candidates.items()):
        path, _, function = candidate.partition("::")
        language = detect_language(Path(path))
        vocabulary = vocabularies.setdefault(language, Vocabulary.load(language))
        parts: dict[str, Part] = {
            "quick": _quick(alerts_summary, language, entry["quick"], by_id, quick_version),
            "engine": _engine(alerts_summary, language, entry["engine"], vocabulary),
            "facts": facts_part(callers[candidate], function, facts_version) if candidate in callers else NONE,
            "delta": NOT_APPLICABLE,
            "verify": verify_part(passes, candidate, entry["line"], verify_version),
            "agree": agree_part(entry.get("final")),
        }
        if index is not None:
            if entries is None:
                entries = entry_names(index.root, {c.partition("::")[0] for c, _ in candidates})
            parts["source"] = source_part(index.lines(path), language, function)
            distance = 0 if function == GLOBAL and path in entries[1] else entry_distance(function, entries[0], index.callers())
            parts["entry_points"] = Part("ran", {"facts.entry_distance": distance})
        out.append(record(candidate, family, language, "plane", parts))
    return out


def _jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _json(path: Path | None) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path is not None and path.is_file() else None


def _model(summary: object) -> str | None:
    return str(summary["model"]) if isinstance(summary, dict) and summary.get("model") else None


def recorded_case(base: Path, case: str, workspace: Path | None = None) -> list[dict[str, Any]]:
    """:func:`case_features` over a recorded run directory's artifacts (the final ``agreed.json`` when present)."""
    final = base / f"{case}-final" / "agreed.json"
    return case_features(
        facts=_json(base / f"{case}-facts" / "facts.json"),
        passes={p: _jsonl(base / f"{case}-v{p}" / "units.jsonl") for p in PASSES},
        models={p: _model(_json(base / f"{case}-v{p}" / "summary.json")) for p in PASSES},
        agreed=_json(final if final.is_file() else base / f"{case}-agree" / "agreed.json"),
        alerts=_jsonl(base / f"{case}-alerts" / "alerts.jsonl"),
        alerts_summary=_json(base / f"{case}-alerts" / "summary.json"),
        workspace=workspace,
        facts_summary=_json(base / f"{case}-facts" / "summary.json"),
    )


def _path(env: Mapping[str, str], name: str) -> Path | None:
    return Path(env[name]) if env.get(name) else None


def _units(path: Path | None) -> list[dict[str, Any]]:
    return _jsonl(path / "units.jsonl" if path is not None and path.is_dir() else path)


def _states(records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for rec in records:
        for name, info in rec["instruments"].items():
            counts.setdefault(name, {}).setdefault(info["state"], 0)
            counts[name][info["state"]] += 1
    return dict(sorted(counts.items()))


def main(environ: Mapping[str, str] | None = None) -> int:
    env = environ if environ is not None else os.environ
    output_dir = _path(env, "OUSAST_OUTPUT_DIR")
    summary: dict[str, Any] = {"status": "failed", "units_done": 0, "units_total": 1, "usd": 0, "calls": 0, "usage": {}, "model": None}
    try:
        if output_dir is None:
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        output_dir.mkdir(parents=True, exist_ok=True)
        workspace = _path(env, "OUSAST_WORKSPACE_DIR")
        records = case_features(
            facts=_json(_path(env, "OUSAST_INPUT_FACTS")),
            passes={p: _units(_path(env, f"OUSAST_INPUT_PASS_{p.upper()}")) for p in PASSES},
            models={p: _model(_json(_path(env, f"OUSAST_INPUT_SUMMARY_{p.upper()}"))) for p in PASSES},
            agreed=_json(_path(env, "OUSAST_INPUT_AGREED")),
            alerts=_jsonl(_path(env, "OUSAST_INPUT_ALERTS")),
            alerts_summary=_json(_path(env, "OUSAST_INPUT_ALERTS_SUMMARY")),
            workspace=workspace,
            facts_summary=_json(_path(env, "OUSAST_INPUT_FACTS_SUMMARY")),
        )
        states = _states(records)
        used = {name: n for name, n in states.items() if name not in ("language", "delta") and set(n) - {"none"}}
        if records and used and all(set(n) == {"failed"} for n in used.values()):
            raise ValueError(f"every instrument failed for this case: {used}")
        (output_dir / OUTPUT).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8")
        summary.update(status="done", units_done=1, records=len(records), instruments=states)
    except Exception:  # noqa: BLE001 -- a crash is `failed` with its traceback
        summary["reason"] = traceback.format_exc()[-2000:]
    if output_dir is not None:
        (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: summary.get(k) for k in ("status", "records")}), file=sys.stderr)
    return 0 if summary["status"] == "done" else 2


__all__ = ["DROPPED_ON_READ", "case_features", "main", "recorded_case"]


if __name__ == "__main__":
    raise SystemExit(main())
