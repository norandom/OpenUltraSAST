"""`verify` task (ai-service-plane task 6): the batched sink hunt of `benchmarks/independent/verify_batched.py`
moved into the package, metered and resumable.

One tool hunt per file for up to `PER_HUNT` candidates and `MAX_STEPS` steps; a verdict is anchored to the
candidate asked about (its file, function and line), the model's own location kept beside it. Two things are
new against the reference: each candidate's known call sites from `repo-facts` (Requirement 5.3) go into the
prompt, and every hunt records its tool turns and usage in `units.jsonl` (one row per file hunt, appended as it
completes, read back on start: Requirement 2.2). The chat client is wrapped by `MeteredClient` (Requirement
2.3/2.4): a ceiling ends the task `unfinished`, an account refusal ends it `failed`, and `summary.json` -- written
last -- names the bound Model (Requirement 7.2) and is `done` only when every unit finished.

Env contract: `OUSAST_WORKSPACE_DIR`, `OUSAST_OUTPUT_DIR`, `OUSAST_INPUT_CANDIDATES`, `OUSAST_INPUT_FACTS`
(optional), `OUSAST_BUDGET_USD`, `OUSAST_BUDGET_CALLS`, `OUSAST_MODEL`, `OUSAST_MODEL_PARAMS`, `OUSAST_PASS`.
Exit 0 done, 2 failed, 3 unfinished.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...tool_hunter import CLIENT_ENV, ChatClient, ChatResponse, resolve_hunter_client, run_tool_hunter, scripted_hunter_client
from ..budget import AccountError, BudgetExhausted, MeteredClient

PER_HUNT = 6
MAX_STEPS = 6
CALLERS_CAP = 8
EXIT_CODES = {"done": 0, "failed": 2, "unfinished": 3}
USAGE_FIELDS = ("prompt_tokens", "prompt_cache_hit_tokens", "completion_tokens")

# What each family's candidate operation does, in the words of `model_sinks.py` (the stage-1 classifier).
OPERATIONS = {
    "injection": (
        "executes a database query (SQL, NoSQL, JCR/graph query), an operating-system command or shell, code or "
        "expression evaluation (eval, exec, dynamic parsing into executable form), server-side template rendering "
        "from a template string, or deserialization"
    ),
    "untrusted_destination": "makes an outbound HTTP/network request, downloads a URL, or redirects the user to a URL",
    "config_secrets": (
        "sets security-relevant configuration: CORS policy, debug mode, TLS/certificate verification, cookie or "
        "session security, or embeds a secret, password or API key"
    ),
}
SYSTEM = (
    "You are a security reviewer with repository tools (read_file, grep_repo, find_refs). You are given several "
    "operations in ONE file, each named by its function. For EACH operation decide whether data an attacker "
    "controls -- HTTP request parameters, body, headers, cookies, uploaded or imported content, webhook or API "
    "payloads, values stored earlier from such input -- can reach it without a sufficient guard (validation or "
    "allowlisting, escaping that fits the exact context, parameterization, or a fixed destination). Use the tools "
    "to follow callers and data. Report an operation only if you can state the concrete path from the source to "
    "it. Answer with a JSON array: one object per vulnerable operation with path, line, function_name (exactly as "
    "listed), title and rationale (the source, each hop, and why no guard applies); [] if none is vulnerable or "
    "you cannot establish a path."
)

Candidate = tuple[str, str, int]


class _Recording:
    """Counts a hunt's tool turns on the way through to the metered client."""

    def __init__(self, client: ChatClient) -> None:
        self.client = client
        self.turns = 0
        self.calls = 0

    def complete(self, **kw: Any) -> ChatResponse:
        response = self.client.complete(**kw)
        self.calls += 1
        if response.tool_calls:
            self.turns += 1
        return response


def load_candidates(payload: object) -> tuple[str | None, list[Candidate]]:
    """(family, unique candidates) from a recorded candidate list: the `independent-v2-modelsinks` case record
    (`{"family", "candidates": [[path, function, line], ...]}`) or a bare list of such triples."""
    family: str | None = None
    rows: object = payload
    if isinstance(payload, Mapping):
        family = str(payload["family"]) if payload.get("family") else None
        rows = payload.get("candidates", [])
    if not isinstance(rows, list):
        raise ValueError("candidates must be a list of [path, function, line]")
    unique: dict[tuple[str, str], Candidate] = {}
    for row in sorted(rows, key=lambda r: (str(r[0]), str(r[1]), int(r[2] or 0) if len(r) > 2 else 0)):
        path, function = str(row[0]), str(row[1])
        line = int(row[2]) if len(row) > 2 and isinstance(row[2], int | float) else 0
        unique.setdefault((path, function), (path, function, line))
    return family, list(unique.values())


def callers_of(facts: Mapping[str, Any] | None, path: str, function: str) -> list[dict[str, Any]]:
    """Known call sites of `path::function` from `facts.json`: the task-5 shape (`callers` keyed by
    `path::function`, rows `{"path", "line", "enclosing"}`) or the design's per-file shape (`{path: {"callers":
    {function: [{"path", "line", "in"}]}}`)."""
    if not facts:
        return []
    rows: object = None
    callers = facts.get("callers")
    if isinstance(callers, Mapping):
        rows = callers.get(f"{path}::{function}")
    if rows is None:
        per_file = facts.get("files", facts)
        entry = per_file.get(path) if isinstance(per_file, Mapping) else None
        if isinstance(entry, Mapping) and isinstance(entry.get("callers"), Mapping):
            rows = entry["callers"].get(function)
    return [dict(r) for r in rows if isinstance(r, Mapping)] if isinstance(rows, list) else []


def callers_line(rows: Sequence[Mapping[str, Any]], cap: int = CALLERS_CAP) -> str:
    """`Known callers: a.py:12 in handler(), ...` (at most `cap`); empty when nothing is known, so the prompt
    only ever gains facts and never asserts an absence the extractor may have missed."""
    parts = []
    for row in rows[:cap]:
        enclosing = row.get("enclosing") or row.get("in") or ""
        where = f"{row.get('path', '?')}:{row.get('line', 0)}"
        parts.append(f"{where} in {enclosing}()" if enclosing else where)
    if not parts:
        return ""
    more = f", and {len(rows) - cap} more" if len(rows) > cap else ""
    return "Known callers: " + ", ".join(parts) + more


def hunt_prompt(path: str, group: Sequence[Candidate], family: str, facts: Mapping[str, Any] | None) -> str:
    lines = []
    for _, function, line in group:
        lines.append(f"- function `{function}` around line {line}")
        known = callers_line(callers_of(facts, path, function))
        if known:
            lines.append(f"  {known}")
    listing = "\n".join(lines)
    return (
        f"Operations to judge, all in `{path}`, each of which {OPERATIONS[family]}:\n{listing}\n"
        "The file is above. For each, trace where the operation's data comes from and whether it is guarded."
    )


def hunt(
    root: Path, path: str, group: Sequence[Candidate], family: str, *, client: ChatClient, model: str, facts: Mapping[str, Any] | None
) -> tuple[list[dict[str, Any]], int, int]:
    """One batched hunt: (flagged rows anchored to the candidates, tool turns, calls)."""
    from ...complexity.map import Hotspot

    recording = _Recording(client)
    spots = [
        Hotspot(
            path=path, function_name=fn, score=1.0, band="candidate", signals={}, rationale="model-classified sink",
            test_hint=None, inventory_finding_ids=(),
        )
        for _, fn, _ in group
    ]  # fmt: skip
    found = run_tool_hunter(
        root, spots, client=recording, model=model, max_steps=MAX_STEPS, system_prompt=SYSTEM,
        user_prompt=hunt_prompt(path, group, family, facts), context_files=[path], tags=("sink-verifier",),
    )  # fmt: skip
    names = {fn for _, fn, _ in group}
    rows = []
    for f in found:
        fn = f.function_name or ""
        if fn not in names:  # attribute by the nearest listed line when the model renamed the function
            fn = min(group, key=lambda c: abs((c[2] or 0) - (f.line or 0)))[1]
        # The verdict is about the candidate operation, so the site is the candidate's file and function; the
        # model's own location is kept beside it (it often names the file where the input enters instead).
        line = f.line if f.path == path else next(c[2] for c in group if c[1] == fn)
        rows.append({
            "candidate": f"{path}::{fn}", "site": f"{path}:{line or 0}:{fn}", "reported_at": f"{f.path}:{f.line or 0}",
            "family": family, "title": f.title, "witness": f.rationale[:600],
        })  # fmt: skip
    return rows, recording.turns, recording.calls


def units_of(candidates: Sequence[Candidate], per_hunt: int = PER_HUNT) -> list[tuple[str, list[Candidate]]]:
    by_file: dict[str, list[Candidate]] = {}
    for c in candidates:
        by_file.setdefault(c[0], []).append(c)
    return [(path, group[i : i + per_hunt]) for path, group in by_file.items() for i in range(0, len(group), per_hunt)]


def unit_key(path: str, group: Sequence[Sequence[object]]) -> tuple[str, tuple[str, ...]]:
    return path, tuple(str(c[1]) for c in group)


def read_units(log: Path) -> list[dict[str, Any]]:
    if not log.is_file():
        return []
    rows = []
    for text in log.read_text().splitlines():
        if text.strip():
            row = json.loads(text)
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _sum_usage(rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, int], int, float | None]:
    usage = dict.fromkeys(USAGE_FIELDS, 0)
    calls, usd, priced = 0, 0.0, True
    for row in rows:
        used = row.get("usage") or {}
        for field in USAGE_FIELDS:
            usage[field] += int(used.get(field) or 0)
        calls += int(used.get("calls") or 0)
        if row.get("usd") is None:
            priced = False
        else:
            usd += float(row["usd"])
    return usage, calls, (round(usd, 6) if priced else None)


def run(
    workspace: Path,
    output_dir: Path,
    candidates: object,
    facts: Mapping[str, Any] | None,
    *,
    client: ChatClient,
    budget: MeteredClient | None = None,
    model: str = "",
    pass_label: str = "a",
    family: str | None = None,
) -> dict[str, Any]:
    """Hunt every unfinished unit, append `units.jsonl` per hunt, write `summary.json` last; returns the summary.

    `budget` is the meter to run under (built from `client` when absent); `client` is what the meter wraps.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    log, summary_path = output_dir / "units.jsonl", output_dir / "summary.json"
    metered = budget if budget is not None else MeteredClient(client)
    model = model or getattr(metered, "model", "") or "unbound"
    recorded_family, unique = load_candidates(candidates)
    family = family or recorded_family
    units = units_of(unique)
    rows = read_units(log)
    done = {unit_key(r["path"], r["candidates"]): r for r in rows if "error" not in r}
    status, reason = "done", ""
    if family is None or family not in OPERATIONS:
        status, reason = "failed", f"unknown family {family!r}: expected one of {sorted(OPERATIONS)}"
        family = ""
    with log.open("a") as sink:
        for path, group in units if status == "done" else []:
            if unit_key(path, group) in done:
                continue
            before = (dict(metered.usage), metered.usd, metered.calls)
            row: dict[str, Any] = {"path": path, "candidates": [list(c) for c in group], "pass": pass_label}
            try:
                flagged, turns, _ = hunt(workspace, path, group, family, client=metered, model=model, facts=facts)
                row.update(flagged=flagged, turns=turns)
            except BudgetExhausted as stop:
                status, reason = "unfinished", str(stop)
                row["error"] = f"BudgetExhausted: {stop}"  # a hunt cut short is re-asked on resume
            except AccountError as refusal:
                status, reason = "failed", refusal.provider_message
                row["error"] = f"AccountError: {refusal.provider_message[:200]}"
            except Exception as error:  # noqa: BLE001 -- recorded, re-asked on resume; never a clean verdict
                row["error"] = f"{type(error).__name__}: {str(error)[:200]}"
            usage = {k: metered.usage[k] - before[0][k] for k in USAGE_FIELDS} | {"calls": metered.calls - before[2]}
            row.update(usage=usage, usd=(round(metered.usd - before[1], 8) if metered.usd is not None and before[1] is not None else None))
            if status != "done" and not usage["calls"]:
                break  # nothing was asked; no row to keep
            sink.write(json.dumps(row) + "\n")
            sink.flush()
            rows.append(row)
            if "error" not in row:
                done[unit_key(path, group)] = row
            if status != "done":
                break
    if status == "done" and len(done) < len(units):
        errors = [r["error"] for r in rows if "error" in r]
        status, reason = "unfinished", f"{len(units) - len(done)} of {len(units)} units not finished; errors: {errors[:5]}"
    usage, calls, usd = _sum_usage(rows)
    summary: dict[str, Any] = {
        "status": status, "units_done": len(done), "units_total": len(units), "usd": usd, "calls": calls, "usage": usage,
        "priced": metered.priced, "model": model, "pass": pass_label, "family": family,
    }  # fmt: skip
    if reason:
        summary["reason"] = reason
    summary_path.write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def _env_path(name: str, *, required: bool = True) -> Path | None:
    value = os.environ.get(name, "").strip()
    if not value:
        if required:
            raise ValueError(f"{name} is not set")
        return None
    return Path(value)


def _env_number(name: str, cast: Any) -> Any:
    value = os.environ.get(name, "").strip()
    return cast(value) if value else None


def build_client() -> ChatClient:
    flag = os.environ.get("OUSAST_CLIENT", "").strip().lower()
    if flag == "scripted":
        return scripted_hunter_client("scripted")
    client = resolve_hunter_client()
    if client is None:
        raise ValueError(f"no model client: set DEEPSEEK_API_KEY, OPENROUTER_API_KEY or {CLIENT_ENV}")
    return client


def _failed(output_dir: Path | None, reason: str, model: str, pass_label: str) -> dict[str, Any]:
    summary = {
        "status": "failed", "units_done": 0, "units_total": 0, "usd": None, "calls": 0, "usage": dict.fromkeys(USAGE_FIELDS, 0),
        "priced": False, "model": model, "pass": pass_label, "reason": reason,
    }  # fmt: skip
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def main() -> int:
    output_dir, model, pass_label = (
        _env_path("OUSAST_OUTPUT_DIR", required=False),
        os.environ.get("OUSAST_MODEL", ""),
        os.environ.get("OUSAST_PASS", "a"),
    )
    try:
        workspace = _env_path("OUSAST_WORKSPACE_DIR")
        candidates_path = _env_path("OUSAST_INPUT_CANDIDATES")
        facts_path = _env_path("OUSAST_INPUT_FACTS", required=False)
        if output_dir is None or workspace is None or candidates_path is None:
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        if not model:
            raise ValueError("OUSAST_MODEL is not set")
        params = json.loads(os.environ.get("OUSAST_MODEL_PARAMS", "") or "{}")
        candidates = json.loads(candidates_path.read_text())
        facts = json.loads(facts_path.read_text()) if facts_path is not None else None
        client = build_client()
        metered = MeteredClient(
            client, prices=params, budget_usd=_env_number("OUSAST_BUDGET_USD", float), budget_calls=_env_number("OUSAST_BUDGET_CALLS", int)
        )
        summary = run(
            workspace, output_dir, candidates, facts, client=client, budget=metered, model=model, pass_label=pass_label,
            family=os.environ.get("OUSAST_FAMILY") or None,
        )  # fmt: skip
    except Exception:  # noqa: BLE001 -- a crash is `failed` with its traceback, never a silent zero
        summary = _failed(output_dir, traceback.format_exc()[-2000:], model, pass_label)
    print(
        json.dumps({k: summary.get(k) for k in ("status", "units_done", "units_total", "usd", "calls", "model", "pass")}), file=sys.stderr
    )
    return EXIT_CODES.get(str(summary["status"]), 2)


__all__ = [
    "MAX_STEPS",
    "OPERATIONS",
    "PER_HUNT",
    "SYSTEM",
    "build_client",
    "callers_line",
    "callers_of",
    "hunt",
    "hunt_prompt",
    "load_candidates",
    "main",
    "run",
    "units_of",
]


if __name__ == "__main__":
    raise SystemExit(main())
