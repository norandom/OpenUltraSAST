"""`roles` (learned-decision-engine design section 2, Req 8.1): the model reads a repository's source and names its
roles -- no vocabulary, no framework table.

The source-only classification of `benchmarks/independent/model_sinks.py` moved into the package and extended
from sinks to every role: per product file chunk of numbered lines, which call sites perform a ``sink`` operation of
a closed kind on non-constant data, read a ``source`` of attacker input, ``sanitizer`` (escape or cleanse) a value,
``guard`` (check and reject) it, or ``dispatch`` it through a string-keyed registry. Each role carries its function,
line, the call, an operation (:data:`..learn.schema.OPERATIONS` for sinks, :data:`..learn.schema.SOURCE_KINDS` for
sources) and a one-line evidence quote. A chunk whose call fails or whose answer does not parse is
**unclassified**, never "no roles" (the `model_sinks.py` rule): its path is listed in ``roles.json``
``unclassified_paths`` and the ``model_sinks`` feature of a function there is ``failed`` unless the model flagged it.

Units are files: a row goes to ``units.jsonl`` as each file finishes, and a restart skips the files already there.
The chat client is injected (``run(client=...)``) and metered (`MeteredClient`): a ceiling ends the task
``unfinished``, an account refusal ``failed``. ``roles.json`` and ``summary.json`` are written last.

Env: ``OUSAST_WORKSPACE_DIR``, ``OUSAST_OUTPUT_DIR``, ``OUSAST_MODEL``, ``OUSAST_MODEL_PARAMS``, ``OUSAST_BUDGET_USD``,
``OUSAST_BUDGET_CALLS``, optional ``OUSAST_INPUT_FILES`` (a JSON list of workspace-relative paths: ``pre-push``
classifies only the changed files and the definitions they call), optional ``OUSAST_CHUNK_LINES``. Exit 0 done,
2 failed, 3 unfinished.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...learn.roles import MODEL_ROLE_KINDS
from ...learn.schema import OPERATIONS, SOURCE_KINDS
from ...tool_hunter import ChatClient
from ..budget import AccountError, BudgetExhausted, MeteredClient
from .repo_facts import GLOBAL, product_files
from .verify import build_client

CHUNK_LINES = 400
EXIT_CODES = {"done": 0, "failed": 2, "unfinished": 3}
USAGE_FIELDS = ("prompt_tokens", "prompt_cache_hit_tokens", "completion_tokens")
MAX_EVIDENCE = 200
PROMPT = (
    "You are auditing source code. List every call site in the code below that plays one of these roles, where the "
    "value involved is not a compile-time constant:\n"
    "- sink: performs an operation of kind " + ", ".join(o for o in OPERATIONS if o != "other") + " (or other);\n"
    "- source: reads attacker-controllable input (kind "
    + ", ".join(k for k in SOURCE_KINDS if k not in ("inferred_role", "prior"))
    + ");\n"
    "- sanitizer: escapes, encodes or cleanses a value for one of those operations;\n"
    "- guard: checks a value and rejects it (allow-list, permission or ownership check);\n"
    "- dispatch: registers or invokes a callback through a string-keyed registry (hooks, events, signals).\n"
    "Answer with JSON only: "
    '{{"roles": [{{"role": "<sink|source|sanitizer|guard|dispatch>", "function": "<enclosing function, or <global>>", '
    '"line": <line number>, "call": "<the call or expression>", "operation": "<the kind>", '
    '"evidence": "<the line, quoted>"}}]}}. Return {{"roles": []}} if there is none.\n\nFile: {path}\n\n{code}'
)


def chunks(text: str, size: int = CHUNK_LINES) -> list[str]:
    """Numbered chunks of ``size`` lines (line numbers are the file's)."""
    lines = text.splitlines()
    return [
        "\n".join(f"{n + 1:5d}| {line}" for n, line in enumerate(lines[i : i + size], start=i)) for i in range(0, max(len(lines), 1), size)
    ]


def parse_roles(content: str | None, path: str) -> list[dict[str, Any]]:
    """The roles of one answer, checked: a closed role and operation, an int line, text trimmed. Raises on an answer
    that is not the JSON object asked for (the chunk is then unclassified)."""
    payload = json.loads(content or "")
    items = payload.get("roles") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ValueError("the answer has no roles list")
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict) or item.get("role") not in MODEL_ROLE_KINDS or not isinstance(item.get("call"), str):
            continue
        vocabulary = SOURCE_KINDS if item["role"] == "source" else OPERATIONS
        operation = item.get("operation") if item.get("operation") in vocabulary else "other"
        named = item.get("function")
        function = named.strip() if isinstance(named, str) and named.strip() else GLOBAL
        line = item["line"] if isinstance(item.get("line"), int) else 0
        out.append(
            {
                "path": path, "role": item["role"], "function": function, "line": line,
                "call": item["call"].strip()[:MAX_EVIDENCE], "operation": operation,
                "evidence": str(item.get("evidence") or "")[:MAX_EVIDENCE],
            }
        )  # fmt: skip
    return out


def classify(root: Path, path: str, *, client: ChatClient, model: str, chunk_lines: int = CHUNK_LINES) -> dict[str, Any]:
    """One file: its roles, and how many chunks were asked and left unclassified. `BudgetExhausted` and
    `AccountError` propagate (the task stops); any other failure of a chunk leaves it unclassified."""
    text = (root / path).read_text(encoding="utf-8", errors="replace")
    roles: list[dict[str, Any]] = []
    asked = unclassified = 0
    for code in chunks(text, chunk_lines):
        asked += 1
        try:
            response = client.complete(
                model=model, messages=[{"role": "user", "content": PROMPT.format(path=path, code=code)}], tools=[], timeout_seconds=90,
                json_object=True,
            )  # fmt: skip
            roles += parse_roles(response.content, path)
        except (BudgetExhausted, AccountError):
            raise
        except Exception:  # noqa: BLE001 -- counted as unclassified, never as "no roles"
            unclassified += 1
    return {"path": path, "roles": roles, "chunks": asked, "unclassified": unclassified}


def _read_units(log: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    if log.is_file():
        for text in log.read_text(encoding="utf-8").splitlines():
            if text.strip():
                row = json.loads(text)
                if isinstance(row, dict) and "error" not in row:
                    rows[str(row["path"])] = row
    return rows


def assemble(rows: Mapping[str, Mapping[str, Any]], model: str) -> dict[str, Any]:
    """``roles.json`` from the per-file rows: roles sorted, the paths with an unclassified chunk, counts."""
    roles = sorted((r for row in rows.values() for r in row.get("roles") or ()), key=lambda r: (r["path"], r["line"], r["role"], r["call"]))
    unclassified = sorted(path for path, row in rows.items() if int(row.get("unclassified") or 0))
    counts: dict[str, int] = {}
    for role in roles:
        counts[role["role"]] = counts.get(role["role"], 0) + 1
    return {
        "model": model, "roles": roles, "unclassified_paths": unclassified, "counts": dict(sorted(counts.items())), "files": len(rows),
        "chunks": sum(int(r.get("chunks") or 0) for r in rows.values()),
        "unclassified_chunks": sum(int(r.get("unclassified") or 0) for r in rows.values()),
    }  # fmt: skip


def run(
    workspace: Path,
    output_dir: Path,
    *,
    client: ChatClient,
    budget: MeteredClient | None = None,
    model: str = "",
    files: Sequence[str] | None = None,
    chunk_lines: int = CHUNK_LINES,
) -> dict[str, Any]:
    """Classify every unfinished file (``files``, default every product file), append ``units.jsonl`` per file, write
    ``roles.json`` and ``summary.json`` last; returns the summary."""
    output_dir.mkdir(parents=True, exist_ok=True)
    log = output_dir / "units.jsonl"
    metered = budget if budget is not None else MeteredClient(client)
    model = model or "unbound"
    wanted = sorted(set(files)) if files is not None else [p.relative_to(workspace).as_posix() for p in product_files(workspace)]
    missing = [p for p in wanted if not (workspace / p).is_file()]
    done = {p: row for p, row in _read_units(log).items() if p in wanted}
    status, reason = ("failed", f"files not in the workspace: {missing[:5]}") if missing else ("done", "")
    with log.open("a", encoding="utf-8") as sink:
        for path in wanted if status == "done" else []:
            if path in done:
                continue
            before = (dict(metered.usage), metered.usd, metered.calls)
            try:
                row = classify(workspace, path, client=metered, model=model, chunk_lines=chunk_lines)
            except BudgetExhausted as stop:
                status, reason = "unfinished", str(stop)
                break
            except AccountError as refusal:
                status, reason = "failed", refusal.provider_message
                break
            usage = {k: metered.usage[k] - before[0][k] for k in USAGE_FIELDS} | {"calls": metered.calls - before[2]}
            row.update(usage=usage, usd=(round(metered.usd - before[1], 8) if metered.usd is not None and before[1] is not None else None))
            sink.write(json.dumps(row, sort_keys=True) + "\n")
            sink.flush()
            done[path] = row
    if status == "done" and len(done) < len(wanted):
        status, reason = "unfinished", f"{len(wanted) - len(done)} of {len(wanted)} files not classified"
    roles = assemble(done, model)
    (output_dir / "roles.json").write_text(json.dumps(roles, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    usd_values = [row.get("usd") for row in done.values()]
    summary: dict[str, Any] = {
        "status": status, "units_done": len(done), "units_total": len(wanted),
        "usd": round(sum(float(u) for u in usd_values if u is not None), 6) if all(u is not None for u in usd_values) else None,
        "calls": sum(int((row.get("usage") or {}).get("calls") or 0) for row in done.values()), "priced": metered.priced, "model": model,
        "roles": roles["counts"], "unclassified_chunks": roles["unclassified_chunks"], "chunks": roles["chunks"],
    }  # fmt: skip
    if reason:
        summary["reason"] = reason
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    output = os.environ.get("OUSAST_OUTPUT_DIR", "").strip()
    model = os.environ.get("OUSAST_MODEL", "")
    try:
        workspace = Path(os.environ.get("OUSAST_WORKSPACE_DIR", "").strip() or "")
        if not output:
            raise ValueError("OUSAST_OUTPUT_DIR is not set")
        if not os.environ.get("OUSAST_WORKSPACE_DIR") or not workspace.is_dir():
            raise ValueError(f"OUSAST_WORKSPACE_DIR is not a directory: {workspace}")
        if not model:
            raise ValueError("OUSAST_MODEL is not set")
        params = json.loads(os.environ.get("OUSAST_MODEL_PARAMS", "") or "{}")
        files_env = os.environ.get("OUSAST_INPUT_FILES", "").strip()
        files = [str(p) for p in json.loads(Path(files_env).read_text(encoding="utf-8"))] if files_env else None
        budget_usd, budget_calls = os.environ.get("OUSAST_BUDGET_USD", "").strip(), os.environ.get("OUSAST_BUDGET_CALLS", "").strip()
        client = build_client()
        metered = MeteredClient(
            client,
            prices=params,
            budget_usd=float(budget_usd) if budget_usd else None,
            budget_calls=int(budget_calls) if budget_calls else None,
        )
        chunk_lines = int(os.environ.get("OUSAST_CHUNK_LINES", "") or CHUNK_LINES)
        summary = run(workspace, Path(output), client=client, budget=metered, model=model, files=files, chunk_lines=chunk_lines)
    except Exception:  # noqa: BLE001 -- a crash is `failed` with its traceback, never a silent zero
        summary = {
            "status": "failed",
            "units_done": 0,
            "units_total": 0,
            "usd": None,
            "calls": 0,
            "model": model,
            "reason": traceback.format_exc()[-2000:],
        }
        if output:
            Path(output).mkdir(parents=True, exist_ok=True)
            (Path(output) / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: summary.get(k) for k in ("status", "units_done", "units_total", "usd", "calls", "model")}), file=sys.stderr)
    return EXIT_CODES.get(str(summary["status"]), 2)


__all__ = ["CHUNK_LINES", "PROMPT", "assemble", "chunks", "classify", "main", "parse_roles", "run"]


if __name__ == "__main__":
    raise SystemExit(main())
