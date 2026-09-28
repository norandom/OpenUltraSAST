"""Diagnostic: does a MODEL, reading source, find the operations the sink vocabulary misses?

Sink-first selection with the shipped vocabulary put the vulnerable function in scope in 2 of 17 v2 cases: the
real sinks (wp_redirect, download_url, spawn, ky, Session.get, parse_expr, Jinja render, Mongo find, JCR
createQuery, ...) are not in any token list, and each population brings new ones. This asks the model instead,
with no vocabulary: per product source file, which functions perform the family's dangerous operation on data
that may not be constant. Candidates are scored exactly as `sink_candidates.py` scores the vocabulary.

Source only. Files: the case's languages, product code (tests, docs, examples, vendored trees, minified bundles
and files over 200 kB excluded), sent in chunks of `--chunk-lines` numbered lines. A chunk whose call fails is
counted as UNCLASSIFIED, never as "no sinks". Hard spend ceiling `--budget-usd`; DeepSeek (`deepseek-flash`).

v2 is spent for tuning; this informs the selection design and qualifies nothing.

Usage: python benchmarks/independent/model_sinks.py [--population population-v2.toml] [--only ID,...]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import shutil
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evaluate  # noqa: E402

from openultrasast.config import load_config  # noqa: E402
from openultrasast.model.endpoint import DEFAULT_DETECTOR_MODEL  # noqa: E402
from openultrasast.preprocess import detect_language, enumerate_source_files  # noqa: E402

NOT_PRODUCT = re.compile(r"(^|/)(tests?|__tests__|spec|specs|docs?|examples?|fixtures?|e2e|cypress|storybook)/|\.(test|spec|stories)\.[jt]sx?$|_test\.py$|(^|/)test_[^/]*\.py$|\.min\.js$|(^|/)dist/|(^|/)build/")
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
PROMPT = (
    "You are auditing source code. List every function in the code below that {operation}, where the query, "
    "command, expression, template, URL or setting is not a compile-time constant. Answer with JSON only: "
    '{{"functions": [{{"function": "<name, or <global> for top-level code>", "line": <line number>, '
    '"operation": "<the call>"}}]}}. Return {{"functions": []}} if there is none.\n\nFile: {path}\n\n{code}'
)


def product_files(root: Path, languages: set[str]) -> list[Path]:
    files = []
    for path in enumerate_source_files(root):
        relative = path.relative_to(root).as_posix()
        if detect_language(path) in languages and not NOT_PRODUCT.search(relative) and path.stat().st_size <= 200_000:
            files.append(path)
    return files


def chunks(text: str, size: int) -> list[str]:
    lines = text.splitlines()
    return ["\n".join(f"{n + 1:5d}| {line}" for n, line in enumerate(lines[i : i + size], start=i)) for i in range(0, max(len(lines), 1), size)]


class Meter:
    def __init__(self, ceiling: float) -> None:
        self.ceiling, self.clients, self.lock = ceiling, [], threading.Lock()

    def add(self, client: object) -> None:
        with self.lock:
            self.clients.append(client)

    def spent(self) -> float:
        with self.lock:
            return sum(float(c.cost_usd()) for c in self.clients)


def classify(root: Path, path: Path, family: str, args: argparse.Namespace, meter: Meter, local: threading.local) -> tuple[list[tuple[str, str, int]], int, int]:
    from openultrasast import tool_hunter

    if not hasattr(local, "client"):
        local.client = tool_hunter.resolve_hunter_client()
        meter.add(local.client)
    relative = path.relative_to(root).as_posix()
    found, failed, asked = [], 0, 0
    for code in chunks(path.read_text(errors="ignore"), args.chunk_lines):
        if meter.spent() >= args.budget_usd:
            return found, failed + 1, asked
        asked += 1
        prompt = PROMPT.format(operation=OPERATIONS[family], path=relative, code=code)
        try:
            response = local.client.complete(model=args.model, messages=[{"role": "user", "content": prompt}], tools=[], timeout_seconds=90, json_object=True)
            items = json.loads(response.content or "{}").get("functions", [])
        except Exception:  # noqa: BLE001 -- counted as unclassified, never as "no sinks"
            failed += 1
            continue
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and isinstance(item.get("function"), str):
                line = item.get("line") if isinstance(item.get("line"), int) else 0
                found.append((relative, item["function"].strip() or "<global>", line))
    return found, failed, asked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--population", type=Path, default=HERE / "population-v2.toml")
    parser.add_argument("--only", default="")
    parser.add_argument("--model", default=DEFAULT_DETECTOR_MODEL)
    parser.add_argument("--chunk-lines", type=int, default=400)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--budget-usd", type=float, default=8.0)
    args = parser.parse_args()
    load_config()  # the project's .env: DeepSeek is the chat provider
    evaluate.use(args.population)
    evaluate.RESULTS = evaluate.RESULTS.with_name(evaluate.RESULTS.name + "-modelsinks")
    evaluate.RESULTS.mkdir(parents=True, exist_ok=True)
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    meter, local, rows = Meter(args.budget_usd), threading.local(), []
    for case in evaluate.cases():
        if only and case["id"] not in only:
            continue
        if meter.spent() >= args.budget_usd:
            print(json.dumps({"stopped": "budget", "spent_usd": round(meter.spent(), 4)}), flush=True)
            break
        started, before = time.monotonic(), meter.spent()
        checkout = evaluate.export(case, "vulnerable", case["vulnerable"])
        try:
            files = product_files(checkout, {case["language"], *case.get("also", [])})
            found, failed, asked = [], 0, 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                for f, fail, ask in pool.map(lambda p: classify(checkout, p, case["family"], args, meter, local), files):
                    found += f
                    failed += fail
                    asked += ask
        finally:
            shutil.rmtree(checkout, ignore_errors=True)
        functions = {(p, fn) for p, fn, _ in found}
        changed = set(evaluate.hunks(case, "old"))
        sites = {tuple(site.split("::", 1)) for site in case.get("sites", [])}
        row = {
            "id": case["id"], "family": case["family"], "files": len(files), "chunks": asked, "unclassified_chunks": failed,
            "candidate_functions": len(functions), "candidate_files": len({p for p, _ in functions}),
            "declared_site_in_candidates": sorted(f"{p}::{fn}" for p, fn in functions if (p, fn) in sites),
            "fix_or_site_file_in_candidates": sorted({p for p, _ in functions if p in changed or p in {s[0] for s in sites}})[:5],
            "usd": round(meter.spent() - before, 4), "seconds": round(time.monotonic() - started, 1),
        }  # fmt: skip
        (evaluate.RESULTS / f"{case['id']}.json").write_text(json.dumps({**row, "candidates": sorted(found)}, indent=1) + "\n")
        rows.append(row)
        print(json.dumps(row), flush=True)
    print(
        json.dumps(
            {
                "cases": len(rows),
                "declared_site_in_candidates": sum(bool(r["declared_site_in_candidates"]) for r in rows),
                "fix_or_site_file_in_candidates": sum(bool(r["fix_or_site_file_in_candidates"]) for r in rows),
                "spent_usd": round(meter.spent(), 4),
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
