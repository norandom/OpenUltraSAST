"""Run and score the pre-registered evaluation of the independent population (protocol-v1.md).

`run` exports each case's four pins (vulnerable, fixed, benign base, benign tip) with `git archive` and scans each
for the case's family through the production scan (`benchmarks/push/finding_dump.py`) inside the shipped image,
one container at a time. It is resumable: a scan whose result exists is not repeated. A scan that asked no
question is an instrument failure and is retried once.

`score` applies protocol-v1.md exactly -- matching, detection, fixed-side and benign false alerts, unanswered --
and draws the precision sample (every third pooled vulnerable-pin finding, or all of them if 15 or fewer).

Protocol v2 (protocol-v2.md, population-v2.toml) scans the vulnerable and fixed pins twice each and credits a
finding at a declared site as well; `--population population-v2.toml` selects it for both commands.

Usage:
    python benchmarks/independent/evaluate.py run --source <frozen analyzer tree> [--only ID,...] [--population F]
    python benchmarks/independent/evaluate.py score [--population F]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
POPULATION = HERE / "population-v1.toml"
CACHE = Path.home() / ".cache" / "openultrasast" / "independent"
RESULTS = Path.home() / "ousast-results" / "independent-v1"
DEADLINE = 2400
LINE_WINDOW = 10


def cases() -> list[dict]:
    return tomllib.loads(POPULATION.read_text())["case"]


def version() -> str:
    return POPULATION.stem.removeprefix("population-")


def use(population: Path) -> None:
    """Point the module at a population file and its own results directory."""
    global POPULATION, RESULTS
    POPULATION = population if population.is_absolute() else HERE / population.name
    RESULTS = Path.home() / "ousast-results" / f"independent-{version()}"


def pins(case: dict) -> dict[str, str]:
    if version() != "v1":
        # Protocol v2: the vulnerable and fixed pins twice each, the benign pair once.
        return {
            "vulnerable_a": case["vulnerable"],
            "vulnerable_b": case["vulnerable"],
            "fixed_a": case["fixed"],
            "fixed_b": case["fixed"],
            "benign_base": case["benign"]["base"],
            "benign_tip": case["benign"]["tip"],
        }
    return {
        "vulnerable": case["vulnerable"],
        "fixed": case["fixed"],
        "benign_base": case["benign"]["base"],
        "benign_tip": case["benign"]["tip"],
    }


def export(case: dict, label: str, commit: str) -> Path:
    target = RESULTS / "checkouts" / case["id"] / label
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    archive = target.parent / f"{label}.tar"
    with archive.open("wb") as stream:
        subprocess.run(["git", "-C", str(CACHE / case["id"]), "archive", commit], stdout=stream, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(target)], check=True)
    archive.unlink()
    if not any(target.rglob("*")):
        raise RuntimeError(f"{case['id']} {label}: the export is empty")
    return target


def scan(case: dict, label: str, checkout: Path, source: Path, out: Path) -> dict:
    command = [
        "docker", "run", "--rm", "--init", "--network", "none", "--memory", "3g", "--entrypoint", "python",
        "-e", "OUSAST_LOG_LEVEL=WARNING", "-e", "PYTHONPATH=/new/src",
        "-v", f"{source / 'src'}:/new/src:ro",
        "-v", f"{source / 'benchmarks' / 'push' / 'finding_dump.py'}:/dump.py:ro",
        "-v", f"{checkout}:/case:ro", "-v", f"{out.parent}:/out",
        "openultrasast:dev", "/dump.py", "--root", "/case", "--families", case["family"],
        "--out", f"/out/{out.name}", "--deadline", str(DEADLINE), "--max-regions", "5000",
    ]  # fmt: skip
    completed = subprocess.run(command, capture_output=True, text=True, timeout=DEADLINE + 900, check=False)
    (out.parent / f"{out.stem}.log").write_text((completed.stdout or "") + "\n" + (completed.stderr or "")[-20000:])
    if not out.is_file():
        return {"instrument_error": f"no result (exit {completed.returncode})"}
    result = json.loads(out.read_text())
    if not result.get("questions"):
        return {"instrument_error": "no question was asked"}
    return result


def run(args: argparse.Namespace) -> int:
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    for case in cases():
        if only and case["id"] not in only:
            continue
        for label, commit in pins(case).items():
            out = RESULTS / "scans" / f"{case['id']}--{label}.json"
            if out.is_file():
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            for attempt in (1, 2):
                checkout = export(case, label, commit)
                result = scan(case, label, checkout, args.source, out)
                shutil.rmtree(checkout, ignore_errors=True)
                if "instrument_error" not in result:
                    break
                print(json.dumps({"case": case["id"], "pin": label, "attempt": attempt, **result}), flush=True)
                out.unlink(missing_ok=True)
            else:
                out.write_text(json.dumps({"instrument_error": result["instrument_error"], "questions": 0, "findings": []}) + "\n")
            summary = json.loads(out.read_text())
            keys = ("questions", "completed", "seconds")
            progress = {"case": case["id"], "pin": label, "findings": len(summary.get("findings", [])), **{k: summary.get(k) for k in keys}}
            print(json.dumps(progress), flush=True)
    return 0


def hunks(case: dict, side: str) -> dict[str, list[tuple[int, int]]]:
    """Changed line ranges per file on one side of the fix (`old` = vulnerable, `new` = fixed)."""
    diff = subprocess.run(
        ["git", "-C", str(CACHE / case["id"]), "diff", "-U0", case["vulnerable"], case["fixed"]], capture_output=True, text=True, check=True
    ).stdout
    ranges: dict[str, list[tuple[int, int]]] = {}
    current = ""
    for line in diff.splitlines():
        if (line.startswith("--- a/") and side == "old") or (line.startswith("+++ b/") and side == "new"):
            current = line[6:]
        elif line.startswith("@@") and current:
            match = re.search(r"-(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))?", line)
            if match:
                start, count = (match.group(1), match.group(2)) if side == "old" else (match.group(3), match.group(4))
                first, length = int(start), int(count) if count is not None else 1
                ranges.setdefault(current, []).append((first, first + max(length, 1) - 1))
    return ranges


def named_functions(case: dict) -> set[str]:
    names: set[str] = set()
    for field in ("sink", "fix_site"):
        _, _, rest = str(case.get(field, "")).partition("::")
        names.update(n.split("::")[-1] for n in re.findall(r"[A-Za-z_][A-Za-z0-9_:]*(?=\s*(?:\(|,|;|$))", rest.split("(")[0] + ","))
    return {n for n in names if n not in {"used", "by", "source", "callers", "and", "from", "the"}}


def matches(finding: dict, case: dict, ranges: dict[str, list[tuple[int, int]]], functions: set[str]) -> bool:
    path, _, rest = finding["site"].partition(":")
    line_text, _, function = rest.partition(":")
    if finding.get("family") != case["family"] or path not in ranges:
        return False
    if function in functions:
        return True
    line = int(line_text) if line_text.isdigit() else -1
    return any(first - LINE_WINDOW <= line <= last + LINE_WINDOW for first, last in ranges[path])


def wilson(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z, p = 1.96, successes / total
    centre, spread = (
        (p + z * z / (2 * total)) / (1 + z * z / total),
        z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total),
    )
    return [round(max(0.0, centre - spread), 3), round(min(1.0, centre + spread), 3)]


def score(args: argparse.Namespace) -> int:
    per_case, pool = [], []
    for case in cases():
        scans = {
            label: json.loads((RESULTS / "scans" / f"{case['id']}--{label}.json").read_text())
            for label in pins(case)
            if (RESULTS / "scans" / f"{case['id']}--{label}.json").is_file()
        }
        if len(scans) < 4:
            per_case.append({"id": case["id"], "status": "incomplete", "scans": sorted(scans)})
            continue
        old, new, functions = hunks(case, "old"), hunks(case, "new"), named_functions(case)
        vulnerable, fixed = scans["vulnerable"].get("findings", []), scans["fixed"].get("findings", [])
        detected = [f["site"] for f in vulnerable if matches(f, case, old, functions)]
        fixed_alerts = [f["site"] for f in fixed if matches(f, case, new, functions)]
        base_regions = {tuple(f["site"].split(":")[0::2]) for f in scans["benign_base"].get("findings", [])}
        benign_alerts = [
            f["site"] for f in scans["benign_tip"].get("findings", []) if tuple(f["site"].split(":")[0::2]) not in base_regions
        ]
        answered = any(r.split(":")[0] in old for r in scans["vulnerable"].get("completed_regions", []))
        errors = {label: s["instrument_error"] for label, s in scans.items() if "instrument_error" in s}
        per_case.append(
            {
                "id": case["id"], "family": case["family"], "language": case["language"],
                "detected": bool(detected), "detected_sites": detected,
                "unanswered": not detected and not answered, "instrument_errors": errors,
                "fixed_side_alerts": fixed_alerts, "benign_alerts": benign_alerts,
                "completion": {label: [s.get("completed"), s.get("questions")] for label, s in scans.items()},
                "seconds": {label: s.get("seconds") for label, s in scans.items()},
            }
        )  # fmt: skip
        pool += [{"case": case["id"], **f} for f in vulnerable]
    pool.sort(key=lambda f: (f["case"], f["site"]))
    sample = pool if len(pool) <= 15 else pool[0::3]
    scored = [c for c in per_case if c.get("status") != "incomplete"]
    detected = sum(c["detected"] for c in scored)
    result = {
        "protocol": "protocol-v1.md",
        "cases_scored": len(scored), "cases_incomplete": [c["id"] for c in per_case if c.get("status") == "incomplete"],
        "recall": [detected, len(scored)], "recall_wilson95": wilson(detected, len(scored)),
        "fixed_side_alerts": sum(len(c["fixed_side_alerts"]) for c in scored),
        "benign_alerts": sum(len(c["benign_alerts"]) for c in scored),
        "pooled_vulnerable_findings": len(pool), "precision_sample_size": len(sample),
        "cases": per_case, "precision_sample": sample,
    }  # fmt: skip
    (RESULTS / "score.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("cases", "precision_sample")}, indent=1))
    return 0


def matches_v2(finding: dict, case: dict, ranges: dict[str, list[tuple[int, int]]]) -> bool:
    """protocol-v2.md: v1's rule with the record's declared site functions, or a declared `path::function`."""
    path, _, rest = finding["site"].partition(":")
    line_text, _, function = rest.partition(":")
    if finding.get("family") != case["family"]:
        return False
    sites = set(case.get("sites", []))
    if f"{path}::{function}" in sites:
        return True
    if path not in ranges:
        return False
    if function in {site.partition("::")[2] for site in sites}:
        return True
    line = int(line_text) if line_text.isdigit() else -1
    return any(first - LINE_WINDOW <= line <= last + LINE_WINDOW for first, last in ranges[path])


def stability(one: list[dict], two: list[dict]) -> tuple[int, int]:
    """(findings in exactly one run, findings in either)."""
    a, b = {f["site"] for f in one}, {f["site"] for f in two}
    return len(a ^ b), len(a | b)


def score_v2() -> int:
    per_case, pool, unstable_pool = [], [], 0
    changing, total_questions, total_completed = [0, 0], 0, 0
    for case in cases():
        path = lambda label: RESULTS / "scans" / f"{case['id']}--{label}.json"  # noqa: E731, B023 -- called only inside this iteration
        scans = {label: json.loads(path(label).read_text()) for label in pins(case) if path(label).is_file()}
        if len(scans) < 6:
            per_case.append({"id": case["id"], "status": "incomplete", "scans": sorted(scans)})
            continue
        old, new = hunks(case, "old"), hunks(case, "new")
        va, vb = scans["vulnerable_a"].get("findings", []), scans["vulnerable_b"].get("findings", [])
        fa, fb = scans["fixed_a"].get("findings", []), scans["fixed_b"].get("findings", [])
        hit_a = {f["site"] for f in va if matches_v2(f, case, old)}
        hit_b = {f["site"] for f in vb if matches_v2(f, case, old)}
        fixed_alerts = sorted({f["site"] for f in fa + fb if matches_v2(f, case, new)})
        base_regions = {tuple(f["site"].split(":")[0::2]) for f in scans["benign_base"].get("findings", [])}
        # protocol-v2.md: benign alerts and the precision pool are findings OF THE CASE FAMILY. The engine's dump
        # emits only that family, so this was invisible until the hunter, whose findings span every family.
        benign_alerts = [
            f["site"]
            for f in scans["benign_tip"].get("findings", [])
            if f.get("family") == case["family"] and tuple(f["site"].split(":")[0::2]) not in base_regions
        ]
        site_files = {site.partition("::")[0] for site in case.get("sites", [])}
        covered = set(old) | site_files
        answered = any(
            r.split(":")[0] in covered for label in ("vulnerable_a", "vulnerable_b") for r in scans[label].get("completed_regions", [])
        )
        diff_v, union_v = stability(va, vb)
        diff_f, union_f = stability(fa, fb)
        changing[0] += diff_v + diff_f
        changing[1] += union_v + union_f
        for scan in scans.values():
            total_questions += int(scan.get("questions") or 0)
            total_completed += int(scan.get("completed") or 0)
        detected = sorted(hit_a & hit_b)
        per_case.append(
            {
                "id": case["id"], "family": case["family"], "language": case["language"],
                "detected": bool(detected), "detected_sites": detected,
                "unstable": bool(hit_a ^ hit_b) and not detected, "unstable_sites": sorted(hit_a ^ hit_b),
                "unanswered": not (hit_a | hit_b) and not answered,
                "instrument_errors": {label: s["instrument_error"] for label, s in scans.items() if "instrument_error" in s},
                "fixed_side_alerts": fixed_alerts, "benign_alerts": benign_alerts,
                "stability": {"vulnerable": [diff_v, union_v], "fixed": [diff_f, union_f]},
                "completion": {label: [s.get("completed"), s.get("questions")] for label, s in scans.items()},
                "seconds": {label: s.get("seconds") for label, s in scans.items()},
            }
        )  # fmt: skip
        stable = {f["site"] for f in vb if f.get("family") == case["family"]}
        pool += [{"case": case["id"], **f} for f in va if f.get("family") == case["family"] and f["site"] in stable]
        unstable_pool += len({f["site"] for f in va if f.get("family") == case["family"]} ^ stable)
    pool.sort(key=lambda f: (f["case"], f["site"]))
    sample = pool if len(pool) <= 15 else pool[0::3]
    scored = [c for c in per_case if c.get("status") != "incomplete"]
    detected = sum(c["detected"] for c in scored)
    result = {
        "protocol": "protocol-v2.md",
        "cases_scored": len(scored), "cases_incomplete": [c["id"] for c in per_case if c.get("status") == "incomplete"],
        "recall": [detected, len(scored)], "recall_wilson95": wilson(detected, len(scored)),
        "unstable_detections": [c["id"] for c in scored if c["unstable"]],
        "fixed_side_alerts": sum(len(c["fixed_side_alerts"]) for c in scored),
        "benign_alerts": sum(len(c["benign_alerts"]) for c in scored),
        "completion": [total_completed, total_questions],
        "stability": changing,
        "pooled_stable_vulnerable_findings": len(pool), "unstable_vulnerable_findings": unstable_pool,
        "precision_sample_size": len(sample),
        "cases": per_case, "precision_sample": sample,
    }  # fmt: skip
    (RESULTS / "score.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("cases", "precision_sample")}, indent=1))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    runner = sub.add_parser("run")
    runner.add_argument("--source", type=Path, required=True, help="a frozen export of the analyzer (freeze_source.sh)")
    runner.add_argument("--only", default="")
    runner.add_argument("--population", type=Path, default=POPULATION)
    scorer = sub.add_parser("score")
    scorer.add_argument("--population", type=Path, default=POPULATION)
    args = parser.parse_args()
    use(args.population)
    if args.command == "run":
        return run(args)
    return score(args) if version() == "v1" else score_v2()


if __name__ == "__main__":
    raise SystemExit(main())
