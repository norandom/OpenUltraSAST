"""Measure the PHP quick-mode rules on the PHP development corpus (never population-v2).

Pins: pmpro vulnerable / fixed / benign (benchmarks/push/inputs.json, role development) and the spent
population-v1 PHP cases' vulnerable and fixed pins, exported beforehand with benchmarks/independent/evaluate.py's
`export` into <corpus>/checkouts/<case>/<label> (pmpro from the repo cache, benign = vulnerable + the declared
authored edit).

Known sites: pmpro's is the declared CVE-2023-23488 function (getMemberOrderByCode) on each pin; a v1 case's are
its fix hunks (vulnerable side on the vulnerable pin, fixed side on the fixed pin; test paths dropped) widened by
evaluate.LINE_WINDOW, plus the declared sink line where the fix does not touch the sink (LearnPress).

The instrument must have read its input: every pin reports the PHP files and bytes the scan read, and a pin with
zero PHP bytes fails the run.

Usage: python measure_php_quick.py <corpus dir> <out.json>
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "benchmarks/independent")
import evaluate  # noqa: E402

from openultrasast.findings import quick_scan_findings  # noqa: E402
from openultrasast.mapping import analyze_entry_points, attach_reachability_hints  # noqa: E402
from openultrasast.preprocess import preprocess_repository  # noqa: E402
from openultrasast.rank import rank_targets  # noqa: E402

V1 = ("wp-ultimate-member-sqli", "wp-learnpress-sqli", "phpmyfaq-captcha-ua-sqli", "yeswiki-bazar-form-sqli")
DECLARED = {"wp-learnpress-sqli": ("inc/Databases/class-lp-db.php", "$FIELDS = implode( ',', array_unique( $filter->only_fields ) );")}
W = evaluate.LINE_WINDOW


def scan(root: Path) -> tuple[list, dict]:
    _, targets = preprocess_repository(root)
    php = [t for t in targets if t.language == "php"]
    read = {"php_files": len(php), "php_bytes": sum(len((root / t.path).read_bytes()) for t in php)}
    if not read["php_bytes"]:
        raise SystemExit(f"instrument failure: no PHP bytes read under {root}")
    targets = attach_reachability_hints(targets, analyze_entry_points(root, targets))
    started = time.monotonic()
    findings = [f for f in quick_scan_findings(root, targets, rank_targets(targets)) if f.finding_id.startswith("php-")]
    read["scan_seconds"] = round(time.monotonic() - started, 1)
    return findings, read


def function_range(path: Path, name: str) -> tuple[int, int]:
    lines = path.read_text(errors="replace").splitlines()
    start = next(i for i, line in enumerate(lines, 1) if f"function {name}(" in line)
    end = next((i for i, line in enumerate(lines[start:], start + 1) if "function " in line), len(lines))
    return start, end - 1


def line_of(path: Path, needle: str) -> int:
    return next(i for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1) if needle in line)


def at(finding, sites: dict[str, list[tuple[int, int]]]) -> bool:
    return any(first <= (finding.line or -1) <= last for first, last in sites.get(finding.path, []))


def summarize(findings: list, sites: dict[str, list[tuple[int, int]]]) -> dict:
    hits = [f for f in findings if at(f, sites)]
    return {
        "findings": len(findings),
        "by_rule": dict(sorted(Counter(f.finding_id.split(":", 1)[0] for f in findings).items())),
        "by_rule_enabled": len([f for f in findings if f.status == "enabled"]),
        "at_known_site": [f.finding_id for f in hits],
    }


def main() -> int:
    corpus, out = Path(sys.argv[1]), Path(sys.argv[2])
    checkouts = corpus / "checkouts"
    result: dict = {"window": W, "cases": {}}
    # pmpro: the declared CVE function on each pin.
    pmpro_dirs = {
        "vulnerable": Path.home() / ".cache/openultrasast/repos/pmpro/1a900be3f09f",
        "fixed": Path.home() / ".cache/openultrasast/repos/pmpro/2f65530f9442",
        "benign": checkouts / "pmpro" / "benign",
    }
    pmpro: dict = {}
    for label, root in pmpro_dirs.items():
        findings, read = scan(root)
        rel = "classes/class.memberorder.php"
        first, last = function_range(root / rel, "getMemberOrderByCode")
        sites = {rel: [(first, last)]}
        pmpro[label] = {"root": str(root), "read": read, "known_site": f"{rel}:{first}-{last}", **summarize(findings, sites)}
        pmpro[label]["_ids"] = sorted(f.finding_id for f in findings)
        print("pmpro", label, read, pmpro[label]["findings"], pmpro[label]["at_known_site"], file=sys.stderr)
    result["cases"]["pmpro"] = pmpro
    for case in evaluate.cases():
        if case["id"] not in V1:
            continue
        entry: dict = {}
        for label, side in (("vulnerable", "old"), ("fixed", "new")):
            root = checkouts / case["id"] / label
            findings, read = scan(root)
            sites = {
                path: [(a - W, b + W) for a, b in ranges]
                for path, ranges in evaluate.hunks(case, side).items()
                if path.endswith(".php") and not path.startswith(("tests/", "test/")) and "/tests/" not in path
            }
            if case["id"] in DECLARED:
                rel, needle = DECLARED[case["id"]]
                n = line_of(root / rel, needle)
                sites.setdefault(rel, []).append((n - W, n + W))
            entry[label] = {"read": read, "known_sites": {p: r for p, r in sorted(sites.items())}, **summarize(findings, sites)}
            entry[label]["_ids"] = sorted(f.finding_id for f in findings)
            print(case["id"], label, read, entry[label]["findings"], entry[label]["at_known_site"], file=sys.stderr)
        result["cases"][case["id"]] = entry
    result["fixtures"] = fixtures()
    result["rules"] = per_rule(result)
    for pins in result["cases"].values():
        for pin in pins.values():
            pin.pop("_ids")
    out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return 0


def fixtures() -> dict:
    """The committed fixture benchmarks, scored exactly as `ousast benchmark` scores them."""
    from openultrasast.benchmark import BenchmarkRun, evaluate_benchmark, load_benchmark_manifest, resolve_benchmark_source
    from openultrasast.gate import _quick_scan

    result = {}
    for name in ("php-vulnerable", "php-benign"):
        path = Path("benchmarks/manifests") / f"{name}.toml"
        manifest = load_benchmark_manifest(path)
        target = resolve_benchmark_source(path, manifest)
        findings = _quick_scan(target)
        run = BenchmarkRun(benchmark_run_id="php-quick", root=Path("/tmp/php-quick"), manifest=manifest)
        bench = evaluate_benchmark(run=run, mode="quick", findings=findings, scan_id=None, scan_run_dir=None)
        m = bench.metrics
        result[name] = {
            "expected": m.expected_findings_total, "matched": m.matched_findings_total, "findings": m.actual_findings_total,
            "false_positives": [fp.finding_id for fp in bench.false_positives], "missed": [x.rule_id or x.cwe for x in bench.misses],
            "true_positives": sorted({f.finding_id for f in findings} - {fp.finding_id for fp in bench.false_positives}),
        }  # fmt: skip
    return result


def per_rule(result: dict) -> dict:
    """Firings per rule and the status/precision policy applied to them (see the module docstring of the ruleset).

    enabled  -- the rule hit a known vulnerable site on the corpus, or it never fired on the corpus (no false-alert
                pressure measured; fixture evidence only);
    shadow   -- it fired on the corpus but never at a known site: every corpus firing was on code whose known bug is
                elsewhere, and it fired as often on the fixed pins.
    precision lower bound = (known-site hits on vulnerable pins + fixture true positives)
                            / (firings on vulnerable pins + fixture firings, both twins); an unlabeled firing counts false.
    """
    rows: dict = defaultdict(lambda: defaultdict(int))
    for pins in result["cases"].values():
        for label, pin in pins.items():
            for fid in pin["_ids"]:
                rows[fid.split(":", 1)[0]][label] += 1
            for fid in pin["at_known_site"]:
                rows[fid.split(":", 1)[0]][label + "_at_site"] += 1
    for _name, fixture in result["fixtures"].items():
        for fid in fixture["true_positives"]:
            rows[fid.split(":", 1)[0]]["fixture_tp"] += 1
        for fid in fixture["false_positives"]:
            rows[fid.split(":", 1)[0]]["fixture_fp"] += 1
    rules = {}
    for rule, row in sorted(rows.items()):
        fired, at_site = row["vulnerable"], row["vulnerable_at_site"]
        status = "enabled" if at_site or not fired else "shadow"
        denominator = fired + row["fixture_tp"] + row["fixture_fp"]
        precision = round((at_site + row["fixture_tp"]) / denominator, 3) if denominator else None
        rules[rule] = {**dict(sorted(row.items())), "status": status, "precision_lower_bound": precision, "n": denominator}
    return rules


if __name__ == "__main__":
    raise SystemExit(main())
