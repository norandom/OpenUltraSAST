#!/usr/bin/env python3
"""Build vibe-py recipes from Real-Vuln-Benchmark ground truth (maintainer, offline once downloaded).

Download first (network, maintainer only):

    mkdir -p /tmp/realvuln
    gh api repos/kolega-ai/Real-Vuln-Benchmark/contents/benchmark-manifest.json --jq .content | base64 -d > /tmp/realvuln/manifest.json
    for r in $(gh api repos/kolega-ai/Real-Vuln-Benchmark/contents/ground-truth --jq '.[] | select(.type=="dir") | .name'); do
      gh api "repos/kolega-ai/Real-Vuln-Benchmark/contents/ground-truth/$r/ground-truth.json" --jq .content | base64 -d > "/tmp/realvuln/$r.json"
    done

Then:

    python benchmarks/pairs/vibe-py/build_recipes.py --ground-truth /tmp/realvuln --licenses /tmp/realvuln/licenses.json
    python benchmarks/pairs/harvest.py --slice vibe-py --all --fetch
    python benchmarks/pairs/catalog_gen.py --slice vibe-py

Pair shape: the vulnerable function (enclosing the labeled sink line) is the vuln side; a
false-positive trap function from the same repository is the fixed twin. Repositories
without a stated license are skipped (Req 5.4). Every recipe is a candidate until the
catalog row is reviewed.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MECHANISM = {
    "idor": "identity_from_request_body",
    "broken_access_control": "missing_auth_guard",
    "mass_assignment": "identity_from_request_body",
    "path_traversal": "path_join_user_input",
    "unrestricted_file_upload": "path_join_user_input",
    "hardcoded_credentials": "secret_in_client",
    "sensitive_data_exposure": "secret_in_client",
    "security_misconfiguration": "permissive_default",
    "insecure_cookie_flags": "permissive_default",
    "csrf": "permissive_default",
    "weak_prng": "config_sink_weak_literal",
    "weak_crypto": "config_sink_weak_literal",
    "weak_hashing": "config_sink_weak_literal",
    "sql_injection": "source_reaches_sink",
    "nosql_injection": "source_reaches_sink",
    "command_injection": "source_reaches_sink",
    "code_injection": "source_reaches_sink",
    "ssti": "source_reaches_sink",
    "ssrf": "source_reaches_sink",
    "open_redirect": "source_reaches_sink",
    "reflected_xss": "source_reaches_sink",
    "stored_xss": "source_reaches_sink",
    "xxe": "source_reaches_sink",
    "insecure_deserialization": "source_reaches_sink",
    "sensitive_data_in_logs": "secret_in_client",
    "business_logic_validation_gap": "validation_strength",
    "user_enumeration": "validation_strength",
    "missing_rate_limiting": "permissive_default",
    "missing_rate_limiting_on_auth": "permissive_default",
    "denial_of_service": "validation_strength",
}
# Classes an intra-file engine can talk about; the rest are recorded as candidates but not selected by default.
DEFAULT_CLASSES = (
    "sql_injection",
    "command_injection",
    "code_injection",
    "ssti",
    "ssrf",
    "path_traversal",
    "open_redirect",
    "insecure_deserialization",
    "idor",
    "broken_access_control",
    "hardcoded_credentials",
    "security_misconfiguration",
    "reflected_xss",
    "xxe",
    "nosql_injection",
)
ACCEPTED_LICENSES = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "GPL-3.0", "GPL-2.0", "MPL-2.0", "Unlicense", "ISC"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def build(
    ground_truth: Path, licenses: Path, *, per_repo: int, classes: set[str], allow_unlicensed: bool, pointers: bool = False
) -> tuple[list[dict[str, object]], dict[str, int]]:
    """``pointers=True`` keeps the LLM-generated repositories without a license as ``vendored = false`` rows (Req 10.6):
    scored through the cache with ``pairs --pointers``, never vendored. Unlicensed human repositories stay skipped."""
    manifest = json.loads((ground_truth / "manifest.json").read_text())
    license_by_repo = json.loads(licenses.read_text()) if licenses.is_file() else {}
    recipes: list[dict[str, object]] = []
    skipped = {"unlicensed": 0, "no_trap": 0, "no_function": 0, "class": 0}
    for repo_id, meta in sorted(manifest["repos"].items()):
        gt_path = ground_truth / f"{repo_id}.json"
        if not gt_path.is_file():
            continue
        gt = json.loads(gt_path.read_text())
        info = license_by_repo.get(repo_id, {})
        license_id = info.get("license") or ""
        licensed = license_id in ACCEPTED_LICENSES
        pointer = pointers and not licensed and meta["authorship"] == "llm_generated"
        if not licensed and not allow_unlicensed and not pointer:
            skipped["unlicensed"] += 1
            continue
        full = info.get("full") or "/".join(meta["repo_url"].rstrip("/").split("/")[-2:])
        commit = meta["commit_sha"]
        provenance = "agent" if meta["authorship"] == "llm_generated" else "human"
        findings = gt.get("findings", [])
        traps = [
            f
            for f in findings
            if not f.get("is_vulnerable") and f.get("location", {}).get("function") and f.get("file", "").endswith(".py")
        ]
        if not traps:
            skipped["no_trap"] += 1
            continue
        taken = 0
        seen_functions: set[tuple[str, str]] = set()
        for finding in findings:
            if taken >= per_repo:
                break
            if not finding.get("is_vulnerable"):
                continue
            location = finding.get("location", {})
            function = location.get("function")
            file = finding.get("file", "")
            if not function or not file.endswith(".py"):
                skipped["no_function"] += 1
                continue
            vclass = str(finding.get("vulnerability_class", ""))
            if vclass not in classes:
                skipped["class"] += 1
                continue
            if (file, function) in seen_functions:
                continue
            seen_functions.add((file, function))
            trap = next((t for t in traps if t["file"] == file), traps[0])
            name = f"{_slug(repo_id.replace('realvuln-', '').replace('vc-', ''))}-{_slug(Path(file).stem)}-{_slug(function)}"[:60]
            while any(r["name"] == name for r in recipes):
                name = name[:57] + "-" + str(sum(1 for r in recipes if str(r["name"]).startswith(name[:57])) + 1)
            recipes.append(
                {
                    "name": name,
                    "host": "github",
                    "repo": full,
                    "parent": commit,
                    "commit": commit,
                    "path": file,
                    "fix_path": trap["file"],
                    "mode": "enclosing",
                    "line": int(location["start_line"]),
                    "fix_line": int(trap["location"]["start_line"]),
                    "function": function,
                    "language": "python",
                    "relpath": file,
                    "license": license_id or "unlicensed",
                    "cve": str(finding.get("evidence", {}).get("cve_id") or ""),
                    "year": 2026,
                    "cwe": str(finding.get("primary_cwe", "")),
                    "class": vclass,
                    "mechanism": MECHANISM.get(vclass, "other"),
                    "provenance": provenance,
                    "origin": "real-vuln-benchmark",
                    "project": repo_id,
                    "framework": str(meta.get("framework", "")),
                    "gt_id": str(finding.get("id", "")),
                    "trap_id": str(trap.get("id", "")),
                    "acceptable_cwes": list(finding.get("acceptable_cwes", [])),
                    "evidence": str(finding.get("evidence", {}).get("description", ""))[:240].replace("\n", " "),
                    "commit_url": f"https://github.com/{full}/blob/{commit}/{file}#L{int(location['start_line'])}",
                }
            )
            if pointer:
                recipes[-1]["vendored"] = False
                recipes[-1]["review_tier"] = "seeded"  # ground truth reviewed upstream; the code is never redistributed
            taken += 1
    # deterministic holdout: every other recipe by sorted name
    for index, recipe in enumerate(sorted(recipes, key=lambda r: str(r["name"]))):
        recipe["split"] = "holdout" if index % 2 else "train"
    return recipes, skipped


def to_toml(recipes: list[dict[str, object]]) -> str:
    lines = [
        "# vibe-py harvest recipes generated from Real-Vuln-Benchmark ground truth by build_recipes.py.",
        "# Vulnerable function = vuln side; a false-positive trap from the same repo = fixed twin.",
        "# Review each row before trusting it as a label; regenerate with build_recipes.py.",
        "",
    ]
    for recipe in sorted(recipes, key=lambda r: str(r["name"])):
        lines.append("[[recipe]]")
        for key, value in recipe.items():
            if isinstance(value, bool):
                lines.append(f"{key} = {'true' if value else 'false'}")
            elif isinstance(value, int):
                lines.append(f"{key} = {value}")
            elif isinstance(value, list):
                inner = ", ".join('"' + str(item).replace('"', '\\"') + '"' for item in value)
                lines.append(f"{key} = [{inner}]")
            else:
                lines.append(f'{key} = "{str(value).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"')
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, required=True, help="directory with manifest.json and <repo>.json ground truth")
    parser.add_argument("--licenses", type=Path, default=None, help="json map repo_id -> {full, license}")
    parser.add_argument("--per-repo", type=int, default=2)
    parser.add_argument("--classes", default=",".join(DEFAULT_CLASSES))
    parser.add_argument("--allow-unlicensed", action="store_true", help="include repositories without a stated license (NOT for vendoring)")
    parser.add_argument(
        "--pointers", action="store_true", help="append the LLM-generated unlicensed repos as vendored = false rows to --out (Req 10.6)"
    )
    parser.add_argument("--out", type=Path, default=ROOT / "recipes.toml")
    args = parser.parse_args(argv)
    recipes, skipped = build(
        args.ground_truth,
        args.licenses or (args.ground_truth / "licenses.json"),
        per_repo=args.per_repo,
        classes=set(args.classes.split(",")),
        allow_unlicensed=args.allow_unlicensed,
        pointers=args.pointers,
    )
    if args.pointers and args.out.is_file():
        import importlib.util
        import tomllib

        spec = importlib.util.spec_from_file_location("pair_harvest_lib", ROOT.parent / "harvest.py")
        assert spec is not None and spec.loader is not None
        harvest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harvest)
        existing = [dict(r) for r in tomllib.loads(args.out.read_text()).get("recipe", [])]
        recipes, added = harvest.merge_recipes(existing, [r for r in recipes if r.get("vendored") is False])
        print(f"appended {len(added)} pointer recipes to {args.out}")
    args.out.write_text(to_toml(recipes), encoding="utf-8")
    print(f"wrote {args.out} ({len(recipes)} recipes); skipped {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
