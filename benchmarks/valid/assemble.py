"""Freeze verified positives and deterministic ordinary draws with a held-out guard."""

from __future__ import annotations

import argparse
import json
import math
import tomllib
from collections import defaultdict
from pathlib import Path

from benchmarks.unseen import extract
from benchmarks.unseen.draft import canonical, manifest
from benchmarks.unseen.eligibility import normalize
from benchmarks.unseen.journal import digest

from .catalog import local_git
from .verify import verdict


def negatives(
    rows: list[dict], fixes: set[str], functions: set[tuple[str, str]], *, count: int, seed: int, floor: int = extract.ORDINARY_FLOOR
):
    """Combine the shipped twelve-commit stratified draws without duplicates.

    Small cells can stay unallocated in every twelve-commit draw, so when the union cannot reach ``count`` (a
    training repository whose eligible commits barely cover the ratio) one stratified draw of ``count`` is used
    instead; with ``count`` equal to the eligible commits that is every eligible commit."""
    available = {row["head"] for row in rows if extract.ordinary_rejection(row, fixes, functions) is None}
    if len(available) < count:
        raise ValueError(f"insufficient ordinary commits: {len(available)} available, {count} required")
    chosen = {}
    # Every call retains the original population and its time/size strata.
    for attempt in range(max(100, math.ceil(count / 12) * 100)):
        drawn, exclusions = extract.draw_ordinary(rows, fixes, functions, seed=seed + attempt, floor=floor)
        for row in drawn:
            chosen.setdefault(row["head"], row)
            if len(chosen) == count:
                return sorted(chosen.values(), key=lambda row: row["head"]), exclusions
    drawn, exclusions = extract.draw_ordinary(rows, fixes, functions, seed=seed, floor=floor, draws=count)
    return sorted(drawn, key=lambda row: row["head"]), exclusions


def freeze(
    directory: Path,
    *,
    cases: list[dict],
    verifications: list[dict],
    repos: dict,
    used,
    seed: int = 0,
    ratio: int = 20,
    history_heads: dict | None = None,
    fix_index: dict | None = None,
    floor: int = extract.ORDINARY_FLOOR,
) -> dict:
    """Freeze accepted positives with ``ratio`` ordinary pushes per fix commit from the same repositories.

    ``floor`` is the eligible-commit count a repository needs before its ordinary pushes are drawn. The
    held-out benchmark keeps the shipped 40; a training freeze may lower it (never below the ratio) so small
    repositories with 20 eligible commits still contribute, and the record carries the floor used."""
    if type(ratio) is not int or ratio < 20:
        raise ValueError("ordinary ratio must be at least 20")
    if type(floor) is not int or floor < ratio:
        raise ValueError("ordinary floor must be at least the ratio")
    if len({row["id"] for row in cases}) != len(cases) or len({row["id"] for row in verifications}) != len(verifications):
        raise ValueError("duplicate case or verification id")
    used_names = {normalize(name) for name in (set().union(*used.sources.values()) if hasattr(used, "sources") else used)}
    repos = {normalize(name): git for name, git in repos.items()}
    checks = {row["id"]: row for row in verifications}
    retained = defaultdict(list)
    dropped = set()
    for case in sorted(cases, key=lambda row: row["id"]):
        check = checks.get(case["id"])
        if check is None or check.get("verdict") != "accepted" or verdict(check) != "accepted":
            continue
        if case.get("method") != "fix_site":
            raise ValueError("only fix-site cases may enter this pool")
        repo = normalize(case["repo"])
        if repo in used_names or normalize(case["url"]) in used_names:
            dropped.add(repo)
        else:
            retained[repo].append(case)
    if not retained:
        raise ValueError("no accepted held-out positives")
    rows, draws, heads = [], {}, {}
    for repo, positives in sorted(retained.items()):
        git = repos[repo]
        all_cases = [case for case in cases if normalize(case["repo"]) == repo]
        fixes = {case["commit"] for case in all_cases} | set((fix_index or {}).get(repo, []))
        functions = {(case["path"], case["function"]) for case in all_cases}
        head = (history_heads or {}).get(repo) or git.run("rev-parse", "HEAD").strip()
        heads[repo] = head
        history = sorted(extract.ordinary_history(git, head), key=lambda row: row["head"])
        # Ratio is per positive CHANGE (a fix commit), not per accepted function. Several
        # accepted functions in one fix collapse to one vulnerability change below, so the
        # negative count must track distinct (commit, parent) pairs.
        change_count = len({(case["commit"], case["parent"]) for case in positives})
        ordinary, exclusions = negatives(history, fixes, functions, count=ratio * change_count, seed=seed, floor=floor)
        draws[repo] = exclusions
        changes = []
        pairs = defaultdict(list)
        for case in positives:
            pairs[case["commit"], case["parent"]].append(case)
        for (commit, parent), pair_cases in sorted(pairs.items()):
            case = pair_cases[0]
            (span,) = case["function_lines"]
            change = dict(
                kind="vulnerability",
                case_id=case["id"],
                base=commit,
                head=parent,
                files=[{"path": case["path"], "head_lines": [span]}],
                path=case["path"],
                function=case["function"],
                function_lines=span,
                family=case["family"],
                cwe=case["cwe"],
                advisory=case["advisory"],
                method="fix_site",
                label_check="confirmed",
            )
            if len(pair_cases) > 1:
                change["case_ids"] = [item["id"] for item in pair_cases]
                change["targets"] = [
                    dict(
                        case_id=item["id"],
                        path=item["path"],
                        function=item["function"],
                        function_lines=item["function_lines"][0],
                        family=item["family"],
                        cwe=item["cwe"],
                    )
                    for item in pair_cases
                ]
                change["files"] = [dict(path=item["path"], head_lines=item["function_lines"]) for item in pair_cases]
            changes.append(change)
        changes.extend({**change, "case_id": repo.replace("/", "-") + "-ordinary-" + change["head"]} for change in ordinary)
        rows.append(dict(id=repo, repository=repo, url=positives[0]["url"], slice=1, changes=changes))
    text = manifest(rows, seed).replace('status = "draft"', 'status = "frozen"', 1).replace('pool = "p1"', 'pool = "valid"', 1)
    pool = tomllib.loads(text)
    # Match replay.py's canonical manifest digest exactly.
    import hashlib

    record = dict(
        freeze_digest=hashlib.sha256(canonical(pool)).hexdigest(),
        guard_result=0,
        dropped_count=len(dropped),
        used_set_digest=hashlib.sha256("\n".join(sorted(used_names)).encode()).hexdigest(),
        catalog_digest=digest(sorted(cases, key=lambda row: row["id"])),
        verification_digest=digest(sorted(verifications, key=lambda row: row["id"])),
        history_heads=heads,
        ordinary_exclusions=draws,
        negative_ratio=ratio,
        ordinary_floor=floor,
        label_check_counts={"confirmed": sum(len(v) for v in retained.values()), "unchecked": 0, "unclear": 0, "refactor": 0},
    )
    payloads = [
        (directory / "pool-valid.toml", text.encode()),
        (directory / "freeze-valid.json", (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()),
    ]
    if any(path.exists() and path.read_bytes() != payload for path, payload in payloads):
        raise FileExistsError("frozen pool differs; use a new output directory")
    directory.mkdir(parents=True, exist_ok=True)
    for path, payload in payloads:
        if not path.exists():
            with path.open("xb") as handle:
                handle.write(payload)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("verification", type=Path)
    parser.add_argument("--repos", type=Path, required=True)
    parser.add_argument("--used", type=Path, required=True, help="JSON array of used repository identities, including known aliases")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    result = freeze(
        args.out,
        cases=tomllib.loads(args.catalog.read_text())["case"],
        verifications=json.loads(args.verification.read_text())["cases"],
        repos={k: local_git(Path(v)) for k, v in json.loads(args.repos.read_text()).items()},
        used=json.loads(args.used.read_text()),
        seed=args.seed,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
