"""Sweep candidate precision filters over the pilot's hunter records (no model calls).

For every hunter defect: classifier verdict, confidence, taxonomy family, and whether its
location sits on a line the push changed (git diff base..head, head side). Then score each
filter with the real scorer: recall over the 12 positives, false alarms per 100 ordinary pushes.
"""

import copy
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/home/mc/Source/OpenUltraSAST")
from benchmarks.unseen import score  # noqa: E402

P = Path("/home/mc/ousast-results/valid/pilot")
repos = json.loads((P / "repos_hist.json").read_text())
rows = score.load_records(P / "hunter")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(repo, base, head):
    out = subprocess.run(
        ["git", "-C", repos[repo], "diff", "-U0", f"{base}..{head}", "--", "."],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    lines, path = {}, None
    for line in out.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("@@") and path:
            m = HUNK.match(line)
            start, n = int(m.group(1)), int(m.group(2) or 1)
            lines.setdefault(path, set()).update(range(start, start + max(n, 1)))
    return lines


def near_changed(defect, lines, slack):
    for path, line in defect.get("locations", []):
        hits = lines.get(path)
        if hits and any(abs(line - h) <= slack for h in hits):
            return True
    return False


def filtered(row, keep):
    r = copy.deepcopy(row)
    adm = r.setdefault("push", {}).setdefault("admission", {})
    adm["defects"] = [d for d in adm.get("defects", []) if keep(d)]
    return r


def rate(rows_, keep):
    pos = [r for r in rows_ if r["kind"] != "ordinary"]
    ord_ = [r for r in rows_ if r["kind"] == "ordinary" and r.get("status") != "instrument_failure"]
    caught = sum(bool(score.catches(filtered(r, keep))) for r in pos)
    alarms = sum(bool(list(score.findings(filtered(r, keep)))) for r in ord_)
    flagged = alarms + sum(bool(list(score.findings(filtered(r, keep)))) for r in pos)
    return caught, len(pos), alarms, len(ord_), flagged


# annotate defects with changed-line proximity
for r in rows:
    lines = changed_lines(r["repo"], r["base"], r["head"])
    for d in r.get("push", {}).get("admission", {}).get("defects", []):
        d["_changed0"] = near_changed(d, lines, 0)
        d["_changed10"] = near_changed(d, lines, 10)

C = lambda d: d.get("classifier") or {}  # noqa: E731
V = lambda d: C(d).get("verdict")  # noqa: E731
conf = lambda d: C(d).get("confidence") or 0  # noqa: E731

filters = {
    "raw (all suspicions)": lambda d: True,
    "verdict=vulnerable": lambda d: V(d) == "vulnerable",
    "vulnerable, conf>=0.7": lambda d: V(d) == "vulnerable" and conf(d) >= 0.7,
    "vulnerable, conf>=0.8": lambda d: V(d) == "vulnerable" and conf(d) >= 0.8,
    "vulnerable, conf>=0.85": lambda d: V(d) == "vulnerable" and conf(d) >= 0.85,
    "vulnerable, not config_secrets": lambda d: V(d) == "vulnerable" and d.get("family") != "config_secrets",
    "vulnerable, conf>=0.8, not config_secrets": lambda d: V(d) == "vulnerable" and conf(d) >= 0.8 and d.get("family") != "config_secrets",
    "vulnerable, on a changed line": lambda d: V(d) == "vulnerable" and d["_changed0"],
    "vulnerable, within 10 of a changed line": lambda d: V(d) == "vulnerable" and d["_changed10"],
    "vulnerable, conf>=0.7, within 10 of changed": lambda d: V(d) == "vulnerable" and conf(d) >= 0.7 and d["_changed10"],
    "vulnerable, conf>=0.8, within 10 of changed": lambda d: V(d) == "vulnerable" and conf(d) >= 0.8 and d["_changed10"],
    "vulnerable, conf>=0.8, within 10, not config_secrets": lambda d: (
        V(d) == "vulnerable" and conf(d) >= 0.8 and d["_changed10"] and d.get("family") != "config_secrets"
    ),
}
print(f"{'filter':58} recall     false alarms /100   flagged pushes")
for name, keep in filters.items():
    c, n, a, m, f = rate(rows, keep)
    print(f"{name:58} {c:2}/{n:<2}      {a:3}/{m} = {100 * a / m:5.1f}      {f}")

# where do ordinary-push suspicions sit relative to the diff?
tot = Counter()
for r in rows:
    if r["kind"] != "ordinary":
        continue
    for d in r.get("push", {}).get("admission", {}).get("defects", []):
        if V(d) == "vulnerable":
            tot["vulnerable total"] += 1
            tot["on changed line"] += d["_changed0"]
            tot["within 10"] += d["_changed10"]
            tot[f"family {d.get('family')}"] += 1
print("\nordinary-push suspicions with verdict=vulnerable:", dict(tot))
confs = Counter(
    round(conf(d), 2)
    for r in rows
    if r["kind"] == "ordinary"
    for d in r.get("push", {}).get("admission", {}).get("defects", [])
    if V(d) == "vulnerable"
)
print("confidence histogram (ordinary, vulnerable):", dict(sorted(confs.items())))
confs = Counter(
    round(conf(d), 2)
    for r in rows
    if r["kind"] != "ordinary"
    for d in r.get("push", {}).get("admission", {}).get("defects", [])
    if V(d) == "vulnerable" and score.catches(filtered(r, lambda x, d=d: x is d))
)
print("confidence of the defects that score a catch:", dict(sorted(confs.items())))
