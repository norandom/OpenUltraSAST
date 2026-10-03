"""Instrument check for exp-004: are the scores real, and how clean is the pooled top of the ranking?"""
import json, collections
from pathlib import Path
from openultrasast.config import load_dotenv
load_dotenv(Path(".env"))
from openultrasast.plane.memory import open_store
from openultrasast.learn import experiments as ex
store = open_store(None)
rows = [r.row for r in store.rows(repo=ex.experiment_repo("exp-004-pooled-block-gate"), kind="arm_outcome")]
units = {json.loads(l)["unit"]: json.loads(l) for l in open("plane/experiments/exp-004-pooled-block-gate.units.jsonl")}
print("arm_outcome rows", len(rows), "units file", len(units))
r0 = rows[0]; print("row keys", sorted(r0)[:30])
print("decision example", json.dumps(r0.get("decision"))[:300])
def score(r):
    d = r.get("decision") or {}
    return r.get("s"), r.get("verdict", "unsure" if r.get("s") is None else "")
fam = collections.defaultdict(list)
for r in rows:
    u = units.get(r.get("unit"))
    if not u: continue
    p, v = score(r)
    fam[u["family"]].append((p, v, u["label"], u.get("pair")))
for f, xs in sorted(fam.items()):
    ps = [x for x in xs if x[0] is not None]
    distinct = len({round(x[0], 4) for x in ps})
    unsure = sum(1 for x in xs if x[1] == "unsure")
    pairs = collections.defaultdict(dict)
    for p, v, y, pr in xs:
        if pr and p is not None: pairs[pr][y] = p
    full = [d for d in pairs.values() if 0 in d and 1 in d]
    wins = sum(1 for d in full if d[1] > d[0]); ties = sum(1 for d in full if d[1] == d[0])
    top = sorted([x for x in ps if x[3]], key=lambda x: -x[0])
    first_neg = next((i for i, x in enumerate(top) if x[2] == 0), len(top))
    print(f"{f}: n={len(xs)} distinct_scores={distinct} unsure={unsure} pairs={len(full)} within_pair_win={wins} tie={ties} pos_above_first_neg={first_neg}")
allp = sorted([x for xs in fam.values() for x in xs if x[0] is not None and x[3]], key=lambda x: -x[0])
print("pooled raw top-30 labels:", "".join(str(x[2]) for x in allp[:30]))
