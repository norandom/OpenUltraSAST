"""Compare the baseline labels (old modules) with the labels built on source.py, sentinel-normalised."""

import collections
import glob
import json
import sys


def load(pattern):
    files = glob.glob(pattern)
    if not files:
        sys.exit(f"no labels file for {pattern}")
    with open(files[0]) as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    return files[0], rows


bfile, before = load("/home/mc/ousast-results/fossil/p1-baseline/out/labels-*.jsonl")
afile, after = load("/home/mc/ousast-results/fossil/p1-after/out/labels-*.jsonl")


def key(r):
    s = json.dumps(r, sort_keys=True).replace("<global>", "<module>")
    return s


B = collections.Counter(key(r) for r in before)
A = collections.Counter(key(r) for r in after)
only_b = B - A
only_a = A - B
print("baseline:", bfile, len(before), "rows")
print("after:   ", afile, len(after), "rows")
print("identical after sentinel normalisation:", len(only_b) == 0 and len(only_a) == 0)
print("rows only in baseline:", sum(only_b.values()), " rows only in after:", sum(only_a.values()))


def summarize(c, title):
    print(f"--- {title} (first 8)")
    for s in list(c)[:8]:
        r = json.loads(s)
        print("  ", {k: r.get(k) for k in ("candidate", "family", "label", "source", "unit", "pin_role") if k in r})


summarize(only_b, "only baseline")
summarize(only_a, "only after")
