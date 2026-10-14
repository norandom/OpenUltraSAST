"""Banks FIXED-SEARCH MVP v2 (batch path -- the working invocation; the single cpg.run path is broken by a
taint.sc exec-signature skew). Build banks CPG, run the taint BATCH on the vuln functions with the annotation
OFF (shipped) vs ON (parameter_sources=True + write_text/read_text added to path sinks). A non-empty flow row =
the engine traced source->sink. Thesis: same target, only the search changes."""

import dataclasses
import sys
from pathlib import Path

sys.path.insert(0, "/venv/lib/python3.12/site-packages")
from openultrasast.cpg.backend import resolve_cpg_backend
from openultrasast.model.specs import taint_specs
from openultrasast.model.taint import request_params

ROOT = Path("/work/banks")
VP = "src/banks/registries/directory.py"
FUNCS = ["from_prompt_path", "set", "_load", "_scan"]

backend = resolve_cpg_backend()
cpg = backend.build(ROOT, language="python")
if cpg is None or not callable(getattr(cpg, "run_batch", None)):
    print("CPG build failed or no run_batch")
    raise SystemExit(1)
print("CPG built; run_batch available.", flush=True)

base = taint_specs(language="python")["path"]
annot = dataclasses.replace(base, sinks=tuple(sorted(set(base.sinks) | {"write_text", "read_text"})))
print("baseline sinks:", base.sinks)
print("annotated sinks:", annot.sinks, flush=True)


def run(label, spec, fn, psrc):
    reqs = {"r1": request_params(spec, function=fn, file=VP, parameter_sources=psrc)}
    try:
        out = cpg.run_batch("taint", reqs)
    except Exception as e:
        print(f"  [{label}] {fn}: ERROR {type(e).__name__}: {str(e)[:150]}")
        return 0
    rows = (out or {}).get("r1") or []
    print(f"  [{label}] {fn} psrc={psrc}: {len(rows)} flow row(s)")
    for r in rows[:3]:
        if isinstance(r, dict):
            print(f"      sink={r.get('sink')} source={r.get('source')} line={r.get('line')} evidence={str(r.get('evidence'))[:60]}")
    return len(rows)


print("\n=== BASELINE (shipped search) ===", flush=True)
b = sum(run("baseline", base, fn, False) for fn in FUNCS)
print("\n=== FIXED SEARCH (annotation: param-source + write_text/read_text sink) ===", flush=True)
f = sum(run("fixed", annot, fn, True) for fn in FUNCS)
print(f"\n=== RESULT: baseline flow rows={b}  fixed-search flow rows={f} ===")
print("FIXED SEARCH TRACES BANKS (search was wrong, not the target)" if f > b else "no change", flush=True)
