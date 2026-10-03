"""Feature records for every labelled pin unit, from the harvested signals (learned-decision-engine task 5, step 3).

Host only. For each labelled pin unit of a label snapshot (``ousast learn labels --out``; conditional rows excluded),
one ``static`` and one ``plane`` record per labelled (candidate, family), built with :mod:`openultrasast.learn.features`
from:

- quick rules and deterministic roles, run here on the unit's tree: a pair side materialised from its excerpt, a
  population or recipe pin exported from its clone or checkout (one at a time, deleted after, disk-guarded);
- the engine: ``benchmarks/learn/engine_pairs.py`` records for pairs, the recorded protocol scans
  (``~/ousast-results/independent-v{1,2}/scans/<case>--<pin role>[_a|_b].json``) for populations;
- verify passes a/b and ``agree`` from the harvest Run (``harvest-verify``) and, for population v2, the recorded
  ``validation-46`` Run; model roles from ``harvest-roles``;
- callers and entry-point distance on a repository (``not_applicable`` on a pair excerpt: no repository exists).

A pair side yields a record only for a labelled function that side declares (the excerpt builder's matcher,
:func:`openultrasast.plane.harvest.declares`); a name taken from the other side is counted as ``absent_on_side``, its
recorded verify verdicts are left unused, and its earlier row is dropped from the store (``dropped_stale_rows``).

An instrument that has not run for a unit yet (the engine job still running, a Run task not done) is recorded as
``failed`` with version ``missing:not-run`` -- null features, never zeros -- and counted as *missing*. Rows go to the
memory store (``OUSAST_MEMORY``, default ``~/ousast-results/plane/memory``) as kind ``features``; a rerun replaces
them by id. ``--counts`` writes the counts-only coverage record (no candidate, path or repository name).

``--dry-run`` instead compares existing local store examples with the corrected engine features, printing
per-source transitions from not-run/none to ran (and recorded failures separately). It reads only the spent
v1/v2 manifests, saved scans and local Git objects; it writes neither the store nor ``--counts`` and does not
rebuild other instruments. No label snapshot, harvest units or scratch directory is needed in this mode.

Usage::

    python benchmarks/learn/build_features.py --labels labels-<sha>.jsonl --units <harvest plane>/units.json --counts counts.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from openultrasast.findings import quick_scan_findings
from openultrasast.learn.features import (
    NONE,
    NOT_APPLICABLE,
    Part,
    SourceIndex,
    Vocabulary,
    _callers_of,
    _signals,
    agree_part,
    engine_part,
    entry_distance,
    entry_names,
    facts_part,
    function_of,
    model_sinks_part,
    quick_part,
    record,
    roles_part,
    ruleset_digest,
    source_part,
    verify_part,
)
from openultrasast.learn.labels import Clone
from openultrasast.learn.roles import RoleSet, from_model_roles, infer_for_checkout
from openultrasast.pairs import DEFAULT_CATALOG, _materialize_side, _targets, load_pair_catalog
from openultrasast.plane import memory
from openultrasast.plane.harvest import declares
from openultrasast.plane.tasks.alerts import covers
from openultrasast.plane.tasks.alerts import engine_languages as _engine_languages
from openultrasast.plane.tasks.alerts import quick_languages as _quick_languages
from openultrasast.plane.tasks.repo_facts import GLOBAL
from openultrasast.preprocess import detect_language
from openultrasast.rank import rank_targets
from openultrasast.ruleset import DEFAULT_RULESET_DIR, load_ruleset

RESULTS = Path.home() / "ousast-results"
MISSING = Part("failed", version="missing:not-run")
CONDITIONAL_SOURCES = ("benign_control", "assumed_benign")
PASSES = ("a", "b", "c")
QUICK_LANGUAGES = _quick_languages()
ENGINE_LANGUAGES = _engine_languages()


def jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()] if path.is_file() else []


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def resolve_scan(scans: Path, case: str, side: str) -> dict[str, Any] | None:
    """Read the v1 single scan, otherwise combine the v2 repeats for this side."""
    single = read_json(scans / f"{case}--{side}.json")
    if single is not None:
        return dict(single)
    repeats = [read_json(scans / f"{case}--{side}_{repeat}.json") for repeat in ("a", "b")]
    available = [r for r in repeats if r is not None]
    if not available:
        return None
    # Identical rule for vulnerable and fixed: a finding in either repeat counts;
    # exact duplicates count once. engine_part takes the highest rung and minimum
    # witness steps across the union. Completion is sum(completed)/sum(questions).
    # A successful repeat survives a failed/missing peer, which marks degradation.
    ran = [r for r in available if engine_for(r) is None]
    findings = {json.dumps(f, sort_keys=True): f for r in ran for f in r.get("findings", [])}
    degradations = sorted({d for r in available for d in r.get("degradations", [])})
    if len(ran) != len(repeats):
        degradations.append("repeat_missing_or_failed")
    return {
        "state": "ran" if ran else "none" if all(engine_for(r) == NONE for r in available) else "failed",
        "questions": sum(int(r.get("questions") or 0) for r in available),
        "completed": sum(int(r.get("completed") or 0) for r in available),
        "findings": list(findings.values()),
        "degradations": degradations,
        "image": "+".join(sorted({str(r.get("image") or "recorded") for r in available})),
    }


def recorded_engine(language: str, findings: list, result: Mapping | None, repository: bool) -> Part:
    # The language list describes standalone scans. Repository scans also analyze
    # TypeScript; recorded function findings take precedence over that list.
    if language not in ENGINE_LANGUAGES and not findings and not (repository and language == "typescript" and result is not None):
        return NONE
    state = engine_for(result)
    if state is not None:
        return state
    result = result or {}
    questions, completed = int(result.get("questions") or 0), int(result.get("completed") or 0)
    return engine_part(
        findings, completion=completed / questions if questions else None, degraded=bool(result.get("degradations")),
        vocabulary=Vocabulary.load(language), version=str(result.get("image") or "recorded"),
    )  # fmt: skip


class PinSourceIndex(SourceIndex):
    """Resolve findings with the same matcher as a checkout, without exporting it."""

    def __init__(self, clone: Path, pin: str) -> None:
        super().__init__(clone)
        self.clone, self.pin = Clone(clone), pin

    def lines(self, path: str) -> list[str]:
        if path not in self._lines:
            self._lines[path] = self.clone.git("show", f"{self.pin}:{path}").splitlines()
        return self._lines[path] or []


def dry_run(store: memory.FileStore, results: Path, cache: Path) -> dict[str, Any]:
    """Count existing examples whose engine becomes available; never write rows or blobs.

    Only spent v1/v2 populations are read. Counts are examples, not the two
    static/plane feature records. Other sources are reported with zero changes.
    """
    root = Path(__file__).resolve().parents[2]
    cases = {}
    for population in ("population-v1", "population-v2"):
        manifest = root / "benchmarks" / "independent" / f"{population}.toml"
        for case in tomllib.loads(manifest.read_text(encoding="utf-8"))["case"]:
            for side in ("vulnerable", "fixed"):
                cases[(population, memory.repo_key(case["repo"]), case[side], side)] = case["id"]
    rows = [r.row for r in store.rows(kind="example")]
    if not rows:
        raise ValueError("dry run read no examples from the store")
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        count = counts[row["source"]]
        count["examples"] += 1
        old = row["instruments"]["engine"]
        reason = "not_run" if old.get("version") == "missing:not-run" else "none" if old["state"] == "none" else None
        if reason is None:
            continue
        key = (row["split"], row["repo"], row["pin"], row["pin_role"])
        case_id = cases.get(key)
        if case_id is None:
            continue
        scans = results / row["split"].replace("population", "independent") / "scans"
        result = resolve_scan(scans, case_id, row["pin_role"])
        path, _, function = row["candidate"].partition("::")
        engine = {}
        if engine_for(result) is None:
            index = PinSourceIndex(cache / "independent" / case_id, row["pin"])
            lines = index.lines(path)  # fail loudly if the candidate's input cannot be read
            count["source_bytes_read"] += len("\n".join(lines).encode("utf-8"))
            selected = dict(result or {})
            selected["findings"] = [f for f in selected.get("findings", []) if f["site"].partition(":")[0] == path]
            _, engine = _signals(index, [], selected, {})
        part = recorded_engine(row["language"], engine.get((path, function, row["family"]), []), result, True)
        if part.state == "ran":
            count[f"{reason}_to_ran"] += 1
        elif result is not None and part.state == "failed":
            count[f"{reason}_to_recorded_failed"] += 1
    return {source: {**{"not_run_to_ran": 0, "none_to_ran": 0}, **dict(count)} for source, count in sorted(counts.items())}


def done(run: Path, entry: str) -> bool:
    state = (read_json(run / "state.json") or {}).get("tasks", {})
    return state.get(entry, {}).get("status") == "done"


class Signals:
    """The harvested model signals: verify/agree per unit name, model roles per unit name."""

    def __init__(self, verify_run: Path, roles_run: Path, v46: Path) -> None:
        self.verify_run, self.roles_run, self.v46 = verify_run, roles_run, v46
        self.roles: dict[str, tuple[dict[str, Any], set[str]]] = {}
        state = (read_json(roles_run / "state.json") or {}).get("tasks", {})
        for entry, info in state.items():
            if info.get("status") != "done":
                continue
            payload = read_json(roles_run / entry / "roles.json") or {}
            classified = {str(r["path"]) for r in jsonl(roles_run / entry / "units.jsonl") if "error" not in r}
            self._index_roles(entry.removesuffix("-roles"), payload, classified)

    def _index_roles(self, owner: str, payload: Mapping[str, Any], classified: set[str]) -> None:
        grouped = any("/" in p and p.split("/", 1)[0].startswith("h-") for p in classified)
        if not grouped:  # a pin's Task: the paths are the repository's
            self.roles[owner] = (dict(payload), classified)
            return
        for unit in {p.split("/", 1)[0] for p in classified}:
            prefix = unit + "/"

            def strip(paths: Any, prefix: str = prefix) -> list[str]:
                return [p.removeprefix(prefix) for p in paths if str(p).startswith(prefix)]

            rows = [
                r | {"path": r["path"].removeprefix(prefix)}
                for r in payload.get("roles") or ()
                if str(r.get("path", "")).startswith(prefix)
            ]
            unit_payload = {
                "model": payload.get("model"),
                "roles": rows,
                "unclassified_paths": strip(payload.get("unclassified_paths") or ()),
            }
            self.roles[unit] = (unit_payload, set(strip(classified)))

    def passes(self, base: Path, entry_stem: str) -> tuple[dict[str, list], dict[str, str | None], Any] | None:
        if not (done(base, f"{entry_stem}-va") and done(base, f"{entry_stem}-vb")):
            return None
        passes = {p: jsonl(base / f"{entry_stem}-v{p}" / "units.jsonl") for p in PASSES}
        models = {p: (read_json(base / f"{entry_stem}-v{p}" / "summary.json") or {}).get("model") for p in PASSES}
        final = base / f"{entry_stem}-final" / "agreed.json"
        agreed = read_json(final if final.is_file() else base / f"{entry_stem}-agree" / "agreed.json")
        return passes, models, agreed


def final_of(agreed: Any, candidate: str) -> str | None:
    if not agreed:
        return None
    disputed = {str(d["candidate"]) for d in agreed.get("disputed") or []}
    for row in agreed.get("candidates") or []:
        if str(row["candidate"]) == candidate:
            return "agreed" if row.get("agreed") else "disputed" if candidate in disputed else "rejected"
    return None


def plane_parts(signals: Signals, stems: list[tuple[Path, str]], roles_owner: str | None, candidate: str, line: int,
                path: str, function: str,
                verify_expected: bool) -> dict[str, Part]:  # fmt: skip
    """verify, agree, model_sinks of one candidate: ``stems`` are (run dir, entry stem) that may have asked it."""
    parts: dict[str, Part] = {"verify": NONE, "agree": NONE}
    pending = False
    for base, stem in stems:
        got = signals.passes(base, stem)
        if got is None:
            pending = pending or (base == signals.verify_run and verify_expected)
            continue
        passes, models, agreed = got
        part = verify_part(passes, candidate, line, "+".join(sorted({m for m in models.values() if m})) or None)
        if part.state == "ran":
            parts = {"verify": part, "agree": agree_part(final_of(agreed, candidate))}
            break
    else:
        if pending:
            parts = {"verify": MISSING, "agree": MISSING}
    if roles_owner is None or roles_owner not in signals.roles:
        parts["model_sinks"] = MISSING
    else:
        payload, classified = signals.roles[roles_owner]
        if path not in classified:
            parts["model_sinks"] = MISSING
        else:
            parts["model_sinks"] = model_sinks_part(from_model_roles(payload), path, function, str(payload.get("model") or "") or None)
    return parts


def static_parts(root: Path, index: SourceIndex, quick: Mapping, engine: Mapping, engine_state: Part | None, engine_result: Mapping | None,
                 inferred: RoleSet, rules: Mapping, quick_version: str, path: str, function: str, family: str, repository: bool,
                 entries: tuple[set[str], set[str]] | None) -> dict[str, Part]:  # fmt: skip
    language = detect_language(Path(path)) or "other"
    key = (path, function, family)
    parts: dict[str, Part] = {}
    parts["quick"] = quick_part(quick.get(key, []), rules, quick_version) if covers(QUICK_LANGUAGES, language) else NONE
    parts["engine"] = recorded_engine(language, engine.get(key, []), engine_result, repository)
    lines = index.lines(path)
    parts["source"] = source_part(lines, language, function)
    parts["roles"] = roles_part(function_of(lines, path, language, function), inferred, language)
    parts["delta"] = NOT_APPLICABLE
    if repository and entries is not None:
        distance = 0 if function == GLOBAL and path in entries[1] else entry_distance(function, entries[0], index.callers())
        parts["entry_points"] = Part("ran", {"facts.entry_distance": distance})
        parts["facts"] = facts_part(_callers_of(index, index.callers(), path, function), function, "host")
    else:
        parts["entry_points"] = NOT_APPLICABLE
        parts["facts"] = NOT_APPLICABLE
    return parts


def engine_for(result: Mapping[str, Any] | None) -> Part | None:
    """None when the engine ran (its findings feed engine_part); else the state Part."""
    if result is None:
        return MISSING
    state = result.get("state", "ran" if result.get("questions") else "failed")
    if state == "ran" and int(result.get("questions") or 0) > 0:
        return None
    if state == "none":
        return NONE
    return Part("failed", version=str(result.get("image") or "recorded"))


def export(clone: Path, pin: str, target: Path) -> bool:
    target.mkdir(parents=True)
    archive = target.parent / "pin.tar"
    with archive.open("wb") as stream:
        ok = subprocess.run(["git", "-C", str(clone), "archive", pin], stdout=stream, check=False).returncode == 0
    ok = ok and subprocess.run(["tar", "-xf", str(archive), "-C", str(target)], check=False).returncode == 0
    archive.unlink(missing_ok=True)
    return ok and any(target.iterdir())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--units", type=Path, help="units.json of the harvest plane")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "openultrasast")
    parser.add_argument("--engine", type=Path, default=RESULTS / "plane" / "harvest-engine")
    parser.add_argument("--verify-run", type=Path, default=RESULTS / "plane" / "harvest-verify")
    parser.add_argument("--roles-run", type=Path, default=RESULTS / "plane" / "harvest-roles")
    parser.add_argument("--v46", type=Path, default=RESULTS / "plane" / "validation-46")
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--min-free-gb", type=float, default=1.2)
    parser.add_argument("--counts", type=Path)
    parser.add_argument("--store", help="OUSAST_MEMORY spec (default: the environment's)")
    parser.add_argument("--limit", type=int, default=0, help="stop after this many targets (a test)")
    parser.add_argument("--kinds", default="pairs,pin", help="which targets: pairs, pin (population and recipe pins)")
    parser.add_argument("--results-root", type=Path, default=RESULTS)
    parser.add_argument("--dry-run", action="store_true", help="read local stored examples and print engine changes by source; no writes")
    args = parser.parse_args()
    if args.dry_run:
        spec = args.store or os.environ.get("OUSAST_MEMORY") or ""
        if spec and not spec.startswith("file://"):
            parser.error("--dry-run requires a local file:// store (no network)")
        store = memory.open_store(spec)
        if not isinstance(store, memory.FileStore):
            parser.error("--dry-run requires a local file:// store (no network)")
        print(json.dumps({"dry_run": True, "by_source": dry_run(store, args.results_root, args.cache)}, sort_keys=True))
        return 0
    if any(getattr(args, name) is None for name in ("labels", "units", "scratch", "counts")):
        parser.error("--labels, --units, --scratch and --counts are required unless --dry-run is used")

    labels = [r for r in jsonl(args.labels) if r["unit"] == "pin" and r["source"] not in CONDITIONAL_SOURCES and not r.get("conditional")]
    units = json.loads(args.units.read_text(encoding="utf-8"))
    by_pair = {(u["ref"], u["side"]): n for n, u in units.items() if u["source"] == "pairs"}
    by_pin: dict[tuple[str, str], list[str]] = defaultdict(list)
    for n, u in units.items():
        if u["source"] != "pairs":
            by_pin[(u["repo"], u["pin"])].append(n)
    targets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in labels:
        key = ("pairs", row["source_ref"], row["pin_role"]) if row["source"] == "pairs" else ("pin", row["repo"], row["pin"])
        targets[key].append(row)
    cases = {c.name: c for c in load_pair_catalog(args.catalog)}
    loaded = load_ruleset(DEFAULT_RULESET_DIR)
    rules = {r.rule_id: r for r in loaded}
    quick_version = ruleset_digest(loaded)
    signals = Signals(args.verify_run, args.roles_run, args.v46)
    store = memory.open_store(args.store)
    tally: Counter[tuple[str, ...]] = Counter()
    coverage: dict[str, Counter[str]] = defaultdict(Counter)
    skipped: Counter[str] = Counter()
    absent: Counter[str] = Counter()  # family -> labelled pair candidates their side does not declare
    dropped = 0
    reingested = 0  # rows the index remembered from an earlier build but a later one had dropped
    args.scratch.mkdir(parents=True, exist_ok=True)
    chosen = [(k, r) for k, r in sorted(targets.items()) if k[0] in args.kinds.split(",")]
    for number, ((kind, ref, role_or_pin), rows) in enumerate(chosen):
        if args.limit and number >= args.limit:
            break
        with tempfile.TemporaryDirectory(dir=args.scratch) as tmp:
            root = Path(tmp) / "tree"
            if kind == "pairs":
                name = by_pair.get((ref, role_or_pin))
                if name is None or ref not in cases:
                    skipped["pair side not in the harvest units"] += len(rows)
                    continue
                unit = units[name]
                _materialize_side(root, cases[ref], side="vuln" if role_or_pin == "vulnerable" else "fixed")
                engine_result = read_json(args.engine / f"{ref}--{'vuln' if role_or_pin == 'vulnerable' else 'fixed'}.json")
                stems = [(args.verify_run, name)]
                owner, repository, repo, pin = name, False, unit["repo"], unit["pin"]
            else:
                names = by_pin.get((ref, role_or_pin), [])
                if not names:
                    skipped["pin not in the harvest units"] += len(rows)
                    continue
                unit = units[names[0]]
                repo, pin, repository = ref, role_or_pin, True
                if shutil.disk_usage(args.scratch).free / 1e9 < args.min_free_gb:
                    skipped["disk guard: pin not exported"] += len(rows)
                    continue
                if unit["source"] == "dev-php":
                    source_dir = args.cache / "repos" / unit["ref"].split(":")[0] / pin[:12]
                    shutil.copytree(source_dir, root, symlinks=True, ignore=shutil.ignore_patterns(".git"))
                    engine_result = None
                else:
                    case_id = unit["ref"]
                    if not export(args.cache / "independent" / case_id, pin, root):
                        skipped["pin export failed"] += len(rows)
                        continue
                    split = {r["split"] for r in rows} | {unit["source"]}
                    population = "independent-v1" if "population-v1" in split else "independent-v2"
                    engine_result = resolve_scan(args.results_root / population / "scans", case_id, rows[0]["pin_role"])
                stems = [(args.verify_run, n) for n in names] + [(args.v46, unit["ref"])]
                owner = next(
                    (n for n in names if f"{n}-roles" in {e for e in (read_json(args.roles_run / "state.json") or {}).get("tasks", {})}),
                    names[0],
                )
            index = SourceIndex(root)
            targets_ = _targets(root)
            findings = quick_scan_findings(root, targets_, rank_targets(targets_), None)
            engine_state = engine_for(engine_result)
            quick, engine = _signals(index, findings, engine_result if engine_state is None else None, rules)
            inferred = infer_for_checkout(root)
            entries = entry_names(root, {r["candidate"].partition("::")[0] for r in rows}) if repository else None
            out_rows: list[dict[str, Any]] = []
            seen: set[tuple[str, str]] = set()
            for row in rows:
                candidate, family = row["candidate"], row["family"]
                if (candidate, family) in seen:
                    continue
                seen.add((candidate, family))
                path, _, function = candidate.partition("::")
                if kind == "pairs" and not declares(index.lines(path), path, function):
                    skipped["absent_on_side"] += 1  # a name from the other side: no candidate here, its verdicts unused
                    absent[family] += 1
                    continue
                cand_line = next((c[2] for n in ([owner] if kind == "pairs" else by_pin[(repo, pin)]) for c in units[n]["candidates"]
                                  if f"{c[0]}::{c[1]}" == candidate), None)  # fmt: skip
                parts = static_parts(root, index, quick, engine, engine_state, engine_result, inferred, rules, quick_version, path,
                                     function, family, repository, entries)  # fmt: skip
                language = detect_language(Path(path)) or "other"
                verify_expected = any(units[n]["family"] == family for n in ([owner] if kind == "pairs" else by_pin[(repo, pin)]))
                plane = {**parts, **plane_parts(signals, stems, owner, candidate, cand_line or 1, path, function, verify_expected)}
                for profile, use in (("static", parts), ("plane", plane)):
                    rec = record(candidate, family, language, profile, use)
                    out_rows.append({
                        "id": memory.row_id("features", "harvest", owner, f"{candidate}:{family}:{profile}"), "kind": "features",
                        "repo": memory.repo_key(repo), "pin": pin, "run": "harvest", "task": owner, "population": row["source"],
                        "split": row["split"], "image": str((engine_result or {}).get("image") or "none"), **rec,
                    })  # fmt: skip
                    tally[(profile, family)] += 1
                    if profile == "plane":
                        for inst, info in rec["instruments"].items():
                            state = "missing" if info.get("version") == "missing:not-run" else info["state"]
                            coverage[f"{family}:{inst}"][state] += 1
            ingested = store.ingest_rows("harvest", f"features:{owner}", out_rows)
            built = {r["id"] for r in out_rows}
            stored = store.rows(repo=memory.repo_key(repo), pin=pin, kind="features", where={"run": "harvest", "task": owner})
            present = {r.row["id"] for r in stored}
            restored = 0
            if ingested.skipped and not built <= present:
                # the index remembers these very rows from an earlier build, but a later build dropped them as stale
                # (the side did not declare the function then); an index hit is not evidence the rows are there
                store.put_rows(out_rows)
                restored = len(built - present)
                reingested += restored
            stale = [r.row["id"] for r in stored if r.row["id"] not in built]
            dropped += store.drop_rows(memory.repo_key(repo), pin, stale)
            print(json.dumps({"target": owner, "rows": len(out_rows), "dropped": len(stale), "restored": restored}), flush=True)
    counts = {
        "absent_on_side": dict(sorted(absent.items())),
        "dropped_stale_rows": dropped,
        "restored_after_drop": reingested,
        "records": {f"{p}:{f}": n for (p, f), n in sorted(tally.items())},
        "instrument_states_plane": {k: dict(sorted(v.items())) for k, v in sorted(coverage.items())},
        "skipped_label_rows": dict(skipped),
        "store": store.describe(),
    }
    args.counts.write_text(json.dumps(counts, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"records": sum(tally.values()), "skipped": dict(skipped)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
