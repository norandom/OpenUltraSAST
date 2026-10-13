"""Semgrep CE as a benchmark arm: our regex rules and taint facts converted, run per frozen change.

Two subcommands. ``rules`` converts every enabled quick rule to a ``pattern-regex`` rule and every
source/sink/sanitizer fact triple to a ``mode: taint`` rule, one YAML file per language, and writes a
conversion report naming what was skipped and why. ``run`` checks out each frozen change's head into a
temporary worktree, runs Semgrep over the changed files only, proves the targets were read (bytes per
file), and writes one scorer-shaped record per change, resumable exactly like ``hunter_arm``.

Nothing here ships: the rules are ours, the engine is a measurement instrument.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

import yaml

from openultrasast.hunter_tools import clamp_repo_path
from openultrasast.model.taxonomy import load_families
from openultrasast.ruleset import DEFAULT_RULESET_DIR, load_ruleset
from openultrasast.semantic.facts import DEFAULT_FACTS_DIR, load_facts

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.unseen.extract import SHA, InstrumentFailure
from benchmarks.unseen.replay import canonical, load_slice
from benchmarks.valid.catalog import local_git

# Our language ids to Semgrep's. Groovy has no Semgrep parser: `generic` plus a path filter.
SEMGREP_LANGUAGES = {
    "c": "c",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "php": "php",
}
GENERIC_PATHS = {"groovy": ["*.groovy", "*.tpl"]}
# The rule file a rule lands in: one per language family.
FILE_OF_LANGUAGE = {"cpp": "c", "typescript": "javascript"}
# Fact languages whose Semgrep rules need a second dialect.
FACT_DIALECTS = {"c": ["c", "cpp"], "javascript": ["javascript", "typescript"]}
# PHP language constructs are not calls: `echo(...)` would parse as a call expression, and Semgrep's PHP
# pattern parser takes `echo` only as a whole statement.
PHP_CONSTRUCTS = {
    "echo": "echo $VALUE;",
    "print": "print $VALUE;",
    "include": "include ...",
    "include_once": "include_once ...",
    "require": "require ...",
    "require_once": "require_once ...",
}
# DOM properties assigned, not called.
ASSIGNED_SINKS = {"innerHTML", "outerHTML"}
SEMGREP_FLAGS = (
    "--json",
    "--metrics=off",
    "--disable-version-check",
    "--no-git-ignore",
    "--timeout",
    "60",
    "--max-memory",
    "1500",
    "-j",
    "1",
)
# A Semgrep launch that returns faster than its own startup never ran the engine.
MIN_PLAUSIBLE_SECONDS = 1.0
# PCRE2 compiles a bounded repeat of a group by copying it: `(?:...){0,2000}?` is "too large". The lazy
# unbounded form keeps the match and widens the window from 2000 characters to the statement.
BOUNDED_GROUP_REPEAT = re.compile(r"\{0,\d+\}\?")


def _family_of(cwe):
    family = load_families().family_of_cwe(cwe or "")
    return family.id if family else "unknown"


def _ident(value):
    return re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-")


# --- regex rules -------------------------------------------------------------------------------------------


def _raw_rules(ruleset_dir):
    rows = []
    for path in sorted(Path(ruleset_dir).rglob("*.toml")):
        if path.parent.name in {"semantic", "obligations"} or path.parent == Path(ruleset_dir):
            continue
        for item in tomllib.loads(path.read_text()).get("rule", []):
            rows.append(item)
    return rows


def convert_regex_rules(ruleset_dir=DEFAULT_RULESET_DIR, *, min_precision=0.0):
    """Every enabled quick rule as a Semgrep ``pattern-regex`` rule; the rest named with a reason."""
    active = {rule.rule_id: rule for rule in load_ruleset(Path(ruleset_dir))}
    converted, skipped, rewrites = {}, [], []
    for item in _raw_rules(ruleset_dir):
        rule_id = str(item["rule_id"])
        rule = active.get(rule_id)
        if rule is None:
            skipped.append({"origin": rule_id, "reason": f"fallback for {item.get('fallback_for')}: the tagged rule is active"})
            continue
        if rule.status == "disabled":
            skipped.append({"origin": rule_id, "reason": "disabled"})
            continue
        if rule.status == "shadow":
            skipped.append(
                {"origin": rule_id, "reason": f"shadow status (precision_estimate {rule.precision_estimate}); not admitted by the hook"}
            )
            continue
        if rule.precision_estimate < min_precision:
            skipped.append({"origin": rule_id, "reason": f"emit floor: precision_estimate {rule.precision_estimate} < {min_precision}"})
            continue
        if not rule.languages:
            skipped.append({"origin": rule_id, "reason": "non-code file targets: the rule applies to every file"})
            continue
        languages = [SEMGREP_LANGUAGES[language] for language in rule.languages if language in SEMGREP_LANGUAGES]
        generic = [language for language in rule.languages if language in GENERIC_PATHS]
        unsupported = [language for language in rule.languages if language not in SEMGREP_LANGUAGES and language not in GENERIC_PATHS]
        if unsupported:
            skipped.append({"origin": rule_id, "reason": f"no Semgrep language for {unsupported}"})
            continue
        family = _family_of(rule.cwe)
        pattern = BOUNDED_GROUP_REPEAT.sub("*?", rule.pattern)
        if pattern != rule.pattern:
            rewrites.append({"origin": rule_id, "rewrite": "bounded lazy group repeat {0,N}? widened to *? (PCRE2 size limit)"})
        entry = {
            "id": f"ousast.{FILE_OF_LANGUAGE.get(rule.languages[0], rule.languages[0])}.regex.{_ident(rule_id)}",
            "languages": languages or ["generic"],
            "severity": "WARNING",
            "message": rule.title,
            "metadata": {
                "family": family,
                "cwe": rule.cwe,
                "origin": rule_id,
                "precision_estimate": str(rule.precision_estimate),
                "kind": "regex",
                "tags": list(rule.tags),
                "status": rule.status,
                "version": rule.version,
            },
            "pattern-regex": pattern,
        }
        if not languages:
            entry["paths"] = {"include": [glob for language in generic for glob in GENERIC_PATHS[language]]}
        key = FILE_OF_LANGUAGE.get(rule.languages[0], rule.languages[0])
        converted.setdefault(key, []).append(entry)
    return converted, skipped, rewrites


# --- taint facts -------------------------------------------------------------------------------------------


def _call_patterns(call, language):
    """The Semgrep call shapes of one fact token (a function, a method, a construct)."""
    if language == "php":
        if call in PHP_CONSTRUCTS:
            return [PHP_CONSTRUCTS[call]]
        return [f"{call}(...)"]
    if "." in call or "->" in call:
        return [f"{call}(...)"]
    if language == "java" and call[:1].isupper():
        return [f"new {call}(...)"]
    return [f"{call}(...)", f"$OBJ.{call}(...)"]


def _source_patterns(token, language):
    if language == "php":
        if token == "php://input":
            return ['file_get_contents("php://input")']
        return [token, f"{token}[...]"]
    if token.endswith("("):
        return [f"{token}...)"]
    if "." in token:
        return [token, f"{token}(...)"]
    if language == "c":
        return [token, f"{token}(...)"]
    return [token, f"$OBJ.{token}", f"{token}(...)", f"$OBJ.{token}(...)"]


def _sink_entries(call, language, *, format_arg=None, single_argument=False):
    """Sink patterns for one call; a focused argument where the fact names one."""
    if call in ASSIGNED_SINKS:
        return [{"patterns": [{"pattern": f"$OBJ.{call} = $VALUE"}, {"focus-metavariable": "$VALUE"}]}]
    if call == "dangerouslySetInnerHTML":
        return [{"patterns": [{"pattern": "{__html: $VALUE}"}, {"focus-metavariable": "$VALUE"}]}]
    if format_arg is not None:
        arguments = ", ".join([*(f"$ARG{index}" for index in range(format_arg)), "$FORMAT", "..."])
        heads = [call] if "." in call or language == "c" else [call, f"$OBJ.{call}"]
        return [{"patterns": [{"pattern": f"{head}({arguments})"}, {"focus-metavariable": "$FORMAT"}]} for head in heads]
    if single_argument:
        heads = [call] if "." in call or "->" in call else [call, f"$OBJ.{call}"]
        return [{"patterns": [{"pattern": f"{head}($QUERY)"}, {"focus-metavariable": "$QUERY"}]} for head in heads]
    return [{"pattern": pattern} for pattern in _call_patterns(call, language)]


def _weak_literal_rule(language, sink_id, cwe, calls, literals, dialects):
    """A `weak_literals` sink is a search, not a flow: the call with a named weak literal, or a call named after one."""
    alternatives = []
    lowered = {literal.lower() for literal in literals}
    for call in sorted(calls):
        for head in [call] if "." in call else [call, f"$OBJ.{call}"]:
            if call.rsplit(".", 1)[-1].lower() in lowered:
                alternatives.append({"pattern": f"{head}(...)"})
            else:
                alternatives.append(
                    {
                        "patterns": [
                            {"pattern": f"{head}($ALGORITHM, ...)"},
                            {
                                "metavariable-regex": {
                                    "metavariable": "$ALGORITHM",
                                    "regex": "^[\"']?(" + "|".join(re.escape(literal) for literal in sorted(literals)) + ")[\"']?$",
                                }
                            },
                        ]
                    }
                )
    return {
        "id": f"ousast.{language}.weak.{_ident(sink_id)}",
        "languages": dialects,
        "severity": "WARNING",
        "message": f"{sink_id}: a weak literal reaches {', '.join(sorted(calls))}",
        "metadata": {
            "family": _family_of(cwe),
            "cwe": cwe,
            "origin": f"sink:{language}:{sink_id}",
            "precision_estimate": "unmeasured",
            "kind": "weak_literal",
            "weak_literals": sorted(literals),
        },
        "pattern-either": alternatives,
    }


def convert_facts(facts_dir=DEFAULT_FACTS_DIR):
    """One taint rule per (language, sink id, CWE); the facts Semgrep has no word for are named, not dropped silently."""
    facts = load_facts(Path(facts_dir))
    converted, skipped, lossy = {}, [], []
    for language in sorted({fact.language for fact in facts.sinks}):
        scoped = facts.for_language(language)
        dialects = FACT_DIALECTS.get(language, [SEMGREP_LANGUAGES[language]])
        sources = [
            {"pattern": pattern} for fact in scoped.sources for token in fact.patterns for pattern in _source_patterns(token, language)
        ]
        parameterized = set()
        sanitizers = []
        for fact in scoped.sanitizers:
            origin = f"sanitizer:{language}:{fact.id}"
            if fact.guard:
                skipped.append({"origin": origin, "reason": "guard: a check whose safety depends on dominance; Semgrep has no equivalent"})
                continue
            if fact.parameterized:
                parameterized.update(fact.calls)
                skipped.append(
                    {"origin": origin, "reason": "parameterized: a call shape, not a cleansing; expressed as the single-argument sink form"}
                )
                continue
            if fact.literal_format_arg is not None:
                skipped.append(
                    {
                        "origin": origin,
                        "reason": "literal_format_arg: a shape; a literal format is never tainted at the focused sink argument",
                    }
                )
                continue
            if fact.quoted_only:
                loss = {"origin": origin, "loss": "quoted_only escape treated as a full sanitizer (silences the CVE-2024-1071 shape)"}
                if loss not in lossy:
                    lossy.append(loss)
            sanitizers.extend({"pattern": pattern} for call in fact.calls for pattern in _call_patterns(call, language))
        for fact in scoped.dispatches:
            skipped.append(
                {
                    "origin": f"dispatch:{language}:{fact.id}",
                    "reason": "dispatch: string-keyed hook registry routing; no Semgrep equivalent",
                }
            )
        for fact in scoped.layouts:
            skipped.append({"origin": f"layout:{language}:{fact.id}", "reason": "layout: scope policy (vendored, tests), not a rule"})
        grouped = {}
        for fact in scoped.sinks:
            grouped.setdefault((fact.id, fact.cwe), []).append(fact)
        for (sink_id, cwe), rows in sorted(grouped.items()):
            origin = f"sink:{language}:{sink_id}"
            calls = sorted({call for row in rows for call in row.calls})
            literals = {literal for row in rows for literal in row.weak_literals}
            if literals:
                converted.setdefault(language, []).append(_weak_literal_rule(language, sink_id, cwe, calls, literals, dialects))
                continue
            entries, extra_sanitizers = [], []
            format_arg = next((row.format_arg for row in rows if row.format_arg is not None), None)
            for call in calls:
                if call == "v-html":
                    skipped.append({"origin": f"{origin}:{call}", "reason": "template directive, not a call"})
                    continue
                entries.extend(_sink_entries(call, language, format_arg=format_arg, single_argument=call in parameterized))
            for row in rows:
                if row.prefix_fixes_origin:
                    lossy.append(
                        {"origin": origin, "loss": "prefix_fixes_origin: a value appended after a fixed origin still counts as tainted"}
                    )
                    break
            for anchor in sorted({anchor for row in rows for anchor in row.origin_anchors}):
                extra_sanitizers.extend({"pattern": pattern} for pattern in _call_patterns(anchor, language))
            if not entries:
                skipped.append({"origin": origin, "reason": "no call form survives conversion"})
                continue
            rule = {
                "id": f"ousast.{language}.taint.{_ident(sink_id)}",
                "mode": "taint",
                "languages": dialects,
                "severity": "ERROR",
                "message": f"{sink_id}: untrusted input reaches {', '.join(calls)}",
                "metadata": {
                    "family": _family_of(cwe),
                    "cwe": cwe,
                    "origin": origin,
                    "precision_estimate": "unmeasured",
                    "kind": "taint",
                    "calls": calls,
                },
                "pattern-sources": [{"pattern-either": sources}],
                "pattern-sinks": [{"pattern-either": entries}],
            }
            if sanitizers or extra_sanitizers:
                rule["pattern-sanitizers"] = [{"pattern-either": [*sanitizers, *extra_sanitizers]}]
            converted.setdefault(language, []).append(rule)
    return converted, skipped, lossy


def _obligation_tables(ruleset_dir):
    count = 0
    for path in sorted((Path(ruleset_dir) / "obligations").glob("*.toml")):
        payload = tomllib.loads(path.read_text())
        count += sum(len(value) for value in payload.values() if isinstance(value, list))
    return count


def write_rules(out, *, ruleset_dir=DEFAULT_RULESET_DIR, facts_dir=DEFAULT_FACTS_DIR, min_precision=0.0, semgrep=None):
    """Write one YAML per language under ``out`` plus ``conversion_report.json``; validate with Semgrep when present."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    regex_rules, regex_skipped, rewrites = convert_regex_rules(ruleset_dir, min_precision=min_precision)
    taint_rules, fact_skipped, lossy = convert_facts(facts_dir)
    files = {}
    for language in sorted(set(regex_rules) | set(taint_rules)):
        rules = [*regex_rules.get(language, []), *taint_rules.get(language, [])]
        path = out / f"{language}.yaml"
        path.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False, width=200, allow_unicode=True))
        files[path.name] = len(rules)
    obligations = _obligation_tables(ruleset_dir)
    report = {
        "regex": {
            "converted": sorted(rule["metadata"]["origin"] for rules in regex_rules.values() for rule in rules),
            "skipped": regex_skipped,
            "rewritten": rewrites,
        },
        "facts": {
            "converted": sorted(rule["metadata"]["origin"] for rules in taint_rules.values() for rule in rules),
            "skipped": fact_skipped,
            "lossy": lossy,
        },
        "obligations": {
            "skipped_tables": obligations,
            "reason": "an obligation finds a missing guard (an absence), which no pattern expresses",
        },
        "not_carried": [
            "comment skipping: the quick engine drops a regex match inside a comment; pattern-regex does not",
            "framework priors and fallback rules: the tagged rule is emitted, its language-level fallback is not",
            "min_evidence_level, ranking priority, the rung: post-match policy on our side",
        ],
        "files": files,
        "validation": None,
    }
    binary = semgrep or shutil.which("semgrep")
    if binary:
        try:
            completed = subprocess.run(
                [binary, "--validate", "--config", str(out), "--metrics=off", "--disable-version-check"], capture_output=True, text=True
            )
        except OSError as error:
            report["validation"] = {"exit": None, "error": f"semgrep not found or not runnable: {type(error).__name__}"}
        else:
            report["validation"] = {"exit": completed.returncode, "stderr": completed.stderr[-4000:], "stdout": completed.stdout[-4000:]}
    (out / "conversion_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


# --- run ---------------------------------------------------------------------------------------------------


def result_defect(result):
    """One Semgrep result as a scorer defect; the family and CWE come from the rule's own metadata."""
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    path = result["path"]
    line = result.get("start", {}).get("line", 0)
    origin = metadata.get("origin", result["check_id"])
    return {
        "defect_id": f"{origin}:{path}:{line}",
        "family": metadata.get("family", "unknown"),
        "cwe": metadata.get("cwe"),
        "locations": [[path, line]],
        "source": "semgrep",
        "rule_id": result["check_id"],
        "origin": origin,
        "title": extra.get("message", ""),
        "rationale": extra.get("message", ""),
        "confidence": extra.get("severity"),
        "dataflow": bool(extra.get("dataflow_trace")),
    }


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def _record_path(out, identity):
    return out / (hashlib.sha256(identity.encode()).hexdigest() + ".json")


def _inputs(out):
    path = out / "inputs.json"
    entries = json.loads(path.read_text()) if path.exists() else []
    for key in (lambda entry: entry["item_id"], lambda entry: entry["change"]["id"]):
        if len({key(entry) for entry in entries}) != len(entries):
            raise ValueError(f"duplicate ids in {path}")
    return entries


def run_semgrep(binary, rules, root, targets, *, timeout=900):
    """Semgrep over explicit targets inside ``root``; paths in the output stay repository-relative."""
    argv = [binary, "scan", "--config", str(rules), *SEMGREP_FLAGS, *targets]
    started = time.monotonic()
    completed = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=timeout)
    return completed, time.monotonic() - started


def _scan_change(change, repos, rules, *, binary):
    instrument = {
        "hook_exit": 0,
        "hook_bytes_read": 0,
        "changed_bytes": {},
        "head_verified": False,
        "base_verified": False,
        "failure": None,
        "suspect_fast": False,
        "semgrep": {"exit": None, "wall_seconds": None, "scanned": [], "errors": [], "results": 0},
    }
    record = {
        "id": change["id"],
        "done": True,
        "status": "semgrep_covered",
        "instrument": instrument,
        "push": {"admission": {"defects": [], "dispositions": []}, "quick_tier": []},
        "skipped": [],
    }
    try:
        if not all(SHA.fullmatch(change[side]) for side in ("base", "head")):
            raise InstrumentFailure("invalid_revision")
        git = local_git(Path(repos[change["repo"]]).expanduser().resolve())
        git.run("cat-file", "-e", change["base"] + "^{commit}")
        instrument["base_verified"] = True
        with tempfile.TemporaryDirectory(prefix="ousast-semgrep-") as temporary:
            root = Path(temporary) / "head"
            added = False
            try:
                git.run("-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", str(root), change["head"])
                added = True
                if local_git(root).run("rev-parse", "HEAD").strip() != change["head"]:
                    raise InstrumentFailure("head_mismatch")
                instrument["head_verified"] = True
                targets = []
                for relative in dict.fromkeys(file["path"] for file in change.get("files", [])):
                    path = clamp_repo_path(root, relative)
                    try:
                        path.stat()
                    except FileNotFoundError:
                        record["skipped"].append({"path": relative, "reason": "missing_at_head"})
                        print(f"{change['id']} {relative}: skipped (missing_at_head)", flush=True)
                        continue
                    try:
                        data = path.read_bytes()
                    except OSError:
                        print(f"{change['id']} {relative}: 0 bytes read", flush=True)
                        raise InstrumentFailure(f"unreadable_target:{relative}") from None
                    size = len(data)
                    print(f"{change['id']} {relative}: {size} bytes read", flush=True)
                    if not size:
                        record["skipped"].append({"path": relative, "reason": "empty_at_head"})
                        continue
                    instrument["changed_bytes"][relative] = size
                    instrument["hook_bytes_read"] += size
                    targets.append(relative)
                if not targets:
                    raise InstrumentFailure("no_readable_targets")
                try:
                    completed, wall = run_semgrep(binary, rules, root, targets)
                except subprocess.TimeoutExpired:
                    raise InstrumentFailure("semgrep_timeout") from None
                semgrep = instrument["semgrep"]
                semgrep.update(exit=completed.returncode, wall_seconds=round(wall, 3))
                instrument["hook_exit"] = completed.returncode
                if wall < MIN_PLAUSIBLE_SECONDS:
                    instrument["suspect_fast"] = True
                if completed.returncode not in (0, 1):
                    semgrep["stderr"] = completed.stderr[-2000:]
                    raise InstrumentFailure(f"semgrep_exit_{completed.returncode}")
                try:
                    payload = json.loads(completed.stdout)
                except json.JSONDecodeError:
                    semgrep["stderr"] = completed.stderr[-2000:]
                    raise InstrumentFailure("semgrep_output_unreadable") from None
                semgrep["scanned"] = sorted(payload.get("paths", {}).get("scanned", []))
                semgrep["errors"] = [
                    {"type": str(error.get("type")), "path": error.get("path"), "message": str(error.get("message", ""))[:300]}
                    for error in payload.get("errors", [])
                ]
                results = payload.get("results", [])
                semgrep["results"] = len(results)
                record["push"]["admission"]["defects"] = [result_defect(result) for result in results]
                print(f"{change['id']}: semgrep exit {completed.returncode}, {len(results)} results, {wall:.1f}s", flush=True)
            finally:
                if added:
                    git.run("worktree", "remove", "--force", str(root))
    except Exception as error:  # noqa: BLE001
        reason = str(error) if isinstance(error, InstrumentFailure) else type(error).__name__
        instrument.update(hook_exit=2, failure=reason)
        record["status"] = "instrument_failure"
        record["push"]["admission"]["defects"] = []
        print(f"{change['id']}: instrument_failure ({reason})", file=sys.stderr, flush=True)
    return record


def run(manifest, repos_path, rules, out, *, slice_id="1", only="all", semgrep=None):
    binary = semgrep or shutil.which("semgrep")
    if binary is None:
        print("No semgrep binary found on PATH.", file=sys.stderr)
        return 2
    rules = Path(rules).expanduser().resolve()
    if not rules.is_dir():
        raise ValueError(f"rules directory missing: {rules}")
    changes = load_slice(manifest, slice_id)
    if len({change["id"] for change in changes}) != len(changes):
        raise ValueError("duplicate change ids")
    changes = [change for change in changes if only == "all" or change["kind"] == only]
    entries = _inputs(out)
    indexed = {entry["change"]["id"]: entry for entry in entries}
    pending = []
    for change in changes:
        path = _record_path(out, change["id"])
        previous = json.loads(path.read_text()) if path.exists() else {}
        entry = indexed.get(change["id"])
        if entry is None:
            entry = {
                "item_id": change["id"],
                "change": change,
                "input_digest": previous.get("input_digest") or hashlib.sha256(canonical(change)).hexdigest(),
            }
            entries.append(entry)
        elif entry["change"] != change or entry["item_id"] != change["id"]:
            raise ValueError("existing semgrep inputs do not match frozen change")
        if previous.get("done") is True:
            print(f"{change['id']}: skipped (done)", flush=True)
            continue
        pending.append(entry)
    _write_json(out / "inputs.json", entries)
    if not pending:
        return 0
    repos = json.loads(Path(repos_path).expanduser().read_text())
    failed = False
    for entry in pending:
        record = _scan_change(entry["change"], repos, rules, binary=binary)
        record["input_digest"] = entry["input_digest"]
        _write_json(_record_path(out, entry["item_id"]), record)
        failed |= record["status"] == "instrument_failure"
    return 2 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    rules = commands.add_parser("rules", help="convert the ruleset and the facts into Semgrep rules")
    rules.add_argument("--out", type=Path, required=True)
    rules.add_argument("--ruleset", type=Path, default=DEFAULT_RULESET_DIR)
    rules.add_argument("--facts", type=Path, default=DEFAULT_FACTS_DIR)
    rules.add_argument("--min-precision", type=float, default=0.0, help="the hook's min_emit_precision floor")
    rules.add_argument("--semgrep", help="semgrep binary (default: PATH)")
    scan = commands.add_parser("run", help="run Semgrep over each frozen change's changed files")
    scan.add_argument("manifest", type=Path)
    scan.add_argument("--slice", default="1")
    scan.add_argument("--repos", type=Path, required=True)
    scan.add_argument("--rules", type=Path, required=True)
    scan.add_argument("--out", type=Path, required=True)
    scan.add_argument("--only", choices=("vulnerability", "ordinary", "all"), default="all")
    scan.add_argument("--semgrep", help="semgrep binary (default: PATH)")
    args = parser.parse_args(argv)
    if args.command == "rules":
        report = write_rules(
            args.out, ruleset_dir=args.ruleset, facts_dir=args.facts, min_precision=args.min_precision, semgrep=args.semgrep
        )
        validation = report["validation"]
        print(
            f"regex converted {len(report['regex']['converted'])}, skipped {len(report['regex']['skipped'])}; "
            f"facts converted {len(report['facts']['converted'])}, skipped {len(report['facts']['skipped'])}, "
            f"lossy {len(report['facts']['lossy'])}; "
            f"obligations skipped {report['obligations']['skipped_tables']}; "
            f"validation {'not run' if validation is None else 'exit ' + str(validation['exit'])}"
        )
        return 0 if validation is None or validation["exit"] == 0 else 2
    return run(args.manifest, args.repos, args.rules, args.out.expanduser(), slice_id=args.slice, only=args.only, semgrep=args.semgrep)


if __name__ == "__main__":
    raise SystemExit(main())
