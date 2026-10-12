"""Run the shipped tool hunter on local frozen changes, then join replay records."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from copy import deepcopy
from pathlib import Path

from openultrasast import tool_hunter
from openultrasast.complexity.map import Hotspot
from openultrasast.config import load_config
from openultrasast.hunter_tools import clamp_repo_path
from openultrasast.model.endpoint import resolve_models
from openultrasast.model.taxonomy import FAMILY_IDS, load_families

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.unseen.extract import SHA, InstrumentFailure
from benchmarks.unseen.replay import canonical, load_slice
from benchmarks.unseen.score import load_records
from benchmarks.valid.catalog import local_git

# These names describe findings, never benchmark labels. The taxonomy owns the
# family mapping; an ambiguous family alone does not establish a particular CWE.
_WEAKNESSES = (
    (r"\bsql[ _-]injection\b", "CWE-89"),
    (r"\b(?:os[ _-])?command[ _-]injection\b", "CWE-78"),
    (r"\b(?:code[ _-]injection|dynamic execution|remote code execution)\b", "CWE-94"),
    (r"\b(?:ssti|server[ -]side template injection)\b", "CWE-1336"),
    (r"\bcypher[ _-]injection\b", "CWE-943"),
    (r"\b(?:path[ _-]traversal|directory[ _-]traversal)\b", "CWE-22"),
    (r"\b(?:unsafe[ _-]deserialization|insecure[ _-]deserialization)\b", "CWE-502"),
    (r"\b(?:xss|cross[ -]site scripting)\b", "CWE-79"),
    (r"\b(?:ssrf|server[ -]side request forgery)\b", "CWE-918"),
    (r"\bopen[ _-]redirect\b", "CWE-601"),
    (r"\bprototype[ _-]pollution\b", "CWE-1321"),
    (r"\b(?:missing[ _-]authentication|missing[ _-]auth[ _-]guard)\b", "CWE-306"),
    (r"\b(?:missing[ _-]authorization|broken[ _-]access[ _-]control)\b", "CWE-862"),
    (r"\bhardcoded[ _-](?:secret|credential|password)s?\b", "CWE-798"),
)


def finding_defect(finding):
    """Translate the hunter's own CWE, family tag or weakness title to a defect."""
    taxonomy = load_families()
    raw_family = next((tag.split(":", 1)[1].strip() for tag in finding.tags if tag.startswith("family:")), "")
    evidence = " ".join([*finding.tags, finding.title])
    explicit = re.search(r"\bCWE-\d+\b", evidence, re.I)
    cwe = explicit.group().upper() if explicit else next((cwe for pattern, cwe in _WEAKNESSES if re.search(pattern, evidence, re.I)), None)
    mapped = taxonomy.family_of_cwe(cwe or "")
    mechanism = taxonomy.family_of_mechanism(raw_family)
    family = raw_family if raw_family in FAMILY_IDS else mechanism.id if mechanism else mapped.id if mapped else "unknown"
    if mapped and mapped.id != family:
        cwe = None
    return {
        "defect_id": finding.finding_id,
        "family": family,
        "cwe": cwe,
        "function": finding.function_name,
        "locations": [[finding.path, finding.line if finding.line is not None else 0]],
        "source": "hunter",
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


def _hunt_change(change, repos, *, client, model, max_steps):
    instrument = {
        "hook_exit": 0,
        "hook_bytes_read": 0,
        "changed_bytes": {},
        "head_verified": False,
        "base_verified": False,
        "failure": None,
        "suspect_fast": False,
    }
    record = {
        "id": change["id"],
        "done": True,
        "status": "hunter_covered",
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
        with tempfile.TemporaryDirectory(prefix="ousast-hunter-") as temporary:
            root = Path(temporary) / "head"
            added = False
            try:
                git.run("-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", str(root), change["head"])
                added = True
                if local_git(root).run("rev-parse", "HEAD").strip() != change["head"]:
                    raise InstrumentFailure("head_mismatch")
                instrument["head_verified"] = True
                hotspots = []
                for relative in dict.fromkeys(file["path"] for file in change.get("files", [])):
                    path = clamp_repo_path(root, relative)
                    try:
                        path.stat()
                    except FileNotFoundError:
                        reason = {"path": relative, "reason": "missing_at_head"}
                        record["skipped"].append(reason)
                        print(f"{change['id']} {relative}: skipped (missing_at_head)", flush=True)
                        continue
                    try:
                        data = path.read_bytes()
                    except OSError:
                        print(f"{change['id']} {relative}: 0 bytes read", flush=True)
                        raise InstrumentFailure(f"unreadable_hotspot:{relative}") from None
                    size = len(data)
                    print(f"{change['id']} {relative}: {size} bytes read", flush=True)
                    instrument["changed_bytes"][relative] = size
                    instrument["hook_bytes_read"] += size
                    if not size:
                        raise InstrumentFailure(f"empty_hotspot:{relative}")
                    hotspots.append(
                        Hotspot(
                            path=relative,
                            function_name=None,
                            score=1.0,
                            band="low",
                            signals={"bytes_read": size},
                            rationale="Changed file at the frozen head",
                            test_hint=None,
                            inventory_finding_ids=(),
                        )
                    )
                if not hotspots:
                    raise InstrumentFailure("no_readable_hotspots")
                found = tool_hunter.run_tool_hunter(root, hotspots, client=client, model=model, max_steps=max_steps)
                record["push"]["admission"]["defects"] = [finding_defect(finding) for finding in found]
            finally:
                if added:
                    git.run("worktree", "remove", "--force", str(root))
    except Exception as error:  # noqa: BLE001
        # Provider exception messages can contain credentials. Store only the
        # error type, except for our own bounded instrument reasons.
        reason = str(error) if isinstance(error, InstrumentFailure) else type(error).__name__
        instrument.update(hook_exit=2, failure=reason)
        record["status"] = "instrument_failure"
        record["push"]["admission"]["defects"] = []
        print(f"{change['id']}: instrument_failure ({reason})", file=sys.stderr, flush=True)
    return record


def run(manifest, repos_path, out, *, slice_id="1", max_steps=tool_hunter.DEFAULT_MAX_STEPS, only="all", client_mode=None):
    if max_steps < 1:
        raise ValueError("max_steps must be positive")
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
            raise ValueError("existing hunter inputs do not match frozen change")
        if previous.get("done") is True:
            print(f"{change['id']}: skipped (done)", flush=True)
            continue
        pending.append(entry)
    if not pending:
        _write_json(out / "inputs.json", entries)
        return 0
    config_path = Path("openultrasast.toml")
    config = load_config(config_path if config_path.exists() else None, dotenv=client_mode != "scripted")
    model = resolve_models(config)[0]
    client = tool_hunter.scripted_hunter_client() if client_mode == "scripted" else tool_hunter.resolve_hunter_client()
    if client is None:
        print("No hunter client resolved. Configure a hunter provider or use --client scripted for offline tests.", file=sys.stderr)
        return 2
    repos = json.loads(repos_path.read_text())
    _write_json(out / "inputs.json", entries)
    failed = False
    for entry in pending:
        # The built-in script is a finite sequence, so each change needs a fresh
        # sequence. Live clients remain shared and are resolved only once.
        if client_mode == "scripted":
            client = tool_hunter.scripted_hunter_client()
        record = _hunt_change(entry["change"], repos, client=client, model=model, max_steps=max_steps)
        record["input_digest"] = entry["input_digest"]
        _write_json(_record_path(out, entry["item_id"]), record)
        failed |= record["status"] == "instrument_failure"
    return 2 if failed else 0


def _joined(out):
    _inputs(out)
    rows = load_records(out)
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("duplicate joined change ids")
    return {row["id"]: row for row in rows}


def _extend_defects(existing, extra):
    seen = set()
    merged = []
    for defect in [*existing, *extra]:
        locations = []
        for path, line in defect.get("locations", []):
            key = (path, line, defect.get("family"))
            if key not in seen:
                locations.append([path, line])
                seen.add(key)
        if locations:
            merged.append({**defect, "locations": locations})
        elif not defect.get("locations"):
            merged.append(defect)
    return merged


def combine(replay_out, hunter_out, out):
    """Preserve replay coverage while adding independently detected hunter defects."""
    a = _joined(replay_out)
    b = _joined(hunter_out) if (hunter_out / "inputs.json").exists() else {}
    combined = []
    for identity, left in a.items():
        right = b.get(identity, {})
        has_a, has_b = "push" in left, "push" in right
        merged = deepcopy(left if has_a or not has_b else right)
        if has_a and has_b:
            admission = merged["push"].setdefault("admission", {})
            admission["defects"] = _extend_defects(
                admission.get("defects", []),
                right["push"].get("admission", {}).get("defects", []),
            )
        merged["arms"] = {
            "a": left.get("status", "missing") if has_a else "missing",
            "b": right.get("status", "missing") if has_b else "missing",
        }
        combined.append(merged)
    _write_json(out, combined)
    return combined


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    hunt = commands.add_parser("run")
    hunt.add_argument("manifest", type=Path)
    hunt.add_argument("--slice", default="1")
    hunt.add_argument("--repos", type=Path, required=True)
    hunt.add_argument("--out", type=Path, required=True)
    hunt.add_argument("--max-steps", type=int, default=tool_hunter.DEFAULT_MAX_STEPS)
    hunt.add_argument("--only", choices=("vulnerability", "ordinary", "all"), default="all")
    hunt.add_argument("--client", choices=("scripted",))
    join = commands.add_parser("combine")
    join.add_argument("replay_out", type=Path)
    join.add_argument("hunter_out", type=Path)
    join.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "combine":
        combine(args.replay_out, args.hunter_out, args.out)
        return 0
    return run(args.manifest, args.repos, args.out, slice_id=args.slice, max_steps=args.max_steps, only=args.only, client_mode=args.client)


if __name__ == "__main__":
    raise SystemExit(main())
