"""Rule-status proposals from the plane's memory store (harnessx-removal Req 6.2/6.4, design section 5).

The store (:mod:`..plane.memory`) holds what plane runs learned per repository and pin. Two deterministic rules turn
its ``alert`` and ``verdict`` rows into :class:`RuleStatusEdit` proposals that :func:`.evolve.run_round` validates
and gates exactly like the benchmark's own edits; a third reads dispute rates as advisory routing input only.

Join key: an ``alert`` and a ``verdict`` match when repo, pin and ``path::function`` are equal. A ``disputed``
final counts as no evidence in either direction.

- **M1, repeated false alerts** (``enabled -> shadow``): at least :data:`M1_MIN_FALSE` alerts of the rule are false
  -- at a ``rejected`` candidate, or on a ``fixed`` pin inside the declared fix range (the alert row says
  ``in_fix_range: true``, or its ``path::function`` is a ``site_match`` site of the same repository) -- across at
  least :data:`M1_MIN_REPOS` repositories, and no alert of the rule sits at an ``agreed`` or ``site_match``
  candidate.
- **M2, missed declared sites** (``shadow -> enabled``): the shadow rule's alerts hit at least :data:`M2_MIN_HITS`
  ``agreed`` candidates with ``site_match`` true across at least :data:`M2_MIN_REPOS` repositories, no enabled rule
  alerts at those candidates, the rule has no ``fixed``-pin alert at the same function, and at most
  :data:`M2_MAX_REJECTED` alert at a ``rejected`` candidate.
- **M3, disputed families**: families with at least :data:`M3_MIN_CANDIDATES` candidates and a dispute rate of at
  least :data:`M3_MIN_DISPUTE_RATE`. Advisory (``signals.json``); never an edit, never shown to the validator.

**Train-on-test guard** (:class:`Guard`), applied before any rule sees a row: a row is dropped when its population
is one the proposal will be qualified on, its (repo, pin) is a case of the gated benchmark manifest, or its
repository is a holdout pair's repository. The pair catalog records a holdout pair's *fix* commit, not the
vulnerable pin (its parent), so the holdout clause matches by repository, a superset of (repo, pin). This is the
rule the closed-loop leak broke, where a holdout pair taught the shape that then "recovered" it.

**Provenance**: each proposal's rationale is ``memory:<proposal_id>``, ``proposal_id`` being the sha256 of (rule,
edit key, sorted evidence row ids, thresholds). The sidecar ``memory_proposals.jsonl`` next to the journal carries
the evidence rows (id, repo, pin, run, task, object key and version -- MinIO's version id, a file's content hash),
the counts that met each threshold, what the guard excluded and the store's index digest.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..plane.memory import MemoryStore, Record, repo_key, row_id, rows_digest
from ..ruleset import PatternRule
from .validator import RuleStatusEdit

M1_MIN_FALSE = 3
M1_MIN_REPOS = 2
M2_MIN_HITS = 2
M2_MIN_REPOS = 2
M2_MAX_REJECTED = 1
M3_MIN_CANDIDATES = 5
M3_MIN_DISPUTE_RATE = 0.3
THRESHOLDS: dict[str, dict[str, float]] = {
    "M1": {"min_false_alerts": M1_MIN_FALSE, "min_repos": M1_MIN_REPOS, "max_agreed_hits": 0},
    "M2": {"min_site_hits": M2_MIN_HITS, "min_repos": M2_MIN_REPOS, "max_rejected": M2_MAX_REJECTED, "max_fixed_pin_same_function": 0},
    "M3": {"min_candidates": M3_MIN_CANDIDATES, "min_dispute_rate": M3_MIN_DISPUTE_RATE},
}
RATIONALE_PREFIX = "memory:"
SIDECAR = "memory_proposals.jsonl"
SIGNALS = "signals.json"


@dataclass(frozen=True)
class MemoryProposal:
    edit: RuleStatusEdit
    provenance: dict[str, Any]

    @property
    def proposal_id(self) -> str:
        return str(self.provenance["proposal_id"])


def proposal_id_of(edit: object) -> str | None:
    """The proposal id a memory edit carries in its rationale; None for any other edit."""
    rationale = getattr(edit, "rationale", "")
    return rationale[len(RATIONALE_PREFIX) :] if isinstance(rationale, str) and rationale.startswith(RATIONALE_PREFIX) else None


# --- the train-on-test guard ---------------------------------------------------------------------------------------


def _tail(repo: str) -> str:
    """``owner/name`` of a repository, lower-cased: the pair catalog names repositories without a host."""
    return "/".join(repo_key(repo).lower().split("/")[-2:])


@dataclass(frozen=True)
class Guard:
    populations: frozenset[str] = frozenset()
    gated_cases: frozenset[tuple[str, str]] = frozenset()  # (repo_key, pin) of the benchmark being gated
    holdout_repos: frozenset[str] = frozenset()  # owner/name of every holdout pair

    @classmethod
    def build(
        cls, populations: Iterable[str] = (), gated_cases: Iterable[tuple[str, str]] = (), holdout_pairs: Iterable[object] = ()
    ) -> Guard:
        repos = {_tail(str(getattr(p, "repo", ""))) for p in holdout_pairs if getattr(p, "repo", "")}
        return cls(frozenset(populations), frozenset((repo_key(r), p) for r, p in gated_cases), frozenset(repos))

    def reason(self, row: Mapping[str, Any]) -> str | None:
        if row.get("population") in self.populations:
            return "population"
        if (row.get("repo"), row.get("pin")) in self.gated_cases:
            return "gated_case"
        if _tail(str(row.get("repo"))) in self.holdout_repos:
            return "holdout_pair"
        return None

    def apply(self, records: Iterable[Record]) -> tuple[list[Record], dict[str, Any]]:
        """(kept records, what was excluded: row count, and counts per population / repo@pin per clause)."""
        kept: list[Record] = []
        excluded: dict[str, Any] = {"rows": 0, "population": {}, "gated_case": {}, "holdout_pair": {}}
        for record in records:
            why = self.reason(record.row)
            if why is None:
                kept.append(record)
                continue
            excluded["rows"] += 1
            label = str(record.row.get("population")) if why == "population" else f"{record.row.get('repo')}@{record.row.get('pin')}"
            excluded[why][label] = excluded[why].get(label, 0) + 1
        for clause in ("population", "gated_case", "holdout_pair"):
            excluded[clause] = dict(sorted(excluded[clause].items()))
        return kept, excluded


# --- the rules -----------------------------------------------------------------------------------------------------


def _cand(row: Mapping[str, Any]) -> str:
    return f"{row.get('path')}::{row.get('function')}"


def _status(rule_id: str, ruleset_by_id: Mapping[str, PatternRule], ledger: Mapping[str, dict[str, object]]) -> str | None:
    rule = ruleset_by_id.get(rule_id)
    return None if rule is None else str(ledger.get(rule_id, {}).get("status", rule.status))


@dataclass
class _View:
    verdicts: dict[tuple[str, str, str], Record] = field(default_factory=dict)  # (repo, pin, candidate)
    sites: set[tuple[str, str]] = field(default_factory=set)  # (repo, candidate) with site_match true
    alerts: dict[str, list[Record]] = field(default_factory=dict)  # rule_id -> alerts

    @classmethod
    def of(cls, records: Sequence[Record]) -> _View:
        view = cls()
        for rec in records:
            row = rec.row
            if row["kind"] == "verdict":
                view.verdicts[(row["repo"], row["pin"], str(row.get("candidate")))] = rec
                if row.get("site_match") is True:
                    view.sites.add((row["repo"], str(row.get("candidate"))))
            elif row["kind"] == "alert" and row.get("rule_id"):
                view.alerts.setdefault(str(row["rule_id"]), []).append(rec)
        return view

    def verdict(self, alert: Mapping[str, Any]) -> Record | None:
        return self.verdicts.get((alert["repo"], alert["pin"], _cand(alert)))

    def fixed_in_range(self, alert: Mapping[str, Any]) -> bool:
        if alert.get("pin_role") != "fixed":
            return False
        flag = alert.get("in_fix_range")
        return bool(flag) if flag is not None else (alert["repo"], _cand(alert)) in self.sites


def _m1(rule_id: str, view: _View) -> tuple[list[Record], dict[str, int]] | None:
    evidence: list[Record] = []
    repos: set[str] = set()
    false_alerts = 0
    for alert in view.alerts.get(rule_id, []):
        verdict = view.verdict(alert.row)
        final = verdict.row.get("final") if verdict else None
        if final == "agreed" or (verdict is not None and verdict.row.get("site_match") is True):
            return None  # the rule caught something the plane agreed on: never demote it on this evidence
        if final == "rejected" or view.fixed_in_range(alert.row):
            false_alerts += 1
            repos.add(alert.row["repo"])
            evidence.extend([alert, verdict] if verdict is not None and final == "rejected" else [alert])
    if false_alerts < M1_MIN_FALSE or len(repos) < M1_MIN_REPOS:
        return None
    return evidence, {"false_alerts": false_alerts, "repos": len(repos), "agreed_hits": 0}


def _m2(rule_id: str, view: _View, enabled: set[str]) -> tuple[list[Record], dict[str, int]] | None:
    alerts = view.alerts.get(rule_id, [])
    hits: dict[tuple[str, str, str], tuple[Record, Record]] = {}
    rejected = 0
    for alert in alerts:
        verdict = view.verdict(alert.row)
        if verdict is None or alert.row.get("pin_role") == "fixed":
            continue
        if verdict.row.get("final") == "rejected":
            rejected += 1
        elif verdict.row.get("final") == "agreed" and verdict.row.get("site_match") is True:
            hits[(alert.row["repo"], alert.row["pin"], _cand(alert.row))] = (alert, verdict)
    if not hits:
        return None
    caught = {
        (a.row["repo"], a.row["pin"], _cand(a.row)) for rid in enabled if rid != rule_id for a in view.alerts.get(rid, [])
    }  # fmt: skip
    missed = {k: v for k, v in hits.items() if k not in caught}
    fixed_same = sum(
        1 for a in alerts if a.row.get("pin_role") == "fixed" and any((a.row["repo"], _cand(a.row)) == (r, c) for r, _, c in missed)
    )
    repos = {repo for repo, _, _ in missed}
    if len(missed) < M2_MIN_HITS or len(repos) < M2_MIN_REPOS or fixed_same > 0 or rejected > M2_MAX_REJECTED:
        return None
    evidence = [rec for key in sorted(missed) for rec in missed[key]]
    return evidence, {"site_hits": len(missed), "repos": len(repos), "rejected": rejected, "fixed_pin_same_function": 0}


def _evidence(records: Sequence[Record]) -> list[dict[str, Any]]:
    unique = {rec.row["id"]: rec for rec in records}
    return [
        {"id": i, "kind": r.row["kind"], "repo": r.row["repo"], "pin": r.row["pin"], "run": r.row["run"], "task": r.row["task"],
         "key": r.key, "version": r.version}
        for i, r in sorted(unique.items())
    ]  # fmt: skip


def evidence_digest(evidence_ids: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(evidence_ids)).encode("utf-8")).hexdigest()


def _proposal(
    rule: str, edit_key: str, rule_id: str, records: Sequence[Record], counts: dict[str, int], excluded: dict[str, Any], index: str
) -> dict[str, Any]:
    evidence = _evidence(records)
    ids = [e["id"] for e in evidence]
    seed = json.dumps([rule, edit_key, ids, THRESHOLDS[rule]], sort_keys=True, separators=(",", ":"))
    return {
        "proposal_id": hashlib.sha256(seed.encode("utf-8")).hexdigest(),
        "rule": rule,
        "edit_key": edit_key,
        "rule_id": rule_id,
        "evidence": evidence,
        "evidence_digest": evidence_digest(ids),
        "counts": counts,
        "thresholds": THRESHOLDS[rule],
        "excluded": excluded,
        "index_digest": index,
    }


def propose_from_memory(
    rows: Sequence[Record],
    ruleset_by_id: Mapping[str, PatternRule],
    current_ledger: Mapping[str, dict[str, object]],
    journal_rounds: Sequence[Mapping[str, object]],
    *,
    excluded: Guard,
    index_digest: str = "",
) -> list[MemoryProposal]:
    """M1 and M2 over the rows the guard keeps, minus proposals already reverted on the same evidence."""
    kept, dropped = excluded.apply(rows)
    view = _View.of(kept)
    statuses = {rid: _status(rid, ruleset_by_id, current_ledger) for rid in ruleset_by_id}
    enabled = {rid for rid, status in statuses.items() if status == "enabled"}
    proposals: list[MemoryProposal] = []
    for rule_id in sorted(view.alerts):
        status = statuses.get(rule_id)
        if status == "enabled" and (m1 := _m1(rule_id, view)):
            name, found, to_status = "M1", m1, "shadow"
        elif status == "shadow" and (m2 := _m2(rule_id, view, enabled)):
            name, found, to_status = "M2", m2, "enabled"
        else:
            continue  # unknown to the ruleset (the loop cannot add rules), disabled, or no rule fired
        key = RuleStatusEdit(rule_id, status, to_status).key()
        provenance = _proposal(name, key, rule_id, found[0], found[1], dropped, index_digest)
        edit = RuleStatusEdit(rule_id, status, to_status, rationale=RATIONALE_PREFIX + provenance["proposal_id"])
        proposals.append(MemoryProposal(edit, provenance))
    return applicable(proposals, ruleset_by_id, current_ledger, journal_rounds)


def applicable(
    proposals: Sequence[MemoryProposal],
    ruleset_by_id: Mapping[str, PatternRule],
    current_ledger: Mapping[str, dict[str, object]],
    journal_rounds: Sequence[Mapping[str, object]],
) -> list[MemoryProposal]:
    """Proposals whose rule still has the ``from`` status and whose evidence no reverted round already tried."""
    tried: set[tuple[str, str]] = set()
    for entry in journal_rounds:
        edits = entry.get("edits")
        if entry.get("outcome") == "reverted" and isinstance(edits, list):
            tried |= {(str(e.get("key")), str(e.get("evidence"))) for e in edits if isinstance(e, dict) and e.get("evidence")}
    return [
        p for p in proposals
        if _status(p.edit.rule_id, ruleset_by_id, current_ledger) == p.edit.from_status and (p.edit.key(), p.proposal_id) not in tried
    ]  # fmt: skip


def disputed_families(rows: Sequence[Record], guard: Guard) -> list[dict[str, Any]]:
    """M3: families disputed often enough to route differently. Advisory only: never an edit."""
    kept, _ = guard.apply(rows)
    per: dict[str, list[int]] = {}
    for rec in kept:
        if rec.row["kind"] == "verdict" and rec.row.get("family"):
            tally = per.setdefault(str(rec.row["family"]), [0, 0])
            tally[0] += 1
            tally[1] += rec.row.get("final") == "disputed"
    return [
        {"family": fam, "candidates": n, "disputed": d, "dispute_rate": round(d / n, 4), "advice": "schedule pass c up front"}
        for fam, (n, d) in sorted(per.items())
        if n >= M3_MIN_CANDIDATES and d / n >= M3_MIN_DISPUTE_RATE
    ]


# --- the store, the sidecar and the outcomes -----------------------------------------------------------------------


def index_digest(store: MemoryStore) -> str:
    return rows_digest(store.index())


def write_sidecar(journal_path: Path, round_index: int, proposals: Sequence[MemoryProposal]) -> None:
    """Append each proposal once (by id) to ``memory_proposals.jsonl`` next to the journal."""
    if not proposals:
        return
    path = journal_path.with_name(SIDECAR)
    seen = {json.loads(line)["proposal_id"] for line in path.read_text().splitlines() if line.strip()} if path.is_file() else set()
    new = [p for p in proposals if p.proposal_id not in seen]
    if not new:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as sink:
        for p in new:
            sink.write(json.dumps({**p.provenance, "round": round_index}, sort_keys=True, separators=(",", ":")) + "\n")


def read_sidecar(journal_path: Path) -> dict[str, dict[str, Any]]:
    path = journal_path.with_name(SIDECAR)
    if not path.is_file():
        return {}
    return {row["proposal_id"]: row for row in (json.loads(line) for line in path.read_text().splitlines() if line.strip())}


def write_signals(directory: Path, signals: Sequence[Mapping[str, Any]]) -> Path:
    path = directory / SIGNALS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"advisory": True, "disputed_families": list(signals), "thresholds": THRESHOLDS["M3"]}, indent=2) + "\n")
    return path


def outcome_of(reason: str, accepted: bool) -> str | None:
    if accepted:
        return "accepted"
    if reason == "no_proposals":
        return None
    if reason.startswith(("validation_failed", "replay_failed")):
        return "rejected"
    return "reverted"


def outcome_rows(
    edits: Sequence[RuleStatusEdit],
    outcome: str,
    round_index: int,
    reason: str,
    proposals: Mapping[str, MemoryProposal],
    gate_run: str,
) -> list[dict[str, Any]]:
    """One ``proposal_outcome`` row per (repository, pin) of each memory edit's evidence."""
    rows: list[dict[str, Any]] = []
    for edit in edits:
        pid = proposal_id_of(edit)
        proposal = proposals.get(pid or "")
        if proposal is None:
            continue
        by_place: dict[tuple[str, str], dict[str, Any]] = {}
        for ev in proposal.provenance["evidence"]:
            by_place.setdefault((ev["repo"], ev["pin"]), ev)
        for (repo, pin), _ in sorted(by_place.items()):
            task = f"round-{round_index}"
            rows.append(
                {
                    "id": row_id("proposal_outcome", gate_run, task, f"{pid}:{repo}:{pin}"), "kind": "proposal_outcome",
                    "repo": repo, "pin": pin, "run": gate_run, "task": task, "population": "improve-loop", "split": "loop",
                    "image": "host", "edit_key": edit.key(), "proposal_id": pid,
                    "evidence_digest": proposal.provenance["evidence_digest"], "outcome": outcome, "reason": reason,
                    "gate_run": gate_run,
                }
            )  # fmt: skip
    return rows


def gate_run_name(manifest_name: str) -> str:
    return f"improve:{manifest_name}:{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"


# --- the `ousast improve --memory` session -------------------------------------------------------------------------


def benchmark_cases(manifest: object) -> frozenset[tuple[str, str]]:
    """(repo, pin) of the gated benchmark's cases. Local sources (the only kind `resolve_benchmark_source` accepts)
    name no repository pin, so they exclude nothing here; a pinned source would list its case."""
    source = getattr(manifest, "source", None)
    repo, pin = getattr(source, "repo", ""), getattr(source, "pin", "")
    return frozenset({(repo_key(repo), pin)}) if repo and pin else frozenset()


def store_spec(value: str) -> str | None:
    """``--memory`` value -> ``open_store`` spec: empty uses OUSAST_MEMORY or the default, a bare path is a FileStore."""
    if not value:
        return None
    return value if "://" in value else f"file://{Path(value).resolve()}"


@dataclass
class MemorySession:
    """One `improve --memory` invocation: the store read once, proposals per round, outcomes written back."""

    store: MemoryStore
    guard: Guard
    records: list[Record]
    ruleset_dir: Path
    gate_run: str
    made: dict[str, MemoryProposal] = field(default_factory=dict)

    @classmethod
    def open(
        cls, spec: str, manifest: object, target: Path, ruleset_dir: Path, populations: Sequence[str], catalog: Path | None
    ) -> MemorySession:
        from ..pairs import load_pair_catalog, select_split
        from ..plane.memory import FileStore, open_store

        store = open_store(store_spec(spec))
        if isinstance(store, FileStore) and not (store.root / "index.jsonl").is_file():
            raise SystemExit(f"memory store {store.describe()} has no index.jsonl: an unread store would propose nothing")
        if catalog is None or not catalog.is_file():
            raise SystemExit(f"--memory needs the pair catalog for the holdout guard: {catalog} is not a file")
        holdout = select_split(load_pair_catalog(catalog), "holdout")
        guard = Guard.build(populations, benchmark_cases(manifest), holdout)
        records = store.rows()
        print(
            f"memory={store.describe()} index_entries={len(store.index())} rows={len(records)} "
            f"guard: populations={sorted(guard.populations) or '-'} gated_cases={len(guard.gated_cases)} "
            f"holdout_repos={len(guard.holdout_repos)}"
        )
        return cls(store, guard, records, ruleset_dir, gate_run_name(str(getattr(manifest, "name", "manifest"))))

    def proposals(self, ledger_path: Path, journal_path: Path) -> list[MemoryProposal]:
        from ..ruleset import load_ruleset, read_rule_ledger
        from .journal import load_journal

        rules = load_ruleset(self.ruleset_dir, ledger_path if ledger_path.is_file() else None)
        found = propose_from_memory(
            self.records,
            {r.rule_id: r for r in rules},
            read_rule_ledger(ledger_path),
            load_journal(journal_path),
            excluded=self.guard,
            index_digest=index_digest(self.store),
        )
        kept, excluded = self.guard.apply(self.records)
        kinds: dict[str, int] = {}
        for rec in kept:
            kinds[rec.row["kind"]] = kinds.get(rec.row["kind"], 0) + 1
        print(f"memory_rows kept={len(kept)} by_kind={json.dumps(dict(sorted(kinds.items())))}")
        print(f"memory_excluded={json.dumps(excluded, sort_keys=True)}")
        for p in found:
            print(f"memory_proposal {p.edit.key()} rule={p.provenance['rule']} id={p.proposal_id} evidence={len(p.provenance['evidence'])}")
        print(f"memory_proposals={len(found)}")
        self.made.update({p.proposal_id: p for p in found})
        return found

    def finish(self, outcomes: Sequence[Any], journal_path: Path, *, dry_run: bool) -> None:
        signals = disputed_families(self.records, self.guard)
        path = write_signals(journal_path.parent, signals)
        print(f"memory_signals disputed_families={[s['family'] for s in signals] or '-'} ({path.name}, advisory)")
        rows: list[dict[str, Any]] = []
        for o in outcomes:
            outcome = outcome_of(o.reason, o.accepted)
            if outcome is not None:
                rows += outcome_rows(o.edits, outcome, o.round, o.reason, self.made, self.gate_run)
        if dry_run:
            print(f"memory_outcomes={len(rows)} (dry run: not written to the store)")
            return
        if rows:
            self.store.put_rows(rows)
        print(f"memory_outcomes={len(rows)} written to {self.store.describe()}")


__all__ = [
    "Guard",
    "MemorySession",
    "benchmark_cases",
    "store_spec",
    "M1_MIN_FALSE",
    "M1_MIN_REPOS",
    "M2_MAX_REJECTED",
    "M2_MIN_HITS",
    "M2_MIN_REPOS",
    "M3_MIN_CANDIDATES",
    "M3_MIN_DISPUTE_RATE",
    "MemoryProposal",
    "THRESHOLDS",
    "applicable",
    "disputed_families",
    "evidence_digest",
    "gate_run_name",
    "index_digest",
    "outcome_of",
    "outcome_rows",
    "propose_from_memory",
    "proposal_id_of",
    "read_sidecar",
    "write_sidecar",
    "write_signals",
]
