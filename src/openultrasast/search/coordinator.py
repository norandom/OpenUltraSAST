"""Host-only board driver. Executors own task isolation and enforce supplied limits.

Reason/explore workers are group 5. They return proposals, never board writes.
Only the trusted verify executor may return a demonstrated outcome. An interrupted
call is conservatively charged its reservation on resume, never silently free.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from importlib import import_module
from pathlib import Path
from typing import Any, Protocol

from ..plane.budget import BudgetExhausted, SpendBudget
from ..plane.memory import open_store
from .board import Board
from .budget import SearchBudget


@dataclass(frozen=True)
class SearchTask:
    id: str
    search_id: str
    step: str
    snapshot: str
    payload: dict[str, Any]
    limits: dict[str, Any]
    lane: str = "ax"

    def __post_init__(self) -> None:
        for value in (self.id, self.search_id):
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value):
                raise ValueError("invalid search task identifier")
        if self.step not in ("reason", "explore", "verify") or self.lane not in ("ax", "kind", "docker"):
            raise ValueError("invalid search task step or lane")


class Executor(Protocol):
    def __call__(self, task: SearchTask) -> dict[str, Any]:
        """Finish/clean up within limits; report actual cost, including failed calls.

        A missing cost on a model task charges its entire reservation. Model
        workers must reserve each call against limits.max_call_usd (the task's
        total allowance) using plane.budget.SpendBudget. Exceptions are untrusted
        diagnostics and must never be copied into the board.
        """
        ...


class Coordinator:
    def __init__(
        self,
        board: Board,
        executor: Executor,
        *,
        budget: SearchBudget | None = None,
        clock: Callable[[], float] = time.time,
        push_budget: SpendBudget | None = None,
    ) -> None:
        self.board, self.executor = board, executor
        self.budget, self.clock, self.push_budget = budget or SearchBudget(), clock, push_budget
        self.state = board.state
        self.state.setdefault("end_detail", None)
        self.progress = self.state["checkpoint"] or dict(
            started_at=clock(),
            spent_usd=0.0,
            tasks=0,
            rounds=0,
            retries=0,
            demonstrations=0,
            pending=None,
            verified=[],
            failures=[],
        )
        self.meter = SpendBudget(self.budget.spend_usd, spent=self.progress["spent_usd"])

    def _save(self) -> None:
        self.progress["wall_seconds"] = max(0, self.clock() - self.progress["started_at"])
        self.state["checkpoint"] = self.progress
        self.board.commit(
            writer=self.board.coordinator,
            **{k: self.state[k] for k in ("facts", "intents", "hints", "end_reason", "end_detail", "checkpoint")},
        )

    def _end(self, reason: str, end_detail: str | None = None) -> dict[str, Any]:
        if reason == "budget_spent" and end_detail not in {
            "spend",
            "task_spend",
            "reason_rounds",
            "demonstrations",
            "tasks",
            "task_wall",
            "search_wall",
            "worker_steps",
            "worker_wall",
            "run_ceiling",
        }:
            raise ValueError("budget_spent requires an exhausted limit")
        self.state["end_detail"] = end_detail
        self.state["end_reason"] = reason
        self._save()
        return self.board.state

    def _remaining(self) -> float:
        return float(self.budget.wall_seconds - max(0, self.clock() - self.progress["started_at"]))

    def _snapshot(self) -> str:
        return self.board.snapshot(
            budget_left={
                "tasks": max(0, self.budget.tasks - self.progress["tasks"]),
                "reason_rounds": max(0, self.budget.reason_rounds - self.progress["rounds"]),
                "spend_usd": max(0, self.budget.spend_usd - self.meter.spent),
                "wall_seconds": max(0, self._remaining()),
            }
        )

    def _call(self, step: str, payload: dict[str, Any]) -> dict[str, Any]:
        lane = "ax"
        while True:
            remaining = self._remaining()
            if remaining <= self.budget.cleanup_seconds or self.progress["tasks"] >= self.budget.tasks:
                raise BudgetExhausted(
                    "task or wall budget exhausted",
                    usd=self.meter.spent,
                    calls=self.progress["tasks"],
                    end_detail="search_wall" if remaining <= self.budget.cleanup_seconds else "tasks",
                )
            maximum = self.budget.max_call_usd if step != "verify" else 0
            reservation = self.meter.reserve(maximum)
            push_reservation = None
            try:
                if self.push_budget is not None:
                    push_reservation = self.push_budget.reserve(maximum)
            except BudgetExhausted as exc:
                reservation.release()
                raise BudgetExhausted("push ceiling", usd=exc.usd, calls=exc.calls, end_detail="run_ceiling") from exc
            task_id = "task-" + str(self.progress["tasks"] + 1)
            limits = asdict(self.budget)
            limits["task_wall_seconds"] = min(self.budget.task_wall_seconds, remaining - self.budget.cleanup_seconds)
            task = SearchTask(task_id, self.state["search_id"], step, self._snapshot(), payload, limits, lane)
            self.progress["tasks"] += 1
            self.progress["pending"] = {"id": task_id, "step": step, "payload": payload}
            # A crash after this durable write may have spent the whole allowance.
            self.progress["spent_usd"] = self.meter.spent + maximum
            if step == "explore":
                intent = next(i for i in self.state["intents"] if i["id"] == payload["intent_id"])
                intent.update(status="claimed", claimant=task_id)
            self._save()
            task = replace(task, snapshot=self._snapshot())
            dispatched_at = self.clock()
            try:
                result = self.executor(task)
            except Exception:
                # Includes cleanup failures: never launch more work after a task
                # may have leaked. The persisted reservation remains conservative.
                reservation.settle(maximum)
                if push_reservation is not None:
                    push_reservation.settle(maximum)
                raise
            if not isinstance(result, dict):
                result = {"status": "invalid_result"}
            actual = result.get("cost_usd", maximum)
            try:
                reservation.settle(actual)
                if push_reservation is not None:
                    push_reservation.settle(actual)
            except (ValueError, TypeError, ArithmeticError):
                # Charge the maximum and stop on a violated executor contract.
                if reservation._active:
                    reservation.settle(maximum)
                if push_reservation is not None and push_reservation._active:
                    push_reservation.settle(maximum)
                result = {"status": "invalid_cost"}
            self.progress["spent_usd"] = self.meter.spent
            self.progress["pending"] = None
            if (
                result.get("status") == "invalid_cost"
                or self._remaining() <= 0
                or self.clock() - dispatched_at > limits["task_wall_seconds"]
            ):
                raise BudgetExhausted(
                    "executor exceeded cost or wall contract",
                    usd=self.meter.spent,
                    calls=self.progress["tasks"],
                    end_detail="task_spend"
                    if result.get("status") == "invalid_cost"
                    else "search_wall"
                    if self._remaining() <= 0
                    else "task_wall",
                )
            result = {**result, "task_id": task_id}
            # Persist results together with their effects in run(), not a "done"
            # checkpoint which could lose the result if the host then crashes.
            if result.get("status") in ("sandbox_failure", "oom", "instrument_failure") and self.progress["retries"] < self.budget.retries:
                self.progress["retries"] += 1
                lane = "docker"
                continue
            if step == "reason":
                self.progress["reason_completed"] = self.progress.get("reason_completed", 0) + 1
            return result

    def run(self) -> dict[str, Any]:
        if self.state["end_reason"]:
            return self.board.state
        candidate = self.board.candidate()
        if not self.progress["tasks"] and not self.state["intents"] and candidate.get("file") and candidate.get("function"):
            self.state["intents"].append(
                dict(
                    id="bootstrap",
                    description=(
                        f"Read the candidate function {candidate['function']} in {candidate['file']}, "
                        "the code that calls it, and how the application is started and reached from outside; "
                        "report the entry point, the route or CLI path to the candidate, and the inputs that reach it."
                    ),
                    from_facts=[],
                    status="open",
                    claimant=None,
                    step="bootstrap",
                    task_id="coordinator",
                )
            )
            self._save()
        pending = self.progress.get("pending")
        if pending:
            # Do not duplicate a possibly paid operation. Recover the claim as a
            # recorded failure; the next reason task can propose another direction.
            self.progress["failures"].append({"task_id": pending["id"], "reason": "interrupted"})
            for intent in self.state["intents"]:
                if intent.get("claimant") == pending["id"]:
                    intent.update(status="concluded", failure="interrupted")
            if pending["step"] == "verify":
                self.progress["verified"].append(pending["payload"]["fact_id"])
            self.progress["pending"] = None
            self._save()
        while True:
            if self._remaining() <= self.budget.cleanup_seconds:
                return self._end("budget_spent", "search_wall")
            try:
                intent = next((i for i in self.state["intents"] if i["status"] == "open"), None)
                demo = next((f for f in self.state["facts"] if f.get("demo") and f["id"] not in self.progress["verified"]), None)
                if demo is not None:
                    if self.progress["demonstrations"] >= self.budget.demonstrations:
                        return self._end("budget_spent", "demonstrations")
                    self.progress["demonstrations"] += 1
                    result = self._call(
                        "verify",
                        {
                            "fact_id": demo["id"],
                            "demo": demo["demo"],
                            "family": self.board.candidate().get("family"),
                            "oracle": demo.get("oracle"),
                        },
                    )
                    self.progress["verified"].append(demo["id"])
                    refs = result.get("evidence_refs")
                    if result.get("status") == "ok" and result.get("outcome") == "demonstrated" and self._refs(refs):
                        self.state["facts"].append(
                            dict(
                                id="verified-" + result["task_id"],
                                text="Differential demonstrated",
                                evidence_refs=refs,
                                from_intents=demo["from_intents"],
                                step="verify",
                                task_id=result["task_id"],
                            )
                        )
                        return self._end("goal_met")
                    self.progress["failures"].append({"task_id": result["task_id"], "reason": "not_demonstrated"})
                elif intent is not None:
                    result = self._call("explore", {"intent_id": intent["id"], "description": intent["description"]})
                    intent["status"] = "concluded"
                    fact = result.get("fact")
                    if (
                        result.get("status") == "ok"
                        and isinstance(fact, dict)
                        and isinstance(fact.get("text"), str)
                        and fact["text"]
                        and self._refs(fact.get("evidence_refs"))
                    ):
                        entry = dict(
                            id="fact-" + result["task_id"],
                            text=fact["text"],
                            evidence_refs=fact["evidence_refs"],
                            from_intents=[intent["id"]],
                            step="explore",
                            task_id=result["task_id"],
                        )
                        if isinstance(fact.get("demo"), str) and fact["demo"]:
                            entry["demo"] = fact["demo"]
                            entry["oracle"] = fact.get("oracle")
                        self.state["facts"].append(entry)
                        intent["conclusion"] = {"facts": [entry["id"]]}
                    else:
                        intent["failure"] = result.get("failure") or (
                            "invalid_result" if result.get("status") == "ok" else result.get("status", "execution_failure")
                        )
                        intent["conclusion"] = {"failure": intent["failure"]}
                    if result.get("budget_exhaustion", {}).get("end_detail") == "task_spend":
                        intent["limit"] = "task_spend"
                        self.progress["failures"].append({"task_id": result["task_id"], "reason": "task_spend"})
                else:
                    if self.progress["rounds"] >= self.budget.reason_rounds:
                        return self._end("budget_spent", "reason_rounds")
                    self.progress["rounds"] += 1
                    result = self._call("reason", {})
                    if result.get("status") == "ok" and not result.get("intents") and "complete" not in result:
                        result = self._call(
                            "reason",
                            {
                                "reminder": (
                                    "No intents are open. You MUST propose 1-3 independent new intents, "
                                    "or cite facts containing a complete demo. An empty reply is a refusal."
                                )
                            },
                        )
                        if result.get("status") == "ok" and not result.get("intents") and "complete" not in result:
                            self.progress["failures"].append({"task_id": result["task_id"], "reason": "reason_refused"})
                            return self._end("reason_refused")
                    if result.get("budget_exhaustion", {}).get("end_detail") == "task_spend":
                        self.progress["failures"].append({"task_id": result["task_id"], "reason": "task_spend"})
                        self._save()
                        continue
                    if result.get("budget_exhaustion"):
                        return self._end("budget_spent", result["budget_exhaustion"]["end_detail"])
                    for attempt in range(2):
                        _, rejected = self._admit_intents(result)
                        if not rejected or attempt:
                            break
                        self._save()
                        result = self._call("reason", {"reminder": "duplicate_intent: choose a new direction; see snapshot rejections."})
                        if result.get("budget_exhaustion"):
                            if result["budget_exhaustion"]["end_detail"] == "task_spend":
                                break
                            return self._end("budget_spent", result["budget_exhaustion"]["end_detail"])
                    if result.get("budget_exhaustion", {}).get("end_detail") == "task_spend":
                        self.progress["failures"].append({"task_id": result["task_id"], "reason": "task_spend"})
                        self._save()
                        continue
                    if not any(i["status"] == "open" for i in self.state["intents"]):
                        return self._end("exhausted")
                if result.get("budget_exhaustion") and result["budget_exhaustion"]["end_detail"] != "task_spend":
                    return self._end("budget_spent", result["budget_exhaustion"]["end_detail"])
                self._save()
            except BudgetExhausted as exc:
                return self._end("budget_spent", exc.end_detail)

    def _admit_intents(self, result: dict[str, Any]) -> tuple[int, bool]:
        proposals = result.get("intents", [])
        if result.get("status") != "ok" or not isinstance(proposals, list) or len(proposals) > self.budget.intents_per_round:
            return 0, False
        known = {f["id"] for f in self.state["facts"]}
        descriptions = {i["description"] for i in self.state["intents"]}
        added = 0
        rejections = []
        for proposal in proposals:
            if not isinstance(proposal, dict):
                continue
            description, refs = proposal.get("description"), proposal.get("from_facts", [])
            if not isinstance(description, str) or not description.strip():
                continue
            if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in known for ref in refs):
                continue
            tokens = Counter(re.findall(r"\w+", description.casefold()))
            duplicate = next(
                (
                    i
                    for i in self.state["intents"]
                    if i["status"] == "concluded"
                    and tokens
                    and sum((tokens & Counter(re.findall(r"\w+", i["description"].casefold()))).values()) / sum(tokens.values()) > 0.6
                ),
                None,
            )
            if duplicate is not None:
                rejection = {
                    "task_id": result["task_id"],
                    "reason": "duplicate_intent",
                    "description": description,
                    "concluded_intent": duplicate["id"],
                }
                rejections.append(rejection)
                self.progress["failures"].append(rejection)
                continue
            if description in descriptions:
                continue
            added += 1
            descriptions.add(description)
            self.state["intents"].append(
                dict(
                    id=result["task_id"] + "-intent-" + str(added),
                    description=description,
                    from_facts=refs,
                    status="open",
                    claimant=None,
                    step="reason",
                    task_id=result["task_id"],
                )
            )
        self.progress["duplicate_rejections"] = rejections
        return added, bool(rejections)

    @staticmethod
    def _refs(refs: Any) -> bool:
        return isinstance(refs, list) and bool(refs) and all(isinstance(ref, str) and bool(ref) for ref in refs)


class BatchExecutor:
    """Adapter to the existing AX/VM transfer and checkpoint protocol.

    Pass AXLane/DockerLane instances and a trusted worker command. No default
    worker is invented here: reason/explore entrypoints belong to group 5.
    The coordinator owns retries, so batch performs exactly one attempt.
    """

    def __init__(self, *, image: str, command: tuple[str, ...], output: Path, lanes: dict[str, Any]) -> None:
        batch = import_module("benchmarks.ax.batch")
        batch.validate_image(image)
        if not command:
            raise ValueError("worker command required")
        self.image, self.command, self.output, self.lanes = image, command, output, lanes

    def __call__(self, task: SearchTask) -> dict[str, Any]:
        import copy

        batch = import_module("benchmarks.ax.batch")

        if task.lane not in self.lanes:
            return {"status": "sandbox_failure", "cost_usd": 0}
        data = json.dumps(asdict(task), sort_keys=True, allow_nan=False).encode()
        digest = hashlib.sha256(data).hexdigest()
        identity = task.search_id + "-" + task.id
        item = batch.Item(
            identity,
            {"SPEC_URL": data},
            "result.dat",
            self.command,
            {"SEARCH_STEP": task.step, "SEARCH_ID": task.search_id, "SEARCH_TASK_ID": task.id},
            digest,
        )

        def validate(raw: bytes, output: Path) -> None:
            if len(raw) > 262144:
                raise ValueError("search result size exceeded")
            record = json.loads(raw)
            if not isinstance(record, dict) or record.get("status") not in (
                "ok",
                "sandbox_failure",
                "instrument_failure",
                "oom",
                "execution_failure",
            ):
                raise ValueError("invalid search result")
            (output / "result.json").write_text(json.dumps(record))

        workload = batch.Workload(self.image, frozenset({"SPEC_URL", "RESULT_URL"}), task.limits["task_wall_seconds"], validate)
        lane = copy.copy(self.lanes[task.lane])
        if hasattr(lane, "workload"):
            lane.workload = workload
        out = self.output / task.search_id / task.id
        batch.dispatch([item], workload, out, {task.lane: lane}, lanes=(task.lane,), max_attempts=1)
        record_path = out / (hashlib.sha256(identity.encode()).hexdigest() + ".json")
        if not record_path.exists():
            return {"status": "execution_failure", "cost_usd": 0}
        record: dict[str, Any] = json.loads(record_path.read_text())
        return record


def main() -> None:
    """Offline checkpoint inspection, also useful before resuming with an executor."""
    parser = argparse.ArgumentParser(description="Inspect a search board checkpoint (no model calls)")
    parser.add_argument("--memory", required=True)
    parser.add_argument("--search-id", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    board = Board.resume(open_store(args.memory), args.search_id, args.head, coordinator="inspect")
    print(board.snapshot(), end="")


if __name__ == "__main__":
    main()
