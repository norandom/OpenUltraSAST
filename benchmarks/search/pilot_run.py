"""One-sided feasibility searches. Live mode is opt-in by omitting --dry-run."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import re
import tarfile
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from benchmarks.ax.batch import AXLane, ClusterUnavailable, SearchExecutorTask, Workload, validate_image
from benchmarks.ax.search_verify import AXSideDispatcher, validate_result
from benchmarks.search.executor_smoke import CLONE
from openultrasast.config import load_dotenv
from openultrasast.model.endpoint import (
    DEEPSEEK_BASE_ENV,
    DEEPSEEK_BASE_URL,
    DEEPSEEK_KEY_ENV,
    DEFAULT_DETECTOR_MODEL,
    Prices,
    price_of,
)
from openultrasast.plane.budget import BudgetExhausted, SpendBudget
from openultrasast.plane.memory import FileStore, open_store
from openultrasast.provider.openrouter import OpenRouterChatClient
from openultrasast.search import _sandbox
from openultrasast.search.board import Board
from openultrasast.search.budget import SearchBudget
from openultrasast.search.coordinator import Coordinator
from openultrasast.search.demo import FAMILY_ORACLES, load_demo, validate_oracle
from openultrasast.search.executor import InProcessExecutor
from openultrasast.search.oracles import BrowserExecutor
from openultrasast.search.probe import materialise
from openultrasast.search.task_storage import diagnostic, exception_reason
from openultrasast.search.verify import Side, VerificationRecord, verify
from openultrasast.search.verify_task import extract_checkout, validate_spec
from openultrasast.search.worker import StubModel, Worker


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def tool(name, **args):
    return {"tool_calls": [{"id": "call", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def scripted(schema):
    return StubModel(
        [
            tool("read_file", path="app.py"),
            tool("write_demo", schema=schema),
            tool("finish", fact={"text": "Candidate demo", "evidence_refs": ["tool:1"], "demo": "demo/"}),
            *[{"content": "{}"} for _ in range(4)],
        ]
    )


class RepositoryFailure(ValueError):
    """The selected checkout or candidate cannot be read."""


class Pilot:
    def __init__(self, args, row, index, root, store, run_budget, client, prices, lane=None):
        self.args, self.root, self.lane = args, root, lane
        # Fixed searches retain no vulnerable pin, even in trusted verification state.
        self.row = {k: v for k, v in row.items() if args.side != "fixed" or k != "vulnerable"}
        self.phase = "setup"
        self.deadline = float("inf")
        self.record = dict(
            type="search",
            pair_index=index,
            side=args.side,
            repo_digest=digest(row["repo"]),
            revision_digest=digest(row[args.side]),
            family=row["family"],
            language=row["language"],
            dry_run=args.dry_run,
            fixed_effect_observed=None,
            outcome="no_evidence",
            end_reason="exhausted",
            end_detail=None,
            task_metrics=[],
            executor_task_metrics=[],
            tasks_submitted=0,
            executor_tasks=0,
            verify_tasks=0,
            input_bytes=0,
            wall_seconds_by_phase={},
            failures=[],
        )
        self.board = Board(store, "pilot-" + uuid.uuid4().hex, coordinator="pilot")
        self.board.commit(
            writer="pilot",
            hints=[
                dict(
                    id="candidate",
                    step="reason",
                    task_id="manifest",
                    text=json.dumps({k: row[k] for k in ("family", "file", "function", "oracle") if k in row}),
                )
            ],
        )
        self.worker = Worker(
            client,
            repo=root / "unmounted",
            demo=root / "demo",
            model=args.model,
            prices=prices,
            run_budget=run_budget,
            max_output_tokens=args.max_tokens,
        )
        self.family = row["family"]
        self.sides = None
        self.verifications = []

    def failure(self, phase, reason, command=None):
        private = tuple(str(v) for k, v in self.row.items() if k in {"repo", "file", "function", "vulnerable", "fixed"})
        private += (str(self.root), self.row["repo"].removeprefix("https://github.com/"))
        if isinstance(reason, BaseException):
            safe = exception_reason(reason, private=private)
        elif isinstance(reason, str) and re.match(r"^[A-Za-z_]\w*: ", reason):
            # Worker errors already carry a type. Preserve it when identity redaction
            # expands the message beyond the public record's tail limit.
            kind, message = reason.split(": ", 1)
            safe = kind + ": " + diagnostic(message, maximum=max(0, 298 - len(kind)), private=private)
        else:
            safe = diagnostic(reason, private=private)
        entry = dict(phase=phase, reason=safe)
        command = command if command is not None else reason
        if hasattr(command, "exit_code"):
            entry.update(
                command_phase=diagnostic(command.phase),
                exit_code=command.exit_code,
                stderr=diagnostic(command.stderr, maximum=1500, private=private),
            )
        self.record["failures"].append(entry)

    @contextmanager
    def executor(self, revision, deadline=900):
        before = time.monotonic()
        metrics = dict(self.worker.metrics)
        self.executor_end = "ok"
        submitted = self.record["executor_tasks"]
        try:
            with self._executor(revision, deadline) as task:
                yield task
        except BudgetExhausted as exc:
            self.executor_end = exc.end_detail
            raise
        except Exception:
            self.executor_end = "execution_failure"
            raise
        finally:
            if self.record["executor_tasks"] > submitted:
                self.record["executor_task_metrics"].append(
                    {
                        "executor_task": submitted + 1,
                        **{key: value - metrics[key] for key, value in self.worker.metrics.items()},
                        "wall_seconds": time.monotonic() - before,
                        "end": self.executor_end,
                    }
                )

    @contextmanager
    def _executor(self, revision, deadline=900):
        deadline = min(deadline, self.deadline - time.monotonic())
        if deadline < 1:
            raise BudgetExhausted("task deadline", usd=0, calls=0, end_detail="task_wall")
        acquired_at = time.monotonic()
        empty = io.BytesIO()
        with tarfile.open(fileobj=empty, mode="w"):
            pass
        self.admit_task()
        self.record["executor_tasks"] += 1
        with SearchExecutorTask(self.lane, empty.getvalue(), deadline=deadline) as task:
            remaining = deadline - (time.monotonic() - acquired_at)
            if remaining < 1:
                raise BudgetExhausted("acquisition deadline", usd=0, calls=0, end_detail="task_wall")
            timeout = min(180, remaining)
            result = task.client.submit(
                "run",
                {"command": ["sh", "-ec", CLONE, "clone", self.row["repo"], revision], "timeout_seconds": timeout},
                timeout_seconds=timeout,
            )
            if result.get("exit_code") != 0 or result.get("error"):
                self.failure("acquisition", "checkout_command_failed")
                raise RepositoryFailure("checkout failed")
            remaining = deadline - (time.monotonic() - acquired_at)
            if remaining < 1:
                raise BudgetExhausted("acquisition deadline", usd=0, calls=0, end_detail="task_wall")
            result = task.client.submit("read_file", {"path": self.row["file"]}, timeout_seconds=min(30, remaining))
            if not isinstance(result.get("input_bytes"), int) or result["input_bytes"] <= 0:
                self.failure("acquisition", "candidate_input_unreadable")
                raise RepositoryFailure("unreadable input")
            self.record["input_bytes"] += result["input_bytes"]
            yield task

    def admit_task(self):
        if self.record["tasks_submitted"] >= 32:
            raise BudgetExhausted("executor task cap", usd=0, calls=0, end_detail="tasks")
        self.record["tasks_submitted"] += 1

    def prepare(self, revision, spec):
        before = time.monotonic()
        try:
            with self.executor(revision) as task:
                return task.prepare(spec)
        except BudgetExhausted:
            raise
        except Exception as exc:
            self.failure("build_export", exc)
            raise
        finally:
            wall = self.record["wall_seconds_by_phase"]
            wall["build_export"] = wall.get("build_export", 0) + time.monotonic() - before

    def verification(self):
        if not FAMILY_ORACLES[self.family]:
            return VerificationRecord("no_oracle", (), 0, "no configured owned oracle")
        demo = load_demo(self.root / "demo")
        validate_oracle(self.family, demo["oracle"])
        if self.args.dry_run:
            sides = self.sides if self.args.side == "vulnerable" else (self.sides[1], self.sides[1])
            return verify(*sides, self.root / "demo", self.family, oracle=demo["oracle"])
        revisions = [self.row[self.args.side], self.row["fixed"]]
        if self.args.verify_lane == "ax":
            # Side paths are opaque lookup keys; no checkout or opposite revision reaches the brain.
            sides = [Side(self.root / str(i)) for i in range(2)]
            pins = {s.checkout: pin for s, pin in zip(sides, revisions, strict=True)}
            parent = self

            class CountingLane:
                def __call__(self, *a, **kw):
                    parent.admit_task()
                    parent.record["verify_tasks"] += 1
                    return parent.lane(*a, **kw)

            dispatcher = AXSideDispatcher(
                self.args,
                self.args.image,
                self.root / "verify",
                lane=CountingLane(),
                prepare=lambda side, spec: self.prepare(pins[side.checkout], spec),
            )
            return verify(
                *sides,
                self.root / "demo",
                self.family,
                oracle=demo["oracle"],
                task_dispatcher=dispatcher,
                browser=BrowserExecutor(task_boundary=True) if demo["oracle"] == "xss" else None,
            )
        if _sandbox.isolation_mode() != "userns":
            raise _sandbox.IsolationUnavailable("VM verification requires userns")
        sides = []
        spec = dict(demo=demo, family=self.family, timeout_seconds=5)
        for revision in revisions:
            archive = self.prepare(revision, spec)
            bundle = self.root / ("built-" + uuid.uuid4().hex)
            extract_checkout(archive, bundle)
            sides.append(Side(bundle / "checkout", products=bundle / "products"))
            # Export contains the executor's build-free schema.
            (self.root / "verify-demo").mkdir(exist_ok=True)
            built_spec = validate_spec(json.loads((bundle / "spec.json").read_text()))
            expected_demo = {**demo, "build": {"recipe": "none", "arguments": []}}
            if built_spec != {**spec, "demo": expected_demo}:
                raise ValueError("executor altered verification contract")
            (self.root / "verify-demo/demo.json").write_text(json.dumps(built_spec["demo"]))
        return verify(
            *sides,
            self.root / "verify-demo",
            self.family,
            oracle=demo["oracle"],
            browser=BrowserExecutor() if demo["oracle"] == "xss" else None,
        )

    def dispatch(self, task):
        self.phase = task.step
        before = time.monotonic()
        self.deadline = before + task.limits.get("task_wall_seconds", 900)
        metrics_before = dict(self.worker.metrics)
        result = {}
        end = "execution_failure"
        try:
            if task.step == "verify":
                result = self.verification()
                self.verifications.append(result.outcome)
                self.record["outcome"] = result.outcome
                if self.args.side == "fixed" and result.sides:
                    observations = result.sides[0]
                    if observations.outcome == "observed" and len(observations.runs) == 3:
                        effects = {r.observed for r in observations.runs}
                        if len(effects) == 1:
                            self.record["fixed_effect_observed"] = effects.pop()
                wall = self.record["wall_seconds_by_phase"]
                for phase in ("build", "ready", "run"):
                    wall["verify_" + phase] = wall.get("verify_" + phase, 0) + sum(getattr(s, phase + "_seconds") for s in result.sides)

                for side in result.sides:
                    if side.outcome != "observed":
                        self.failure("verify/" + side.outcome, side.reason, command=side)
                if result.outcome != "demonstrated":
                    self.failure("verify", "no_consistent_differential" if result.outcome == "inconclusive" else result.outcome)
                end = result.outcome
                return dict(status="ok", outcome=result.outcome, evidence_refs=["verify:owned"], cost_usd=0)
            if task.step == "explore":
                if self.args.dry_run:
                    self.worker.executor = InProcessExecutor(self.sides[0 if self.args.side == "vulnerable" else 1].checkout)
                    result = self.worker(task)
                else:
                    with self.executor(self.row[self.args.side], deadline=task.limits["task_wall_seconds"]) as remote:
                        self.worker.executor = remote.client
                        remaining = task.limits["task_wall_seconds"] - (time.monotonic() - before)
                        if remaining < 1:
                            raise BudgetExhausted("explore deadline", usd=0, calls=0, end_detail="task_wall")
                        result = self.worker(replace(task, limits={**task.limits, "task_wall_seconds": remaining}))
                        self.executor_end = result.get("end_detail") or result.get("status", "execution_failure")
            else:
                result = self.worker(task)
            end = result.get("end_detail") or result.get("status", "execution_failure")
            if result.get("status") != "ok":
                self.failure(task.step, result.get("failure", "worker_execution_failed"))
                if self.worker.metrics["model_calls"] == 0 and not result.get("budget_exhaustion"):
                    raise RuntimeError(self.record["failures"][-1]["reason"])
                if not self.verifications:
                    self.record["outcome"] = "inconclusive"
            return result
        except BudgetExhausted as exc:
            end = exc.end_detail
            raise
        finally:
            self.record["task_metrics"].append(
                {
                    "task_id": task.id,
                    "step": task.step,
                    **{key: value - metrics_before[key] for key, value in self.worker.metrics.items()},
                    "wall_seconds": time.monotonic() - before,
                    "end": end,
                }
            )
            wall = self.record["wall_seconds_by_phase"]
            wall[task.step] = wall.get(task.step, 0) + time.monotonic() - before

    def run(self):
        started = time.monotonic()
        coordinator = Coordinator(self.board, self.dispatch, budget=SearchBudget(retries=0))
        try:
            state = coordinator.run()
            self.record["end_reason"] = state["end_reason"]
            self.record["end_detail"] = state.get("end_detail")
            if not self.verifications and any(f.get("step") == "explore" for f in state["facts"]):
                self.record["outcome"] = "plausible_unproven"
        except Exception as exc:
            self.failure(self.phase, exc)
            self.record["outcome"] = (
                "could_not_build"
                if self.record["failures"] and any(f["phase"] in ("build_export", "acquisition") for f in self.record["failures"])
                else "inconclusive"
            )
            self.record["end_reason"] = "instrument_failure"
            if isinstance(exc, ClusterUnavailable) or (self.worker.metrics["model_calls"] == 0 and not isinstance(exc, RepositoryFailure)):
                self.record["aborted_reason"] = self.record["failures"][-1]["reason"]
        metrics = self.worker.metrics
        self.record.update(
            spend={k: metrics[k] for k in ("reserved", "settled")},
            **{k: metrics[k] for k in ("model_calls", "tokens_in", "tokens_out")},
            coordinator_tasks=coordinator.progress["tasks"],
            board_bytes=len(json.dumps(self.board.state).encode()),
            wall_seconds=time.monotonic() - started,
        )
        return self.record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--pairs", required=True)
    parser.add_argument("--ceiling-usd", required=True, type=float)
    parser.add_argument("--manifest", type=Path, default=Path("benchmarks/search/private/pilot.json"))
    parser.add_argument("--private-root", type=Path, default=Path("benchmarks/search/private/runs"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--board-memory", help="Memory store URI; defaults to a private local FileStore")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-lane", choices=("vm", "ax"), default="vm")
    parser.add_argument("--model", default=DEFAULT_DETECTOR_MODEL)
    parser.add_argument("--max-tokens", type=int, default=1024)
    parser.add_argument("--usd-per-mtok-in", type=float)
    parser.add_argument("--usd-per-mtok-out", type=float)
    parser.add_argument("--image")
    parser.add_argument("--ax-bin", default="ax")
    parser.add_argument("--atespace", default="default")
    parser.add_argument("--kubeconfig")
    args = parser.parse_args(argv)
    if not math.isfinite(args.ceiling_usd) or args.ceiling_usd < 0:
        parser.error("ceiling must be finite and nonnegative")
    run_budget = SpendBudget(args.ceiling_usd)
    if not re.fullmatch(r"\d+(,\d+)*", args.pairs) or args.max_tokens < 1:
        parser.error("pairs must be comma-separated nonnegative indices; max tokens must be positive")
    indices = [int(i) for i in args.pairs.split(",")]
    if len(indices) != len(set(indices)):
        parser.error("duplicate pair indices")
    prices = price_of(args.model)
    if args.usd_per_mtok_in is not None or args.usd_per_mtok_out is not None:
        if any(v is None or not math.isfinite(v) or v < 0 for v in (args.usd_per_mtok_in, args.usd_per_mtok_out)):
            parser.error("both finite nonnegative prices required")
        prices = Prices(args.usd_per_mtok_in, args.usd_per_mtok_in, args.usd_per_mtok_out)
    if prices is None:
        parser.error("unknown model: supply both price flags")
    lane = None
    if args.dry_run:
        if indices != [0] or args.verify_lane != "vm" or args.board_memory:
            parser.error("dry run uses probe index 0, VM verifier and private FileStore only")
        rows = [
            dict(
                repo="probe",
                vulnerable="probe-before",
                fixed="probe-after",
                family="path",
                language="python",
                file="app.py",
                function="main",
            )
        ]
    else:
        try:
            validate_image(args.image or "")
        except ValueError:
            parser.error("image must be pinned by sha256 digest")
        if not args.private_root.resolve().is_relative_to(Path("benchmarks/search/private").resolve()):
            parser.error("live working files must stay in benchmarks/search/private")
        if args.verify_lane == "vm":
            if _sandbox.isolation_mode() != "userns":
                parser.error("VM verification requires userns")
            try:
                _sandbox.isolation_check(timeout_seconds=5)
            except _sandbox.IsolationUnavailable:
                parser.error("VM userns isolation probe failed")
        # Validate private manifest before opening any remote store or client.
        if not args.manifest.resolve().is_relative_to(Path("benchmarks/search/private").resolve()):
            parser.error("manifest must stay in benchmarks/search/private")
        try:
            rows = json.loads(args.manifest.read_bytes())["pairs"]
            if not isinstance(rows, list) or any(index >= len(rows) for index in indices):
                parser.error("pair index outside manifest")
        except (OSError, ValueError, KeyError, TypeError):
            parser.error("private manifest unreadable or invalid")
        for index in indices:
            row = rows[index]
            if not isinstance(row, dict) or not all(
                isinstance(row.get(k), str) and row[k] for k in ("repo", args.side, "fixed", "family", "language", "file", "function")
            ):
                parser.error("invalid manifest pair")
            if row["family"] not in (
                "injection",
                "path",
                "output_encoding",
                "untrusted_destination",
                "sql",
                "command",
                "xss",
                "ssrf",
                "access_control",
                "deserialization",
                "configuration",
                "secrets",
            ):
                parser.error("unknown manifest family")
            if row["language"] not in ("python", "javascript", "typescript", "php", "java"):
                parser.error("unknown manifest language")
            path = Path(row["file"])
            if path.is_absolute() or ".." in path.parts or "\\" in row["file"]:
                parser.error("invalid candidate path")

            if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", row["repo"]):
                parser.error("invalid repository URL")
            if not all(re.fullmatch("[0-9a-f]{40}", row[s]) for s in (args.side, "fixed")):
                parser.error("invalid revision")
        load_dotenv()
        if not os.environ.get(DEEPSEEK_KEY_ENV):
            parser.error("DeepSeek key is not configured")
        client = OpenRouterChatClient(
            api_key=os.environ[DEEPSEEK_KEY_ENV], base_url=os.environ.get(DEEPSEEK_BASE_ENV, DEEPSEEK_BASE_URL), max_attempts=1
        )
    root = args.private_root / uuid.uuid4().hex
    root.mkdir(parents=True, mode=0o700)
    records = []
    started = time.monotonic()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as output:
        aborted_reason = None
        try:
            store = open_store(args.board_memory) if args.board_memory else FileStore(root / "boards")
            if not args.dry_run:
                lane = AXLane(args, Workload(args.image, frozenset({"VERIFY_INPUT_URL", "RESULT_URL"}), 900, validate_result))
        except Exception as exc:
            aborted_reason = exception_reason(exc)
        for index in indices if aborted_reason is None else []:
            local = root / str(index)
            local.mkdir()
            if args.dry_run:
                sides, demos = materialise(local / "probe", "path")
                client = scripted(load_demo(demos["real"]))
            pilot = Pilot(args, rows[index], index, local, store, run_budget, client, prices, lane)
            if args.dry_run:
                pilot.sides = sides
                pilot.record["input_bytes"] = len((sides[0 if args.side == "vulnerable" else 1].checkout / "app.py").read_bytes())
            record = pilot.run()
            records.append(record)
            output.write(json.dumps(record, allow_nan=False) + "\n")
            output.flush()
            if record.get("aborted_reason"):
                aborted_reason = record["aborted_reason"]
                break
        summary = dict(
            type="summary",
            end_reason="instrument_failure" if aborted_reason else "completed",
            aborted_reason=aborted_reason,
            skipped_pairs=indices[len(records) :],
            searches=len(records),
            dry_run=args.dry_run,
            side=args.side,
            ceiling_usd=args.ceiling_usd,
            purpose="feasibility_only",
            advantages=["known_location", "labelled_family", "runnable_project_selection_bias"],
            fixed_effects_observed=sum(r["fixed_effect_observed"] is True for r in records),
            outcomes=dict(Counter(r["outcome"] for r in records)),
            spend={k: sum(r["spend"][k] for r in records) for k in ("reserved", "settled")},
            **{k: sum(r[k] for r in records) for k in ("model_calls", "tokens_in", "tokens_out", "tasks_submitted")},
            wall_seconds=time.monotonic() - started,
        )
        output.write(json.dumps(summary, allow_nan=False) + "\n")
    return int(bool(aborted_reason) or any(r["end_reason"] == "instrument_failure" for r in records))


if __name__ == "__main__":
    raise SystemExit(main())
