"""Replay a stored pilot demo without a board or model; output DIR/record.json.

Live execution acquires repositories inside executor tasks. Offline tests inject
an in-process executor and a fake lane; this CLI itself is not an offline clone.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from benchmarks.ax.batch import DockerLane
from benchmarks.search.pilot_run import (
    FAMILY_ORACLES,
    AXLane,
    AXSideDispatcher,
    BrowserExecutor,
    Pilot,
    Side,
    Workload,
    diagnostic,
    digest,
    exception_reason,
    load_demo,
    validate_image,
    validate_oracle,
    validate_result,
    verification_run_seconds,
    verification_timeout,
    verify,
)
from openultrasast.search.verify import SideRecord


class Replay(Pilot):
    """Reuse pilot acquisition/redaction without constructing its board or worker."""

    def __init__(self, args, root, lane, demo):
        self.args, self.root, self.lane = args, root, lane
        self.deadline = float("inf")
        self.row = dict(repo=args.repo_url, vulnerable=args.commit, fixed=args.fixed_commit or args.commit, file=demo["start"]["path"])
        self.record = dict(tasks_submitted=0, executor_tasks=0, verify_tasks=0, input_bytes=0, failures=[])
        self.preparations = []

    def prepare(self, revision, spec):
        row = dict(
            revision_digest=digest(revision),
            wall_seconds_by_phase={},
            build_exit_code=None,
            build_stderr_tail="",
            archive_bytes=0,
            archive_parts=0,
        )
        self.preparations.append(row)
        started = time.monotonic()
        task = None
        try:
            with self._executor(revision) as task:
                row["wall_seconds_by_phase"]["acquisition"] = time.monotonic() - started
                before = time.monotonic()
                try:
                    return task.prepare(spec)
                finally:
                    row["wall_seconds_by_phase"]["prepare_roundtrip"] = time.monotonic() - before
        except Exception as exc:
            self.failure("build_export", exc)
            # The dispatcher preserves build failure semantics and we retain diagnostics.
            raise ValueError(self.record["failures"][-1]["reason"]) from exc
        finally:
            result = getattr(task, "preparation_result", {})
            row["wall_seconds_by_phase"].update(result.get("wall_seconds_by_phase", {}))
            row.update(
                build_exit_code=result.get("exit_code"),
                build_stderr_tail=result.get("stderr", ""),
                archive_bytes=result.get("archive_bytes", 0),
                archive_parts=result.get("archive_parts", 0),
                wall_seconds=time.monotonic() - started,
            )


def run_replay(args, root, *, lane=None):
    started = time.monotonic()
    demo = load_demo(args.demo)
    timeout = verification_timeout(demo)
    replay = Replay(args, root, lane, demo)
    record = dict(
        type="demo_replay",
        repo_digest=digest(args.repo_url),
        revision_digest=digest(args.commit),
        family=args.family,
        lane=args.lane,
        both=args.both,
        model_calls=0,
        spend_usd=0,
    )
    if args.both:
        record["fixed_revision_digest"] = digest(args.fixed_commit)
    if not FAMILY_ORACLES[args.family]:
        result = SideRecord("no_oracle", (), 0, "no configured owned oracle")
        sides = [] if args.both else [result]
    else:
        validate_oracle(args.family, demo["oracle"])
        workload = Workload(
            args.image,
            frozenset({"VERIFY_INPUT_URL", "RESULT_URL"}),
            verification_run_seconds(demo, timeout) + 60,
            validate_result,
            kind="search-verify",
        )
        lane = lane or (DockerLane if args.lane == "docker" else AXLane)(args, workload)
        if isinstance(lane, DockerLane):
            lane._diagnostics = []
            lane._prepare_image()
            lane._prepared = True
        replay.lane = copy.copy(lane)
        if isinstance(lane, DockerLane):
            replay.lane.ax = replay.lane._docker_command
        keys = [Side(root / "affected"), Side(root / "fixed")]
        pins = {keys[0].checkout: args.commit, keys[1].checkout: args.fixed_commit}

        def counted_lane(*a, **kw):
            replay.admit_task()
            replay.record["verify_tasks"] += 1
            return lane(*a, **kw)

        dispatcher = AXSideDispatcher(
            args, args.image, root / "verify", lane=counted_lane, prepare=lambda side, spec: replay.prepare(pins[side.checkout], spec)
        )

        def dispatch(**kwargs):
            before = time.monotonic()
            try:
                return dispatcher(**kwargs)
            except Exception as exc:
                replay.failure("verify", exc)
                return SideRecord(
                    "could_not_run", (), time.monotonic() - before, replay.record["failures"][-1]["reason"], isolation_mode="task-boundary"
                )

        if args.both:
            result = verify(
                *keys,
                args.demo,
                args.family,
                timeout_seconds=timeout,
                oracle=demo["oracle"],
                task_dispatcher=dispatch,
                browser=BrowserExecutor(task_boundary=True) if demo["oracle"] == "xss" else None,
            )
            sides = result.sides
        else:
            result = dispatch(side=keys[0], demo=demo, family=args.family, timeout_seconds=timeout, fresh_task=True)
            sides = [result]
    phases = {}
    for preparation in replay.preparations:
        for phase, seconds in preparation["wall_seconds_by_phase"].items():
            phases[phase] = phases.get(phase, 0) + seconds
    for phase in ("build", "ready", "run"):
        phases["verify_" + phase] = sum(getattr(s, phase + "_seconds") for s in sides)
    record.update(
        outcome=result.outcome,
        reason=result.reason,
        sides=[asdict(s) for s in sides],
        preparations=replay.preparations,
        **replay.record,
        wall_seconds_by_phase=phases,
        wall_seconds=time.monotonic() - started,
    )
    # Apply the pilot's diagnostic redaction to every free-form string, including evidence.
    private = tuple(str(v) for v in replay.row.values()) + (str(root), args.repo_url.removeprefix("https://github.com/"))

    def redact(value):
        if isinstance(value, str):
            return diagnostic(value, maximum=1500, private=private)
        if isinstance(value, list):
            return [redact(v) for v in value]
        if isinstance(value, dict):
            return {k: redact(v) for k, v in value.items()}
        return value

    return redact(record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("repo-url", "commit", "image"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--demo", type=Path, required=True)
    parser.add_argument("--family", choices=tuple(FAMILY_ORACLES), required=True)
    parser.add_argument("--lane", choices=("ax", "docker"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--both", action="store_true")
    parser.add_argument("--fixed-commit")
    parser.add_argument("--ax-bin", default="ax")
    parser.add_argument("--atespace", default="default")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--docker-image-bytes", type=int)
    args = parser.parse_args(argv)
    if args.both != bool(args.fixed_commit):
        parser.error("--both and --fixed-commit must be supplied together")
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo_url):
        parser.error("credential-free GitHub HTTPS repository URL required")
    if any(not re.fullmatch(r"[0-9a-f]{40}", pin) for pin in (args.commit, args.fixed_commit) if pin is not None):
        parser.error("full lowercase commit SHA required")
    try:
        validate_image(args.image)
        load_demo(args.demo)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.lane == "docker" and (args.docker_image_bytes is None or args.docker_image_bytes <= 0):
        parser.error("docker requires --docker-image-bytes (unpacked image upper bound)")
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="demo-replay-") as directory:
        try:
            record = run_replay(args, Path(directory))
        except Exception as exc:
            record = dict(
                type="demo_replay",
                repo_digest=digest(args.repo_url),
                revision_digest=digest(args.commit),
                outcome="could_not_run",
                reason=exception_reason(exc, private=(args.repo_url, args.commit, args.fixed_commit or "", directory)),
                model_calls=0,
                spend_usd=0,
                sides=[],
            )
            if args.both:
                record["fixed_revision_digest"] = digest(args.fixed_commit)
    (args.out / "record.json").write_text(json.dumps(record, indent=2, allow_nan=False) + "\n")
    print(json.dumps(record, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
