"""A sampling profiler for long runs, switched on by ``OUSAST_SAMPLE_PROFILE=<path>``.

Named by the 2026-09-23 PHP transfer replay, which found three quadratic walls one per two-hour run: a cache
that rescanned itself on every write, a relationship list searched linearly, and a fsync per cache entry. Each
was invisible until a run died on it, because the only record was the engine's own log and all three were
Python-side bookkeeping BETWEEN engine calls. The host cannot attach a profiler to the container's process, so
the process profiles itself.

A daemon thread samples the main thread's stack every ``interval`` seconds and rewrites ``path`` every
``flush`` seconds with the functions that were on the stack most often, cumulative and self. It rewrites rather
than appends, so a process killed at its deadline still leaves the profile of everything before the kill -- the
case that matters most, and the one an exit hook cannot serve.
"""

from __future__ import annotations

import collections
import contextlib
import os
import sys
import threading
import time
from pathlib import Path
from types import FrameType

ENV = "OUSAST_SAMPLE_PROFILE"


def _frames(frame: FrameType | None) -> list[str]:
    names = []
    while frame is not None:
        code = frame.f_code
        names.append(f"{Path(code.co_filename).name}:{code.co_firstlineno}:{code.co_name}")
        frame = frame.f_back
    return names


def start(path: str | None = None, *, interval: float = 0.01, flush: float = 30.0) -> threading.Thread | None:
    """Start sampling the calling thread; ``None`` when no path is configured."""
    target = path or os.environ.get(ENV, "").strip()
    if not target:
        return None
    main = threading.get_ident()
    cumulative: collections.Counter[str] = collections.Counter()
    own: collections.Counter[str] = collections.Counter()
    started = time.monotonic()
    samples = 0

    def write() -> None:
        lines = [f"samples {samples} over {time.monotonic() - started:.0f}s at {interval}s", "", "cumulative (on the stack):"]
        lines += [f"{count / max(samples, 1):7.1%}  {name}" for name, count in cumulative.most_common(40)]
        lines += ["", "self (executing):"]
        lines += [f"{count / max(samples, 1):7.1%}  {name}" for name, count in own.most_common(25)]
        partial = Path(target + ".partial")
        partial.write_text("\n".join(lines) + "\n")
        partial.replace(target)

    def run() -> None:
        nonlocal samples
        last = time.monotonic()
        while True:
            time.sleep(interval)
            frame = sys._current_frames().get(main)
            if frame is None:
                return
            stack = _frames(frame)
            samples += 1
            own[stack[0]] += 1
            for name in set(stack):
                cumulative[name] += 1
            if time.monotonic() - last >= flush:
                last = time.monotonic()
                with contextlib.suppress(OSError):
                    write()

    thread = threading.Thread(target=run, name="ousast-sampler", daemon=True)
    thread.start()
    return thread
