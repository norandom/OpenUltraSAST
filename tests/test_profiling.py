"""The in-process sampler leaves a readable profile behind, including for a process killed mid-run."""

import time

from openultrasast import profiling


def _busy_quadratic(n: int) -> int:
    seen: list[int] = []
    for i in range(n):
        if i not in seen:
            seen.append(i)
    return len(seen)


def test_the_sampler_names_the_function_that_holds_the_time(tmp_path, monkeypatch):
    target = tmp_path / "profile.txt"
    monkeypatch.delenv(profiling.ENV, raising=False)
    assert profiling.start() is None  # off unless asked for
    assert profiling.start(str(target), interval=0.002, flush=0.2) is not None
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:
        _busy_quadratic(3000)
    time.sleep(0.3)
    text = target.read_text()
    assert text.startswith("samples ")
    self_section = text.split("self (executing):")[1]
    assert "_busy_quadratic" in self_section.splitlines()[1], self_section[:300]
