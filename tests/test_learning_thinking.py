"""Thinking is a measured condition, not a hidden default (learning-harness, Req 8.3).

Thinking was disabled so that `temperature: 0` would not be silently ignored — a trade that only pays if it buys
determinism. Round zero measured 11 of 20 injection pairs disagreeing with themselves across five runs, so it did
not: the variance comes from the agentic path, not the decoder. Which mode is better is a question the harness is
built to answer, so it is a knob whose value the artifact records and whose runs cannot overwrite each other.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.config import load_config


def test_thinking_is_configurable_and_off_by_default(tmp_path: Path) -> None:
    """The default preserves what round zero was measured under; changing it silently would make the two runs
    incomparable while looking like one number."""
    assert load_config(None).learning.thinking is False
    path = tmp_path / "openultrasast.toml"
    path.write_text("[learning]\nthinking = true\n")
    assert load_config(path).learning.thinking is True


def test_the_endpoint_records_the_mode_it_ran_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from openultrasast.learning.endpoint import resolve_chat_endpoint

    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    monkeypatch.delenv("OPENULTRASAST_HUNTER_CLIENT", raising=False)
    path = tmp_path / "openultrasast.toml"
    path.write_text("[learning]\nthinking = true\n")
    client, endpoint = resolve_chat_endpoint(load_config(path))  # type: ignore[misc]
    assert endpoint.thinking is True
    assert client._disable_thinking is False  # type: ignore[attr-defined]
    path.write_text("[learning]\nthinking = false\n")
    client, endpoint = resolve_chat_endpoint(load_config(path))  # type: ignore[misc]
    assert endpoint.thinking is False and client._disable_thinking is True  # type: ignore[attr-defined]


def test_the_two_modes_are_two_baselines_not_one_overwriting_the_other(tmp_path: Path) -> None:
    """The condition that produced a number is part of what identifies it."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from test_learning_rounds import _always, _case, _steady  # noqa: PLC0415

    from openultrasast.learning.families import load_families
    from openultrasast.learning.rounds import compare_baselines, run_baseline

    out = tmp_path / "out"
    for thinking in (False, True):
        run_baseline(
            [_case(tmp_path, "a")],
            taxonomy=load_families(),
            configs_dir=tmp_path / "configs",
            scan_factory=_always(_steady),
            model="deepseek-v4-flash",
            out_dir=out,
            k_runs=3,
            thinking=thinking,
        )
    written = sorted(path.name for path in (out / "baseline").iterdir())
    assert written == ["deepseek-v4-flash", "deepseek-v4-flash-thinking"], written
    assert set(compare_baselines(out)) == {"deepseek-v4-flash", "deepseek-v4-flash (thinking)"}
    report = json.loads((out / "baseline" / "deepseek-v4-flash-thinking" / "report.json").read_text())
    assert report["thinking"] is True
