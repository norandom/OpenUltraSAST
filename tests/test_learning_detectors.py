"""learning-harness task 2.5: per-family detector configurations and the family runner (offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openultrasast.learning.families import load_families
from openultrasast.tool_hunter import ChatResponse, ScriptedChatClient, ToolCall

APP = (
    "from flask import request\n\n\n"
    "@app.route('/books/<title>')\n@login_required\ndef guarded(title):\n"
    "    return Book.query.filter_by(book_title=title).first()\n\n\n"
    "@app.route('/books/any/<title>')\ndef leaky(title):\n"
    "    owner = request.args.get('owner')\n"
    "    return Book.query.filter_by(user_id=owner, book_title=title).first()\n"
)
REPLY = '[{"path": "app.py", "line": 12, "title": "unconstrained read", "rationale": "no owner check"}]'


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(APP)
    return tmp_path


def _write_config(root: Path, family: str, **overrides: object) -> Path:
    directory = root / family
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "prompt.md").write_text(str(overrides.get("prompt", f"You hunt {family} only.")))
    (directory / "checklist.md").write_text(str(overrides.get("checklist", "- did the handler check ownership?")))
    tools = overrides.get("tools", ["read_definition", "obligations"])
    (directory / "family.toml").write_text(
        f'version = "{overrides.get("version", "1")}"\ntools = {json.dumps(tools)}\n'
        f"max_steps = {overrides.get('max_steps', 3)}\nmax_cost_usd = {overrides.get('max_cost_usd', 0.5)}\n"
        f"max_chars = {overrides.get('max_chars', 4000)}\n"
    )
    (directory / "hard_negatives.jsonl").write_text(json.dumps({"note": "a guarded handler is not a finding"}) + "\n")
    (directory / "counterexamples.jsonl").write_text("")
    return directory


def test_a_configuration_loads_every_part_it_needs(tmp_path: Path) -> None:
    from openultrasast.learning.detectors import load_family_configs

    _write_config(tmp_path, "access_control")
    configs = load_family_configs(tmp_path, load_families())
    config = configs["access_control"]
    assert config.family == "access_control" and config.version == "1"
    assert config.prompt.startswith("You hunt access_control") and "ownership" in config.checklist
    assert config.tools == ("read_definition", "obligations")
    assert config.max_steps == 3 and config.max_cost_usd == 0.5 and config.max_chars == 4000
    assert config.hard_negatives[0]["note"].startswith("a guarded handler")
    assert config.counterexamples == ()
    assert load_family_configs(tmp_path, load_families())["access_control"] == config  # loading twice is the same config


@pytest.mark.parametrize(
    ("overrides", "needle"),
    [
        ({"prompt": "x" * 9000}, "length"),
        ({"tools": ["read_file", "run_shell"]}, "run_shell"),
        ({"version": ""}, "version"),
    ],
    ids=["over_cap_prompt", "unknown_tool", "no_version"],
)
def test_the_loader_refuses_a_broken_configuration_by_name(tmp_path: Path, overrides: dict[str, object], needle: str) -> None:
    from openultrasast.learning.detectors import DetectorConfigError, load_family_configs

    _write_config(tmp_path, "access_control", **overrides)
    with pytest.raises(DetectorConfigError, match=needle):
        load_family_configs(tmp_path, load_families())


def test_a_directory_that_is_not_a_family_is_refused_by_name(tmp_path: Path) -> None:
    from openultrasast.learning.detectors import DetectorConfigError, load_family_configs

    _write_config(tmp_path, "access_control")
    (tmp_path / "sql_injection").mkdir()
    (tmp_path / "sql_injection" / "prompt.md").write_text("x")
    with pytest.raises(DetectorConfigError, match="sql_injection"):
        load_family_configs(tmp_path, load_families())


def test_the_runner_uses_the_family_prompt_tools_and_tags(repo: Path, tmp_path: Path) -> None:
    from openultrasast.learning.detectors import Region, load_family_configs, run_family_detector

    configs_dir = tmp_path / "configs"
    _write_config(configs_dir, "access_control")
    config = load_family_configs(configs_dir, load_families())["access_control"]
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="1", name="obligations", arguments={"path": "app.py", "function": "leaky"}),)),
            ChatResponse(content=REPLY),
        ]
    )
    findings = run_family_detector(repo, Region(path="app.py", function="leaky"), config, client=client, model="m")
    assert [finding.tags for finding in findings] == [["family:access_control", "detector:access_control@1"]]
    assert findings[0].evidence_level == "suspicion"
    call = client.calls[0]
    assert call["messages"][0]["content"] == "You hunt access_control only."
    assert [tool["function"]["name"] for tool in call["tools"]] == ["read_definition", "obligations"]
    user = str(call["messages"][1]["content"])
    assert "def leaky" in user and "def guarded" in user  # the whole file, not an excerpt around a hotspot
    assert "ownership" in user and "a guarded handler is not a finding" in user


def test_a_region_runs_every_admitted_family_plus_the_generalist(repo: Path, tmp_path: Path) -> None:
    from openultrasast.learning.detectors import Region, load_family_configs, run_region_detectors

    configs_dir = tmp_path / "configs"
    for family in ("access_control", "injection", "unknown"):
        _write_config(configs_dir, family, tools=["read_file"])
    configs = load_family_configs(configs_dir, load_families())
    client = ScriptedChatClient(
        [
            ChatResponse(tool_calls=(ToolCall(id="1", name="read_file", arguments={"path": "app.py"}),)),
            ChatResponse(content=REPLY),
        ]
        * 4
    )
    region = Region(path="app.py", function="leaky", families=("access_control",))
    findings = run_region_detectors(repo, region, configs, client=client, model="m")
    families = sorted({tag for finding in findings for tag in finding.tags if tag.startswith("family:")})
    assert families == ["family:access_control", "family:unknown"]  # the admitted family and the generalist, not injection
    assert len(client.calls) == 4  # two turns each, and nothing else was run


def test_the_runner_never_offers_a_tool_outside_the_curated_set(repo: Path, tmp_path: Path) -> None:
    from openultrasast.learning.detectors import Region, load_family_configs, run_family_detector
    from openultrasast.tool_hunter import HUNTER_TOOLS

    configs_dir = tmp_path / "configs"
    _write_config(
        configs_dir, "injection", tools=["read_file", "grep_repo", "find_refs", "read_definition", "entry_points", "flows", "obligations"]
    )
    config = load_family_configs(configs_dir, load_families())["injection"]
    client = ScriptedChatClient([ChatResponse(content="")])
    run_family_detector(repo, Region(path="app.py", function="leaky"), config, client=client, model="m")
    offered = {tool["function"]["name"] for tool in client.calls[0]["tools"]}
    assert offered == {str(tool["function"]["name"]) for tool in HUNTER_TOOLS}
    assert "bash" not in offered and "run_shell" not in offered


def test_round_zero_can_write_a_configuration_for_every_family(tmp_path: Path) -> None:
    from openultrasast.learning.detectors import load_family_configs, write_default_configs

    taxonomy = load_families()
    written = write_default_configs(tmp_path, taxonomy, prompt="You are a security hunter.", version="0")
    assert set(written) == {family.id for family in taxonomy.families}
    configs = load_family_configs(tmp_path, taxonomy)
    assert set(configs) == {family.id for family in taxonomy.families}
    assert all(config.version == "0" for config in configs.values())
    assert all(config.prompt.startswith("You are a security hunter.") for config in configs.values())
    assert configs["access_control"].prompt != configs["injection"].prompt  # each carries its own family's definition
