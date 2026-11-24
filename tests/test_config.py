import json
import logging
import os
from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast.config import ResolvedConfig, RetiredConfigError, load_config, load_dotenv, write_resolved_config


def test_load_config_reads_toml(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(
        "\n".join(
            [
                "[models]",
                'ranker = "openrouter/test-ranker"',
                "[sandbox]",
                "memory_mb = 1024",
            ]
        )
    )

    config = load_config(config_path)

    assert config.models.ranker == "openrouter/test-ranker"
    assert config.sandbox.memory_mb == 1024


def test_retired_agentic_section_loads_with_one_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # retired 2026-09-30: a budget-only [harnessx] section loads with one warning naming the plane (Req 3.3)
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text('[harnessx]\nprovider = "openai"\nmax_cost_usd = 5.0\n[score]\nmin_score = 70\n')  # retired 2026-09-30

    with caplog.at_level(logging.WARNING, logger="openultrasast.config"):
        config = load_config(config_path)

    records = [record for record in caplog.records if record.name == "openultrasast.config"]
    assert len(records) == 1
    assert "ax plane" in records[0].getMessage() and "ops/ax/README.md" in records[0].getMessage()
    assert config.score.min_score == 70  # the rest of the file still loads
    assert config == replace(load_config(None), score=config.score)  # and nothing else is read from the section


@pytest.mark.parametrize(
    ("body", "key", "replacement"),
    [
        ('[models]\nverifier = "gpt-4o"\n', "`[models] verifier`", "`verify` + `agree`"),
        ('[fusion]\npanel_model = "gpt-4o"\n', "`[fusion] panel_model`", "`agree` task"),
        ('[fusion]\ndecider_model = "gpt-4o"\n', "`[fusion] decider_model`", "`agree` task"),
    ],
)
def test_retired_llm_keys_fail_naming_the_replacement(tmp_path: Path, body: str, key: str, replacement: str) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(body)

    with pytest.raises(RetiredConfigError) as raised:
        load_config(config_path)

    message = str(raised.value)
    assert key in message and replacement in message and "ousast plane run" in message and "Remove the key" in message


@pytest.mark.parametrize(
    ("body", "key"),
    [
        ('[models]\npatcher = "gpt-4o"\n', "`[models] patcher`"),
        ("[dynamic]\nenabled = true\n", "`[dynamic] enabled`"),
        ('[dynamic]\nnetwork_scope = ["127.0.0.1:8080"]\n', "`[dynamic] network_scope`"),
        ('[evidence]\nminimum_report_verified = "static_corroboration"\n', "`[evidence] minimum_report_verified`"),
        ('[evidence]\nminimum_exploit = "crash_reproduced"\n', "`[evidence] minimum_exploit`"),
        ('[evidence]\nminimum_patch = "root_cause_explained"\n', "`[evidence] minimum_patch`"),
        ("[variants]\nenabled = false\n", "`[variants] enabled`"),
        ("[variants]\nmax_mechanisms = 10\n", "`[variants] max_mechanisms`"),
        ('[embeddings]\nmodel = "openai/text-embedding-3-small"\n', "`[embeddings] model`"),
        ('[embeddings]\nstore = "json-local"\n', "`[embeddings] store`"),
        ("[sandbox]\nnetwork = true\n", "`[sandbox] network`"),
        ("[sandbox]\nworkspace_readonly = false\n", "`[sandbox] workspace_readonly`"),
        ("[complexity]\ntop_k = 3\n", "`[complexity] top_k`"),
    ],
)
def test_unread_keys_fail_naming_why(tmp_path: Path, body: str, key: str) -> None:
    """Keys that loaded but were never read are retired (2026-10-02) the same way, each naming its reason."""
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(body)

    with pytest.raises(RetiredConfigError) as raised:
        load_config(config_path)

    message = str(raised.value)
    assert key in message and "retired 2026-10-02 because nothing ever read it" in message and "Remove the key" in message


def test_the_cli_exits_2_on_a_retired_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from openultrasast.cli import main

    (tmp_path / "repo").mkdir()
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text('[models]\nverifier = "gpt-4o"\n')

    assert main(["scan", str(tmp_path / "repo"), "--config", str(config_path)]) == 2
    assert "`[models] verifier`" in capsys.readouterr().err


def test_fusion_defaults_when_section_absent() -> None:
    config = load_config(None)
    assert config.fusion.enabled is True
    assert config.fusion.high_assurance is False


def test_load_config_reads_fusion_section(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text("[fusion]\nenabled = false\nhigh_assurance = true\n")

    config = load_config(config_path)

    assert config.fusion.enabled is False
    assert config.fusion.high_assurance is True


def test_hardening_defaults_when_section_absent() -> None:
    config = load_config(None)
    assert config.hardening.redact_secrets is True
    assert config.hardening.max_findings == 0


def test_load_config_reads_hardening_section(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text("[hardening]\nredact_secrets = false\nmax_findings = 5\n")

    config = load_config(config_path)

    assert config.hardening.redact_secrets is False
    assert config.hardening.max_findings == 5


def test_write_resolved_config_creates_json(tmp_path: Path) -> None:
    output = tmp_path / "run" / "resolved_config.json"

    write_resolved_config(load_config(None), output)

    assert output.exists()
    payload = json.loads(output.read_text())
    assert payload["sandbox"]["memory_mb"] == 2048
    # retired 2026-10-02 (never read): the unread sections are not echoed as if they configured something
    assert not {"dynamic", "evidence", "variants", "embeddings"} & set(payload) and "patcher" not in payload["models"]


def test_complexity_defaults_when_section_absent() -> None:
    config = load_config(None)

    assert config.complexity.max_hunter_hotspots == 8
    assert config.sandbox.memory_mb == 2048
    assert config.sandbox.timeout_seconds == 300
    assert config.sandbox.pids_limit == 512


def test_override_changes_max_hunter_hotspots_only(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(
        "\n".join(
            [
                "[complexity]",
                "max_hunter_hotspots = 3",
            ]
        )
    )

    config = load_config(config_path)

    assert config.complexity.max_hunter_hotspots == 3
    assert config.sandbox.memory_mb == 2048
    assert config.sandbox.timeout_seconds == 300
    assert config.sandbox.pids_limit == 512


def test_load_dotenv_sets_missing_keys_only(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=from-file\nS3_REGION=us-east-1\n")
    monkeypatch.setenv("OPENROUTER_API_KEY", "already-set")
    monkeypatch.delenv("S3_REGION", raising=False)

    load_dotenv(env_file, force=True)

    assert os.environ["OPENROUTER_API_KEY"] == "already-set"
    assert os.environ["S3_REGION"] == "us-east-1"


def test_runs_dir_defaults_to_the_user_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    assert Path(load_config(None).runs_dir) == tmp_path / "cache" / "openultrasast" / "runs"


@pytest.mark.parametrize("xdg", ["", "relative/cache"])
def test_an_empty_or_relative_xdg_cache_home_falls_back_to_the_home_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, xdg: str
) -> None:
    monkeypatch.delenv("OPENULTRASAST_RUNS_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CACHE_HOME", xdg)

    assert Path(load_config(None).runs_dir) == tmp_path / ".cache" / "openultrasast" / "runs"


def test_the_runs_dir_override_wins_and_an_absolute_one_is_used_as_given(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(link / "runs"))

    assert Path(load_config(None).runs_dir) == link / "runs"


def test_a_relative_runs_dir_override_is_taken_from_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    working = tmp_path / "working"
    working.mkdir()
    monkeypatch.chdir(working)
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert Path(load_config(None).runs_dir) == working / ".runs"


def test_a_config_built_without_the_loader_follows_the_same_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", str(tmp_path / "runs"))

    assert ResolvedConfig().runs_dir == str(tmp_path / "runs")
