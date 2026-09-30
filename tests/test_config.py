import logging
import os
from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast.config import RetiredConfigError, load_config, load_dotenv, write_resolved_config


def test_load_config_reads_toml(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(
        "\n".join(
            [
                "[models]",
                'ranker = "openrouter/test-ranker"',
                "[sandbox]",
                "memory_mb = 1024",
                "[dynamic]",
                "enabled = true",
                'network_scope = ["127.0.0.1:8080"]',
            ]
        )
    )

    config = load_config(config_path)

    assert config.models.ranker == "openrouter/test-ranker"
    assert config.embeddings.store == "json-local"
    assert config.sandbox.memory_mb == 1024
    assert config.dynamic.enabled is True
    assert config.dynamic.network_scope == ("127.0.0.1:8080",)


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
    assert '"minimum_report_verified": "static_corroboration"' in output.read_text()


def test_complexity_and_regress_defaults_when_section_absent() -> None:
    config = load_config(None)

    assert config.complexity.top_k == 20
    assert config.complexity.max_hunter_hotspots == 8
    assert config.regress.max_candidates == 5
    assert config.regress.images == ()
    assert config.sandbox.network is False
    assert config.sandbox.workspace_readonly is True
    assert config.sandbox.memory_mb == 2048
    assert config.sandbox.timeout_seconds == 300
    assert config.sandbox.pids_limit == 512


def test_override_changes_top_k_and_max_candidates_only(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(
        "\n".join(
            [
                "[complexity]",
                "top_k = 3",
                "[regress]",
                "max_candidates = 2",
            ]
        )
    )

    config = load_config(config_path)

    assert config.complexity.top_k == 3
    assert config.regress.max_candidates == 2
    assert config.complexity.max_hunter_hotspots == 8
    assert config.regress.images == ()
    assert config.sandbox.network is False
    assert config.sandbox.workspace_readonly is True
    assert config.sandbox.memory_mb == 2048
    assert config.sandbox.timeout_seconds == 300
    assert config.sandbox.pids_limit == 512


def test_load_config_reads_regress_image_pins(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(
        "\n".join(
            [
                "[regress]",
                "max_candidates = 4",
                "[regress.images]",
                'python = "python:3.12-slim"',
                'javascript = "node:22-slim"',
            ]
        )
    )

    config = load_config(config_path)

    assert config.regress.max_candidates == 4
    assert dict(config.regress.images) == {"python": "python:3.12-slim", "javascript": "node:22-slim"}
    assert config.complexity.top_k == 20
    assert config.complexity.max_hunter_hotspots == 8
    assert config.sandbox.memory_mb == 2048


def test_load_dotenv_sets_missing_keys_only(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=from-file\nOPENROUTER_EMBEDDING_MODEL=openai/text-embedding-3-small\n")
    monkeypatch.setenv("OPENROUTER_API_KEY", "already-set")
    monkeypatch.delenv("OPENROUTER_EMBEDDING_MODEL", raising=False)

    load_dotenv(env_file, force=True)

    assert os.environ["OPENROUTER_API_KEY"] == "already-set"
    assert os.environ["OPENROUTER_EMBEDDING_MODEL"] == "openai/text-embedding-3-small"


def test_embeddings_model_from_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OPENROUTER_EMBEDDING_MODEL", "openai/text-embedding-3-small")
    config = load_config(None)
    assert config.embeddings.model == "openai/text-embedding-3-small"
