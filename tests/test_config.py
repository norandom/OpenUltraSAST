from pathlib import Path

from openultrasast.config import load_config, write_resolved_config


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


def test_harnessx_defaults_when_section_absent() -> None:
    config = load_config(None)
    assert config.harnessx.provider == "anthropic"
    assert config.harnessx.max_cost_usd == 2.0
    assert config.harnessx.token_threshold == 120_000


def test_load_config_reads_harnessx_section(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text(
        "\n".join(
            [
                "[harnessx]",
                'provider = "openai"',
                "max_cost_usd = 5.0",
                "token_threshold = 200000",
            ]
        )
    )

    config = load_config(config_path)

    assert config.harnessx.provider == "openai"
    assert config.harnessx.max_cost_usd == 5.0
    assert config.harnessx.token_threshold == 200_000


def test_write_resolved_config_creates_json(tmp_path: Path) -> None:
    output = tmp_path / "run" / "resolved_config.json"

    write_resolved_config(load_config(None), output)

    assert output.exists()
    assert '"minimum_report_verified": "static_corroboration"' in output.read_text()
