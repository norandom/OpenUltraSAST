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


def test_fusion_defaults_when_section_absent() -> None:
    config = load_config(None)
    assert config.fusion.enabled is True
    assert config.fusion.panel_model is None
    assert config.fusion.high_assurance is False


def test_load_config_reads_fusion_section(tmp_path: Path) -> None:
    config_path = tmp_path / "openultrasast.toml"
    config_path.write_text('[fusion]\nenabled = true\npanel_model = "gpt-4o"\ndecider_model = "gpt-4o"\nhigh_assurance = true\n')

    config = load_config(config_path)

    assert config.fusion.panel_model == "gpt-4o"
    assert config.fusion.decider_model == "gpt-4o"
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
