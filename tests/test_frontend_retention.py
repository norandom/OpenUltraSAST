"""Explicit frontend input policy must survive both subprocess paths."""

from openultrasast.cpg.backend import JoernBackend


def test_first_party_tests_enabled_by_backend(monkeypatch):
    monkeypatch.setenv("OUSAST_INCLUDE_TESTS", "0")
    assert JoernBackend()._jvm_env()["OUSAST_INCLUDE_TESTS"] == "1"


def test_retention_can_be_disabled_explicitly():
    assert JoernBackend(include_tests=False)._jvm_env()["OUSAST_INCLUDE_TESTS"] == "0"


def test_builder_rejects_unrecognized_dependency_before_download(tmp_path):
    import importlib.util
    from pathlib import Path

    import pytest

    spec = importlib.util.spec_from_file_location("retention_builder", Path("ops/frontend-retention/install.py"))
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    jar = tmp_path / "frontends/jssrc2cpg/lib/io.joern.jssrc2cpg-4.0.625.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"different dependency")
    with pytest.raises(ValueError, match="pristine Joern"):
        builder.build(tmp_path)
    assert jar.read_bytes() == b"different dependency"
    assert not (tmp_path / "ousast-frontend-retention-v1").exists()


def test_build_config_retention_is_explicit_and_overrides_ambient_policy(monkeypatch):
    monkeypatch.setenv("OUSAST_INCLUDE_BUILD_CONFIGS", "0")
    assert JoernBackend()._jvm_env()["OUSAST_INCLUDE_BUILD_CONFIGS"] == "1"
    assert JoernBackend(include_build_configs=False)._jvm_env()["OUSAST_INCLUDE_BUILD_CONFIGS"] == "0"
