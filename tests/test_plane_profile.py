"""plane-on-kubernetes task 1.1: the ``PlaneProfile`` (Req 1.1). Defaults, file-then-environment precedence, every
rejection naming its field, both committed profiles loading, and no committed value that looks like a credential."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from openultrasast.plane import profile as profile_module
from openultrasast.plane.profile import PlaneProfile, Pool, ProfileError, load_images, load_profile, profiles_dir

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "ab" * 32
MINIMAL = 'exec = "local"\nkube_context = "kind-test"\nregistry = "registry.test:5000"\nimages = "images.json"\nmemory = "s3://m"\n'


def write_profile(tmp_path: Path, text: str = MINIMAL, name: str = "test") -> Path:
    path = tmp_path / f"{name}.toml"
    path.write_text(text, encoding="utf-8")
    (tmp_path / "images.json").write_text(json.dumps({"runner": f"registry.test:5000/ousast-runner@{DIGEST}"}), encoding="utf-8")
    return path


def test_defaults_and_the_images_path_resolve_against_the_profile_file(tmp_path: Path) -> None:
    loaded = load_profile(str(write_profile(tmp_path)), environ={})
    assert loaded.name == "test" and loaded.exec == "local" and loaded.kube_context == "kind-test"
    assert loaded.images == tmp_path / "images.json" and loaded.load_images() == {"runner": f"registry.test:5000/ousast-runner@{DIGEST}"}
    assert loaded.atespace == "default" and loaded.router_url == "" and loaded.pools == {}
    assert "(tunnel through the kube context)" in loaded.addresses()["router_url"]


def test_the_environment_overrides_the_file_and_names_the_profile(tmp_path: Path) -> None:
    path = write_profile(tmp_path, MINIMAL + '[pools.default]\nreplicas = 2\ncpu = "1"\nmemory = "1536Mi"\n')
    env = {
        "OUSAST_PLANE_PROFILE": str(path),
        "OUSAST_KUBE_CONTEXT": "other-cluster",
        "OUSAST_MEMORY": "s3://elsewhere/prefix",
        "OUSAST_ROUTER_URL": "https://router.test",
        "OUSAST_POOL_DEFAULT_REPLICAS": "5",
        "OUSAST_POOL_DEFAULT_MEMORY": "2Gi",
        "OUSAST_EXEC": "",  # an empty variable is not an override
    }
    loaded = load_profile(environ=env)
    assert (loaded.kube_context, loaded.memory, loaded.router_url, loaded.exec) == (
        "other-cluster",
        "s3://elsewhere/prefix",
        "https://router.test",
        "local",
    )
    assert loaded.pools == {"default": Pool(replicas=5, cpu="1", memory="2Gi")}
    assert load_profile(str(path), environ={}).kube_context == "kind-test", "the file is unchanged"


@pytest.mark.parametrize(
    ("text", "field"),
    [
        (MINIMAL + 'colour = "blue"\n', "unknown keys: colour"),
        (MINIMAL + 'aws_secret_key = "x"\n', "aws_secret_key looks like a credential"),
        (MINIMAL + 'api_token = "x"\n', "api_token looks like a credential"),
        (MINIMAL.replace('exec = "local"', 'exec = "cluster"'), "exec must be one of local, remote"),
        (MINIMAL + '[pools.default]\nreplicas = "two"\ncpu = "1"\nmemory = "1Gi"\n', "pools.default.replicas must be an integer"),
        (MINIMAL + '[pools.default]\nreplicas = 1\ncpu = "1"\n', "pools.default lacks memory"),
        (MINIMAL + '[pools.default]\nreplicas = 1\ncpu = "1"\nmemory = "1Gi"\nnodes = 3\n', "pools.default has unknown keys: nodes"),
        (MINIMAL.replace('kube_context = "kind-test"', "kube_context = 3"), "kube_context must be a string"),
    ],
)
def test_each_rejection_names_the_field(tmp_path: Path, text: str, field: str) -> None:
    path = write_profile(tmp_path, text)
    with pytest.raises(ProfileError, match=re.escape(field)) as exc:
        load_profile(str(path), environ={})
    assert str(path) in str(exc.value)


def test_a_credential_shaped_value_is_refused(tmp_path: Path) -> None:
    path = write_profile(tmp_path, MINIMAL.replace("s3://m", "sk-" + "a1b2c3d4" * 3))
    with pytest.raises(ProfileError, match="value of memory looks like a credential"):
        load_profile(str(path), environ={})


def test_an_images_file_without_digest_pins_is_refused(tmp_path: Path) -> None:
    path = write_profile(tmp_path)
    (tmp_path / "images.json").write_text(json.dumps({"runner": "registry.test:5000/ousast-runner:dev"}), encoding="utf-8")
    with pytest.raises(ProfileError, match="runner is not digest-pinned"):
        load_profile(str(path), environ={})
    (tmp_path / "images.json").write_text(f"registry.test:5000/ousast-runner@{DIGEST}\n", encoding="utf-8")
    assert load_images(tmp_path / "images.json") == {"runner": f"registry.test:5000/ousast-runner@{DIGEST}"}, "the one-line form"
    (tmp_path / "images.json").unlink()
    loaded = load_profile(str(path), environ={})  # a file the release has not published yet: doctor's finding, not a load error
    with pytest.raises(ProfileError, match="images file"):
        loaded.load_images()


def test_an_environment_override_of_the_wrong_shape_is_refused(tmp_path: Path) -> None:
    path = write_profile(tmp_path, MINIMAL + '[pools.default]\nreplicas = 1\ncpu = "1"\nmemory = "1Gi"\n')
    with pytest.raises(ProfileError, match="OUSAST_POOL_DEFAULT_REPLICAS must be an integer"):
        load_profile(str(path), environ={"OUSAST_POOL_DEFAULT_REPLICAS": "many"})
    with pytest.raises(ProfileError, match="names a pool the profile does not declare"):
        load_profile(str(path), environ={"OUSAST_POOL_ENGINE_REPLICAS": "1"})
    with pytest.raises(ProfileError, match="exec must be one of"):
        load_profile(str(path), environ={"OUSAST_EXEC": "both"})


def test_a_missing_profile_names_its_path(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="no-such.toml"):
        load_profile(str(tmp_path / "no-such.toml"), environ={})
    with pytest.raises(ProfileError, match="unknown"):
        load_profile("unknown", environ={"OUSAST_PLANE_PROFILES": str(tmp_path)})


@pytest.mark.parametrize("name", ["kind", "k3s"])
def test_both_committed_profiles_load_with_the_designs_values(name: str) -> None:
    loaded = load_profile(name, environ={})
    assert loaded.path == profiles_dir() / f"{name}.toml" and profiles_dir() == ROOT / "ops/k8s/profiles"
    assert loaded.exec == {"kind": "local", "k3s": "remote"}[name]
    assert loaded.memory == "s3://sast-memory" and loaded.atespace == "default" and loaded.snapshots_bucket == "s3://ax-snapshots"
    assert set(loaded.pools) == {"default", "engine"} and loaded.pools["engine"].memory == "4Gi"
    assert loaded.router_url == "" and loaded.ax_server == "", "both profiles tunnel through the Kubernetes API"
    if name == "kind":
        assert loaded.image_pull_secret == "" and loaded.images.name == "kind-images.json" and loaded.images.is_file()
        assert set(loaded.load_images()) == {"runner"} and loaded.load_images()["runner"].startswith(loaded.registry + "/")
    else:
        assert loaded.image_pull_secret == "ghcr-pull" and loaded.registry.startswith("ghcr.io/") and loaded.images.name == "images.json"
        assert not loaded.images.is_file(), "the release asset is downloaded, never committed (design section 8)"


def test_no_committed_profile_value_matches_a_credential_pattern() -> None:
    patterns = (
        re.compile(r"(?i)(api_key|secret_key|access_key|token|password)\s*="),  # image_pull_secret names a Secret, holds none
        re.compile(r"sk-[A-Za-z0-9]{8,}"),
        re.compile(r"AKIA[0-9A-Z]{12,}"),
    )
    for path in sorted(profiles_dir().glob("*.toml")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            for pattern in patterns:
                assert not pattern.search(code), f"{path}:{number}: {line.strip()}"


def test_print_for_shell_scripts(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = write_profile(tmp_path, MINIMAL + '[pools.default]\nreplicas = 3\ncpu = "1"\nmemory = "1Gi"\n')
    fields = ["registry", "kube_context", "images.runner", "pools.default.replicas"]
    assert profile_module.main(["--profile", str(path), "--print", *fields]) == 0
    assert capsys.readouterr().out.splitlines() == ["registry.test:5000", "kind-test", f"registry.test:5000/ousast-runner@{DIGEST}", "3"]
    assert profile_module.main(["--profile", str(path), "--print", "images.engine"]) == 2
    assert "no image named 'engine'" in capsys.readouterr().err
    assert profile_module.main(["--profile", str(path), "--print", "nothing"]) == 2


def test_profile_is_frozen_and_typed() -> None:
    loaded = load_profile("kind", environ={})
    assert isinstance(loaded, PlaneProfile)
    with pytest.raises(AttributeError):
        loaded.exec = "remote"  # type: ignore[misc]
