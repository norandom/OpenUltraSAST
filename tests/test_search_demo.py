import json

import pytest

from openultrasast.search.demo import load_demo, validate_demo


def document():
    return {
        "oracle": "path",
        "build": {"recipe": "none", "arguments": []},
        "start": {"runtime": "python", "path": "app.py", "arguments": [], "mode": "cli"},
        "steps": [{"type": "cli", "arguments": ["hello"]}],
    }


def test_valid_and_roundtrip(tmp_path):
    value = document()
    (tmp_path / "demo.json").write_text(json.dumps(value))
    assert load_demo(tmp_path) == value


@pytest.mark.parametrize("path", ["../app.py", "/fixture/canary", "/etc/passwd", "a/../../app.py", "-c", "a\\b"])
def test_checkout_paths_only(path):
    value = document()
    value["start"]["path"] = path
    with pytest.raises(ValueError):
        validate_demo(value)


@pytest.mark.parametrize("argument", ["$PROOF_MARKER", "${CANARY}", "/fixture/canary", "/proc/1/environ", "${later}", "x\x00y"])
def test_private_references_rejected(argument):
    value = document()
    value["steps"][0]["arguments"] = [argument]
    with pytest.raises(ValueError):
        validate_demo(value)


def test_sequential_capture():
    value = document()
    value["steps"][0]["capture"] = {"name": "token", "source": "json", "path": ["token"]}
    value["steps"].append({"type": "cli", "arguments": ["${token}"]})
    assert validate_demo(value) == value
    value["steps"][0]["arguments"] = ["${token}"]
    with pytest.raises(ValueError):
        validate_demo(value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(env={}),
        lambda d: d["build"].update(recipe="shell"),
        lambda d: d["build"].update(arguments=["--index-url=evil"]),
        lambda d: d["start"].update(runtime="sh"),
        lambda d: d.update(steps=d["steps"] * 33),
    ],
)
def test_unknown_keys_recipes_and_limits(mutate):
    value = document()
    mutate(value)
    with pytest.raises(ValueError):
        validate_demo(value)


@pytest.mark.parametrize("recipe", ["npm", "composer", "gradle"])
def test_directory_build_recipe_accepts_checkout_root(recipe):
    value = document()
    value["build"] = {"recipe": recipe, "arguments": ["."]}
    assert validate_demo(value) == value


@pytest.mark.parametrize("recipe", ["pip", "maven"])
def test_manifest_recipe_accepts_project_directory(recipe):
    value = document()
    value["build"] = {"recipe": recipe, "arguments": ["."]}
    assert validate_demo(value) == value


@pytest.mark.parametrize("oracle", [None, "injection", "unknown", [], 1])
def test_oracle_required_and_known(oracle):
    value = document()
    if oracle is None:
        value.pop("oracle")
    else:
        value["oracle"] = oracle
    with pytest.raises(ValueError):
        validate_demo(value)


@pytest.mark.parametrize(
    "family,allowed",
    [
        ("injection", ("sql", "command")),
        ("path", ("path",)),
        ("output_encoding", ("xss",)),
        ("untrusted_destination", ("ssrf",)),
        ("deserialization", ()),
        ("access_control", ()),
        ("config_secrets", ()),
    ],
)
def test_family_oracle_contract(family, allowed):
    from openultrasast.search.demo import FAMILY_ORACLES, validate_oracle

    assert FAMILY_ORACLES[family] == allowed
    for oracle in ("sql", "command", "path", "xss", "ssrf"):
        if oracle in allowed:
            validate_oracle(family, oracle)
        else:
            with pytest.raises(ValueError, match="not allowed"):
                validate_oracle(family, oracle)


@pytest.mark.parametrize(
    "recipe,manifest",
    [("pip", "package.json"), ("npm", "requirements.txt"), ("composer", "pom.xml"), ("maven", "composer.json"), ("gradle", "setup.py")],
)
@pytest.mark.parametrize("directory", [False, True])
def test_recipe_rejects_other_ecosystem(tmp_path, recipe, manifest, directory):
    (tmp_path / manifest).write_text("{}")
    value = document()
    value["build"] = {"recipe": recipe, "arguments": ["." if directory else manifest]}
    with pytest.raises(ValueError, match="ecosystem"):
        validate_demo(value, checkout=tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "NODE_PATH",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "PHP_INI_SCAN_DIR",
        "PHPRC",
        "PATH",
        "HOME",
        "TMPDIR",
        "OUSAST_SECRET",
        "MY_CANARY_KEY",
        "lowercase",
        "1KEY",
        "A" * 65,
    ],
)
def test_environment_denylist(name):
    value = document()
    value["start"]["environment"] = {name: "value"}
    with pytest.raises(ValueError):
        validate_demo(value)


@pytest.mark.parametrize("content", ["${canary}", "/fixture/canary", "$PROOF_MARKER", "x\0y"])
@pytest.mark.parametrize("field,key", [("environment", "JWT_KEY"), ("files", "jwt.key")])
def test_config_preserves_no_canary_rule(field, key, content):
    value = document()
    value["start"][field] = {key: content}
    with pytest.raises(ValueError):
        validate_demo(value)


def test_config_boundaries_and_private_file_modes(tmp_path):
    from openultrasast.search.demo import write_start_files

    value = document()
    value["start"]["environment"] = {f"KEY_{i}": "é" * 4096 for i in range(32)}
    value["start"]["files"] = {f"keys/{i}.pem": "é" * 32768 for i in range(8)}
    assert validate_demo(value) == value
    write_start_files(tmp_path, value["start"])
    for name, content in value["start"]["files"].items():
        path = tmp_path / ".demo" / name
        assert path.read_text() == content
        assert path.stat().st_mode & 0o777 == 0o600
    for field, key, content in [("environment", "EXTRA", "x"), ("files", "extra.pem", "x")]:
        value["start"][field][key] = content
        with pytest.raises(ValueError):
            validate_demo(value)
        del value["start"][field][key]
    value["start"]["files"]["keys/0.pem"] += "x"
    with pytest.raises(ValueError):
        validate_demo(value)
    value["start"]["files"] = {}
    value["start"]["environment"]["KEY_0"] += "x"
    with pytest.raises(ValueError):
        validate_demo(value)


@pytest.mark.parametrize("name", ["../key.pem", "a/../key.pem", "/tmp/key.pem", "a..pem", "app.py", "run.sh", "x.exe", "a\\b.pem"])
def test_data_file_paths_and_extensions(name):
    value = document()
    value["start"]["files"] = {name: "data"}
    with pytest.raises(ValueError):
        validate_demo(value)


@pytest.mark.parametrize("where", ["root", "parent", "file", "existing"])
def test_data_files_never_follow_links_or_overwrite(tmp_path, where):
    from openultrasast.search.demo import write_start_files

    outside = tmp_path / "outside"
    outside.mkdir()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    root = checkout / ".demo"
    if where == "root":
        root.symlink_to(outside, target_is_directory=True)
    else:
        root.mkdir()
        if where == "parent":
            (root / "keys").symlink_to(outside, target_is_directory=True)
        else:
            (root / "keys").mkdir()
            if where == "file":
                (root / "keys/key.pem").symlink_to(outside / "key.pem")
            else:
                (root / "keys/key.pem").write_text("original")
    with pytest.raises((ValueError, FileExistsError)):
        write_start_files(checkout, {"files": {"keys/key.pem": "changed"}})
    assert not list(outside.iterdir())
    if where == "existing":
        assert (root / "keys/key.pem").read_text() == "original"
