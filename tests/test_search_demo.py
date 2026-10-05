import json

import pytest

from openultrasast.search.demo import load_demo, validate_demo


def document():
    return {
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
def test_manifest_recipe_requires_file_path(recipe):
    value = document()
    value["build"] = {"recipe": recipe, "arguments": ["."]}
    with pytest.raises(ValueError):
        validate_demo(value)
