"""Bounded declarative demonstrations; no executable agent content or private variables.

Only a previously captured application response can define a substitution. Runtime
paths and build manifests are checkout relative; request payloads remain data (and
may contain traversal or injection strings being tested at the public interface).
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, cast

FAMILY_ORACLES = {
    "injection": ("sql", "command"),
    "path": ("path",),
    "output_encoding": ("xss",),
    "untrusted_destination": ("ssrf",),
    "deserialization": (),
    "access_control": (),
    "config_secrets": (),
}


def validate_oracle(family: str, oracle: str) -> None:
    if not isinstance(family, str) or family not in FAMILY_ORACLES:
        raise ValueError("unknown search family")
    if oracle not in FAMILY_ORACLES[family]:
        raise ValueError("demo oracle is not allowed for search family " + family)


# JSON escaping can expand UTF-8 data sixfold and non-BMP environment characters
# into twelve-byte surrogate pairs. Keep the ordinary demo payload at 64 KiB.
MAX_DEMO_BYTES = 5 * 1024 * 1024
MAX_DATA_BYTES = 64 * 1024
ENV_DENYLIST = {
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
}
DATA_EXTENSIONS = {".pem", ".key", ".json", ".yaml", ".yml", ".txt", ".env", ".ini", ".toml", ".db", ".sqlite", ".crt"}
MAX_STEPS = 32
MAX_VALUE_BYTES = 16384
# Every executable and option is verifier-owned. Arguments below are manifests or
# an enumerated build goal, never arbitrary package-manager flags or scripts.
BUILD_RECIPES = {
    "none": (),
    "pip": ("/usr/bin/python3", "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--target", "/scratch/packages", "-r"),
    "npm": ("/usr/bin/npm", "ci", "--offline", "--ignore-scripts", "--prefix"),
    "composer": ("/usr/bin/composer", "install", "--no-plugins", "--no-scripts", "--no-interaction", "--working-dir"),
    "maven": ("/usr/bin/mvn", "--offline", "-f"),
    "gradle": ("/usr/bin/gradle", "--offline", "--no-daemon", "--project-dir"),
}
RUNTIMES = {"python": ("/usr/bin/python3", "-I"), "node": ("/usr/bin/node",), "php": ("/usr/bin/php",), "java": ("/usr/bin/java", "-jar")}
_REFERENCE = re.compile(r"\$\{([a-z][a-z0-9_]{0,31})\}")
_PRIVATE = re.compile(r"/(?:fixture|proc|sys|dev|deps|build)(?:/|\b)|(?:PROOF_MARKER|CALLBACK_URL|DATABASE|SERVED_ROOT)", re.I)


# The model-facing schema is the same closed structure checked by validate_demo;
# dynamic capture ordering and checkout containment are additional semantic checks.
_TEXT_SCHEMA = {"type": "string", "maxLength": MAX_VALUE_BYTES}
_ARG_SCHEMA = {"type": "array", "items": _TEXT_SCHEMA, "maxItems": 64}
_CAPTURE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["name", "source"],
    "properties": {
        "name": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
        "source": {"enum": ["output", "json"]},
        "path": {"type": "array", "maxItems": 8, "items": {"type": ["string", "integer"]}},
    },
}
DEMO_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["oracle", "build", "start", "steps"],
    "properties": {
        "oracle": {"enum": sorted({o for allowed in FAMILY_ORACLES.values() for o in allowed})},
        "build": {
            "type": "object",
            "additionalProperties": False,
            "required": ["recipe", "arguments"],
            "properties": {
                "recipe": {"enum": list(BUILD_RECIPES)},
                "arguments": {"type": "array", "items": {"type": "string", "maxLength": 512}, "maxItems": 1},
            },
            "description": "none takes no arguments; other recipes take one checkout-relative manifest or project path.",
        },
        "start": {
            "type": "object",
            "additionalProperties": False,
            "required": ["runtime", "path", "arguments", "mode"],
            "properties": {
                "runtime": {"enum": list(RUNTIMES)},
                "path": {"type": "string", "minLength": 1, "maxLength": 512},
                "arguments": _ARG_SCHEMA,
                "mode": {"enum": ["http", "cli"]},
                "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
                "environment": {
                    "type": "object",
                    "maxProperties": 32,
                    "propertyNames": {
                        "pattern": "^[A-Z][A-Z0-9_]{0,63}$",
                        "not": {
                            "anyOf": [
                                {"enum": sorted(ENV_DENYLIST)},
                                {"pattern": "^OUSAST_|CANARY"},
                            ]
                        },
                    },
                    "additionalProperties": {"type": "string", "maxLength": 4096},
                },
                "files": {
                    "type": "object",
                    "maxProperties": 8,
                    "additionalProperties": {"type": "string", "maxLength": MAX_DATA_BYTES},
                    "description": "Relative data filenames under .demo/, no ..; allowed extensions: "
                    + " ".join(sorted(DATA_EXTENSIONS))
                    + "; contents at most 64 KiB UTF-8 each, written mode 0600. No scripts.",
                },
            },
            "description": "Tracked checkout entrypoint only. HTTP mode requires a port; CLI mode forbids it.",
        },
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_STEPS,
            "items": {
                "oneOf": [
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["type", "arguments"],
                        "properties": {
                            "type": {"const": "cli"},
                            "arguments": _ARG_SCHEMA,
                            "stdin": _TEXT_SCHEMA,
                            "capture": _CAPTURE_SCHEMA,
                        },
                    },
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["type", "method", "path"],
                        "properties": {
                            "type": {"const": "http"},
                            "method": {"enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
                            "path": {"type": "string", "pattern": "^/(?!/)", "maxLength": MAX_VALUE_BYTES},
                            "headers": {"type": "object", "maxProperties": 32, "additionalProperties": _TEXT_SCHEMA},
                            "body": _TEXT_SCHEMA,
                            "capture": _CAPTURE_SCHEMA,
                        },
                    },
                ]
            },
            "description": "Steps match the start mode. Only ${name} from a prior response capture may be substituted.",
        },
    },
}


def _keys(value: Any, required: set[str], optional: set[str] | frozenset[str] = frozenset()) -> None:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("invalid or unknown schema fields")


def checkout_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or "\0" in value:
        raise ValueError("invalid checkout path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("", "..", ".") or p.startswith("-") for p in value.split("/")):
        raise ValueError("path must stay inside checkout")
    if not re.fullmatch(r"[a-zA-Z0-9_./ -]+", value):
        raise ValueError("invalid checkout path")
    return value


_MANIFESTS = {
    "pip": ("pyproject.toml", "setup.py", "setup.cfg"),
    "npm": ("package.json", "package-lock.json"),
    "composer": ("composer.json", "composer.lock"),
    "maven": ("pom.xml",),
    "gradle": ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew"),
}


def build_project(recipe: str, path: Path, checkout: Path) -> Path:
    """Validate the recipe ecosystem against actual checkout files."""

    def manifest(candidate: Path) -> bool:
        return candidate.name in _MANIFESTS[recipe] or (recipe == "pip" and candidate.match("requirements*.txt"))

    def contained(candidate: Path) -> bool:
        return candidate.resolve().is_relative_to(checkout.resolve())

    if not contained(path):
        raise ValueError("recipe input outside checkout")
    if path.is_file():
        if not manifest(path):
            raise ValueError("recipe input is not an ecosystem manifest")
        return path.parent
    if path.is_dir() and any(p.is_file() and contained(p) and manifest(p) for p in path.iterdir()):
        return path
    raise ValueError("recipe input must be an ecosystem manifest or project directory")


def preparation_command(recipe: str, path: Path, checkout: Path, products: Path) -> tuple[list[str], Path]:
    project = build_project(recipe, path, checkout)
    if recipe == "pip":
        requirements = path if path.is_file() and path.match("requirements*.txt") else None
        pyproject = project / "pyproject.toml"
        backend = False
        if requirements is None and pyproject.is_file():
            if not pyproject.resolve().is_relative_to(checkout.resolve()):
                raise ValueError("recipe input outside checkout")
            backend = bool(tomllib.loads(pyproject.read_text()).get("build-system", {}).get("build-backend"))
        if requirements is None and not backend and not (project / "setup.py").is_file():
            fallback = project / "requirements.txt"
            if fallback.is_file():
                requirements = fallback
        target = requirements or project
        if not target.resolve().is_relative_to(checkout.resolve()):
            raise ValueError("recipe input outside checkout")
        return [
            "python3",
            "-I",
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(products / "packages"),
            *(["-r", str(target)] if requirements else [str(target)]),
        ], project
    if recipe == "npm":
        return ["npm", "ci" if (project / "package-lock.json").is_file() else "install", "--ignore-scripts"], project
    if recipe == "composer":
        return ["composer", "install", "--no-interaction", "--no-plugins", "--no-scripts"], project
    if recipe == "maven":
        return ["mvn", "-q", "-DskipTests", "package", "-f", str(project / "pom.xml")], project
    wrapper = project / "gradlew"
    if not wrapper.is_file() or not wrapper.resolve().is_relative_to(checkout.resolve()):
        raise ValueError("missing or external Gradle wrapper")
    return ["/bin/sh", str(wrapper), "--no-daemon", "--project-dir", str(project), "assemble"], project


def _text(value: Any, names: set[str], *, maximum: int = MAX_VALUE_BYTES) -> str:
    if not isinstance(value, str) or "\0" in value or len(value.encode()) > maximum:
        raise ValueError("invalid or oversized value")
    if _PRIVATE.search(value):
        raise ValueError("private verifier references are forbidden")
    references = _REFERENCE.findall(value)
    if any(name not in names for name in references) or "$" in _REFERENCE.sub("", value):
        raise ValueError("only earlier response captures may be referenced")
    return value


def _arguments(value: Any, names: set[str]) -> None:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("invalid argument list")
    for arg in value:
        _text(arg, names)


def validate_start_config(start: dict[str, Any]) -> None:
    environment = start.get("environment", {})
    if not isinstance(environment, dict) or len(environment) > 32:
        raise ValueError("invalid environment map")
    for name, value in environment.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name)
            or name in ENV_DENYLIST
            or name.startswith("OUSAST_")
            or "CANARY" in name
        ):
            raise ValueError("forbidden environment variable")
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError("invalid environment value")
        _text(value, set())
    files = start.get("files", {})
    if not isinstance(files, dict) or len(files) > 8:
        raise ValueError("invalid data file map")
    for name, content in files.items():
        checkout_path(name)
        if ".." in name or not any(name.endswith(ext) for ext in DATA_EXTENSIONS):
            raise ValueError("invalid data file extension or name")
        _text(content, set(), maximum=MAX_DATA_BYTES)


def write_start_files(checkout: Path, start: dict[str, Any]) -> None:
    """Create only new private data files, before any app process is launched."""
    validate_start_config(start)
    for name, content in start.get("files", {}).items():
        path = checkout / ".demo" / name
        directory = checkout
        for part in path.parent.relative_to(checkout).parts:
            directory /= part
            if directory.is_symlink():
                raise ValueError("data directory cannot be a symlink")
            directory.mkdir(exist_ok=True)
        # O_EXCL refuses existing files, links and hardlinks: never overwrite checkout data.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content.encode())


def validate_demo(value: Any, *, checkout: Path | None = None) -> dict[str, Any]:
    try:
        encoded = json.dumps(value, allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("demo must be JSON data") from exc
    if len(encoded) > MAX_DEMO_BYTES:
        raise ValueError("demo exceeds size limit")
    _keys(value, {"oracle", "build", "start", "steps"})
    if not isinstance(value["oracle"], str) or not any(value["oracle"] in allowed for allowed in FAMILY_ORACLES.values()):
        raise ValueError("unknown demo oracle")
    build, start = value["build"], value["start"]
    _keys(build, {"recipe", "arguments"})
    recipe = build["recipe"]
    if not isinstance(recipe, str) or recipe not in BUILD_RECIPES:
        raise ValueError("unknown build recipe")
    _arguments(build["arguments"], set())
    args = build["arguments"]
    if recipe == "none":
        if args:
            raise ValueError("none recipe accepts no arguments")
    else:
        if len(args) != 1:
            raise ValueError("recipe requires one checkout path")
        if args[0] != ".":
            checkout_path(args[0])
        if checkout is not None:
            build_project(recipe, checkout / args[0], checkout)
    _keys(start, {"runtime", "path", "arguments", "mode"}, {"port", "environment", "files"})
    validate_start_config(start)
    ordinary = {**value, "start": {k: v for k, v in start.items() if k not in {"environment", "files"}}}
    if len(json.dumps(ordinary, allow_nan=False).encode()) > 65536:
        raise ValueError("demo excluding configuration exceeds size limit")
    if not isinstance(start["runtime"], str) or start["runtime"] not in RUNTIMES:
        raise ValueError("unknown runtime")
    checkout_path(start["path"])
    if start["path"].split("/")[0] == ".demo":
        raise ValueError("data files cannot be runtime entrypoints")
    _arguments(start["arguments"], set())
    if any(
        arg.startswith("/") or ".." in arg.split("/") or re.search(r"(?:^|[= :])/(?:etc|home|root|tmp|workspace|scratch)/", arg)
        for arg in start["arguments"]
    ):
        raise ValueError("start arguments must not name external paths")
    if start["mode"] not in ("http", "cli"):
        raise ValueError("invalid start mode")
    if start["mode"] == "http":
        if type(start.get("port")) is not int or not 1024 <= start["port"] <= 65535:
            raise ValueError("http requires an unprivileged port")
    elif "port" in start:
        raise ValueError("cli does not accept a port")
    steps = value["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError("invalid step count")
    names: set[str] = set()
    for step in steps:
        if not isinstance(step, dict) or step.get("type") != start["mode"]:
            raise ValueError("step must match runtime mode")
        if step["type"] == "cli":
            _keys(step, {"type", "arguments"}, {"stdin", "capture"})
            _arguments(step["arguments"], names)
            _text(step.get("stdin", ""), names)
        else:
            _keys(step, {"type", "method", "path"}, {"headers", "body", "capture"})
            if step["method"] not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                raise ValueError("invalid HTTP method")
            path = _text(step["path"], names)
            if not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n"):
                raise ValueError("HTTP path must be origin relative")
            headers = step.get("headers", {})
            if not isinstance(headers, dict) or len(headers) > 32:
                raise ValueError("invalid headers")
            for key, val in headers.items():
                if (
                    not isinstance(key, str)
                    or not re.fullmatch(r"[A-Za-z0-9-]+", key)
                    or key.lower() in ("host", "connection", "content-length", "transfer-encoding", "proxy-authorization")
                ):
                    raise ValueError("invalid HTTP header")
                if any(c in _text(val, names) for c in "\r\n"):
                    raise ValueError("invalid HTTP header value")
            _text(step.get("body", ""), names)
        if "capture" in step:
            capture = step["capture"]
            _keys(capture, {"name", "source"}, {"path"})
            name = capture["name"]
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name)
                or name in names
                or name == "canary"
                or _PRIVATE.search(name)
            ):
                raise ValueError("invalid capture name")
            if capture["source"] not in ("output", "json"):
                raise ValueError("invalid capture source")
            path = capture.get("path", [])
            if not isinstance(path, list) or len(path) > 8 or any(type(p) not in (str, int) for p in path):
                raise ValueError("invalid JSON capture path")
            names.add(name)
    return cast(dict[str, Any], json.loads(encoded))


def load_demo(path: Path) -> dict[str, Any]:
    if path.is_dir():
        # Legacy scripts cannot coexist with the schema and accidentally execute.
        if any(p.name != "demo.json" for p in path.iterdir()):
            raise ValueError("demo directory may contain only demo.json")
        path = path / "demo.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DEMO_BYTES:
        raise ValueError("invalid demo file")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    try:
        return validate_demo(json.loads(path.read_text(), object_pairs_hook=pairs))
    except RecursionError as exc:
        raise ValueError("demo nesting exceeds limit") from exc


def substitute(value: str, captures: dict[str, str]) -> str:
    result = _REFERENCE.sub(lambda m: captures[m.group(1)], value)
    if len(result.encode()) > MAX_VALUE_BYTES or "\0" in result:
        raise ValueError("expanded value exceeds limit")
    return result


def capture_output(step: dict[str, Any], output: str, captures: dict[str, str], nonce: str) -> None:
    if "capture" not in step:
        return
    spec = step["capture"]
    value: Any = output
    if spec["source"] == "json":
        value = json.loads(output)
        for part in spec.get("path", []):
            value = value[part]
    if not isinstance(value, str):
        value = json.dumps(value, allow_nan=False)
    # Even a response revealing the canary cannot turn it into an input variable.
    if nonce in value:
        raise ValueError("canary values cannot be captured")
    _text(value, set())
    captures[spec["name"]] = value
