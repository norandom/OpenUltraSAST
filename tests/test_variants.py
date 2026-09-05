"""corpus-seeded-mechanisms: structural shapes derived from pairs and matched on trees (offline, stdlib ast)."""

from __future__ import annotations

from openultrasast.semantic.facts import load_facts
from openultrasast.semantic.ir import parse_file

VULN = "from flask import request\nimport os\n\n\ndef run():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n"
FIXED = (
    "from flask import request\nimport os\n\nALLOWED = {'ls', 'date'}\n\n\ndef run():\n    cmd = request.args.get('cmd')\n"
    "    if cmd not in ALLOWED:\n        return None\n    os.system(cmd)\n"
)


def _derive(vuln: str = VULN, fixed: str = FIXED, **overrides: object):
    from openultrasast.semantic.variants import derive_shape

    kwargs: dict[str, object] = {"function": "run", "sink": "os.system", "line": None, "mechanism": "source_reaches_sink"}
    kwargs.update(overrides)
    return derive_shape(
        parse_file("app.py", vuln, "python"),
        parse_file("app.py", fixed, "python"),
        vuln_text=vuln,
        fixed_text=fixed,
        facts=load_facts(),
        **kwargs,
    )


def test_derive_shape_from_a_request_to_os_system_pair_with_an_allowlist_fix() -> None:
    from openultrasast.semantic.variants import GUARD_KINDS, SOURCE_KINDS

    shape = _derive()
    assert shape is not None
    assert shape.language == "python" and shape.sink_name == "system" and shape.arity == 1
    assert shape.source_positions == (0,) and shape.source_kinds == ("fact_source",)
    assert shape.guard == "allowlist_test" and shape.guard in GUARD_KINDS and shape.mechanism == "source_reaches_sink"
    assert set(shape.source_kinds) <= set(SOURCE_KINDS)


def test_shape_key_is_stable_and_carries_no_path_line_or_literal() -> None:
    a, b = _derive(), _derive()
    assert a is not None and b is not None and a.key() == b.key()
    key = a.key()
    for forbidden in ("app.py", "cmd", "'ls'", "request.args", ":6", ":7"):
        assert forbidden not in key
    # the same code in another file with different variable names is the same shape
    other_vuln = VULN.replace("cmd", "command")
    other = _derive(other_vuln, FIXED.replace("cmd", "command"))
    assert other is not None and other.key() == key


def test_parameter_and_container_read_sources_are_classified() -> None:
    vuln = "import os\n\n\ndef run(payload, cmd):\n    target = payload['t']\n    os.system(cmd + target)\n"
    fixed = (
        "import os\n\n\ndef run(payload, cmd):\n    target = payload['t']\n    if len(target) > 32:\n        return None\n"
        "    os.system(cmd + target)\n"
    )
    shape = _derive(vuln, fixed)
    assert shape is not None
    assert shape.source_positions == (0,)
    assert shape.source_kinds in {("parameter",), ("container_read",)}  # one argument carrying both; the kind is the first found
    assert shape.guard == "bounds_test"


def test_unlabeled_or_missing_sink_returns_none_and_guard_defaults_to_none() -> None:
    assert _derive(sink="subprocess.run") is None  # the label names a sink the function never calls
    assert _derive(function="other") is None  # no such function
    same = _derive(VULN, VULN)
    assert same is not None and same.guard == "none"  # no statement differs on the fixed side
    constant = "import os\n\n\ndef run():\n    os.system('ls')\n"
    assert _derive(constant, constant) is None  # a constant argument carries no source: nothing to learn


def test_parse_failed_side_yields_no_shape() -> None:
    assert _derive("def run(:\n", FIXED) is None
