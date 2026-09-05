"""authorization-obligations task 1.2: obligation shapes derived from trusted pairs (offline, stdlib ast)."""

from __future__ import annotations

from openultrasast.semantic.facts import load_facts
from openultrasast.semantic.ir import parse_file

VULN_READ = (
    "from flask import request\n\n\ndef get_book(book_title):\n"
    "    resp = token_validator(request.headers.get('Authorization'))\n"
    "    if 'error' in resp:\n        return None\n"
    "    book = Book.query.filter_by(book_title=book_title).first()\n    return book\n"
)
FIXED_READ = (
    "from flask import request\n\n\ndef get_book(book_title):\n"
    "    resp = token_validator(request.headers.get('Authorization'))\n"
    "    if 'error' in resp:\n        return None\n"
    "    user = User.query.filter_by(username=resp['sub']).first()\n"
    "    book = Book.query.filter_by(user=user, book_title=book_title).first()\n    return book\n"
)
# Real-Vuln style: the vulnerable side already contains the safe branch; the fixed twin is the same function
TOGGLED = (
    "from flask import request\n\n\ndef get_book(book_title):\n"
    "    resp = token_validator(request.headers.get('Authorization'))\n"
    "    if 'error' in resp:\n        return None\n"
    "    if vuln:\n        book = Book.query.filter_by(book_title=book_title).first()\n"
    "    else:\n        user = User.query.filter_by(username=resp['sub']).first()\n"
    "        book = Book.query.filter_by(user=user, book_title=book_title).first()\n    return book\n"
)
VULN_SETTING = (
    "from flask import Flask\nfrom flask_cors import CORS\n\n\ndef create_app():\n"
    + "    app = Flask(__name__)\n    CORS(app, origins='*')\n    return app\n"
)
FIXED_SETTING = (
    "from flask import Flask\nfrom flask_cors import CORS\n\n\ndef create_app():\n"
    + "    app = Flask(__name__)\n    CORS(app, origins=['https://app.example'])\n    return app\n"
)
BODY_IDENTITY_FIX = (
    "from flask import request\n\n\ndef update_profile():\n    data = request.get_json()\n"
    "    user_id = request.user.id\n    Profile.query.filter_by(user_id=user_id).update(data)\n"
)
BODY_IDENTITY_VULN = (
    "from flask import request\n\n\ndef update_profile():\n    data = request.get_json()\n"
    "    user_id = data['user_id']\n    Profile.query.filter_by(user_id=user_id).update(data)\n"
)


def _derive(vuln: str, fixed: str, *, function: str, mechanism: str = "missing_auth_guard", obligation: str | None = None):
    from openultrasast.semantic.obligations import load_obligation_facts
    from openultrasast.semantic.obligations.shapes import derive_obligation

    return derive_obligation(
        parse_file("app.py", vuln, "python"),
        parse_file("app.py", fixed, "python"),
        function=function,
        obligation=obligation,
        mechanism=mechanism,
        facts=load_obligation_facts(),
        flow_facts=load_facts(),
        vuln_text=vuln,
        fixed_text=fixed,
    )


def test_identity_constraint_added_on_the_fixed_side_is_the_lesson() -> None:
    from openultrasast.semantic.obligations.shapes import ObligationShape

    shape = _derive(VULN_READ, FIXED_READ, function="get_book")
    assert isinstance(shape, ObligationShape)
    assert (shape.language, shape.operation_kind, shape.discharger_kind, shape.provenance) == (
        "python",
        "protected_read",
        "identity_constraint",
        "authenticated_context",
    )
    assert shape.resource_class == "owned" and shape.mechanism == "missing_auth_guard" and shape.family == "obligation"
    key = shape.key()
    assert key.startswith("obligation|") and "app.py" not in key and "book_title" not in key and "resp" not in key
    assert ObligationShape.from_dict(shape.to_dict()) == shape


def test_flag_toggled_twin_teaches_from_the_discharged_sibling_operation() -> None:
    """Real-Vuln pairs: identical function on both sides; the safe branch's constrained read is the discharger lesson."""
    shape = _derive(TOGGLED, TOGGLED, function="get_book")
    assert shape is not None and shape.discharger_kind == "identity_constraint" and shape.provenance == "authenticated_context"
    renamed = _derive(
        TOGGLED.replace("book", "item").replace("Book", "Item"),
        TOGGLED.replace("book", "item").replace("Book", "Item"),
        function="get_item",
    )
    assert renamed is not None and renamed.key() == shape.key()


def test_permissive_default_pair_yields_a_setting_shape_with_constant_provenance() -> None:
    shape = _derive(VULN_SETTING, FIXED_SETTING, function="create_app", mechanism="permissive_default")
    assert shape is not None
    assert (shape.operation_kind, shape.discharger_kind, shape.provenance, shape.resource_class) == (
        "security_setting",
        "non_permissive_value",
        "constant",
        "setting",
    )


def test_identity_from_request_body_pair_reports_the_fixed_provenance_and_the_label_kind_wins() -> None:
    shape = _derive(
        BODY_IDENTITY_VULN,
        BODY_IDENTITY_FIX,
        function="update_profile",
        mechanism="identity_from_request_body",
        obligation="protected_write",
    )
    assert shape is not None
    assert (
        shape.operation_kind == "protected_write"
        and shape.discharger_kind == "identity_constraint"
        and shape.provenance == "authenticated_context"
    )


def test_no_discharger_added_and_missing_function_return_none_with_reasons() -> None:
    from openultrasast.semantic.obligations.shapes import explain_skip

    assert _derive(VULN_READ, VULN_READ, function="get_book") is None
    reason = explain_skip(
        parse_file("app.py", VULN_READ, "python"),
        parse_file("app.py", VULN_READ, "python"),
        function="get_book",
        vuln_text=VULN_READ,
        fixed_text=VULN_READ,
    )
    assert reason.startswith("no_discharger_added:") and "identity_constraint" in reason  # names the dischargers the operation accepts
    assert _derive(VULN_READ, FIXED_READ, function="nope") is None
    constant_only = "def show():\n    return Book.query.filter_by(book_title='x').first()\n"
    assert _derive(constant_only, constant_only, function="show") is None
    assert _derive("def f(:\n", FIXED_READ, function="get_book") is None


def test_unrelated_trap_twin_teaches_from_the_vulnerable_functions_own_safe_branch() -> None:
    """Real-Vuln twins are often a different trap function with no same-kind operation; the lesson then comes from the
    vulnerable function's own discharged sibling operation."""
    trap = "def health():\n    return 'ok'\n"
    shape = _derive(TOGGLED, trap, function="get_book")
    assert shape is not None and shape.discharger_kind == "identity_constraint" and shape.provenance == "authenticated_context"
