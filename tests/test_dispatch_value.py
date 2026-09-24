"""A registry read returns its VALUE argument, not its context: a fact, loaded and checked."""

import dataclasses

import pytest

from openultrasast.model.specs import taint_specs
from openultrasast.semantic.facts import FactLoadError, load_facts


def _write(tmp_path, dispatch: str) -> None:
    (tmp_path / "php.toml").write_text('language = "php"\n[[source]]\nid = "g"\npatterns = ["$_GET"]\n' + dispatch)


def test_the_shipped_facts_say_which_argument_a_filter_returns() -> None:
    spec = taint_specs(language="php")["injection"]
    assert "apply_filters:2" in spec.dispatch_value and "do_action:0" in spec.dispatch_value


def test_a_dispatch_row_declares_returns_with_a_position(tmp_path) -> None:
    row = '[[dispatch]]\nid = "hooks"\nregister = ["add_filter"]\napply = ["apply_filters", "do_action"]\n'
    _write(tmp_path, row + 'returns = ["apply_filters"]\nvalue_arg = 2\n')
    (fact,) = load_facts(tmp_path).dispatches
    assert fact.returns == ("apply_filters",) and fact.value_arg == 2


@pytest.mark.parametrize(
    "row",
    [
        'returns = ["apply_filters"]\n',  # a returning call without the value's position
        'returns = ["not_an_apply_call"]\nvalue_arg = 2\n',
        "value_arg = -1\n",
    ],
)
def test_a_malformed_dispatch_row_is_refused(tmp_path, row: str) -> None:
    _write(tmp_path, '[[dispatch]]\nid = "hooks"\nregister = ["add_filter"]\napply = ["apply_filters"]\n' + row)
    with pytest.raises(FactLoadError):
        load_facts(tmp_path)


def test_request_arguments_must_name_register_calls(tmp_path) -> None:
    row = '[[dispatch]]\nid = "hooks"\nregister = ["add_action"]\napply = ["do_action"]\n'
    _write(tmp_path, row + 'request_arguments = ["register_rest_route"]\n')
    with pytest.raises(FactLoadError):
        load_facts(tmp_path)


def test_a_hook_callback_gets_the_registrys_arguments_not_the_requests(tmp_path) -> None:
    """`edit_user_profile` hands its callback the WP_User WordPress loaded; a shortcode's $atts are content."""
    from openultrasast.mapping import analyze_entry_points
    from openultrasast.model import scan
    from openultrasast.model.regions import regions_for
    from openultrasast.preprocess import build_file_target, enumerate_source_files

    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('edit_user_profile', 'show_history');\n"
        'function show_history($user) { global $wpdb; return $wpdb->get_var("SELECT 1 WHERE id = \'" . $user->ID . "\'"); }\n'
        "add_shortcode('box', 'render_box');\n"
        "function render_box($atts) { global $wpdb; return $wpdb->get_var(\"SELECT 1 WHERE n = '\" . $atts['n'] . \"'\"); }\n"
    )
    files = enumerate_source_files(tmp_path)
    targets = [build_file_target(tmp_path, p) for p in files]
    entries = analyze_entry_points(tmp_path, targets)
    assert {e.function_name: e.registered_by for e in entries if e.registered_by} == {
        "show_history": "add_action",
        "render_box": "add_shortcode",
    }
    regions = {r.function: r for r in regions_for(entries, targets)}
    assert regions["show_history"].entry_registry == "add_action"
    assert not scan._parameters_are_input(regions["show_history"])
    assert scan._parameters_are_input(regions["render_box"])
    # A route that did not come from a registry keeps its parameters as input.
    route = dataclasses.replace(regions["show_history"], entry_registry="", entry_kind="route")
    assert scan._parameters_are_input(route)


def test_every_callback_of_one_rest_registration_is_a_route(tmp_path) -> None:
    """PMPro registers a GET and a POST handler in one `register_rest_route`; taking the first callback left
    the writer an ordinary function, so its `$request` was no source."""
    from openultrasast.mapping import analyze_entry_points
    from openultrasast.preprocess import build_file_target, enumerate_source_files

    (tmp_path / "rest.php").write_text(
        "<?php\nclass Routes {\n  function register() {\n"
        "    register_rest_route( $ns, '/code',\n    array(\n"
        "      array( 'methods' => 'GET', 'callback' => array( $this, 'read_code' ),\n"
        "        'permission_callback' => array( $this, 'can_read' ) ),\n"
        "      array( 'methods' => 'POST', 'callback' => array( $this, 'write_code' ), 'permission_callback' => '__return_true' ),\n"
        "    ));\n  }\n"
        "  function read_code($request) { return 1; }\n  function write_code($request) { return 2; }\n}\n"
    )
    files = enumerate_source_files(tmp_path)
    entries = analyze_entry_points(tmp_path, [build_file_target(tmp_path, p) for p in files])
    routes = {e.function_name: e for e in entries if e.name == "wp:rest_route"}
    assert set(routes) == {"read_code", "write_code"}
    # Each endpoint keeps its OWN permission callback.
    assert routes["write_code"].access_level == "public" and routes["read_code"].access_level != "public"
