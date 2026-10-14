"""One CST walker: tree-sitter nodes into FileIR. No per-language visitors."""

from __future__ import annotations

from typing import Any

from .ir import Bind, CallSite, FileIR, FunctionIR

_KIND = {
    "php": {
        "function": frozenset({"function_definition", "method_declaration", "anonymous_function", "arrow_function"}),
        "assign": frozenset({"assignment_expression", "augmented_assignment_expression"}),
        "call": frozenset(
            {"function_call_expression", "member_call_expression", "scoped_call_expression", "nullsafe_member_call_expression"}
        ),
        "args": frozenset({"arguments"}),
        "string": frozenset({"string", "encapsed_string"}),
        "params": frozenset({"formal_parameters"}),
    },
    "python": {
        "function": frozenset({"function_definition"}),
        "assign": frozenset({"assignment", "augmented_assignment"}),
        "call": frozenset({"call"}),
        "args": frozenset({"argument_list", "arguments"}),
        "string": frozenset({"string"}),
        "params": frozenset({"parameters"}),
    },
    "javascript": {
        "function": frozenset({"function_declaration", "method_definition", "arrow_function", "function_expression"}),
        "assign": frozenset({"assignment_expression", "augmented_assignment_expression", "variable_declarator"}),
        "call": frozenset({"call_expression"}),
        "args": frozenset({"arguments"}),
        "string": frozenset({"string"}),
        "params": frozenset({"formal_parameters"}),
    },
    "c": {
        "function": frozenset({"function_definition"}),
        "assign": frozenset({"assignment_expression", "init_declarator"}),
        "call": frozenset({"call_expression"}),
        "args": frozenset({"argument_list"}),
        "string": frozenset({"string_literal"}),
        "params": frozenset({"parameter_list"}),
    },
    "java": {
        "function": frozenset({"method_declaration", "constructor_declaration"}),
        "assign": frozenset({"assignment_expression", "variable_declarator"}),
        "call": frozenset({"method_invocation"}),
        "args": frozenset({"argument_list"}),
        "string": frozenset({"string_literal"}),
        "params": frozenset({"formal_parameters"}),
    },
}
_KIND["cpp"] = _KIND["c"]
_KIND["typescript"] = _KIND["javascript"]
_KIND["tsx"] = _KIND["javascript"]

_CONST = frozenset(
    {
        "string",
        "string_literal",
        "integer",
        "number",
        "float",
        "true",
        "false",
        "null",
        "nil",
        "character_literal",
        "escape_sequence",
    }
)
_SEQUENCE = frozenset({"list", "tuple", "array", "array_creation_expression", "initializer_list"})


def parse_with_cst(path: str, text: str, language: str) -> FileIR | None:
    from .extra import grammar_for

    grammar = grammar_for(_grammar_language(language, path))
    if grammar is None:
        return None
    try:
        from tree_sitter import Parser

        parser = Parser(grammar)
        tree = parser.parse(text.encode())
    except Exception:
        return FileIR(path=path, language=language, engine="tree-sitter", functions=(), parse_ok=False, reason="parse_failed")
    return file_ir_from_tree(path=path, text=text, language=language, tree=tree)


def parse_function_nodes(path: str, text: str, language: str) -> list[Any]:
    """The syntax nodes of every function in the file, in the order `file_ir_from_tree` lists them.

    The control-flow builder needs the statements of one function, which the FileIR does not keep. An unparsable
    file or a language without a grammar yields no nodes.
    """
    from .extra import grammar_for

    kinds = _KIND.get(language)
    grammar = grammar_for(_grammar_language(language, path))
    if grammar is None or kinds is None:
        return []
    try:
        from tree_sitter import Parser

        tree = Parser(grammar).parse(text.encode())
    except Exception:
        return []
    if bool(getattr(tree.root_node, "has_error", False)):
        return []
    return [node for node in _walk(tree.root_node) if node.type in kinds["function"]]


def _grammar_language(language: str, path: str) -> str:
    """TypeScript ships two grammars; a `.tsx` file needs the JSX-aware one. The FileIR keeps the language it was given."""
    return "tsx" if language == "typescript" and path.endswith(".tsx") else language


def file_ir_from_tree(*, path: str, text: str, language: str, tree: Any) -> FileIR:
    del text
    root = tree.root_node
    if bool(getattr(root, "has_error", False)):
        return FileIR(path=path, language=language, engine="tree-sitter", functions=(), parse_ok=False, reason="parse_failed")
    kinds = _KIND.get(language)
    if kinds is None:
        return FileIR(path=path, language=language, engine="none", functions=(), parse_ok=False, reason="language_unsupported")
    functions: list[FunctionIR] = []
    module_binds, module_calls = _collect(root, kinds, skip=kinds["function"])
    functions.append(
        FunctionIR(
            name="<module>",
            params=(),
            start_line=_line(root),
            end_line=_end_line(root),
            binds=tuple(module_binds),
            calls=tuple(module_calls),
        )
    )
    for node in _walk(root):
        if node.type not in kinds["function"]:
            continue
        binds, calls = _collect(node, kinds, skip=kinds["function"])
        functions.append(
            FunctionIR(
                name=_function_name(node),
                params=_params(node, kinds),
                start_line=_line(node),
                end_line=_end_line(node),
                binds=tuple(binds),
                calls=tuple(calls),
            )
        )
    return FileIR(path=path, language=language, engine="tree-sitter", functions=tuple(functions), parse_ok=True)


def _collect(node: Any, kinds: dict[str, frozenset[str]], *, skip: frozenset[str]) -> tuple[list[Bind], list[CallSite]]:
    binds: list[Bind] = []
    calls: list[CallSite] = []
    for child in _walk(node, skip=skip):
        if child.type in kinds["assign"]:
            bind = _bind(child, kinds)
            if bind is not None:
                binds.append(bind)
        if child.type in kinds["call"]:
            calls.append(_call(child, kinds))
    return binds, calls


def _walk(node: Any, *, skip: frozenset[str] | None = None) -> list[Any]:
    found: list[Any] = [node]
    for child in getattr(node, "named_children", ()) or ():
        if skip is not None and child.type in skip:
            continue
        found.extend(_walk(child, skip=skip))
    return found


def _bind(node: Any, kinds: dict[str, frozenset[str]]) -> Bind | None:
    children = list(getattr(node, "named_children", ()) or ())
    if not children:
        return None
    name_node = children[0]
    value_node = children[-1] if len(children) > 1 else None
    name = _left_name(name_node)
    if not name:
        return None
    value_text = _text(value_node) if value_node is not None else ""
    augmented = node.type in {"augmented_assignment", "augmented_assignment_expression"}
    names = _identifiers(value_node) if value_node is not None else ()
    if augmented:
        names = (name, *names)
    return Bind(
        name=name,
        order=int(node.end_byte),
        line=_line(node),
        value_text=value_text,
        is_constant=not augmented and _is_constant(value_node, kinds) if value_node is not None else False,
        names=names,
        call_name=_call_name(value_node, kinds) if value_node is not None and value_node.type in kinds["call"] else None,
    )


def _call(node: Any, kinds: dict[str, frozenset[str]]) -> CallSite:
    args_node = next((child for child in getattr(node, "named_children", ()) or () if child.type in kinds["args"]), None)
    arg_nodes = list(getattr(args_node, "named_children", ()) or ()) if args_node is not None else []
    # PHP wraps positional and named argument values in an `argument` node.
    arg_nodes = [arg.named_children[-1] if arg.type == "argument" and arg.named_children else arg for arg in arg_nodes]
    extra = len(arg_nodes) >= 2 and arg_nodes[1].type in _SEQUENCE
    return CallSite(
        order=int(node.end_byte),
        name=_callee_name(node, args_node),
        line=_line(node),
        arg_texts=tuple(_text(arg) for arg in arg_nodes),
        arg_is_constant=tuple(_is_constant(arg, kinds) for arg in arg_nodes),
        arg_names=tuple(_identifiers(arg) for arg in arg_nodes),
        extra_arg_is_sequence=extra,
    )


def _callee_name(node: Any, args_node: Any) -> str:
    if node.type in _KIND["php"]["call"]:
        callee = node.child_by_field_name("name") or node.child_by_field_name("function")
        if callee is not None:
            return _text(callee).rsplit("\\", 1)[-1]
    idents = [
        _text(child)
        for child in getattr(node, "named_children", ()) or ()
        if child is not args_node and child.type in {"identifier", "property_identifier"}
    ]
    if idents:
        return idents[-1]
    for child in getattr(node, "named_children", ()) or ():
        if child is not args_node:
            text = _text(child)
            if text:
                return text.split("(")[0]
    return _text(node).split("(")[0]


def _call_name(node: Any, kinds: dict[str, frozenset[str]]) -> str | None:
    if node.type in kinds["call"]:
        args_node = next((child for child in getattr(node, "named_children", ()) or () if child.type in kinds["args"]), None)
        return _callee_name(node, args_node)
    return None


def _function_name(node: Any) -> str:
    for child in getattr(node, "named_children", ()) or ():
        if child.type in {"identifier", "name"}:
            return _text(child)
        if child.type == "function_declarator":
            for grandchild in getattr(child, "named_children", ()) or ():
                if grandchild.type == "identifier":
                    return _text(grandchild)
    return "<anon>"


def _params(node: Any, kinds: dict[str, frozenset[str]]) -> tuple[str, ...]:
    parameter = node.child_by_field_name("parameter")
    if parameter is not None:
        return _identifiers(parameter)
    for child in _walk(node, skip=frozenset()):
        if child.type in kinds["params"]:
            if any(param.type in {"formal_parameter", "spread_parameter", "receiver_parameter"} for param in child.named_children):
                # Annotations such as `@QueryParameter` are identifiers too; keep the declared names only.
                return tuple(name for param in child.named_children if (name := _java_parameter_name(param)))
            if any(
                param.type in {"simple_parameter", "variadic_parameter", "property_promotion_parameter"} for param in child.named_children
            ):
                return tuple(_text(name) for param in child.named_children if (name := param.child_by_field_name("name")) is not None)
            return _identifiers(child)
        if child.type == "function_declarator":
            for grandchild in getattr(child, "named_children", ()) or ():
                if grandchild.type in kinds["params"]:
                    return _identifiers(grandchild)
    return ()


def _java_parameter_name(param: Any) -> str:
    if param.type == "formal_parameter":
        name = param.child_by_field_name("name")
        return _text(name) if name is not None else ""
    if param.type == "spread_parameter":
        declarator = next((child for child in param.named_children if child.type == "variable_declarator"), None)
        name = declarator.child_by_field_name("name") if declarator is not None else None
        return _text(name) if name is not None else ""
    return ""


def _left_name(node: Any) -> str:
    if node.type in {"identifier", "property_identifier", "variable_name"}:
        return _text(node)
    idents = _identifiers(node)
    return idents[0] if idents else ""


def _identifiers(node: Any) -> tuple[str, ...]:
    names: list[str] = []
    for child in _walk(node):
        # Keep PHP's sigil, matching source facts such as $_GET and $_POST. The
        # nested `name` node is not another variable (nor are class/type names).
        if child.type in {"identifier", "variable_name"}:
            names.append(_text(child))
    return tuple(names)


def _is_constant(node: Any, kinds: dict[str, frozenset[str]]) -> bool:
    if node.type == "encapsed_string":
        return all(child.type in {"string_content", "escape_sequence"} for child in node.named_children)
    if node.type in _CONST or node.type in kinds["string"]:
        return True
    if node.type not in {"binary_expression", "concatenated_string"}:
        return False
    children = list(getattr(node, "named_children", ()) or ())
    return bool(children) and all(_is_constant(child, kinds) for child in children)


def _text(node: Any) -> str:
    raw = getattr(node, "text", None)
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode(errors="ignore")
    return str(raw)


def _line(node: Any) -> int:
    point = getattr(node, "start_point", (0, 0))
    return int(point[0]) + 1


def _end_line(node: Any) -> int:
    point = getattr(node, "end_point", getattr(node, "start_point", (0, 0)))
    return int(point[0]) + 1
