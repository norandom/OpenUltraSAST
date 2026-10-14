"""A structural control-flow graph of one function, built from its syntax tree (access-control-prover, Req 10).

`FunctionCfg.from_cst(node, language)` turns the statements of one function into nodes and edges: statement
sequences, if and else branches, switch arms, loops with their back edges, try, catch and finally, return, throw,
break, continue and calls that end the process. Every statement a construct contains is a node; an expression is
never split. The graph answers three questions by line: does one line dominate another (every path from the entry
to the second passes the first), how does a guard on one line relate to an operation on another, and under which
branch conditions, loops and try blocks a line sits.

A construct the builder does not model (a labelled jump, a jump hidden inside an expression, a statement nested in
an expression) leaves the function without a graph: `available` is false and `reason` says why. The caller then
judges by order and records the degradation. A partial graph would be a wrong graph.

Exceptions are modelled conservatively: any statement inside a try body, and the try's start, may transfer to each
enclosing catch (or finally). That adds paths and never removes one, so it can only weaken dominance.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

LANGUAGES = frozenset({"java", "php", "python", "javascript", "typescript", "tsx"})
RELATIONS = ("all_paths", "some_paths", "none", "after")
EFFECTS = ("throws", "returns", "exits", "branches", "value_only")

_COMMENTS = frozenset({"comment", "line_comment", "block_comment", "text_interpolation", "php_tag", "empty_statement"})
_BLOCKS = frozenset({"block", "compound_statement", "statement_block", "colon_block", "constructor_body"})
_IF = frozenset({"if_statement"})
_WHILE = frozenset({"while_statement"})
_FOR = frozenset({"for_statement", "enhanced_for_statement", "for_in_statement", "foreach_statement"})
_DO = frozenset({"do_statement"})
_SWITCH = frozenset({"switch_statement", "switch_expression", "match_statement"})
_TRY = frozenset({"try_statement", "try_with_resources_statement"})
_HEADED = frozenset({"with_statement", "synchronized_statement"})
_LABELLED = frozenset({"labeled_statement"})
_RETURN = frozenset({"return_statement"})
_THROW = frozenset({"throw_statement", "raise_statement"})
_BREAK = frozenset({"break_statement"})
_CONTINUE = frozenset({"continue_statement"})
_EXIT_STATEMENT = frozenset({"exit_statement"})
_COMPOUND = _IF | _WHILE | _FOR | _DO | _TRY | _HEADED | _LABELLED | frozenset({"switch_statement", "match_statement"})
# Jumps that would leave an atomic statement without an edge for them.
_HIDDEN_JUMP = _RETURN | _THROW | _BREAK | _CONTINUE | _EXIT_STATEMENT | frozenset({"throw_expression", "yield_statement"})
# Nested functions and classes run elsewhere; their statements are not this function's control flow.
_NESTED = frozenset(
    {
        "function_definition",
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "generator_function",
        "method_declaration",
        "method_definition",
        "constructor_declaration",
        "arrow_function",
        "anonymous_function",
        "lambda_expression",
        "lambda",
        "class_definition",
        "class_declaration",
        "class_body",
        "class",
        "interface_declaration",
        "enum_declaration",
        "declaration_list",
        "anonymous_class",
    }
)
# Calls that end the process or abort the request; a call is matched by its last name segment.
_EXIT_CALLS = frozenset({"exit", "die", "_exit", "abort"})
_JUMPS = frozenset({"return", "throw", "break", "continue", "exit"})


class _Unmodelled(Exception):
    """A construct the builder does not model; the function gets no graph."""


@dataclass(frozen=True)
class ControlContext:
    """Where a line sits: the branch conditions above it in order, loops, try blocks and exception paths."""

    conditions: tuple[str, ...] = ()
    in_loop: bool = False
    in_try: bool = False
    catches: tuple[str, ...] = ()
    on_exception_path: bool = False


@dataclass
class _Node:
    kind: str  # entry, end, statement, branch, case, try, catch, finally, or a jump: return, throw, break, continue, exit
    start_line: int
    end_line: int
    start_byte: int
    context: ControlContext
    condition: str = ""
    located: bool = True  # False for synthetic nodes that no source line names


@dataclass
class FunctionCfg:
    """Nodes, normal and exceptional edges, and dominators of one function."""

    start_line: int
    end_line: int
    available: bool
    reason: str | None = None
    nodes: list[_Node] = field(default_factory=list)
    normal: list[set[int]] = field(default_factory=list)
    exceptional: list[set[int]] = field(default_factory=list)
    _dominators: dict[int, int] = field(default_factory=dict, repr=False)

    ENTRY = 0
    EXIT = 1

    @classmethod
    def from_cst(cls, node: Any, language: str) -> FunctionCfg:
        start, end = _line(node), _end_line(node)
        if language not in LANGUAGES:
            return cls(start, end, False, "no_control_flow_builder")
        builder = _Builder(start, end)
        try:
            builder.build(node)
        except _Unmodelled as error:
            return cls(start, end, False, str(error) or "unmodelled_construct")
        except RecursionError:
            return cls(start, end, False, "nesting_too_deep")
        cfg = cls(start, end, True, None, builder.nodes, builder.normal, builder.exceptional)
        cfg._dominators = _dominators(cfg)
        return cfg

    # Lines to nodes.

    def node_at(self, line: int) -> int | None:
        """The node a line names: the narrowest statement or condition covering it, the earliest on a tie.

        A line after the function's last line names the exit, so a handler measured at its end is judged at the exit.
        """
        if not self.available:
            return None
        if line > self.end_line:
            return self.EXIT
        best: tuple[int, int, int] | None = None
        for index, node in enumerate(self.nodes):
            if not node.located or not node.start_line <= line <= node.end_line:
                continue
            key = (node.end_line - node.start_line, node.start_byte, index)
            if best is None or key < best:
                best = key
        return best[2] if best is not None else None

    # Questions by line.

    def dominates(self, a_line: int, b_line: int) -> bool:
        a, b = self.node_at(a_line), self.node_at(b_line)
        return a is not None and b is not None and self._dominates(a, b)

    def relation(self, guard_line: int, operation_line: int) -> str | None:
        """`all_paths`, `some_paths`, `none` or `after`; None when a line names no node."""
        guard, operation = self.node_at(guard_line), self.node_at(operation_line)
        if guard is None or operation is None:
            return None
        if guard_line > operation_line:
            return "after"
        if self._dominates(guard, operation):
            return "all_paths"
        if guard in self._dominators and self._reaches({guard}, operation, avoid=frozenset()):
            return "some_paths"
        return "none"

    def effect(self, guard_line: int, operation_line: int, *, throwing: bool) -> str | None:
        """What happens to the operation when the guard fails: `throws`, `returns`, `exits`, `branches` or `value_only`.

        A guard in a branch condition counts when the operation cannot be reached from one arm of that branch; the
        arm's own exit names the effect, and an arm that simply does not hold the operation is `branches`. A guard
        whose value is assigned counts through a later branch on that variable which lies between it and the
        operation. Otherwise a throwing guard (`throwing`) is `throws` and anything else is `value_only`.
        """
        guard, operation = self.node_at(guard_line), self.node_at(operation_line)
        if guard is None or operation is None:
            return None
        found = self._branch_effect(guard, operation)
        if found is None:
            variable = _assigned_name(self.nodes[guard].condition)
            if variable:
                pattern = re.compile(r"(?<![\w$])" + re.escape(variable) + r"(?![\w$])")
                for index, node in enumerate(self.nodes):
                    if (
                        node.kind == "branch"
                        and index != guard
                        and pattern.search(node.condition)
                        and self._dominates(guard, index)
                        and self._dominates(index, operation)
                    ):
                        found = self._branch_effect(index, operation)
                        if found is not None:
                            break
        if found is not None:
            return found
        return "throws" if throwing else "value_only"

    def context(self, line: int) -> ControlContext:
        node = self.node_at(line)
        return self.nodes[node].context if node is not None else ControlContext()

    # Graph internals.

    def _dominates(self, a: int, b: int) -> bool:
        mask = self._dominators.get(b)
        return mask is not None and bool(mask >> a & 1)

    def _successors(self, node: int) -> set[int]:
        return self.normal[node] | self.exceptional[node]

    def _reaches(self, starts: set[int], target: int, *, avoid: frozenset[int]) -> bool:
        seen: set[int] = set()
        stack = [node for node in starts if node not in avoid]
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(next_node for next_node in self._successors(node) if next_node not in avoid and next_node not in seen)
        return False

    def _branch_effect(self, branch: int, operation: int) -> str | None:
        arms = sorted(self.normal[branch])
        if self.nodes[branch].kind != "branch" or len(arms) < 2 or branch == operation:
            return None
        avoid = frozenset({branch})
        failing = [arm for arm in arms if not self._reaches({arm}, operation, avoid=avoid)]
        passing = [arm for arm in arms if arm not in failing]
        if not failing or not passing:
            return None
        jumps, falls = self._arm_ends(failing[0], avoid)
        if falls or not jumps:
            # The failing arm carries on without the operation: the operation lies only inside the passing branch.
            return "branches"
        if jumps == {"throw"}:
            return "throws"
        if jumps & {"exit", "break", "continue"}:
            return "exits"
        return "returns"

    def _arm_ends(self, start: int, avoid: frozenset[int]) -> tuple[set[str], bool]:
        """The jumps the arm ends in along normal edges, and whether it reaches the function's end without one."""
        jumps: set[str] = set()
        falls = False
        seen: set[int] = set()
        stack = [start]
        while stack:
            node = stack.pop()
            if node in seen or node in avoid:
                continue
            seen.add(node)
            kind = self.nodes[node].kind
            if kind in _JUMPS:
                jumps.add(kind)
                continue
            if node == self.EXIT:
                falls = True
                continue
            stack.extend(self.normal[node])
        return jumps, falls


def _dominators(cfg: FunctionCfg) -> dict[int, int]:
    """Dominator sets as bit masks over the nodes reachable from the entry (iterative data flow)."""
    order: list[int] = []
    seen: set[int] = set()
    stack: list[tuple[int, bool]] = [(FunctionCfg.ENTRY, False)]
    while stack:
        node, done = stack.pop()
        if done:
            order.append(node)
            continue
        if node in seen:
            continue
        seen.add(node)
        stack.append((node, True))
        for successor in sorted(cfg._successors(node), reverse=True):
            if successor not in seen:
                stack.append((successor, False))
    order.reverse()
    predecessors: dict[int, list[int]] = {node: [] for node in order}
    for node in order:
        for successor in cfg._successors(node):
            if successor in predecessors:
                predecessors[successor].append(node)
    everything = 0
    for node in order:
        everything |= 1 << node
    dom = {node: everything for node in order}
    dom[FunctionCfg.ENTRY] = 1 << FunctionCfg.ENTRY
    changed = True
    while changed:
        changed = False
        for node in order[1:]:
            mask = everything
            for predecessor in predecessors[node]:
                mask &= dom[predecessor]
            mask |= 1 << node
            if mask != dom[node]:
                dom[node] = mask
                changed = True
    return dom


@dataclass
class _Frame:
    kind: str  # loop or switch
    breaks: list[int] = field(default_factory=list)
    continues: list[int] = field(default_factory=list)


class _Builder:
    def __init__(self, start: int, end: int) -> None:
        self.nodes: list[_Node] = []
        self.normal: list[set[int]] = []
        self.exceptional: list[set[int]] = []
        self.frames: list[_Frame] = []
        self.handlers: list[list[int]] = []
        self.conditions: list[str] = []
        self.loops = 0
        self.catches: list[str] = []
        self.tries = 0
        self.exception_paths = 0
        self._new("entry", start, start, -1, located=False)
        self._new("end", end, end, -1, located=False)

    # Node creation and edges.

    def _new(self, kind: str, start: int, end: int, start_byte: int, *, condition: str = "", located: bool = True) -> int:
        index = len(self.nodes)
        self.nodes.append(
            _Node(
                kind,
                start,
                end,
                start_byte,
                ControlContext(tuple(self.conditions), self.loops > 0, self.tries > 0, tuple(self.catches), self.exception_paths > 0),
                condition,
                located,
            )
        )
        self.normal.append(set())
        self.exceptional.append(set())
        if index > FunctionCfg.EXIT:
            for targets in self.handlers:
                self.exceptional[index].update(targets)
        return index

    def _node(self, kind: str, syntax: Any, preds: Sequence[int], *, condition: str = "") -> int:
        index = self._new(kind, _line(syntax), _end_line(syntax), int(syntax.start_byte), condition=condition)
        self._link(preds, index)
        return index

    def _link(self, preds: Sequence[int], target: int) -> None:
        for pred in preds:
            self.normal[pred].add(target)

    @contextmanager
    def _condition(self, text: str) -> Iterator[None]:
        self.conditions.append(text)
        try:
            yield
        finally:
            self.conditions.pop()

    # Construction.

    def build(self, function: Any) -> None:
        body = function.child_by_field_name("body")
        if body is None:
            self._link([FunctionCfg.ENTRY], FunctionCfg.EXIT)
            return
        out = self._statement(body, [FunctionCfg.ENTRY]) if body.type in _BLOCKS else self._simple(body, [FunctionCfg.ENTRY])
        self._link(out, FunctionCfg.EXIT)

    def _sequence(self, statements: Sequence[Any], preds: list[int]) -> list[int]:
        for statement in statements:
            preds = self._statement(statement, preds)
        return preds

    def _statement(self, node: Any, preds: list[int]) -> list[int]:
        kind = node.type
        if kind in _COMMENTS:
            return preds
        if kind in _BLOCKS:
            return self._sequence(_statements(node), preds)
        if kind in _IF:
            return self._if(node, preds)
        if kind in _WHILE or kind in _FOR:
            return self._loop(node, preds)
        if kind in _DO:
            return self._do(node, preds)
        if kind in _SWITCH:
            return self._switch(node, preds)
        if kind in _TRY:
            return self._try(node, preds)
        if kind in _HEADED:
            body = node.child_by_field_name("body")
            if body is None:
                raise _Unmodelled("unmodelled_construct")
            header_end = max(_line(node), _line(body) - 1)
            header = self._new("statement", _line(node), header_end, int(node.start_byte), condition=_header_text(node, body))
            self._link(preds, header)
            return self._statement(body, [header])
        if kind in _LABELLED:
            inner = [child for child in node.named_children if child.type not in {"identifier", "statement_identifier"}]
            return self._sequence(inner, preds)
        return self._simple(node, preds)

    def _simple(self, node: Any, preds: list[int]) -> list[int]:
        kind = node.type
        thrown = kind == "expression_statement" and _only_child(node) == "throw_expression"
        inner = _descendants(node.named_children[0]) if thrown else _descendants(node)
        if any(child.type in _HIDDEN_JUMP or child.type in _COMPOUND for child in inner):
            raise _Unmodelled("jump_inside_expression")
        if kind in _RETURN:
            self._link([self._node("return", node, preds)], FunctionCfg.EXIT)
            return []
        if kind in _THROW or thrown:
            index = self._node("throw", node, preds)
            if not self.handlers:
                self._link([index], FunctionCfg.EXIT)
            return []
        if kind in _BREAK or kind in _CONTINUE:
            if any(child.type not in _COMMENTS for child in node.named_children) and not _single_level(node):
                raise _Unmodelled("labelled_jump")
            frame = next((f for f in reversed(self.frames) if kind in _BREAK or f.kind == "loop"), None)
            if frame is None:
                raise _Unmodelled("jump_without_target")
            index = self._node("break" if kind in _BREAK else "continue", node, preds)
            (frame.breaks if kind in _BREAK else frame.continues).append(index)
            return []
        if kind in _EXIT_STATEMENT or _is_exit_call(node):
            self._link([self._node("exit", node, preds)], FunctionCfg.EXIT)
            return []
        if kind == "assert_statement":
            index = self._node("branch", node, preds, condition=_condition_text(node))
            failed = self._new("throw", _line(node), _line(node), int(node.start_byte), located=False)
            self.normal[index].add(failed)
            if not self.handlers:
                self._link([failed], FunctionCfg.EXIT)
            return [index]
        return [self._node("statement", node, preds, condition=_text(node)[:240])]

    def _branch(self, condition: Any, fallback: Any, preds: list[int]) -> tuple[int, str]:
        syntax = condition if condition is not None else fallback
        text = _condition_text(condition) if condition is not None else ""
        if condition is not None and any(child.type in _HIDDEN_JUMP or child.type in _COMPOUND for child in _descendants(condition)):
            raise _Unmodelled("jump_inside_expression")
        return self._node("branch", syntax, preds, condition=text), text

    def _if(self, node: Any, preds: list[int]) -> list[int]:
        condition = node.child_by_field_name("condition")
        then = node.child_by_field_name("consequence") or node.child_by_field_name("body")
        branch, text = self._branch(condition, node, preds)
        outs: list[int] = []
        with self._condition(text):
            outs.extend(self._statement(then, [branch]) if then is not None else [branch])
        rest = [branch]
        negated = [f"not ({text})"]
        for alternative in node.children_by_field_name("alternative"):
            pushed = list(negated)
            self.conditions.extend(pushed)
            try:
                if alternative.type in _IF:
                    outs.extend(self._if(alternative, rest))
                    rest = []
                elif alternative.type in {"elif_clause", "else_if_clause"}:
                    inner = alternative.child_by_field_name("condition")
                    body = alternative.child_by_field_name("consequence") or alternative.child_by_field_name("body")
                    inner_branch, inner_text = self._branch(inner, alternative, rest)
                    with self._condition(inner_text):
                        outs.extend(self._statement(body, [inner_branch]) if body is not None else [inner_branch])
                    rest = [inner_branch]
                    negated.append(f"not ({inner_text})")
                elif alternative.type == "else_clause":
                    body = alternative.child_by_field_name("body")
                    if body is None:
                        body = next((child for child in alternative.named_children if child.type not in _COMMENTS), None)
                    outs.extend(self._statement(body, rest) if body is not None else rest)
                    rest = []
                else:
                    # A grammar that names the else statement itself as the alternative.
                    outs.extend(self._statement(alternative, rest))
                    rest = []
            finally:
                del self.conditions[len(self.conditions) - len(pushed) :]
        return outs + rest

    def _loop(self, node: Any, preds: list[int]) -> list[int]:
        body = node.child_by_field_name("body")
        condition = node.child_by_field_name("condition")
        if body is None:
            raise _Unmodelled("unmodelled_construct")
        header_end = max(_line(node), _line(body) - 1)
        text = _condition_text(condition) if condition is not None and condition.type != "empty_statement" else _header_text(node, body)
        if condition is not None and any(child.type in _HIDDEN_JUMP or child.type in _COMPOUND for child in _descendants(condition)):
            raise _Unmodelled("jump_inside_expression")
        header = self._new("branch", _line(node), header_end, int(node.start_byte), condition=text)
        self._link(preds, header)
        frame = _Frame("loop")
        self.frames.append(frame)
        self.loops += 1
        try:
            with self._condition(text):
                out = self._statement(body, [header])
        finally:
            self.loops -= 1
            self.frames.pop()
        self._link(out + frame.continues, header)
        outs = [header]
        alternative = node.child_by_field_name("alternative")
        if alternative is not None:
            else_body = alternative.child_by_field_name("body")
            outs = self._statement(else_body, outs) if else_body is not None else outs
        return outs + frame.breaks

    def _do(self, node: Any, preds: list[int]) -> list[int]:
        body = node.child_by_field_name("body")
        condition = node.child_by_field_name("condition")
        if body is None or condition is None:
            raise _Unmodelled("unmodelled_construct")
        frame = _Frame("loop")
        self.frames.append(frame)
        self.loops += 1
        first = len(self.nodes)
        try:
            out = self._statement(body, preds)
        finally:
            self.loops -= 1
            self.frames.pop()
        branch, _ = self._branch(condition, node, out + frame.continues)
        self.normal[branch].add(first if first < branch else branch)
        return [branch, *frame.breaks]

    def _switch(self, node: Any, preds: list[int]) -> list[int]:
        subject = node.child_by_field_name("condition") or node.child_by_field_name("value") or node.child_by_field_name("subject")
        body = node.child_by_field_name("body")
        if body is None:
            raise _Unmodelled("unmodelled_construct")
        branch, subject_text = self._branch(subject, node, preds)
        frame = _Frame("switch")
        self.frames.append(frame)
        outs: list[int] = []
        falling: list[int] = []
        has_default = False
        try:
            for arm in body.named_children:
                if arm.type in _COMMENTS:
                    continue
                label, statements, default, falls_through = _arm(arm)
                has_default = has_default or default
                case = self._new("case", _line(arm), _line(arm), int(arm.start_byte), condition=label)
                self._link([branch], case)
                text = "default" if default else f"case {label} of {subject_text}"
                with self._condition(text):
                    if falls_through:
                        out = self._sequence(statements, [case, *falling])
                        falling = out
                    else:
                        outs.extend(self._sequence(statements, [case]))
        finally:
            self.frames.pop()
        return outs + falling + frame.breaks + ([] if has_default else [branch])

    def _try(self, node: Any, preds: list[int]) -> list[int]:
        body = node.child_by_field_name("body")
        if body is None:
            raise _Unmodelled("unmodelled_construct")
        clauses = [child for child in node.named_children if child.type in {"catch_clause", "except_clause", "except_group_clause"}]
        handler = node.child_by_field_name("handler")
        if handler is not None and handler not in clauses:
            clauses.append(handler)
        final = next((child for child in node.named_children if child.type == "finally_clause"), None)
        orelse = next((child for child in node.named_children if child.type == "else_clause"), None)
        start = self._new("try", _line(node), _line(node), int(node.start_byte))
        self._link(preds, start)
        entries = [self._new("catch", _line(clause), _line(clause), int(clause.start_byte)) for clause in clauses]
        final_entry = self._new("finally", _line(final), _line(final), int(final.start_byte)) if final is not None else None
        targets = entries or ([final_entry] if final_entry is not None else [])
        self.exceptional[start].update(targets)
        types = [_catch_type(clause) for clause in clauses]
        self.handlers.append(targets)
        self.tries += 1
        self.catches.extend(types)
        try:
            resources = node.child_by_field_name("resources")
            out = [start]
            if resources is not None:
                out = [self._node("statement", resources, out, condition=_text(resources))]
            out = self._statement(body, out)
        finally:
            del self.catches[len(self.catches) - len(types) :]
            self.tries -= 1
            self.handlers.pop()
        if orelse is not None:
            else_body = orelse.child_by_field_name("body")
            out = self._statement(else_body, out) if else_body is not None else out
        normal = list(out)
        if final_entry is not None:
            self.handlers.append([final_entry])
        self.exception_paths += 1
        try:
            for clause, entry in zip(clauses, entries, strict=True):
                clause_body = clause.child_by_field_name("body") or next(
                    (child for child in clause.named_children if child.type in _BLOCKS), None
                )
                normal.extend(self._statement(clause_body, [entry]) if clause_body is not None else [entry])
        finally:
            self.exception_paths -= 1
            if final_entry is not None:
                self.handlers.pop()
        if final_entry is None or final is None:
            return normal
        self._link(normal, final_entry)
        final_body = final.child_by_field_name("body") or next((child for child in final.named_children if child.type in _BLOCKS), None)
        final_out = self._statement(final_body, [final_entry]) if final_body is not None else [final_entry]
        # An exception that entered the finally block leaves it again towards the enclosing handler or the exit.
        for index in final_out:
            if self.handlers:
                for targets in self.handlers:
                    self.exceptional[index].update(targets)
            else:
                self.exceptional[index].add(FunctionCfg.EXIT)
        return final_out


def _arm(arm: Any) -> tuple[str, list[Any], bool, bool]:
    """Label text, statements, whether it is the default arm, and whether control falls into the next arm."""
    kind = arm.type
    named = [child for child in arm.named_children if child.type not in _COMMENTS]
    if kind == "switch_block_statement_group":
        labels = [child for child in named if child.type == "switch_label"]
        statements = [child for child in named if child.type != "switch_label"]
        return _label(labels), statements, any(_text(label).strip().startswith("default") for label in labels), True
    if kind == "switch_rule":
        labels = [child for child in named if child.type == "switch_label"]
        statements = [child for child in named if child.type != "switch_label"]
        return _label(labels), statements, any(_text(label).strip().startswith("default") for label in labels), False
    if kind in {"case_statement", "switch_case"}:
        value = arm.child_by_field_name("value") or (named[0] if named else None)
        statements = arm.children_by_field_name("body") if kind == "switch_case" else named[1:]
        return _text(value) if value is not None else "", list(statements), False, True
    if kind in {"default_statement", "switch_default"}:
        statements = arm.children_by_field_name("body") if kind == "switch_default" else named
        return "default", list(statements), True, True
    if kind == "case_clause":
        consequence = arm.child_by_field_name("consequence")
        patterns = [child for child in named if child != consequence]
        label = ", ".join(_flat(_text(child)) for child in patterns)
        default = len(patterns) == 1 and _text(patterns[0]).strip() == "_"
        return label, [consequence] if consequence is not None else [], default, False
    raise _Unmodelled("unmodelled_construct")


def _label(labels: Sequence[Any]) -> str:
    return ", ".join(_flat(re.sub(r"^\s*case\s+", "", _text(label)).rstrip(":").strip()) for label in labels)


def _catch_type(clause: Any) -> str:
    typed = clause.child_by_field_name("type")
    if typed is not None:
        return _flat(_text(typed))
    for child in clause.named_children:
        if child.type == "catch_formal_parameter":
            caught = next((item for item in child.named_children if item.type == "catch_type"), None)
            if caught is not None:
                return _flat(_text(caught))
    if clause.type in {"except_clause", "except_group_clause"}:
        value = clause.child_by_field_name("value")
        if value is None:
            value = next((child for child in clause.named_children if child.type not in _BLOCKS and child.type not in _COMMENTS), None)
        if value is not None:
            caught = value.named_children[0] if value.type == "as_pattern" and value.named_children else value
            return _flat(_text(caught))
    return "any"


def _statements(node: Any) -> list[Any]:
    return [child for child in node.named_children if child.type not in _COMMENTS]


def _descendants(node: Any) -> Iterator[Any]:
    for child in node.named_children:
        if child.type in _NESTED:
            continue
        yield child
        yield from _descendants(child)


def _only_child(node: Any) -> str:
    named = [child for child in node.named_children if child.type not in _COMMENTS]
    return named[0].type if len(named) == 1 else ""


def _single_level(node: Any) -> bool:
    """`break 1;` names the innermost target, as a bare `break` does."""
    named = [child for child in node.named_children if child.type not in _COMMENTS]
    return len(named) == 1 and named[0].type == "integer" and _text(named[0]).strip() == "1"


def _is_exit_call(node: Any) -> bool:
    if node.type != "expression_statement":
        return False
    named = [child for child in node.named_children if child.type not in _COMMENTS]
    if len(named) != 1 or named[0].type not in {"call", "call_expression", "method_invocation", "function_call_expression"}:
        return False
    callee = _text(named[0]).split("(", 1)[0]
    return re.split(r"[.\\:>-]+", callee.strip())[-1] in _EXIT_CALLS


def _condition_text(node: Any) -> str:
    while node.type == "parenthesized_expression" and len(node.named_children) == 1:
        node = node.named_children[0]
    if node.type == "assert_statement":
        named = [child for child in node.named_children if child.type not in _COMMENTS]
        return _flat(_text(named[0])) if named else ""
    return _flat(_text(node))


def _header_text(node: Any, body: Any) -> str:
    header = _text(node)[: max(0, int(body.start_byte) - int(node.start_byte))]
    return _flat(header.rstrip(" :{\n"))


def _assigned_name(text: str) -> str:
    """The variable a statement assigns, when it assigns one plain name."""
    match = re.match(r"^\s*(?:(?:final|const|let|var|auto)\s+)?(?:[\w<>\[\],.?]+\s+)?(\$?[A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)", text)
    return match.group(1) if match else ""


def _flat(text: str) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= 160 else flat[:157] + "..."


def _text(node: Any) -> str:
    raw = getattr(node, "text", None)
    if raw is None:
        return ""
    return raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)


def _line(node: Any) -> int:
    return int(node.start_point[0]) + 1


def _end_line(node: Any) -> int:
    return int(node.end_point[0]) + 1


__all__ = ["EFFECTS", "LANGUAGES", "RELATIONS", "ControlContext", "FunctionCfg"]
