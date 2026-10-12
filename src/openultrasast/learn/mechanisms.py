"""Deterministic discharge proposals, never admitted facts.

The shared tree-sitter IR supplies function/call identity. Its CST supplies bounded
expression containment and structured if branches; loops, exceptions, alias writes,
and unmodelled expressions fail closed. Parameters and fact-table sources are
potential taint, as in learn.slice. A return is an output boundary only for
output_encoding (a proposal, not a claim that every return renders HTML).

Patterns use zero-based argument positions. Only >=2 independent repository
proposers survive. Each fold carries its own training evidence; global evidence
must never be used to admit a fact for a held-out fold. No fact table/store writes.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import Any

from ..model.specs import taint_specs
from ..plane.memory import MemoryStore, repo_key
from ..semantic.cst import _KIND, _walk, file_ir_from_tree
from ..semantic.extra import grammar_for
from ..semantic.facts import load_facts
from ..semantic.ir import FileIR, trailing_name
from ..semantic.taint import _call_matches, _source_in
from .examples import Example
from .folds import Fold, compile_split, folds_digest, outer_folds

RECORD = Path("benchmarks/measurements/2026-10-04-fix-mechanisms-mining/record.json")
SUPPORTED = frozenset({"python", "javascript", "typescript", "tsx", "php"})
_NUMBERED = re.compile(r"^\s*(\d+)(?:  (.*))?$")


@dataclass(frozen=True)
class Pair:
    id: str
    repository: str
    group: str
    language: str
    family: str
    vulnerable: str
    fixed: str
    source: str = "pairs"
    frameworks: tuple[str, ...] = ()
    package: str = ""
    example_ids: tuple[str, ...] = ()


@dataclass
class MiningResult:
    candidates: list[dict[str, Any]]
    record: dict[str, Any]


class Unsupported(ValueError):
    """A counted skip, never an empty successful analysis."""


def _text(node: Any) -> str:
    return bytes(node.text).decode("utf-8")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _parse(text: str, language: str) -> tuple[Any, FileIR]:
    if language not in SUPPORTED:
        raise Unsupported("unsupported_language")
    grammar = grammar_for(language)
    if grammar is None:
        raise Unsupported("grammar_unavailable")
    lines = text.split("\ndiff:\n", 1)[0].splitlines()
    matches = [_NUMBERED.match(line) for line in lines]
    if any(matches):
        if not all(matches) or len({m[1] for m in matches if m}) != len(lines):
            raise Unsupported("unparseable")
        lines = [(m[2] or "") for m in matches if m]
    code = dedent("\n".join(lines))
    if language == "php" and not code.lstrip().startswith("<?php"):
        code = "<?php\n" + code
    from tree_sitter import Parser

    tree = Parser(grammar).parse(code.encode())
    ir = file_ir_from_tree(path="excerpt", text=code, language=language, tree=tree)
    if not ir.parse_ok or not code.strip():
        raise Unsupported("unparseable")
    return tree, ir


def _callee(name: str, variables: set[str]) -> str:
    name = name.strip().replace("->", ".").replace("::", ".")
    if "(" in name or not re.fullmatch(r"[\w$\\]+(?:\.[\w$]+)*", name):
        raise Unsupported("unsupported_shape")
    if name.split(".")[0] in variables or name.startswith("$"):
        if "." not in name:
            raise Unsupported("unsupported_shape")
        return trailing_name(name)
    return name.lstrip("\\")


@dataclass(frozen=True)
class Flow:
    roots: frozenset[str] = frozenset()
    patterns: frozenset[str] = frozenset()


def _union(flows: Sequence[Flow]) -> Flow:
    return Flow(frozenset().union(*(f.roots for f in flows)), frozenset().union(*(f.patterns for f in flows)))


@dataclass
class Site:
    callee: str
    flow: Flow
    arguments: dict[str, Any]
    slot: tuple[int, ...]
    guards: frozenset[str]


class Analysis:
    """Small structured walker over the shipped IR's call sites, not a new parser."""

    def __init__(self, language: str, family: str, function: Any, ir: Any) -> None:
        self.language, self.family = language, family
        self.kinds = _KIND[language]
        self.calls = {call.order: call for call in ir.calls}
        self.variables = set(ir.params) | {bind.name for bind in ir.binds}
        self.states = {name: Flow(frozenset({name})) for name in ir.params}
        self.sites: list[Site] = []
        self.facts = load_facts().for_language(language)
        self.spec = taint_specs(language=language).get(family)
        self.function = function

    def name(self, node: Any) -> str:
        call = self.calls.get(node.end_byte)
        if call is None:
            raise Unsupported("unsupported_shape")
        return _callee(call.name, self.variables)

    def args(self, node: Any) -> list[Any]:
        args = node.child_by_field_name("arguments")
        if args is None:
            args = next((c for c in node.named_children if c.type in self.kinds["args"]), None)
        return list(args.named_children) if args else []

    def expr(self, node: Any, slot: tuple[int, ...], guards: frozenset[str]) -> Flow:
        kind = node.type
        children = list(node.named_children)
        if kind in {"identifier", "variable_name"}:
            return self.states.get(_text(node), Flow())
        if kind in {"string", "string_literal", "integer", "float", "number", "true", "false", "null", "none", "boolean"}:
            return Flow()
        if kind in self.kinds["call"]:
            name = self.name(node)
            args = self.args(node)
            values = [self.expr(arg, slot + (i,), guards) for i, arg in enumerate(args)]
            flow = _union(values)
            if _source_in(self.calls[node.end_byte].name + "(", self.facts):
                flow = Flow(flow.roots | {"<source:" + name + ">"}, flow.patterns)
            arguments = _arguments(args)
            self.sites.append(Site(name, flow, arguments, slot, guards))
            added = {_canonical({"callee": name, "argument": i}) for i, value in enumerate(values) if value.roots}
            return Flow(flow.roots, flow.patterns | added)
        if kind in {"attribute", "member_expression", "subscript", "subscript_expression", "member_access_expression"}:
            flow = self.expr(children[0], slot, guards) if children else Flow()
            if _source_in(_text(node), self.facts):
                return Flow(flow.roots | {"<source>"}, flow.patterns)
            return flow
        if kind in {"keyword_argument", "argument", "parenthesized_expression", "unary_expression", "not_operator"}:
            return self.expr(children[-1], slot, guards) if children else Flow()
        if kind in {
            "binary_expression",
            "binary_operator",
            "comparison_operator",
            "list",
            "tuple",
            "array",
            "array_creation_expression",
            "array_element_initializer",
            "pair",
            "dictionary",
            "object",
        }:
            return _union([self.expr(child, slot + (i,), guards) for i, child in enumerate(children)])
        if kind in {"property_identifier", "name", "comment", "string_content", "escape_sequence"}:
            return Flow()
        raise Unsupported("unsupported_shape")

    def predicate(self, node: Any, truth: bool) -> frozenset[str]:
        while node.type == "parenthesized_expression":
            node = node.named_children[0]
        if node.type in {"not_operator", "unary_expression"}:
            if not _text(node).lstrip().startswith(("not ", "!")):
                raise Unsupported("unsupported_shape")
            return self.predicate(node.named_children[-1], not truth)
        if node.type not in self.kinds["call"]:
            raise Unsupported("unsupported_shape")
        name = self.name(node)
        predicates = []
        for index, arg in enumerate(self.args(node)):
            # Evaluating a condition is not an output path or a sanitizer.
            value = self.expr(arg, (), frozenset())
            if value.roots:
                predicates.append(
                    _canonical(
                        {"callee": name, "argument": index, "predicate": "truthy" if truth else "falsy", "_roots": sorted(value.roots)}
                    )
                )
        return frozenset(predicates)

    def block(self, node: Any, prefix: tuple[int, ...] = (), guards: frozenset[str] = frozenset()) -> bool:
        children = list(node.named_children) if node.type in {"block", "statement_block", "compound_statement"} else [node]
        for index, statement in enumerate(children):
            slot = prefix + (index,)
            kind = statement.type
            if kind in self.kinds["function"] or kind in {"comment", "pass_statement"}:
                continue
            if kind == "if_statement":
                condition = statement.child_by_field_name("condition")
                consequence = statement.child_by_field_name("consequence") or statement.child_by_field_name("body")
                alternative = statement.child_by_field_name("alternative")
                if condition is None or consequence is None or alternative is not None:
                    raise Unsupported("unsupported_shape")
                before = dict(self.states)
                yes, no = self.predicate(condition, True), self.predicate(condition, False)
                exits = self.block(consequence, slot, guards | yes)
                # Branch writes need SSA/joins; no invented textual-order dataflow.
                if self.states != before:
                    raise Unsupported("unsupported_shape")
                if exits:
                    guards |= no
                continue
            if kind in {"return_statement", "echo_statement", "throw_statement", "raise_statement"}:
                flow = _union([self.expr(c, slot, guards) for c in statement.named_children])
                if self.family == "output_encoding" and kind in {"return_statement", "echo_statement"}:
                    self.sites.append(Site("<return>" if kind == "return_statement" else "echo", flow, {}, slot, guards))
                if kind != "echo_statement":
                    return True
                continue
            if kind in {"lexical_declaration", "variable_declaration", "expression_statement"}:
                if self.block(statement.named_children[0], slot, guards):
                    return True
                if len(statement.named_children) != 1:
                    raise Unsupported("unsupported_shape")
                continue
            if kind in self.kinds["assign"]:
                left = statement.child_by_field_name("left") or statement.child_by_field_name("name")
                right = statement.child_by_field_name("right") or statement.child_by_field_name("value")
                if left is None or right is None or left.type not in {"identifier", "variable_name"}:
                    raise Unsupported("unsupported_shape")
                if kind.startswith("augmented"):
                    raise Unsupported("unsupported_shape")
                self.states[_text(left)] = self.expr(right, slot, guards)
                continue
            if kind in self.kinds["call"]:
                self.expr(statement, slot, guards)
                if self.name(statement) in {"abort", "exit", "die"}:
                    return True
                continue
            raise Unsupported("unsupported_shape")
        return False

    def run(self) -> list[Site]:
        body = self.function.child_by_field_name("body")
        if body is None:
            raise Unsupported("unsupported_shape")
        self.block(body)
        return self.sites

    def sink(self, site: Site) -> bool:
        return (self.family == "output_encoding" and site.callee in {"<return>", "echo"}) or bool(
            self.spec and any(_call_matches(site.callee, sink) for sink in self.spec.sinks)
        )


def _literal(node: Any) -> tuple[bool, Any]:
    text = _text(node)
    if text.lower() in {"true", "false", "null", "none"}:
        return True, {"true": True, "false": False, "null": None, "none": None}[text.lower()]
    if node.type not in {"string", "string_literal", "integer", "number", "float"}:
        return False, None
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return False, None
    return (True, value) if isinstance(value, str | int | float | bool) else (False, None)


def _arguments(args: list[Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for position, original in enumerate(args):
        arg = original.named_children[-1] if original.type == "argument" else original
        key = ""
        if arg.type == "keyword_argument":
            key = _text(arg.named_children[0])
            arg = arg.named_children[-1]
        ok, value = _literal(arg)
        if ok:
            result[_canonical({"key": key} if key else {"argument": position, "key": key})] = value
        elif arg.type in {"array_creation_expression", "dictionary", "object"}:
            for entry in arg.named_children:
                if entry.type not in {"array_element_initializer", "pair"} or len(entry.named_children) != 2:
                    continue
                valid_key, key_value = _literal(entry.named_children[0])
                valid_value, value = _literal(entry.named_children[-1])
                if valid_key and isinstance(key_value, str) and valid_value:
                    result[_canonical({"argument": position, "key": key_value})] = value
    return result


def _functions(tree: Any, ir: FileIR) -> dict[str, tuple[Any, Any]]:
    nodes = [n for n in _walk(tree.root_node) if n.type in _KIND[ir.language]["function"]]
    functions = list(ir.functions[1:])
    if not functions or len({f.name for f in functions}) != len(functions):
        raise Unsupported("unsupported_shape")
    return {f.name: (node, f) for node, f in zip(nodes, functions, strict=True)}


def _proposals(before: Analysis, after: Analysis) -> set[tuple[str, str]]:
    old, new = before.run(), after.run()
    result: set[tuple[str, str]] = set()
    old_sinks = [s for s in old if before.sink(s) and s.flow.roots]
    for sink in old_sinks:
        # Ambiguous repeated operations are not aligned by textual similarity.
        matches = [s for s in new if s.callee == sink.callee and s.flow.roots == sink.flow.roots]
        if len([s for s in old_sinks if s.callee == sink.callee]) != 1:
            raise Unsupported("ambiguous_sink")
        if len(matches) == 1:
            fixed = matches[0]
            result.update(("sanitizer", p) for p in fixed.flow.patterns - sink.flow.patterns)
            # Only predicates involving a value on this sink's path are retained below.
            for encoded in fixed.guards - sink.guards:
                predicate = json.loads(encoded)
                roots = set(predicate.pop("_roots"))
                if roots & fixed.flow.roots:
                    result.add(("guard", _canonical(predicate)))
            for key, value in fixed.arguments.items():
                if key not in sink.arguments or _canonical(sink.arguments[key]) != _canonical(value):
                    result.add(("safe_argument", _canonical({"callee": fixed.callee, **json.loads(key), "value": value})))
        elif not matches:
            replacements = [s for s in new if s.flow.roots == sink.flow.roots]
            if len(replacements) == 1 and replacements[0].slot == sink.slot and replacements[0].callee != sink.callee:
                result.add(("safe_alternative", _canonical({"callee": sink.callee, "replacement": replacements[0].callee})))
            elif replacements:
                raise Unsupported("ambiguous_sink")
        else:
            raise Unsupported("ambiguous_sink")
    return result


def _known(language: str, family: str, form: str, pattern: Mapping[str, Any]) -> bool:
    spec = taint_specs(language=language).get(family)
    if spec is None:
        return False
    name = str(pattern.get("replacement") if form == "safe_alternative" else pattern.get("callee"))
    if form == "guard" and pattern.get("predicate") != "truthy":
        return False
    names = spec.guards if form == "guard" else spec.sanitizers + spec.quoted_sanitizers
    # Shape sinks alone do not establish a particular keyword/literal restriction.
    return form != "safe_argument" and any(_call_matches(name, known) for known in names)


def _project_specific(pattern: Mapping[str, Any], pair: Pair, local: set[str]) -> str | None:
    names = [str(pattern.get(k, "")) for k in ("callee", "replacement")]
    if any(trailing_name(n) in local for n in names if n):
        return "local_definition"
    identities = [pair.repository.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1], pair.package]
    compact = re.sub(r"[^a-z0-9]", "", _canonical(pattern).lower())
    if any((token := re.sub(r"[^a-z0-9]", "", identity.lower())) and token in compact for identity in identities):
        return "project_identifier"
    return None


def mine_pairs(pairs: Sequence[Pair], *, folds: Sequence[Fold] = ()) -> MiningResult:
    skips: Counter[str] = Counter()
    parsed: dict[int, tuple[dict[str, tuple[Any, Any]], dict[str, tuple[Any, Any]]]] = {}
    definitions: dict[tuple[str, str], set[str]] = defaultdict(set)
    for index, pair in enumerate(pairs):
        try:
            before = _functions(*_parse(pair.vulnerable, pair.language))
            after = _functions(*_parse(pair.fixed, pair.language))
            parsed[index] = before, after
            definitions[repo_key(pair.repository), pair.language].update(before.keys() | after.keys())
        except Unsupported as exc:
            skips[str(exc)] += 1
    proposals: dict[tuple[str, str, str, str], list[Pair]] = defaultdict(list)
    mined = 0
    for index, (old, new) in parsed.items():
        pair = pairs[index]
        try:
            common = old.keys() & new.keys()
            if not common:
                raise Unsupported("unmatched_function")
            found: set[tuple[str, str]] = set()
            for name in sorted(common):
                found |= _proposals(Analysis(pair.language, pair.family, *old[name]), Analysis(pair.language, pair.family, *new[name]))
            mined += 1
            if not found:
                skips["no_supported_change"] += 1
            for form, pattern in sorted(found):
                reason = _project_specific(json.loads(pattern), pair, definitions[repo_key(pair.repository), pair.language])
                if reason:
                    skips[reason] += 1
                else:
                    proposals[pair.language, pair.family, form, pattern].append(pair)
        except Unsupported as exc:
            skips[str(exc)] += 1
    candidates = []
    cells: dict[str, dict[str, int]] = {}
    tops: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for (language, family, form, encoded), evidence in sorted(proposals.items()):
        repos = {_hash(repo_key(p.repository)) for p in evidence}
        pattern = json.loads(encoded)
        known = _known(language, family, form, pattern)
        cell = cells.setdefault(f"{language}/{family}/{form}", {"total": 0, "at_least_two_repositories": 0, "known": 0})
        cell["total"] += 1
        cell["known"] += int(known)
        if len(repos) < 2:
            skips["fewer_than_two_repositories"] += 1
            continue
        cell["at_least_two_repositories"] += 1
        candidate = {
            "language": language,
            "family": family,
            "form": form,
            "pattern": pattern,
            "known": known,
            "proposing_pairs": sorted({p.id for p in evidence}),
            "proposing_examples": {p.id: sorted(p.example_ids) for p in sorted(evidence, key=lambda p: p.id)},
            "repository_count": len(repos),
            "repository_ids": sorted(repos),
        }
        training = []
        for fold in folds:
            held_repos = {repo_key(p.repository) for p in pairs if p.group in fold.eval_groups}
            train = [
                p
                for p in evidence
                if p.group not in fold.eval_groups
                and repo_key(p.repository) not in held_repos
                and p.source != fold.held_source
                and (not fold.held_framework or fold.held_framework not in p.frameworks)
            ]
            train_repos = sorted({_hash(repo_key(p.repository)) for p in train})
            training.append(
                {
                    "fold": fold.name,
                    "repository_count": len(train_repos),
                    "repository_ids": train_repos,
                    "proposing_pairs": sorted({p.id for p in train}),
                    "supported": len(train_repos) >= 2,
                    "eligible": len(train_repos) >= 2 and not known and fold.status == "ok",
                }
            )
        candidate["folds"] = training
        candidates.append(candidate)
        tops[form].append({"language": language, "family": family, "pattern": pattern, "repository_count": len(repos)})
    return MiningResult(
        candidates,
        {
            "pairs_read": len(pairs),
            "pairs_mined": mined,
            "skips": dict(sorted(skips.items())),
            "candidates": cells,
            "top_patterns": {
                form: sorted(rows, key=lambda r: (-r["repository_count"], _canonical(r)))[:10] for form, rows in sorted(tops.items())
            },
        },
    )


def pairs_from_rows(
    rows: Sequence[Mapping[str, Any]], excerpt_text: Callable[[str], str | None], *, profile: str = "static"
) -> tuple[list[Pair], Counter[str], int]:
    """Never pair on repository group alone. Legacy rows use an unambiguous candidate.

    Explicit pair/source_ref keys take precedence; repeated revisions/profiles and
    missing sides are counted, not guessed. Delta rows duplicate pin evidence.
    """
    from .labels import load_sources

    allowed = {source.id for source in load_sources().sources}
    buckets: dict[tuple[str, str, str, str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    skips: Counter[str] = Counter()
    for row in rows:
        if row.get("profile", "static") != profile or row.get("unit", "pin") != "pin":
            continue
        source = str(row.get("source", ""))
        if source not in allowed or row.get("origin") == "user" or row.get("conditional"):
            skips["excluded_source"] += 1
            continue
        repo, group = str(row.get("repo") or ""), str(row.get("group") or "")
        candidate = str(row.get("candidate") or "")
        if not repo or not group or "/" not in repo or not candidate:
            skips["missing_pair_identity"] += 1
            continue
        explicit = str(row.get("pair_id") or row.get("pair") or row.get("source_ref") or "")
        identity = explicit or candidate
        key = (repo_key(repo), group, source, str(row.get("language", "")), str(row.get("family", "")), identity)
        buckets[key].append(row)
    pairs: list[Pair] = []
    for key, members in sorted(buckets.items()):
        sides = {label: [r for r in members if r.get("label") == label] for label in (0, 1)}
        if len(members) != 2 or any(len(side) != 1 for side in sides.values()):
            skips["incomplete_pair" if any(not s for s in sides.values()) else "ambiguous_pair"] += 1
            continue
        fixed, vulnerable = sides[0][0], sides[1][0]
        if any(r.get("pin_role", role) != role for r, role in ((fixed, "fixed"), (vulnerable, "vulnerable"))):
            skips["label_side_mismatch"] += 1
            continue
        texts = [excerpt_text(str(r.get("excerpt_sha") or "")) for r in (vulnerable, fixed)]
        if any(not text for text in texts):
            skips["unreadable_excerpt"] += 1
            continue
        repo, group, source, language, family, identity = key
        if not any(vulnerable.get(k) for k in ("pair_id", "pair", "source_ref")):
            identity = "legacy-" + _hash(_canonical(key))
        pairs.append(
            Pair(
                identity,
                repo,
                group,
                language,
                family,
                texts[0] or "",
                texts[1] or "",
                source,
                tuple(sorted(set(vulnerable.get("frameworks") or ()) | set(fixed.get("frameworks") or ()))),
                str(vulnerable.get("package") or ""),
                tuple(sorted(str(r["id"]) for r in members if r.get("id"))),
            )
        )
    return pairs, skips, len(buckets)


def mine_store(store: MemoryStore, *, profile: str = "static", spec_path: Path | None = None) -> MiningResult:
    from .compile import load_spec
    from .labels import load_sources

    rows = [r.row for r in store.rows(kind="example")]
    allowed = {source.id for source in load_sources().sources}
    examples = [
        Example.from_row(row)
        for row in rows
        if row.get("profile") == profile and row.get("source") in allowed and row.get("origin") != "user" and not row.get("conditional")
    ]
    spec = load_spec(spec_path) if spec_path else load_spec()
    split = compile_split(examples, fraction=float(spec["split"].get("compile_fraction", 0.25)), seed=spec.seed)
    folds = outer_folds(examples, seed=spec.seed, exclude=split.groups)
    read_bytes = 0
    blobs = 0

    def excerpt_text(sha: str) -> str | None:
        nonlocal read_bytes, blobs
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            return None
        data = store.get_blob("excerpts", sha)
        if data is None:
            return None
        read_bytes += len(data)
        blobs += 1
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    pairs, skips, pairs_read = pairs_from_rows(rows, excerpt_text, profile=profile)
    result = mine_pairs(pairs, folds=folds)
    combined = Counter(result.record["skips"]) + skips
    result.record.update(
        {
            "rows_read": len(rows),
            "pairs_read": pairs_read,
            "complete_pairs": len(pairs),
            "excerpt_blobs_read": blobs,
            "excerpt_bytes_read": read_bytes,
            "skips": dict(sorted(combined.items())),
            "folds_digest": folds_digest(split, folds),
            "compile_spec_sha256": spec.sha256,
            "fold_seed": spec.seed,
            "profile": profile,
            "status": "mined" if result.record["pairs_mined"] else "no_mineable_pairs",
        }
    )
    return result


def write_result(result: MiningResult, out: Path, *, root: Path, results: Path) -> None:
    """Counts-only checked-in record; candidate evidence must stay under results outside the repo."""
    out, root, results = out.resolve(), root.resolve(), results.resolve()
    if out.is_relative_to(root) or not out.is_relative_to(results):
        raise ValueError("--out must be under the results root and outside the repository")
    record = root / RECORD
    if not record.resolve().is_relative_to(root):
        raise ValueError("measurement record must stay inside the repository")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(_canonical(candidate) + "\n" for candidate in result.candidates), encoding="utf-8")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps(result.record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
