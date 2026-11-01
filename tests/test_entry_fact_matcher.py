"""Authority-bearing structural matching for reviewed Express entry facts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from openultrasast.core import canonical, provenance
from openultrasast.core.factapply import FactApplicationError, apply_fact
from openultrasast.core.factpack import FactPackValidationError
from openultrasast.core.semantics import RelationKind, RelationStatus
from openultrasast.mapping.entry_fact_matcher import match_entry_fact
from openultrasast.mapping.entry_packs import load_installed_entry_fact_authority
from openultrasast.mapping.fact_authority import EntryFactAuthorityContext
from openultrasast.mapping.fact_match_store import FactMatchArtifactWriter


class _UnusedCustody:
    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        raise AssertionError(f"authority load read custody: {population_digest}")


class _LogsCustody:
    def __init__(
        self,
        logs: tuple[provenance.PopulationCustodyLog, ...],
        policy: provenance.PopulationCustodyPolicy,
    ) -> None:
        self._logs = {log.population_digest: log for log in logs}
        self._policy = policy

    def current_log(self, population_digest: str) -> provenance.PopulationCustodyLog:
        try:
            return self._logs[population_digest]
        except KeyError as exc:
            raise provenance.PopulationCustodyError("population custody log not found") from exc

    def append(self, request: provenance.PopulationUseRequest) -> provenance.PopulationUseReceipt:
        prior = self.current_log(request.population_digest)
        custodian = self._policy.reviewed_custodian_digests[0]
        receipt = provenance.record_population_use(request, prior, custodian, self._policy)
        self._logs[request.population_digest] = provenance.append_population_use(prior, receipt, self._policy)
        return receipt


def _authority() -> tuple[EntryFactAuthorityContext, str, _LogsCustody]:
    loaded = load_installed_entry_fact_authority(_UnusedCustody())
    bundle = loaded.bundle
    custodian = bundle.custody_policy.reviewed_custodian_digests[0]
    logs: dict[str, provenance.PopulationCustodyLog] = {}
    for lineage in bundle.lineages:
        for use in lineage.uses:
            prior = logs.setdefault(
                use.source_population_digest,
                provenance.empty_population_custody_log(use.source_population_digest, custodian),
            )
            request = provenance.PopulationUseRequest(
                use.source_population_digest,
                lineage.arm_id,
                use.purpose,
                use.labels_accessed,
                use.influenced_artifact_digest,
                prior.log_digest,
            )
            receipt = provenance.record_population_use(request, prior, custodian, bundle.custody_policy)
            assert receipt.receipt_digest == use.population_use_receipt_digest
            logs[use.source_population_digest] = provenance.append_population_use(prior, receipt, bundle.custody_policy)
    evaluation = canonical.content_digest("untouched-entry-matcher-evaluation")
    logs[evaluation] = provenance.empty_population_custody_log(evaluation, custodian)
    custody = _LogsCustody(tuple(logs.values()), bundle.custody_policy)
    return replace(loaded, custody=custody), evaluation, custody


def _writer(tmp_path: Path, context: EntryFactAuthorityContext) -> FactMatchArtifactWriter:
    return FactMatchArtifactWriter(
        tmp_path / "matches",
        context.bundle.review_policy.trusted_store_identities[0],
        canonical.content_digest("retain-entry-fact-match-tests"),
    )


def _source(tmp_path: Path, name: str, content: str) -> tuple[Path, str]:
    root = tmp_path / "repository"
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    assert path.stat().st_size > 0  # Prove the matcher instrument receives readable input.
    return root, name


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_complete_route_structure_persists_and_applies_declared_relation(
    tmp_path: Path,
    language: str,
    suffix: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/routes.{suffix}",
        'import express from "express";\n'
        "const app = express();\n"
        'app.get("/admin", adminHandler);\n'
        "function adminHandler(req, res) { res.sendStatus(204); }\n",
    )
    writer = _writer(tmp_path, context)

    results = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=writer,
        evaluation_population_digest=evaluation,
    )

    assert len(results) == 1
    result = results[0]
    assert result.decision.status is RelationStatus.COMPLETE
    assert tuple(observation.requirement_id for observation in result.match.observations) == (
        "qualified_target",
        "call_shape",
        "receiver",
        "arguments",
    )
    assert tuple((relation.kind, relation.role, relation.status) for relation in result.relations) == (
        (RelationKind.REGISTRATION, "entry_registration", RelationStatus.COMPLETE),
    )
    assert writer.resolver.resolve(result.match_reference).content
    assert all(writer.resolver.resolve(item.evidence).content for item in result.match.observations)


def test_factory_binding_applies_only_from_verified_express_import(tmp_path: Path) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        "src/app.js",
        'import express from "express";\nconst app = express();\n',
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language="javascript",
        fact_id="entry:express:express-app",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.COMPLETE
    assert tuple(item.observed for item in result.match.observations) == (
        "express",
        "factory_call",
        "application_instance_binding",
    )

    untrusted_root, untrusted_relative = _source(
        tmp_path,
        "untrusted/local.js",
        "function express() {}\nconst app = express();\n",
    )
    untrusted = match_entry_fact(
        repository_root=untrusted_root,
        relative_path=untrusted_relative,
        language="javascript",
        fact_id="entry:express:express-app",
        authority=context,
        writer=_writer(tmp_path / "untrusted", context),
        evaluation_population_digest=evaluation,
    )[0]
    assert untrusted.decision.status is RelationStatus.INCOMPLETE
    assert "missing_observation:binding" in untrusted.decision.reasons
    assert "express_binding_not_authoritative:express" in untrusted.structural_reasons


@pytest.mark.parametrize(
    "source,missing_reason,structural_reason",
    (
        (
            'app.get("/admin", adminHandler);\nfunction adminHandler(req, res) {}\n',
            "missing_observation:receiver",
            "receiver_binding_missing:app",
        ),
        (
            'import express from "express";\nconst app = express();\napp.get("/admin");\n',
            "missing_observation:arguments",
            "route_arguments_incomplete",
        ),
        (
            'import express from "express";\nconst app = express();\napp.get("/admin", adminHandler);\n',
            "missing_observation:arguments",
            "handler_binding_missing:adminHandler",
        ),
    ),
)
def test_name_only_and_partial_structure_cannot_complete(
    tmp_path: Path,
    source: str,
    missing_reason: str,
    structural_reason: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(tmp_path, "src/routes.js", source)

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language="javascript",
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.INCOMPLETE
    assert missing_reason in result.decision.reasons
    assert structural_reason in result.structural_reasons
    assert all(relation.status is not RelationStatus.COMPLETE for relation in result.relations)


def test_ambiguous_receiver_bindings_are_unresolved(tmp_path: Path) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        "src/routes.js",
        'import express from "express";\n'
        "const app = express();\n"
        "const app = express.Router();\n"
        'app.get("/admin", adminHandler);\n'
        "function adminHandler(req, res) {}\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language="javascript",
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.UNRESOLVED
    assert "duplicate_observation:receiver" in result.decision.reasons
    assert "conflicting_observation:receiver" in result.decision.reasons
    assert "receiver_binding_ambiguous:app" in result.structural_reasons


def test_substituted_match_reference_is_refused_by_core(tmp_path: Path) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        "src/routes.js",
        'import express from "express";\nconst app = express();\napp.get("/admin", adminHandler);\nfunction adminHandler(req, res) {}\n',
    )
    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language="javascript",
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    substituted = replace(result.match_reference, storage_receipt_digest="f" * 64)
    with pytest.raises(FactApplicationError, match="match reference cannot be validated"):
        apply_fact(
            result.pack,
            result.match.fact_id,
            result.match,
            substituted,
            context.bundle.contract,
            evaluation,
            context.bundle.lineages,
            context.custody,
            context.bundle.custody_policy,
            context.bundle.review_policy,
            result.resolver,
        )


def test_current_same_population_label_influence_cannot_complete(tmp_path: Path) -> None:
    context, _, custody = _authority()
    matcher_lineage = next(
        item for item in context.bundle.lineages if item.manifest_digest == context.bundle.matcher_lineage_manifest_digest
    )
    population = matcher_lineage.uses[0].source_population_digest
    current = custody.current_log(population)
    custody.append(
        provenance.PopulationUseRequest(
            population,
            matcher_lineage.arm_id,
            provenance.LineagePurpose.MATCHING_BEHAVIOR,
            True,
            context.bundle.matcher_behavior_digest,
            current.log_digest,
        )
    )
    root, relative = _source(
        tmp_path,
        "src/routes.js",
        'import express from "express";\nconst app = express();\napp.get("/admin", adminHandler);\nfunction adminHandler(req, res) {}\n',
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language="javascript",
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=population,
    )[0]

    assert result.decision.status is RelationStatus.UNRESOLVED
    assert f"protected_population_labels:{population}" in result.decision.reasons
    assert all(relation.status is not RelationStatus.COMPLETE for relation in result.relations)


def test_current_same_population_fact_label_influence_is_refused(tmp_path: Path) -> None:
    context, _, custody = _authority()
    pack = next(item for item in context.bundle.packs if item.language == "javascript")
    fact_lineage = next(item for item in context.bundle.lineages if item.subject_digest == pack.normalized_content_digest)
    population = fact_lineage.uses[0].source_population_digest
    current = custody.current_log(population)
    custody.append(
        provenance.PopulationUseRequest(
            population,
            fact_lineage.arm_id,
            provenance.LineagePurpose.SEMANTIC_FACT,
            True,
            pack.normalized_content_digest,
            current.log_digest,
        )
    )
    root, relative = _source(
        tmp_path,
        "src/routes.js",
        'import express from "express";\nconst app = express();\napp.get("/admin", adminHandler);\nfunction adminHandler(req, res) {}\n',
    )

    with pytest.raises(FactPackValidationError, match="semantic fact lineage is contaminated.*protected_population_labels"):
        match_entry_fact(
            repository_root=root,
            relative_path=relative,
            language="javascript",
            fact_id="entry:express:app-route:get",
            authority=context,
            writer=_writer(tmp_path, context),
            evaluation_population_digest=population,
        )


def test_matcher_refuses_empty_unreadable_or_outside_source(tmp_path: Path) -> None:
    context, evaluation, _ = _authority()
    root = tmp_path / "repository"
    root.mkdir()
    (root / "empty.js").touch()

    for relative in ("empty.js", "missing.js", "../outside.js"):
        with pytest.raises(ValueError, match="repository source"):
            match_entry_fact(
                repository_root=root,
                relative_path=relative,
                language="javascript",
                fact_id="entry:express:app-route:get",
                authority=context,
                writer=_writer(tmp_path, context),
                evaluation_population_digest=evaluation,
            )


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_function_local_require_does_not_authorize_top_level_local_express(
    tmp_path: Path,
    language: str,
    suffix: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/local.{suffix}",
        "function unrelated() { const express = require('express'); return express; }\n"
        "function express() {}\n"
        "const app = express();\n"
        "function handler(req, res) {}\n"
        "app.get('/x', handler);\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.INCOMPLETE
    assert "express_binding_not_authoritative:express" in result.structural_reasons


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_receiver_reassignment_cannot_complete(tmp_path: Path, language: str, suffix: str) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/reassigned.{suffix}",
        "import express from 'express';\n"
        "let app = express();\n"
        "app = express.Router();\n"
        "function handler(req, res) {}\n"
        "app.get('/x', handler);\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.INCOMPLETE
    assert "receiver_binding_reassigned:app" in result.structural_reasons


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_handler_reassignment_cannot_complete(tmp_path: Path, language: str, suffix: str) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/handler-reassigned.{suffix}",
        "import express from 'express';\n"
        "const app = express();\n"
        "let handler = (req, res) => {};\n"
        "handler = otherHandler;\n"
        "app.get('/x', handler);\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.INCOMPLETE
    assert "handler_binding_reassigned:handler" in result.structural_reasons
    assert result.resolved_handlers == ()


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_duplicate_handler_declarations_are_unresolved(tmp_path: Path, language: str, suffix: str) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/duplicate-handler.{suffix}",
        "import express from 'express';\n"
        "const app = express();\n"
        "function handler(req, res) {}\n"
        "function handler(req, res) {}\n"
        "app.get('/x', handler);\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.UNRESOLVED
    assert "handler_binding_ambiguous:handler" in result.structural_reasons
    assert len(result.resolved_handlers) == 2


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_valid_nested_registration_resolves_exact_handler_declaration(
    tmp_path: Path,
    language: str,
    suffix: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/nested.{suffix}",
        "import express from 'express';\n"
        "function register() {\n"
        "  const app = express();\n"
        "  const nestedHandler = (req, res) => {};\n"
        "  app.get('/x', nestedHandler);\n"
        "}\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.COMPLETE
    assert result.structural_reasons == ()
    assert len(result.resolved_handlers) == 1
    assert result.resolved_handlers[0].symbol == "nestedHandler"
    assert result.resolved_handlers[0].identity == f"nestedHandler@src/nested.{suffix}:4:8"
    assert result.resolved_handlers[0].location.path == f"src/nested.{suffix}"
    assert result.resolved_handlers[0].location.line == 4
    assert result.match.product_location.symbol == f"app.get->nestedHandler@src/nested.{suffix}:4:8"


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_mixed_receiver_declarations_suppress_authoritative_observation(
    tmp_path: Path,
    language: str,
    suffix: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/mixed-receiver.{suffix}",
        "import express from 'express';\nvar app = express();\nvar app = fake;\nfunction handler(req, res) {}\napp.get('/x', handler);\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.INCOMPLETE
    assert "receiver_binding_ambiguous:app" in result.structural_reasons
    assert "receiver_factory_not_authoritative:app" in result.structural_reasons
    assert not any(item.requirement_id == "receiver" for item in result.match.observations)


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_mixed_handler_declarations_suppress_argument_observation(
    tmp_path: Path,
    language: str,
    suffix: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/mixed-handler.{suffix}",
        "import express from 'express';\n"
        "const app = express();\n"
        "function handler(req, res) {}\n"
        "var handler = externalHandler;\n"
        "app.get('/x', handler);\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.INCOMPLETE
    assert "handler_binding_ambiguous:handler" in result.structural_reasons
    assert "handler_binding_not_repository_defined:handler" in result.structural_reasons
    assert result.resolved_handlers == ()
    assert not any(item.requirement_id == "arguments" for item in result.match.observations)


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_inner_lexical_bindings_cleanly_shadow_outer_bindings(tmp_path: Path, language: str, suffix: str) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/shadowed.{suffix}",
        "import express from 'express';\n"
        "const app = express();\n"
        "function handler(req, res) {}\n"
        "function register() {\n"
        "  const express = require('express');\n"
        "  const app = express();\n"
        "  const handler = (req, res) => {};\n"
        "  app.get('/x', handler);\n"
        "}\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.COMPLETE
    assert result.structural_reasons == ()
    assert result.resolved_handlers[0].identity == f"handler@src/shadowed.{suffix}:7:8"


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_post_registration_reassignment_does_not_contaminate_match(
    tmp_path: Path,
    language: str,
    suffix: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/post-write.{suffix}",
        "import express from 'express';\n"
        "let app = express();\n"
        "let handler = (req, res) => {};\n"
        "app.get('/x', handler);\n"
        "app = express.Router();\n"
        "handler = externalHandler;\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.COMPLETE
    assert result.structural_reasons == ()


@pytest.mark.parametrize("language,suffix", (("javascript", "js"), ("typescript", "ts")))
def test_post_registration_declaration_initializers_do_not_contaminate_match(
    tmp_path: Path,
    language: str,
    suffix: str,
) -> None:
    context, evaluation, _ = _authority()
    root, relative = _source(
        tmp_path,
        f"src/post-initializer.{suffix}",
        "import express from 'express';\n"
        "var app = express();\n"
        "function handler(req, res) {}\n"
        "app.get('/x', handler);\n"
        "var app = fake;\n"
        "var handler = externalHandler;\n",
    )

    result = match_entry_fact(
        repository_root=root,
        relative_path=relative,
        language=language,
        fact_id="entry:express:app-route:get",
        authority=context,
        writer=_writer(tmp_path, context),
        evaluation_population_digest=evaluation,
    )[0]

    assert result.decision.status is RelationStatus.COMPLETE
    assert result.structural_reasons == ()
