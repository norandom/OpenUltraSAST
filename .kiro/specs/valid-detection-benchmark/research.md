# Research and Gap Analysis: valid-detection-benchmark

## Summary

- **Feature**: `valid-detection-benchmark`
- **Analysis date**: 2026-11-05
- **Discovery scope**: Complex brownfield integration; gap analysis only
- **Requirements state**: Generated but unapproved. The existing `design.md` and `tasks.md` predate the reopened requirements and are stale.
- **Overall finding**: The repository has strong reusable fix-site, ordinary-history, artifact, admission, custody, proof, and measurement foundations. It does not yet have a valid replacement population, authoritative reservation/lifecycle workflow, durable custody store, canonical ecosystem review, or exact per-family/per-ecosystem quality reports.
- **Leading design candidate**: A hybrid approach that minimally extends detection-core's authoritative scoped result contract and adds benchmark-owned population governance, persistence, adapters, and operator reporting.
- **Estimated effort**: XL, more than two weeks of implementation plus separately scheduled sourcing and human review.
- **Risk**: High overall. The largest risks are cross-spec metric authority, irreversible admission spend, durable compare-and-swap semantics, and the human/data work needed for at least 40 accepted positives.

## Analysis Context

The selected direction is a general Python and JavaScript/TypeScript benchmark with multiple vulnerability families and quality denominators scoped by exact family and ecosystem. It supersedes the access-control-specific use of the 2026-10-12 pilot. Permanent reservation remains authoritative, the historical pilot remains byte-preserved but non-admissible, and the parked access-control arm is not reactivated by this work.

No external dependency research was necessary for this pass. The main gaps are internal contracts and workflows. External capability research is deferred only for the deployed durable store's conditional-write semantics.

## Current Architecture and Reusable Assets

### Population construction

- `benchmarks/valid/catalog.py` builds fix-site cases and already recognizes Python, JavaScript, and TypeScript files. It records vulnerability family and CWE but drops source ecosystem metadata.
- `benchmarks/valid/verify.py` reads both revisions with nonzero-byte instrumentation, records model assistance, and accepts a human spot check. Its current verdict still makes the model booleans authoritative prerequisites.
- `benchmarks/valid/assemble.py` filters accepted fix-site cases, draws at least 20 ordinary first-parent commits per distinct vulnerability push, collapses multi-function fixes into one push, freezes deterministic TOML/JSON artifacts, and refuses conflicting in-place rewrites.
- `benchmarks/unseen/eligibility.py` gathers repository identities from development sources and resolves aliases, former names, redirects, and fork networks.
- `tests/test_independent_population.py` is the authoritative permanent-reservation guard.

### Artifact, admission, and custody contracts

- `benchmarks/valid/artifact_contract.py` supplies canonical digest envelopes, ordered collection identities, atomic writes, idempotency, and conflict refusal.
- `src/openultrasast/core/admission_review.py` supplies reviewed label-blind `PopulationCensus`, `ScopeCensus`, `AdmissionManifestV2`, and thresholds.
- `src/openultrasast/core/admission_feasibility.py` proves threshold arithmetic before label access.
- `src/openultrasast/core/admission_case.py` binds post-spend cases to exact scope, role, pair, result, evidence, change inputs, and reviewed input manifest.
- `src/openultrasast/core/admission_spend.py` and `benchmarks/valid/population_custody.py` enforce available-to-spent custody before label bytes are released.
- `src/openultrasast/core/admission_metrics.py` rederives metrics from validated evidence and namespaces pair identity by family and ecosystem.
- `src/openultrasast/core/admission_report.py` produces authoritative GO/NO-GO reports and replay validation.
- `src/openultrasast/core/proof.py` and the search adapter provide the differential proof authority required for demonstrated claims.

### Operational persistence patterns

- `benchmarks/unseen/bank.py` and `src/openultrasast/plane/memory.py` provide reusable S3-compatible persistence and lifecycle checks.
- Those writers are unconditional. No production implementation of `CompareAndSwapCustodyStore` exists; only test-local in-memory implementations exercise the custody protocol.

## Requirement-to-Asset Gap Map

| Requirement | Existing assets | Status | Principal gap |
|---|---|---|---|
| 1. General multi-family population | `catalog.py`, source family/ecosystem metadata, multi-target freeze tests | Partial / Constraint | No replacement population; no 40-positive acceptance; source ecosystem is dropped; no canonical ecosystem review; core pools claimed scopes into one metric result |
| 2. Fix-derived positive ground truth | `catalog.build_cases`, `extract.fix_sites`, `verify_case`, `spot_check` | Partial / Constraint | Human independence policy and conflict disclosure are absent; model booleans currently control acceptance; exclusions lack durable reasons; multi-scope labels are not reviewed |
| 3. Representative ordinary changes | `ordinary_history`, `draw_ordinary`, `assemble.negatives`, legacy mislabeled-defect refusal | Partial / Constraint / Missing | No ecosystem on ordinary rows; no reviewed projection across claimed family scopes; no reviewed negative adjudication or post-freeze retirement transition |
| 4. Permanent reservation and withdrawal | `eligibility.py`, permanent guard, immutable historical files | Missing / Constraint | No authoritative reservation census consumed by freeze; no influence events; no enumerated-only disposition; no withdrawal/inventory record; no exact-file historical authorization; guard currently fails |
| 5. Development/admission separation | Core reviewed manifest, readiness, custody, spend, case release | Partial | Benchmark cannot author the label-blind manifest; development inspection is not wired to custody/lineage; durable CAS store is missing |
| 6. Scoped denominators and gates | `ScopeKey`, `DenominatorPolicy`, `ScopeCensus`, feasibility and metric validation | Partial / Constraint | One policy rule per metric currently pools all claimed scopes; no per-scope result container, minimum-size/interval rule, or `insufficient` outcome |
| 7. Reproducible population and custody | deterministic freeze, artifact contract, custody protocol, object-store patterns | Partial / Missing / Unknown | Population freeze uses legacy artifacts; no production CAS, resumable replacement workflow, license boundary, withdrawal lifecycle, or transient-record retention enforcement |
| 8. Standard measurement and failure visibility | `MeasurementRecordV2`, coverage validation, admission report/replay | Partial / Constraint | Final admission report drops some whole-population/runtime detail, records no general degradations, and cannot persist pre-report failures as bounded workflow outcomes |
| 9. Push-path arms and demonstrated evidence | separate runners, legacy hunter combine, proof contracts and adapters | Partial / Missing | No manifest-bound combined-arm rule, component report preservation, scoped demonstrated rate, or general multi-arm admission report |
| 10. Operator outcomes and boundary | core GO/NO-GO gates and steering notification policy | Partial / Missing | No general benchmark CLI/presenter, `insufficient` or failed workflow envelope, safe report projection, or notifier integration; current runner is access-control-specific |

## Detailed Gap Findings

### Population shape and ecosystem identity

The existing candidate sources often carry package ecosystems such as `pip` and `npm`, while existing detection-core examples use language-like ecosystem values such as `python` and `javascript`. The benchmark needs one reviewed vocabulary and a rule for repositories containing more than one framework or ecosystem. This is a design decision; the implementation must not silently infer or coerce the value.

`assemble.freeze()` accepts any nonempty retained population. It does not enforce the 40-positive full-population boundary or classify smaller freezes as development pilots or insufficient populations. It also freezes labels and identities in a legacy manifest rather than producing the label-blind reviewed census required before admission.

### Curation authority

Fix-site extraction is already the correct foundation and has strong offline tests. The human-review record is too weak for the reopened requirements: it contains only decision, reviewer text, and date. It does not bind producer identity, review policy, conflict disclosure, or individual ground-truth judgments.

The current `verify.verdict()` accepts a case only when the model returned all three positive booleans. That makes model assistance part of label authority. The design must retain the model output as review evidence while making a policy-compliant human attestation authoritative.

### Permanent reservation and historical pilot

The guard was run with readable inputs: unseen TOML inputs totaled 3,475,696 bytes and the guard test file totaled 9,146 bytes. The focused test exited 1 after 33.84 seconds with 73 reserved references, all under `benchmarks`; `src`, `tests`, and `plane` contributed zero. This is a real policy conflict, not an unread-input zero.

The pilot payloads must remain unchanged. A new reservation-owned withdrawal inventory must bind each retained historical path and SHA-256 digest, record its non-admissible status and replacement relationship, and authorize only those exact files. The guard may consume reviewed exact-file authorizations but must not gain a directory exclusion or repository-name allowlist.

`eligibility.build_used()` is a broad discovery collector, not an authoritative event ledger. The replacement workflow needs reviewed influence dispositions so an enumerated-only repository can be distinguished from one whose code, labels, or metadata informed a decision.

### Scoped metric authority

Detection-core already validates exact `ScopeKey` values, rejects cross-scope pair substitution, preserves whole-population coverage alongside in-scope cases, and proves threshold feasibility. However, one `DenominatorPolicy` rule currently names the complete claimed scope tuple and `derive_admission_metrics()` pools those scopes into one `MetricResult` per metric. `MetricResult` carries no scope or weighting metadata.

Therefore the requirement for independently interpretable family/ecosystem results cannot be implemented safely only in `benchmarks/valid/metrics.py`. That would create a second metric authority. The design must choose a versioned detection-core extension, such as one admission manifest producing a canonical tuple of exact-scope reports plus a non-authorizing aggregate. Separate post-spend reports must not independently reinterpret one label release.

The core also needs an explicit `insufficient` outcome or equivalent non-authorizing status for scopes whose minimum sample or interval rule fails. GO/NO-GO alone cannot represent a pre-spend denominator that is validly too small.

### Durable custody and recovery

The custody protocol correctly requires a successful compare-and-swap append and reread before label access. Its production storage seam is unimplemented. Existing object-store adapters provide versioning and lifecycle inspection but not conditional compare-and-swap.

Before selecting an adapter, the design phase must capability-test the deployed store for conditional create/update, concurrent-writer behavior, version visibility, restart recovery, and current/noncurrent expiry. If the store cannot provide the required semantics, the design needs a different durable serialization authority; ordinary overwriting `put_object` calls are not sufficient.

### Measurement, proof, and operator outcomes

The v2 core measurement path is substantially stronger than the legacy `benchmarks/valid/metrics.py` path. It revalidates evidence, metrics, gates, and replay identities. The benchmark should adapt to it rather than extend the legacy aggregate scorer as an admission authority.

The current v2 report does not carry a durable workflow outcome for exceptions that happen before report construction. Instrument failures fail closed, but operators cannot distinguish a bounded incomplete run from an absent report. A benchmark-owned workflow envelope can record safe reason codes and digests without weakening the authoritative core report.

Proof authority already exists. The missing work is to bind proof-derived scoped rates and any combined arm rule into the pre-label baseline. Legacy shape checking in `metrics.demonstrated()` is useful compatibility code but cannot authorize blocking.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Effort / Risk |
|---|---|---|---|---|
| A. Extend existing components | Expand current `assemble.py`, `metrics.py`, admission contracts, and guard in place | Few new modules; maximum reuse; short path for simple criteria | Bloating of already mixed responsibilities; legacy and v2 authority remain easy to confuse; strict core schemas make broad in-place edits risky | L–XL / High |
| B. New benchmark-only layer | Leave detection-core unchanged and implement scoped projections, lifecycle, custody, and reports entirely under `benchmarks/valid/` | Clear benchmark ownership; limited core migration | Duplicates or bypasses authoritative metric algebra; unsafe after one irreversible spend; creates competing report authorities | L / High integrity risk |
| C. Hybrid versioned extension | Add the minimum scoped-result and workflow-status contracts upstream; add benchmark-owned population, reservation, custody adapter, case adapters, and presenter | Preserves one metric authority and existing ownership split; migration can be staged; most current assets remain reusable | Cross-spec coordination and artifact migration; more components and conformance tests | XL / High overall, Medium per component |

Option C is the leading design candidate because it is the only approach that satisfies scoped denominators without duplicating admission authority. It remains a candidate until the core schema shape and durable-store capability are resolved in design.

## Compatibility and Migration Boundaries

- Historical pilot and measurement payloads are immutable audit inputs, never migration targets.
- Legacy `metrics.py` and the parked access-control helpers remain readable historical/development paths but do not authorize the replacement admission baseline.
- New population, lifecycle, census, manifest, custody, run, and report artifacts require versioned kinds and new identities.
- A population, vocabulary, scope, denominator, analyzer, fact, threshold, or outcome-mapping change creates a new baseline.
- Detection-core owns metric algebra, scope validation, spend validation, and authoritative replay. The benchmark owns sourcing, review records, reservation/lifecycle state, durable label custody, arm execution adapters, and operator presentation.
- The replacement workflow must not call or requalify the parked access-control arm unless a separate maintainer decision changes that policy.

## Complexity and Risk Assessment

### Effort

- **Core scoped-result extension**: L. It changes strict dataclasses, canonical digests, report/replay validation, and conformance tests.
- **Reservation withdrawal and exact-file authorization**: M. The code is bounded, but migration evidence and immutable inventory require care.
- **Ecosystem, review, and population freeze schemas**: L. Existing catalog and assembly code are reusable, but responsibilities must be separated.
- **Durable CAS custody adapter and recovery tests**: M–L, depending on store capability.
- **General arm orchestration, workflow outcomes, and presentation**: L.
- **Replacement sourcing and independent review**: XL elapsed work; rate limits, license decisions, repository availability, and human review dominate.
- **Overall**: XL, more than two weeks, with operational curation continuing beyond pure code implementation.

### Risk

- **Overall risk: High.** Admission spend is irreversible, the existing guard is red, and one wrong scope projection can authorize a false claim.
- **Schema migration risk: High.** Core artifacts are closed, digest-bound graphs; changing fields requires full replay and compatibility tests.
- **Persistence risk: High until measured.** Durable conditional-write semantics are unverified on the deployed store.
- **Population availability risk: High.** Forty accepted, reachable, permissively distributable positives across two language groups and multiple families may require many more candidates.
- **Detection implementation risk: Low within this spec.** Detector logic is explicitly out of scope and must remain unchanged.

## Design-Phase Recommendations

1. Define a versioned core scoped-result container: exact `ScopeKey` result rows, one non-authorizing aggregate, minimum-size/interval sufficiency, and a workflow-safe `insufficient` status.
2. Keep core changes in the detection-core ownership boundary. The benchmark design consumes that contract and must not reproduce its metric algebra.
3. Add an authoritative reservation/influence ledger and a digest-bound withdrawal inventory before sourcing the replacement.
4. Define one canonical ecosystem vocabulary and independent review record before changing catalog or freeze formats.
5. Replace model-controlled acceptance with human-authoritative reviewed ground truth while retaining model output as non-authoritative evidence.
6. Author label-blind census/manifest artifacts from the new freeze and integrate them with existing readiness, spend, case release, and replay contracts.
7. Capability-test the durable store before committing to a CAS adapter. Preserve the custody protocol's spend-before-read ordering.
8. Add a benchmark workflow envelope for completion, insufficient, timeout, resource, and instrument-failure outcomes using fixed redacted reason codes.
9. Migrate in this order: core scoped contract; reservation/withdrawal; ecosystem and review schemas; population freeze; durable custody; arm adapters; scoped reporting; replacement sourcing and review.

## Research Needed for Design

1. **Scoped result shape**: one manifest with a tuple of per-scope reports versus another versioned container; define aggregate weighting and replay rules.
2. **Canonical ecosystem taxonomy**: package ecosystem, runtime/framework ecosystem, or a reviewed composite; specify multi-ecosystem repositories.
3. **Durable CAS capability**: conditional write semantics, concurrent writers, version visibility, crash recovery, and lifecycle enforcement on the deployed store.
4. **Population sizing**: candidate yield needed to reach 40 accepted positives and the pre-registered minimum/interval rule for each claimed scope.
5. **Historical authorization format**: review subject, exact path/digest inventory, relocation rules, and guard integration.
6. **Safe workflow reason taxonomy**: stable operator-facing codes that reveal no private labels, paths, payloads, or exception text.
7. **License custody**: approved permissive-license vocabulary and opaque private-reference workflow for uncertain or non-permissive material.

## Validation Evidence

- The requirement headings and acceptance criteria passed the EARS mechanical gate before this analysis.
- Focused reservation guard command:

  ```text
  PYTHONPATH=src:tests .venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_independent_population.py::test_no_reserved_repository_is_referenced_by_the_development_tree
  ```

- Result: `1 failed in 33.84s`, exit code `1`, with `73` benchmark references and zero references from `src`, `tests`, or `plane`.
- No full test suite was run for this read-only analysis.

## References

- `.kiro/specs/valid-detection-benchmark/requirements.md`
- `.kiro/specs/valid-detection-benchmark/design.md` — stale reference only
- `.kiro/steering/detection-quality.md`
- `.kiro/steering/storage-streaming.md`
- `.kiro/steering/code-standards.md`
- `benchmarks/valid/`
- `benchmarks/unseen/eligibility.py`
- `tests/test_independent_population.py`
- `src/openultrasast/core/admission_*.py`
- `src/openultrasast/core/measurement.py`
- `src/openultrasast/core/proof.py`

---

## Design Discovery and Synthesis (2026-11-06)

### Discovery Summary

- **Discovery type**: Complex integration, full discovery.
- **Selected pattern**: Hybrid versioned extension. Detection-core remains the sole authority for scope validation, metric algebra, threshold evaluation, and replay. The benchmark owns population governance, reservation state, review, freezing, custody adapters, arm execution, workflow outcomes, and operator presentation.
- **Critical prerequisite**: The replacement admission baseline requires a detection-core V3 admission root. V2 necessarily pools all claimed scopes and cannot be projected into authoritative per-scope results after label release.
- **Compatibility rule**: V2 artifacts remain byte-preserved and replayable. A pooled V2 result is never auto-upgraded; the V3 population starts a new baseline.

### Research Log

#### Detection-core scoped-result seam

- **Context**: Requirements 6 and 8 require exact family-and-ecosystem metrics, per-scope gates, whole-population coverage, and non-authorizing aggregates.
- **Sources consulted**: `measurement.py`, `admission_context.py`, `admission_feasibility.py`, `admission_metrics.py`, `admission_report.py`, `_admission_replay.py`, and their core admission tests.
- **Findings**:
  - V2 assigns every standard metric rule the full claimed-scope tuple, sums census capacity across the tuple, derives one metric result per metric, and stores no scope on `MetricResult`.
  - The smallest safe change is a new V3 root with exact-scope metric rules and thresholds, pre-spend scope sufficiency, one canonical result per scope, separate deduplicated whole-population coverage, and an optional aggregate type with no gate or decision field.
  - `insufficient` belongs to pre-spend feasibility. Because custody releases one population, any insufficient claimed scope makes `may_spend` false. Partial-scope label release is a different custody model and is out of scope.
  - Multi-scope whole-population coverage must deduplicate by canonical change-input identity; summing scoped rows can count one multi-label push more than once.
- **Implications**: This spec consumes the V3 contract as an upstream prerequisite. It does not duplicate metric algebra under `benchmarks/valid/` and does not modify detection-core-owned files.

#### Canonical ecosystem and human review authority

- **Context**: Existing source records carry package ecosystem and license evidence, while the valid catalog drops it and current model booleans control acceptance.
- **Sources consulted**: `benchmarks/unseen/source.py`, `benchmarks/valid/catalog.py`, `verify.py`, `assemble.py`, and review contracts under `src/openultrasast/core/`.
- **Findings**:
  - The V1 benchmark vocabulary is `python` and `javascript`; TypeScript maps to the JavaScript ecosystem while remaining visible as an observed language. Package ecosystems such as `pip` and `npm` remain source evidence, not canonical scope values.
  - One independent repository review selects exactly one canonical ecosystem. A polyglot or conflicting case is `insufficient`, never silently coerced.
  - Ground truth is a human attestation over defect presence, fix effect, in-repository reachability, and exact verified scopes. Model output is retained only as a digest-bound assistance reference and never participates in acceptance algebra.
- **Implications**: Cataloging preserves source evidence; a new review component owns authoritative decisions; freezing consumes only accepted reviewed records.

#### Permanent reservation and historical withdrawal

- **Context**: The old pilot is permanently reserved but must remain accessible for audit without creating a broad guard exclusion.
- **Sources consulted**: `benchmarks/unseen/eligibility.py`, `tests/test_independent_population.py`, the current pilot artifacts, and the focused guard evidence recorded above.
- **Findings**:
  - Broad discovery of repository names is not an influence ledger. A reviewed append-only event must distinguish `enumerated_only` from `influenced` and resolve aliases/forks before projection into the permanent census.
  - Historical authorization is an append-only lifecycle: a `withdrawn` event binds exact repository-relative paths and SHA-256 digests; a later `replacement_bound` event links the new population and freeze identities.
  - The production guard permits only exact path-and-current-digest matches. Relocation or byte changes require a new reviewed event; repository-name or directory allowlists are forbidden.
- **Implications**: Reservation semantics move from test-only logic into `benchmarks/unseen/reservation.py`; the existing test becomes a consumer of that authority.

#### Durable compare-and-swap custody

- **Context**: The core requires a committed and reread custody transition before exposing label bytes, but current S3 writers are unconditional.
- **Sources consulted**: installed boto3/botocore service model, AWS S3 conditional-write documentation, RustFS S3 compatibility documentation, `population_custody.py`, `bank.py`, and `plane/memory.py`.
- **Findings**:
  - The locked boto3/botocore `1.43.107` service model exposes `IfMatch` and `IfNoneMatch` on `PutObject`.
  - Amazon S3 documents conditional create/update using `If-None-Match: *` and `If-Match` ETags, with 412 for failed preconditions and possible 409 conflicts under concurrency.
  - RustFS documents common conditional requests, versioning, and lifecycle, but explicitly requires applications to validate exact advanced operations against the target release. Its published compatibility matrix does not establish this project's complete CAS protocol.
  - The adapter must therefore perform a target-store capability probe for conditional create, conditional update, two-writer conflict, version visibility, restart recovery, and lifecycle behavior. Unsupported or ambiguous behavior fails closed before any real population is stored.
- **Implications**: A benchmark-owned S3 CAS adapter uses content digests as domain identity and ETag/version only as the storage concurrency token. Existing unconditional `CorpusObjects` is not reused as custody authority.
- **Official references**:
  - [Amazon S3 PutObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
  - [Amazon S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
  - [RustFS S3 protocol and compatibility scope](https://docs.rustfs.com/en/administration/protocols/s3)
  - [RustFS S3 compatibility matrix](https://docs.rustfs.com/en/reference/s3-compatibility)

#### General arm orchestration and operator outcomes

- **Context**: `admission_run.py` is access-control-specific and the parked arm must remain parked. Completed core reports cannot represent failures before report construction.
- **Sources consulted**: `benchmarks/valid/admission_run.py`, `admission_scoring.py`, `metrics.py`, core case/proof/report contracts, and `operator-notifications.md`.
- **Findings**:
  - The reusable ordering is preflight, authorize, durable spend, label release, label-blind arm execution, reviewed case binding, core score, and replay validation.
  - Arms receive immutable label-blind case inputs. The custodian alone joins detector observations to released ground truth. Combined-arm rules are digest-bound before label access and preserve every component result.
  - Early or impaired runs need a benchmark-owned envelope with a closed redacted reason taxonomy. It may reference a completed core replay but cannot fabricate a core report.
  - The spec owns deterministic JSON/text presentation. Discord transport remains outside the boundary because no shared notifier implementation exists and steering permits separate wiring.
- **Implications**: The replacement runner is general and cannot import access-control-specific site judgment helpers.

### Architecture Pattern Evaluation Update

| Option | Decision | Rationale |
|---|---|---|
| Extend V2 and legacy benchmark modules | Rejected | Pooled V2 metrics cannot become exact-scope authority; mixed modules would retain competing admission paths. |
| Benchmark-only V3 projection | Rejected | It would duplicate detection-core algebra after irreversible label release. |
| Hybrid versioned extension | Selected | One authoritative core result graph, bounded benchmark ownership, preserved V2 compatibility, and independently testable persistence/adapters. |

### Design Decisions

#### Decision: Treat detection-core V3 as an explicit upstream prerequisite

- **Selected approach**: Detection-core owns `DenominatorPolicyV3`, exact-scope feasibility, scoped results, deduplicated whole-population coverage, non-authorizing aggregate, report, and replay. This spec consumes those contracts.
- **Rationale**: Scope and metric authority already belong to detection-core; moving them into benchmark code would create hidden shared ownership.
- **Trade-off**: Implementation cannot begin admission scoring until the dependency amendment lands, but population governance and non-label-bearing work can proceed in parallel.

#### Decision: Make population spend atomic across all claimed scopes

- **Selected approach**: Every claimed scope must be feasible before the one population label release. Any insufficiency emits a pre-spend outcome and leaves the population unspent.
- **Rationale**: The current custody object releases the population as a unit. Partial release would expose labels for all scopes while pretending some remained untouched.
- **Trade-off**: Sparse scopes delay admission, but the result remains interpretable and reusable.

#### Decision: Use reviewed repository-level ecosystem identity

- **Selected approach**: Canonical values are `python` and `javascript`; TypeScript is an observed language within `javascript`. One independent review chooses the repository ecosystem or records `insufficient`.
- **Rationale**: This matches the existing core examples, gives stable denominators, and prevents framework-specific inventories from becoming architecture.
- **Trade-off**: Ambiguous polyglot repositories are excluded from admission until their benchmark role is clear.

#### Decision: Build reservation state as an append-only reviewed projection

- **Selected approach**: Influence and lifecycle events are immutable; deterministic censuses and exact-file authorizations are projections.
- **Rationale**: It distinguishes enumeration from influence, preserves historical bytes, and makes every exception auditable without weakening the guard.
- **Trade-off**: Accepted V1 lifecycle events have no general correction transition. Invalid proposals are rejected before projection; terminal development/retirement states cannot be undone.

#### Decision: Adopt S3 conditional writes only after a capability probe

- **Selected approach**: Use existing boto3 and S3 conditional headers through a new CAS adapter; validate the deployed RustFS release and bucket policy before real use.
- **Rationale**: The SDK supports the API, but compatibility claims are not a substitute for testing the exact target store and concurrency protocol.
- **Trade-off**: A failed probe blocks custody implementation; there is no unsafe unconditional-write fallback.

#### Decision: Keep workflow status outside the authoritative core report

- **Selected approach**: A benchmark envelope records completed, insufficient, timeout, budget, resource, instrument, and interruption outcomes. Completed entries reference the core V3 replay.
- **Rationale**: Pre-report failures need durable visibility but must not be made to look like a quality decision.
- **Trade-off**: Operators consume two nested authorities: workflow completion from the benchmark and quality decisions from detection-core.

### Synthesis

- **Generalization**: Population review, arm registration, and outcome reporting are horizontal contracts. Concrete repositories, frameworks, and vulnerability vocabularies remain data/evidence.
- **Build versus adopt**: Reuse core canonicalization, case/proof/admission contracts, benchmark artifact envelopes, Git identity resolution, boto3, S3 conditional requests, and RustFS versioning/lifecycle. Build only the missing governance, CAS adapter, general orchestration, and presentation seams.
- **Simplification**: No partial-scope custody, no V2 migration, no benchmark metric engine, no notifier transport, no detector plugin framework, and no access-control compatibility adapter in the new path.

### Updated Risks and Mitigations

- **Upstream V3 drift** — pin exact schema identifiers and add consumer conformance tests before population spend.
- **Sparse scope blocks the whole gate** — run label-blind feasibility while sourcing and classify small freezes as pilots; never open labels to learn sample adequacy.
- **RustFS CAS mismatch** — run the exact capability probe against the configured target and fail closed.
- **Polyglot ambiguity** — require independent ecosystem review; unresolved rows are insufficient.
- **Model influence on labels** — store assistance separately and derive acceptance only from human attestations.
- **Historical authorization broadens silently** — normalize paths, verify current bytes, and accept only reviewed exact path/digest inventory rows.
- **Post-spend interruption** — persist the spent transition and workflow envelope; resume the same immutable run without restoring untouched status.

### Design Review Gate Refinements

The automatic gate required two bounded repair passes. The resulting refinements are architectural commitments, not implementation preferences:

- **Two-stage V3 authorization**: `EvaluationPlanManifestV3` supports label-blind arithmetic feasibility before arm execution. After every custodian-sealed observation set exists, `EvaluationAdmissionManifestV3` binds their exact bytes and core derives the spend authority against the current custody head.
- **One shared multi-arm root**: one reviewed plan and one custody receipt bind independent per-arm scoped reports inside one `EvaluationReplayV3`. Missing any planned arm prevents completion.
- **Execute before spend, inspect only after disqualification**: isolated arms run before labels open. Observation sets remain custodian-sealed; only closed counts/digests/reason codes are visible. Human access or any plan/configuration change records `development_opened`, adds influence events, and makes the population admission-ineligible.
- **Core-owned ordinary projection**: the freeze stores and executes an ordinary push once with its reviewed ecosystem. Detection-core projects it per claimed family in that ecosystem and deduplicates whole-population coverage.
- **Typed proof promotion**: pre-spend proof candidates carry no ground-truth role. The custodian promotes one to `ProofAttachment` only after exact family, pair, role, input, location, differential record, control, and receipt binding succeeds.
- **Separate durable authorities**: a content-addressed artifact repository owns immutable events, freezes, sealed observations, terminal outcomes, reports, and replays; custody and workflow heads use stronger conditional-update protocols. Expiring run journals cannot make terminal evidence unreachable.
- **Causal lifecycle and workflow chains**: lifecycle events name predecessors and terminal development/retirement cannot be undone. Workflow heartbeats use a CAS head, sequence, predecessor, attempt, and lease owner so concurrent resume and stale renewal are deterministic.
- **Explicit predecessor gate**: implementation task generation waits for an approved and validated `detection-core` amendment exporting `openultrasast.detection-core.evaluation-admission.v3`; this spec does not absorb upstream core changes.
