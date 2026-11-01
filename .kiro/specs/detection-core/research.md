# Research Log: detection-core

## Gap analysis (2026-10-30)

### Current-state inventory (from codebase exploration)

The security trace already exists for one family (access_control) in the prover:
`Trace`/`PathRecord`/`ProverResult` (`src/openultrasast/hunt/prover.py`,
`semantic/obligations/trace.py`), three-way judgment (`PairJudgment`,
`semantic/obligations/judgment.py`), coverage counters (`Coverage`, `stage_funnel`,
resolution buckets in `semantic/obligations/resolution.py`), digest stamping
(`benchmarks/valid/run_manifests.py` `AnalyzerBundle`, `_input_digest`/`_population_digest`
in `arm_regression.py`), and the admission workflow (`benchmarks/valid/prover_admission.py`,
`admission_scoring.py`, `admission_run.py`).

### Requirement-to-asset map

| Req | Existing asset | Status |
|---|---|---|
| 1 trace object | `Trace`/`ProverResult` in prover | Exists, access_control-only; needs family-agnostic core contract |
| 2 three-way judgment | `PairJudgment`, `judgment.py` | Exists; promote to core vocabulary |
| 3 coverage accounting | `Coverage`, `stage_funnel`, resolution buckets | Exists; zero-byte refusal lives only in runners |
| 4 measured budget | static `BUDGET_SECONDS = 120.0` in runners; per-change `seconds` recorded | **Gap**: budget is a constant; complexity features not recorded; no per-class derivation. Evidence: dev pool 20/483 overruns (max 240s) vs pilot max 7.7s |
| 5 verdict contract | findings carry witness; indeterminate handling in prover | Exists; needs core-level contract (proven vs bounded silence) |
| 6 digests/provenance | `AnalyzerBundle`, input/population digests | Exists; stamping rule must become core-level |
| 7 admission gate | `prover_admission.py`/`admission_scoring.py`/`admission_run.py` | Exists for one arm; needs family-agnostic generalization |
| 8 no fitting on labels | steering rule only (detection-quality.md) | **Gap**: no reversed-pair probe harness exists |
| 9 bounded model role | zero-shot judge measured 2026-10-28 (nearly inert, safe) | Policy; core must state the boundary contract |
| 10 fact packs | `ruleset/obligations/*.toml`, `fact_init.py` | Exists per language; needs family-pack admission + scope tagging |
| 11 consumer contract | each runner has its own envelope (`prover_arm.run/summarize`, push.admission.defects) | **Gap**: no shared core interface |
| 12 measurement schema | `score.rate`, `summarize_*` | Partial; vocabulary/digest fields not unified |

### Implementation approach options

- **A. Extend in place**: grow the prover modules into the core. Minimal new files, but
  bloats family-specific code and keeps the "one arm = one contract" problem.
- **B. New core module, prover reimplemented**: clean contract, but discards measured,
  reviewer-approved code (risk of regression in the 34.8%-recall strict lane).
- **C. Hybrid (recommended)**: new thin core-contract package that the prover's existing
  types implement, and the runners consume incrementally. Contract extracted, behavior
  preserved; migration is per-consumer, each step reviewable.

### Effort / risk
- Effort: M-L (contract extraction across ~6 runner modules plus core package).
- Risk: Medium — contract extraction touches measured code paths; mitigated by keeping
  existing behavior byte-identical per consumer during migration and re-running the
  admission suite as the regression gate.

### Research needed (carried to design)
- Measured-budget model: which complexity features predict reply time on the two pools
  (dev 483 changes with seconds; pilot 264). Carry the 13.3/13.4 record sets as the fitting
  data — measurement only, never training a detector on them.
- Reversed-pair probe harness for Req 8: fix/reversed-fix pairs exist in the pools.

---

## Gap analysis: family-neutral evidence and model augmentation (2026-10-31)

### Scope and approval state

- **Feature type:** complex integration over an existing contract package. The core exists,
  but its public schema, tests, producer adapter, and historical admission schema embody the
  authorization family that supplied the original implementation.
- **Requirements state:** generated but not approved. This analysis may inform review; design
  generation remains gated on explicit requirements approval.
- **Discovery method:** integration-focused source inspection. No external dependency research
  was needed: the neutral core can remain Python 3.11 typed dataclasses and canonical JSON,
  while DSPy remains the existing optional `hunt` dependency (`>=3.4,<3.5`) behind an adapter.
- **Instrument check:** representative requirements, core, authorization-adapter, model-runner,
  and project-metadata inputs were opened with nonzero byte counts before interpreting gaps.

### Current-state inventory

The existing `src/openultrasast/core/` package is a compact contract layer with reusable
machinery:

- `trace.py` supplies immutable records and deterministic JSON serialization.
- `verdict.py` supplies the authorization three-way judgment plus claim and bounded-silence
  records.
- `coverage.py` supplies exact call-resolution buckets and zero-byte input refusal.
- `budget.py` supplies measured percentile budgets and a named budget gate.
- `provenance.py` supplies input-identity stamping and mismatch refusal.
- `factpack.py` supplies reviewed pack loading and content digests.
- `admission.py` supplies consume-only manifest validation and a fixed report schema.
- `probes.py` supplies reversed-pair and holdout/admission checks.
- `consumer.py` supplies a push request/verdict envelope.

Current integration is narrow. `semantic/obligations/trace.py` converts the authorization
trace into the core `TraceRecord`; `hunt/prover.py` converts authorization coverage;
`mapping/entry_packs.py` consumes core fact packs; benchmark admission modules consume part
of the admission contract. The production push and proof paths do not yet consume the core
end to end. `benchmarks/valid/judge_pass.py` is the closest existing DSPy residual-judgment
adapter, but it reads authorization findings directly rather than a family-neutral evidence
record.

### Requirement-to-asset map

| Requirements | Existing assets | Gap classification and impact |
|---|---|---|
| 1–2 Evidence record and outcomes | Deterministic serialization, frozen dataclasses | **Missing / breaking:** `TraceRecord` requires authorization fields (`entry`, operation, resource, authority, guards) and `Judgment` is exactly unguarded/discharged/indeterminate. Missing family/security-object identity, analyzed scope, generic transitions and observations, family decision, neutral outcome, evidence basis, and bounded satisfaction. |
| 3 Family contract | Family strings exist in findings and packs | **Missing:** no versioned contract, ecosystem scope, security-object schema, accepted semantic roles, decision mapping, completeness policy, or two-family conformance fixtures. |
| 4 Typed semantics | Authorization hops/guards and recognition packs | **Missing:** no generic registration, invocation, call, return, transformation, operation-effect, or constraint-effect relation with conditions, fact identity, ambiguity handling, and per-relation completeness. |
| 5 Coverage and instrument | Zero-byte refusal, call buckets, authorization funnel | **Partial:** missing generic question → recognition → transition → security-object → constraint → outcome → finding counters and last-success/first-zero diagnosis. Existing coverage cannot distinguish all newly required failure layers. |
| 6 Budget and scope | `Complexity`, `Budget`, percentile derivation; change-scoped runners | **Constraint:** reusable budget logic is not bound to the neutral run, `calls` is not a generic transition count, and current runners may still pass a static 120-second value. Scope identity is absent from the evidence result. |
| 7 Verdict | `ProvenClaim`, `BoundedSilence`, consumer validation | **Partial / semantic mismatch:** no bounded-satisfaction record, evidence-basis tag, evidence-record identity, completed-question inventory, or multi-path aggregation. `ProvenClaim` currently implies proof-grade evidence for every claim. |
| 8 Readiness | Separate development and admission runners | **Missing:** no ordered readiness stages, prerequisite digests, staleness propagation, positive/negative/ambiguity fixture contract, or refusal of later gates after an earlier failure. |
| 9 Model augmentation | Existing DSPy program, cached calls, parsing/failure records, zero-shot judge experiment | **Missing / contradictory test:** no core handoff/result contract; a core test explicitly asserts that no model path is public. Model programs consume code/features or authorization findings, not canonical evidence records. The core must not import optional DSPy. |
| 10 Provenance | Six current digests and mismatch refusal | **Partial:** missing family-contract, semantic-pack/fact, model, program, prompt, and model-configuration identities. |
| 11 Fact packs | Review attestation, content digest, Express entry pack | **Partial / validation gap:** facts remain `dict[str, Any]`; the typed object lacks schema version, ecosystem/language scope, closed roles, structural match requirements, relation conditions, and conflict detection. The embedded review digest authenticates the review note, not the fact content itself. |
| 12 Admission | Consume-only manifests, pair scoring, Wilson intervals, GO/NO-GO reports | **Partial / authorization-shaped:** missing readiness prerequisites, ecosystem and denominator policy, family/model identities, arithmetic feasibility, in-scope scoring, neutral outcomes, semantic-stage funnel, and model-call results. |
| 13 Evaluation separation | Reversed-pair probe and coarse holdout/admission check | **Partial:** no lineage proving prompts, examples, facts, mappings, and promotion excluded admission labels. The current probe treats any differing score as a shortcut and is not a semantic audit by itself. |
| 14 Consumers | Push wrapper and authorization native conversion | **Partial:** the request is not used by `consume_verdict`; no proof-attachment interface, family readiness declaration, or production pre-push consumption exists. |
| 15 Measurement | Fixed report keys and benchmark metric helpers | **Partial / schema migration:** missing neutral outcomes, evidence bases, family/model identities, the generic semantic funnel, model failures, readiness digests, and enforceable baseline-reset metadata. Existing keys encode the legacy admission vocabulary. |

### Compatibility and architecture constraints

1. `TraceRecord` and `Judgment` are public exports and are pinned exactly by contract tests.
   Replacing them in place breaks the authorization adapter immediately.
2. Historical admission reports are immutable evidence. A neutral schema must have a new
   version and baseline; historical artifacts must not be rewritten to pass a new validator.
3. The authorization trace has no per-hop completeness and conservatively maps every hop to
   incomplete. Migration must preserve that behavior until the family producer supplies
   stronger evidence.
4. The core package must remain dependency-light. DSPy execution belongs in a hunt-side or
   family-side adapter; the core owns only typed request, result, and provenance contracts.
5. Vendored source remains excluded. Framework behavior needed for a determinate decision
   must arrive through reviewed semantic relations or remain indeterminate.
6. `core/admission.py` currently imports forbidden-label markers from `tools.fact_init`, an
   upward dependency from a foundational contract into acquisition tooling. The design must
   reverse or remove this dependency.
7. Fact-pack strengthening affects `mapping/entry_packs.py` and the shipped Express pack;
   versioned loading or migration is required.
8. Core-unit success alone cannot establish integration because the production push and
   proof consumers are not yet wired to the contract.

### Implementation approach options

#### Option A: Extend the existing types in place

Add neutral fields and aliases while retaining authorization fields and judgment values.

- **Strengths:** smallest initial patch; current producers and tests need fewer immediate
  changes.
- **Risks:** creates dual sources of truth, permanently leaks authorization vocabulary into
  every family, and cannot convincingly satisfy two-family neutrality.
- **Effort / risk:** L / High.

#### Option B: Add an independent v2 core beside the current package

Build a separate neutral package and migrate consumers later.

- **Strengths:** clean schema and clear compatibility boundary.
- **Risks:** recreates the parallel-contract problem this spec exists to remove; downstream
  specs can continue using v1 indefinitely; admission and measurement logic is duplicated.
- **Effort / risk:** XL / High.

#### Option C: Hybrid versioned migration

Add neutral typed primitives and family, readiness, and model contracts inside the existing
core boundary; retain reusable budget, provenance, and validation machinery; place explicit
authorization and DSPy adapters outside the neutral types; migrate consumers before removing
legacy exports.

- **Strengths:** preserves measured machinery without preserving the wrong abstraction;
  maintains a dependency-light core; provides a bounded migration path and a natural place
  for two unlike reference-family conformance fixtures.
- **Risks:** requires deliberate schema versioning, temporary compatibility adapters, and a
  new measurement baseline.
- **Effort / risk:** XL / Medium-High.
- **Design-phase recommendation:** prefer this option, subject to requirements approval and
  resolution of the carried research items below.

### Candidate responsibility and file boundaries

The gap analysis identifies responsibilities, not final design choices:

- `core/evidence.py` — family-neutral evidence record, typed transitions, observations, and
  completeness.
- `core/family.py` — versioned family contract, declared schemas/roles, and decision mapping.
- `core/readiness.py` — stage results, prerequisites, invalidation, and promotion refusal.
- `core/model.py` — dependency-free model handoff/result and identities.
- `core/measurement.py` — neutral funnel and versioned measurement schema.
- Existing `verdict.py`, `coverage.py`, `factpack.py`, `provenance.py`, `admission.py`,
  `consumer.py`, `probes.py`, `budget.py`, and `__init__.py` — extend reusable behavior and
  phase out authorization-shaped exports.
- `semantic/obligations/trace.py` — authorization-family adapter rather than a core schema
  definition.
- A hunt-side adapter — converts an evidence packet into the family DSPy input and converts
  the model result into the core model-result contract without importing DSPy into core.
- Benchmark development/admission modules — produce readiness artifacts and score the neutral
  schema while preserving historical report validation separately.
- Contract, migration, two-reference-family, model-handoff, readiness, and admission tests —
  replace authorization-specific assumptions with explicit adapter conformance.

### Design research carried forward

1. Choose whether the two conformance families are synthetic authorization-plus-taint
   fixtures or real adapters. They must prove different security-object shapes without
   implying user-facing capability enablement.
2. Define the stable proof-attachment subset of demonstrated search results; proof execution
   remains outside this spec.
3. Assign readiness-artifact persistence: the likely seam is that benchmark workflows
   produce/store artifacts while the core validates prerequisites and staleness.
4. Define the wire migration and removal policy for legacy `TraceRecord`, `Judgment`, and
   historical authorization report validation.
5. Pin the rule for model-corroborated outcomes: a model may answer only a family-declared
   residual question. A missing relation declared necessary for the family outcome remains
   indeterminate; model corroboration cannot fill it implicitly.
6. Decide whether budget workload-class assignment stays a runner responsibility or becomes
   part of the neutral request contract; the core should validate, not infer, change scope.

### Gap conclusion

The existing package provides useful primitives but does not yet implement the amended
family-neutral contract. The dominant work is schema and lifecycle migration, not new graph
analysis. The authorization arm should remain a family adapter and regression source; it
must not define the new core vocabulary. Design generation should begin only after explicit
requirements approval.

---

## Design discovery and synthesis (2026-10-31)

### Summary

- **Feature:** detection-core
- **Discovery scope:** complex integration and public-contract migration.
- **Key findings:**
  - The reusable assets are canonical serialization, immutable records, budget derivation,
    digest verification, manifest refusal, and metric helpers. Authorization field names and
    outcomes are not reusable core concepts.
  - The smallest viable architecture is a versioned ports-and-adapters contract: the core
    owns typed evidence and validation; deterministic analyzers, DSPy, proof execution,
    benchmarks, and push policy remain outside it.
  - Readiness must be an immutable prerequisite graph validated by the core and persisted by
    benchmark workflows. This makes a failed semantic stage stop later population gates.
  - Migration must be finite: v2 is the only write contract after consumers migrate; v1
    remains a read-only historical decoder, not a second detection core.

### Research log

#### Existing integration and dependency direction

- **Context:** the amended requirements generalize an already implemented authorization
  contract without reopening the parked arm.
- **Sources consulted:** `src/openultrasast/core/`, authorization trace and prover adapters,
  benchmark development/admission runners, push consumers, search verifier records, current
  tests, and project steering.
- **Findings:**
  - Core production imports are concentrated, so a staged adapter migration is feasible.
  - `core/admission.py` currently imports acquisition-tool policy, which inverts the desired
    dependency direction.
  - Production push and proof paths are not yet end-to-end core consumers; unit conformance
    alone cannot establish integration readiness.
- **Implications:** core modules import only the standard library and other core modules.
  Analyzer, model, benchmark, proof, and push adapters import core, never the reverse.

#### DSPy boundary

- **Context:** the original product direction augments DSPy programs with deterministic
  analysis evidence, while the core installation must remain independent of the optional
  model stack.
- **Sources consulted:** existing `hunt/program.py` and `judge_pass.py`; official DSPy
  documentation for signatures and modules.
- **Findings:** DSPy signatures declare structured input/output behavior, while modules may
  contain learnable prompt or model parameters. A stable core handoff can therefore be a
  typed request/result contract, but reproducibility requires program, prompt, model, and
  configuration identities rather than a model name alone.
- **Implications:** DSPy execution, caching, parsing, and redaction remain in a hunt-side
  adapter. The core receives a `ModelResult` tied to an immutable evidence digest and a
  family-declared residual question.

#### Canonical records and schema choice

- **Context:** evidence records, facts, readiness receipts, and admission identities require
  deterministic bytes and closed family extensions.
- **Sources consulted:** Python 3.11 `json` documentation, RFC 8785, JSON Schema Draft
  2020-12, and the existing core serializer.
- **Findings:** Python's sorted-key compact JSON is sufficient for repeatable records inside
  the current Python boundary when non-finite numbers and unsupported objects are refused.
  RFC 8785 is stricter and useful for cross-language signatures, which are not required here.
  General JSON Schema validation would add a runtime dependency and permit a broader payload
  language than the current families require.
- **Implications:** v2 defines a narrow canonical JSON profile and closed typed `FieldSpec`
  values. Ordered transitions remain tuples; family payloads stay shallow and typed; complex
  structure is represented by semantic transitions and observations. Cross-language signing
  is a revalidation trigger rather than speculative scope.

#### Proof attachment boundary

- **Context:** execution-backed evidence may support blocking, but proof execution and
  rollout policy are outside this spec.
- **Sources consulted:** `search/verify.py`, `search/coordinator.py`, search tests, and
  `safety-net.md`.
- **Findings:** the verifier already produces a differential `demonstrated` outcome over
  affected and safe sides. The core needs only the immutable result identity, matched family
  and location, side digests, verifier revision, witness reference, and evidence-record
  digest.
- **Implications:** the core validates and attaches a proof record; it does not run or
  reinterpret the oracle. Execution-backed basis is necessary but does not by itself enable
  downstream BLOCK policy.

#### Readiness and admission ownership

- **Context:** repository admission exposed semantic failures that should have stopped the
  arm at recognition, transitions, or constraints.
- **Sources consulted:** development/admission runners, the 2026-10-31 handoff, and detection
  quality steering.
- **Findings:** artifact production and storage already belong to benchmark workflows.
  Contract validation, prerequisite freshness, denominator feasibility, pure scoring, and
  report validation are reusable core responsibilities.
- **Implications:** benchmark workflows persist immutable `ReadinessResult` and case-result
  artifacts. The core derives `passed`, `failed`, or `stale`, refuses later gates when
  prerequisites do not pass, and never mutates historical artifacts.

### Architecture pattern evaluation

| Option | Description | Strengths | Risks and limitations | Decision |
|---|---|---|---|---|
| Extend v1 in place | Add neutral fields and aliases to authorization records | Small initial patch | Dual sources of truth and permanent family leakage | Rejected |
| Parallel v2 package | Build a second neutral package and migrate later | Clean initial schema | Recreates parallel contracts and duplicated admission | Rejected |
| Versioned ports and adapters | Add v2 neutral contracts to core, migrate through explicit adapters, retain v1 read-only decoding | Preserves reusable machinery and enforces boundaries | Requires controlled schema and baseline migration | Selected |

### Design decisions

#### Decision: split deterministic packet from decision

- **Context:** model and proof adapters must not rewrite program-analysis evidence.
- **Selected approach:** `EvidencePacket` contains immutable deterministic semantics;
  `Decision` contains family code, neutral outcome, basis, and bounded scope;
  `EvidenceRecord` binds them by packet digest.
- **Rationale:** derived decisions can change while the underlying evidence identity remains
  stable and auditable.
- **Trade-off:** one additional aggregate type, offset by a clear mutation boundary.

#### Decision: family contracts are data, family reasoning stays outside core

- **Context:** the core must validate family vocabulary without implementing every
  vulnerability abstraction.
- **Selected approach:** an immutable `FamilyContract` declares ecosystems, shallow typed
  fields, roles, decisions, mappings, required evidence, completeness rules, residual
  questions, and named indeterminate reasons. Family adapters construct evidence and apply
  their algorithms.
- **Rationale:** the core can refuse undeclared roles, fields, decisions, and scopes without
  importing family logic.
- **Trade-off:** adding a new field kind changes the core schema and triggers revalidation;
  this is preferred to unrestricted `Any` payloads.

#### Decision: conformance uses two test-only semantic shapes

- **Context:** authorization alone cannot demonstrate neutrality, and the parked arm must
  not be revived through the core spec.
- **Selected approach:** test-only obligation and taint-flow contracts each supply positive,
  negative, and missing-evidence fixtures. They make no user-facing capability claim.
- **Rationale:** the pair exercises control/constraint and flow/sanitization shapes without
  target vocabulary or admission reuse.

#### Decision: model corroboration answers declared residuals only

- **Context:** Requirements 2.4 and 9.3–9.4 must not allow a model to fill missing required
  deterministic relations.
- **Selected approach:** each residual question declares deterministic prerequisites and
  allowed family decisions. A missing required prerequisite forces indeterminate. A valid
  model result may produce model-corroborated advisory evidence but never execution-backed
  basis.
- **Rationale:** this restores DSPy augmentation without treating plausible text as missing
  static evidence.

#### Decision: readiness persistence belongs to benchmarks

- **Context:** core-owned files or storage would duplicate run orchestration.
- **Selected approach:** the core defines and validates receipts and freshness; benchmark
  workflows write and load them.
- **Rationale:** separates pure contract logic from population custody and run persistence.

#### Decision: versioned canonical JSON profile, not a new serializer dependency

- **Context:** identical input must produce byte-identical records and stable digests.
- **Selected approach:** UTF-8 JSON with sorted keys, compact separators, preserved sequence
  order, no non-finite numbers, and explicit enum values. The schema version is part of every
  digestible aggregate.
- **Rationale:** uses the existing Python runtime and meets the current boundary without
  claiming RFC 8785 interoperability.

#### Decision: finite legacy migration

- **Context:** historical v1 evidence must remain readable without allowing two live write
  contracts.
- **Selected approach:** add v2, migrate authorization and benchmark adapters, stop v1
  writes, migrate downstream consumers, remove v1 public exports, and retain only a
  read-only legacy decoder/validator.
- **Rationale:** preserves historical artifacts while restoring one canonical write path.

### Risks and mitigations

- **Permanent dual contracts:** milestone explicitly stops v1 writes and removes v1 exports
  after an import census reaches zero.
- **Authorization vocabulary leaks into v2:** neutral-type review plus two unlike synthetic
  family conformance suites.
- **Model fills semantic holes:** family-declared residual prerequisites and core-side result
  validation.
- **Readiness becomes ceremonial:** later gates require current predecessor digests and
  refuse stale, failed, or absent receipts.
- **Historical comparability is lost:** v1 stays immutable and v2 creates a new baseline
  identity; cross-baseline trend comparison is refused.
- **Fact review attests prose but not content:** v2 review identity covers normalized facts,
  schema, scope, and review evidence together.
- **Proof result silently enables blocking:** proof attachment changes evidence basis only;
  rollout eligibility remains downstream.
- **Hidden training contamination:** the core validates declared lineage and population
  digests; external review remains the trust boundary for undisclosed training data.

### References

- [DSPy signatures](https://dspy.ai/3.0.4/learn/programming/signatures/) — structured,
  declarative model inputs and outputs.
- [DSPy modules](https://dspy.ai/3.0.4/learn/programming/modules/) — module composition and
  learnable program state.
- [Python 3.11 JSON](https://docs.python.org/3.11/library/json.html) — sorted keys, compact
  separators, and strict number handling.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) — evaluated but not adopted for
  the current single-runtime wire boundary.
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) — evaluated but not
  adopted for the bounded family-field contract.

---

## Review-gate contract closure (2026-10-31)

### Scope of this pass

- **Context:** the first merge draft covered all requirement IDs but several late validators
  received only digests or caller-produced summaries, so their stated revalidation behavior
  was not implementable from the interface.
- **Sources consulted:** the approved detection-core requirements, complete project steering,
  the merge draft, current core/benchmark seams already recorded above, and independent
  architecture, risk, and traceability reviews.
- **Decision:** keep the requirements and architecture boundary unchanged; repair the
  interfaces that must carry canonical objects and fix the label-custody order before task
  generation.

### Decision: admission receives a closed validation context

- `FamilyCatalog` is now a real immutable value with re-derived contract and catalog
  digests and exact family/version/ecosystem resolution.
- `AdmissionValidationContext` carries the actual catalog, fact packs, model declarations,
  lineages, and review/custody/provenance/proof policies. Authorization and scoring both
  re-derive its digest and validate the objects; a set digest is not treated as the set.
- The threshold set is a baseline identity. Its actual lineage targets the threshold-set
  digest and is validated before labels open.

### Decision: excluded-dependency behavior is typed

- A family role declares either product-or-reviewed-fact provenance or
  excluded-dependency-fact-only provenance.
- A dependency-fact-only relation cannot be complete from product-code evidence. Missing
  reviewed knowledge is an explicit incomplete reason; only a revalidated pack, fact, and
  structural match can make it complete.
- This closes the vendored-source boundary without importing dependency source or family
  algorithms into core.

### Decision: lineage binds model, matcher, and threshold behavior

- Lineage manifests name a subject; individual uses name the exact influenced artifact and
  resolve to current custody receipts.
- Model requests embed a frozen program declaration and the actual lineage used for prompt,
  examples, fitted components, and decision mappings.
- Fact matches bind matcher revision, matcher-behavior digest, and matcher lineage.
  Admission-label influence on matching behavior spends the population just as prompt,
  fact, threshold, or promotion influence does.

### Decision: provenance validation must resolve bytes

- Named provenance inputs use a closed role vocabulary and a manifest digest.
- Validation receives a resolver and trust policy and checks bytes, SHA-256, length,
  storage receipt, retention policy, trusted store, and size bound before accepting the
  stamp. Unreadable input cannot validate as a clean identity-only result.

### Decision: spend before label release

- Authorization returns a label-release request committed to the exact current custody
  head and authorization digest.
- The benchmark custodian compare-and-swap appends `AVAILABLE` to `SPENT` durably and only
  then releases label bytes. Scoring accepts that exact current-chain receipt and returns a
  report bound to it; it does not request a later spend.
- This removes the crash and concurrency window in which labels could be observed while the
  population still appeared available.

### Decision: fitted-component authorization replays probes

- Authorization receives probe plus observation pairs and calls the canonical evaluator.
  It does not accept caller-produced `passed` summaries.
- Derived probe digests must equal the fitted-component evidence, alongside disjoint
  repository holdout, fitting lineage, and the bound admission report.
- Contract, review policy, and custody policy are resolved from the same context bound into
  the admission report. The authorization API does not accept caller-selected alternatives.

### Decision: raw records share one validation composition seam

- Admission and push consumption previously had unequal validation context: admission could
  re-open facts and lineage while a consumer could still receive a raw `EvidenceRecord`.
- `validation.py` now owns `EvidenceValidationContext`, `EvidenceValidationInput`, and the
  composition validator over catalog, named provenance inputs, facts, model derivation,
  lineage, custody, and resolver trust. Both admission and consumer APIs call that seam;
  there is no constructible validated-token shortcut.
- Per-case fact/model tuples were removed in favor of the single validation envelope, so
  context membership and derivation replay have one source of truth.

### Decision: admission review is independently attestable

- The manifest and label-blind census each carry a payload digest and independence
  attestation. Their reviewer cannot equal the producer and must satisfy a context-bound
  review policy; the conflict disclosure is resolver-validated.
- A review flag or unattached digest is insufficient for criteria 12.1–12.2 and fails before
  feasibility or label release.

### Decision: lineage expectations bind the influenced artifact

- A matching manifest subject is not enough because an embedded receipt could name a
  different influenced artifact.
- Callers provide typed expectations containing purpose, artifact digest, and allowed use
  counts. Generic lineage validation checks every current-chain receipt against those
  expectations. Fact content forbids all labelled ancestry; model, threshold, matcher, and
  fitted-component validation protects the current evaluation population while allowing
  separately spent development populations.

---

## Post-spend case-release trust closure (2026-11-01)

### Scope of this pass

- **Context:** task 8.7 demonstrated that aggregate census cardinalities and a valid spend
  receipt do not authenticate which immutable operational result belongs to which released
  case role and pair. A caller could swap vulnerable/fixed payloads, recompute result
  digests, and change admission metrics while preserving every approved pre-label object.
- **Sources consulted:** requirements 12.1–12.6 and 15.1–15.5, the admission design and
  custody contracts, the task-8.7 implementation diff and adversarial review reproducer,
  and project steering on label isolation and fixed measurement.
- **Finding:** this is a design-contract gap, not a metric-algebra bug. The pre-label census
  correctly withholds per-case identities and labels; therefore it cannot also authenticate
  the post-opening mapping used for scoring.

### Decision: add an authenticated post-spend case release

- **Alternatives considered:** put per-case commitments in the pre-label census; trust
  caller-supplied case roles after a valid spend; or add a separate post-spend release.
- **Selected approach:** the custodian produces an independently attested
  `AdmissionCaseRelease` only after the exact label-opening spend. Each binding joins a case
  identity and released scope/role/pair to the exact result, evidence-input, change-input,
  and input-manifest identities that core re-derives during scoring.
- **Rationale:** the release preserves aggregate-only pre-registration while giving the
  scorer an authority for the association that determines every numerator and denominator.
- **Trade-offs:** admission orchestration gains one immutable artifact and review step. In
  exchange, case substitution, role swaps, cross-scope pair collisions, and rehashed payload
  swaps fail before any measurement is emitted.
- **Boundary:** core defines and validates the release; the benchmark custodian remains the
  sole producer, durable writer, and label releaser. No cryptographic signing system or
  population persistence moves into core.

### Revalidation impact

- Admission scoring and report assembly must consume and bind the release digest.
- Benchmark-owned guarded custody must produce the release after the winning spend and
  prove crash/concurrency behavior at that external boundary.
- The pre-label census and feasibility contracts remain unchanged and label-blind.

---

## Authoritative admission replay closure (2026-11-01)

### Scope of this pass

- **Context:** task 8.9 showed that a structurally valid, self-consistent report cannot be
  authenticated later without the authoritative manifest, denominator, readiness,
  preparation, spend receipt, case release, and case results from which it was derived.
- **Finding:** contextual report validation inside the scoring call fixed local gate forgery
  but did not give task 8.10 a safe consumer contract. Accepting a bare report would either
  trust its digest as a capability or require every consumer to recover unbound inputs.
- **Classification:** specification conflict at the 8.9/8.10 boundary, not an isolated code
  defect. The report is result data; later authorization needs replayable evidence.

### Decision: carry and independently replay authoritative inputs

- **Alternatives considered:** treat `report_digest` as an authorization token; add more
  nested evidence to the report; make every fitted-component caller pass the original inputs
  separately; or return one immutable replay bundle from scoring.
- **Selected approach:** `score_admission` returns `AdmissionReplay`, containing the exact
  frozen authoritative inputs and the derived report. `validate_admission_replay` accepts
  only that bundle plus independently supplied current context, custody, and content
  resolution, re-runs the full derivation, and compares exact output.
- **Rationale:** the bundle prevents accidental input loss without promoting a digest or
  caller-provided aggregate into a capability. Current external trust state remains an
  explicit validator input.
- **Model applicability closure:** model success is mandatory when a model is frozen in the
  baseline or validated claimed-scope calls occurred. Configured zero-call, missing model
  threshold, or failed declared calls force `NO_GO`; undeclared claimed-scope calls are
  refused before report production, and out-of-scope-only calls do not alter the arm's gate.
- **Boundary:** replay production remains part of task 8.9. Task 8.10 consumes and validates
  the replay before fitted-component checks and refuses raw reports.
