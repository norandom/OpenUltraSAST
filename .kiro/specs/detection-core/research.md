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

---

## Downstream fact-authority boundary correction (2026-11-01)

### Scope and finding

- **Trigger:** task 9.4 could not migrate the legacy Express pattern pack without either
  inventing reviewer/custodian authority inside mapping or removing current recognition.
- **Instrument evidence:** the installed `express.json` was read at 963 bytes; the legacy
  and v2 fact suites passed 80 tests, confirming this was not an unread-input or broken-core
  diagnosis.
- **Finding:** the attempted core task decomposition put a production access-control
  contract, target authority, matcher, and artifact writer into the neutral core. That
  violated the engine/target split even though the generic validators were already sound.

### Decision: downstream ownership plus core conformance

- `access-control-prover` owns its production family contract, reviewed target packs,
  externally authenticated authority bundle, matcher, and canonical observation/match
  artifact writer. Its bootstrap trust remains external to the authenticated bundle.
- Detection-core owns only family-neutral validation and relation application. Its task 9.4
  becomes a conformance gate over downstream-produced objects and cannot import target code.
- The legacy recognition projection remains downstream-owned, byte-stable, and explicitly
  non-authoritative until cutover. Name-only recognition cannot produce complete v2 evidence.
- The downstream spec must first deliver authority, reviewed packs, persistence, and the
  structural adapter. Core conformance then proves those objects satisfy the generic
  contract before readiness, admission, or single-writer cutover can depend on them.

---

## Legacy namespace isolation and cutover-gate correction (2026-11-02)

### Scope and instrument evidence

- **Trigger:** task 10.1 could validate frozen v1 bytes and enumerate known writers, but
  repeated adversarial review showed that an exact semantic-use census over arbitrary
  Python aliases is equivalent to a partial Python interpreter. The bounded analyzer
  produced false zeroes for partial `try`/`finally` paths, generic alias escape, and
  module-valued `ImportFrom` bindings.
- **Instrument proof:** the final review opened 803 nonzero Python inputs totaling
  8,193,901 bytes with a 29-byte minimum; the focused migration suite passed 85 tests and
  the core suite passed 916. The failure is therefore in the census model, not unread
  input, stale fixtures, or a broken decoder.
- **Existing assets retained:** the exact-byte v1 trace/report decoder, hostile-byte and
  report-invariant tests, the frozen historical fixtures, the reviewed initial
  import/writer inventory, and the v2 contracts remain valid inputs.

### Architecture pattern evaluation

| Option | Description | Strengths | Risks and limitations | Decision |
|---|---|---|---|---|
| Continue alias interpretation | Extend the custom AST flow model until it recognizes more Python execution forms | Preserves mixed modules | Unbounded semantics; another construct can create a plausible zero | Rejected |
| Count every mixed-module import | Treat imports of shared modules such as `provenance` as v1 dependencies | Simple and conservative | V2-only users can never reach zero; gate measures import style rather than v1 dependency | Rejected |
| Explicit legacy namespace | Move v1 contracts and temporary write capability behind `openultrasast.core.legacy_v1`; keep only explicit compatibility shims until cutover | Syntactic, deletion-backed gate; no use-flow inference; preserves historical bytes | Requires one bounded namespace-isolation migration before consumer cutover | Selected |

### Decision: make legacy capability explicit and deletable

- `openultrasast.core.legacy_v1` temporarily owns all live v1 contract values and the only
  v1 serialization capability. Mixed v2 modules stop defining or re-exporting legacy
  symbols.
- The existing top-level v1 API remains byte- and name-compatible during migration, but its
  implementation is an explicit shim importing from `legacy_v1`. Production code may not
  use module-valued `openultrasast.core` imports or dynamic import/getattr to reach that
  shim; imports must name a submodule or symbol.
- The previously reviewed census becomes a frozen migration inventory. Every registered
  reader/writer is migrated to v2 or retired; new inventory entries are not a path to
  completion.
- The cutover checker parses import and call syntax only. It reports imports of the legacy
  namespace, temporary shim modules, top-level legacy symbols, and the explicit v1 writer
  facade. It does not infer runtime alias values.
- The zero gate additionally proves that the v1 writer facade and compatibility shim
  modules are deleted and no legacy symbol is importable from the top-level package. A
  surviving dependency therefore fails import instead of disappearing from a semantic-use
  census.
- `openultrasast.core.legacy` remains a separate read-only historical byte decoder. It has
  no contract constructors, serializer, converter, or v2 outcome mapping and survives the
  cutover.

### Boundary and task impact

- Detection-core owns namespace isolation, the frozen migration inventory, the syntactic
  boundary checker, top-level shim removal, and the retained decoder.
- Adjacent owners migrate their registered imports and writers; they do not extend the
  compatibility namespace.
- Task 10.1 must be re-planned as namespace isolation plus schema-routed historical reads.
  Task 10.2 may publish the v2 top-level only after inventory closure, syntactic zero,
  deletion of the v1 write/shim capability, and unchanged historical fixture hashes.

### Synthesis

- **Generalization:** absence is proved by removing a capability boundary, not by predicting
  every way Python can transport an alias. The same rule covers readers, writers, top-level
  compatibility names, and future adjacent consumers.
- **Build versus adopt:** Python's standard `ast` is sufficient for the intentionally
  syntactic boundary check. A new import-lint or abstract-interpretation dependency would
  either duplicate the project rule or reintroduce semantic-use analysis and is not
  adopted.
- **Simplification:** discard the custom lexical/control-flow census and its migration-only
  flow engine. Retain the reviewed inventory as evidence, then rely on explicit modules,
  forbidden dynamic access, import-failure tests, and deletion of the writer capability.

### Risks and mitigations

- **Hidden dynamic access:** production dynamic import/getattr of `openultrasast.core` is
  prohibited and checked syntactically; no runtime dataflow inference is attempted.
- **New unregistered v1 writer:** the compatibility namespace is closed, and only its
  explicit writer facade can serialize a v1 contract. Review and tests reject new direct
  compatibility exports or inventory growth.
- **Top-level compatibility masks incomplete migration:** the gate counts named top-level
  legacy imports and then proves those attributes are absent after cutover.
- **Historical artifacts become unreadable:** frozen trace/report bytes and hashes continue
  through the independent read-only decoder before and after namespace deletion.

---

## Gap analysis: exact-scope multi-arm evaluation admission V3 (2026-11-06)

### Scope, approval state, and instrument check

- **Feature type:** complex brownfield contract extension. Requirements 16–20 add a new
  evaluation-admission root beside the implemented V2 admission graph; they do not replace
  the family-neutral evidence contracts in Requirements 1–15.
- **Approval warning:** Requirements 16–20 are generated but not approved. This gap analysis
  is permitted to inform review, but `design.md` cannot be regenerated until the requirements
  are approved or `/kiro-spec-design detection-core -y` is invoked.
- **Discovery method:** integration-focused source inspection of the admission contracts,
  their tests, their only production authorization consumer, and the approved
  `valid-detection-benchmark` consumer design. No external dependency research was needed:
  the amendment is a standard-library Python contract, validation, and replay change.
- **Instrument proof:** the requirements (32,917 bytes), current design (130,524 bytes),
  existing research (45,818 bytes), approved valid-benchmark design (72,402 bytes), ten
  primary admission/core modules (166,630 bytes), and the relevant admission/measurement
  tests (270,157 bytes) were opened as nonzero inputs before interpreting gaps.

### Current architecture and reusable assets

The implemented V2 admission path is a closed canonical graph:

`BaselineIdentity` → reviewed `AdmissionManifestV2` and census → context validation and
pooled feasibility → one `AdmissionPreparation` → exact `AVAILABLE`-to-`SPENT` custody
receipt → independently reviewed `AdmissionCaseRelease` → revalidated case results →
one `AdmissionReportV2` → one `AdmissionReplay`.

The following machinery is reusable without changing its meaning:

- canonical JSON, content digests, closed-graph checks, exact-dataclass checks, and strict
  enum/type validation;
- `ScopeKey`, the fixed metric identifiers and algebra, Wilson 95% computation, readiness
  validation, review-independence attestations, content resolution, and provenance checks;
- the append-only custody log and exact monotonic `AVAILABLE`-to-`SPENT` receipt validation;
- case evidence, input, budget, coverage, and proof-attachment validation after a V3 release
  establishes the correct arm/scope association;
- V2 report and replay rederivation, which must remain independently replayable and
  byte-compatible.

The reusable implementation is not the V2 aggregate root itself. V2 has one arm identity,
assigns every metric rule the full claimed-scope tuple, pools capacities and cases across
those scopes, derives one unscoped result per metric, and emits one arm-level decision. That
shape cannot express the exact per-arm, family, and ecosystem claims required by V3.

### Requirement-to-asset map

| Requirement | Existing asset | Gap classification and impact |
|---|---|---|
| 16.1–16.4 Version isolation | Canonical schemas, exact-type replay validation, historical decoder patterns | **Missing / compatibility constraint:** no V3 root or explicit version dispatcher exists. Extending V2 dataclasses changes accepted bytes and digests; inferred conversion would make pooled evidence appear exact. |
| 16.5 Baseline identity | `BaselineIdentity` binds one arm, population/freeze, scopes, facts, analyzer, configuration, denominator, thresholds, and outcomes | **Missing:** plan, input-set, sufficiency, registered budget, execution, observation-set, and combination-rule identities are absent. These must belong to a distinct V3 identity rather than changing V2. |
| 16.6 Non-authorizing partial artifacts | V2 replay, not a raw report, authorizes fitted-component use | **Partial:** there is no V3 completion root or closed status distinction for insufficiency, impairment, aggregates, incomplete arm results, and raw per-arm reports. |
| 17.1–17.4 Reviewed multi-arm preflight | Independent V2 manifest/census review and threshold feasibility | **Missing:** no reviewed plan containing every component/combined arm and observation slot; no per-arm/per-scope sufficiency rules; V2 feasibility sums capacities across selected scopes and therefore cannot veto the shared spend independently for each exact scope. |
| 17.5–17.6 Post-observation authority | V2 authorization revalidates context, feasibility, readiness, and custody | **Missing:** no second reviewed manifest binding the feasible plan to exact sealed observation identities, no observation-byte resolution, and no all-slot completeness check immediately before spend. |
| 17.7–17.9 Atomic shared spend | Exact V2 preparation and custody successor validation | **Constraint:** V2 `PopulationUseRequest` names one arm. No preparation/receipt binds every planned arm and scope, and no root rejects a partial subset while retaining one shared custody transition. |
| 17.10–17.12 Confidential retry/disposition | Append-only custody and lineage policies | **Missing / adjacent boundary:** core lacks typed retry identity and development/spent disposition validation for raw-observation access. The benchmark owns access enforcement and lifecycle events; core must validate their immutable authority and exact retry identity, not implement storage or access control. |
| 18.1–18.4 Exact scoped metrics | Fixed metric algebra, Wilson intervals, reviewed scope census, validated cases | **Missing:** `standard_metric_rules()` assigns all scopes to every rule; `MetricResult` and `AdmissionThreshold` have no scope key; context requires pooled rule scopes; feasibility and scoring derive once across the union. |
| 18.3, 18.5 Ordinary projection and whole coverage | Case roles and an intermediate whole-population funnel | **Missing:** ordinary cases lack a stable underlying-push identity that permits once-per-family projection inside the reviewed ecosystem while deduplicating the same push once for whole coverage. Whole-population evidence is not preserved in the final V2 report. |
| 18.6–18.8 Scoped reporting, aggregates, post-spend validity | Metric numerator/denominator/value/Wilson fields | **Partial:** metric arithmetic is reusable, but scope-qualified results and non-authorizing aggregate identities/weights do not exist. Post-spend zero or census mismatch must be invalid, not a zero-valued metric, insufficiency, GO, or NO-GO. |
| 19.1–19.3 V3 case release | Strong independent V2 release with exact role/pair/result/evidence/input binding | **Missing:** `ReleasedCaseBinding` has no arm identity, and the release binds one V2 manifest and authorization. Exact V2/V3 type separation is required. |
| 19.4–19.5 Combination lineage | No equivalent admission root | **Missing:** there is no graph preserving every component observation/report/gate while binding a combined arm to its registered deterministic lineage or detecting omission, replacement, and contradiction. |
| 19.6–19.10 Proof continuity | Strong `ProofAttachment` validation | **Partial:** the proof contract can be reused after V3 release, but no label-blind proof-candidate identity is carried from the component observation to prevent a combined arm from creating or transferring proof evidence. |
| 19.11 Arm independence | Exact V2 replay for one arm | **Missing:** no all-planned-arm cardinality and identity check prevents one valid report from hiding another arm's missing, invalid, or failed result. |
| 20.1–20.2 Scoped decisions and failure classes | V2 mandatory gates and GO/NO-GO derivation | **Missing:** V2 emits one pooled arm decision. V3 needs a completed decision per exact scope and separate non-quality states for insufficiency, unread inputs, skipped stages, impairment, and incomplete arms. |
| 20.3 Complete reports | `MeasurementRecordV2`; intermediate `AdmissionMetricEvidence` carries an extra whole funnel/runtime | **Partial:** completed/deferred work, whole coverage, degradation reasons, and complete instrument failures are not preserved in the final report; `_measurement()` currently supplies `instrument_failures=()`. |
| 20.4–20.7 Complete replay authority | `AdmissionReplay` rederives one V2 report from authoritative inputs | **Missing:** no multi-arm replay binds both reviewed stages, shared feasibility/authority/custody/release, all independently valid scoped reports, and combination lineage. `admission_fitted.py` accepts only V2 `AdmissionReplay` and derives authorization from its single report. |
| 20.8 Nonzero execution evidence | Coverage/input validation and clean-measurement checks | **Partial:** reusable case evidence exists, but V3 completion must require it independently for every arm and exact scope before accepting a clean-looking result. |

### Concrete integration surfaces

The V3 amendment affects these core responsibilities while retaining V2 definitions:

- `src/openultrasast/core/measurement.py`: reusable scope and metric algebra; new V3
  baseline, scope-qualified metric/policy/threshold, aggregate, and sufficiency contracts.
- `src/openultrasast/core/admission_review.py`: new reviewed two-stage plan and admission
  manifests with canonical per-arm plans and expected/actual observation bindings.
- `src/openultrasast/core/admission_feasibility.py`: independent feasibility witnesses for
  every arm and exact scope plus one shared non-spend result.
- `src/openultrasast/core/admission_context.py`: V3 plan, identity, policy, readiness,
  observation, and lineage validation without the V2 all-scopes-equal rule.
- `src/openultrasast/core/admission_spend.py`: a distinct V3 authority/preparation binding
  every planned arm and the current custody head; V2 functions remain unchanged.
- `src/openultrasast/core/admission_case.py`: an arm-aware V3 case-release graph bound to
  the plan, exact observations, authority, and shared receipt.
- `src/openultrasast/core/admission_metrics.py`: exact-scope derivation, ordinary-push
  projection within ecosystem, whole-population deduplication, and proof-candidate
  continuity.
- `src/openultrasast/core/admission_report.py`: independently valid per-arm/per-scope
  reports, non-authorizing aggregates, and explicit non-quality failure classes.
- `src/openultrasast/core/_admission_replay.py`: one closed `EvaluationReplayV3` containing
  the complete shared graph and all planned reports.
- `src/openultrasast/core/admission_fitted.py`: explicit version dispatch; V3 authorization
  accepts only a complete validated evaluation replay and an exact arm/scope selection,
  never a raw report or aggregate.
- `tests/test_core_admission_*.py`, `tests/test_core_measurement*.py`, and frozen V2
  fixtures: compatibility, exact-scope algebra, all-arm completeness, mixed-version
  refusal, atomic-spend, proof-continuity, and replay conformance.

The approved benchmark remains a downstream consumer. Its current
`benchmarks/valid/admission_run.py`, `admission_scoring.py`, and `population_custody.py`
are V2 single-arm paths and stay compatibility-only. Population lifecycle, durable object
storage/CAS, observation access, detector execution, retry orchestration, and operator
presentation remain benchmark-owned and are not implementation work for this amendment.

### Implementation approach options

#### Option A: extend V2 contracts in place

Add arm/scope/plan fields to existing V2 identities, policies, manifests, releases,
reports, and replay.

- **Strengths:** smallest initial module count and direct reuse of current call paths.
- **Risks / limitations:** changes canonical V2 bytes and digests, makes exact-type version
  refusal ambiguous, overloads already dense single-arm modules, and risks accidental
  projection of pooled evidence. It conflicts with 16.1–16.4.
- **Effort / risk:** L / High; not a viable compatibility path unless Requirement 16 is
  weakened, which is not recommended.

#### Option B: create a fully parallel V3 stack and facade

Introduce an independent `evaluation_admission` facade and V3 modules for identity, plan,
feasibility, authority, release, metrics, reports, and replay.

- **Strengths:** clearest public version boundary, exact-type refusal, and protection of V2
  bytes and behavior; components are testable in isolation.
- **Risks / limitations:** duplicates canonical validation, custody, readiness, proof, and
  metric plumbing unless reuse is disciplined; two large stacks increase maintenance cost.
- **Effort / risk:** XL / Medium-High.

#### Option C: parallel V3 public roots with version-neutral internal helpers

Keep V2 and V3 aggregate roots, facades, schemas, and validators exact and separate. Reuse
or extract only helpers whose inputs and outputs have no serialized V2 identity, such as
Wilson arithmetic, review validation, custody-chain checks, proof validation, and canonical
collection validation.

- **Strengths:** preserves strict version boundaries and V2 replay while avoiding avoidable
  duplication; aligns with the current closed-graph and ports-and-adapters pattern.
- **Risks / limitations:** helper extraction can still change V2 behavior if performed
  before compatibility fixtures lock accepted bytes and errors; dependency direction and
  exact-type tests must be explicit.
- **Effort / risk:** XL / High.
- **Design-phase candidate:** this offers the best balance, using Option B-style public
  separation. It remains a candidate until the design review resolves the research items
  below.

### Complexity and risk

- **Effort: XL (2+ weeks).** The amendment adds two-stage review, exact-scope algebra,
  multi-arm completeness, one shared spend, a new release graph, per-arm reports, consumer
  dispatch, and a closed replay root across multiple existing contract modules.
- **Risk: High.** The main failure modes are silent V2 behavior drift, pooled-to-scoped
  misinterpretation, partial-arm authorization, stale observation/custody acceptance,
  ordinary-push double counting, and an aggregate or raw report becoming an authorization
  token.

### Design-phase recommendations and research needed

1. Freeze representative accepted V2 canonical bytes, digests, decisions, validation
   failures, and replay outputs before extracting helpers. Treat any change as a regression.
2. Define one explicit V3 facade/schema family and refuse unknown, mixed, subclassed, or
   substituted V2/V3 roots at every public boundary.
3. Resolve the exact V3 module split and aggregate roots: per-arm plan, reviewed plan
   manifest, observation binding, admission authority/preparation, V3 release, scoped
   report, and evaluation replay.
4. Define the observation-slot identity and content-resolution contract, including how an
   observation proves arm, input, execution, budget, configuration, and plan identity
   without exposing raw diagnostics before spend.
5. Define a stable underlying-push identity for ordinary projection and whole-population
   deduplication, including multi-family fixes and ecosystem review authority.
6. Define sufficiency and interval-precision rules as reviewed per-arm/per-scope contracts,
   separate from post-spend invalidity and completed GO/NO-GO gates.
7. Define the benchmark-supplied retry/development disposition evidence that core validates;
   do not move durable lifecycle, access enforcement, or CAS implementation into core.
8. Define component-to-combined observation lineage and proof-candidate identity so a
   combined arm can retain only the identical component candidate and cannot suppress a
   component report.
9. Define V3 fitted-component consumption as complete-replay validation plus exact arm/scope
   selection. Per-arm reports, aggregates, incomplete roots, and V2 artifacts cannot
   authorize a V3 consumer.
10. Derive the V3 conformance suite from 16.1–20.8: frozen V2 compatibility; unknown/mixed
    version refusal; per-arm/per-scope feasibility; missing observation and stale custody
    refusal; one atomic spend; exact ordinary projection/dedup; post-spend zero invalidity;
    proof continuity; all-arm completion; and nonzero input/stage execution evidence.

### Gap conclusion

The current implementation provides strong canonical validation, custody, evidence,
metric, proof, and replay primitives, but its V2 admission root is structurally unable to
represent an exact-scope multi-arm evaluation. The gap is therefore an additive versioned
contract and replay graph, not a correction to the V2 metric formula. The design should
retain V2 unchanged, introduce exact V3 roots, and reuse only version-neutral internals.
Design generation remains blocked on approval of Requirements 16–20.

---

## Design discovery and synthesis: evaluation-admission V3 (2026-11-06)

### Summary

- **Feature:** detection-core evaluation-admission V3 amendment.
- **Discovery scope:** complex integration and immutable-contract version extension.
- **Selected pattern:** parallel V3 public aggregate roots with reuse limited to
  version-neutral canonical, review, custody, proof, readiness, and metric primitives.
- **Key findings:** V2 aggregate roots cannot be generalized without changing their bytes;
  the V3 plan needs a non-circular declaration/baseline identity; and one complete replay,
  rather than a report or aggregate, must be the only downstream authorization source.

### Research log

#### Version and canonicalization boundary

- **Context:** 16.1–16.4 require historical V2 bytes, digests, decisions, and replay to
  remain unchanged while V3 refuses mixed or inferred shapes.
- **Sources consulted:** current V2 canonical and admission modules, frozen-dataclass and
  exact-type patterns in the repository, Python 3.11 JSON documentation, and RFC 8785.
- **Finding:** the existing sorted-key compact JSON profile is sufficient for the current
  single-Python-runtime contract. Adopting JCS would create a second canonical profile and
  risk changing V2 bytes without satisfying an additional requirement.
- **Implication:** `evaluation_admission.py` is the only V3 facade. V3 validators require
  exact dataclass types and exact V3 schema constants. A read router may select a validator
  by schema but never converts V2 to V3.

#### Non-circular plan and baseline identity

- **Context:** every arm needs an immutable baseline, and a change to the evaluation plan
  must start a new baseline without making the plan and baseline digests recursive.
- **Finding:** a reviewed plan declaration can be hashed before baseline construction. It
  contains the population, input set, arm configurations, combination rules, and expected
  observation slots. Each arm baseline then binds that declaration digest and its exact arm
  configuration digest.
- **Implication:** any plan or arm mutation changes the declaration and therefore every arm
  baseline, while the plan manifest can embed the derived baselines without a digest cycle.

#### Two-stage review and shared spend

- **Context:** arithmetic feasibility happens before detector execution; spend authority
  requires every exact sealed observation and the current custody head afterwards.
- **Finding:** one manifest cannot safely serve both moments. The second authority must
  resolve observation bytes and bind the earlier feasible plan rather than repeat or
  summarize it.
- **Implication:** `EvaluationPlanManifestV3` supports label-blind preflight;
  `EvaluationAdmissionManifestV3` binds exact sealed observations and retry/disposition
  evidence. `EvaluationAdmissionAuthorityV3` is constructible only when both validate.

#### Existing custody reuse

- **Context:** 17.7–17.9 require one atomic population transition binding all arms, while
  the existing custody graph already validates an exact monotonic transition.
- **Finding:** the existing request/receipt can remain unchanged if its influenced artifact
  is the V3 authority digest, which transitively commits to every planned baseline. A V3
  spend binding makes that transitive relationship explicit inside the replay.
- **Implication:** no second custody implementation is introduced. The benchmark remains
  the CAS writer and label releaser; core builds and validates the authority, preparation,
  receipt binding, and replay relationship.

#### Exact-scope projection and whole coverage

- **Context:** one underlying push may contribute to several verified family scopes while
  whole-population coverage must count it once.
- **Finding:** case identity alone is insufficient because vulnerable and fixed sides and
  several arm/scope projections can refer to the same push.
- **Implication:** V3 release bindings carry a separate `underlying_push_digest` and exact
  `ArmScopeKey`. Scoped metrics project from arm/scope bindings; whole coverage deduplicates
  only by the underlying push identity. Ordinary projection is limited to families claimed
  by the arm in the push's reviewed ecosystem.

#### Combination and proof continuity

- **Context:** a combined arm must preserve component results and cannot manufacture or
  transfer demonstrated proof.
- **Finding:** proof validation alone establishes attachment correctness but does not prove
  candidate continuity from a component observation to a combined observation.
- **Implication:** label-blind observations and released bindings carry a stable
  proof-candidate digest. Combination lineage names exact component observation digests;
  the combined arm may retain only an identical candidate named by a component.

### Architecture pattern evaluation

| Option | Description | Strengths | Risks / limitations | Decision |
|---|---|---|---|---|
| Extend V2 roots | Add plan, arm and scope fields to current types | Smallest initial file count | Changes V2 bytes and permits pooled/scoped ambiguity | Rejected |
| Fully parallel V3 implementation | Duplicate the entire validation stack | Strong version separation | Duplicates custody, proof, review and metric machinery | Rejected |
| Parallel V3 roots plus neutral helpers | Separate public schemas and aggregates; share only identity-neutral primitives | Preserves V2 and avoids duplicate trusted logic | Helper extraction needs frozen V2 regression evidence | Selected |

### Design decisions

#### Decision: one V3 facade and exact roots

- `evaluation_admission.py` exports preflight, authorization, score/replay, and replay
  validation. V2 admission entry points remain unchanged.
- V3 modules do not import V2 aggregate roots. `admission_fitted.py` exposes a separate V3
  consumer function rather than broadening the V2 function's accepted graph.

#### Decision: plan declaration precedes baselines

- `EvaluationPlanDeclarationV3` owns population, freeze, input set, arm configurations,
  expected observation slots, and combination declarations.
- `EvaluationBaselineIdentityV3` binds the declaration digest and one arm configuration.
  The reviewed manifest embeds both and proves the exact canonical derivation.

#### Decision: insufficiency is a pre-spend result, not a quality decision

- `EvaluationFeasibilityV3` contains exactly one row per declared arm/scope and derives one
  `may_spend` value. Any insufficient row makes it false and prevents preparation.
- GO and NO-GO occur only in completed post-spend scope reports. Instrument impairment,
  unread inputs, skipped stages, incomplete arms, and invalid post-spend denominators never
  map to those decisions.

#### Decision: reports are evidence; the complete replay is authority

- Per-arm scoped reports and optional aggregates are serializable evidence but cannot
  authorize consumers.
- `EvaluationReplayV3` binds both reviewed manifests, feasibility, authority, preparation,
  shared receipt, spend binding, V3 release, exact cases, all planned reports, and
  combination lineage. Validation rederives the graph and exact planned-arm cardinality.

#### Decision: aggregate has no decision field

- An aggregate identifies constituents, sample counts, weights, and derived values. Its
  type contains neither gates nor authorization decisions, preventing an aggregate from
  being mistaken for an admission result.

### Synthesis

- **Generalization:** expected observation slots, arm/scope keys, and complete replay
  cardinality are three applications of one closed-plan principle: later artifacts must be
  an exact projection of the reviewed plan, never a caller-selected subset.
- **Build versus adopt:** reuse the existing Python canonical, custody, review, readiness,
  proof, and Wilson primitives. Do not adopt a new serializer, workflow engine, object-store
  client, or transaction library because persistence and orchestration stay downstream.
- **Simplification:** use the existing custody request/receipt transitively through a V3
  authority and explicit spend binding; do not create a second custody state machine.
  Keep lifecycle/access enforcement outside core and validate only immutable disposition
  evidence supplied by the benchmark.

### Risks and mitigations

- **V2 drift during helper extraction:** freeze canonical V2 bytes, digests, decisions,
  failures, and replay outputs before extraction; run them after every shared-helper change.
- **Partial-arm authorization:** derive report and replay cardinality from the plan and make
  the complete replay the sole consumer input.
- **Observation substitution:** resolve nonzero bytes and require an exact one-to-one slot,
  arm, input, execution, budget, configuration, and digest match before authority.
- **Ordinary-push double counting:** separate scoped projection keys from the deduplicated
  underlying-push identity.
- **Combined proof fabrication:** require component observation lineage and identical
  proof-candidate identity before accepting a retained attachment.
- **Core absorbing benchmark workflow:** keep storage, CAS, access enforcement, retries,
  detector isolation, label joining, status, and presentation explicitly out of boundary.

### References

- [Python 3.11 JSON documentation](https://docs.python.org/3.11/library/json.html) —
  deterministic sorted-key compact serialization controls used by the existing profile.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) — evaluated but not adopted;
  cross-runtime canonical signatures are outside the current boundary.
- [Approved valid-detection-benchmark design](../valid-detection-benchmark/design.md) —
  downstream V3 consumer contract and ownership boundary.
