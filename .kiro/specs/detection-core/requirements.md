# Requirements Document

## Project Description (Input)

**Who has the problem:** the maintainer of OpenUltraSAST. The intended detection loop is
to augment family-specific model programs with deterministic program-analysis evidence.
Today that loop cannot be extended safely because the shared core embeds authorization
vocabulary, semantic gaps surface only during repository admission, and a clean-looking
zero can still hide a failure before the model receives useful evidence.

**Current situation:** the instrument-verified 2026-10-31 authorization diagnosis showed
two different failures. Framework-mediated reachability stopped before protected
operations, and paths that survived still lacked the constraint semantics needed to
distinguish vulnerable and fixed code. These are useful limits of the deterministic
evidence producer, not a reason to require it to become a complete vulnerability prover.
The core must expose such limits early and give each vulnerability family a stable way to
interpret the evidence without translating its semantics into authorization terms.

**What should change:** the detection core shall provide a family-neutral evidence and
verdict envelope. Deterministic analysis shall contribute typed transitions, effects,
provenance, and explicit completeness. Each vulnerability family shall define its security
object and decision vocabulary and may use a bounded model program to answer residual
questions over that evidence. A staged readiness contract shall stop a family at the first
failing semantic layer, before population-level admission is attempted.

**Evaluation-admission V3 amendment, 2026-11-06:** the validated version-two admission
contract pools all claimed scopes and represents one arm. The approved replacement benchmark
requires a new contract that evaluates multiple component and combined arms under one population
spend while preserving an independently interpretable result for every exact vulnerability-family
and ecosystem scope. Existing version-two evidence remains historical and unchanged.

## Boundary Context

- **In scope**: the family-neutral evidence, outcome, trace, coverage, provenance, budget,
  staged-readiness, admission, measurement, fact-pack, model-handoff, and consumer
  contracts; family conformance requirements; failure-visible semantic-stage accounting;
  and the versioned exact-scope, multi-arm evaluation-admission validation and replay contract.
- **Out of scope**: vulnerability-family detection algorithms and prompt content;
  framework-specific fact content; model optimization; analysis of vendored dependency
  source; the pre-push transaction and rollout policy; proof execution; enabling a new
  vulnerability family for users; population sourcing, curation, reservation, licensing,
  and lifecycle; durable object-store or compare-and-swap adapters and bucket administration;
  detector execution or isolation; observation storage, access enforcement, and retry
  orchestration; workflow heartbeat and status presentation; and operator notifications.
- **Adjacent expectations**: the existing deterministic analysis is an evidence producer,
  not a required complete prover; family-specific DSPy programs may consume the evidence
  packet under the model-handoff contract; proof-based blocking remains a separate
  consumer. Benchmark-owned workflows supply the reviewed population, lifecycle, custody,
  sealed-observation, access-control, and post-spend release evidence that the core validates;
  the core does not create or operate those workflows. A parked arm remains parked unless a
  separately reviewed strategy creates a new arm, baseline, and admission population.

## Requirements

### Requirement 1: Family-neutral evidence record
The detection core shall define one canonical evidence record for every examined security
question within an analyzed change.
1. When a security question is analyzed, the detection core shall produce a canonical
   evidence record carrying the family identity, security-object identity, analyzed scope,
   ordered semantic transitions, observations with provenance, completeness reasons,
   family decision, neutral outcome, evidence basis, and input digests.
2. When a transition or observation is derived from product code or reviewed semantic
   knowledge, the detection core shall record its semantic role, source location,
   provenance, and completeness independently of every other transition or observation.
3. When a family supplies family-specific evidence fields, the detection core shall
   preserve those fields under the declared family schema without requiring them to use
   another family's vocabulary.
4. The detection core shall serialize every evidence record deterministically, so that
   identical inputs produce byte-identical records.

### Requirement 2: Neutral outcome and evidence basis
The detection core shall separate a family-specific decision from the neutral outcome and
the basis supporting that outcome.
1. When a family reaches a decision, the detection core shall record exactly one neutral
   outcome of violation, satisfied, or indeterminate and shall retain the family's own
   decision code separately.
2. When an outcome is satisfied, the detection core shall report the exact bounded scope
   over which satisfaction was established and shall not present it as repository-wide
   safety.
3. When evidence is incomplete for the family decision, the detection core shall return
   indeterminate with every named incompleteness reason.
4. If a required semantic relation is unavailable or ambiguous, the detection core shall
   prevent that missing relation from creating a violation or satisfied outcome.
5. When an outcome is reported, the detection core shall identify whether its basis is
   deterministic analysis, model corroboration, or execution-backed proof.

### Requirement 3: Vulnerability-family conformance contract
The detection core shall require every vulnerability family to declare the meaning and
limits of the evidence it consumes and the decisions it produces.
1. When a family is registered, the detection core shall require its family and schema
   versions, claimed ecosystems, security-object definition, accepted semantic roles,
   decision vocabulary, neutral-outcome mapping, completeness conditions, and named
   indeterminate reasons.
2. When a family claims a violation or satisfied outcome, the detection core shall require
   the family contract to identify the minimum evidence and completeness conditions for
   that outcome.
3. When a family receives evidence outside its declared ecosystem or schema scope, the
   detection core shall report the question as unsupported rather than applying a
   different family's interpretation.
4. If a family decision code, evidence field, or semantic role is not declared by the
   family contract, the detection core shall refuse the result.
5. The detection core shall demonstrate conformance with at least two reference families
   that use materially different security objects before the family-neutral contract is
   declared ready for downstream family specifications.

### Requirement 4: Typed semantic transitions and effects
The detection core shall preserve reviewed semantic knowledge needed to connect product
code across framework and dependency boundaries without analyzing vendored source.
1. When reviewed semantic knowledge supplies a registration, invocation, call, return,
   value transformation, operation effect, or constraint effect, the detection core shall
   record the typed relation and the supplying fact identity in the evidence record.
2. When a typed relation is complete only under stated conditions, the detection core shall
   retain those conditions and shall mark the relation incomplete when they are not met.
3. If multiple reviewed relations conflict or match ambiguously, the detection core shall
   report the ambiguity and shall not choose a complete relation silently.
4. When vendored source is excluded, the detection core shall require a reviewed semantic
   relation for any dependency behavior needed by a determinate family decision.

### Requirement 5: Coverage and instrument accounting
The detection core shall account for every input and semantic stage it did or did not use,
so a zero result is never indistinguishable from unread or unmodeled input.
1. When a change is analyzed, the detection core shall report counts for inputs read,
   security questions formed, semantic sites recognized, transitions materialized,
   security objects constructed, constraints evaluated, determinate outcomes, and findings
   emitted.
2. When product-code or fact-derived relations are considered, the detection core shall
   assign each relation exactly one complete, incomplete, or unresolved outcome.
3. If a semantic site, transition, security object, or constraint cannot be modeled, the
   detection core shall report the specific missing relation rather than interpreting its
   absence as safe.
4. If any tracked input file is read as zero bytes or cannot be opened, the detection core
   shall fail the run as an instrument failure rather than reporting a clean result.
5. When a stage produces zero outputs, the detection core shall identify the last stage
   with verified nonzero input and the first stage that failed to produce its expected
   output.

### Requirement 6: Measured budget and change scoping
The detection core shall derive its time budget from measurement, not from a fixed constant.
1. When a change is analyzed, the detection core shall measure and record reply time and
   change complexity, including changed regions, transition count, and changed size.
2. When a workload-class budget is published, the detection core shall disclose the sample
   count, percentile, reference workload, reference hardware, and derived budget.
3. When a change exceeds its measured workload-class budget, the detection core shall fail
   the budget gate naming the change, elapsed time, and budget derivation exceeded.
4. While a push is analyzed, the detection core shall limit analysis to regions affected
   by the change and shall record the scope it used.

### Requirement 7: Verdict contract
The detection core shall distinguish supported defect claims, bounded satisfaction, and
bounded silence.
1. When the detection core reports a defect, the claim shall carry its evidence basis, an
   exact location tied to the change, and the complete evidence record supporting the
   claim.
2. When the detection core reports satisfaction, the claim shall carry the completed
   security questions and the bounded scope over which they were decided.
3. When the detection core cannot decide a question, it shall report that question as
   indeterminate with its coverage reasons and shall never present it as clean.
4. If a claim depends on an incomplete or unresolved semantic relation, the detection core
   shall expose the affected question as bounded silence unless another complete path
   independently supports the claim.

### Requirement 8: Staged readiness and promotion
The detection core shall require a vulnerability-family arm to pass each semantic readiness
stage before it can advance to broader evaluation.
1. When an arm begins development, the detection core shall require separate readiness
   results for instrument validity, semantic recognition, transition construction,
   security-object and constraint evaluation, vulnerable/fixed pair behavior, development
   population behavior, fresh admission, and consumer integration.
2. When a readiness stage is evaluated, the detection core shall require a positive case,
   a negative case, and an ambiguity or missing-evidence case appropriate to that stage.
3. If a readiness stage fails, the detection core shall stop promotion at that stage and
   shall report the failing semantic layer and named correction lever.
4. If any prerequisite readiness result is missing, stale, or failed, the detection core
   shall refuse to run a later population or integration gate as evidence of readiness.
5. When a semantic change invalidates an earlier readiness result, the detection core shall
   mark every dependent later result stale.
6. When a family passes a stage, the detection core shall preserve the fixtures and results
   as regression evidence without treating them as fresh admission evidence.

### Requirement 9: Model-augmentation contract
The detection core shall support bounded family-specific model reasoning over deterministic
evidence without allowing model output to rewrite that evidence.
1. Where a family uses a model program, the detection core shall present the canonical
   evidence record, its completeness state, the family contract, and the residual question
   to be answered.
2. When a model program returns a family decision, the detection core shall preserve the
   model response, program and configuration identities, evidence-record digest, and
   declared decision mapping.
3. If deterministic evidence is incomplete, the detection core shall prevent a model
   response from converting the affected question into a satisfied outcome or a
   proof-backed violation.
4. When model output supports an advisory claim, the detection core shall label the claim
   as model-corroborated and shall keep it distinct from deterministic and execution-backed
   claims.
5. The detection core shall not allow a model to propose and independently adjudicate the
   same claim within one evidence path.
6. The detection core shall reserve blocking verdicts for execution-backed proof with a
   differential witness.

### Requirement 10: Provenance and digests
The detection core shall stamp every evidence record and verdict with the identities of its
inputs.
1. When an analysis is recorded, the detection core shall include the analyzer revision,
   family-contract digest, fact-set digest, acquisition-record digest, configuration
   digest, population digest, and per-change input digest.
2. When an evidence record uses reviewed semantic knowledge, the detection core shall
   include the semantic pack and fact identities needed to reproduce each derived relation
   or effect.
3. When a model program contributes a decision, the detection core shall include the model,
   program, prompt, and configuration identities needed to reproduce the call.
4. If any recorded digest or semantic fact identity cannot be re-derived from the named
   inputs, the detection core shall refuse the result rather than accept it.

### Requirement 11: Reviewed semantic fact packs as the extension point
The detection core shall admit family and ecosystem knowledge only through reviewed,
versioned semantic fact packs over the family-neutral contract.
1. When a semantic fact pack is admitted, the detection core shall validate its schema
   version, claimed family and ecosystem scope, stable fact identities, declared semantic
   roles, and review evidence.
2. When a semantic fact matches analyzed product code, the detection core shall permit the
   consuming family to record the corresponding transition or effect only with the matching
   evidence and fact provenance attached.
3. The detection core shall not allow a name-only match without the fact's required
   structural evidence to create a complete semantic relation or determinate outcome.
4. If a semantic fact has an undeclared role, unknown field, invalid scope, missing review
   evidence, or inconsistent digest, the detection core shall refuse the pack.
5. When admitted knowledge is insufficient to resolve a semantic relation, the detection
   core shall preserve the partial evidence record and report the relation as incomplete or
   unresolved.
6. The detection core shall report, per arm, the vulnerability families and ecosystems the
   arm claims, so admission and rollout numbers are never read across unsupported scopes.

### Requirement 12: Admission gate contract
The detection core shall gate every generalization claim on completed readiness stages and
a reviewed untouched population whose denominator matches the arm's declared scope.
1. When an arm is proposed for consumer use, the detection core shall require a reviewed
   manifest naming the frozen analyzer, family contract, model program where applicable,
   facts, acquisition, configuration, claimed families, claimed ecosystems, denominator
   policy, readiness results, and untouched admission population before any admission
   label is opened.
2. The detection core shall consume admission manifests without producing, mutating, or
   re-labeling them and shall refuse manifests that are unreviewed, label-exposing,
   acquisition-changed, or spent.
3. When an admission manifest is validated before label opening, the detection core shall
   verify that every pre-registered success threshold is arithmetically reachable under the
   declared family, ecosystem, and denominator policy.
4. If a threshold cannot be reached even when every in-scope case succeeds, the detection
   core shall refuse the admission configuration rather than run or report a misleading
   no-go result.
5. When a population contains cases outside an arm's declared scope, the detection core
   shall score quality gates on the pre-registered in-scope denominator and shall report
   whole-population coverage separately.
6. When admission evidence is scored, the detection core shall report paired
   vulnerable/fixed behavior, ordinary false alarms, semantic-stage coverage, model-call
   outcomes where applicable, and every budget, instrument, and quality gate as an
   evidence-backed go or no-go result.

### Requirement 13: Separation of development and evaluation
The detection core shall prevent evaluation labels from influencing an arm before its
generalization claim is scored.
1. The detection core shall prohibit prompts, examples, thresholds, fitted models, semantic
   facts, or decision mappings whose preparation data includes admission labels.
2. When a fitted component is proposed, the detection core shall require reversed-pair
   probes, repository-held-out development evaluation, and admission on an untouched
   population before any generalization claim is made.
3. When semantic knowledge is acquired, the detection core shall require source,
   documentation, or independently reviewed behavioral evidence that is isolated from
   vulnerability, fix-location, and ordinary-change labels.
4. If evaluation labels influence semantic fact content, matching behavior, prompt
   content, examples, thresholds, or promotion, the detection core shall mark the affected
   population spent and shall refuse it for admission.

### Requirement 14: Consumer and re-parenting contract
The detection core shall be the single contract that existing and future detection specs
reuse.
1. The detection core shall define the interface through which the pre-push transaction
   consumes evidence records and verdicts within its deadline.
2. The detection core shall define the interface through which proof-based blocking
   evidence attaches to an existing claim.
3. When an existing arm's behavior is described, the detection core shall require that
   description to be expressed over the family-neutral contract rather than as a separate
   runner contract.
4. When a consumer receives bounded silence caused by missing semantic knowledge, the
   detection core shall require the consumer to preserve the named coverage reasons.
5. When a family specification is created, the detection core shall require it to identify
   its family contract, readiness fixtures, development population, and admission boundary.

### Requirement 15: Fixed measurement schema
The detection core shall require one fixed measurement schema for every detection number.
1. When any detection result is reported, the detection core shall require population and
   freeze digests, claimed family and ecosystem scope, denominator policy, family decision
   vocabulary, neutral outcomes, evidence bases, every rate with its sample count and
   uncertainty interval, coverage, instrument failures, model-call failures, and runtime.
2. When semantic relations participate in an arm, the detection core shall require the
   report to include sites considered, sites recognized, transitions completed, security
   objects constructed, constraints evaluated, determinate outcomes, and unresolved counts
   by named reason.
3. When a measurement changes population, denominator policy, claimed scope, family
   contract, fact schema, model program, or outcome mapping, the detection core shall treat
   the result as a new baseline and shall not present it as a trend against the previous
   baseline.
4. When a zero or clean-looking result is reported, the detection core shall require proof
   that every tracked input was read and that every prerequisite semantic stage executed.
5. When a later-stage metric is reported, the detection core shall include the results and
   digests of every prerequisite readiness stage.

## Evaluation-Admission V3 Amendment

Requirements 16–20 extend Requirements 12 and 15 for a new evaluation-admission contract. Requirements 1–15 and completed version-two evidence retain their existing meaning, identities, and validation behavior; the amendment does not reinterpret or upgrade them.

### Requirement 16: Versioned evaluation-admission compatibility
The detection core shall provide a new evaluation-admission contract for exact-scope, multi-arm qualification without changing the meaning or validation of historical admission artifacts.

#### Acceptance Criteria
1. When a new evaluation admission is requested, the detection core shall validate it under a distinct contract version and shall keep every earlier admission contract independently replayable.
2. The detection core shall preserve the accepted bytes, digests, decisions, and replay behavior of existing version-two admission artifacts.
3. If pooled version-two evidence is presented as exact-scope version-three evidence, the detection core shall refuse the conversion and shall require a new baseline evaluated under the new contract.
4. If an admission artifact names an unknown, mixed, or incompatible contract version, the detection core shall refuse it rather than infer a compatible shape.
5. When a population, evaluation plan, arm identity, claimed scope, denominator policy, threshold set, judgment vocabulary, analyzer identity, fact identity, configuration identity, registered budget, execution identity, outcome mapping, or combination rule changes, the detection core shall require a new baseline identity.
6. The detection core shall prevent an insufficient result, impaired result, aggregate result, incomplete arm result, raw report, or other partial artifact from authorizing consumer use.

### Requirement 17: Reviewed multi-arm plan and atomic spend authority
The detection core shall bind every arm evaluated against one untouched population to a reviewed label-blind plan and one atomic admission spend.

#### Acceptance Criteria
1. When an evaluation plan is registered before label access, the detection core shall require a reviewed label-blind plan naming the population, input-set identity, every component arm, every combined arm, and every expected observation slot.
2. When an arm enters an evaluation plan, the detection core shall require its immutable baseline identity, exact claimed family-and-ecosystem scopes, denominator policy, thresholds, sufficiency rules, outcome mapping, and combination lineage where applicable.
3. When the label-blind plan is reviewed, the detection core shall evaluate threshold reachability and evidence sufficiency independently for every planned arm and exact claimed scope.
4. If any planned arm or claimed scope cannot meet its registered minimum-size, threshold-reachability, or interval-precision rule, the detection core shall report that arm and scope as insufficient and shall refuse the shared population spend.
5. When every planned observation is complete and before label access, the detection core shall require an admission authority reviewed independently from its producer that binds the feasible plan to the exact completed observation identities and the current population custody state.
6. If an expected observation is absent, unreadable, changed, associated with another arm, input, or plan, or inconsistent with the feasible plan, the detection core shall refuse admission authorization.
7. When shared labels are released, the detection core shall require one admission preparation, one exact monotonic population transition, and one resulting label-release receipt binding every planned arm.
8. If the custody head is stale, the transition is not the exact available-to-spent successor, the receipt is absent or mismatched, or availability is later restored, the detection core shall refuse label release and scoring.
9. The detection core shall not authorize a partial spend for a subset of planned arms or scopes.
10. While the population remains unspent, the detection core shall permit admission reuse only when raw observations and population-specific diagnostics remain unavailable to detector development and only closed process status, counts, and digests are exposed.
11. If raw observations or population-specific diagnostics are inspected, or an arm, plan, configuration, registered budget, or execution identity changes after an attempt, the detection core shall require a development or spent disposition and shall refuse that population for admission.
12. When a pre-spend attempt is retried, the detection core shall accept the retry only under the exact unchanged population, plan, arms, inputs, configuration, registered budgets, and execution identities.

### Requirement 18: Exact-scope denominators and whole-population coverage
The detection core shall derive qualification independently for each arm's exact vulnerability-family and ecosystem scope while preserving separate whole-population coverage.

#### Acceptance Criteria
1. When quality is evaluated, the detection core shall derive one complete standard metric set for every exact arm, vulnerability-family, and ecosystem scope declared in the reviewed plan.
2. When recall or pair correctness is derived for a scope, the detection core shall use only vulnerable and fixed cases independently verified for that exact family and ecosystem.
3. When ordinary false alarms are derived for an arm, the detection core shall count each eligible ordinary push once for every family claimed by that arm in the push's reviewed ecosystem and shall not project it into another ecosystem.
4. When precision is derived for a scope, the detection core shall use only findings and cases assigned to that exact arm, family, and ecosystem under the reviewed denominator policy.
5. When one underlying push contributes to multiple verified scoped denominators, the detection core shall count it once in whole-population coverage.
6. When a scoped metric is reported, the detection core shall include its numerator, denominator, value, sample count, and Wilson 95% interval under the fixed metric algebra.
7. Where an overall aggregate is reported, the detection core shall identify its constituent arms and scopes, sample counts, and weighting and shall not attach a gate or authorization decision to the aggregate.
8. If a post-spend scoped denominator is zero or differs from the reviewed label-blind census and feasible plan, the detection core shall refuse the evaluation as invalid rather than report insufficient, go, or no-go.

### Requirement 19: Version-three case release, arm results, and proof binding
The detection core shall validate post-spend evidence separately for every planned arm while preserving shared population custody and combination lineage.

#### Acceptance Criteria
1. When post-spend cases are released, the detection core shall require one version-three case-release graph reviewed independently from its producer and bound to the reviewed evaluation plan, shared spend, and exact completed observations.
2. When a case is released for an arm, the detection core shall bind its arm identity, exact scope, role, pair identity, result, evidence, change inputs, reviewed input manifest, and release review.
3. If a version-two case release is supplied to a version-three evaluation, the detection core shall refuse it rather than reinterpret it under the new contract.
4. When a combined arm is evaluated, the detection core shall preserve every component arm's observations, metrics, gates, and decision and shall report the registered combination lineage.
5. If a combined result omits, replaces, or contradicts a required component result, the detection core shall refuse the combined evaluation.
6. While ground-truth roles remain sealed, the detection core shall treat every label-blind proof candidate as non-authoritative for demonstrated status.
7. When a proof-backed status is derived after case release, the detection core shall require an exact validated proof attachment matching the released family, scope, pair roles, change inputs, finding location, differential record, control binding, producer, verification receipt, and trust policy.
8. When a combined arm retains proof evidence, the detection core shall require the identical validated proof candidate from the matching component observation and shall prevent the combined arm from creating or transferring proof evidence.
9. If proof is absent or inconclusive, the detection core shall retain the finding as not demonstrated.
10. If a proof attachment is role-swapped, cross-family, cross-scope, location-mismatched, or bound to unrelated inputs or controls, the detection core shall refuse the attachment as invalid and shall not count it as demonstrated.
11. The detection core shall not allow one planned arm's valid result to hide another planned arm's missing, invalid, or failed result.

### Requirement 20: Complete evaluation reports and replay authority
The detection core shall make the complete multi-arm evaluation replay the only admission artifact capable of authorizing downstream consumption.

#### Acceptance Criteria
1. When a planned arm completes evaluation, the detection core shall report one go or no-go decision for every exact claimed scope from that arm's validated instrument, budget, readiness, and quality gates.
2. The detection core shall reserve go and no-go for completed quality evaluations and shall keep pre-spend insufficiency, unread input, skipped stages, incomplete arms, and other instrument failures distinct from quality decisions.
3. When an evaluation report is produced, the detection core shall preserve per-arm scoped metrics separately from whole-population coverage, completed and deferred work, coverage funnels, instrument and model failures, runtime, and every degradation reason.
4. When every planned arm has a valid report, the detection core shall produce one complete evaluation replay binding the reviewed plans, feasibility results, admission authority, shared custody transition and receipt, the version-three case-release graph, independently valid per-arm scoped reports, and combination lineage.
5. If any planned arm report, mandatory gate, custody binding, case release, or replay component is missing or invalid, the detection core shall refuse evaluation completion.
6. When an evaluation replay is validated, the detection core shall rederive identities, counts, metrics, gates, and decisions from the canonical source artifacts rather than trust caller-supplied summaries.
7. When a consumer requests admission evidence, the detection core shall provide authorization only from a complete validated evaluation replay and shall not authorize from a per-arm report or aggregate alone.
8. When a zero or clean-looking arm result is included, the detection core shall require nonzero input-read evidence and execution evidence for every required stage before accepting the replay.

## Out of Scope
- The pre-push hook transaction, rollout policy, and capability registry.
- Vulnerability-family algorithms, prompts, examples, and optimization programs.
- Framework- or repository-specific semantic fact content.
- Analysis or indexing of vendored dependency source.
- Proof execution and sandbox orchestration.
- Enabling a vulnerability family for advisory or blocking use.
- Analysis-engine, frontend, graph, and family-internal implementation details.
- Population sourcing, human curation, permanent reservation, licensing, and lifecycle operations.
- Durable object-store or compare-and-swap adapter implementation, bucket administration, and retention configuration.
- Detector execution and isolation, observation storage and access enforcement, and retry orchestration.
- Workflow heartbeat and operator-status presentation, notification transport, and product rollout.
