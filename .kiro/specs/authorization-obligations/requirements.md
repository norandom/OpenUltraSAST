# Requirements Document

## Introduction

AppSec engineers and maintainers of OpenUltraSAST scan web code, increasingly vibe-coded or agent-written, in which the dominant bugs are absences rather than flows: a handler queries a user-owned record without constraining it to the caller, a privileged route has no guard on its path, an identity is read from the request body instead of the authenticated context, a security control stays at its permissive default. Today the detector, the overlay, and the variant search model only source-to-sink flows, so these pairs score zero and cannot teach a mechanism (6 of 19 non-teaching vibe-py pairs; 15 of 29 agent-vfc rows carry absence labels). This spec adds obligations: an operation that must be discharged by a guard, an identity constraint, or a safe value before it is reached. The application's own policy, recovered from the consistency of its sibling handlers and optionally declared in a versioned file, says which operations carry which obligations. Violations are reported with the missing discharger and its evidence, measured leave-one-out on the absence pairs, and admitted into the detector through the existing improve-loop gate.

## Boundary Context

- **In scope**: obligated operations and discharger kinds as closed facts data; obligation shapes learned from trusted pairs; consistency detection across sibling handlers; an optional declared policy file with a closed schema; path-aware violation evaluation with a function-local degraded mode; obligation evidence rungs, report wording and worth-fixing weighting; a corpus recipe shape that keeps the handler's registration context; leave-one-out per obligation kind; an `obligations` improve lever; offline tests.
- **Out of scope**: flow taint, walker or sink facts; the call graph, path records and dominance computation (owned by `reachability-flow-model` and `guard-dominance-regime`); model-authored policy or shapes; sandbox proof of absence bugs; any merge gate; vendoring unlicensed code.
- **Adjacent expectations**: the entry-point mapper keeps providing routes with an access level and their decorators; the reachability spec provides entry-point-to-operation paths and the guard-dominance spec provides "a guard dominates the path"; the mechanism store, its deterministic ids and the lever contract from `corpus-seeded-mechanisms` are reused unchanged; the pair scorer accepts one additive label field; `local` remains the only slice that can fail CI.

## Requirements

### Requirement 1: Obligated operations and dischargers are closed facts

**Objective:** As a maintainer, I want the operations that carry an obligation and the ways an obligation can be discharged to be data, so that absence detection grows by adding facts rather than patterns.

#### Acceptance Criteria

1. The system shall load, per language, a closed set of obligated operation kinds: protected data read, protected data write, privileged action, security-relevant setting.
2. The system shall load, per language, a closed set of discharger kinds: path guard, identity constraint from authenticated context, ownership check, non-permissive value, validated input.
3. When a fact names an operation or a discharger, the system shall carry the call or attribute it matches, the operation or discharger kind, and, for identity constraints, the parameter or field position the constraint must occupy.
4. If a facts file names an operation kind, a discharger kind, or a field outside the closed sets, the facts loader shall reject the file with an error naming the entry.
5. The system shall not detect an obligation from any pattern that is not present in the facts data.

### Requirement 2: Obligation shapes are learned from trusted pairs

**Objective:** As a maintainer, I want each reviewed absence pair to teach the detector what a discharged operation looks like, so that the corpus raises absence recall the way it raises flow recall.

#### Acceptance Criteria

1. When a pair has `review_tier` `seeded` or `reviewed` and its label names an obligation kind, the system shall derive one obligation shape carrying the language, the operation kind, the discharger kind the fixed side adds, the provenance of the value the discharger binds (authenticated context, request input, constant), and the labeled mechanism id.
2. The system shall not derive an obligation shape from `advisory` or `title` pairs, from `known_limit` pairs, or from pairs whose vulnerable excerpt fails to parse.
3. An obligation shape shall contain no path, line, literal longer than an identifier, or code text.
4. When the same obligation shape is derived from several pairs, the system shall keep one record listing every pair in its provenance, stored in the same append-only mechanism store with a distinct shape family.
5. When a label names an obligation kind but the fixed side adds no recognizable discharger, the system shall skip the pair with a reason that names the missing discharger.

### Requirement 3: Consistency across sibling handlers recovers the policy

**Objective:** As an AppSec engineer, I want a handler that omits a discharge its siblings perform to be reported as the anomaly, so that the application's own conventions expose the missing guard without anyone writing a rule.

#### Acceptance Criteria

1. The system shall group handlers into sibling sets by the resource they operate on and by the router or module that registers them.
2. When at least the configured minimum number of siblings discharge an obligation and one sibling reaches the same operation kind without that discharge, the system shall report a `consistency_violation` for that sibling naming the obligation, the missing discharger kind, and the siblings that discharge it.
3. If a sibling set has fewer than the configured minimum number of members, the system shall not report a consistency violation for it and shall record the set as under-populated.
4. When a handler's route is classified public by the entry-point mapper and its siblings are authenticated, the system shall report the missing path guard as a consistency violation and shall name the access classification as evidence.
5. The system shall never demote, suppress, or re-label an existing finding on the basis of consistency.
6. When a consistency violation is evaluated on the fixed side of a pair whose siblings all discharge, the system shall report silence; the leak rate of the consistency detector on fixed twins shall be reported per slice.

### Requirement 4: A declared policy is optional, versioned, and closed

**Objective:** As a maintainer of a scanned project, I want to state which resources are protected and which routes are public, so that violations of my stated policy outrank anomalies inferred from consistency.

#### Acceptance Criteria

1. Where a project carries a policy file at the documented location, the system shall load protected resources, public routes, the identity source, and role names from it and shall record the policy version in the manifest.
2. If the policy file contains a field or a value outside the closed schema, the policy loader shall reject it with an error naming the field, and the scan shall continue without a declared policy and with a recorded degradation.
3. When a declared protected resource is reached by an operation without a discharger on its path, the system shall report a `declared_policy_violation` naming the policy clause.
4. When a route is declared public, the system shall not report a missing path guard for it and shall report a missing identity constraint on a protected resource it reaches.
5. The system shall never write or change a policy file on its own; a proposed clause shall appear only as an improve-loop edit that a human accepts.

### Requirement 5: Violations are evaluated on the path

**Objective:** As an AppSec engineer, I want an obligation reported only when an entry point actually reaches the operation without a discharger dominating the way, so that guards in middleware, decorators, and callers count.

#### Acceptance Criteria

1. While path records from the reachability model are available, the system shall report an obligation violation only when an entry point reaches the obligated operation and no discharger of the required kind dominates the path.
2. When a discharger of the required kind dominates the path, the system shall record the discharge with its location and shall report no violation.
3. If path records are unavailable for a file or language, the system shall evaluate obligations within the handler function only, shall label such findings `function_local`, and shall record a degradation naming the file.
4. When an identity constraint is present but binds a value whose provenance is request input rather than the authenticated context, the system shall report the violation with the discharger kind `identity constraint` and the provenance `request input`.
5. Obligation evaluation shall run in standard and deep scans and shall be absent from quick.

### Requirement 6: Obligation evidence stays honest and is reported with its reasons

**Objective:** As an operator, I want an absence finding to tell me what obligation was missed, why the tool believes the obligation exists, and how the known fix looks, so that I can fix or dismiss it without reading the tool's mind.

#### Acceptance Criteria

1. The system shall label obligation findings with exactly one of `consistency_violation`, `declared_policy_violation`, or `function_local`, and shall never label them with a sandbox-proven rung.
2. When a finding is reported, the markdown and SARIF reports shall show the obligation kind, the missing discharger kind, the evidence (the siblings or the policy clause), the resource, and the known fix guard learned from the corpus with its pair provenance.
3. When the hunter is available and a finding's route is not declared public, the system shall let the hunter adjudicate whether the route is meant to be public, shall record the adjudication and its rationale on the finding, and shall not raise the finding above `declared_policy_violation` on the hunter's word alone.
4. The worth-fixing ranking shall weigh an obligation finding by the sensitivity of the resource (declared, or inferred from the operation kind) and by its evidence label, and shall never rank it above a sandbox-proven finding on the same path.
5. The manifest shall record the number of sibling sets evaluated, obligations found, violations by label, and the policy version or its absence.

### Requirement 7: The corpus carries absence pairs with their context

**Objective:** As a maintainer, I want absence pairs harvested with the handler's registration context, so that guards living in decorators, routers, and middleware are visible to the teacher and the scorer.

#### Acceptance Criteria

1. The harvest library shall offer an excerpt mode that keeps the handler together with its registration (decorators, router calls, or middleware attachment) on both sides of a pair.
2. When a catalog row carries an obligation kind, the label schema shall accept it as an additive field and the pair scorer shall count an obligation finding inside the labeled function as a detection.
3. The system shall extend the closed mechanism vocabulary with the obligation kinds it needs and shall reject any row naming an obligation kind outside the vocabulary.
4. When the maintainer runs leave-one-out on a slice, the report shall include recall, silence, and Youden per obligation kind next to the flow mechanisms, and shall list which pair taught the discharger that found each held-out pair.
5. The roadmap shall carry the absence-pair baseline per slice; the baseline shall never be a merge condition.

### Requirement 8: An `obligations` lever under the existing gate

**Objective:** As a maintainer, I want the improve loop to admit obligation shapes and to propose policy clauses from consistency evidence, so that absence recall rises under the same honesty gate as everything else.

#### Acceptance Criteria

1. The improve loop shall gain an `obligations` lever whose edits admit or retract an obligation shape record, or propose a policy clause derived from a consistency violation with its sibling evidence.
2. The validator shall accept only shape records derived by the exporter from trusted pairs and only policy clauses whose fields are in the closed policy schema; free text beyond a rationale shall be rejected.
3. When an `obligations` edit is evaluated, the existing accept gate and the per-profile holdout clause shall apply, computed over the holdout pairs scored with the store before and after; an admission that fires on a holdout fixed side shall be rejected and the store restored byte for byte.
4. A proposed policy clause shall be journaled as pending until a human accepts it, and shall not affect any scan before acceptance.
5. The journal shall record each obligation edit with its pair or sibling provenance and the metrics before and after.

### Requirement 9: Offline tests and unchanged gates

**Objective:** As a maintainer, I want the feature proven without network, models, or a sandbox, so that it lands under the existing CI.

#### Acceptance Criteria

1. Facts loading, shape derivation, consistency detection, policy loading, path-aware and function-local evaluation, reporting, and the lever shall be unit-tested on local fixtures; semantic-marked tests shall skip without the extra.
2. The stage-1 detection gate, the split-sink map gate, and the local pair gate shall be unchanged.
3. The extra-free suite shall stay green, and no test shall require network, a model, or a sandbox.
