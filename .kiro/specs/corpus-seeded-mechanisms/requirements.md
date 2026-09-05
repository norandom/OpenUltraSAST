# Requirements Document

## Introduction

OpenUltraSAST's labeled pair corpus measures the detector but does not improve it, and its mechanism memory is empty because only sandbox-proven findings may write to it. This spec turns every trusted pair into a mechanism record, adds a structural variant search that proposes matches on any scanned tree, measures the corpus's own detection rate leave-one-out, and gives the improve loop a lever that can raise recall under the existing false-positive ceiling and per-profile holdout gate.

## Boundary Context

- **In scope**: mechanism export from pairs; shape normalization per language; variant search proposer in MAP; leave-one-out evaluation; `mechanisms` improve lever; store schema additions; reports showing mechanism ids; offline tests.
- **Out of scope**: taint, facts, walker, dispositions, evidence rungs; embedding retrieval changes; inter-file flow; LLM-authored shapes; catalogs and scorer changes beyond reading `PairCase`; any merge gate.
- **Adjacent expectations**: `Mechanism` gains additive fields only; `order_promotions` keeps working on old records; the improve loop's existing clauses and the per-profile holdout clause apply unchanged; `local` remains the only slice that can fail CI.

## Requirements

### Requirement 1: Mechanisms seeded from trusted pairs

**Objective:** As a maintainer, I want each reviewed pair to become a mechanism record, so that the corpus is a library the detector can search, not only a ruler.

#### Acceptance Criteria

1. When a pair has `review_tier` `seeded` or `reviewed` and its vulnerable excerpt parses, the system shall derive one mechanism record carrying mechanism id, CWE, language, provenance, review tier, pair name, the sink shape, the source shape, and the guard shape the fixed side added.
2. The system shall not seed a mechanism from `advisory` or `title` pairs, from `known_limit` pairs, or from pairs whose vulnerable excerpt is `parse_failed`.
3. When the same shape is derived from several pairs, the system shall store one record and list every pair in its provenance.
4. Seeded records shall be written to the same append-only JSONL store as sandbox-proven mechanisms, tagged with `origin = "corpus"`, and the existing embedding cache shall remain rebuildable from it.
5. The system shall expose the export as a maintainer command that runs offline on the vendored catalog.

### Requirement 2: Shapes are structural and language-scoped

**Objective:** As an engineer, I want mechanism shapes that match code structure rather than text, so that variants across projects are found without regex growth.

#### Acceptance Criteria

1. A sink shape shall consist of the callee name (trailing segment), the argument count, and the argument positions that carry source-derived identifiers, derived from `FileIR` call sites.
2. A source shape shall be either a fact source id, a function parameter, or a container read, derived from the vulnerable excerpt's binds.
3. A guard shape shall be one of a closed set: `null_test`, `bounds_test`, `allowlist_test`, `auth_check`, `parameterized_call`, `type_change`, `none`, derived from statements present on the fixed side and absent on the vulnerable side.
4. Shapes shall never contain literal source text longer than an identifier; paths, line numbers, and secrets shall not appear in a shape.
5. When the semantic extra is absent for a language, the system shall skip shape derivation for that language with a recorded degradation and shall not fall back to regex.

### Requirement 3: Variant search proposes, it does not decide

**Objective:** As an AppSec engineer, I want a scanned tree searched for structural variants of known mechanisms, so that recall rises with the corpus while evidence stays honest.

#### Acceptance Criteria

1. When a standard scan runs and the mechanism store holds records for the file's language, the system shall search each parsed file's call sites for sink shapes whose source-position arguments carry a fact source, a parameter, or a container read.
2. A match shall produce a finding with origin `variant`, the mechanism id, evidence level `suspicion`, and the pair provenance in its rationale.
3. When the overlay already records a source-to-sink flow at the same call site, the overlay record shall carry the mechanism id and the variant finding shall be merged into it rather than duplicated.
4. Variant findings shall be eligible for the sandbox candidate set under the existing safety check and caps, ranked after overlay promotions.
5. The system shall bound variant search by the existing MAP file budget and shall record how many files and mechanisms were searched in the manifest.
6. Variant search shall never demote, never raise evidence above `suspicion` on its own, and shall be absent from `quick`.

### Requirement 4: Leave-one-out is the corpus's detection rate

**Objective:** As a maintainer, I want to know whether adding pairs raises recall, so that corpus growth is measured by what it teaches the detector.

#### Acceptance Criteria

1. When the maintainer runs the leave-one-out command on a slice, the system shall, for each trusted pair, seed a temporary store from every other trusted pair, run variant search on the held-out vulnerable and fixed excerpts, and score the pair with the pair scorer's rules.
2. The command shall report leave-one-out recall, silence on the fixed side, and Youden per slice, per provenance profile, and per mechanism id.
3. The report shall list, per held-out pair, which mechanism record found it, so that a maintainer can see which pairs teach and which only test.
4. Leave-one-out results shall be written as a JSON artifact and recorded in the roadmap table; they shall never be a merge condition.

### Requirement 5: A recall-raising lever in the improve loop

**Objective:** As a maintainer, I want the improve loop to be able to admit mechanisms, so that it can raise recall and not only shadow noisy rules.

#### Acceptance Criteria

1. The improve loop shall gain a `mechanisms` lever whose edits admit or retract a candidate mechanism record into the scan-time store.
2. The validator shall accept only records derived by the shape exporter from trusted pairs, with a closed guard kind and no literal text beyond identifiers; free-form patterns shall be rejected.
3. The proposer shall suggest admitting a candidate mechanism when it recovers a currently missed holdout pair in a profile, and retracting one when it leaks on holdout fixed sides.
4. When a `mechanisms` edit is evaluated, the existing accept gate and the per-profile holdout clause shall apply unchanged; rejection shall revert the store byte for byte.
5. The journal shall record each mechanism edit with its pair provenance and the metrics before and after.

### Requirement 6: Reports name the mechanism

**Objective:** As an operator, I want a finding to say which known mechanism it resembles and where that mechanism was learned, so that a fix can follow the known fix.

#### Acceptance Criteria

1. When a finding carries a mechanism id, the markdown and SARIF reports shall show the mechanism summary, the guard shape the known fix used, and the pair provenance.
2. The manifest shall record the number of variant findings and the mechanisms searched.
3. Reports shall label variant findings as suspicions unless the overlay or the sandbox raised them.

### Requirement 7: Offline tests and unchanged gates

**Objective:** As a maintainer, I want the feature proven without network, models, or a sandbox, so that it lands under the existing CI.

#### Acceptance Criteria

1. Shape derivation, variant matching, leave-one-out, and the lever shall be unit-tested on local fixtures; the semantic-marked tests shall skip without the extra.
2. The stage-1 detection gate, the split-sink map gate, and the local pair gate shall be unchanged.
3. The extra-free suite shall stay green.
