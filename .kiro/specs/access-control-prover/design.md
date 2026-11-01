# Design Document

## Overview
The access-control prover remains a deterministic rule arm over the existing obligation checker. The amendment
changes the semantic contract: resolution, resource matching, authority matching and dominance return abstract
relations rather than booleans, and every examined path receives one of three judgments: `unguarded`,
`discharged`, or `indeterminate`. A degraded instrument may reduce precision to `indeterminate`; it cannot
manufacture either final verdict.

Target knowledge remains outside the engine. Entry shapes live in registered recognition strategies, while
operations, dischargers, resource rules and authority implications live in promoted fact data. A label-blind
initialization job produces that knowledge, and evaluation freezes its digest before admission labels are opened.

### Goals
- Produce an unguarded finding only from a complete, sufficiently resolved evidence path.
- Make call, path, resource, authority and control-flow uncertainty explicit and monotone.
- Carry target knowledge as verified data or recogniser strategies, never engine branches.
- Attribute development gains across analyzer and fact changes before measuring an untouched admission population.
- Fail the runtime and instrument gates rather than summarize partial work as a result.

### Non-Goals
- Taint analysis, Joern integration, model calls inside the prover, or vulnerability families beyond access control.
- Client-side presentation gating, proof execution, pre-push wiring, or admission-policy thresholds.
- Replacing the existing order-based checker mode for consumers that do not opt into prover semantics.

## Boundary Commitments

### This Spec Owns
- The abstract evidence domain and three-way pair/path judgment.
- Stable program identities, conservative call-target sets and bounded interprocedural summaries.
- Resource- and authority-sensitive operation/witness matching.
- Prover-mode control-flow dominance without textual-order fallback.
- Acquired entry, operation, discharger and authority knowledge needed by this family.
- The production access-control detection-core family contract, independently reviewed
  target-knowledge authority, structural matcher, and canonical observation/match writer.
- Deterministic traces, failure-visible coverage, development arms and the admission-run contract.

### Out of Boundary
- The legacy checker behavior used by existing callers; default APIs remain backward compatible.
- Target labels and benchmark curation, owned by `valid-detection-benchmark`.
- Runtime demonstrations, owned by `search-with-proof`.
- Hook admission and rollout, owned by `pre-push-safety-net`.
- Continuous fact evolution after the one-time initialization pass.
- Family-neutral fact, match, evidence, readiness and admission validation, owned by
  `detection-core`.

### Allowed Dependencies
- `openultrasast.source`, `openultrasast.mapping`, the existing semantic IR and CFG, and the existing obligation
  facts/checker contracts.
- The hunter `Context` caches, valid-benchmark metrics, replay record envelopes and reserved-population guard.
- Public detection-core v2 contracts and validators through an adapter dependency from this
  spec to core; detection-core never imports access-control or target-aware modules.
- No new third-party dependency.

### Revalidation Triggers
- A change to `EntryPointRecord`, `Operation`, `Discharge`, `Trace`, hunt-defect or replay-record contracts.
- A change to call-site receiver/signature capture, target-knowledge schemas or authority implication semantics.
- A change to path aggregation, judgment ordering, admission population isolation or the 120-second budget.
- A change to detection-core family, fact-pack, fact-match, provenance, custody or canonical
  serialization contracts; the adapter must re-run downstream conformance before use.

## Architecture

### Existing Architecture Analysis
The delivered baseline already recognises entries, composes bounded paths, discovers operations and witnesses,
builds structural CFGs, emits traces and scores replay records. Its decision interfaces are boolean: unresolved
receivers fall back to a bare name, unavailable CFGs fall back to textual order, and a witness either discharges or
does not. The amendment preserves the existing checker as the single verdict owner while inserting typed abstract
values before that boolean boundary and adding an opt-in three-way judgment path.

### Architecture Pattern & Boundary Map
~~~mermaid
flowchart LR
  TK[Target knowledge] --> MR[Mapping registry]
  TK --> FI[Fact interpreter]
  TK --> FA[Reviewed fact authority]
  FA --> FM[Structural matcher and artifact writer]
  FM --> DC[Detection core validation]
  MR --> CTX[Per change context]
  FI --> OP[Operations and witnesses]
  CTX --> SI[Symbol index]
  SI --> CR[Call resolution]
  CR --> FS[Function summaries]
  OP --> FS
  FS --> PM[Concrete path materializer]
  CTX --> CFG[Control flow relations]
  PM --> J[Three way judgment]
  CFG --> J
  OP --> J
  J --> TR[Canonical traces]
  J --> PR[Prover findings and coverage]
  TR --> RUN[Development and admission runners]
  PR --> RUN
~~~

Dependency direction is:
`abstract domain -> fact and recogniser adapters -> symbol resolution -> summaries and CFG -> checker judgment
-> prover integration -> runners`. Engine modules never import target-named strategy modules. Target-aware
adapters may import engine contracts.

- **Strategy + Registry**: entry recognisers are registered per recognition concern.
- **Interpreter**: promoted fact rows describe operations, dischargers, resource rules and authority implications.
- **Adapter**: the prover converts repository IR, target knowledge and context caches into engine contracts.
- **Abstract interpretation**: finite domains and monotone joins propagate evidence and incompleteness.

### Technology Stack
| Layer | Choice | Role |
|---|---|---|
| Analysis | Python 3.11, existing semantic IR and structural CFG | symbols, calls, summaries, dominance |
| Knowledge | Existing TOML fact files and mapping strategies | target-specific vocabulary |
| Core contract | detection-core v2 typed records and validators | family-neutral conformance |
| Scoring | Existing valid-benchmark metrics and replay records | development and admission results |

## File Structure Plan
~~~text
src/openultrasast/
├── mapping/
│   ├── registry.py                      # strategy registration and dispatch
│   ├── registration_sites.py            # generic call-site registration adapter
│   ├── fact_authority.py                 # authenticate installed reviewed authority
│   ├── installed_fact_authority.py       # closed JSON decoders and checked-in artifact resolver
│   ├── entry_packs.py                    # compatibility projection and v2 structural adapter
│   ├── fact_match_store.py               # persist canonical observations and match artifacts
│   ├── legacy.py                          # production caller migrates to authority-bearing adapter
│   └── <target>.py                       # one target-aware strategy per migrated concern
├── semantic/
│   ├── ir.py                             # CallSite receiver and signature evidence
│   ├── cst.py                            # receiver, arity and signature capture
│   └── obligations/
│       ├── abstract_domain.py            # relations, completeness, resources, authorities, judgments
│       ├── core_contract.py              # production access-control FamilyContract
│       ├── resolution.py                 # SymbolId, symbol index and CallTargetSet
│       ├── summaries.py                  # monotone FunctionSummary computation over call components
│       ├── paths.py                      # concrete evidence paths and cutoff records
│       ├── operations.py                 # operation/witness abstract identities
│       ├── dominance.py                  # legacy order mode, unchanged by default
│       ├── cfg_dominance.py              # prover-mode control-flow relation, no order fallback
│       ├── check.py                      # opt-in abstract matching and PairJudgment
│       ├── enforcement.py                # target-aware enforcement adapter
│       └── trace.py                      # canonical trace with abstract relations and completeness
├── hunt/
│   ├── producers.py                      # cached symbol index and summaries
│   └── prover.py                         # integration, path aggregation, findings and coverage
└── tools/
    └── fact_init.py                      # label-blind extract/propose/verify/promote workflow
ruleset/obligations/*.toml                # promoted operation, witness and authority knowledge
src/openultrasast/ruleset/entries/
├── bootstrap.json                      # host trust policy, external to authenticated bundle
├── authority.json                      # reviewed bundle payload and immutable references
├── express.javascript.v2.json          # reviewed JavaScript FactPack
├── express.typescript.v2.json          # reviewed TypeScript FactPack
├── express.json                        # authenticated non-authoritative compatibility projection
├── identities/
│   ├── generator.json                    # producer identity manifest
│   ├── maintainer-reviewer.json          # maintainer approval identity manifest
│   └── custodian.json                    # installed-artifact custody identity manifest
└── artifacts/sha256/<content-digest>   # canonical review/disclosure/evidence bytes
benchmarks/valid/
├── prover_arm.py                         # records, stage funnel, gates and four-arm comparison
└── prover_admission.py                   # frozen-manifest admission orchestration
tests/
├── test_obligation_abstract_domain.py
├── test_obligation_core_contract.py
├── test_obligation_resolution.py
├── test_obligation_summaries.py
├── test_obligation_judgment.py
├── test_obligation_trace.py
├── test_mapping_registry.py
├── test_fact_init.py
├── test_hunt_prover.py
└── test_prover_arm.py
~~~

### Modified Files
- Existing facts, IR, checker, dominance, trace, prover and arm modules receive additive or opt-in contracts.
- Existing callers retain legacy defaults; only the prover selects three-way judgment and strict CFG semantics.
- Existing completed benchmark records remain immutable development baselines.
- `mapping/entry_packs.py` keeps legacy pattern output byte-stable while adding an explicit
  authority-bearing v2 path; no-context legacy loading cannot emit detection-core evidence.

## System Flows

### Analysis
~~~mermaid
flowchart TD
  A[Read cached source] --> B[Recognise entries and facts]
  B --> C[Build symbol index]
  C --> D[Resolve call target sets]
  D --> E[Compute function summaries]
  E --> F[Materialise evidence paths]
  F --> G[Match witnesses to obligations]
  G --> H[Evaluate control flow]
  H --> I{Path state}
  I -->|complete and missing| U[Unguarded]
  I -->|complete and governed| DCH[Discharged]
  I -->|possible unknown or cut| IND[Indeterminate]
  U --> FIND[Finding and trace]
  DCH --> TRACE[Trace only]
  IND --> TRACE
~~~

### Evaluation
~~~mermaid
flowchart LR
  ACQ[Label blind acquisition] --> FREEZE[Freeze candidate bundle]
  BASE[Materialize baseline bundle] --> DEV[Four arm development comparison]
  FREEZE --> DEV
  DEV --> AUDIT[Review ordinary labels]
  AUDIT --> HOLD[Untouched paired admission run]
  HOLD --> GATE{Instrument budget and quality gates}
  GATE -->|pass| GO[G1 eligible]
  GATE -->|fail| NOGO[No go]
~~~

### Reviewed fact adaptation
~~~mermaid
flowchart LR
  BP[Host bootstrap policy] --> AUTH[Authenticate authority bundle]
  DATA[Reviewed contract packs and projection] --> AUTH
  AUTH --> MATCH[Match typed repository structure]
  MATCH --> OBS[Persist canonical observations]
  OBS --> EVID[Build and persist FactMatchEvidence]
  EVID --> CORE[Detection core validate and apply]
  LEGACY[Legacy pattern projection] --> RECOG[Compatibility recognition only]
  LEGACY -. forbidden .-> CORE
~~~

The access-control adapter writes each observation before constructing the match, writes the
canonical match bytes next, and only then calls core with the immutable references. The
resolver exposed to core is read-only. A regex or name hit can preserve recognition during
migration but cannot substitute for typed structural observations.

## Requirements Traceability
| Requirement | Components |
|---|---|
| 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7 | mapping registry, registration adapter, fact initialization, coverage |
| 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10 | fact interpreter, abstract domain, operations, enforcement, witness matcher |
| 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10 | symbol resolution, summaries, path materializer |
| 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7 | pair judgment, checker integration, prover findings |
| 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7 | prover arm, four-arm development comparison |
| 6.1, 6.2, 6.3 | context caches, deadline state, runner budget gate |
| 7.1, 7.2, 7.3, 7.4, 7.5, 7.6 | completeness, prover coverage, runner funnel |
| 8.1, 8.2, 8.3 | finding contract, trace references, proof-arm filter |
| 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7 | canonical trace and record provenance |
| 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7 | strict CFG dominance and legacy order compatibility |
| 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8 | abstract domain, path and operation aggregation, transition report |
| 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.9 | acquisition record, freeze manifest, admission runner |
| 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8 | access-control family contract, reviewed fact authority, structural matcher, artifact writer, detection-core conformance, caller cutover |

## Components and Interfaces

### Abstract evidence domain
~~~python
class EvidenceRelation(Enum):
    MUST = "must"
    MAY = "may"
    NO = "no"
    UNKNOWN = "unknown"

class PairJudgment(Enum):
    UNGUARDED = "unguarded"
    DISCHARGED = "discharged"
    INDETERMINATE = "indeterminate"

@dataclass(frozen=True)
class Completeness:
    is_complete: bool
    reasons: tuple[str, ...] = ()

@dataclass(frozen=True)
class ResourceRef:
    kind: Literal["exact", "aliases", "request_global", "unknown"]
    values: tuple[str, ...] = ()

@dataclass(frozen=True)
class AuthorityRef:
    values: tuple[str, ...]
    is_unknown: bool = False
~~~

The partial order places definite evidence below possible or unknown evidence. Join never converts `MAY` or
`UNKNOWN` into `MUST` or `NO`. The precision order is:

~~~text
MUST  <= MAY <= UNKNOWN
NO    <= MAY <= UNKNOWN
~~~

`MUST` and `NO` are incomparable. The alternative-path join is fixed by this table:

| join | MUST | NO | MAY | UNKNOWN |
|---|---|---|---|---|
| MUST | MUST | MAY | MAY | UNKNOWN |
| NO | MAY | NO | MAY | UNKNOWN |
| MAY | MAY | MAY | MAY | UNKNOWN |
| UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |

Three separate operations prevent one table from being used for the wrong quantifier:

1. `join_alternatives` uses the table above when alternative call targets or control paths contribute evidence.
2. `conjoin_dimensions` combines kind, scope, resource, authority and dominance for one witness: any `NO`
   produces `NO`; otherwise any `UNKNOWN` produces `UNKNOWN`; otherwise any `MAY` produces `MAY`; only
   all-`MUST` produces `MUST`.
3. `aggregate_witnesses` asks whether any witness definitely governs one obligation: any `MUST` produces
   `MUST`; otherwise `UNKNOWN` takes precedence over `MAY`, and `MAY` takes precedence over `NO`.
   An empty witness set is `NO` only when discovery and facts are complete; otherwise it is `UNKNOWN`.

For one complete path, all required obligations at `MUST` yield `discharged`; any `MAY` or `UNKNOWN` yields
`indeterminate`; otherwise any `NO` yields `unguarded` and every `NO` obligation is reported missing.
Thus a mixed `[MUST, NO]` obligation vector is unguarded for the `NO` obligation. Resource
alias sets join by finite union; an unbounded or unresolvable value joins to `unknown`. Authority implication is
read from promoted facts and contributes its fact identifier to the match evidence.

### Symbol resolution
~~~python
@dataclass(frozen=True, order=True)
class SymbolId:
    module: str
    enclosing_type: str | None
    name: str
    signature: tuple[str, ...] | None

@dataclass(frozen=True)
class CallTargetSet:
    targets: tuple[SymbolId, ...]
    completeness: Completeness
~~~

The symbol index covers repository-defined declarations and inheritance. Exact receiver and full signature produce
one complete target. Partial type or signature information produces a finite candidate set with an incompleteness
reason. No call falls back to a global bare-name key. Base declarations attach through explicit descendant edges.

### Function summaries and paths
~~~python
@dataclass(frozen=True)
class FunctionSummary:
    symbol: SymbolId
    operations: tuple[Operation, ...]
    witnesses: tuple[Discharge, ...]
    calls: tuple[CallTargetSet, ...]
    completeness: Completeness
~~~

Summaries are computed by a monotone worklist over strongly connected call components. Their finite contents grow
by union until stable. A budget cutoff stops growth, records the cutoff and leaves affected summaries incomplete.
Concrete paths are then materialised from recognised entries through exact targets for evidence. Candidate edges
may contribute diagnostic traces but cannot complete a final path.

### Witness matching and judgment
~~~python
@dataclass(frozen=True)
class WitnessMatch:
    relation: EvidenceRelation
    resource_relation: EvidenceRelation
    authority_relation: EvidenceRelation
    evidence: tuple[str, ...]

@dataclass(frozen=True)
class PathJudgment:
    judgment: PairJudgment
    missing: tuple[str, ...]
    completeness: Completeness
    matches: tuple[WitnessMatch, ...]
~~~

A witness governs an obligation only when kind, scope, resource, authority and dominance are all `MUST`.
Any `MAY` or `UNKNOWN` required relation makes the path indeterminate. With complete evidence and no governing
witness for a required kind, the path is unguarded. Multiple paths aggregate as follows:

- any complete unguarded path -> `unguarded`;
- complete enumeration and every path discharged -> `discharged`;
- otherwise -> `indeterminate`.

The checker gains an opt-in abstract mode. Legacy callers keep the current boolean result and order-based default.

### Strict CFG dominance
`CfgDominance.relation` returns an evidence relation and a guard effect. Prover mode never calls
`OrderDominance` when a graph, line mapping or construct is unavailable; it returns `UNKNOWN` with
`cfg_unavailable` or `line_without_node`. Route and declaration scopes return `MUST` only after exact handler
attachment. The legacy dominance class remains unchanged.

### Target knowledge and acquisition
The mapping registry and fact interpreter are target-aware adapters. The initialization job has:

- extraction mode for existing strategies and fact rows;
- proposal mode for source- or documentation-derived candidate knowledge;
- verification that checks source, version, region and concrete matches;
- promotion that writes only verified rows or enabled strategies;
- an acquisition record containing input revision, evidence digest, accepted/rejected proposals and output digest.

Admission mode prevents the acquisition process from receiving benchmark labels or fix locations. A changed output
digest after labels are opened spends the population.

### Reviewed detection-core fact adapter

The production contract is family-specific but target-neutral. Its initial reviewed
identity is `family_id=access_control`, `family_version=2.0.0`,
`schema_version=openultrasast.detection-core.evidence-packet.v2`, and
`ecosystems=(express,)`; later ecosystems require a reviewed contract-version change. It
uses the security object `entry_operation_authorization` with required text identity fields
`operation` and `boundary`. Its closed vocabulary is:

| Role | Contract |
|---|---|
| `operation` | no fields; `OPERATION_EFFECT`; `product_or_reviewed_fact` |
| `constraint` | no fields; `CONSTRAINT_EFFECT`; `product_or_reviewed_fact` |
| `security_object` | required text fields `operation` and `boundary`; no relation kinds; `product_or_reviewed_fact` |
| `framework_factory` | no fields; `REGISTRATION`; `product_or_reviewed_fact` |
| `framework_instance` | no fields; `REGISTRATION`; `product_or_reviewed_fact` |
| `entry_handler` | no fields; `INVOCATION`; `product_or_reviewed_fact` |
| `entry_registration` | no fields; `REGISTRATION`; `product_or_reviewed_fact` |

The decision rules are exactly `unguarded -> violation`, `discharged -> satisfied`, and
`indeterminate -> indeterminate`. The two determinate decisions require `operation`,
`constraint`, and `security_object` with allowed statuses `(COMPLETE,)`; the indeterminate
decision requires `constraint` with allowed statuses `(INCOMPLETE, UNRESOLVED)`. Residual question
`is_path_authorized` requires `operation`, `constraint`, and `security_object` and permits
all three decisions. The initial indeterminate-reason set includes
`missing_constraint_relation` and `ambiguous_constraint_relation`; additions require a
contract-version change and downstream revalidation.

```python
@dataclass(frozen=True)
class EntryFactAuthorityBundle:
    contract: FamilyContract
    packs: tuple[FactPack, ...]
    recognition_projection: ContentRef
    lineages: tuple[LineageManifest, ...]
    custody_policy: PopulationCustodyPolicy
    review_policy: ReviewIndependencePolicy
    matcher_revision: str
    matcher_behavior_digest: str
    matcher_lineage_manifest_digest: str
    authority_review: IndependenceAttestation
    bundle_digest: str

@dataclass(frozen=True)
class EntryAuthorityBootstrapPolicy:
    reviewed_bundle_reviewer_digests: tuple[str, ...]
    forbidden_identity_pairs: tuple[tuple[str, str], ...]
    trusted_store_identities: tuple[str, ...]
    maximum_bundle_bytes: int
    policy_digest: str

@dataclass(frozen=True)
class EntryFactAuthorityContext:
    bundle: EntryFactAuthorityBundle
    custody: PopulationCustodyPort
    resolver: ContentResolver

class FactMatchArtifactWriter(Protocol):
    def persist_observation(self, value: StructuralObservation) -> ContentRef: ...
    def persist_match(self, value: FactMatchEvidence) -> ContentRef: ...
```

The authority review subject is the canonical bundle payload digest with
`authority_review` omitted. The host supplies the bootstrap policy separately; neither the
bundle nor mapping code may choose its own trusted reviewers or stores. Validation
re-derives policy, attestation, disclosure, pack, projection, lineage, and bundle digests;
requires producer-reviewer separation; applies forbidden identity pairs; resolves every
referenced byte from an admitted store; and refuses missing, duplicate, or substituted
language packs. Because `FactPack.language` is singular, a multi-language target has one
reviewed pack per language with shared semantic intent but distinct canonical identities.
The shipped host trust policy is loaded from `bootstrap.json`, never referenced as authority
by the bundle it authenticates, and is replaceable by host configuration. The artifact
writer receives an explicit store root, store identity, and retention-policy digest; it
writes content-addressed canonical bytes and returns a read-only resolver plus re-derivable
storage receipts admitted by that bootstrap policy.

#### Installed authority wire and review ceremony

The checked-in authority uses closed canonical JSON records; decoders reject unknown or
missing fields before constructing typed objects. `bootstrap.json` has schema
`openultrasast.access-control.entry-authority-bootstrap.v2` and exactly the five
`EntryAuthorityBootstrapPolicy` fields. `authority.json` has schema
`openultrasast.access-control.installed-entry-authority.v1` and exactly:

- `pack_files`: the ordered pair `express.javascript.v2.json`,
  `express.typescript.v2.json`;
- `recognition_projection`, lineages, custody policy, review policy, matcher revision,
  matcher behavior digest, matcher lineage digest, authority review, and bundle digest;
- no trust-root, reviewer-admission, or store-admission fields.

Each v2 pack file is canonical JSON over every public `FactPack` field and the complete
nested `SemanticFact`, structural-requirement, relation-effect, knowledge-evidence,
attestation, and `ContentRef` values. Enum values use their public string values. The
installed decoder accepts only `FACT_PACK_SCHEMA`, re-encodes the typed value, and requires
byte equality so alternate/unknown encodings cannot share authority. `authority.json`
embeds policies and lineages because those values participate directly in the typed bundle;
review evidence and disclosures remain immutable `ContentRef` values.

All referenced bytes live under `artifacts/sha256/<content_digest>`. The installed resolver
validates the lowercase SHA-256 digest first and derives the filesystem basename solely from
`ContentRef.content_digest`; `artifact_id` is diagnostic metadata and is never interpreted as
a path. The resolver verifies byte length and digest, and derives
the `StorageReceipt` from the bootstrap-admitted store identity
`openultrasast-installed-entry-artifacts-v1`, the reference retention-policy digest, content
digest, and length. Receipts are derived, not separately mutable files. Pack filenames are
fixed by the closed authority schema; their typed normalized identities are covered by the
bundle digest, so substituting either pack changes authority even though the filenames are
not trust roots.

The approved repo-local ceremony records three distinct canonical identity manifests under
schema `openultrasast.access-control.authority-identity.v1`. Every manifest has exactly
`schema_version`, `role`, `name`, and `approval_basis`; its identity is the digest of its
canonical bytes, and the loader rejects unknown fields or noncanonical bytes. The fixed rows
are:

| File | `role` | `name` | `approval_basis` |
|---|---|---|---|
| `generator.json` | `producer` | `openultrasast-entry-pack-generator-v1` | `generated-from-reviewed-entry-data` |
| `maintainer-reviewer.json` | `reviewer` | `openultrasast-maintainer` | `maintainer-session-approval:2026-11-01` |
| `custodian.json` | `custodian` | `openultrasast-installed-entry-custodian-v1` | `checked-in-artifact-custody` |

The ceremony loader requires bootstrap reviewer admission to equal the reviewer-manifest
digest, custody-policy admission to equal the custodian-manifest digest, authority review
producer/reviewer identities to equal the generator/reviewer digests, and pack evidence to
use the same producer/reviewer identities. The maintainer explicitly approved this ceremony
on 2026-11-01; that approval authorizes recording the reviewer identity but does not let the
generator choose a different reviewer. Bootstrap admits only that reviewer digest and the
installed store identity. Producer and reviewer must differ, the pair remains subject to the
forbidden-pair policy, conflict disclosures must be canonical and resolved, and any identity
field or approval-basis change creates a new digest and invalidates these bindings until a
new human review.

The structural adapter consumes promoted recognition output and repository structure. For
each fact it emits the complete typed requirement set (qualified target, AST shape,
receiver, call target, argument shape, or configuration as declared), persists every
canonical `StructuralObservation`, builds `FactMatchEvidence`, persists
`fact_match_bytes(match)`, and then calls detection-core with the match plus its content
reference. Match construction never accepts a future self-reference: the reference is an
input only to core application after persistence.

#### Initial compatibility migration evidence

The first reviewed migration preserves the existing Express recognition rows as data, not
engine vocabulary. `express.javascript.v2.json` and `express.typescript.v2.json` carry the
same semantic expansion under distinct language-scoped pack identities. The authenticated
projection uses schema `openultrasast.entry-recognition-projection.v1` and closed row fields
`legacy_fact_id`, `languages`, `defines_handler`, `handler_kind`, and `pattern`; its content
reference is covered by the authority bundle digest. The projection keeps legacy regular
expressions and IDs byte-stable while the v2 packs use these exact facts:

| Legacy data row | Reviewed v2 fact | Required observations | Effect |
|---|---|---|---|
| `entry:express:app-route` | for each `method` in `get`, `post`, `put`, `delete`, `patch`, `all`, `use`: ID `entry:express:app-route:<method>`, fact role `entry_registration` | `qualified_target`: `QUALIFIED_NAME`, field `qualified_target`, expected `app.<method>`; `call_shape`: `AST_SHAPE`, field `call_shape`, expected `member_call`; `receiver`: `RECEIVER_TYPE`, field `receiver`, expected `express_application`; `arguments`: `ARGUMENT_SHAPE`, field `arguments`, expected `route_path_and_handler` | kind `REGISTRATION`, role `entry_registration`, source `framework_instance`, target `entry_handler`, conditions `()` |
| `entry:express:router-route` | for the same methods: ID `entry:express:router-route:<method>`, fact role `entry_registration` | `qualified_target`: `QUALIFIED_NAME`, field `qualified_target`, expected `router.<method>`; `call_shape`: `AST_SHAPE`, field `call_shape`, expected `member_call`; `receiver`: `RECEIVER_TYPE`, field `receiver`, expected `express_router`; `arguments`: `ARGUMENT_SHAPE`, field `arguments`, expected `route_path_and_handler` | kind `REGISTRATION`, role `entry_registration`, source `framework_instance`, target `entry_handler`, conditions `()` |
| `entry:express:express-app` | ID `entry:express:express-app`, fact role `framework_instance` | `qualified_target`: `QUALIFIED_NAME`, field `qualified_target`, expected `express`; `call_shape`: `AST_SHAPE`, field `call_shape`, expected `factory_call`; `binding`: `ARGUMENT_SHAPE`, field `binding`, expected `application_instance_binding` | kind `REGISTRATION`, role `framework_instance`, source `framework_factory`, target `framework_instance`, conditions `()` |

The promoted route-method values are read from reviewed projection data rather than copied
into engine branches. A pattern hit alone is `INCOMPLETE`; it cannot produce
`FactMatchEvidence`, enter readiness, or support admission. The no-context legacy loader is
removed only after `mapping/legacy.py` uses the authority-bearing path, a repository census
finds no caller that treats the projection as v2 evidence or bypasses authority, and the
core conformance handoff passes. `analyze_entry_points` remains the stable public entry;
bootstrap and adapter construction occur at its target-aware mapping boundary rather than
being pushed into neutral engine callers.

### Prover integration
`prove_change` orchestrates cached reads, recognition, resolution, summaries, paths, strict dominance and
judgment. It emits findings only for `unguarded` pairs and preserves all three judgments as traces. Coverage
contains stage counts, reason counts, pair judgments and exploration cutoffs. Exceptions are recorded at the stage
that raised them.

### Development and admission runners
Before comparison, the development runner materialises and validates two immutable bundles:

~~~python
@dataclass(frozen=True)
class AnalyzerBundle:
    analyzer_revision: str
    fact_set_digest: str
    acquisition_record_digest: str
    configuration_digest: str
~~~

The baseline bundle points to the analyzer revision and fact set that produced the immutable 2026-10-28 records;
the candidate bundle points to the amended equivalents. The runner refuses a four-arm comparison if either
revision or fact artifact cannot be materialised and digest-verified. It then registers baseline
analyzer/baseline facts, baseline analyzer/candidate facts, candidate analyzer/baseline facts and candidate
analyzer/candidate facts. This separates knowledge coverage from engine behavior.

The admission runner accepts only a frozen manifest naming analyzer, facts, acquisition, configuration and
population digests. The population manifest is produced and reviewed by `valid-detection-benchmark`; this spec
only consumes and validates it. The runner verifies its review and isolation fields, scores its paired
vulnerable/fixed cases and reviewed ordinary labels, refuses zero-byte or stale-anchor records, fails any change
over 120 seconds, and never converts indeterminate pairs to clean results.

## Data Models

### Canonical trace
Each trace carries:
- entry identity and target-knowledge evidence;
- exact hops and call-target completeness;
- operation kind, resource and authority;
- witnesses with kind, scope, provenance, resource, authority, dominance and match relations;
- control context and guard effects;
- completeness reasons and final path judgment;
- analyzer, fact-set and input digests.

Repository identity, repository size and function-size features remain outside decision input.

### Run manifest
The manifest contains population role (`development` or `admission`), immutable input digest, analyzer revision,
fact-set digest, acquisition-record digest, configuration digest, label-review state and spent-state marker.
The analyzer/fact bundle is a separate immutable input whose artifacts must be materialisable by revision and
digest; a manifest cannot redefine or synthesize the baseline.

## Error Handling
- Parse, recognition, resolution, summary, CFG and judgment exceptions become stage-specific incompleteness reasons.
- Deadline, fan-out, depth and recursion limits preserve accumulated evidence and return indeterminate affected
  pairs.
- Zero-byte reads and stale anchors are instrument failures that invalidate the run.
- Missing or mismatched manifest digests invalidate admission rather than falling back to development mode.

## Testing Strategy
- Unit: the complete join table, dimension conjunction, witness aggregation and monotonicity laws; symbol
  collisions and overload candidates; resource aliases and authority
  implication; SCC termination; CFG unknown behavior; three-way aggregation.
- Metamorphic: renaming a type preserves judgment; adding an unresolved overload can only preserve a judgment or
  move it to indeterminate; removing semantic evidence cannot switch directly between discharged and unguarded.
- Integration: exact unguarded and discharged paths; a guard in a called helper; registration-site entries; base
  attachment; resource mismatch; authority insufficiency; ambiguous calls; CFG unavailable; budget cutoff.
- Runner: baseline/candidate bundle materialisation, four-arm attribution, paired vulnerable/fixed scoring,
  reviewed-manifest validation, freeze-digest guard, zero-byte and stale-anchor refusal, indeterminate rate, and
  hard 120-second gate.
- Fact authority: bootstrap-policy independence, canonical bundle identity, reviewer/store
  admission, forbidden identity pairs, disclosure resolution, one pack per language, and
  refusal of substituted or self-authored artifacts.
- Fact matching: canonical observation and match persistence, complete structural matches,
  name-only/partial ambiguity, lineage/custody contamination, and read-only core resolution.
- Compatibility: byte-stable legacy recognition projection and proof that it cannot construct
  v2 evidence, readiness, or admission; core imports remain target-neutral.

## Migration Strategy
1. Add abstract types and adapters without changing legacy checker defaults.
2. Add strict resolution, summaries and judgment behind the prover's opt-in path.
3. Migrate traces and coverage, then enable the amended development arms.
4. Freeze facts and analyzer before running a separate admission population.
5. Authenticate the existing entry projection, publish reviewed language-scoped v2 packs,
   and run the authority-bearing structural adapter beside the legacy loader.
6. Pass detection-core downstream conformance, migrate production callers, then remove the
   no-context compatibility path at the single-writer cutover.

Rollback is the previous prover arm and fact-set digest; baseline records remain immutable and comparable.
