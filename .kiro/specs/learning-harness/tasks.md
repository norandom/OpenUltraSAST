# Implementation Plan

- [x] 1. Foundation: taxonomy, endpoint, corpus fields, grammar
- [x] 1.1 Closed family taxonomy with a verifier per family
  - Ten families exactly as decided, each with its CWE set, mechanism set, verifier kind (canary, static, none) and description; `unknown` always present with no verifier; a version string.
  - Loader rejects an unknown field, an eleventh family, a missing verifier kind or a CWE claimed by two families, naming the offender; relation lookup answers same, parent–child, lateral or fabricated for any two ids.
  - Observable: the taxonomy loads from the ruleset directory, a fixture with a fabricated family fails by name, and every mechanism id in the mechanism vocabulary resolves to exactly one family.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 1.2 Independent chat endpoint with the DeepSeek adapter
  - Endpoint resolution order: explicit override, scripted client modes, DeepSeek key and base URL, then OpenRouter; the embedding client keeps reading only its own variables; `[models]` gains the hunter and judge defaults and the endpoint keys, `[learning]` gains its section.
  - Adapter disables thinking and sends temperature zero for detector and classifier calls, keeps the provider's reasoning field on assistant messages so a caller can replay it, supports JSON-object mode with one retry on empty content and optional log-probabilities, and reports normalized usage and cost from the provider's cache-hit fields.
  - Observable: with both provider keys set the hunter client targets the DeepSeek base URL without a version suffix while the embedding client still targets OpenRouter; a scripted client is chosen under the existing environment flag; a recorded request shows thinking disabled and the reasoning field retained on the reply.
  - _Requirements: 6.6, 11.4_

- [x] 1.3 Additive corpus fields and hygiene at load
  - Expected rows accept an opaque family id (validated later by the classifier task, so the corpus module never imports the learning package); a pair carries a computed unscorable reason (identical twin by normalized body comparison with headers stripped, computed only when the catalog does not already declare a known limit) and is never dropped; duplicates across pairs are reported before any split; a repository-and-date split helper assigns train or holdout to rows that lack a split, keeps declared splits, and reports rows from one repository that straddle the split; pair signals take a split filter.
  - Observable: the five identical vibe-py twins load with the identical-twin reason and the existing catalogs load with unchanged row counts; the straddle report on the current catalogs is produced and committed.
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 1.4 TypeScript rows parse under the extra
  - The semantic extra gains the TypeScript grammar and the parser maps TypeScript and TSX to it; the extra-free suite still skips them with the existing marker.
  - Observable: every vendored TypeScript pair parses on both sides under the extra, and the parser reports no unsupported-language result for TypeScript or TSX.
  - _Requirements: 10.1_

- [x] 1.5 Curated hunter tools and hunter-loop parameters
  - Four new repository tools beside the existing three: resolve a definition by symbol, list entry points, list flows for a function, list obligations for a function, each clamped to the scanned repository and returning identifiers and line spans only; the hunter loop gains prompt, context files, tool set, character limit and tag parameters with today's behavior as defaults and replays the provider's reasoning field across tool turns.
  - Observable: the existing hunter tests pass unchanged with default parameters; each new tool answers on the shared handler fixture and refuses a path outside the repository; a recorded tool-turn conversation shows the reasoning field replayed.
  - _Requirements: 6.4, 6.5_

- [x] 2. Core: classifier, scorer, detectors, verifiers, journal
- [x] 2.1 (P) Classifier tiers
  - Tier one decides from rule id, sink family, obligation kind, mechanism id or labeled CWE without a model; tier two asks the chat endpoint in JSON-object mode with thinking disabled and averages log-probabilities, falling to unknown under a threshold; tier three is unknown; every answer records its tier; results are multi-label; loaded catalog family labels are validated against the taxonomy here and a fabricated family is rejected by name.
  - Observable: on the shared handler fixture tier one classifies the leaky handler as access control without any client; with a scripted client an off-vocabulary answer becomes unknown; a catalog with a fabricated family is rejected by name.
  - _Requirements: 2.1, 2.2_
  - _Boundary: Classifier_

- [x] 2.2 Classifier measurement and review queue
  - Report: agreement with maintainer labels on reviewed pairs with parent–child partial credit and no credit for lateral or fabricated ids, confusion matrix per family, accuracy against a random router and an oracle router, counts per tier and unknown; disagreements append to a review queue and never change a label; the whole corpus, including free-text and `other` rows, is classified with per-family counts.
  - Observable: the report on the vendored corpus lists the vfc `other` rows by resulting family and the queue holds every disagreement once with both answers and the tier.
  - Observable: the report also states whether hierarchical partial credit could apply.
  - _Requirements: 2.3, 2.4, 2.5, 2.6_

- [x] 2.3 (P) Per-pair family scoring
  - Detection only for a finding whose family tag relates same or parent–child to the labeled family and whose line lies in the labeled function, with the maximum penalty for a fabricated family; silence only when no such finding lies in the labeled function on the fixed side; other findings counted separately, never as leaks; text is never inspected; outcomes pair-correct, both-flagged, both-silent, reversed and unscorable; the unscorable reason also covers unsupported language, unresolved label and missing context.
  - Observable: a synthetic run set where every fixed side carries an other-family finding scores full silence; a finding with a fabricated family never counts; a pair in an unsupported language scores unscorable with that reason.
  - _Requirements: 3.1, 3.2, 3.6, 4.1_
  - _Boundary: Scorer_

- [x] 2.4 Aggregation, noise handling and denominators
  - Per family and slice: outcome counts, recall, silence, Youden, directional-bias index, a fixed-false-positive-rate view; K runs per pair with the majority outcome, negative flips per family against a baseline set, and a paired reliable-change test; unscorable rows listed by reason and excluded from every denominator; every metrics block carries the taxonomy version and the scorable and unscorable counts.
  - Observable: a single-run difference below the reliable-change threshold reports no change while a consistent flip across runs does; the unscorable count and taxonomy version appear in every metrics block.
  - Observable: every metrics block states whether hierarchical partial credit could apply.
  - _Requirements: 3.3, 3.4, 3.5, 3.7, 4.5_

- [x] 2.5 (P) Per-family detector configurations and the family detector runner
  - A configuration directory per family: prompt under a stated length cap, checklist, tool list from the curated set only, step and cost budget, maximum characters, hard negatives and counterexamples, version; the loader rejects an over-cap prompt, an unknown tool or a missing family; this task ships the loader and a test fixture configuration, the shipped per-family directories are written by round zero.
  - The runner takes the families admitted by the classifier as input, builds the detector's user message from the whole file plus definitions its tools resolve, runs the hunter loop with the family's prompt, tools and budgets, and tags each finding with exactly one family tag and one detector-version tag; the generalist is the unknown family's configuration.
  - Observable: a family run on the shared fixture with a scripted client yields findings tagged with that family and version and uses only the family's tool list; a configuration whose prompt exceeds the cap fails to load by name.
  - _Depends: 2.1_
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_
  - _Boundary: Detectors_

- [x] 2.6 (P) Verifier registry and the oracle callback
  - The regress verdict accepts an optional oracle callback and keeps exit-code behavior otherwise; a registry keyed by the taxonomy's verifier kind returns a canary, static or no-op verifier; the static verifier raises access-control claims to static corroboration when the obligations checker reports the same function; the no-op verifier leaves suspicion.
  - Observable: with the fake sandbox runner a result whose output carries the token yields triggerable while a nonzero exit without the token does not; a family with no verifier keeps suspicion on the shared fixture; the access-control claim on the leaky handler reaches static corroboration.
  - _Requirements: 7.1, 7.3, 7.4_
  - _Boundary: Verifiers, Regress_

- [x] 2.7 Canary templates and the second judge
  - Family snippet templates for injection, file path and deserialization plant a canary (row in an in-memory database, file under the scratch mount, marked object) and print the token only when the vulnerability fires; the second judge asks the judge model with the snippet, oracle output and claim and answers confirm or not in JSON-object mode; a claim is published as proven only when it confirms; templates, oracle code and gold labels live outside every proposer write root.
  - Observable: every canary template passes the existing snippet safety check; a scripted judge that declines keeps the claim below proven; templates and oracle code live under the verifier directory and gold labels under the corpus directory.
  - _Requirements: 7.2, 7.5_

- [x] 2.8 (P) Round journal, archive and rejected buffer
  - Append-only round records with hypothesis, levers, predicted affected and at-risk families, outcome, reason, target deltas, per-family sweep flips, attribution (flipped predicted, flipped unpredicted, precision), cost, taxonomy and configuration versions; a per-family archive of which configuration version wins which pair; a rejected-hypothesis buffer per family; every persisted text passes redaction.
  - Observable: a record round-trips through the file; the buffer returns only the target family's rejected hypotheses; the archive names one winner per pair per family; a secret literal written into a record is stored redacted.
  - _Requirements: 9.3, 9.6, 9.7, 11.3_
  - _Boundary: Journal_

- [ ] 3. Integration: split, scoring paths, rounds, proposer, publish, CLI
- [x] 3.1 One teacher rule across every learning path
  - Teachers are vendored, gating-tier, train-split, scorable pairs; a refusal names any candidate taught by or touching a holdout pair; the exporter, leave-one-out, per-profile evaluation, mechanism-profile evaluation, mechanism admission and pair signals all obtain teachers through the rule and record refusals as degradations; the mechanism lever's holdout number is re-measured under the rule and its raw artifact committed for the publish task.
  - Observable: leave-one-out on the toy slice seeds from train pairs only; a candidate shape taught by a holdout pair is refused by name; the re-measured artifact is in the measurements directory.
  - _Depends: 1.3_
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 3.2 Family scoring on the pairs hunter path
  - The pair scorer's hunter path takes an injected family matcher and leak rule from the learning package, classifies each pair once, runs the admitted family detectors plus the generalist K times per side, and emits family outcomes and metrics; the overlay and inventory paths stay untouched.
  - Observable: the pairs command with a scripted client on the shared fixture reports a family outcome per pair; no text-token matching remains on the hunter path; the pair gate output is byte-identical to before.
  - _Depends: 2.1, 2.4, 2.5, 2.6_
  - _Requirements: 3.1, 3.2, 3.3, 3.5, 11.5_

- [ ] 3.3 Round zero and the noise floor
  - Clone the current hunter prompt into every family configuration; run each family K = 5 times over the scorable vendored pairs of the selected slices at deterministic settings; record the per-family negative-flip rate between runs as that family's regression budget; persist noise floors and round-zero artifacts keyed by detector model so another model can be baselined and compared without touching configurations; the web families over vibe-py and agent-vfc are the default selection and the memory-safety family over vfc is selectable but never gates.
  - Observable: with a scripted client round zero writes a noise-floor file with one budget per family and a round-zero report per slice; a second baseline under another model name writes a separate artifact and the comparison table lists both.
  - _Depends: 3.2_
  - _Requirements: 8.1, 8.2, 8.3, 8.4_

- [ ] 3.4 Family detectors, verifiers and tags in scans
  - In a standard scan each classified region runs its admitted family detectors plus the generalist from the directories round zero wrote (a missing family directory is a recorded degradation and that family's detector is skipped), claims pass through the family's verifier, findings carry family, detector and verifier tags in reports and SARIF, and the manifest gains a learning block with taxonomy version, per-family counts, the classifier report and the current round; the detection and map gates stay byte-identical.
  - Observable: a standard scan of the shared fixture with a scripted client writes findings tagged with a family, a detector version and a verifier rung, and the manifest block; the detection and map gate outputs diff empty.
  - _Depends: 3.3, 2.6_
  - _Requirements: 6.3, 7.1, 11.5_

- [ ] 3.5 Proposer protocol, scripted proposer and the HarnessX proposer
  - Failure facts for one family: misses and leaks with pair, function, sink or check, line, verifier outcome and run outcomes, plus the rejected buffer and the current configuration; a proposal is one hypothesis, one lever (tool, checklist, counterexample, memory, prompt), one file-level change inside the family directory, and predicted affected and at-risk families; the proposer never receives holdout inputs, outputs or scores.
  - A scripted proposer for tests and offline rounds; a HarnessX proposer composing the meta-agent with write roots limited to the family directory, degrading to a recorded reason without the extra.
  - Observable: the scripted proposer returns a proposal from a facts fixture; the HarnessX proposer is skipped with the reason recorded when the extra is absent and, when present, writes only inside the family directory; the write-root list excludes the verifier and corpus directories.
  - _Depends: 2.5, 2.8_
  - _Requirements: 9.1, 9.2, 5.4, 7.6_

- [ ] 3.6 Acceptance rule and directory revert
  - Acceptance requires train and holdout non-negative with one strictly positive and every other family within its budget; ties reject; a family directory snapshot restores byte for byte on rejection or overrun; refusals for holdout contact, length cap and lever set are outcomes with reasons.
  - Observable: a helpful change is accepted, a tie is rejected, a change that breaches another family's budget is rejected with the family named, and a revert restores the directory byte for byte.
  - Observable: every family other than the target has a byte-identical directory before and after the round, whatever the outcome.
  - _Depends: 3.3_
  - _Requirements: 6.2, 9.5_

- [ ] 3.7 Evolve round orchestration, cost and journal
  - One round: facts, proposal, refusals, train minibatch, target-family holdout, sweep over every other family's holdout, K-run scoring at every stage as the scorer requires, accept (freeze, bump version, archive) or revert; cost metered per stage with revert and a recorded reason on overrun; a journal record and the rejected buffer written for every outcome; a round directory holds the snapshot, proposal, scores and trajectories and a repeated round number is refused.
  - Observable: with the scripted proposer each of accepted, rejected, budget-breach and cost-overrun leaves one journal record with attribution and a round directory; a repeated round number is refused.
  - The round directory holds the pair identities behind the attribution counts and every detector trajectory, redacted, so a round can be replayed and its attribution audited; every stage scores at least three runs per pair.
  - _Depends: 3.5, 3.6_
  - _Requirements: 3.5, 9.4, 9.6, 9.7, 9.8, 9.9, 11.3_

- [ ] 3.8 Publish from artifacts
  - One entry point regenerates every family and slice number from committed artifacts, writes a markdown table with scorable and unscorable counts, taxonomy version, noise floor and cost per point beside every number, replaces the roadmap's measured section between markers, and writes the raw artifacts under the measurements directory.
  - Observable: running the publish entry point twice without new artifacts produces byte-identical output; the corrected mechanism-lever number from the re-measurement artifact replaces the earlier roadmap value.
  - _Depends: 3.1, 3.3_
  - _Requirements: 11.1, 11.2, 4.5, 5.3_

- [ ] 3.9 Learning subcommands
  - Subcommands for classify, score, baseline, round and publish with the flags the design names; the pairs hunter path gains the K-runs flag; every step runs under the harness runtime with degradations for missing extras, endpoints or sandbox.
  - Observable: each subcommand exits zero on the shared fixture with a scripted client and writes its artifact; the roadmap section written by the publish subcommand carries the command line that produced it; a missing endpoint records the reason and the remaining steps complete.
  - _Depends: 3.7, 3.8_
  - _Requirements: 11.1, 11.4_

- [ ] 4. Corpus repairs
- [x] 4.1 Re-harvest absence rows with registration context
  - Absence rows in vibe-py and agent-vfc gain their family and the handler-context mode in the recipes; the maintainer re-harvests them over the network; every re-harvested excerpt keeps its license line, passes redaction and keeps the decorators and registration statements; failed fetches keep the old excerpt with a recorded reason; catalogs regenerate idempotently.
  - Observable: the vampi and threatbyte excerpts contain their registration lines, the entry-point mapper names their handlers, and the catalogs load with unchanged vendored counts.
  - _Depends: 1.3_
  - _Requirements: 10.2_

- [ ] 4.2 Identical twins and the fixture-difficulty check
  - The five identical vibe-py twins carry the identical-twin known-limit reason in the catalog; a test derives a difficulty vector for a unit fixture (binding hops to the identity source, registration present, cross-file registration) and for the corpus rows its docstring names, and fails when the fixture is strictly easier.
  - Observable: the twins are excluded from every denominator with their reason listed; the shared obligations fixture is compared against the re-harvested vampi rows and the check's verdict is recorded.
  - _Depends: 4.1_
  - _Requirements: 10.3, 10.4_

- [ ] 4.3 Fix dates and the post-cutoff slice
  - Catalog rows gain a fix date populated by the catalog generator from recipe metadata where available; rows without a date are counted separately; rows dated after the configured detector cutoff form a separately reported slice in every scoreboard.
  - Observable: the scoreboard shows the post-cutoff slice with its own counts, the cutoff date it used and the undated count.
  - _Depends: 1.3, 2.4_
  - _Requirements: 10.5_

- [ ] 5. Validation
- [ ] 5.1 Gates, matrices and degradation paths
  - Detection, map and local pair gate outputs byte-identical to the pre-feature commit; the extra-free suite green with semantic and HarnessX tests skipping; each optional dependency's absence exercised once with its recorded reason.
  - Observable: the three gate outputs diff empty against the recorded baseline and both test matrices pass.
  - _Requirements: 11.4, 11.5_

- [ ] 5.2 Live round zero
  - Round zero through the DeepSeek endpoint on the vibe-py and agent-vfc web families with K = 5, plus the memory-safety family over the vfc slice as a measured, non-gating run; artifacts, noise floors and cost per pair committed; the classifier report and review queue produced on the same run; a second baseline with the judge model on one slice for the model comparison table.
  - Observable: the published table shows per-family outcomes, noise floors and cost for both models and for the vfc memory-safety family, and the roadmap section is regenerated from it.
  - _Depends: 3.9, 4.1_
  - _Requirements: 8.3, 8.4, 11.1, 11.2_

- [ ] 5.3 First evolve rounds
  - Three rounds with the scripted proposer on the access-control family using the obligation shapes as the first memory entries, then one round with the HarnessX proposer; every round journaled with attribution; the roadmap regenerated.
  - Observable: the journal holds four records with outcomes and attribution precision, at least one accepted change is versioned in its family directory, and no other family exceeded its budget in any accepted round.
  - _Depends: 5.2_
  - _Requirements: 9.9_

## Task-plan review notes

- Sanity review round 1 (2026-09-06): NEEDS_FIXES, eleven findings, all repaired (K-run policy honors Req 3.5; per-model baselines added to the design; family validation moved out of the corpus loader; reasoning replay owned by the hunter loop; Req 5.3 split into re-measure and publish; scoring path split into pairs and scan tasks; oversized tasks split; fix-date prerequisite added; fixture-difficulty check depends on the re-harvest; memory-safety family measured on vfc; detector task depends on the classifier and round zero owns the shipped directories; observables re-anchored).
- Sanity review round 2 (2026-09-06): NEEDS_FIXES with three local items, repaired without a third review under the bounded loop: task 1.5 delivers the four curated tools and the hunter-loop parameters that 2.5 relied on; the scan-path task now follows round zero and degrades when a family directory is missing; the write-root observable moved to the HarnessX proposer task with 7.6. Non-blocking notes applied: the split helper assigns as well as reports (4.4), 3.2 depends on 2.1 rather than 2.2.

## Implementation Notes

- Requirements approved 2026-09-06, design approved 2026-09-06, tasks approved 2026-09-06 (maintainer, in session).
- Task 1.1 (2026-09-06, RED first: 9 failing tests in `tests/test_learning_families.py`, `ModuleNotFoundError: openultrasast.learning`; then green): `learning/families.py` and `ruleset/families.toml` with the ten decided families, each carrying its CWE set, mechanism set, verifier kind and description. Decisions taken while writing the data: (a) `unknown` carries the six mechanisms that span families (`source_reaches_sink`, `container_taint`, `validation_strength`, `redos`, `cross_artifact`, `other`) and the two weaknesses we deliberately do not target (CWE-20 generic validation, CWE-835 infinite loop), so a row we considered and declined is visible instead of unresolved; an earlier draft said `unknown` had none. (b) The maintainer's "server-side request forgery" family is named `untrusted_destination` and also covers open redirect (CWE-601), because both are untrusted input choosing a request destination and the corpus carries 34 open-redirect rows that would otherwise be unclassifiable. (c) The taxonomy is flat: `parent` is an optional field no shipped family uses, exercised by a fixture, because Req 2.3 and 3.1 need a parent-child arm and inventing a hierarchy would be worse than leaving it empty. (d) Abstention earns no partial credit: `related("unknown", X)` is `lateral`. All 33 labeled corpus weaknesses resolve, none is claimed twice, and every mechanism id belongs to exactly one family.
- Task 1.2 (2026-09-06, RED first: 8 failing tests in `tests/test_learning_endpoint.py`; then green): `learning/endpoint.py` resolves override, then the scripted flag, then a configured endpoint, then DeepSeek, then OpenRouter; the embedding client is untouched. `provider/openrouter.py` gains `complete_chat_raw` (whole payload, for `usage`) and an `extra_body` passthrough; `ChatResponse` gains `reasoning` and `mean_logprob`. Design deviation: `ChatEndpoint` deliberately holds no `api_key` (the design listed one) so the record is safe to journal; the key stays on the client. `[models]` gains `judge`, `chat_base_url`, `chat_api_key_env`; `[learning]` is new. `ModelConfig.hunter` keeps its `None` default on purpose: defaulting it would silently enable LLM stages in existing scans, so the DeepSeek model defaults live in `resolve_models`.
- Task 1.3 (2026-09-06, RED first: 7 failing tests in `tests/test_pair_hygiene.py`; then green): `ExpectedFinding.family` (opaque; the classifier validates it), `PairCase.unscorable`, `PairCase.split_declared`, `PairCase.fix_date` (the generator fills it in 4.3), `duplicate_groups`, `split_by_repository` with `SplitReport`, and a split filter on `build_pair_signals`. Measured and committed as `benchmarks/measurements/2026-09-06-corpus-hygiene.json`: **19 repositories straddle the train/holdout split** (a learning path can be taught by one file of a repository and evaluated on another) and **10 groups of pairs share a vulnerable excerpt byte for byte**, mostly the same fix harvested twice at different granularity. Only three vendored rows (the `local` slice) declare no split.
- Task 1.4 (2026-09-06, RED first: 2 failing tests in `tests/test_typescript_grammar.py`; then green): the semantic extra gains `tree-sitter-typescript`; `grammar_for` maps a language to (module, attribute) because the wheel ships two grammars, and `parse_with_cst` picks the JSX-aware one for a `.tsx` path while the parsed file keeps the language it was given. Eighteen agent-vfc rows plus the TypeScript absence rows now parse on both sides.
- Task 1.5 (2026-09-06, RED first: 5 of 6 tests in `tests/test_hunter_curated_tools.py` failing; then green): `hunter_tools` gains `read_definition`, `entry_points`, `flows`, `obligations`; `run_tool_hunter` gains `system_prompt`, `user_prompt`, `context_files`, `tools`, `max_chars` and `tags`, all defaulting to today's behaviour, and replays the provider's reasoning field on the next turn. Deviations: `read_definition` returns the definition text as well as its span, and includes preceding decorator lines, because a resolver that returns only line numbers forces another `read_file` and a handler's decorators are exactly what the obligations work showed to matter; the three list tools return identifiers and spans only. No caching: a stale view of a tree a round may have rewritten is worse than a reparse.
- Review round 1 (2026-09-06) APPROVED 1.1, 1.2, 1.4, 1.5; REJECTED 1.3. The reviewer ran every check in a detached worktree at the group-1 tip and confirmed RED-first by running each new test file against the pre-feature commit (37 failures there, all passing after), the three gate outputs byte-identical, and `pairs`/`benchmark` free of any learning import.
  - **1.3 rejection, remediated RED-first**: `_body_digest` stripped every leading comment line, which in C and C++ swallows `#include` and `#define`, and in any language swallows an ordinary leading comment. Two files differing only in a buffer size on a `#define` hashed equal and were marked `identical_twin`, removing a real pair from every denominator. Measured before the fix: twelve file sides across six vendored pairs had directives inside the stripped prefix, including the Juliet stack-overflow pair whose whole point is that constant. The strip is now anchored to the grammar `harvest.provenance_header` writes: a leading comment counts as header only when it carries one of the eleven provenance keys followed by a colon, and the scan stops at the first line of code. Four regression tests pin both directions plus a corpus-wide assertion that no vendored excerpt loses a directive. The five twins, ten duplicate groups and nineteen straddling repositories are unchanged, so the committed hygiene artifact still holds.
  - Suggestions applied: a mechanism claimed by two families now fails loud by name; the obligations tool's path-escape refusal and the endpoint's degrade-to-None on a provider error are now asserted; the TypeScript parse assertion is exact instead of a 25% allowance, which surfaced one real corpus defect (`lensops-kubernetesmanagement-fe4910` was harvested as a truncated destructuring parameter list and is not valid TypeScript on its own; it belongs to the 4.1 re-harvest).
  - **Two findings escalated to the maintainer, both blocking task 3.8 rather than group 1.** (a) `untrusted_destination` contradicts the approved requirement sentence, which says "server-side request forgery": the family id is the key every published number carries, so `requirements.md` Req 1.1 and the brief's Decision 1 must be amended to the widened name, or the family renamed back and CWE-601's 34 rows re-homed. (b) The shipped taxonomy is flat, so `parent_child` is unreachable in production and the "partial credit for a parent-child relation" in Req 2.3 and 3.1 is inert at version 1; either declare real parents or record the inertness beside every published agreement number.
  - Carry-forward: the nineteen straddling repositories cross the split by declaration, so `split_by_repository` cannot fix them and task 3.1's teacher rule inherits the leak until a maintainer re-declares those splits. The `preprocess_repository` cost of the three list tools should be measured in 2.5 before round zero.
- Task 2.1 (2026-09-06, RED first: 8 failing tests in `tests/test_learning_classify.py`; then green): `learning/classify.py` with three tiers, multi-label answers in taxonomy order, and `validate_family_labels` owning the taxonomy check the corpus loader deliberately does not do.
- Task 2.2 (2026-09-06, RED first: 5 failing tests in `tests/test_learning_classifier_report.py`; then green): `measure_classifier` and `write_review_queue`. Bug caught by the RED test: the classifier read the declared label it was being scored against, making agreement trivially 1.0; `classify_pair(..., use_declared=False)` is what the measurement uses. Measured on the 277 vendored pairs: tier one places 275 without a model call, 2 land in `unknown`, and the 176 memory-safety rows resolve to one family. `labeled` is 0 because no row carries a maintainer family label yet, and the report says so instead of inventing a score.
- Task 2.3 (2026-09-06, RED first: 8 failing tests in `tests/test_learning_scoring.py`; then green): `learning/scoring.py` `score_pair_family`. Detection is a family-tagged finding inside the labeled function; text is never read. Findings of other families or outside the function are counted separately and never called leaks; a fabricated family id is counted as noise. K runs, majority outcome, disagreeing runs recorded as flips.
- Task 2.4 (2026-09-06, RED first: 7 failing tests in `tests/test_learning_aggregation.py`; then green): `aggregate` and `sign_test`. Recall at a fixed false-positive ceiling is forfeited entirely when the leak rate exceeds it; the directional-bias index separates "flags everything" from "silent on everything", which Youden cannot; change against a baseline is a two-sided exact sign test over per-pair flips, not a difference of means. `PairFamilyScore` gained a `slice` field (additive, filled from the case) so metrics can be reported per slice.
- Task 2.5 (2026-09-06, RED first: 9 failing tests in `tests/test_learning_detectors.py`; then green): `learning/detectors.py` with `FamilyConfig`, `Region`, `load_family_configs`, `run_family_detector`, `run_region_detectors`, `write_default_configs`. Deviations: the parts live in one `family.toml` plus the markdown and JSON-lines files, because two TOML files with three keys between them was more surface than value and `version` had no home in the design's list; configurations live under the project's learning directory, not inside the package, because a round writes them. `CURATED_TOOLS` is derived from `HUNTER_TOOLS` so the closed set cannot drift.
- Task 2.6 (2026-09-06, RED first: 6 failing tests in `tests/test_learning_verifiers.py`; then green): the optional oracle callback on `verdict_from_result`, inserted after the inconclusive guards and before the exit-code branch so a call without an oracle is the old decision tree, plus `verifier_for`, `StaticVerifier`, `NoVerifier` and `apply_verification`.
- Task 2.7 (2026-09-06, RED first: 8 failing tests in `tests/test_learning_canaries.py`; then green): `learning/canaries.py` with per-family templates, `CanaryVerifier` and `confirm_proven`. Deviation: templates live in `learning/canaries.py` rather than the design's `learning/verifiers/` directory; the property that matters, being outside every proposer write root, holds and is tested.
- Task 2.8 (2026-09-06, RED first: 6 failing tests in `tests/test_learning_journal.py`; then green): `learning/journal.py` with `RoundRecord`, `Attribution`, `LearningJournal`, `Archive` and `summarize`.
- Review round 2 (2026-09-06) APPROVED 2.1, 2.2, 2.4, 2.5, 2.8; REJECTED 2.3, 2.6, 2.7. The reviewer ran every check in a detached worktree at the group tip, re-derived the RED phase per task against each task's parent commit (8/5/8/7/9/6/8/6 failures, the four recorded claims exact), killed 15 mutants against the new tests, and hand-verified `sign_test` against the closed form for every (better, worse) with n <= 20.
  - **2.3 rejection, remediated RED-first**: two of Req 4.1's five unscorable reasons had no code path, so a row whose language could not be parsed was reported as `unresolved_label`, a corpus labelling defect, when the cause was a tooling gap. The design's `unscorable_reason(case, *, parse_ok, ranges)` is reinstated as a public function, `score_pair_family` takes `parse_ok` and `entry_points`, and `missing_context` names a handler that arrived without the registration that makes it reachable, for the families whose bug shape is a missing check.
  - **2.6 rejection, remediated RED-first**: `apply_verification` wrote `evidence_level="proven"`, which is not a member of the project's `EvidenceLevel`, so `verify_finding`, `is_report_verified` and `verify_judge` all raise `ValueError` on it. Requirements put the evidence ladder out of scope and the design's data contract specifies only the `verifier:<rung>` tag. Nothing in production called it yet, so the suite stayed green while task 3.4's wiring would have broken a scan. `apply_verification` now writes only the tag; `evidence_level_for` and `raise_to` are the single explicit bridge onto the ladder, and a test round-trips a proven claim through the project's own helpers.
  - **2.7 rejection, remediated RED-first**: the injection canary opened its own in-memory database, inserted the token there and called the handler without ever giving it that connection, so the oracle could never fire; the fake sandbox runner returned the token regardless of the snippet, which is why no test noticed. It is now an execution canary whose marker only an interpreter could write, and each template is exercised end to end by running the rendered snippet against a vulnerable fixture and its fixed twin. That test immediately caught a second flaw: a fixed twin that echoes its input printed the oracle token and satisfied the oracle with no vulnerability at all, so an injected payload now carries a value unrelated to the token the oracle looks for. Recorded scope: the injection canary confirms command, code and template execution; a query-language injection whose payload never reaches an interpreter stays a suspicion.
  - Suggestions applied: a configuration with an empty tool list is refused by name instead of producing a detector that silently reports nothing; the classifier abstains when its no-adapter fallback call also fails; the archive docstring states that the earliest winning version keeps its claim to a pair.
  - Task-plan updates from the review: 2.2 and 2.4 claim the two criteria the maintainer added (2.6 and 3.7); 3.6 claims Req 6.2 with an observable that every non-target family directory is byte-identical across a round; 3.7 claims Req 3.5's K floor, 9.6's pair identities and 11.3's trajectories.
  - **Escalated to the maintainer**: Req 6.1 lists "a skills set" among a detector configuration's parts, and neither the approved design nor the code has one, although the repository ships a skill router. Either Req 6.1 drops the skills set or a task wires it; the implementation followed the approved design, so this is a spec-internal conflict rather than a deviation.
  - Carry-forward: the nineteen straddling repositories still cross the split by declaration and cap every holdout number these tasks produce; `unknown` serves as both the classifier's abstention and the generalist detector, which deserves a sentence in the design before a round ever targets it.
- Task 4.1 (2026-09-06, RED first: 21 of 23 failing tests in `tests/test_pair_registration_context.py`; then green, 26 tests). Measured before the change: **8 of the 10 vendored access-control rows had no named handler at all**, so every one of them would have scored `missing_context` forever rather than as a detector miss. After the re-harvest 9 of 10 are named and the tenth states its reason. What the repair needed, in order of how much it cost:
  - **Class registration.** A flask-restx handler is a method; `@ns.route('/profile')` sits on the class. `extract_handler_context` now carries the enclosing class declaration and its decorators, so the excerpt is both reachable and parsable — a bare indented `def get` is neither.
  - **Multi-line decorators and commented-out guards.** `@ns.doc(...)` wraps over four lines, and stopping at a continuation dropped the `@ns.route(...)` above it — the registration itself. `#@token_required` above a handler is not noise; in the two ThreatByte rows it is the entire bug, and the evidence field says so. `_decorator_start` now walks both.
  - **Cross-file registration (design amendment, recorded in `design.md`).** connexion registers VAmPI's handlers by `operationId` in `openapi_specs/openapi3.yml`; Overleaf registers `exportProject` in `router.mjs`. No single-file excerpt can contain that, so a recipe may name `context = [...]`, the harvester writes the stanza per side under `<name>/context/<side>/<relpath>`, the catalog carries `[[pair.context]]`, and `_materialize_side` lays the documents out beside the excerpt at their repository-relative paths. `mapping._route_manifest_entry_points` reads `operationId` plus the operation's `security` block; `_js_statements` joins a registration that spans lines, because reading `webRouter.post(` alone finds neither the handler nor the middleware that guards it.
  - **Anchors.** Real-Vuln-Benchmark trap rows take their fixed side from a different, correctly guarded handler of the same snapshot, so `handler_context` honours `line`/`fix_line` and a new `fix_function` gives the fixed side *its* registration instead of the vulnerable side's.
  - **`innermost_function_bounds`** for brace languages, used only by this mode: `function_bounds_at` returns the outermost top-level group, which for a handler declared inside a React component is the whole 6000-line component. `hunk` and `enclosing` rows keep the bounds they were harvested with.
  - **Fetch-then-write.** `harvest_recipe` fetches every blob before the first write, and the driver takes `--report` so a failed fetch leaves the reviewed excerpt exactly as it was and says why. A half-written re-harvest is indistinguishable from a real upstream change.
  - Bugs the re-harvest exposed and fixed on the way: `.mjs` and `.cjs` were not in `LANGUAGE_BY_EXTENSION`, so the one pair vendored as an ES module had **no file target at all** — no entry point, no finding, a permanent miss; and `_python_route_access` matched auth words anywhere in a decorator, so `@ns.doc(description='... without proper authorization checks')` read the unguarded ThreatByte endpoint as `authenticated`, silencing every obligation on it. The guard is now the decorator's name, never its prose, and `@token_required` — the commonest Flask guard — is recognised at all.
  - Corpus corrections: `lensops-kubernetesmanagement-fe4910` was labeled `setErrorMessage`, a React state setter, because the hunk landed in the wrong bounds; it is now `loadNamespaces` and the pair diff is exactly the fix. Its bug is a browser-side call omitting the header its siblings carry, not a missing guard on an inbound handler, so it carries `known_limit = "client_side_caller"` and leaves the denominators with a stated reason.
  - Three existing tests encoded the old corpus and now encode the new one: the TypeScript parse pin (the lensops excerpt parses now), the classifier report (`labeled` 0 -> 4, the four seeded rows; the six `title`-tier agent rows carry a family but are not labels a maintainer stands behind), and the hygiene report ordering.
  - **New honesty finding, recorded in the hygiene artifact as `cross_split_duplicates`: nine of the ten duplicate groups sit on both sides of the split.** Two forks of one project (`openniw-jobs-0fc947` train, `openniw-jobs-b74de3` holdout) and eight CVEs harvested twice under different names are byte-identical, so the train row teaches the holdout row exactly. `split_by_repository` cannot see it — the duplicates are different repositories. `duplicate_groups` is now ordered by name so the committed report does not reshuffle when one excerpt is re-harvested.
  - Pre-existing drift the regeneration corrected, unrelated to this task: `catalog.toml` in git disagreed with a fresh `catalog_gen` run at the group-3 tip on two derived labels (`origin` -> `createApplication`, `normalizeDomain` -> `getGoogleProvider`). Verified in a detached worktree at `7a33756` before touching anything.
