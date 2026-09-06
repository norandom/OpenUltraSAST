# Implementation Plan

- [ ] 1. Foundation: taxonomy, endpoint, corpus fields, grammar
- [ ] 1.1 Closed family taxonomy with a verifier per family
  - Ten families exactly as decided, each with its CWE set, mechanism set, verifier kind (canary, static, none) and description; `unknown` always present with no verifier; a version string.
  - Loader rejects an unknown field, an eleventh family, a missing verifier kind or a CWE claimed by two families, naming the offender; relation lookup answers same, parent–child, lateral or fabricated for any two ids.
  - Observable: the taxonomy loads from the ruleset directory, a fixture with a fabricated family fails by name, and every mechanism id in the mechanism vocabulary resolves to exactly one family.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [ ] 1.2 Independent chat endpoint with the DeepSeek adapter
  - Endpoint resolution order: explicit override, scripted client modes, DeepSeek key and base URL, then OpenRouter; the embedding client keeps reading only its own variables; `[models]` gains the hunter and judge defaults and the endpoint keys, `[learning]` gains its section.
  - Adapter disables thinking and sends temperature zero for detector and classifier calls, keeps the provider's reasoning field on assistant messages so a caller can replay it, supports JSON-object mode with one retry on empty content and optional log-probabilities, and reports normalized usage and cost from the provider's cache-hit fields.
  - Observable: with both provider keys set the hunter client targets the DeepSeek base URL without a version suffix while the embedding client still targets OpenRouter; a scripted client is chosen under the existing environment flag; a recorded request shows thinking disabled and the reasoning field retained on the reply.
  - _Requirements: 6.6, 11.4_

- [ ] 1.3 Additive corpus fields and hygiene at load
  - Expected rows accept an opaque family id (validated later by the classifier task, so the corpus module never imports the learning package); a pair carries a computed unscorable reason (identical twin by normalized body comparison with headers stripped, computed only when the catalog does not already declare a known limit) and is never dropped; duplicates across pairs are reported before any split; a repository-and-date split helper assigns train or holdout to rows that lack a split, keeps declared splits, and reports rows from one repository that straddle the split; pair signals take a split filter.
  - Observable: the five identical vibe-py twins load with the identical-twin reason and the existing catalogs load with unchanged row counts; the straddle report on the current catalogs is produced and committed.
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [ ] 1.4 TypeScript rows parse under the extra
  - The semantic extra gains the TypeScript grammar and the parser maps TypeScript and TSX to it; the extra-free suite still skips them with the existing marker.
  - Observable: every vendored TypeScript pair parses on both sides under the extra, and the parser reports no unsupported-language result for TypeScript or TSX.
  - _Requirements: 10.1_

- [ ] 1.5 Curated hunter tools and hunter-loop parameters
  - Four new repository tools beside the existing three: resolve a definition by symbol, list entry points, list flows for a function, list obligations for a function, each clamped to the scanned repository and returning identifiers and line spans only; the hunter loop gains prompt, context files, tool set, character limit and tag parameters with today's behavior as defaults and replays the provider's reasoning field across tool turns.
  - Observable: the existing hunter tests pass unchanged with default parameters; each new tool answers on the shared handler fixture and refuses a path outside the repository; a recorded tool-turn conversation shows the reasoning field replayed.
  - _Requirements: 6.4, 6.5_

- [ ] 2. Core: classifier, scorer, detectors, verifiers, journal
- [ ] 2.1 (P) Classifier tiers
  - Tier one decides from rule id, sink family, obligation kind, mechanism id or labeled CWE without a model; tier two asks the chat endpoint in JSON-object mode with thinking disabled and averages log-probabilities, falling to unknown under a threshold; tier three is unknown; every answer records its tier; results are multi-label; loaded catalog family labels are validated against the taxonomy here and a fabricated family is rejected by name.
  - Observable: on the shared handler fixture tier one classifies the leaky handler as access control without any client; with a scripted client an off-vocabulary answer becomes unknown; a catalog with a fabricated family is rejected by name.
  - _Requirements: 2.1, 2.2_
  - _Boundary: Classifier_

- [ ] 2.2 Classifier measurement and review queue
  - Report: agreement with maintainer labels on reviewed pairs with parent–child partial credit and no credit for lateral or fabricated ids, confusion matrix per family, accuracy against a random router and an oracle router, counts per tier and unknown; disagreements append to a review queue and never change a label; the whole corpus, including free-text and `other` rows, is classified with per-family counts.
  - Observable: the report on the vendored corpus lists the vfc `other` rows by resulting family and the queue holds every disagreement once with both answers and the tier.
  - _Requirements: 2.3, 2.4, 2.5_

- [ ] 2.3 (P) Per-pair family scoring
  - Detection only for a finding whose family tag relates same or parent–child to the labeled family and whose line lies in the labeled function, with the maximum penalty for a fabricated family; silence only when no such finding lies in the labeled function on the fixed side; other findings counted separately, never as leaks; text is never inspected; outcomes pair-correct, both-flagged, both-silent, reversed and unscorable; the unscorable reason also covers unsupported language, unresolved label and missing context.
  - Observable: a synthetic run set where every fixed side carries an other-family finding scores full silence; a finding with a fabricated family never counts; a pair in an unsupported language scores unscorable with that reason.
  - _Requirements: 3.1, 3.2, 3.6, 4.1_
  - _Boundary: Scorer_

- [ ] 2.4 Aggregation, noise handling and denominators
  - Per family and slice: outcome counts, recall, silence, Youden, directional-bias index, a fixed-false-positive-rate view; K runs per pair with the majority outcome, negative flips per family against a baseline set, and a paired reliable-change test; unscorable rows listed by reason and excluded from every denominator; every metrics block carries the taxonomy version and the scorable and unscorable counts.
  - Observable: a single-run difference below the reliable-change threshold reports no change while a consistent flip across runs does; the unscorable count and taxonomy version appear in every metrics block.
  - _Requirements: 3.3, 3.4, 3.5, 4.5_

- [ ] 2.5 (P) Per-family detector configurations and the family detector runner
  - A configuration directory per family: prompt under a stated length cap, checklist, tool list from the curated set only, step and cost budget, maximum characters, hard negatives and counterexamples, version; the loader rejects an over-cap prompt, an unknown tool or a missing family; this task ships the loader and a test fixture configuration, the shipped per-family directories are written by round zero.
  - The runner takes the families admitted by the classifier as input, builds the detector's user message from the whole file plus definitions its tools resolve, runs the hunter loop with the family's prompt, tools and budgets, and tags each finding with exactly one family tag and one detector-version tag; the generalist is the unknown family's configuration.
  - Observable: a family run on the shared fixture with a scripted client yields findings tagged with that family and version and uses only the family's tool list; a configuration whose prompt exceeds the cap fails to load by name.
  - _Depends: 2.1_
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_
  - _Boundary: Detectors_

- [ ] 2.6 (P) Verifier registry and the oracle callback
  - The regress verdict accepts an optional oracle callback and keeps exit-code behavior otherwise; a registry keyed by the taxonomy's verifier kind returns a canary, static or no-op verifier; the static verifier raises access-control claims to static corroboration when the obligations checker reports the same function; the no-op verifier leaves suspicion.
  - Observable: with the fake sandbox runner a result whose output carries the token yields triggerable while a nonzero exit without the token does not; a family with no verifier keeps suspicion on the shared fixture; the access-control claim on the leaky handler reaches static corroboration.
  - _Requirements: 7.1, 7.3, 7.4_
  - _Boundary: Verifiers, Regress_

- [ ] 2.7 Canary templates and the second judge
  - Family snippet templates for injection, file path and deserialization plant a canary (row in an in-memory database, file under the scratch mount, marked object) and print the token only when the vulnerability fires; the second judge asks the judge model with the snippet, oracle output and claim and answers confirm or not in JSON-object mode; a claim is published as proven only when it confirms; templates, oracle code and gold labels live outside every proposer write root.
  - Observable: every canary template passes the existing snippet safety check; a scripted judge that declines keeps the claim below proven; templates and oracle code live under the verifier directory and gold labels under the corpus directory.
  - _Requirements: 7.2, 7.5_

- [ ] 2.8 (P) Round journal, archive and rejected buffer
  - Append-only round records with hypothesis, levers, predicted affected and at-risk families, outcome, reason, target deltas, per-family sweep flips, attribution (flipped predicted, flipped unpredicted, precision), cost, taxonomy and configuration versions; a per-family archive of which configuration version wins which pair; a rejected-hypothesis buffer per family; every persisted text passes redaction.
  - Observable: a record round-trips through the file; the buffer returns only the target family's rejected hypotheses; the archive names one winner per pair per family; a secret literal written into a record is stored redacted.
  - _Requirements: 9.3, 9.6, 9.7, 11.3_
  - _Boundary: Journal_

- [ ] 3. Integration: split, scoring paths, rounds, proposer, publish, CLI
- [ ] 3.1 One teacher rule across every learning path
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
  - _Depends: 3.3_
  - _Requirements: 9.5_

- [ ] 3.7 Evolve round orchestration, cost and journal
  - One round: facts, proposal, refusals, train minibatch, target-family holdout, sweep over every other family's holdout, K-run scoring at every stage as the scorer requires, accept (freeze, bump version, archive) or revert; cost metered per stage with revert and a recorded reason on overrun; a journal record and the rejected buffer written for every outcome; a round directory holds the snapshot, proposal, scores and trajectories and a repeated round number is refused.
  - Observable: with the scripted proposer each of accepted, rejected, budget-breach and cost-overrun leaves one journal record with attribution and a round directory; a repeated round number is refused.
  - _Depends: 3.5, 3.6_
  - _Requirements: 9.4, 9.6, 9.7, 9.8, 9.9_

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
- [ ] 4.1 Re-harvest absence rows with registration context
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
