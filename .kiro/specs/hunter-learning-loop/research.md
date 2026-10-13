# Research and design decisions: hunter-learning-loop

## Summary
- **Feature**: `hunter-learning-loop`
- **Discovery scope**: Extension of the learn harness and the valid benchmark; one new runtime dependency (DSPy).
- **Maintainer direction, 2026-10-13**: "the core we need to evolve is feature engineering ... that is the deciding
  factor here"; "labels for me are a pandas task"; DSPy for the hunter program first, statistics libraries second,
  no OpenAI SDK on its own ("unless dspy pulls it in"; it does, through litellm); lizard against its alternatives is worth
  pursuing; labels and folds are a pandas and scikit-learn task; Semgrep OSS is a good idea. Each of those is a
  feature producer or a feature consumer, and the feature table decides between them.
- **Key findings**:
  - The pilot (benchmarks/measurements/2026-10-12-valid-benchmark-pilot) measured the hunter at 5 to 6 of 12 and 54
    false alarms per 100 pushes after the classifier; 250 of 343 "vulnerable" suspicions on ordinary pushes sit more
    than 10 lines from the diff. The hunter never sees the diff (01-flowcharts/U6-hunter-client.md).
  - The harness already has the pieces the loop needs: labels (`learn/labels.py`), repository folds and leak audit
    (`learn/folds.py`, `learn/leaks.py`), paired experiments with cluster bootstrap and McNemar
    (`learn/experiments.py`), the cached caller (`learn/program.py`), and the runner that joins hunter output to
    frozen changes (`benchmarks/valid/hunter_arm.py`). What it lacks is a feature table and a program runtime that
    can be optimised rather than hand-edited.
  - `source.facts_for` (P1, commit 062a7b7) is the first feature producer: language, enclosing function, span,
    callers, entry points, from the repository only.

## Research log

### DSPy as the program runtime
- **Context**: requirements R3 to R6 need a signature with switchable inputs, demonstrations, instruction
  proposals, a scorer-driven compile, and metered, replayable model calls.
- **Sources**: local install, `dspy==3.4.1` into the research venv (`uv pip install --dry-run dspy`: 42 packages,
  among them `litellm 1.105`, `openai 2.54`, `gepa 0.1.4`, `diskcache`, `json_repair`, `tenacity`, `pydantic`);
  API introspection of the installed package (`dspy.LM(model, cache=True, num_retries=3, ...)`,
  `dspy.ReAct(signature, tools, max_iters=20)`, `dspy.Predict`, `dspy.Signature` with `InputField`/`OutputField`,
  `dspy.Evaluate(devset, metric, num_threads)`, `dspy.BootstrapFewShot`, `dspy.MIPROv2(metric, auto=...)`,
  `dspy.GEPA(metric, auto, reflection_lm, candidate_selection_strategy="pareto")`, `dspy.track_usage()`,
  `dspy.Module.save(path)`).
- **Findings**: `dspy.LM` reaches DeepSeek and OpenRouter through litellm with an OpenAI-compatible base URL and the
  key from the environment; the project's model id `deepseek-flash` is not in litellm's price table, so prices are
  registered from our table (`model/endpoint.py:55`). DSPy caches responses on disk (`diskcache`) keyed by the
  request; a run's cache directory is settable, so a run can be replayed from its own directory. `dspy.ReAct` is
  the tool-calling loop the hunter already is (read_file, grep_repo, find_refs). GEPA is the optimiser the
  learning-harness brief described (per-instance Pareto archive, reflective edits); MIPROv2 is the instruction and
  demo search. Neither applies our acceptance rule; that stays outside DSPy (R6).
- **Implications**: the hunter program is written as a DSPy module from the start; the classifier
  (`learn/program.py`) stays as is for this spec (R7.5). The hook's urllib client is untouched: the hook has no LLM
  tier yet, and the core install stays PyYAML-only; DSPy is a research extra.

### The feature table (labels and features as a pandas task)
- **Context**: R1, R3, R4 need one row per candidate location with named feature columns, a label, provenance, and
  the ability to switch columns off per ablation arm.
- **Findings**: `learn/features.py` builds feature records as nested dicts and parts; `learn/labels.py` (979 lines)
  joins sources by hand; `benchmarks/unseen/score.py` joins records by id. All of it is group-by, merge and
  dedup work. pandas and scikit-learn (grouped folds, calibration, metrics) are what the maintainer expects here and are pulled
  by none of the current extras.
- **Implications**: the loop's contract is a DataFrame (persisted as JSONL or parquet) with a fixed column schema;
  producers add columns, ablation arms drop columns, the program renders a row into its prompt. Existing dict-based
  builders are consumed, not rewritten, in this spec; migrating labels to pandas is part of the statistics item,
  not this one.

### Feature producers and the tools under evaluation
- **Context**: the annotation model (R3) lists the facts; the maintainer wants the producers chosen by what gives
  the best features.
- **Candidates**: `source.facts_for` (ours; P1), the semantic overlay facts (roles, def-use, obligations;
  `semantic/`), `mapping.analyze_entry_points`, lizard (function spans, nesting, cyclomatic complexity; pure
  Python), universal-ctags (spans across many languages; a binary), Semgrep OSS or Opengrep (pattern
  and taint findings as features; also a candidate to replace the quick-rule engine, a separate decision).
- **Result, lizard (benchmarks/measurements/2026-10-13-span-engines/REPORT.md)**: on 610 pair files and 570 labelled
  functions, lizard matches our parser engine line for line on C, Python and Java (end-line difference 0.00,
  name-set Jaccard 0.97 to 1.00) and survives the 56 excerpts the cpp grammar rejects, but loses 6 of 44 labelled
  JavaScript functions to naming (`$` identifiers, `function anonymous`, nested named functions, assigned function
  expressions), gets TypeScript end lines wrong on 22% of labels (one by 81 lines), has no Perl reader, and is the
  slowest of the four engines. Verdict: keep ours; lizard's per-function cyclomatic complexity and nesting are a
  candidate feature column, not a span engine (its nesting correlates with `measure_nesting` at Spearman 0.6, so
  it is not a drop-in there either).
- **Result, tree-sitter-language-pack**: the same tree-sitter, 503 of 503 spans identical with our parser engine,
  1.4x faster (it caches parsers), one 6 MB MIT wheel in place of six grammar wheels, and it adds Go, Ruby, PHP
  and Perl grammars that ours handles by regex today. Adopt it as the grammar packaging in `semantic/extra.py`;
  map `.c` to the c grammar first (20 of the 56 rejections clear); cache the parser. `tree-sitter-languages` is
  ABI-broken under tree-sitter 0.26; universal-ctags has no pip build.
- **Pending**: the Semgrep CE and Opengrep brief (`~/ousast-results/fossil/semgrep-brief.md`). Producers land behind
  the same contract; the ablation decides whether their columns stay.
- **Research needed**: Semgrep registry rule licence terms for an open-source tool.

### Training data apart from the pilot
- **Context**: R2. The pilot (252 changes, 12 positives) is held out.
- **Findings**: `benchmarks/valid/catalog.py` and `verify.py` produce fix-site positives from OSV advisories in
  about 12 accepted per 32 advisories; the used-set guard (`benchmarks/unseen/*`) excludes training-only sources.
  `learn/folds.py` groups by repository; `learn/leaks.py` audits per-signal separation.
- **Implications**: about 100 advisories give about 40 positives; negatives at 20 per positive from the same
  repositories; folds by repository; the pilot is never read by the loop.

## Architecture pattern evaluation
| Option | Description | Strengths | Risks | Notes |
|---|---|---|---|---|
| A. Extend `learn/program.py` with a hunter signature | one harness, our caller and cache | no new dependency | the compile loop has no train-vs-holdout rule, no tool loop, no optimiser beyond demos+instructions; everything the maintainer asked for (statistical mutation of prompts) is to build | rejected |
| B. New `hunt/` package on DSPy, feature table as the contract, harness reused for labels, folds, leaks, paired analysis | the optimisers, the tool loop, caching and usage come with the library; our code is the feature producers, the table, the acceptance rule, the scoring | one heavy research dependency; two caches (DSPy's and `Caller`'s) until the classifier migrates | selected |
| C. Rewrite the classifier onto DSPy too | one runtime | large rewrite of a parked line | later, if B earns it |

## Design decisions
### Decision: DSPy runs the hunter program; the acceptance rule stays ours
- Alternatives: A above; a hand-written optimiser.
- Selected: `dspy.ReAct` over a `HuntSignature` whose inputs are the rendered feature row plus the changed hunks;
  `dspy.GEPA` or `MIPROv2` propose candidates; `dspy.Evaluate` scores them on compile folds with our metric; the
  candidate is accepted only by our rule on held-out folds (R6), implemented outside DSPy.
- Trade-offs: DSPy's cache is request-keyed, not content-addressed; a run pins its cache directory and copies it
  with the run record. Cost comes from `dspy.track_usage()` with our prices registered in litellm.

### Decision: the feature table is the contract between producers, ablation and the program
- Selected: one row per (change, path, line) candidate with columns `feature.<producer>.<name>`, `label`,
  `provenance.*`, `fold`; producers are functions `(root, change, path, line) -> dict`; an ablation arm is a
  column mask recorded in the manifest; the program sees only the unmasked columns, rendered in a fixed order.
- Trade-offs: a table per run is larger than nested records; it is also what pandas, scipy and the maintainer read.

### Decision: producers are a fixed list, switched by name, no registry
- `source.facts_for`, `semantic` facts (roles, def-use, obligations), `mapping` entry points, `diff` hunks; lizard and
  Semgrep/Opengrep join the list only after their evaluation reports.

### Decision: objective and metric
- Search stage: recall over verified fix sites (a suspicion within the scorer's tolerance of the fix site with the
  right family) and suspicions per ordinary push; the DSPy metric returns the per-change score and, for GEPA, a
  text feedback naming the missed site or the off-diff suspicions. No threshold is tuned (R4.7); the curve is
  reported (R4.8).

## Risks and mitigations
- DSPy or litellm upgrades change behaviour: pin `dspy==3.4.*`, record versions in every run artifact.
- A producer reads a label by accident: producers take the repository and a location only; a test feeds a
  repository with a planted advisory id and asserts no feature carries it (R3.7).
- Train-on-test: the pilot path is denied to the loop by construction (the runner refuses the pilot manifest
  digest), and every artifact lists the data digests it read (R2.4).
- Cost: budgets per run (R9.1); DSPy cache on; `--replay-only` reruns at no cost.

## References
- DSPy 3.4.1 (installed; https://dspy.ai), GEPA (https://github.com/gepa-ai/gepa), litellm pricing registration.
- PATHFINDER-2026-10-13/01-flowcharts/U6-hunter-client.md, U7-learn-memory-tasks.md; 02-duplication-report.md D1, D4.
- benchmarks/measurements/2026-10-12-valid-benchmark-pilot/NOTES.md (numbers and the filter sweep).
