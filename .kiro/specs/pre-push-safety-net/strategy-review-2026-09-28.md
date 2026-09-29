# Strategy review after the independent evaluations (2026-09-28)

Status: for maintainer decision. Nothing below changes the approved specs until a direction is chosen.

## 1. What was measured

Two populations of real vulnerabilities that no rule had seen, each with its fix and a benign control, scored by
protocols committed before the first scan (`benchmarks/independent/`).

| | v1 (11 cases, 2026-09-24) | v2 (17 cases, 2026-09-28) |
|---|---|---|
| Analyzer | 13180a1 | a75b9f6 (v1 plus every retune learned from v1) |
| Recall | 1 / 11 | **0 / 17** (Wilson 95% 0–0.18) |
| Sampled precision | 1 / 12 | **0 / 17** (0–0.18) |
| Question completion | near zero | **12%** (13,206 / 108,374) |
| Benign false alerts | — | 3 |
| Run-to-run stability | not measured | 2 of 100 findings differ |

Between v1 and v2 the analyzer received every fix v1 suggested: file-owned graph gaps, `.gitignore` semantics,
Node `vm` sinks, Django sources, quoted-only SQL escapes, fixed-origin redirects, guards and allowlists. On the
v1 cases those retunes raised detection from 1 to 4 of 11. On untouched cases they transferred to nothing.

## 2. Why, per class of cause (observed in v2, from source)

1. **Entry points are framework-shaped, and our sources are token lists.** Request data arrives as
   `filter_input(INPUT_GET, …)` and the WordPress REST `$request` (GoPay, Directorist), plugin helpers such as
   `get_url_var()` (Groundhogg), FastAPI and NestJS typed or decorated handler parameters (qwed, ReactPress,
   LMDeploy, ContextForge), and Koa's `ctx.request` (Budibase). A vocabulary grows one framework at a time, and
   each new population brings frameworks it lacks.
2. **Flows cross module boundaries the frontends do not resolve.** JavaScript `require`d modules (FUXA's route
   to its storage module), dependency-injected receivers (YesWiki, v1), registry dispatch (OpenCVE, v1), parser
   combinators (alerta, v1).
3. **Sinks are matched by name, so precision fails where names collide.** Every sampled v2 finding was false:
   a regex `.match()`/`.exec()` read as injection, `header()` with an integer cast, parameterised ORM statements,
   client-SDK code, a process's own `argv`, a generated database name.
4. **Scale.** Large repositories complete a few percent of their questions inside a 40-minute budget (pgAdmin
   2%, ContextForge 6%, Budibase 1%); one repository crashes the taint batch on every scan (LMDeploy).

Classes 1–3 are breadth problems: each fix is correct and local, and the next repository needs another. That is
the pattern both evaluations show, and the reason more patching on the same design is unlikely to reach M4.

## 3. What we know about the alternative

The tool hunter (a model with `read_file` / `grep_repo` / `find_refs`) was measured once, on 2026-09-06, on the
vibe-py pair holdout: **12 of 14 detected, Youden +0.857, no leaks**, against the overlay's 5 of 14 on the same
pairs (class-aware scoring; `benchmarks/measurements/2026-09-06-vibe-py-holdout-hunter-*.json`). Caveats: one
language, curated excerpts, a pair corpus rather than whole repositories, and never run on an independent
population. Classes 1–3 above are exactly where a model reading the code has an advantage over token lists;
class 4 (cost, scope) is where it has a disadvantage.

## 4. Options

**A. Continue engine-first.** Model framework entry points, fix the sink-collision classes, raise completion,
then qualify on a v3 population. Every item is sound; the evidence (v1 → v2) says the breadth does not converge
at the pace one population teaches. Highest effort, weakest evidence.

**B. Model proposes, engine proves.** The hunter supplies recall; the CPG, where it can reach, supplies the
witness and admission evidence; findings the engine cannot confirm are reported as unconfirmed rather than
dropped. This inverts `propose-adjudicate-prove`'s current out-of-scope line ("making an LLM the adjudicator")
only partly: the model proposes, it does not adjudicate. Needs a cost and scope design (which files a pre-push
scan hands the model) and a run of the **unchanged** hunter on an untouched population before any tuning.

**C. Narrow the product.** Qualify one ecosystem first (for example WordPress plugins, the declared v0.1 target),
where a framework model is finite, and ship only that capability (M5 already allows per-capability enablement).
Compatible with A or B.

## 5. Recommendation

Run the decisive, cheap experiment before choosing: **the unchanged tool hunter on the v2 pins**, scored with
protocol v2's matching, within a stated model-cost budget. v2 is spent for the engine, but the hunter was never
tuned on it; the rule is that no hunter prompt, tool or configuration may change before that measurement is
recorded, and the scope handed to it must be decided and written down first (it must not use the fix diff or the
declared sites, which would leak the answer).

- If the hunter reaches useful recall on v2 with few fixed-side and benign alerts, re-plan M2–M4 around B,
  narrowed by C.
- If it does not, pursue A narrowed by C, starting with the WordPress entry-point model and the sink-collision
  precision classes, and qualify on a v3 population.

## 6. Decisions needed

1. Direction: run the hunter experiment first (recommended), or choose A, B or C now.
2. For the experiment: the scope handed to the model per pin, the model, and the cost ceiling.
3. Whether the roadmap's M1b/M2 work (rendering, runtime) pauses until the direction is chosen.


## 7. Update 2026-09-29: what the experiment showed

Recorded in `benchmarks/independent/results-v2-model-pipeline.json` (exploratory; v2 is spent for tuning).

**Instrument first.** Four defects had made every model-backed result since 2026-09-10 unmeasured: the default
model id was the product name and the API rejected it (cf57995); the hunter reached the embeddings provider, not
the chat provider (cf57995); the final-answer turn used the provider's JSON mode and the answers were lost
(3ffb8b4); one grep match in a minified bundle overflowed the model's context (8794884). The "hunter 1/17" number
in section 5's experiment was produced through the broken answer turn and is void.

**Scope selection, source only.** The declared vulnerable function is among the candidates for: the ranker's
top-20 entry points 1/17; the shipped sink vocabulary 2/17; a model reading every product file 15/17 ($14). The
vocabulary route (option A) is confirmed not to converge on this population.

**Verification.** Per-file triage, one 6-step tool hunt per file, two independent passes, report only agreement:
- validation set: 16 of 20 declared sites agreed, 12 of 15 cases; the 26 pgAdmin candidates that flickered
  between single runs reduce to 9 stable, 4 disputed, 13 quiet;
- full run, 7 of 17 cases before the account emptied ($23): detected 4/7 (pgAdmin, qwed, LMDeploy,
  ReactPress); ContextForge and FUXA found in one pass of two; winml missed because a CORS literal is triaged
  "constant" -- the config family needs its own question, not the reachability one;
- cost: $0.009-0.022 per candidate for two passes (old single-pass design: $0.017); a full two-pass run of the
  population is roughly $45-50.

**Precision is the open problem.** 196 agreed findings across 7 cases (pgAdmin alone 126 of 875 verified). Five
pgAdmin findings read against source: three true (privileged; raw `{{ data.* }}` in SQL templates, unescaped
stored `schema_res`), two false with rationales that contradict their own verdict (an ORM call the model itself
calls parameterized; a pickle from the signed session). Agreement cannot catch a mistake both passes make. The
proposed next filter is a no-tools judge over each agreed finding's rationale and code (~$0.002 per finding),
which was not run. Two-pass agreement is itself not stable between runs (ContextForge, FUXA).

**Standing.** Recall: the model route reaches 12/15 candidate-site cases where the engine reached 0/17 and the
vocabulary 2/17; that decides between options A and B in the model's favour for recall. Precision, fixed-pin
behaviour and cost at product scale are unmeasured. No gate is met. Any qualification needs population v3 and
a pre-registered protocol that also states the judge stage, the pass rule and the config-family question.
