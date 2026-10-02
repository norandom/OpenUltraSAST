# Implementation Plan

One task group per increment of `design.md` section 7, in that order; a later group never starts before the
earlier group's kind proof is recorded. Every task ships with its tests; a task is done when its tests pass in
the host suite, ruff and mypy are clean, and nothing in `src/`, `plane/`, `ops/` (minus `ops/ax/up.sh` and
`ops/k8s/profiles/`) or `docs/` names `kind-ousast`, `localhost:5001`, `172.19.` or a port-forward address
(task 1.3 makes that a test). Nothing is deleted before its replacement passes its proof. Each group ends with
its kind proof and the record it writes under `benchmarks/measurements/<date>-k8s-NN-<slug>/record.json`
(commit, images, the instrument checks, the numbers). Steps that call a model are marked **paid: needs a budget
go-ahead** with a ceiling; steps that need a hand on a cluster that does not exist yet are marked **manual**.

- [ ] 1. Profile and literals (design section 1; open-question checks 2, 3, 7)
- [x] 1.1 `PlaneProfile`
  - `src/openultrasast/plane/profile.py`: frozen dataclass with the fields of design section 1; `load_profile()`
    reads `ops/k8s/profiles/<OUSAST_PLANE_PROFILE>.toml` (a name or a path; default `kind`), then applies
    `OUSAST_<FIELD>` overrides; rejects an unknown key, a secret-looking key (`*_KEY`, `*_SECRET`), an `exec`
    outside `local|remote`, an `images` file without digest pins. `ops/k8s/profiles/kind.toml` and `k3s.toml`
    committed with the design's values; `ops/k8s/profiles/kind-images.json` from `~/.cache/ousast/ax-src/runner-image`.
  - `tests/test_plane_profile.py`: defaults; file then env precedence; each rejection names the field; both
    committed profiles load; no field holds a value matching a credential pattern.
  - _Requirements: 1.1_
- [x] 1.2 Literals out of `doctor.py`, `egress.py`, `router.py`, `generate.py`
  - `doctor(profile)`: context from `profile.kube_context`; the registry check resolves the `images` file's runner
    reference (`docker manifest inspect` for a remote registry, `/v2/_catalog` for a local one); `open_store`
    verifies `profile.memory`; prints every configured address (Req 1.2). `Egress(context=...)`,
    `open_router(context=...)` and `receiver_cluster_ip(context)` take the profile's context; `generate.ATESPACE`
    becomes `profile.atespace`. `cli.py`: `ousast plane doctor|run|workspaces|harvest` accept `--profile`.
  - `tests/test_plane_reconciler.py`, `test_plane_router.py`, `test_plane_egress.py`: the fakes receive the
    profile's context, never a built one.
  - Evidence: `grep -rn "kind-" src/openultrasast/plane` matches only comments citing the kind profile.
  - _Requirements: 1.1, 1.2_
- [ ] 1.3 Host-literal scan test
  - `tests/test_plane_literals.py`: pattern built at runtime (as `tests/test_removed_plane_references.py` does)
    over `src/`, `plane/`, `ops/` minus `ops/ax/up.sh` and `ops/k8s/profiles/`, and `docs/`, for `kind-ousast`,
    `localhost:5001`, `172.19.`, `127.0.0.1:` and `port-forward` outside `router.py` and lines tagged
    `ax-tunnel`; fails listing `path:line`.
  - Evidence: the test passes on this commit and fails when a literal is reinserted (shown once in the record).
  - _Requirements: 1.3_
- [ ] 1.4 `up.sh` by profile
  - `ops/ax/up.sh`: `KO_DOCKER_REPO` and the context from `kind.toml` (read with `python -m
    openultrasast.plane.profile --print registry|kube_context`); writes `kind-images.json` instead of
    `runner-image`; `generate.repin_templates` accepts that file (runner key only until task 4.3).
  - Evidence: `ops/ax/up.sh` reruns idempotently on kind; `ops/ax/smoke-run.sh` passes.
  - _Requirements: 1.1, 2.4_
- [ ] 1.5 Placement probe (open question 2, decided before the engine work)
  - `ops/ax/probe-placement.sh`: applies a second WorkerPool `probe-pool` (1 replica, 3 Gi) from the design's
    engine template, then one model-free `repo-facts` Task with `resources.requests.memory: 2560Mi`, and records
    with `kubectl ate get workers` which worker took the actor; then the same Task with 256Mi. Removed after.
  - Evidence: `record.json` says whether Substrate places by resource fit (`placement: fit|any`). `any` selects
    the design's fallback for group 5 and is written into `design.md` section 4 before group 5 starts.
  - _Requirements: 4.1_
- [ ] 1.6 Reconciler bound (open question 7)
  - Record `wc -l src/openultrasast/plane/reconciler.py` (477 at 17ac7ad) and the lines task 2.4 may add
    (receiver wiring removed: `-12`, `Delivery` calls: `+8` estimated). If the estimate crosses 500, the bound
    in `tests/test_plane_reconciler.py:803` moves to 550 in task 2.4 with the reason in the assertion message.
  - Evidence: the numbers in `record.json`.
  - _Requirements: 2.1_
- [ ] 1.7 gvisor tarball reachability (open question 3) **manual**
  - `docs/deployment.md` (B.1, planned): the k3s node must fetch
    `gs://gvisor/releases/nightly/2026-09-02/<arch>/gvisor.tar.zstd` (`substrate/manifests/ate-install/sandboxconfig-gvisor.yaml`)
    or a mirrored copy named in a copied SandboxConfig; the check is `kubectl -n ate-system logs` of the worker
    pod's atelet fetch line, run by hand on the day k3s exists. Labelled planned until then.
  - _Requirements: 7.2_
- [ ] 1.8 Kind proof and record 01
  - `ousast plane doctor --profile kind` passes every line; `ousast plane doctor --profile k3s` fails only on the
    unreachable context (the expected line); `test_plane_literals` 0 offenders; the probe of 1.5; the bound of 1.6.
  - `benchmarks/measurements/<date>-k8s-01-profile/record.json`.
  - _Requirements: 1.1, 1.2, 1.3, 7.1_

- [ ] 2. Store delivery, receiver-less egress (design section 3)
- [ ] 2.1 Presigned URLs and the store run directory
  - `src/openultrasast/plane/delivery.py`: `Delivery(store, run)` mints presigned PUT for
    `runs/<run>/<task>/output.tar` and GET for `runs/<run>/<producer>/<artifact>` (boto3 `generate_presigned_url`
    on `S3Client.sdk`, expiry `OUSAST_TASK_TIMEOUT + 600`); `delivered(task)` HEADs the tar; `collect(task)`
    downloads, extracts under the run dir with the member checks `Receiver.accept` has, re-puts declared
    `outputs[]` as single objects, writes `done.json`; `put_input(name, path)` for inputs no task produces;
    `state.json` mirrored to `runs/<run>/state.json` and seeded from it on a rerun.
  - `tests/test_plane_delivery.py`: against a local S3-shaped fake (PUT/GET/HEAD by key); URLs never appear in
    logs; expiry; member rejection; declared-only re-put; state seeding.
  - _Requirements: 3.1, 2.1_
- [ ] 2.2 Runner: `delivery` in the start body
  - `src/openultrasast/plane/runner.py`: `StartGate.offer` validates an optional `delivery {put, inputs}` (https,
    hostname, no echo); `_deliver_output` PUTs the tar to `delivery.put` (same retry and `DeliveryError`
    semantics); `fetch_inputs` GETs from `delivery.inputs[name]`; `OUSAST_ARTIFACT_URL` and `OUSAST_ARTIFACT_DIAL`
    stay honoured until task 2.6 so both paths run in the same build.
  - `tests/test_plane_runner.py`: accepted body with `delivery`; 400 on an `http` or IP URL; PUT to a local
    server; inputs fetched from presigned-shaped URLs; the marker and retry-only boot unchanged.
  - _Requirements: 3.1_
- [ ] 2.3 Egress without the receiver
  - `src/openultrasast/plane/egress.py`: `policy_for(task, workspaces, model, store_host)` emits one
    `tlsPassthrough` rule on 443 over the sorted union of store host, Git hosts, Model hosts; no `http` rule; an
    IP store host raises naming `S3_ENDPOINT`.
  - `tests/test_plane_egress.py`: for every committed template under `plane/tasks/` the rendered policy is the
    expected set; the IP refusal.
  - _Requirements: 3.2_
- [ ] 2.4 Reconciler on `Delivery`
  - `src/openultrasast/plane/reconciler.py`: `run()` opens the store first (no fallback), builds `Delivery`,
    passes `delivery` to `router.starter`/`start_task` (body extended in `router.py`), `_await` on
    `Delivery.delivered`, outcome from the collected `summary.json`; the receiver thread is kept behind
    `OUSAST_DELIVERY=receiver` for this group only. Line bound per task 1.6.
  - `tests/test_plane_reconciler.py`: the ax fake run completes through the delivery fake; a rerun from an empty
    results root resumes from the store's `state.json`.
  - _Requirements: 2.1, 3.1_
- [ ] 2.5 Kind proof and record 02
  - `ops/ax/smoke-run.sh` with `OUSAST_DELIVERY=store`: `facts.json` and `summary.json` arrive through the store;
    the actor's policy read back has one TLS rule naming the store host; `ousast plane status ax-e2e-smoke`
    prints the table. Instrument: the tar's byte size from the store equals the extracted files' total.
  - `benchmarks/measurements/<date>-k8s-02-store-delivery/record.json`: bytes, PUT-to-poll seconds, rules.
  - _Requirements: 3.1, 3.2, 7.1_
- [ ] 2.6 Remove the receiver (last; after 2.5 is recorded)
  - Delete `Receiver`, `_Handler`, `receiver_address`, `receiver_cluster_ip`, `RECEIVER_HOST`, `RECEIVER_PORT`
    from `egress.py`; `OUSAST_ARTIFACT_URL/DIAL/HOST/PORT` from `runner.py` and `reconciler.py`; the
    `OUSAST_DELIVERY` switch; `ops/ax/receiver-service.yaml.tmpl` and the `up.sh` receiver step; the EndpointSlice
    from kind (`kubectl delete`). Docs: `docs/plane.md` sequence diagram, `docs/deployment.md`, `ops/ax/README.md`.
  - Tests using `OUSAST_ARTIFACT_HOST` move to the delivery fake; `test_plane_literals` covers `172.19.`.
  - Evidence: `ops/ax/smoke-run.sh` passes again on the build without the receiver; recorded in 02's record as
    `receiver_removed: <commit>`.
  - _Requirements: 3.1, 1.3_

- [ ] 3. `--exec remote` from a CI-shaped principal (design section 2; open-question check 1)
- [ ] 3.1 Execution mode and RBAC manifests
  - `cli.py`: `ousast plane run --exec local|remote` (default `profile.exec`); `reconciler.Ax` passes the
    profile's context to `ax` (its context flag, read from `ax --help` and pinned in a test); `remote` refuses a
    `file://` store. `ops/k8s/base/rbac-ci.yaml`: SA `ousast-ci` in `ax-system`; Roles and RoleBindings in
    `ax-system` and `ate-system` with `pods` get/list, `services` get, `pods/portforward` create, nothing else.
  - `tests/test_plane_rbac.py`: fake `kubectl`, `ax`, `kubectl-ate` record argv over a full fake Run; the
    verbs implied (`port-forward` -> `pods/portforward` create + `pods` get + `services` get) equal the rendered
    Role's rules exactly.
  - _Requirements: 2.1, 2.2_
- [ ] 3.2 Substrate's authorization of the SA token (open question 1)
  - `ops/ax/probe-ci-token.sh`: `kubectl create token ousast-ci --duration=2h` into a kubeconfig; `kubectl ate
    --token-file - get workers` and `create egress-policy` on a throwaway actor with that kubeconfig. If refused,
    read `substrate/docs/api-guide.md` for the grant (atespace role or token audience) and add the manifest to
    `ops/k8s/base/rbac-ci.yaml`; if no grant exists for a non-admin token, record it and the design's remote mode
    uses the maintainer's admin kubeconfig for the proof, with the gap listed in the runbook.
  - Evidence: `record.json` names the grant used (`grant: <kind/name>` or `admin-kubeconfig`).
  - _Requirements: 2.1_
- [ ] 3.3 CI-shaped container
  - `ops/k8s/ci-shell.Dockerfile`: `python:3.12-slim` + this package + `kubectl`, `kubectl-ate`, `ax` (built from
    the checkouts); no `.env`; runs with `-e KUBECONFIG=/run/kc -e DEEPSEEK_API_KEY -e S3_*` only.
    `.github/workflows/plane-remote.yml` (dispatch only, no schedule): the same image running `ousast plane run
    --exec remote --profile k3s` with repository secrets; disabled until k3s exists (labelled in the file).
  - _Requirements: 2.2, 2.3_
- [ ] 3.4 Kind proof and record 03 **paid: needs a budget go-ahead, ceiling 0.50 USD**
  - From the container of 3.3 against kind (`kind.toml` with `exec = "remote"`): the smoke Run (model-free), then
    one `verify` pass over one case of `plane/runs/validation-46.yaml` (budget `{usd: 0.5, calls: 60}`) so the
    credential path is exercised remotely. Kube audit log (kind apiserver `--audit-policy` of the SA's verbs)
    lists only the Role's verbs.
  - `benchmarks/measurements/<date>-k8s-03-remote-exec/record.json`: audit verbs vs Role, grant of 3.2, run
    status, usd spent.
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 7.1_

- [ ] 4. Images on GHCR (design section 8)
- [ ] 4.1 `images.yml`
  - `.github/workflows/images.yml` on tags `v*`: `docker/build-push-action` for `plane/Dockerfile.runner` ->
    `ghcr.io/norandom/ousast-runner:<tag>` and the root `Dockerfile` -> `ghcr.io/norandom/ousast-engine:<tag>`;
    digests as job outputs and as the release asset `images.json` (`{"runner": "...@sha256:...", "engine": ...}`);
    `GITHUB_TOKEN` with `packages: write`.
  - Evidence: a dry run on a `v*-rc` tag publishes both and the asset (the engine build is ~2.8 GB: record the
    build minutes).
  - _Requirements: 1.1, 4.2_
- [ ] 4.2 Engine image under the runner contract
  - Root `Dockerfile`: the `ax-task-runner` shim and `/workspace` as `plane/Dockerfile.runner:25-29`; the `s3`
    extra is not needed in either image (the runner PUTs by URL).
  - `tests/test_plane_images.py`: both Dockerfiles declare the shim and entrypoint (text check).
  - _Requirements: 4.2_
- [ ] 4.3 `repin` for two images
  - `generate.repin(plane, images)`: `engine.yaml` (added in 5.1; until then absent is fine) takes
    `images["engine"]`, every other template `images["runner"]`; `ousast plane repin images.json`;
    `--runner-image FILE` keeps the single-image file working. `ops/k8s/profiles/k3s.toml` names `images.json`
    downloaded from the release.
  - `tests/test_plane_increment.py`: repin with a two-key file; a template with two image lines is refused.
  - _Requirements: 1.1, 4.2_
- [ ] 4.4 Kind proof and record 04
  - Pools' pod template takes `imagePullSecret` from the profile (`ops/k8s/base/workerpool-*.tmpl`, task 6.1
    brings the full template; here the field only); kind pulls `ghcr.io/norandom/ousast-runner@sha256:...` with
    `ghcr-pull` if the package is private; the smoke Run passes on the GHCR image.
  - `benchmarks/measurements/<date>-k8s-04-ghcr-images/record.json`: image sizes, pull seconds, visibility.
  - _Requirements: 1.1, 4.2, 7.1_

- [ ] 5. The engine as a plane task (design section 4)
- [ ] 5.1 `cpg/dump.py` and `tasks/engine.py`
  - Lift `benchmarks/push/finding_dump.py`'s scan into `src/openultrasast/cpg/dump.py` (the script becomes a
    thin caller; `ops/README.md:78` command unchanged). `src/openultrasast/plane/tasks/engine.py`: env
    `OUSAST_WORKSPACE_DIR`, `OUSAST_FIXED_DIR`, `OUSAST_INPUT_CASE`, pins, `OUSAST_FAMILIES`, `OUSAST_DEADLINE`;
    per pin the quick scan (`tasks.alerts.scan`) and the engine in-process; rows via `engine_alerts.engine_rows`,
    the instrument checks via `read_record`'s rules; `summary.json` as `engine_alerts.produce` writes it with
    `host: false`. `plane/tasks/engine.yaml`: `command: ["engine"]`, requests 3Gi/1, limits 4Gi/2, image from
    `images["engine"]`. `generate.TEMPLATES` gains `engine`; `--loop` emits `engine` instead of `alerts` for a
    case needing the engine when the images file has an engine key.
  - `tests/test_plane_engine_task.py`: a fixture record -> rows and summary equal to `produce`'s shape; the
    unread-input and zero-question failures; the generator's choice.
  - _Requirements: 4.1_
- [ ] 5.2 `engine-pool`
  - `ops/k8s/base/workerpool-engine.yaml.tmpl` rendered by `plane/k8s.py` (task 6.1 generalises; here the engine
    values): kind replicas 1, 4Gi/2; if 1.5 recorded `any`, apply the design's fallback and write it here.
  - Evidence: `kubectl -n ax-system get workerpool engine-pool` ready on kind with `ousast-pool` at 1 replica.
  - _Requirements: 4.1, 5.1_
- [ ] 5.3 `alerts-engine` marked development-only
  - `cli.py` help, `docs/plane.md` task table, `ops/README.md`: "development only (needs Docker on the host);
    the plane task is `engine`". No code removed.
  - _Requirements: 4.3_
- [ ] 5.4 Kind proof and record 05
  - The froxlor case of `validation-46` as an `engine` task on kind (model-free, deadline 1800 s per pin):
    rows equal `benchmarks/measurements/2026-09-30-php-engine-alerts/` (6/6 per pin), placement on `engine-pool`
    shown by `kubectl ate get workers`, peak memory from `kubectl top`.
  - `benchmarks/measurements/<date>-k8s-05-engine-task/record.json`: rows diff, seconds per pin, peak memory,
    placement, image size and pull seconds.
  - _Requirements: 4.1, 4.2, 7.1_

- [ ] 6. Pools, autoscaling, node checklist (design section 5)
- [ ] 6.1 `plane/k8s.py` and the manifests
  - `src/openultrasast/plane/k8s.py`: `render(profile, out)` writes `workerpool-default.yaml`,
    `workerpool-engine.yaml`, `ax-server-snapshots.yaml` (patch with `profile.snapshots_bucket`), `rbac-ci.yaml`;
    for `k3s` also `imagepullsecret.yaml`, `hpa-default.yaml`, `hpa-engine.yaml`, `prometheus-adapter.yaml`
    (copied from `substrate/demos/autoscaled-workerpool`, namespace `ax-system`, metric
    `ate_workerpool_workers{state=at_capacity}`, `averageValue 0.7`). `ousast plane manifests --profile P --out
    DIR`; `ops/k8s/render.sh`. `ops/ax/workerpool.yaml.tmpl` deleted once `up.sh` uses the renderer.
  - `tests/test_plane_k8s.py`: both profiles render; kind has no HPA and no pull secret; k3s has both; engine
    pool limits >= `engine.yaml` limits; every image digest-pinned; no host literal in the output.
  - _Requirements: 5.1_
- [ ] 6.2 Node checklist and footprint
  - `docs/deployment.md`: the gVisor correction (no RuntimeClass; `ateom-gvisor` runs `runsc` from the
    SandboxConfig tarball), PodSecurity for the worker pod's securityContext (recorded from kind), local-path for
    `/var/lib/ate`, the measured footprint per task type (`verify`, `repo-facts`, `engine` from 05) and the
    queueing consequence of one actor per worker with `--workers`.
  - _Requirements: 5.2, 7.2_
- [ ] 6.3 Kind proof and record 06 (HPA: render only; live is k3s-only, **manual** later)
  - `render.sh kind` applied on kind replaces the hand template with identical pools (`kubectl diff` empty but
    for labels); worker pod `securityContext` captured; `render.sh k3s` validates with `kubectl apply
    --dry-run=client` against kind's API (CRDs present).
  - `benchmarks/measurements/<date>-k8s-06-pools/record.json`: footprint table, securityContext, dry-run result.
  - _Requirements: 5.1, 5.2, 7.1_

- [ ] 7. `ousast plane scan` (design section 6)
- [ ] 7.1 Workspaces and candidates from URL + commits
  - `generate.scan_cases(url, base, head, cache, *, all=False)`: shallow clone into the case cache, two pinned
    Workspaces, head-side hunks via `fix_ranges(side="new")`, functions via `repo_facts.enclosing` over
    `product_files`, quick alerts via `tasks.alerts.scan` on the changed files, `candidates.json` and
    `functions.json` as store inputs (`Delivery.put_input`); `--all` takes every product function.
  - `tests/test_plane_scan.py`: a two-commit fixture repository yields exactly the changed functions; a rename
    and a deleted function are handled; `--all` count.
  - _Requirements: 6.1_
- [ ] 7.2 Run composition and the command
  - `src/openultrasast/plane/scan.py` + `cli.py`: `ousast plane scan URL --base C --head C [--all] [--ceiling USD]
    [--exec] [--wait S | --no-wait]`: per set `facts -> va, vb -> agree -> vc -> final -> features -> remember`,
    `engine` when a changed file's language needs it, `roles` once per repository when memory has no `roles`
    rows for `repo_key(url)`; budgets from `verify_budget`; Run annotated `openultrasast.io/population: scan`,
    `split: <repo_dir>`; after the Run, `memory.ingest`, then the attribution table and the plane's agreement
    (`final`), the decision engine's verdict only when adopted. `--no-wait` prints the Run name and exits 0.
  - `tests/test_plane_scan.py`: the rendered Run for the fixture; budgets sum under the ceiling; `roles`
    included only when the store lacks rows; the report's verdict line.
  - _Requirements: 6.1, 6.2_
- [ ] 7.3 Hook opt-in
  - `ops/pre-push`: with `OUSAST_PLANE_SCAN=1`, after the blocking check, `ousast plane scan <remote url>
    --base <old> --head <new> --exec remote --no-wait` and the Run name in the report; the hook's exit code never
    depends on it. `ops/README.md` and `docs/deployment.md`: the latency split.
  - `tests/test_push_hook.py`: the wrapper calls the scan only with the variable set and ignores its failure.
  - _Requirements: 6.3_
- [ ] 7.4 Kind proof and record 07 **paid: needs a budget go-ahead, ceiling 3.00 USD**
  - A PHP pair from the development corpus (pmpro's CVE commit and its parent, never a v2 or v3 case) scanned on
    kind: candidates, the Run through `final`, `engine` for the PHP files, rows under
    `repos/<host>__<owner>__<name>/<head>.jsonl` on the store, the report; then `ousast plane status`.
  - `benchmarks/measurements/<date>-k8s-07-plane-scan/record.json`: candidates, usd, calls, agreement, rows,
    seconds from submit to verdict, whether the known CVE site is among the agreed.
  - _Requirements: 6.1, 6.2, 6.3, 7.1_

- [ ] 8. Runbook (design section 7, Req 7)
- [ ] 8.1 `docs/deployment.md` as the runbook
  - Sections: prerequisites for k3s (Substrate, ax with the snapshots patch, GHCR and the pull secret, buckets,
    the CI SA and its grant from 3.2, the node checklist of 6.2), the profile switch, `--exec remote` from a laptop
    and from CI, and the checklist whose every item names its requirement and its record 01-07; items without a
    recorded run (HPA live, 1.7's fetch) labelled planned. `ops/ax/README.md` and `ops/README.md` point to it;
    the "moving to a separate cluster" tables are replaced by the checklist.
  - _Requirements: 7.2_
- [ ] 8.2 Spec closure
  - `design.md` open questions updated with the outcomes of 1.5, 1.6, 3.2 (1.7 stays open until k3s); the
    `kind-tooling` memory and `.kiro/steering/overview.md` current-state line updated; `/kiro-spec-status`.
  - Evidence: every record 01-07 linked from the runbook's checklist.
  - _Requirements: 7.1, 7.2_
