# kube-ax operator constraints

Verified by the operator on 2026-10-05. These constraints apply across all workloads.

- Two workers, one task per worker, at most two tasks in flight cluster-wide. AX has no
  queue: a third apply returns `no free workers available`. Treat this as back-pressure,
  retry the same task/lane with 15–30 seconds of jitter until its deadline, and never
  count it as a sandbox failure or trigger VM fallback. The host dispatcher shares a
  two-slot reservation across workload instances and long-lived search executors.
- `/` and `/tmp` are RAM-backed and consume the worker's 3 GiB. `/workspace` is the only
  disk-backed path, with about 2 GiB usable per task. Executor and verifier entrypoints
  use `/workspace/tmp`, `/workspace/.npm`, `/workspace/.m2`, `/workspace/.composer`,
  `/workspace/.pip`, and `/workspace/.gradle` through the respective tool environment
  variables. Builds and extracted checkouts live under `/workspace` too. The default
  aggregate workspace scratch guard is 2 GiB; `OUSAST_SCRATCH_BYTES` configures it.
  Exceeding it returns `could_not_build`, reason `scratch limit`. The guard polls
  during child execution and checks after exit; it is not an instantaneous filesystem
  quota or a replacement for the worker memory limit.
- `ousast-engine-search-verify-*` tasks have no egress. The requested exception for
  `files.because-security.com:443` is **pending**, not operationally verified. They
  receive one presigned archive containing `checkout/`, `products/`, and `spec.json`,
  built/exported by an executor. Only `VERIFY_INPUT_URL` and `RESULT_URL` cross the
  verifier boundary. Verifiers reject build recipes and do not install dependencies
  or fetch repositories. Executors finish and release their slots before verifier
  repetitions start. Both task types must be provisioned without model credentials.
- All tasks share one public IP. Repository acquisition uses HTTPS git clone from
  `github.com` or archives from `codeload.github.com`, never `api.github.com`. Host-side
  metadata queries are a separate concern. Search tasks receive checkout archives;
  executor tool guidance carries the same acquisition rule. Retain the 60-second
  first-download retry for delayed task egress policy activation.
