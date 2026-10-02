# Brief: the plane on a Kubernetes cluster

Maintainer, 2026-10-02: "the plan is to move the whole to a kube system soon. what is in the way?" and earlier
"later i will deploy this in a separate kube env."

## Where we are

The plane already runs on google/ax over Agent Substrate, on a single-node kind cluster on the maintainer's
laptop (`ops/ax/`). Its manifests are ax's own kinds, every task is one digest-pinned runner image, the memory
store is external (S3-compatible RustFS), and provider credentials travel only in the start request. What still
assumes the laptop is small and listed in `docs/deployment.md` and `ops/ax/README.md`:

1. the reconciler is a host CLI process (`ousast plane run`);
2. the artifact receiver is a thread of that process, reached through a Service + EndpointSlice to the kind
   gateway; the router is reached through a kubectl port-forward;
3. the kube context `kind-ousast` and the registry `localhost:5001` are hard-coded in `doctor.py`, `egress.py`,
   `router.py`;
4. images come from the kind registry;
5. ax's deploy manifest points `AX_SNAPSHOTS_BUCKET` at the ax authors' bucket;
6. the Joern engine runs as a host Docker container (2.8 GB image, 3 GB memory), not as an ax task;
7. the worker pool is two 1 CPU / 1.5 GiB workers with no autoscaling.

## Direction

Make the plane deployable to any Kubernetes cluster that runs Agent Substrate and ax, prove every change on the
kind cluster first (it already behaves like the target), and leave nothing that only works on this host. The
production use (a pre-push safety net fed by CI) needs, in addition, a delta Run command and Workspaces from a
URL and commit; those are in scope as the last increment because they define what the cluster is for.

## Not in scope

Provisioning the maintainer's cluster, Substrate's and ax's own deployment procedures (followed, not changed),
and any detection change.
