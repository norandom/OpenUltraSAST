# ax on this host

The agentic plane runs every task on google/ax over Agent Substrate in a single-node kind cluster. ax is the
only executor; `ousast plane run` submits, resumes, starts and collects. The flow is drawn in
[The plane on ax](../../plane.md); the bucket setup for the S3 memory store is in
[RustFS setup](../../rustfs.md).

--8<-- "ops/ax/README.md:5"

*Source: `ops/ax/README.md` in the repository, from its line 5 on; this page includes it when the docs site is built.*
