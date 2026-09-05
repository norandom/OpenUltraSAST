# Provenance: HHHHHejia/openniw  (fixed).
# repo: HHHHHejia/openniw
# commit: 0fc94733f6ca3c6b129a0a8e6d7b3acce19d5a10
# parent: 4d91ed82fa9a5ec6bf5ef96da1d221fc187700dc
# commit_url: https://github.com/HHHHHejia/openniw/commit/0fc94733f6ca3c6b129a0a8e6d7b3acce19d5a10
# cve: 
# license: MIT
# function: get_job
# relpath: backend/app/routers/jobs.py
# provenance: agent
# mechanism: identity_from_request_body

async def get_job(job_id: str, user: dict = Depends(auth.current_user)) -> dict:
    job = await jobs_service.get(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    # Authorization: case-bound jobs are visible only to the case owner;
    # caseless jobs (free evaluations) are served by the public route only.
    if job.get("case_id") is None:
        raise HTTPException(404, "Job not found")
    await auth.case_owned_by(str(job["case_id"]), user)
    return {
        "id": str(job["id"]),
        "kind": job["kind"],
        "status": job["status"],
        "result": job["result"],
        "error": job["error"],
    }
