# Provenance: ziyuzuo/openniw  (fixed).
# repo: ziyuzuo/openniw
# commit: b74de31b0a5f37e4e929ba6aa74dbe0f5e6d9a68
# parent: 98a0c392ba96cd2c4aa746dd6fc2b183f385225e
# commit_url: https://github.com/ziyuzuo/openniw/commit/b74de31b0a5f37e4e929ba6aa74dbe0f5e6d9a68
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
