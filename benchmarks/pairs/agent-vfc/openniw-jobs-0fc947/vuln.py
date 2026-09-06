# Provenance: HHHHHejia/openniw get_job (vuln).
# repo: HHHHHejia/openniw
# commit: 4d91ed82fa9a5ec6bf5ef96da1d221fc187700dc
# parent: 4d91ed82fa9a5ec6bf5ef96da1d221fc187700dc
# commit_url: https://github.com/HHHHHejia/openniw/commit/0fc94733f6ca3c6b129a0a8e6d7b3acce19d5a10
# cve: 
# license: MIT
# function: get_job
# relpath: backend/app/routers/jobs.py
# provenance: agent
# mechanism: identity_from_request_body
# upstream_start: 9

@router.get("/{job_id}")
async def get_job(job_id: str, user: dict = Depends(auth.current_user)) -> dict:
    job = await jobs_service.get(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    return {
        "id": str(job["id"]),
        "kind": job["kind"],
        "status": job["status"],
        "result": job["result"],
        "error": job["error"],
    }
