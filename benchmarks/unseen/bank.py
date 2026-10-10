"""Durable, content-addressed draw decisions; object I/O stays on the coordinator."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from urllib.parse import urlencode, urlsplit

CORPUS_KEYS = ("CORPUS_S3_ENDPOINT", "CORPUS_S3_BUCKET", "CORPUS_AWS_ACCESS_KEY_ID", "CORPUS_AWS_SECRET_ACCESS_KEY")


def corpus_settings(environ: Mapping[str, str] | None = None) -> dict:
    """Read corpus-only credentials, naming missing settings without exposing values."""
    if environ is None:
        from openultrasast.config import load_dotenv

        load_dotenv()
        environ = os.environ
    missing = [key for key in CORPUS_KEYS if not environ.get(key)]
    if missing:
        raise ValueError(f"Corpus bank needs {', '.join(missing)} in .env or the environment")
    endpoint = environ["CORPUS_S3_ENDPOINT"].strip()
    try:
        parsed = urlsplit(endpoint)
        valid_endpoint = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except ValueError:
        valid_endpoint = False
    if not valid_endpoint:
        raise ValueError("CORPUS_S3_ENDPOINT must be a URL with a scheme (https://host[:port])")
    settings = {
        "endpoint": endpoint,
        "bucket": environ["CORPUS_S3_BUCKET"],
        "access_key": environ["CORPUS_AWS_ACCESS_KEY_ID"],
        "secret_key": environ["CORPUS_AWS_SECRET_ACCESS_KEY"],
    }
    if environ.get("CORPUS_S3_REGION"):
        settings["region"] = environ["CORPUS_S3_REGION"]
    return settings


class CorpusObjects:
    """Plain S3 put/get/list, with no bucket administration or capability probes."""

    def __init__(self, *, endpoint: str, bucket: str, access_key: str, secret_key: str, region: str | None = None):
        import boto3
        from botocore.config import Config

        self.bucket = bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region or "us-east-1",
            # RustFS/MinIO at an IP endpoint needs path-style addressing
            # (virtual-host bucket.<ip> does not resolve) and SigV4. Verified
            # against ousast-corpus @ 10.0.0.54:9001.
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                retries={"total_max_attempts": 1},
            ),
        )

    def get(self, key: str) -> tuple[bytes, str] | None:
        try:
            result = self.client.get_object(Bucket=self.bucket, Key=key)
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") in {"NoSuchKey", "404", "NotFound"}:
                return None
            raise
        body = result["Body"]
        try:
            return body.read(), result.get("VersionId") or result.get("ETag", "")
        finally:
            body.close()

    def put(self, key: str, data: bytes, labels: dict) -> None:
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentType="application/json",
            Tagging=urlencode(labels),
        )

    def keys(self, prefix: str) -> list[str]:
        pages = self.client.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix)
        return [item["Key"] for page in pages for item in page.get("Contents", [])]


def _retry(operation, *args, **kwargs):
    """Retry one object operation once; a second failure is fatal to durability."""
    try:
        return operation(*args, **kwargs)
    except Exception:
        return operation(*args, **kwargs)


class CorpusBank:
    def __init__(self, client, *, seed: int, prefix: str = "unseen"):
        self.client = client
        self.seed = seed
        self.decisions_prefix = f"{prefix}/{seed}/decisions/"

    @staticmethod
    def key_for(repository: str, fix: str) -> str:
        return hashlib.sha256(f"{repository}\n{fix}".encode()).hexdigest()

    def bank(self, repository: str, fix: str, result: dict, *, contract: str) -> None:
        decision = {
            "repository": repository,
            "fix": fix,
            "decision": "accept" if "entry" in result else "reject",
            "reason": result.get("rejected"),
            "entry": result.get("entry"),
            "ordinary_exclusions": result.get("ordinary_exclusions", {}),
            "counts": result.get("counts", {}),
            "contract": contract,
            "seed": self.seed,
        }
        key = self.decisions_prefix + self.key_for(repository, fix) + ".json"
        existing = _retry(self.client.get, key)
        if existing is not None:
            previous = json.loads(existing[0])
            if {field: value for field, value in previous.items() if field != "ts"} == decision:
                return  # Preserve the first timestamp and avoid an unnecessary object version.
        decision["ts"] = datetime.now(UTC).isoformat()
        data = json.dumps(decision, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        _retry(self.client.put, key, data, labels={"decision": decision["decision"], "contract": contract})

    def decided(self) -> dict[str, dict]:
        decisions = {}
        for key in sorted(self.client.keys(self.decisions_prefix)):
            stored = _retry(self.client.get, key)
            if stored is None:
                raise ValueError("corpus_decision_missing")
            decision = json.loads(stored[0])
            digest = self.key_for(decision["repository"], decision["fix"])
            if key != self.decisions_prefix + digest + ".json" or decision["seed"] != self.seed:
                raise ValueError("corpus_decision_identity")
            if decision["decision"] not in {"accept", "reject"}:
                raise ValueError("corpus_decision_invalid")
            decisions[digest] = decision
        return decisions


def split_decided(decisions: Mapping[str, dict], *, contract: str) -> tuple[list[dict], set[str]]:
    """Split reusable results, sorted independently of bucket listing order.

    The coordinator merges entries into the full advisory population before seeded
    ordering: shuffling only the accepted subset would change the draw's order.
    """
    accepted = [row["entry"] for row in decisions.values() if row["decision"] == "accept"]
    accepted.sort(key=lambda entry: (entry.get("advisory", ""), entry["repository"], entry["fix"]))
    reusable = {key for key, row in decisions.items() if row["decision"] == "accept" or row["contract"] == contract}
    return accepted, reusable
