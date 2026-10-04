"""Host queue transport: source and task metadata only, never analyzer code."""

from __future__ import annotations

import json
import subprocess
import time
import uuid

from engine_worker_service import PENDING, client_from_env, pack, put, read, result_key, status

from openultrasast.plane.memory import PRESIGNED_ARCHIVE_SUFFIX


class Dispatcher:
    def __init__(self, args, client=None, *, pause=time.sleep, clock=time.monotonic):
        self.client = client if client is not None else client_from_env()
        self.run = uuid.uuid4().hex
        self.args, self.pause, self.clock = args, pause, clock

    def execute(self, checkout, output, pin, pin_id):
        task_id = f"{self.run}-{pin_id}"
        task = dict(
            run=self.run,
            id=pin_id,
            task_id=task_id,
            pin=pin,
            input=f"engine-queue/inputs/{self.run}/{pin_id}/source{PRESIGNED_ARCHIVE_SUFFIX}",
            image=self.args.image,
            deadline=self.args.deadline,
            question_deadline=self.args.question_deadline,
        )
        try:
            self.client.put(task["input"], pack(checkout), {})
            put(self.client, PENDING + task_id, task)
            end = self.clock() + self.args.queue_timeout
            while self.clock() < end:
                result = read(self.client, result_key(task))
                if result is not None:
                    (output / "result.json").write_text(json.dumps(result))
                    self.client.delete(task["input"])
                    return subprocess.CompletedProcess([], 0, "", ""), result.get("worker")
                self.pause(2)
            # Removing pending cancels work that has not been claimed; retain source for a live lease.
            self.client.delete(PENDING + task_id)
            return None, None
        except Exception as exc:
            # SDK errors can contain endpoint URLs or credentials. Do not persist their text.
            raise OSError("queue transport failed") from exc

    def status(self):
        return status(self.client)
