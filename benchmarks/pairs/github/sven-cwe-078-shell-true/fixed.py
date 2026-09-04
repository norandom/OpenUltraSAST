# Provenance: SVEN train CWE-78 function pair from
# https://github.com/google/mobly/commit/3862e8ba359040fbdd6e1a6d36e51d07cda8e1ee
# file mobly/controllers/android_device_lib/adb.py function _exec_cmd
import logging
import subprocess


class AdbError(Exception):
    def __init__(self, **kwargs):
        super().__init__(kwargs)


class Adb:
    def _exec_cmd(self, args, shell):
        """Executes adb commands."""
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
        (out, err) = proc.communicate()
        ret = proc.returncode
        logging.debug("cmd: %s, stdout: %s, stderr: %s, ret: %s", args, out, err, ret)
        if ret == 0:
            return out
        raise AdbError(cmd=args, stdout=out, stderr=err, ret_code=ret)
