"""CLI toy: arguments are its sole public interface; config belongs to the app."""

import os
import pathlib
import sqlite3
import subprocess
import sys
import urllib.request

fixed = pathlib.Path("/workspace/fixed").exists()
if sys.argv[1:] == ["--ready"]:
    sys.exit(1 if pathlib.Path("/workspace/broken").exists() else 0)
family, payload = sys.argv[1:]
if family == "path":
    root = pathlib.Path(os.environ["SERVED_ROOT"])
    path = (root / payload).resolve()
    if not fixed or path.is_relative_to(root):
        value = path.read_text()
        if not pathlib.Path("/workspace/flaky").exists() or value.startswith("a"):
            print(value)
elif family == "sql":
    with sqlite3.connect(os.environ["DATABASE"]) as db:
        if fixed:
            rows = db.execute("SELECT value FROM records WHERE public=1 AND name=?", (payload,))
        else:
            rows = db.execute("SELECT value FROM records WHERE public=1 AND name='" + payload + "'")
        print(list(rows))
elif family == "command":
    if not fixed:
        subprocess.run("echo " + payload, shell=True, check=False)
elif family == "ssrf":
    if not fixed:
        print(urllib.request.urlopen(os.path.expandvars(payload), timeout=2).read())
