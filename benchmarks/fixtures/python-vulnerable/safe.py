"""Safe equivalents. None of these lines should produce a finding."""
import hashlib
import subprocess

import yaml
from flask import request


def ping_safe(host):
    # list-form subprocess without shell is not command injection
    return subprocess.check_output(["ping", "-c", "1", host])


def user_safe(db):
    name = request.args["name"]
    # parameterised query: %s here is a bound placeholder, not %-formatting
    return db.execute("select * from users where name = %s", (name,))


def config_safe(data):
    return yaml.safe_load(data)  # safe_load is not the unsafe yaml.load sink


def token_safe(pw):
    return hashlib.sha256(pw.encode()).hexdigest()  # strong hash


def comment_only():
    # os.system("rm -rf /") would be dangerous but this is a comment
    return "ok"
