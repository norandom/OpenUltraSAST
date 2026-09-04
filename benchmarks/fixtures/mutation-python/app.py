"""Mutation of os.system: the callable is aliased before use so a same-line regex misses it."""
import os

from flask import Flask, request

app = Flask(__name__)
run_cmd = os.system


@app.get("/ping")
def ping():
    host = request.args["host"]
    return run_cmd("ping -c 1 " + host)  # CWE-78 mutation: os.system aliased before the call
