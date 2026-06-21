"""Vulnerable Flask app modeled on PyGoat / DVPWA."""
import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.get("/ping")
def ping():
    host = request.args["host"]
    return os.system("ping -c 1 " + host)  # CWE-78 os.system command injection


@app.get("/run")
def run():
    cmd = request.args["cmd"]
    return subprocess.check_output(cmd, shell=True)  # CWE-78 subprocess shell=True


@app.get("/calc")
def calc():
    return str(eval(request.args["expr"]))  # CWE-95 eval of user input


@app.get("/load")
def load():
    return pickle.loads(request.data)  # CWE-502 pickle deserialization of request body


@app.get("/config")
def config():
    return yaml.load(request.data)  # CWE-502 yaml.load of untrusted input


@app.get("/user")
def user(db):
    name = request.args["name"]
    return db.execute("select * from users where name = '" + name + "'")  # CWE-89 SQL injection


@app.get("/report")
def report(db):
    uid = request.args["id"]
    return db.execute("select * from reports where id = %s" % uid)  # CWE-89 SQL injection via %


@app.get("/read")
def read():
    return open(request.args["path"]).read()  # CWE-22 path traversal from request


@app.get("/fetch")
def fetch():
    return requests.get(request.args["url"]).text  # CWE-918 SSRF from request url


@app.get("/token")
def token():
    return hashlib.md5(request.args["pw"].encode()).hexdigest()  # CWE-327 weak hash


@app.get("/render")
def render():
    return render_template_string("Hello " + request.args["name"])  # CWE-94 SSTI


@app.get("/search")
def search(db):
    term = request.args["q"]
    query = "select * from items where title like '%" + term + "%'"
    return db.execute(query)  # CWE-89 second-order: query built on prior line (regex blind spot)


if __name__ == "__main__":
    app.run(debug=True)  # CWE-489 debug mode in production
