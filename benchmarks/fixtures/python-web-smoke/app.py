import subprocess

from flask import Flask, request

app = Flask(__name__)

@app.get("/ping")
def ping():
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)

@app.get("/calc")
def calc():
    return str(eval(request.args["expr"]))
