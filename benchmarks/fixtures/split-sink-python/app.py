"""Split-sink SQL injection: query is built, then executed on the next line."""
from flask import Flask, request

app = Flask(__name__)


@app.get("/search")
def search(db):
    term = request.args["q"]
    query = "select * from items where title like '%" + term + "%'"
    return db.execute(query)  # CWE-89 split-sink: query built on prior line (regex blind spot)
