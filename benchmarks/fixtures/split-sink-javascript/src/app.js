// Split-sink SQL injection: query is built, then executed on the next line.
const express = require("express");
const app = express();

app.get("/search", (req, res) => {
  const term = req.query.q;
  const query = "select * from items where title like '%" + term + "%'";
  db.query(query); // CWE-89 split-sink: query built on prior line (regex blind spot)
  res.send("ok");
});

module.exports = app;
