// Vulnerable Express app modeled on NodeGoat / vulnerable JavaScript samples.
const express = require("express");
const childProcess = require("child_process");
const fs = require("fs");
const crypto = require("crypto");
const axios = require("axios");
const app = express();

app.get("/ping", (req, res) => {
  childProcess.exec("ping -c 1 " + req.query.host, (e, out) => res.send(out)); // CWE-78 command injection
});

app.get("/build", (req, res) => {
  childProcess.execSync("make " + req.query.target); // CWE-78 command injection via execSync
});

app.get("/calc", (req, res) => {
  const result = eval(req.query.expr); // CWE-95 eval of user input
  res.send(String(result));
});

app.get("/fn", (req, res) => {
  const f = new Function("x", req.query.body); // CWE-95 Function constructor injection
  res.send(String(f(1)));
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>"); // CWE-79 reflected XSS
});

app.get("/user", (req, res) => {
  db.query("select * from users where name = '" + req.query.name + "'"); // CWE-89 SQL injection
});

app.get("/report", (req, res) => {
  db.query(`select * from reports where id = ${req.query.id}`); // CWE-89 SQL injection template literal
});

app.get("/read", (req, res) => {
  const data = fs.readFileSync(req.query.path); // CWE-22 path traversal
  res.send(data);
});

app.get("/fetch", (req, res) => {
  axios.get(req.query.url).then((r) => res.send(r.data)); // CWE-918 SSRF
});

app.get("/hash", (req, res) => {
  const digest = crypto.createHash("md5").update(req.query.pw).digest("hex"); // CWE-327 weak hash
  res.send(digest);
});

app.get("/merge", (req, res) => {
  const target = {};
  for (const k in req.query) target[k] = req.query[k]; // CWE-1321 prototype pollution (regex blind spot)
  res.json(target);
});

module.exports = app;
