const express = require("express");
const childProcess = require("child_process");
const app = express();

app.get("/ping", (req, res) => {
  childProcess.exec("ping -c 1 " + req.query.host, (error, stdout) => res.send(stdout));
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

module.exports = app;
