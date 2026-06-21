// Safe equivalents. None of these lines should produce a finding.
const { execFile } = require("child_process");
const crypto = require("crypto");

function pingSafe(host, res) {
  // execFile with an argument array does not invoke a shell with concatenation
  execFile("ping", ["-c", "1", host], (e, out) => res.send(out));
}

function userSafe(db, req) {
  // parameterised query, no concatenation or template interpolation
  db.query("select * from users where name = ?", [req.query.name]);
}

function helloSafe(req, res) {
  res.send("<h1>Hello world</h1>"); // constant response, no reflection
}

function hashSafe(pw) {
  return crypto.createHash("sha256").update(pw).digest("hex"); // strong hash
}

// eval(req.query.expr) would be dangerous but this is a comment
module.exports = { pingSafe, userSafe, helloSafe, hashSafe };
