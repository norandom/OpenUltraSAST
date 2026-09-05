// Provenance: thenables/thenify  (vuln).
// repo: thenables/thenify
// commit: aa21cfb64f47238c764d258d0faf7366a8487e36
// parent: aa21cfb64f47238c764d258d0faf7366a8487e36
// commit_url: https://github.com/thenables/thenify/commit/0d94a24eb933bc835d568f3009f4d269c4c4c17a
// cve: CVE-2020-7677
// license: MIT
// function: thenify
// relpath: index.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 2

var Promise = require('any-promise')
var assert = require('assert')

module.exports = thenify

/**
 * Turn async functions into promises
 *
 * @param {Function} $$__fn__$$
 * @return {Function}
 * @api public
 */

function thenify($$__fn__$$, options) {
  assert(typeof $$__fn__$$ === 'function')
  return eval(createWrapper($$__fn__$$.name, options))
}
