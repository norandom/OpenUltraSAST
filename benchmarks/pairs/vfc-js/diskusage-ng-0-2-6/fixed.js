// Provenance: iximiuz/node-diskusage-ng  (fixed).
// repo: iximiuz/node-diskusage-ng
// commit: 48e7e093486b528f0c81ec699573e0e4a431b8d3
// parent: 53c505506553c83861d1bd67823d6a382d3a5a43
// commit_url: https://github.com/iximiuz/node-diskusage-ng/commit/48e7e093486b528f0c81ec699573e0e4a431b8d3
// cve: CVE-2020-7631
// license: MIT
// function: diskusage
// relpath: lib/posix.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 6

function diskusage(path, cb) {
    execFile('df', ['-k', path], function(err, stdout) {
        if (err) {
            return cb(err);
        }

        try {
            cb(null, parse(stdout));
        } catch (e) {
            cb(e);
        }
    });
}
