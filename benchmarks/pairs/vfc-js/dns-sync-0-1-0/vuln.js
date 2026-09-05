// Provenance: skoranga/node-dns-sync  (vuln).
// repo: skoranga/node-dns-sync
// commit: b748fe77a87749d95876028eda8e759109be4c73
// parent: b748fe77a87749d95876028eda8e759109be4c73
// commit_url: https://github.com/skoranga/node-dns-sync/commit/d9abaae384b198db1095735ad9c1c73d7b890a0d
// cve: CVE-2014-9682
// license: MIT
// function: resolve
// relpath: lib/dns-sync.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 13

module.exports = {
    resolve: function resolve(hostname) {
        var output,
            nodeBinary = process.execPath,
            scriptPath = path.join(__dirname, "../scripts/dns-lookup-script"),
            response,
            cmd = util.format('"%s" "%s" %s', nodeBinary, scriptPath, hostname);

        response = shell.exec(cmd, {silent: true});
        if (response && response.code === 0) {
            output = response.output;
            if (output && net.isIP(output)) {
                return output;
            }
        }
        debug('hostname', "fail to resolve hostname " + hostname);
        return null;
    }
};
