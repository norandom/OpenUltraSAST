// Provenance: simonh1000/angular-http-server  (vuln).
// repo: simonh1000/angular-http-server
// commit: d171a771a92e4685b24fb77cb894a7b7b8024c5c
// parent: d171a771a92e4685b24fb77cb894a7b7b8024c5c
// commit_url: https://github.com/simonh1000/angular-http-server/commit/8bafc9577161469f5dea01e0b98ea9c525d063e9
// cve: 
// license: Apache-2.0
// function: requestListener
// relpath: angular-http-server.js
// provenance: human
// mechanism: path_join_user_input
// upstream_start: 45

function requestListener(req, res) {
    // Add CORS header if option chosen
    if (argv.cors) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Request-Method', '*');
        res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET');
        res.setHeader('Access-Control-Allow-Headers', 'authorization, content-type');
        // When the request is for CORS OPTIONS (rather than a page) return just the headers
        if (req.method === 'OPTIONS') {
            res.writeHead(200);
            res.end();
            return;
        }
    }

    // Request is for a page instead
    // Only interested in the part before any query params
    var url = req.url.split('?')[0]
    // Attaches path prefix with --path option
    var possibleFilename = resolveUrl(url.slice(1)) || "dummy";

    fs.stat(possibleFilename, function(err, stats) {
        var fileBuffer;
        if (!err && stats.isFile()) {
            fileBuffer = fs.readFileSync(possibleFilename);
            let ct = mime.lookup(possibleFilename);
            log(`Sending ${possibleFilename} with Content-Type ${ct}`);
            res.writeHead(200, { 'Content-Type': ct });

        } else {
            log("Route %s, replacing with index.html", possibleFilename);
            fileBuffer = returnDistFile();
            res.writeHead(200, { 'Content-Type': 'text/html' });
        }

        res.write(fileBuffer);
        res.end();
    });
}
