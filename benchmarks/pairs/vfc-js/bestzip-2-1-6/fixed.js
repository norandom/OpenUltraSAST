// Provenance: nfriedly/node-bestzip  (fixed).
// repo: nfriedly/node-bestzip
// commit: 45d4a901478c6a8f396c8b959dd6cf8fd3f955b6
// parent: fcea252e52b6078eff6caf5531bd32c53fccb59f
// commit_url: https://github.com/nfriedly/node-bestzip/commit/45d4a901478c6a8f396c8b959dd6cf8fd3f955b6
// cve: CVE-2020-7730
// license: MIT
// function: nativeZip
// relpath: lib/bestzip.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 66

const nativeZip = options =>
  new Promise((resolve, reject) => {
    const cwd = options.cwd || process.cwd();
    const command = "zip";
    expandSources(cwd, options.source, (err, sources) => {
      const args = ["--quiet", "--recurse-paths", options.destination].concat(
        sources
      );
      const zipProcess = cp.spawn(command, args, {
        stdio: "inherit",
        cwd
      });
      zipProcess.on("error", reject);
      zipProcess.on("close", exitCode => {
        if (exitCode === 0) {
          resolve();
        } else {
          // exit code 12 means "nothing to do" right?
          //console.log('rejecting', zipProcess)
          reject(
            new Error(
              `Unexpected exit code from native zip: ${exitCode}\n executed command '${command} ${args.join(
                " "
              )}'\n executed in directory '${cwd}'`
            )
          );
        }
      });
    });
  });
