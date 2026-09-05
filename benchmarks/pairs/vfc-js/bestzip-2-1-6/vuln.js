// Provenance: nfriedly/node-bestzip  (vuln).
// repo: nfriedly/node-bestzip
// commit: fcea252e52b6078eff6caf5531bd32c53fccb59f
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
    const sources = Array.isArray(options.source)
      ? options.source.join(" ")
      : options.source;
    const command = `zip --quiet --recurse-paths ${
      options.destination
    } ${sources}`;
    const zipProcess = cp.exec(command, {
      stdio: "inherit",
      cwd: options.cwd
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
            `Unexpected exit code from native zip command: ${exitCode}\n executed command '${command}'\n executed inin directory '${options.cwd ||
              process.cwd()}'`
          )
        );
      }
    });
  });
