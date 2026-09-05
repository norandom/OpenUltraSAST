// Provenance: trackly-app/trackly-cli  (vuln).
// repo: trackly-app/trackly-cli
// commit: 8d240ad8d7fc114c8f941ad956a2fdf32391ff60
// parent: 8d240ad8d7fc114c8f941ad956a2fdf32391ff60
// commit_url: https://github.com/trackly-app/trackly-cli/commit/1c1aed89b07edb04051830c8f086e02b65e961c6
// cve: 
// license: MIT
// function: inspectExistingAncestor
// relpath: lib/path-diagnostics.js
// provenance: agent
// mechanism: path_join_user_input

async function inspectExistingAncestor(exactPath) {
  let candidate = exactPath;
  while (true) {
    try {
      const stats = await fs.stat(candidate);
      return {
        ancestor: candidate,
        exactPathExists: candidate === exactPath,
        exactPathType: candidate === exactPath ? (stats.isDirectory() ? 'directory' : 'file') : null,
        writableDirectory: stats.isDirectory() ? candidate : path.dirname(candidate),
      };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      const parent = path.dirname(candidate);
      if (parent === candidate) {
        return { ancestor: parent, exactPathExists: false, exactPathType: null, writableDirectory: parent };
      }
      candidate = parent;
    }
  }
}
