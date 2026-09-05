// Provenance: vvo/node-whereis  (vuln).
// repo: vvo/node-whereis
// commit: b8b642b1163baa37f15ed49b4064dcbdb6e1876c
// parent: b8b642b1163baa37f15ed49b4064dcbdb6e1876c
// commit_url: https://github.com/vvo/node-whereis/commit/0f64e3780235004fb6e43bfd153ea3e0e210ee2b
// cve: CVE-2018-3772
// license: MIT
// function: whereis
// relpath: index.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 3

module.exports = function whereis(name, cb) {
  cp.exec('which ' + name, function(error, stdout, stderr) {
    stdout = stdout.split('\n')[0];
    if (error || stderr || stdout === '' || stdout.charAt(0) !== '/') {
      stdout = stdout.split('\n')[0];
      cp.exec('whereis ' + name, function(error, stdout, stderr) {
        if (error || stderr || stdout === '' || stdout.indexOf( '/' ) === -1) {
          cp.exec('where ' + name, function (error, stdout, stderr) { //windows
            if (error || stderr || stdout === '' || stdout.indexOf('\\') === -1) {
              cp.exec('for %i in (' + name + '.exe) do @echo. %~$PATH:i', function (error, stdout, stderr) { //windows xp
                if (error || stderr || stdout === '' || stdout.indexOf('\\') === -1) {
                  return cb(new Error('Could not find ' + name + ' on your system'));
                }
                return cb(null, stdout);
              });
            } else {
              return cb(null, stdout);
            }
          });
        }
        else {
          return cb(null, stdout.split(' ')[1]);
        }
      });
    } else {
      return cb(null, stdout);
    }
  });
};
