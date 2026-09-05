// Provenance: jarofghosts/glance  (fixed).
// repo: jarofghosts/glance
// commit: 8cfd88e44ebd3f07e3a2eaf376a3e758b6c4ca19
// parent: 7e69a5539236386e747fb240ae87ea65ed64bb2c
// commit_url: https://github.com/jarofghosts/glance/commit/8cfd88e44ebd3f07e3a2eaf376a3e758b6c4ca19
// cve: CVE-2018-3715
// license: MIT
// function: Glance$serveRequest
// relpath: index.js
// provenance: human
// mechanism: path_join_user_input
// upstream_start: 60

Glance.prototype.serveRequest = function Glance$serveRequest (req, res) {
  var request = {}
  var self = this

  request.fullPath = path.join(
    self.dir,
    decodeURIComponent(parse(req.url).pathname)
  )

  request.ip = req.socket.remoteAddress
  request.method = req.method.toLowerCase()
  request.response = res

  // prevent traversing directories that are parents of the root
  if (request.fullPath.slice(0, self.dir.length) !== self.dir) {
    return self.emit('error', 403, request, res)
  }

  if (request.method !== 'get') {
    return self.emit('error', 405, request, res)
  }

  if (self.nodot && /^\./.test(path.basename(request.fullPath))) {
    return self.emit('error', 404, request, res)
  }

  fs.stat(request.fullPath, statFile)

  function statFile (err, stat) {
    if (err) {
      return self.emit('error', 404, request, res)
    }

    if (!stat.isDirectory()) {
      self.emit('read', request)

      return filed(request.fullPath).pipe(res)
    }

    if (self.hideindex) {
      return self.emit('error', 403, request, res)
    }

    if (!self.indices || !self.indices.length) {
      return listFiles()
    }

    var indices = self.indices.slice()

    findIndex(indices.shift())

    function findIndex (indexTest) {
      fileExists(path.join(request.fullPath, indexTest), check)

      function check (hasIndex) {
        if (hasIndex) {
          req.url = req.url + '/' + indexTest

          return self.serveRequest(req, res)
        }

        if (!indices.length) {
          return listFiles()
        }

        findIndex(indices.shift())
      }
    }

    function listFiles () {
      var listPath = request.fullPath.replace(/\/$/, '')

      res.writeHead(200, RESPONSE_HEADERS)
      htmlls(listPath, {hideDot: self.nodot}).pipe(res)

      return self.emit('read', request)
    }
  }
}
