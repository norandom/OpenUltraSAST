// Provenance: jas-/node-libnmap  (vuln).
// repo: jas-/node-libnmap
// commit: 49b72239b144ab7ffdf673b62e18bfd0760948f6
// parent: 49b72239b144ab7ffdf673b62e18bfd0760948f6
// commit_url: https://github.com/jas-/node-libnmap/commit/c235b24b0342e12a5dbf502f89daabe95883b6c8
// cve: CVE-2018-16461
// license: MIT
// function: block
// relpath: lib/classes/tools.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 20

class tools extends emitter {

  /**
   * @function merge
   * Perform preliminary option/default object merge
   *
   * @param {Object} defaults Application defaults
   * @param {Object} obj User supplied object
   *
   * @returns {Object}
   */
  merge(defaults, obj) {
    return merge(defaults, obj);
  }


  /**
   * @function chunk
   * Defines new property for array's
   * 
   * @param {Array} obj Supplied array
   * @param {Integer} offset Supplied offset
   * 
   * @returns {Array}
   */
  chunk(obj, offset) {
    let idx = 0;
    const alength = obj.length;
    const tarray = [];

    for (idx = 0; idx < alength; idx += offset) {
      tarray.push(obj.slice(idx, idx + offset).join(' '));
    }

    return tarray;
  }


  /**
   * @function flatten
   * Flattens nested arrays into one flat array
   * 
   * @param {Array} arr Array combinator
   * @param {Array} obj User supplied array
   * 
   * @returns {Array}
   */
  flatten(arr, obj) {
    let value;
    const result = [];

    for (let i = 0, length = arr.length; i < length; i++) {

      value = arr[i];

      if (Array.isArray(value)) {
        return this.flatten(value, obj);
      } else {
        result.push(value);
      }
    }
    return result;
  }


  /**
   * @function funcs
   * Create functions for use as callbacks
   *
   * @param {Obect} opts Application defaults
   *
   * @returns {Array}
   */
  funcs(opts) {
    const scope = this;
    const funcs = {};
    let cmd = false;
    const errors = [];
    const reports = [];

    if (opts.range.length <= 0)
      return "Range of hosts could not be created";

    Object.keys(opts.range).forEach(function blocks(block) {

      const range = opts.range[block];
      funcs[range] = function block(callback) {
        cmd = scope.command(opts, range);

        if (opts.verbose)
          console.log(`Running: ${cmd}`);

        const report = [];

        const execute = proc(cmd, (err, stdout, stderr) => {
          if (err)
            return reporting.reports(opts, err, callback);
        });

        execute.stderr.on('data', (chunk) => {
          /* Silently discard stderr messages to not interupt scans */
        });

        execute.stdout.on('data', (chunk) => {
          report.push(chunk);
        });

        execute.stdout.on('end', () => {
          if (report.length > 0)
            return reporting.reports(opts, report, callback);
        });
      };
    });

    return funcs;
  }


  /**
   * @function command
   * Generate nmap command string
   *
   * @param {Object} opts - User supplied options
   * @param {String} block - Network block
   *
   * @returns {String} NMAP scan string
   */
  command(opts, block) {
    const flags = opts.flags.join(' ');
    const proto = (opts.udp) ? ' -sU' : ' ';
    const to = `--host-timeout=${opts.timeout}s `;
    const ipv6 = (validation.test(validation.patterns.IPv6, block)) ?
      ' -6 ' : ' ';

    return (opts.ports) ?
      `${opts.nmap+proto} ${to}${flags}${ipv6}-p${opts.ports} ${block}` :
      `${opts.nmap+proto} ${to}${flags}${ipv6}${block}`;
  }


  /**
   * @function worker
   * Executes object of functions
   *
   * @param {Object} obj User supplied object
   * @param {Function} fn Return function
   */
  worker(obj, fn) {
    async.parallelLimit(obj.funcs, obj.threshold, fn);
  }


  /**
   * @function init
   * @scope private
   * Merges supplied options & builds functions
   *
   * @param {Object} defaults libnmap default options
   * @param {Object} opts User supplied configuration object
   * @param {Function} cb Callback
   *
   * @returns {Object}
   */
  init(defaults, opts, cb) {
    let funcs = [];
    const ranges = [];
    const called = caller.get()[1].getFunctionName();

    /* Override 'defaults.flags' array with 'opts.flags' (prevents merge) */
    if (/array/.test(typeof opts.flags))
      defaults.flags = opts.flags;

    opts = this.merge(defaults, opts);

    /* Ensure we can always parse the report */
    if (opts.flags.indexOf('-oX -') === -1)
      opts.flags.push('-oX -');

    /* If we are in a discover mode get adapters for associated network(s) */
    if (/nmap.discover/.test(called)) {

      /* Bail early if we cannot determine any ranges */
      if (!(opts.range = network.adapters(opts)))
        return cb(validation.messages.version);

      /* Set scan options as static values for 'discover' mode */
      opts.ports = '';
      opts.flags = [
        '-n',
        '-oX -',
        '-sn',
        '-PR'
      ];
    }

    validation.init(opts, (err, result) => {
      if (err)
        return cb(err);

      opts.range = network.calculate(opts);
      funcs = this.funcs(opts);

      return cb(null, {
        opts,
        funcs
      });
    });
  }
}
