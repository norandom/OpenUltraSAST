// Provenance: vincentmorneau/apex-publish-static-files  (fixed).
// repo: vincentmorneau/apex-publish-static-files
// commit: 2209af8f2b65c24aa55ab757e0e05b958c16f063
// parent: 8d28fe8a9a49e5ff3f61e239293b5646528e2915
// commit_url: https://github.com/vincentmorneau/apex-publish-static-files/commit/2209af8f2b65c24aa55ab757e0e05b958c16f063
// cve: CVE-2018-16462
// license: MIT
// function: publish
// relpath: index.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 7

module.exports = {
	// Validates a JSON object
	publish(opts) {
		// Set defaults
		const defaults = {
			sqlclPath: 'sql',
			destination: 'application'
		};
		opts = Object.assign(defaults, opts);

		// Validate arguments
		if (typeof opts.connectString === 'undefined') {
			throw new TypeError('connectString is required.');
		}

		if (typeof opts.directory === 'undefined') {
			throw new TypeError('directory is a required argument.');
		}

		if (typeof opts.appID === 'undefined') {
			throw new TypeError('appID is a required argument.');
		}

		if (opts.destination.toLowerCase() === 'plugin' && typeof opts.pluginName === 'undefined') {
			throw new Error('pluginName is a required argument.');
		}

		if (!fs.existsSync(opts.directory)) {
			throw new Error(`Directory ${opts.directory} is not a valid path.`);
		}

		const getAllFiles = dir =>
			fs.readdirSync(dir).reduce((files, file) => {
				const name = path.join(dir, file);
				const isDirectory = fs.statSync(name).isDirectory();
				return isDirectory ? [...files, ...getAllFiles(name)] : [...files, name];
			}, []);

		if (getAllFiles(opts.directory).length === 0) {
			console.log(`Directory is empty.`);
		} else {
			// Execute the upload process
			try {
				switch (opts.destination.toLowerCase()) {
					case 'theme':
						console.log(`Uploading to ${opts.appID} - Theme Files...`);
						break;
					case 'workspace':
						console.log(`Uploading to ${opts.appID} - Workspace Files...`);
						break;
					case 'plugin':
						console.log(`Uploading to ${opts.appID} - ${opts.pluginName} - Plugin Files...`);
						break;
					default:
						console.log(`Uploading to ${opts.appID} - Application Static Files...`);
				}

				const spawnOpts = [
					opts.connectString, // Connect string (user/pass@server:port/sid)
					'@' + path.resolve(__dirname, 'lib/script'), // Sql to execute
					path.resolve(__dirname, 'lib/distUpload.js'), // Param &1 (js to execute)
					path.resolve(opts.directory), // Param &2
					opts.appID, // Param &3
					opts.destination, // Param &4
					opts.pluginName // Param &5
				];

				const childProcess = spawnSync(
					opts.sqlclPath, // Sqlcl path
					spawnOpts, {
						encoding: 'utf8'
					}
				);

				console.log(childProcess.stdout);
				console.log('Files were uploaded successfully.');
			} catch (err) {
				console.error(err);
			}
		}
	}
};
