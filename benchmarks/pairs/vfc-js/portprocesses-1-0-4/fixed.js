// Provenance: rrainn/PortProcesses  (fixed).
// repo: rrainn/PortProcesses
// commit: 86811216c9b97b01b5722f879f8c88a7aa4214e1
// parent: fffceb09aff7180afbd0bd172e820404b33c8299
// commit_url: https://github.com/rrainn/PortProcesses/commit/86811216c9b97b01b5722f879f8c88a7aa4214e1
// cve: CVE-2021-23348
// license: MIT
// function: listProcessesOnPort
// relpath: index.js
// provenance: human
// mechanism: source_reaches_sink
// upstream_start: 2

const listProcessesOnPort = module.exports.listProcessesOnPort = async port => {
	const portNumber = parseInt(port, 10);
	if (Number.isNaN(portNumber)) {
		console.error("Must provide number for port.");
		return;
	}
	try {
		const result = (await exec(`lsof -i :${portNumber}`)).output.split('\n');
		const headers = result.shift().split(' ').filter(item => !!item.trim() && item.trim() !== "").map(item => item.toLowerCase());
		return result.filter(item => !!item.trim() && item.trim() !== "").reduce((accumulator, currentValue) => {
			accumulator.push(currentValue.split(' ').filter(item => !!item.trim() && item.trim() !== "").reduce((accumulator, currentValue, index) => {
				if (index > headers.length - 1) {
					accumulator[headers[headers.length - 1]] = (!!accumulator[headers[headers.length - 1]].trim() && accumulator[headers[headers.length - 1]].trim() !== "") ? `${accumulator[headers[headers.length - 1]]} ${currentValue}` : currentValue;
				} else {
					accumulator[headers[index]] = currentValue;
				}
				return accumulator;
			}, {}));
			return accumulator;
		}, []);
	} catch (e) {
		console.error(e);
	}
};
