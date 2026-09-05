// Provenance: ChristoPy/serve-here.js  (vuln).
// repo: ChristoPy/serve-here.js
// commit: ad077637bf7a9fe0dee3262f011aed19a45ce92c
// parent: ad077637bf7a9fe0dee3262f011aed19a45ce92c
// commit_url: https://github.com/ChristoPy/serve-here.js/commit/cefb51d03290b6a88dd13143ab2de31b8cf57c39
// cve: CVE-2019-5444
// license: MIT
// function: ConfigureFilePath
// relpath: source/response.js
// provenance: human
// mechanism: path_join_user_input
// upstream_start: 5

module.exports.ConfigureFilePath = (Options, FilePath) => {

	const Slash = FilePath.split ("")[FilePath.split ("").length - 1] === "/";

	switch (FilePath) {

		case "/": return `${Options.RootFolder}/${Options.IndexFile}`;
		default: return (Slash ? `${Options.RootFolder}${FilePath.slice (0, -1)}` : `${Options.RootFolder}${FilePath}`);
	}
}
