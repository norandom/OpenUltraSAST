// Provenance: DevilsDev/rag-pipeline-utils  (vuln).
// repo: DevilsDev/rag-pipeline-utils
// commit: ba587867118f703632ff2dc63c4feb8ad6793420
// parent: ba587867118f703632ff2dc63c4feb8ad6793420
// commit_url: https://github.com/DevilsDev/rag-pipeline-utils/commit/76e5f0a94d6803d0e463d26a61cedb7da90857a7
// cve: 
// license: MIT
// function: handleConfigSet
// relpath: src/cli/handlers/config-handler.js
// provenance: agent
// mechanism: prototype_pollution

async function handleConfigSet(globalOptions, key, value) {
  try {
    const config = JSON.parse(await fs.readFile(globalOptions.config, "utf-8"));

    // Set value using dot notation
    const keys = key.split(".");
    let current = config;

    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }

    // Parse value
    let parsedValue;
    try {
      parsedValue = JSON.parse(value);
    } catch (error) {
      parsedValue = value; // Keep as string
    }

    current[keys[keys.length - 1]] = parsedValue;

    // Save configuration
    await fs.writeFile(globalOptions.config, JSON.stringify(config, null, 2));
    console.log("✅ Configuration updated");
  } catch (error) {
    logger.error("❌ Failed to set configuration:", error.message);
    process.exit(1);
  }
}
