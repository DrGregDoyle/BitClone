const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests/browser",
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:18734",
    browserName: "chromium",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "BITCLONE_API_TOKEN=browser-test-token ./.venv/bin/python -m src --db-path /tmp/bitclone-playwright/node.db serve-api --api-only --port 18734",
    url: "http://127.0.0.1:18734/",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
