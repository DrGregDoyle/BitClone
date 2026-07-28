const { test, expect } = require("@playwright/test");

const TOKEN = "browser-test-token";

async function connect(page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Connect to this node" })).toBeVisible();
  await page.getByLabel("API token").fill(TOKEN);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Node overview" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connect to this node" })).not.toBeVisible();
}

test("operator authenticates and navigates primary node views", async ({ page }) => {
  await connect(page);
  await expect(page.getByText("Chain height")).toBeVisible();
  await expect(page.getByText("Independently validated")).toBeVisible();

  await page.getByRole("button", { name: "Chain" }).click();
  await expect(page.getByRole("heading", { name: "Active chain" })).toBeVisible();

  await page.getByRole("button", { name: "Peers" }).click();
  await expect(page.getByRole("heading", { name: "No peer addresses yet" })).toBeVisible();

  await page.getByRole("button", { name: "Mempool" }).click();
  await expect(page.getByRole("heading", { name: "The mempool is empty" })).toBeVisible();
});

test("block explorer and allowlisted RPC console complete operator workflows", async ({ page, request }) => {
  await connect(page);
  const statusResponse = await request.get("/api/v1/node/status", {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  const status = await statusResponse.json();

  await page.getByRole("button", { name: "Explorer" }).click();
  await page.getByPlaceholder("Block hash", { exact: true }).fill(status.tip);
  await page.getByRole("button", { name: "Load block" }).click();
  await expect(page.locator("#block-result")).toContainText(status.tip);

  await page.getByRole("button", { name: "RPC console" }).click();
  await page.locator("#rpc-method").selectOption("getnetworkinfo");
  await page.getByRole("button", { name: "Run RPC" }).click();
  await expect(page.locator("#rpc-result")).toContainText("protocolversion");

  await page.locator("#rpc-method").selectOption("sendrawtransaction");
  await expect(page.locator("#rpc-warning")).toBeVisible();
  await page.getByRole("button", { name: "Run RPC" }).click();
  await expect(page.locator("#rpc-result")).toContainText("Confirmation is required");
});

test("console remains operable at a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await connect(page);
  await expect(page.getByRole("button", { name: "RPC console" })).toBeVisible();
  await expect(page.locator(".metric-card")).toHaveCount(4);
});
