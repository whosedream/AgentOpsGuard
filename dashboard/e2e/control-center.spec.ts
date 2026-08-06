import { expect, test } from "@playwright/test";

type AuthRole = "read_only" | "developer" | "security_reviewer" | "admin";

async function login(page: import("@playwright/test").Page, role: AuthRole) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(`${role}@example.com`);
  await page.getByLabel("Display name").fill(role);
  await page.getByRole("button", { name: new RegExp(role === "security_reviewer" ? "Reviewer" : role === "read_only" ? "Read-only" : role === "developer" ? "Developer" : "Admin") }).click();
  await page.getByRole("button", { name: "Start session" }).click();
  await page.waitForURL(/\/$/);
  await expect(page.getByText("AgentOps Overview")).toBeVisible();
}

test("redirects anonymous users to login", async ({ page }) => {
  await page.goto("/setup");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("developer login reaches overview and can use scanner/policy/mcp", async ({ page }) => {
  await login(page, "developer");
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText("AgentOps Overview")).toBeVisible();
  await expect(page.getByRole("link", { name: "Scanner" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Policy" })).toBeVisible();
  await expect(page.getByRole("link", { name: "MCP" })).toBeVisible();

  await page.goto("/scanner");
  await page.getByRole("button", { name: "Scan content" }).click();
  await expect(page.getByText("instruction_override").first()).toBeVisible();

  await page.goto("/policy");
  await page.getByRole("button", { name: "Evaluate policy" }).click();
  await expect(page.getByText("dangerous_command", { exact: true })).toBeVisible();

  await page.goto("/mcp");
  await page.getByRole("button", { name: "Test tool" }).click();
  await expect(page.getByText("hello")).toBeVisible();
});

test("read_only navigation stays restricted", async ({ page }) => {
  await login(page, "read_only");
  await expect(page.getByRole("link", { name: "Scanner" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Governance" })).toHaveCount(0);
  await page.goto("/mcp");
  await expect(page.getByText("Restricted")).toBeVisible();
});

test("security reviewer can reach governance and review approvals", async ({ page }) => {
  await login(page, "security_reviewer");
  await page.goto("/governance");
  await expect(page.getByText("Governance Control Plane")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Save config" })).toBeDisabled();
});

test("admin sees full navigation and can open governance and MCP", async ({ page }) => {
  await login(page, "admin");
  await expect(page.getByRole("link", { name: "Governance" })).toBeVisible();
  await expect(page.getByRole("link", { name: "MCP" })).toBeVisible();
  await page.goto("/governance");
  await expect(page.getByRole("button", { name: "Save config" })).toBeEnabled();
  await page.goto("/mcp");
  await expect(page.getByRole("button", { name: "Create server" })).toBeEnabled();
});
