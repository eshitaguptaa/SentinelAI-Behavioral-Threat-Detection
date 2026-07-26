import { chromium } from "playwright-core";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, "screenshots");
fs.mkdirSync(OUT, { recursive: true });

async function shot(page, name) {
  await page.waitForTimeout(700);
  await page.screenshot({
    path: path.join(OUT, name),
    fullPage: false,
  });
  console.log("saved", name);
}

const browser = await chromium.launch({
  channel: "chrome",
  headless: true,
});
const page = await browser.newPage({
  viewport: { width: 1440, height: 900 },
});

await page.goto("http://localhost:5173/app", { waitUntil: "networkidle" });
await shot(page, "01-upload.png");

const sample = page.getByRole("button", { name: /sample/i });
if ((await sample.count()) > 0) {
  await sample.first().click();
  await page.waitForURL("**/app/overview", { timeout: 90000 }).catch(() => {});
  await page.waitForTimeout(2000);
}

await page.goto("http://localhost:5173/app/overview", {
  waitUntil: "networkidle",
});
await shot(page, "02-overview.png");

await page.goto("http://localhost:5173/app/risk", {
  waitUntil: "networkidle",
});
await shot(page, "03-risk.png");

await page.goto("http://localhost:5173/app/predictions", {
  waitUntil: "networkidle",
});
await shot(page, "04-predictions.png");

const emp = page.getByText(/EMP-/i).first();
if ((await emp.count()) > 0) {
  await emp.click().catch(() => {});
  await page.waitForTimeout(1000);
}

await page.goto("http://localhost:5173/app/investigate", {
  waitUntil: "networkidle",
});
await shot(page, "05-investigate.png");

const evidence = page.getByRole("button", { name: /evidence/i });
if ((await evidence.count()) > 0) {
  await evidence.first().click();
  await page.waitForTimeout(900);
  await shot(page, "06-evidence.png");
}

await page.goto("http://localhost:5173/app/system", {
  waitUntil: "networkidle",
});
await shot(page, "07-system.png");

await page.goto("http://127.0.0.1:8000/docs", { waitUntil: "networkidle" });
await shot(page, "08-swagger.png");

await browser.close();
