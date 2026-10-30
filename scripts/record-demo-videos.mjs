#!/usr/bin/env node
/**
 * Records the three product walkthroughs shown on the site, from the live demo running the real engine.
 *
 *   npm run dev -- -p 3100            # in another terminal
 *   node scripts/record-demo-videos.mjs http://localhost:3100
 *
 * Writes public/videos/{tour,engine,provenance}.webm with matching WebVTT captions (timed from the moments the
 * script performs each step, so captions and video stay in sync), and public/screens/demo-scan.png -- the
 * landing page's hero image -- from the same session. Nothing is staged: every result on screen is the scan
 * response from /api/demo/scan.
 */
import { chromium } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.argv[2] ?? "http://localhost:3100";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const videoDir = path.join(root, "public", "videos");
const screenDir = path.join(root, "public", "screens");
fs.mkdirSync(videoDir, { recursive: true });
fs.mkdirSync(screenDir, { recursive: true });
const SIZE = { width: 1280, height: 800 };

/** A visitor who has already answered the cookie banner ("necessary only"), so it never covers the recording. */
async function newVisitor(browser, options) {
  const context = await browser.newContext({ viewport: SIZE, deviceScaleFactor: 1, ...options });
  await context.addInitScript(() => {
    try {
      localStorage.setItem("tl_cookie_consent", "necessary");
      localStorage.setItem("tl_cookie_consent_date", new Date().toISOString());
    } catch { /* storage unavailable: the banner would show, nothing else changes */ }
    // the development server's own badge (absent in production) stays out of the recording
    const hide = () => { const s = document.createElement("style"); s.textContent = "nextjs-portal{display:none!important}"; document.head.appendChild(s); };
    if (document.head) hide(); else document.addEventListener("DOMContentLoaded", hide);
  });
  return context;
}

const vttTime = ms => {
  const t = Math.max(0, ms) / 1000;
  const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), s = (t % 60).toFixed(3).padStart(6, "0");
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${s}`;
};

/** One recording: runs `steps`, each with a caption, then saves the video and the captions under `id`. */
async function record(browser, id, steps) {
  const tmp = fs.mkdtempSync(path.join(videoDir, `.rec-${id}-`));
  const context = await newVisitor(browser, { recordVideo: { dir: tmp, size: SIZE } });
  const started = Date.now();
  const page = await context.newPage();
  const cues = [];
  let open = null;
  const caption = text => {
    const now = Date.now() - started;
    if (open) cues.push({ ...open, end: now });
    open = { start: now, text };
  };
  for (const step of steps) {
    caption(step.caption);
    const t0 = Date.now();
    await step.run(page);
    // every caption stays up long enough to read
    const left = 7000 - (Date.now() - t0);
    if (left > 0) await page.waitForTimeout(left);
  }
  const end = Date.now() - started;
  if (open) cues.push({ ...open, end });
  const video = page.video();
  await context.close();
  const out = path.join(videoDir, `${id}.webm`);
  fs.renameSync(await video.path(), out);
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.writeFileSync(path.join(videoDir, `${id}.vtt`),
    "WEBVTT\n\n" + cues.map((c, i) => `${i + 1}\n${vttTime(c.start)} --> ${vttTime(c.end)}\n${c.text}\n`).join("\n"));
  console.log(`recorded ${id}: ${(end / 1000).toFixed(1)} s, ${cues.length} captions`);
}

const pause = ms => page => page.waitForTimeout(ms);
const click = (name, after = 900) => async page => { await page.getByRole("button", { name }).first().click(); await page.waitForTimeout(after); };
const scanAndWait = name => async page => {
  const done = page.waitForResponse(r => r.url().endsWith("/api/demo/scan") && r.request().method() === "POST", { timeout: 120000 });
  await page.getByRole("button", { name }).first().click();
  await done;
  await page.waitForTimeout(1500);
};
const scrollTo = (text, after = 1400) => async page => {
  await page.getByText(text, { exact: false }).first().scrollIntoViewIfNeeded();
  await page.waitForTimeout(after);
};
// "load", not "networkidle": a dev server's live-reload connection never goes idle
const open = async page => { await page.goto(`${BASE}/demo`, { waitUntil: "load", timeout: 120000 }); await page.waitForTimeout(2000); };

const browser = await chromium.launch();
try {
  await record(browser, "tour", [
    { caption: "The TrustLedger live demo runs the real scanner on a sample app. Here: an Express route and a repository in another file.", run: async page => { await open(page); await page.mouse.wheel(0, 260); await page.waitForTimeout(3500); } },
    { caption: "Scanning the vulnerable version — the same engine that checks pull requests.", run: scanAndWait(/Scan the vulnerable code/) },
    { caption: "The check blocks the merge: a SQL injection, reported at the call in the route that hands the email to the repository.", run: pause(4500) },
    { caption: "The trace follows the email from req.query in routes/users.ts into db/users.ts, where it is concatenated into SQL.", run: async page => { await scrollTo("Source → sink trace")(page); await page.waitForTimeout(4000); } },
    { caption: "The fix uses a parameterised query. Rescanning…", run: scanAndWait(/Apply the fix and rescan/) },
    { caption: "No finding: the check passes and the merge is unblocked.", run: async page => { await page.mouse.wheel(0, -400); await page.waitForTimeout(4500); } },
  ]);

  await record(browser, "engine", [
    { caption: "How the engine finds a real vulnerability across files.", run: async page => { await open(page); await page.mouse.wheel(0, 260); await page.waitForTimeout(2500); } },
    { caption: "Scan: the value is tracked from its source, through a function call, to the database call it reaches.", run: scanAndWait(/Scan the vulnerable code/) },
    { caption: "Each step of the trace names its kind, file and line: source, cross-file parameter, sink.", run: async page => { await scrollTo("Source → sink trace")(page); await page.waitForTimeout(5000); } },
    { caption: "Side by side: the concatenated query, and the parameterised one.", run: async page => { await page.mouse.wheel(0, -500); await click(/side-by-side fix/, 4500)(page); } },
    { caption: "Rescanning the fixed code: the SQL text no longer carries request data, so there is nothing to report.", run: async page => { await click(/side-by-side fix/, 600)(page); await scanAndWait(/Apply the fix and rescan/)(page); await page.waitForTimeout(2500); } },
    { caption: "A sanitizer clears only what it neutralises. Python sample: request data echoed into HTML.", run: async page => { await page.getByRole("button", { name: /Reflected XSS/ }).click(); await page.waitForTimeout(1500); await scanAndWait(/Scan the vulnerable code/)(page); await page.waitForTimeout(2500); } },
    { caption: "Escaping the value for HTML clears the XSS finding.", run: async page => { await scanAndWait(/Apply the fix and rescan/)(page); await page.waitForTimeout(3500); } },
  ]);

  await record(browser, "provenance", [
    { caption: "AI provenance and reviewer sign-off, on the same scan.", run: async page => { await open(page); await page.mouse.wheel(0, 260); await page.waitForTimeout(2000); await scanAndWait(/Scan the vulnerable code/)(page); } },
    { caption: "Each file gets an AI-generated estimate — a probability from code signals, not proof of authorship — and a content hash.", run: scrollTo("Provenance & sign-off", 5000) },
    { caption: "A reviewer signs off (simulated here). The sign-off is bound to this exact content hash.", run: async page => { await click(/Simulate a reviewer sign-off/, 4000)(page); } },
    { caption: "Now the code changes…", run: async page => { await page.mouse.wheel(0, -600); await click(/Edit the code/, 800)(page); const box = page.getByRole("textbox").first(); await box.click(); await page.keyboard.press("Control+End"); await page.keyboard.type("\n// a small change after review\n", { delay: 35 }); await page.waitForTimeout(1200); } },
    { caption: "…and is scanned again.", run: scanAndWait(/Scan my edit/) },
    { caption: "The content hash changed, so the old sign-off no longer covers the file: a reviewer must attest again.", run: scrollTo("Provenance & sign-off", 5500) },
  ]);

  // the landing page's hero image: the demo's result for the SQL-injection sample
  const ctx = await newVisitor(browser);
  const page = await ctx.newPage();
  await open(page);
  await scanAndWait(/Scan the vulnerable code/)(page);
  await page.getByRole("button", { name: /SQL Injection/ }).first().click().catch(() => {});
  await page.getByText("TrustLedger check").first().scrollIntoViewIfNeeded();
  await page.mouse.wheel(0, -120);
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(screenDir, "demo-scan.png") });
  await ctx.close();
  console.log("captured public/screens/demo-scan.png");
} finally {
  await browser.close();
}
