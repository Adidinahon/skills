#!/usr/bin/env node
/**
 * Human approval step. Runs the static scan and the AI review, shows the result,
 * and - only if both allow it - writes reviews/<name>.json bound to the exact
 * content hash of the skill. Editing the skill afterwards invalidates the approval
 * (CI fails until it is re-approved).
 *
 *   ANTHROPIC_API_KEY=... node scripts/approve.mjs <name> [--accept-warnings]
 *   node scripts/approve.mjs <name> --from-report ai-report.json [--accept-warnings] [--approver "..."]
 *
 * --from-report uses the AI review produced by GitHub CI (the API key lives only there).
 * The report must have been made for the exact current content of the skill.
 */
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { hashSkill } from "./hash.mjs";

const ROOT = new URL("..", import.meta.url).pathname;
const argv = process.argv.slice(2);
const flag = (f) => {
  const i = argv.indexOf(f);
  return i >= 0 ? argv.splice(i, 2)[1] : undefined;
};
const fromReport = flag("--from-report");
const approver = flag("--approver") ?? "Adi Nahon";
const acceptWarnings = argv.includes("--accept-warnings");
const name = argv.find((a) => !a.startsWith("--"));
if (!name) {
  console.error("Usage: node scripts/approve.mjs <skill-name> [--accept-warnings]");
  process.exit(2);
}
const dir = join(ROOT, "skills", name);
await mkdir(join(ROOT, "reports"), { recursive: true });

const run = (script, out) => {
  try {
    execFileSync("node", [join(ROOT, "scripts", script), "--json", out, `skills/${name}`], { stdio: "inherit" });
    return true;
  } catch {
    return false;
  }
};

console.log(`\n== 1/2 static scan: ${name} ==`);
const scanOut = join(ROOT, "reports", `scan-${name}.json`);
if (!run("scan.mjs", scanOut)) {
  console.error("\n✗ Static scan has HIGH findings. Not approved.");
  process.exit(1);
}
const scan = JSON.parse(await readFile(scanOut, "utf8")).results[0];
const scanWarnings = scan.findings.filter((f) => f.level === "medium");

console.log(`\n== 2/2 AI review: ${name} ==`);
let ai;
let aiOk = true;
if (fromReport) {
  const report = JSON.parse(await readFile(fromReport, "utf8"));
  ai = report.results.find((r) => r.skill === `skills/${name}`);
  if (!ai) {
    console.error(`✗ ${fromReport} has no review for skills/${name}.`);
    process.exit(1);
  }
  if (ai.content_sha256 !== (await hashSkill(dir))) {
    console.error("✗ The AI review was made for different content than what is on disk now. Re-run CI.");
    process.exit(1);
  }
  // Reports from the old reviewer only covered an allow-list of extensions. Accept them only if the skill has
  // no file outside that list (otherwise the AI never saw part of the skill).
  if (!Array.isArray(ai.files_reviewed)) {
    const LEGACY = new Set([".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".csv", ".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".html", ".css", ".svg"]);
    const BIN = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif", ".ttf", ".otf", ".woff", ".woff2"]);
    const { readdir } = await import("node:fs/promises");
    const { extname, basename } = await import("node:path");
    const all = (await readdir(dir, { recursive: true, withFileTypes: true })).filter((e) => e.isFile());
    const unseen = all
      .map((e) => join(e.parentPath ?? e.path, e.name))
      .filter((f) => !LEGACY.has(extname(f).toLowerCase()) && !BIN.has(extname(f).toLowerCase()) && !/LICENSE/.test(basename(f)) && basename(f) !== ".gitkeep");
    if (unseen.length) {
      console.error(`✗ The AI review predates full-file coverage and skipped: ${unseen.map((f) => f.replace(dir + "/", "")).join(", ")}. Re-run CI.`);
      process.exit(1);
    }
  }
  console.log(`[${ai.verdict.toUpperCase()}] ${ai.summary_he}`);
  for (const c of ai.concerns ?? []) console.log(`  ${c.severity.toUpperCase().padEnd(6)} ${c.file}: ${c.issue}`);
} else {
  const aiOut = join(ROOT, "reports", `ai-${name}.json`);
  aiOk = run("ai-review.mjs", aiOut);
  ai = JSON.parse(await readFile(aiOut, "utf8")).results[0];
}
if (!aiOk || ai.verdict === "fail") {
  console.error("\n✗ AI review failed the skill. Not approved.");
  process.exit(1);
}

const hasWarnings = ai.verdict === "warn" || scanWarnings.length > 0;
if (hasWarnings && !acceptWarnings) {
  if (!process.stdin.isTTY) {
    console.error("\n! Warnings present. Re-run with --accept-warnings after reading them.");
    process.exit(1);
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(`\n! ${scanWarnings.length} scan warning(s), AI verdict "${ai.verdict}". Read them above. Approve anyway? (yes/no) `);
  rl.close();
  if (answer.trim().toLowerCase() !== "yes") {
    console.log("Not approved.");
    process.exit(1);
  }
}

const review = {
  skill: name,
  verdict: hasWarnings ? "warn" : "pass",
  content_sha256: await hashSkill(dir),
  reviewed_at: new Date().toISOString(),
  approved_by: approver,
  ai_model: "claude-opus-5-5",
  summary_he: ai.summary_he,
  does_what_it_claims: ai.does_what_it_claims,
  concerns: ai.concerns,
  network_destinations: ai.network_destinations,
  requires_secrets: ai.requires_secrets,
  scan_warnings: scanWarnings.map((f) => `${f.rule} ${f.file}${f.line ? `:${f.line}` : ""}`),
  external_urls: scan.externalUrls,
};
await mkdir(join(ROOT, "reviews"), { recursive: true });
await writeFile(join(ROOT, "reviews", `${name}.json`), JSON.stringify(review, null, 2) + "\n");
console.log(`\n✓ Approved → reviews/${name}.json (${review.verdict}). Now run: npm run index`);
