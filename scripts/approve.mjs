#!/usr/bin/env node
/**
 * Human approval step. Runs the static scan and the AI review, shows the result,
 * and - only if both allow it - writes reviews/<name>.json bound to the exact
 * content hash of the skill. Editing the skill afterwards invalidates the approval
 * (CI fails until it is re-approved).
 *
 *   ANTHROPIC_API_KEY=... node scripts/approve.mjs <name> [--accept-warnings]
 */
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { hashSkill } from "./hash.mjs";

const ROOT = new URL("..", import.meta.url).pathname;
const name = process.argv[2];
const acceptWarnings = process.argv.includes("--accept-warnings");
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
const aiOut = join(ROOT, "reports", `ai-${name}.json`);
const aiOk = run("ai-review.mjs", aiOut);
const ai = JSON.parse(await readFile(aiOut, "utf8")).results[0];
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
  approved_by: "Adi Nahon",
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
