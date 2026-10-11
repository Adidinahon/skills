#!/usr/bin/env node
/**
 * Static security scan for every skill under skills/.
 *
 *   node scripts/scan.mjs                 # scan all skills
 *   node scripts/scan.mjs skills/foo      # scan specific skill folders
 *   node scripts/scan.mjs --json out.json # also write a machine-readable report
 *
 * Exit code 1 if any HIGH finding exists. MEDIUM findings are printed as warnings
 * and must be acknowledged by a human reviewer in the PR.
 *
 * This is a first line of defence, not a proof of safety. Every skill also goes
 * through the AI review (ai-review.mjs) and a human approval before merge.
 */
import { readdir, readFile, lstat, writeFile } from "node:fs/promises";
import { join, relative, extname, basename } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const SKILLS_DIR = join(ROOT, "skills");

const MAX_FILE_BYTES = 1_000_000;
const MAX_SKILL_BYTES = 5_000_000;
const ALLOWED_EXT = new Set([
  ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".csv",
  ".py", ".js", ".mjs", ".cjs", ".ts", ".sh",
  ".html", ".css", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif",
]);
const BINARY_EXT = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif"]);
const SCRIPT_EXT = new Set([".py", ".js", ".mjs", ".cjs", ".ts", ".sh"]);
const LICENSE_NAMES = new Set(["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE.upstream"]);

/** @typedef {{ level: "high" | "medium", rule: string, file: string, line?: number, detail: string }} Finding */

const SECRET_RULES = [
  ["anthropic-key", /sk-ant-[a-z0-9_-]{20,}/i],
  ["openai-key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
  ["github-token", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}/],
  ["aws-key", /\bAKIA[0-9A-Z]{16}\b/],
  ["google-key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["slack-token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ["stripe-key", /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/],
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ["supabase-service-jwt", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*c2VydmljZV9yb2xl[A-Za-z0-9_-]*\./],
];

// Dangerous behaviour in scripts AND in instructions (a SKILL.md can tell the agent to run these).
const DANGER_RULES = [
  ["pipe-to-shell", "high", /\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/i],
  ["pipe-to-interpreter", "high", /\b(?:curl|wget)\b[^\n|]*\|\s*(?:python3?|node|perl|ruby)\b/i],
  ["rm-rf-root-or-home", "high", /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:\/(?:\s|$|\*)|~\/?(?:\s|$|\*)|\$HOME\b)/i],
  ["base64-exec", "high", /base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh\b|atob\([^)]*\)\s*\)?\s*;?\s*(?:eval|Function)\b|exec\(\s*(?:base64\.b64decode|codecs\.decode)/i],
  ["reverse-shell", "high", /\/dev\/tcp\/|\bnc\s+(?:-[a-z]*e|.*-e\s)|\bncat\b.*--exec|bash\s+-i\s+>&|socat\b.*exec:/i],
  ["powershell-encoded", "high", /powershell(?:\.exe)?\s+[^\n]*-(?:enc|encodedcommand)\b/i],
  ["credential-store", "high", /security\s+find-(?:generic|internet)-password|\bsecret-tool\s+lookup|Login\s+Data|\.aws\/credentials|\.ssh\/id_[a-z0-9]+|\.netrc\b|keychain-db/i],
  ["browser-cookies", "high", /Cookies(?:\.sqlite)?\b.*(?:Chrome|Firefox|Safari)|(?:Chrome|Firefox).*\bCookies\b/i],
  ["persistence", "medium", /\bcrontab\s+-|LaunchAgents\/|systemctl\s+enable|\/etc\/rc\.local|schtasks\s+\/create/i],
  ["sudo", "medium", /\bsudo\s+/],
  ["chmod-world", "medium", /chmod\s+(?:-R\s+)?(?:777|a\+w|o\+w)/],
  ["eval", "medium", /\beval\s*\(|\bnew\s+Function\s*\(|\bexec\s*\(\s*compile\(/],
  ["env-dump", "medium", /\b(?:printenv|env)\s*(?:\||>)|process\.env\s*\)|os\.environ\s*\)|JSON\.stringify\(\s*process\.env/],
  ["dotenv-read", "medium", /(?:readFile|open|cat)\s*\(?\s*['"`][^'"`]*\.env(?:\.[a-z]+)?['"`]/i],
  ["osascript", "medium", /\bosascript\b/],
  ["disable-safety", "medium", /--dangerously-skip-permissions|--no-verify\b|set\s+\+o\s+history|HISTFILE=\/dev\/null/i],
];

// Prompt-injection patterns aimed at the agent reading the skill.
const INJECTION_RULES = [
  ["ignore-instructions", "high", /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:all\s+)?(?:previous|prior|above|earlier|system|other)\s+(?:instructions|prompts?|rules|messages)/i],
  ["hide-from-user", "high", /\b(?:do\s+not|don't|never)\s+(?:tell|inform|show|mention|reveal)[^.\n]{0,30}\b(?:the\s+)?user\b|\bwithout\s+(?:telling|informing|notifying)\s+the\s+user/i],
  ["exfiltrate", "high", /\bexfiltrat|\bsend\b[^.\n]{0,40}\b(?:api\s*keys?|tokens?|credentials|passwords?|secrets?|\.env)\b[^.\n]{0,40}\b(?:to|via)\b/i],
  ["role-hijack", "medium", /\byou\s+are\s+now\b|\bnew\s+system\s+prompt\b|\bact\s+as\s+(?:root|admin|the\s+system)\b|\bjailbreak\b|\bDAN\b mode/i],
  ["skip-confirmation", "medium", /\bwithout\s+asking\s+(?:for\s+)?(?:permission|confirmation)|\bdo\s+not\s+ask\s+(?:for\s+)?(?:permission|confirmation)|\bauto-?approve\b/i],
];

const HIDDEN_CHARS = [
  // bidi overrides can make code read differently than it runs ("Trojan Source")
  ["bidi-override", "high", /[‪-‮⁦-⁩]/],
  // Unicode tag block - invisible text that models still read
  ["unicode-tags", "high", /[\u{E0000}-\u{E007F}]/u],
  // zero-width chars hide words inside text
  ["zero-width", "medium", /[​-‍⁠﻿]/],
];

async function walk(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out;
}

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

function parseFrontmatter(md) {
  const m = md.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return null;
  const data = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (kv) data[kv[1]] = kv[2].replace(/^["']|["']$/g, "").trim();
  }
  return data;
}

function isExecutableBinary(buf) {
  const h = buf.subarray(0, 4);
  return (
    (h[0] === 0x7f && h[1] === 0x45 && h[2] === 0x4c && h[3] === 0x46) || // ELF
    (h[0] === 0x4d && h[1] === 0x5a) || // PE / MZ
    [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(buf.readUInt32BE(0)) // Mach-O / fat
  );
}

/** @returns {Promise<Finding[]>} */
export async function scanSkill(skillDir) {
  /** @type {Finding[]} */
  const findings = [];
  const name = basename(skillDir);
  const rel = (p) => relative(ROOT, p);
  const add = (level, rule, file, detail, line) => findings.push({ level, rule, file: rel(file), line, detail });

  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(name)) add("high", "folder-name", skillDir, "Skill folder must be kebab-case (a-z, 0-9, -)");

  const files = await walk(skillDir);
  const skillMd = join(skillDir, "SKILL.md");
  if (!files.includes(skillMd)) add("high", "missing-skill-md", skillDir, "Every skill needs a SKILL.md");

  // SKILL.md frontmatter
  let origin = "original";
  if (files.includes(skillMd)) {
    const fm = parseFrontmatter(await readFile(skillMd, "utf8"));
    if (!fm) add("high", "frontmatter", skillMd, "SKILL.md must start with YAML frontmatter (name, description)");
    else {
      if (!fm.name) add("high", "frontmatter", skillMd, "Frontmatter is missing `name`");
      if (fm.name && fm.name !== name) add("medium", "frontmatter", skillMd, `Frontmatter name "${fm.name}" differs from folder "${name}"`);
      if (!fm.description || fm.description.length < 20) add("high", "frontmatter", skillMd, "Frontmatter needs a real `description` (20+ chars)");
    }
  }

  // Provenance: SOURCE.md is required and decides the licence rules
  const sourceMd = join(skillDir, "SOURCE.md");
  if (!files.includes(sourceMd)) add("high", "missing-source", skillDir, "Every skill needs a SOURCE.md (origin, author, license)");
  else {
    const src = parseFrontmatter(await readFile(sourceMd, "utf8")) ?? {};
    origin = src.origin ?? "";
    if (!["original", "imported", "adapted"].includes(origin)) add("high", "source-origin", sourceMd, "SOURCE.md `origin` must be original | imported | adapted");
    if (!src.license) add("high", "source-license", sourceMd, "SOURCE.md must declare an SPDX `license`");
    if (origin !== "original") {
      if (!src.upstream || !/^https:\/\//.test(src.upstream)) add("high", "source-upstream", sourceMd, "Imported/adapted skills need an `upstream` https URL");
      if (!src.commit || !/^[0-9a-f]{40}$/.test(src.commit)) add("high", "source-commit", sourceMd, "Imported/adapted skills must pin the exact upstream `commit` (40-char SHA)");
      if (!src.author) add("high", "source-author", sourceMd, "Imported/adapted skills must credit the upstream `author`");
      if (!files.some((f) => LICENSE_NAMES.has(basename(f)))) add("high", "license-file", skillDir, "Imported/adapted skills must carry the upstream LICENSE file");
    }
  }

  let total = 0;
  const externalUrls = new Set();

  for (const file of files) {
    const st = await lstat(file);
    if (st.isSymbolicLink()) { add("high", "symlink", file, "Symlinks are not allowed"); continue; }
    total += st.size;
    const ext = extname(file).toLowerCase();
    const base = basename(file);

    if (!ALLOWED_EXT.has(ext) && !LICENSE_NAMES.has(base) && base !== "NOTICE") {
      add("high", "file-type", file, `File type "${ext || base}" is not allowed`);
      continue;
    }
    if (st.size > MAX_FILE_BYTES) add("high", "file-size", file, `File is ${(st.size / 1e6).toFixed(1)}MB (max 1MB)`);
    if (st.mode & 0o111 && !SCRIPT_EXT.has(ext)) add("medium", "exec-bit", file, "Non-script file has the executable bit set");

    const buf = await readFile(file);
    if (buf.length >= 4 && isExecutableBinary(buf)) { add("high", "binary-executable", file, "Compiled executable detected"); continue; }
    if (BINARY_EXT.has(ext)) continue;

    const text = buf.toString("utf8");
    if (text.includes("\u0000")) { add("high", "binary-content", file, "Text file contains NUL bytes"); continue; }

    for (const [rule, re] of SECRET_RULES) {
      const m = re.exec(text);
      if (m) add("high", `secret:${rule}`, file, "Looks like a real credential", lineOf(text, m.index));
    }
    for (const [rule, level, re] of DANGER_RULES) {
      const m = re.exec(text);
      if (m) add(level, `danger:${rule}`, file, m[0].slice(0, 120), lineOf(text, m.index));
    }
    if (ext === ".md" || ext === ".txt" || ext === ".html") {
      for (const [rule, level, re] of INJECTION_RULES) {
        const m = re.exec(text);
        if (m) add(level, `injection:${rule}`, file, m[0].slice(0, 120), lineOf(text, m.index));
      }
      // instructions hidden in HTML comments are invisible on GitHub but visible to the model
      for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) {
        if (/\b(?:you|agent|assistant|claude|model|run|execute|ignore|send|curl)\b/i.test(m[1]) && m[1].trim().length > 20) {
          add("medium", "injection:html-comment", file, m[1].trim().slice(0, 120), lineOf(text, m.index));
        }
      }
      if (/data:[a-z]+\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/]{200,}/i.test(text)) add("medium", "embedded-blob", file, "Large base64 data: URI embedded in text");
    }
    for (const [rule, level, re] of HIDDEN_CHARS) {
      const m = re.exec(text);
      if (m) add(level, `hidden:${rule}`, file, `U+${m[0].codePointAt(0).toString(16).toUpperCase()} found`, lineOf(text, m.index));
    }
    for (const m of text.matchAll(/https?:\/\/[^\s)"'`<>\]]+/g)) externalUrls.add(m[0]);
  }

  if (total > MAX_SKILL_BYTES) add("high", "skill-size", skillDir, `Skill is ${(total / 1e6).toFixed(1)}MB (max 5MB)`);

  return { name, origin, findings, externalUrls: [...externalUrls].sort() };
}

async function main() {
  const args = process.argv.slice(2);
  const jsonIdx = args.indexOf("--json");
  const jsonOut = jsonIdx >= 0 ? args.splice(jsonIdx, 2)[1] : null;

  let targets = args.map((a) => join(ROOT, a));
  if (targets.length === 0) {
    const entries = await readdir(SKILLS_DIR, { withFileTypes: true }).catch(() => []);
    targets = entries.filter((e) => e.isDirectory()).map((e) => join(SKILLS_DIR, e.name));
  }

  const results = [];
  for (const dir of targets) results.push(await scanSkill(dir));

  let high = 0;
  let medium = 0;
  for (const r of results) {
    const h = r.findings.filter((f) => f.level === "high");
    const m = r.findings.filter((f) => f.level === "medium");
    high += h.length;
    medium += m.length;
    const status = h.length ? "FAIL" : m.length ? "WARN" : "PASS";
    console.log(`\n[${status}] ${r.name} (${r.origin})`);
    for (const f of r.findings) console.log(`  ${f.level.toUpperCase().padEnd(6)} ${f.rule}  ${f.file}${f.line ? `:${f.line}` : ""}  ${f.detail}`);
    if (r.externalUrls.length) console.log(`  external URLs (review manually): ${r.externalUrls.length}`);
  }
  console.log(`\n${results.length} skill(s) scanned · ${high} high · ${medium} medium`);

  if (jsonOut) await writeFile(jsonOut, JSON.stringify({ scannedAt: new Date().toISOString(), results }, null, 2));
  if (results.length === 0) console.log("No skills yet.");
  process.exit(high > 0 ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
