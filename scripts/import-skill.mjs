#!/usr/bin/env node
/**
 * Import a skill from another GitHub repo into skills/<name>/, pinned to an exact commit,
 * with its licence and full credit to the original author.
 *
 *   node scripts/import-skill.mjs <owner>/<repo>[/<path/to/skill>] [--name my-name] [--ref <branch|tag|sha>]
 *
 * Examples:
 *   node scripts/import-skill.mjs mattpocock/skills/grill-me
 *   node scripts/import-skill.mjs skills-il/hebrew-content-writer --name hebrew-content-writer
 *
 * Refuses to copy a skill whose licence does not allow redistribution (or has no licence).
 * After importing, run: npm run scan -- skills/<name>   and   npm run review -- skills/<name>
 */
import { execFileSync } from "node:child_process";
import { cp, mkdtemp, readFile, readdir, rm, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { parseFrontmatter } from "./frontmatter.mjs";

const ROOT = new URL("..", import.meta.url).pathname;

// Licences that allow copying + redistribution with attribution.
const PERMISSIVE = [
  ["MIT", /Permission is hereby granted, free of charge/i],
  ["Apache-2.0", /Apache License[\s,]+Version 2\.0/i],
  ["BSD-3-Clause", /Redistribution and use in source and binary forms[\s\S]{0,800}Neither the name/i],
  ["BSD-2-Clause", /Redistribution and use in source and binary forms/i],
  ["ISC", /Permission to use, copy, modify, and\/or distribute this software for any purpose/i],
  ["CC0-1.0", /CC0 1\.0 Universal/i],
  ["Unlicense", /This is free and unencumbered software released into the public domain/i],
  ["CC-BY-4.0", /Creative Commons Attribution 4\.0 International/i],
];
const LICENSE_FILES = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"];

function git(args, cwd) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

async function exists(p) {
  return access(p).then(() => true, () => false);
}

async function findLicense(dirs) {
  for (const dir of dirs) {
    for (const name of LICENSE_FILES) {
      const p = join(dir, name);
      if (await exists(p)) return { path: p, text: await readFile(p, "utf8") };
    }
  }
  return null;
}

function detectSpdx(text) {
  for (const [id, re] of PERMISSIVE) if (re.test(text)) return id;
  return null;
}


async function locateSkill(repoDir, subpath) {
  if (subpath) {
    const dir = join(repoDir, subpath);
    if (await exists(join(dir, "SKILL.md"))) return dir;
    // common layouts: skills/<name>, <name>
    for (const alt of [join(repoDir, "skills", subpath), join(repoDir, ".claude", "skills", subpath)]) {
      if (await exists(join(alt, "SKILL.md"))) return alt;
    }
    throw new Error(`No SKILL.md found at ${subpath}`);
  }
  if (await exists(join(repoDir, "SKILL.md"))) return repoDir;
  throw new Error("Repo root has no SKILL.md - pass the path to the skill folder, e.g. owner/repo/skills/name");
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (flag) => {
    const i = args.indexOf(flag);
    return i >= 0 ? args.splice(i, 2)[1] : undefined;
  };
  const nameOverride = opt("--name");
  const ref = opt("--ref");
  const spec = args[0];
  if (!spec || !/^[\w.-]+\/[\w.-]+(\/.+)?$/.test(spec)) {
    console.error("Usage: node scripts/import-skill.mjs <owner>/<repo>[/<path>] [--name x] [--ref y]");
    process.exit(2);
  }
  const [owner, repo, ...rest] = spec.split("/");
  const subpath = rest.join("/");

  if (owner.toLowerCase() === "adidinahon") {
    console.error("This is already your repo - add the skill directly under skills/ with origin: original.");
    process.exit(2);
  }

  const tmp = await mkdtemp(join(tmpdir(), "skill-import-"));
  try {
    const url = `https://github.com/${owner}/${repo}.git`;
    console.log(`Cloning ${url} ...`);
    // Sparse, blobless clone: download only the skill folder and licence files, not the whole repo.
    git(["clone", "--quiet", "--filter=blob:none", "--no-checkout", ...(ref ? [] : ["--depth", "1"]), url, tmp]);
    const sparse = ["/LICENSE*", "/LICENCE*", "/COPYING*", "/SKILL.md"];
    if (subpath) sparse.push(`/${subpath}/`, `/skills/${subpath}/`, `/.claude/skills/${subpath}/`);
    git(["sparse-checkout", "set", "--no-cone", ...sparse], tmp);
    git(["checkout", "--quiet", ref ?? "HEAD"], tmp);
    const commit = git(["rev-parse", "HEAD"], tmp);

    const skillDir = await locateSkill(tmp, subpath);
    const fm = parseFrontmatter(await readFile(join(skillDir, "SKILL.md"), "utf8")) ?? {};
    const name = (nameOverride ?? fm.name ?? basename(skillDir)).toLowerCase().replace(/[^a-z0-9-]+/g, "-");

    const license = await findLicense([skillDir, tmp]);
    const spdx = license ? detectSpdx(license.text) : null;
    if (!license) {
      console.error(`\n✗ ${owner}/${repo} has no LICENSE. Without a licence all rights are reserved - it cannot be copied.`);
      console.error("  Options: ask the author to add a licence, or list it on the site as an external link (not imported).");
      process.exit(3);
    }
    if (!spdx) {
      console.error(`\n✗ Licence at ${license.path.replace(tmp, "")} is not a recognised permissive licence.`);
      console.error("  It may forbid redistribution (e.g. 'source-available' or proprietary). Not importing. Read it and decide manually.");
      process.exit(3);
    }

    const dest = join(ROOT, "skills", name);
    if (await exists(dest)) {
      console.error(`\n✗ skills/${name} already exists. Use --name to pick another name, or delete it first to re-import.`);
      process.exit(4);
    }

    await cp(skillDir, dest, {
      recursive: true,
      filter: (src) => !/(^|\/)\.git(\/|$)/.test(src),
    });
    // keep the upstream licence verbatim, even if it lived at the repo root
    const destLicense = join(dest, LICENSE_FILES.includes(basename(license.path)) && license.path.startsWith(skillDir) ? basename(license.path) : "LICENSE.upstream");
    if (!(await exists(destLicense))) await writeFile(destLicense, license.text);

    const author = git(["log", "-1", "--format=%an", "--", subpath || "."], tmp) || owner;
    const upstream = `https://github.com/${owner}/${repo}${subpath ? `/tree/${commit}/${subpath}` : `/tree/${commit}`}`;
    const today = new Date().toISOString().slice(0, 10);

    await writeFile(
      join(dest, "SOURCE.md"),
      `---
origin: imported
upstream: ${upstream}
repo: ${owner}/${repo}
path: ${subpath || "."}
commit: ${commit}
author: ${owner}
last_commit_author: ${author}
license: ${spdx}
imported_at: ${today}
curated_by: Adi Nahon
---

# מקור הסקיל

הסקיל הזה **לא נכתב על ידי עדי נהון**. הוא נאסף, נבדק ומופץ כאן לפי הרישיון שלו.

- **יוצר:** [${owner}](https://github.com/${owner})
- **מקור:** [${owner}/${repo}](${upstream})
- **גרסה:** \`${commit}\`
- **רישיון:** ${spdx} (הטקסט המלא בקובץ הרישיון בתיקייה הזו)

## מה השתנה מהמקור

לא שונה דבר. אם הסקיל יותאם בעתיד, \`origin\` ישתנה ל-\`adapted\` והשינויים יתועדו כאן.
`,
    );

    const files = (await readdir(dest, { recursive: true })).length;
    console.log(`\n✓ Imported ${owner}/${repo}${subpath ? `/${subpath}` : ""} → skills/${name}`);
    console.log(`  commit ${commit} · licence ${spdx} · ${files} files`);
    console.log(`\nNext: npm run scan -- skills/${name}  &&  npm run review -- skills/${name}`);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
