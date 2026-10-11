#!/usr/bin/env node
/**
 * Builds skills.json - the public catalogue adinahon.com reads.
 * Only skills that passed review (reviews/<name>.json with verdict pass|warn) are listed.
 *
 *   node scripts/build-index.mjs           # write skills.json
 *   node scripts/build-index.mjs --check   # fail if skills.json is out of date (CI)
 */
import { readdir, readFile, writeFile } from "node:fs/promises";
import { parseFrontmatter } from "./frontmatter.mjs";
import { join } from "node:path";
import { hashSkill } from "./hash.mjs";

const ROOT = new URL("..", import.meta.url).pathname;
const REPO = "Adidinahon/skills";


async function readJson(p) {
  try {
    return JSON.parse(await readFile(p, "utf8"));
  } catch {
    return null;
  }
}

async function build() {
  const dirs = (await readdir(join(ROOT, "skills"), { withFileTypes: true }).catch(() => [])).filter((e) => e.isDirectory());
  const skills = [];
  const stale = [];
  for (const d of dirs.sort((a, b) => a.name.localeCompare(b.name))) {
    const base = join(ROOT, "skills", d.name);
    const skill = (parseFrontmatter(await readFile(join(base, "SKILL.md"), "utf8").catch(() => "")) ?? {});
    const source = (parseFrontmatter(await readFile(join(base, "SOURCE.md"), "utf8").catch(() => "")) ?? {});
    const review = await readJson(join(ROOT, "reviews", `${d.name}.json`));
    if (!review || !["pass", "warn"].includes(review.verdict)) continue; // not reviewed yet = not public
    if (review.content_sha256 !== (await hashSkill(base))) {
      stale.push(d.name);
      continue; // edited after approval = not public until re-approved
    }

    skills.push({
      name: d.name,
      description: skill.description ?? "",
      origin: source.origin ?? "original",
      author: source.origin === "original" ? "Adidinahon" : source.author,
      license: source.license,
      upstream: source.upstream ?? null,
      upstream_commit: source.commit ?? null,
      github_url: `https://github.com/${REPO}/tree/main/skills/${d.name}`,
      install_command: `npx skills add ${REPO}/skills/${d.name}`,
      review: {
        verdict: review.verdict,
        reviewed_at: review.reviewed_at,
        content_sha256: review.content_sha256,
        summary_he: review.summary_he,
        network_destinations: review.network_destinations ?? [],
        requires_secrets: review.requires_secrets ?? [],
        approved_by: review.approved_by,
      },
    });
  }
  return { index: { repo: REPO, generated_from: "scripts/build-index.mjs", skills }, stale };
}

const { index, stale } = await build();
if (stale.length) {
  console.error(`Changed after approval (re-run scripts/approve.mjs): ${stale.join(", ")}`);
  if (process.argv.includes("--check")) process.exit(1);
}
const out = JSON.stringify(index, null, 2) + "\n";
const target = join(ROOT, "skills.json");
if (process.argv.includes("--check")) {
  const current = await readFile(target, "utf8").catch(() => "");
  if (current !== out) {
    console.error("skills.json is out of date - run `npm run index` and commit it.");
    process.exit(1);
  }
  console.log("skills.json is up to date.");
} else {
  await writeFile(target, out);
  console.log(`skills.json written (${JSON.parse(out).skills.length} public skills).`);
}
