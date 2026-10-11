import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

async function walk(dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out;
}

/** SHA-256 over every file path + content in a skill folder. Any edit changes it. */
export async function hashSkill(skillDir) {
  const h = createHash("sha256");
  for (const f of (await walk(skillDir)).sort()) {
    h.update(relative(skillDir, f).replaceAll("\\", "/"));
    h.update("\0");
    h.update(await readFile(f));
    h.update("\0");
  }
  return h.digest("hex");
}
