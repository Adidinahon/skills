/**
 * Minimal YAML frontmatter reader for SKILL.md / SOURCE.md.
 * Supports `key: value`, quoted values, and folded/literal blocks (`key: >` / `key: |`).
 */
export function parseFrontmatter(md) {
  const m = md.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return null;
  const data = {};
  const lines = m[1].split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const kv = lines[i].match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!kv) continue;
    let value = kv[2];
    if (/^[>|][+-]?$/.test(value)) {
      const literal = value.startsWith("|");
      const block = [];
      while (i + 1 < lines.length && (/^\s+\S/.test(lines[i + 1]) || lines[i + 1].trim() === "")) block.push(lines[++i].trim());
      value = literal ? block.join("\n") : block.join(" ").replace(/\s+/g, " ");
    }
    data[kv[1]] = value.replace(/^["']|["']$/g, "").trim();
  }
  return data;
}
