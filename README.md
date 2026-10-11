# Adi Nahon · Agent Skills

<p dir="rtl">
סקילים לסוכני AI (Claude Code, Codex, Cursor ועוד) שאספתי, בדקתי ואני ממליץ עליהם.
כל סקיל כאן עבר סריקת אבטחה אוטומטית, סקירת AI ואישור ידני שלי לפני שהוא נכנס.
</p>

**Curated, security-reviewed agent skills.** Some I wrote; most were written by others and are redistributed here under their licences, with full credit, pinned to the exact version that was reviewed.

## התקנה · Install

```bash
npx skills add Adidinahon/skills/<skill-name>
```

The full catalogue with review summaries: **[adinahon.com/skills](https://www.adinahon.com/skills)** · machine-readable: [`skills.json`](skills.json)

## Why install from here instead of the original repo?

1. **Reviewed.** Every skill passes a static scan (secrets, dangerous commands, prompt injection, hidden Unicode, binaries) and an AI security review, then a human approval. See [SECURITY.md](SECURITY.md).
2. **Frozen.** Each imported skill is a copy pinned to one upstream commit. If the original changes - or its author's account is compromised - nothing reaches you until the new version is reviewed again.
3. **Tamper-evident.** Each approval in [`reviews/`](reviews) is bound to a SHA-256 of the skill's files. Any edit after approval fails CI and drops the skill from the public catalogue until it is re-approved.

## Credit

Imported skills belong to their authors. Every imported skill folder contains:

- `SOURCE.md` - original author, repo, pinned commit, licence, and what (if anything) was changed
- the upstream `LICENSE` file, verbatim

| `origin` in SOURCE.md | Meaning |
|---|---|
| `original` | Written by Adi Nahon (MIT) |
| `imported` | Unchanged copy of someone else's skill, under its licence |
| `adapted` | Someone else's skill, modified (e.g. translated to Hebrew) - changes listed in SOURCE.md |

Skills without a licence, or with a licence that does not allow redistribution, are **never** copied here.

## Adding a skill

```bash
npm install

# someone else's skill (licence is checked automatically)
npm run import -- <owner>/<repo>/<path-to-skill>

# or your own: create skills/<name>/SKILL.md + SOURCE.md (origin: original, license: MIT)

npm run scan -- skills/<name>                       # static checks
ANTHROPIC_API_KEY=... node scripts/approve.mjs <name> # AI review + human approval
npm run index                                        # update skills.json
```

Then open a PR. CI re-runs everything, and `main` only accepts PRs that pass. Only skills with an approval in `reviews/` that matches their exact content appear in `skills.json`.

## Licence

Tooling and original skills: [MIT](LICENSE). Imported skills: see each skill's own licence.
