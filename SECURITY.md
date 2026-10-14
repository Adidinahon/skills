# Security

## What every skill goes through

| Gate | Tool | Blocks on |
|---|---|---|
| 1. Licence | `scripts/import-skill.mjs` | No licence, or one that forbids redistribution |
| 2. Secrets | gitleaks + `scripts/scan.mjs` | API keys, tokens, private keys - anywhere in git history |
| 3. Static scan | `scripts/scan.mjs` | `curl \| sh`, reverse shells, base64-to-exec, credential/keychain/cookie access, `rm -rf ~`, prompt injection ("ignore previous instructions", "don't tell the user"), bidi overrides & invisible Unicode tags, compiled binaries, symlinks, disallowed file types, oversized files, missing provenance |
| 3b. Exceptions | `scan-allowlist.json` | Each entry silences one finding only while the file, rule and exact flagged text still match, and must state a reason (e.g. a skill that *quotes* an injection phrase to defend against it). Editing the line revives the finding; the file is code-owner reviewed |
| 4. AI review | `scripts/ai-review.mjs` (Claude) | Code or instructions that do more than the description says, exfiltration, obfuscation, privilege escalation, unconfirmed destructive actions. The skill is passed as untrusted data; attempts to instruct the reviewer are themselves a finding |
| 5. Human approval | `scripts/approve.mjs` | Anything the owner is not comfortable with. Warnings must be read and explicitly accepted. The approval is a signed-off file in `reviews/`, merged only through a PR |
| 6. Tamper evidence | `reviews/<name>.json` + CI | Approval is bound to a SHA-256 of the skill's files; any later edit fails CI and unpublishes the skill |
| 7. Upstream drift | `.github/workflows/upstream-check.yml` | Monthly report of upstream changes. Nothing is pulled automatically |

Repository hardening: `main` accepts changes only through pull requests that pass CI - no direct or force pushes, admins included; linear history; GitHub secret scanning with push protection; Dependabot alerts; Actions pinned to commit SHAs; `pull_request` (not `pull_request_target`) so fork PRs never see secrets.

## Limits - please read

Automated review lowers risk; it does not prove a skill is safe. A skill is instructions for an agent that can run commands on your machine. Read a skill before installing it, prefer running agents with permission prompts on, and never give a skill credentials it does not obviously need.

## Reporting

Found something unsafe in a skill listed here? Open an issue (or email hello@adinahon.com for anything sensitive). Affected skills are unpublished first and investigated second.
