---
name: nvr-verify-close
description: Prove a Node.js patch took effect and close out - no vulnerable or EOL binaries, no STALE processes, PM2 apps and Docker containers on fixed versions, repos re-scanned, closure summary. Use after patching or for "did the update work", "verify the fix", "close the incident", "verificar el parche", "confirmar que quedó".
---

# Verify and Close

Follow **nvr-navigator** rules. Read-only. For many apps or client systems, have a
separate agent or person verify (the bundled `nvr-verifier` agent in Claude Code), so
the patch work is not grading itself.

## 1. Each server

```bash
bash "$NVR/scripts/verify.sh" --url https://<site>
```

| Result | Meaning | Action |
|---|---|---|
| PASS | No vulnerable/EOL binaries, no STALE processes, PM2 apps and containers fixed | Close |
| CONFIRM | Distro builds, ranges or hidden items unconfirmed | Confirm backport or real version |
| FAIL | Something still vulnerable, EOL or STALE | Back to nvr-patch (often just a restart: `pm2 update`) |

## 2. Repos and platforms

- `scan.sh --project <code dir>`: no EOL or VULNERABLE pins left; FLOATING entries
  rebuilt with `--pull` since the release (check image build dates).
- Platforms (Vercel, Netlify, Lambda, Heroku): a deploy after the release date, Node
  setting on a supported line.

## 3. Closure checklist

- [ ] Every server: verify PASS
- [ ] Every repo: no EOL/VULNERABLE pins; floating images rebuilt
- [ ] HTTP2Shell: system Brotli library updated (or bridged with a dated plan), Bun >= 1.4.4,
      body-parser >= 2.4.0 / 1.20.9, EXPOSED Express 5 apps confirmed on a patched Node
- [ ] Every platform app: redeployed on a supported line
- [ ] Internet-facing apps: compromise check done, gaps listed
- [ ] EOL apps: migrated, or containment recorded with a migration date
- [ ] Secrets rotated where compromise was confirmed
- [ ] `nvr-log.md` complete

## 4. Summary

Scope, findings, what changed and when, open items with owners and dates, evidence
(reports, log). No secrets.
