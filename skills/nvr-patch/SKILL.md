---
name: nvr-patch
description: Patch Node.js for the current security release with approval gates and rollback - servers (nvm, fnm, Volta, asdf, mise, n, Homebrew, NodeSource, distro packages, cPanel/CloudLinux/Plesk, tarballs), Docker images, CI, and platforms (Vercel, Netlify, AWS Lambda, Heroku, Render, Cloud Run, Azure), plus restarts (PM2, systemd, Passenger) and end-of-life major upgrades. Use for "patch Node", "upgrade Node", "fix the Node vulnerability", "actualizar Node", "parchar Node".
---

# Patch (changes systems: approval required at every step)

Follow **nvr-navigator** rules, especially rule 3: exact command, impact, downtime and
rollback, then an explicit yes for **each** command.

## 1. Plan (read-only)

Servers:
```bash
bash "$NVR/scripts/patch-plan.sh" | tee plan-$(hostname).txt
```
It prints commands per install method found (nvm, NodeSource, Homebrew...) plus the
restarts for PM2, systemd units, containers and Passenger apps. It runs nothing.

Repos, images, CI and platforms: use the `scan.sh --project` report and
`references/playbooks.md`.

## 2. Pre-flight (one approval for the list)

- [ ] Snapshot/backup, or current versions recorded (the plan lists them)
- [ ] Same-major patch (e.g. 24.22.0 -> 24.22.1): drop-in, restart only
- [ ] Major change (EOL): staging first, `npm rebuild` for native addons
      (`references/eol-migration.md`)
- [ ] Signs of compromise checked; if active, contain and run nvr-compromise-check first
- [ ] Rollback written down (playbooks.md has one per method)

## 3. Execute one step at a time

1. Show the command with one line on what it does.
2. Wait for "yes" ("sí", "dale", "adelante").
3. Run it, show the key output, log it in `nvr-log.md`.
4. Stop and ask on anything unexpected (other packages removed, a different version,
   prompts). Never add `--force` or blanket yes flags on your own.

Order: install the fixed Node -> switch the default -> restart every app that runs
Node -> verify. **Installing is not enough: running apps keep the old runtime until
restarted** (PM2 needs `pm2 update`).

## 4. HTTP2Shell extras (patch-plan prints these too)

- **System Brotli library** (distro Node, curl, others): OS update for `libbrotli1` /
  `brotli` / `brotli-libs`, then restart services that load it. No fixed build yet
  (Ubuntu under evaluation)? Bridge: block `Content-Encoding: br` request bodies at the
  proxy/WAF; isolate services that fetch untrusted URLs.
- **Bun**: `bun upgrade` (or `brew upgrade bun`), pin `oven/bun:1.4.4`+ and rebuild.
- **Express 5 apps**: `npm update body-parser` (2.4.0 fixes CVE-2026-111181); until Node
  is patched, `express.json({ inflate: false })` (rejects gzip bodies too, so check
  clients first) or the proxy rule above. Express 4 already rejects Brotli bodies.

## 5. FLOATING configs

`node:22-alpine`, `lts/*`, `engines >=22` pick up the fix only on the next build or
install. Prefer pinning the fixed release (`node:22.23.4-alpine`, `.nvmrc 22.23.4`),
then rebuild with `--pull` and redeploy. Commit the pin so the fix is reviewable.

## 6. Hand off

Finish with **nvr-verify-close**: no VULNERABLE/EOL/STALE, PM2 apps and containers on
fixed versions, repos re-scanned.
