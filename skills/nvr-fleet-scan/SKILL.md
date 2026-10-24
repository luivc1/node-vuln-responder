---
name: nvr-fleet-scan
description: Scan code repositories, deploy configs and websites for exposure to the current Node.js security release. Reads .nvmrc, package.json engines/volta, Dockerfiles, docker-compose, GitHub Actions, Netlify, Lambda/Terraform/App Engine runtimes, and fingerprints Node-based sites. Use for "scan our repos", "which projects use old Node", "check my clients' sites", "escanea los repositorios", "qué proyectos usan Node viejo". Produces a color HTML report and CSV.
---

# Fleet Scan (repos, configs and sites; read-only)

Follow **nvr-navigator** rules. Confirm authorization for every repo and domain.

## 1. Repos and deploy configs (the main evidence)

```bash
bash "$NVR/scripts/scan.sh" --project ~/code -o reports/repos-$(date +%Y%m%d)
```
Point `--project` at a folder of many repos or one repo; repeat the flag for several.
It skips `node_modules`, build output and `.git`.

What it reads and how to act:

| Source | Typical finding | Action |
|---|---|---|
| `.nvmrc`, `.node-version`, `.tool-versions` | exact pin below fixed | bump the pin to the fixed release |
| `package.json` engines / volta | `>=18` (CHECK) or exact pin | raise the minimum to a supported line; `volta pin node@<fixed>` |
| Dockerfile / compose `node:<tag>` | `22-alpine` FLOATING, `20.x` EOL, exact old tag VULNERABLE | pin `node:<fixed>-<variant>`, rebuild with `--pull` |
| GitHub Actions `node-version` | matrix with 18/20 (EOL) | drop EOL entries; add `check-latest: true` |
| Netlify `NODE_VERSION`, Lambda/Terraform `nodejsNN.x` | EOL runtime or MANAGED | migrate runtime; redeploy |
| Lockfiles (`package-lock`, `pnpm-lock`, `yarn.lock`, `bun.lock`): body-parser | 2.x EXPOSED (Express 5 decodes Brotli bodies), below 2.4.0 / 1.20.9 VULNERABLE (crash, CVE-2026-111181) | `npm update body-parser`; patch Node where it runs |
| `package.json` express ^5 / body-parser ^2 with no lockfile | EXPOSED, version unknown | add a lockfile; `npm ls body-parser` |
| Bun: `packageManager: bun@`, `.bun-version`, `oven/bun:` images, CI `bun-version` | below 1.4.4 VULNERABLE, `latest`/`1` FLOATING | pin `1.4.4` or newer, rebuild with `--pull` |

## 2. Websites (find which sites run Node)

```bash
bash "$NVR/scripts/scan.sh" -f sites.txt -o reports/sites-$(date +%Y%m%d)
```
Expect mostly **HIDDEN**: Express, Next.js, Nuxt, SvelteKit or Astro detected, version
not exposed. Use it as a map: every HIDDEN site points to a server (nvr-server-audit)
or a repo/platform setting (step 1, nvr-patch platform playbooks). Static exports
(no server code) run no Node at request time.

## 3. Rank (show as a table)

| Priority | Rule |
|---|---|
| P1 | EOL or VULNERABLE in a production, internet-facing app (APIs, SSR sites, auth, payments), and EXPOSED Express 5 APIs on an unpatched Node |
| P2 | Other EOL/VULNERABLE, and STALE processes |
| P3 | FLOATING production images/configs not rebuilt since the release |
| P4 | CHECK (ranges, distro builds) and HIDDEN sites without a mapped repo/server |
| P5 | CI-only and dev-machine findings |

## 4. Hand off

Servers -> nvr-server-audit. Platforms -> nvr-patch. Colleagues/clients ->
nvr-client-comms (attach the HTML report). Also suggest `npm audit` in each repo:
apps that depend on `undici` directly from npm need that package updated separately.
