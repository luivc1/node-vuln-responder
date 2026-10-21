---
name: nvr-advisory-update
description: Create or refresh the advisory file that drives every nvr-* script (fixed versions, CVEs, key CVEs for backport checks, LTS codenames, recommended upgrade line) from official Node.js sources. Use when Node publishes a new security release, when the advisory is older than 7 days, or for "new Node security release", "update the advisory", "nueva versión de seguridad de Node".
---

# Advisory Update

A wrong fixed version makes every scan wrong, so every value must come from a source
read in this session.

## Sources, in priority order

1. nodejs.org security release post (`/en/blog/vulnerability/...`) and release notes
2. nodejs.org release schedule (supported and EOL lines, LTS codenames)
3. Distro trackers for backports (Ubuntu USN, Debian tracker, Red Hat), NodeSource
4. Platform bulletins (AWS Lambda, Vercel, Netlify) for managed runtimes
5. Security press only for context, never as the sole source of a version

## Steps

1. Copy `advisories/nodejs-2026-10.env` to `advisories/nodejs-YYYY-MM.env` and fill:

| Key | Rule |
|---|---|
| `FIXED_VERSIONS` | the fixed release for every supported major, from the release post |
| `CVES` / `BACKPORT_KEY_CVES` | all CVEs / the highest-severity ones affecting every line |
| `LTS_CODENAMES` | only codenames nodejs.org has announced |
| `RECOMMENDED_UPGRADE_MAJOR` | the LTS line with the longest support left |
| `IOC_SINCE` | earliest known exploitation/disclosure date; otherwise release date minus 14 days |
| `MITIGATION_NOTE` | only what Node.js states |
| `SOURCES`, `LAST_VERIFIED` | URLs used; today's date |

2. Validate:
   ```bash
   bash -c '. scripts/lib.sh; load_advisory advisories/nodejs-YYYY-MM.env; \
     for v in <one-below-fixed> <fixed> 20.0.0; do classify_ver "$v"; echo "$v $STATUS"; done'
   ```
   Expect VULNERABLE, PATCHED, EOL.
3. Show the user the diff and sources; pass `--advisory` to every script. Keep old
   advisory files (logs reference them).

Never guess a fixed version from a distro package number or a news article.
