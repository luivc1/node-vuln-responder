# End-of-life Node migration (no fix exists for the old major)

Node 20 and older, plus odd lines (21, 23, 25), get no fix. Move apps to the
advisory's `RECOMMENDED_UPGRADE_MAJOR` (24 at the time of writing) or another
supported line.

## Today: contain

1. Internet-facing apps on EOL Node: restrict exposure where possible (WAF, IP
   allowlists for admin/internal apps, take non-essential services offline).
2. Commercial extended support (HeroDevs, TuxCare and similar) counts only if the
   vendor publicly confirms builds fixing these CVEs.

## This week: migrate

1. **Inventory**: framework and version (Next.js, Nest, Express...), native addons
   (`bcrypt`, `sharp`, `sqlite3`, `canvas`...), engines fields, CI images, Dockerfiles.
2. **Check framework support** for the target major (framework release notes).
3. **Branch + staging**: bump `.nvmrc`, `engines`, Dockerfile `FROM`, CI matrices.
4. **Reinstall cleanly**: `rm -rf node_modules && npm ci` (native addons rebuild for the
   new ABI; `npm rebuild` if you keep node_modules).
5. **Test**: unit/e2e tests, startup, auth flows, file uploads, scheduled jobs, logs clean.
6. **Deploy**, restart every runner (PM2 `pm2 update`), keep the old image/runtime
   available for quick rollback for 48 hours.
7. **Re-run** `scan.sh --project` and `verify.sh`.

## Talking to clients and colleagues

Use `eol-upgrade-proposal` in nvr-client-comms: factual risk, no patch coming, plan,
estimate, rollback.
