# Cleanup and credential rotation (every step needs approval)

Only after evidence is copied aside and Node is patched.

## Remove footholds

| Foothold | Action |
|---|---|
| Modified app code | Redeploy from a known-good git commit; do not hand-edit in place |
| Tampered node_modules | `rm -rf node_modules && npm ci` from the committed lockfile (review lockfile changes first) |
| Unknown PM2 processes | Record `pm2 list` and `pm2 describe <id>`, then `pm2 delete <id>` and `pm2 save` |
| Unknown cron / systemd units / SSH keys | Copy to evidence, then remove |
| Modified shell profiles / `.npmrc` | Restore from backup; check for malicious registry or token settings in `.npmrc` |
| Unknown global npm packages | Record, then `npm uninstall -g <pkg>` |
| Running shells/miners | Record `ps` and `/proc/<pid>/exe`, then `kill` |

Rebuilding the host or container from a known-good image is often faster and safer
when footholds are many.

## Rotate secrets (the Node process could read all of these)

- Everything in `.env` files and the process environment: DB URLs, JWT/session secrets
  (forces re-login), API keys (Stripe, email, storage, CRM, AI providers)
- npm tokens in `.npmrc` (revoke at npmjs.com), Git deploy keys, CI tokens
- Cloud credentials on the host (`~/.aws`, service-account keys, instance roles: review
  their activity logs)
- SSH keys and panel passwords if the app user could reach them

## Afterwards

Re-run `ioc-hunt.sh --deep` and `verify.sh`; watch logs for 7 days for reinfection.
