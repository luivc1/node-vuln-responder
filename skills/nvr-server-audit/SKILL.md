---
name: nvr-server-audit
description: Audit a server or workstation you have shell access to for the current Node.js security release - every Node install (system, NodeSource, nvm, fnm, Volta, asdf, mise, n, Homebrew, cPanel/CloudLinux/Plesk), what actually runs apps (PM2, systemd, Docker, Passenger), stale processes and distro backports. Use for "check my server", "what Node is running", "audit this VPS", "revisa mi servidor", "qué versión de Node corre".
---

# Server Audit (inside, read-only)

Follow **nvr-navigator** rules. Read-only, so no change approvals, but confirm
authorization on the host. Run with `sudo` for all users' version managers.

## Steps

1. **Fingerprint**
   ```bash
   bash "$NVR/scripts/detect-stack.sh" | tee stack-$(hostname).txt
   ```
   Key lines: `NODE_BIN ... method= status=`, `INSTALL_METHODS`, `PROCESS_MANAGER`,
   `SYSTEMD_NODE_UNIT`, `DOCKER_NODE_CONTAINER`, `PASSENGER_CONFIG`, `APP_ROOT`.
2. **Scan binaries and processes**
   ```bash
   bash "$NVR/scripts/scan.sh" --local -o reports/local-$(hostname)
   ```
   STALE rows are processes still running a binary replaced on disk. Distro packages
   are confirmed PATCHED only if their changelog lists the key CVEs.
3. **Find what serves traffic.** Version managers often hold several Nodes; the one
   that matters is what each app runs: `pm2 jlist` (`node_version` per app), the
   `ExecStart=` of systemd units, the container image, or the panel's app setting.
   `verify.sh` reports PM2 apps and containers directly.
4. **Summarize** as a table: install, version, method, status, which apps use it.
5. **Next**: VULNERABLE/EOL/STALE -> nvr-patch. Internet-facing apps -> also
   nvr-compromise-check. Repos/Dockerfiles on this host -> `scan.sh --project <dir>`.

## Gotchas

- **PM2 runs on Node itself.** Upgrading Node does not move the PM2 daemon;
  `pm2 update` does. Apps started by an old daemon keep the old runtime.
- **nvm is per user.** Each deploy user may have its own `~/.nvm` with old versions.
- **Ubuntu/Debian `nodejs` packages** often ship an EOL major (e.g. 18). A backport is
  possible but not guaranteed; NodeSource or a version manager is the usual fix.
- **Bundled Node** inside Electron apps, SEA executables or vendor appliances needs
  the vendor's update; not covered by these scripts.
