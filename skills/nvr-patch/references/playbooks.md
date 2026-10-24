# Node.js patch playbooks

`<B>` = major (22), `<FX>` = fixed release for that major from the advisory
(22.23.4 / 24.22.1 / 26.12.1). Every command that changes something needs approval.
Confirm names on the host first; vendors change paths and menus over time.

## Servers and workstations

| Method | Upgrade | Switch default | Rollback |
|---|---|---|---|
| nvm | `nvm install <FX> --reinstall-packages-from=<old>` | `nvm alias default <FX>` | `nvm alias default <old>` |
| fnm | `fnm install <FX>` | `fnm default <FX>` | `fnm default <old>` |
| Volta | `volta install node@<FX>` | per repo: `volta pin node@<FX>` | `volta install node@<old>` |
| asdf | `asdf install nodejs <FX>` | `asdf set -u nodejs <FX>` (older: `asdf global nodejs <FX>`) | set back to `<old>` |
| mise | `mise use -g node@<FX>` | (same) | `mise use -g node@<old>` |
| n | `sudo n <FX>` | (same) | `sudo n <old>` |
| Homebrew | `brew update && brew upgrade node@<B>` (or `node`) | `brew link --overwrite node@<B>` if needed | `brew install node@<B>` pinned older is not supported: use a version manager |
| NodeSource (apt) | `sudo apt-get update && sudo apt-get install --only-upgrade nodejs` | n/a | `sudo apt-get install nodejs=<oldversion>` |
| NodeSource (rpm) | `sudo dnf upgrade nodejs` | n/a | `sudo dnf history undo <id>` |
| Distro package | `apt-get changelog nodejs \| grep CVE-...` then upgrade; if the OS ships an EOL major, move the app to NodeSource or a version manager | | |
| cPanel (ea-nodejs) | `sudo dnf upgrade 'ea-nodejs*'` | restart apps in **Application Manager** | `dnf history undo <id>` |
| CloudLinux selector | `sudo yum upgrade 'alt-nodejs*'` | restart apps in **Setup Node.js App** | `yum history undo <id>` |
| Plesk | `sudo plesk installer update` | restart apps in **Websites & Domains > Node.js** | snapshot |
| Tarball | download from `nodejs.org/dist/v<FX>/`, verify against signed `SHASUMS256.txt`, replace | | keep the old folder until verify passes |
| Windows | `winget upgrade OpenJS.NodeJS.LTS` (or `OpenJS.NodeJS`), nvm-windows: `nvm install <FX>` then `nvm use <FX>` | | reinstall old MSI |

Changing a NodeSource major (EOL upgrade): NodeSource's documented setup script for
the new major (e.g. `setup_24.x`) replaces the repo; read the script before running
it, then `sudo apt-get install nodejs`.

## HTTP2Shell: Brotli outside the Node binary

| Component | Update | Rollback |
|---|---|---|
| Debian/Ubuntu `libbrotli1` | `sudo apt-get update && sudo apt-get install --only-upgrade libbrotli1` (Debian 12: 1.0.9-2+deb12u1, Debian 13: 1.1.0-2+deb13u1) | `apt-get install libbrotli1=<old>` (only if something breaks) |
| RHEL/Fedora `brotli` | `sudo dnf upgrade brotli` once the vendor ships it | `dnf downgrade brotli` |
| Alpine `brotli-libs` | `apk upgrade brotli-libs`; in images, rebuild with `--pull` | previous image |
| Homebrew `brotli` | `brew upgrade brotli` (Homebrew's node links it) | `brew pin`/reinstall old bottle |
| Bun | `bun upgrade`; `brew upgrade bun`; images `FROM oven/bun:1.4.4` | previous image, or reinstall the old version |
| Express 5 | `npm update body-parser` (>= 2.4.0), commit the lockfile | revert the lockfile commit |

Restart afterwards: anything that loaded the old shared library keeps it in memory
until restarted (`sudo needrestart` on Debian/Ubuntu lists those processes).

Bridges while a fix is not available: block requests with `Content-Encoding: br` at
nginx (`if ($http_content_encoding ~* br) { return 415; }`), the load balancer or WAF;
`express.json({ inflate: false })`; run URL-fetching workers unprivileged with no
secrets in their environment and restricted outbound network.

## Restart what runs Node

| Runner | Command |
|---|---|
| PM2 | `pm2 update` (restarts the daemon on the new Node and reloads apps), then `pm2 save` |
| systemd | `sudo systemctl restart <unit>` for each unit whose ExecStart runs node/npm |
| Passenger (cPanel/Plesk) | restart in the panel, or `touch <app>/tmp/restart.txt` |
| forever / nodemon / screen / tmux | stop and start each app |
| Docker | rebuild and recreate (below) |

## Docker images

- Pin the fixed tag: `FROM node:<FX>-alpine` (or `-slim`, `-bookworm`...). Floating tags
  (`node:<B>-alpine`, `node:lts`) are acceptable only if you rebuild with `--pull`.
- `docker compose build --pull && docker compose up -d`
- Check: `docker compose exec <svc> node -v`
- Rollback: redeploy the previous image tag (keep it until verify passes).
- Multi-stage builds: the runtime stage is what matters, but patch every `FROM node`.

## CI

- GitHub Actions: `actions/setup-node` with `node-version: <FX>` or `node-version: <B>.x`
  plus `check-latest: true`; remove EOL versions from matrices.
- GitLab/Bitbucket/CircleCI: same rule for `image: node:<tag>`.
- Re-run release pipelines so shipped artifacts were built and tested on fixed Node.

## Platforms (no shell)

| Platform | What to do |
|---|---|
| Vercel | Project Settings: Node.js Version must be a supported major (or `engines.node` in package.json). Vercel manages patch releases for functions; **redeploy** so builds and functions use the patched runtime. |
| Netlify | `NODE_VERSION` env var or `.nvmrc` to a fixed/supported version, then **Clear cache and deploy site**. Check the Functions runtime version setting too. |
| AWS Lambda (zip) | Managed runtimes `nodejs22.x/24.x` get patches automatically when runtime management is **Auto**. If set to **Function update** or **Manual**, update/redeploy. Deprecated runtimes (`nodejs20.x` and older): migrate. |
| AWS Lambda (container) | Rebuild from `public.ecr.aws/lambda/nodejs:<B>` with `--pull`, push, update the function. |
| Heroku / Render / Railway / Fly | Set `engines.node` (or the platform setting) to a supported line and trigger a new build/deploy; existing dynos keep the old runtime until redeployed. |
| Google Cloud Run / Functions / App Engine | Managed runtimes are patched by Google; redeploy functions/App Engine to be sure; Cloud Run containers must be rebuilt. |
| Azure App Service / Functions | Set the Node version in configuration to a supported line; restart the app. |

Always confirm each provider's own security bulletin for these CVEs.
