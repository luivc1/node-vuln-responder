#!/usr/bin/env bash
# =====================================================================
#  patch-plan.sh  -  print a step-by-step Node.js patch plan for THIS
#  machine. DRY RUN ONLY: it never executes the commands it prints. The
#  agent (or you) runs them one at a time, with human approval.
#
#  Usage:
#    patch-plan.sh                      # detect, then plan
#    patch-plan.sh --stack stack.txt    # reuse saved detect-stack output
#    patch-plan.sh --advisory file.env
#
#  Methods: nvm fnm volta asdf mise n nodenv brew nodesource distro
#           cpanel cloudlinux plesk manual (+ docker, pm2, systemd restarts)
#  Platforms without a shell (Vercel, Netlify, Lambda, Heroku, CI) are in
#  skills/nvr-patch/references/playbooks.md.
# =====================================================================

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
ADV=""; STACKF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --advisory) ADV="$2"; shift 2;;
    --stack)    STACKF="$2"; shift 2;;
    -h|--help)  sed -n '2,/^# ====/p' "$0" | sed 's/^#//'; exit 0;;
    *) echo "Unknown option: $1"; exit 3;;
  esac
done
load_advisory "$ADV"
if [ -n "$STACKF" ]; then STACK=$(cat "$STACKF"); else STACK=$(bash "$HERE/detect-stack.sh" ${ADV:+--advisory "$ADV"}); fi
get() { echo "$STACK" | grep "^$1=" | head -1 | cut -d= -f2-; }
field() { echo "$1" | grep -oE "$2=(\"[^\"]*\"|[^ ]+)" | head -1 | cut -d= -f2- | tr -d '"'; }
CVE_RE=$(echo $BACKPORT_KEY_CVES | sed 's/ /|/g')
RUM=$RECOMMENDED_UPGRADE_MAJOR; RUFX=$(fixed_for_major "$RUM")

step() { printf '\n%s%s%s\n' "$BD$C" "$1" "$N"; }
cmd()  { printf '  %s$%s %s\n' "$D" "$N" "$1"; }
say()  { printf '  %s\n' "$1"; }

printf '\n%sNode.js PATCH PLAN (dry run, nothing is executed)%s\n' "$BD" "$N"
say "Host: $(get HOSTNAME)   OS: $(get OS)   Panel: $(get PANEL)   Repo: $(get NODE_REPO)"
say "Install methods: $(get INSTALL_METHODS)   Node processes running: $(get NODE_PROCESSES)"

ACTION=$(echo "$STACK" | grep '^NODE_BIN=' | grep -E 'status=(VULNERABLE|EOL|CHECK)')
if [ -z "$ACTION" ]; then
  printf '\n%sNo Node install on this machine needs patching.%s Still run verify.sh (restarts, pm2, containers) and check repos with scan.sh --project.\n\n' "$G" "$N"
  exit 0
fi

step "STEP 0  Safety first (needs approval)"
say "- Snapshot/backup the server, or at minimum note current versions (this plan lists them)."
say "- Same-major patch upgrades (e.g. 22.23.3 -> 22.23.4) are drop-in; restarts take seconds."
say "- EOL upgrades change the major version: test on staging first (native addons need npm rebuild)."
say "- Agents: get explicit human approval before every command below."

while IFS= read -r line; do
  path=$(field "$line" path); ver=$(field "$line" version); m=$(field "$line" method); st=$(field "$line" status)
  maj=${ver%%.*}; FX=$(fixed_for_major "$maj")
  if [ -z "$FX" ]; then T=$RUFX; TM=$RUM; kind="EOL: move to Node $RUM (no fix exists for $maj)"; else T=$FX; TM=$maj; kind="patch to $FX"; fi
  step "Node $ver  [$st]  via $m  ->  $kind"
  say "binary: $path"
  case "$m" in
    nvm)   cmd "source ~/.nvm/nvm.sh   # non-interactive shells need this"
           cmd "nvm install $T --reinstall-packages-from=$ver"
           cmd "nvm alias default $T"
           say "Later, after verify passes: nvm uninstall $ver";;
    fnm)   cmd "fnm install $T && fnm default $T";;
    volta) cmd "volta install node@$T"
           say "Projects pinned with Volta: run 'volta pin node@$T' in each repo and commit package.json.";;
    asdf)  cmd "asdf install nodejs $T"
           cmd "asdf set -u nodejs $T    # asdf < 0.16: asdf global nodejs $T";;
    mise)  cmd "mise use -g node@$T";;
    n)     cmd "sudo n $T";;
    nodenv) cmd "nodenv install $T && nodenv global $T";;
    brew)  cmd "brew update && brew upgrade node@$TM 2>/dev/null || brew upgrade node";;
    nodesource)
           if [ -z "$FX" ]; then
             say "NodeSource repo is set to EOL Node $maj. Switch the repo to $RUM.x (see playbooks.md), then:"
           fi
           if [ "$(get PKG_MANAGER)" = apt-get ]; then
             cmd "sudo apt-get update && apt-cache policy nodejs"
             cmd "sudo apt-get install --only-upgrade nodejs"
           else
             cmd "sudo dnf upgrade nodejs    # yum on older systems"
           fi;;
    distro)
           if [ -z "$FX" ]; then
             say "The OS ships EOL Node $maj. Distro backports are possible but not guaranteed:"
           fi
           if [ "$(get PKG_MANAGER)" = apt-get ]; then
             cmd "sudo apt-get update && apt-get changelog nodejs 2>/dev/null | grep -m5 -E '$CVE_RE'"
             cmd "sudo apt-get install --only-upgrade nodejs"
           else
             cmd "sudo dnf check-update nodejs && sudo dnf upgrade nodejs"
           fi
           say "If no fixed build is offered, move this app to NodeSource or a version manager on Node $TM ($T).";;
    cpanel) cmd "sudo dnf upgrade 'ea-nodejs*'    # yum on CentOS 7"
           say "Then restart each app in cPanel > Application Manager (Passenger).";;
    cloudlinux) cmd "sudo yum upgrade 'alt-nodejs*'"
           say "Then restart apps in cPanel > Setup Node.js App (CloudLinux Node.js Selector).";;
    plesk) cmd "sudo plesk installer update"
           say "Then restart each app in Plesk > Websites & Domains > Node.js.";;
    *)     say "Manual/tarball install. Download $T from https://nodejs.org/dist/v$T/ and verify it against SHASUMS256.txt (GPG-signed) before replacing $path.";;
  esac
done <<< "$ACTION"

step "RESTART everything that runs Node (or it keeps the old, vulnerable runtime)"
if echo "$STACK" | grep -q '^PROCESS_MANAGER=pm2'; then
  cmd "pm2 update     # restarts the PM2 daemon itself on the new Node, then reloads apps"
  cmd "pm2 save"
fi
echo "$STACK" | grep '^SYSTEMD_NODE_UNIT=' | cut -d= -f2 | while IFS= read -r u; do cmd "sudo systemctl restart $u"; done
echo "$STACK" | grep '^DOCKER_NODE_CONTAINER=' | cut -d= -f2- | while IFS= read -r c; do
  say "container $c: pin FROM node:<fixed tag for its line: $(echo $FIXED_VERSIONS | sed 's/ /, /g')>, then:"
  cmd "docker compose build --pull && docker compose up -d"
done
echo "$STACK" | grep -q '^PROCESS_MANAGER=forever' && say "forever/nodemon: stop and start each app manually."
echo "$STACK" | grep -q '^PASSENGER_CONFIG=' && say "Passenger apps: restart in the panel, or: touch <app>/tmp/restart.txt"

step "STEP 4  Verify"
cmd "bash $(basename "$HERE")/verify.sh"
say "verify.sh re-scans, flags STALE processes still on the replaced binary, and checks pm2 and containers."
step "STEP 5  Repos and deploy configs"
cmd "bash $(basename "$HERE")/scan.sh --project <code dir>"
say "FLOATING configs (node:22-alpine, lts/*) only pick up the fix on the next build: rebuild with --pull and redeploy."
step "STEP 6  Compromise check (internet-facing apps)"
cmd "bash $(basename "$HERE")/ioc-hunt.sh --since $IOC_SINCE"
echo
