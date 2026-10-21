#!/usr/bin/env bash
# =====================================================================
#  detect-stack.sh  -  fingerprint a machine so the agent picks the right
#  Node patch playbook(s). READ-ONLY: lists files, processes and versions.
#
#  Usage:  detect-stack.sh [--advisory file]
#  Output: KEY=value lines (for agents and patch-plan.sh)
# =====================================================================

. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
ADV=""; [ "$1" = "--advisory" ] && ADV="$2"
load_advisory "$ADV"

kv()  { printf '%s=%s\n' "$1" "$2"; }
has() { command -v "$1" >/dev/null 2>&1; }

echo "# detect-stack $(date -u '+%Y-%m-%dT%H:%M:%SZ') advisory=$ADVISORY_ID"

# ---- OS / platform ----------------------------------------------------
if [ -r /etc/os-release ]; then ( . /etc/os-release; kv OS "${PRETTY_NAME:-$ID}"; kv OS_ID "${ID:-unknown}" )
elif [ "$(uname -s)" = Darwin ]; then kv OS "macOS $(sw_vers -productVersion 2>/dev/null)"; kv OS_ID macos
else kv OS "$(uname -s)"; kv OS_ID "$(uname -s | tr 'A-Z' 'a-z')"; fi
kv HOSTNAME "$(hostname 2>/dev/null || uname -n)"
kv IS_ROOT "$([ "$(id -u)" = 0 ] && echo yes || echo no)"
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then kv CONTAINER yes; else kv CONTAINER no; fi
PM=none; for p in apt-get dnf yum apk zypper brew; do has "$p" && { PM=$p; break; }; done
kv PKG_MANAGER "$PM"

PANEL=none
[ -f /usr/local/cpanel/version ] && PANEL="cpanel"
[ -f /usr/local/psa/version ]    && PANEL="plesk"
[ -d /usr/local/directadmin ]    && PANEL="directadmin"
{ [ -f /etc/cloudlinux-release ] || uname -r | grep -q lve; } && PANEL="$PANEL+cloudlinux"
kv PANEL "$PANEL"

REPO=none
if [ -d /etc/apt ] && grep -rqs 'nodesource' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then REPO=nodesource-apt; fi
if [ -d /etc/yum.repos.d ] && ls /etc/yum.repos.d 2>/dev/null | grep -qi nodesource; then REPO=nodesource-rpm; fi
kv NODE_REPO "$REPO"

# ---- every Node binary, with its install method -------------------------
METHODS=""
bins=$(discover_node_bins)
if [ -n "$bins" ]; then
  while IFS= read -r b; do
    v=$("$b" -v </dev/null 2>/dev/null | head -1); v=${v#v}
    pk=$(pkg_of "$b")
    m=$(node_install_method "$b" "$pk")
    classify_ver "${v:-?}${pk:+ [pkg $pk]}"
    if [ "$STATUS" = CHECK ] && [ -n "$pk" ] && pkg_has_backport "${pk%% *}"; then STATUS=PATCHED; fi
    kv NODE_BIN "path=$b version=${v:-?} method=$m package=\"${pk:-none}\" status=$STATUS"
    METHODS="$METHODS $m"
  done <<< "$bins"
else
  kv NODE_BIN "none-found"
fi
kv INSTALL_METHODS "$(echo $METHODS | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')"

# ---- what runs Node apps (these must be restarted after upgrading) ------
PS=$(ps -eo pid=,args= 2>/dev/null)
kv NODE_PROCESSES "$(echo "$PS" | awk '{print $2}' | grep -cE '(^|/)(node|nodejs)$')"

if has pm2 || ls -d /root/.pm2 /home/*/.pm2 "$HOME/.pm2" >/dev/null 2>&1; then
  kv PROCESS_MANAGER "pm2 (after upgrading run: pm2 update, then pm2 save)"
fi
echo "$PS" | grep -qE '[f]orever|[n]odemon' && kv PROCESS_MANAGER "forever/nodemon (restart manually)"
if [ -d /etc/systemd/system ]; then
  grep -lsE '^ExecStart=.*(node|npm|yarn|pnpm|next|nuxt)( |$)' /etc/systemd/system/*.service /lib/systemd/system/*.service 2>/dev/null \
    | while IFS= read -r u; do kv SYSTEMD_NODE_UNIT "$(basename "$u")"; done
fi
grep -lsE 'PassengerNodejs|passenger_nodejs' /etc/apache2/conf.d/* /etc/httpd/conf.d/* /etc/nginx/conf.d/* 2>/dev/null | head -3 \
  | while IFS= read -r c; do kv PASSENGER_CONFIG "$c (cPanel Application Manager / Passenger apps)"; done
if has docker; then
  docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -iE '(^|[ /])node(:|$)|node[-_:]' \
    | while read -r n i; do kv DOCKER_NODE_CONTAINER "name=$n image=$i"; done
fi

# ---- app roots (for ioc-hunt) -----------------------------------------
for d in /var/www /srv /opt/apps /home/*/apps /home/*/app /home/*/nodeapps /home/*/public_html; do
  [ -d "$d" ] && find "$d" -maxdepth 3 -name package.json -not -path '*/node_modules/*' 2>/dev/null | head -20 | while IFS= read -r p; do kv APP_ROOT "$(dirname "$p")"; done
done

# ---- recommended playbooks ----------------------------------------------
PB=""
if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then PB="docker"; fi
for m in $(echo $METHODS | tr ' ' '\n' | sort -u); do PB="$PB $m"; done
[ -z "$PB" ] && PB="unknown-or-managed"
kv PLAYBOOKS "$(echo $PB)"
echo "# next: patch-plan.sh prints the commands for these playbooks (it does not run them)"
