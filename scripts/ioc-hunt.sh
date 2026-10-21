#!/usr/bin/env bash
# =====================================================================
#  ioc-hunt.sh  -  compromise triage for hosts running internet-facing
#  Node.js apps.
#
#  READ-ONLY. It lists, reads and greps. It never deletes, quarantines,
#  edits, or runs app code. Every finding is a LEAD to review, not proof:
#  deploys and npm installs also change files.
#  Run with sudo for full coverage (other users' crontabs, pm2 homes).
#
#  Usage:
#    ioc-hunt.sh                              # auto-detect app roots
#    ioc-hunt.sh --root /srv/api --root /var/www/web --since 2026-10-07
#    ioc-hunt.sh --deep                       # pattern-scan all app JS
#    ioc-hunt.sh -o report.txt --max 40
#
#  Exit codes: 0 no leads, 1 leads found (review them), 3 usage error
# =====================================================================

. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

ADV=""; SINCE=""; ROOTS=(); DEEP=0; MAX=25; OUTF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --advisory) ADV="$2"; shift 2;;
    --since)    SINCE="$2"; shift 2;;
    --root)     ROOTS+=("$2"); shift 2;;
    --deep)     DEEP=1; shift;;
    --max)      MAX="$2"; shift 2;;
    -o|--out)   OUTF="$2"; shift 2;;
    -h|--help)  sed -n '2,/^# ====/p' "$0" | sed 's/^#//'; exit 0;;
    *) echo "Unknown option: $1"; exit 3;;
  esac
done
load_advisory "$ADV"
SINCE="${SINCE:-$IOC_SINCE}"
HOST=$(hostname 2>/dev/null || uname -n)
OUTF="${OUTF:-ioc-report-$HOST-$(date +%Y%m%d-%H%M).txt}"
LEADS=0

if [ ${#ROOTS[@]} -eq 0 ]; then
  while IFS= read -r p; do ROOTS+=("$(dirname "$p")"); done < <(
    for d in /var/www /srv /opt/apps /opt /home/*/apps /home/*/app /home/*/nodeapps /home/*/public_html /app /usr/src/app; do
      [ -d "$d" ] && find "$d" -maxdepth 3 -name package.json -not -path '*/node_modules/*' 2>/dev/null
    done | sort -u | head -40)
fi

exec > >(tee "$OUTF") 2>&1

section() { printf '\n%s== %s ==%s\n' "$BD$C" "$1" "$N"; }
show() {
  local n; n=$(grep -c . "$1" 2>/dev/null); n=${n:-0}
  if [ "$n" -gt 0 ]; then
    LEADS=$((LEADS+n))
    printf '%s%d lead(s)%s %s\n' "$Y$BD" "$n" "$N" "$2"
    head -n "$MAX" "$1" | sed 's/^/   /'
    [ "$n" -gt "$MAX" ] && printf '   %s... %d more (raise --max)%s\n' "$D" "$((n-MAX))" "$N"
  else
    printf '%sclean%s  %s\n' "$G" "$N" "$2"
  fi
}

printf '%sNode.js compromise triage%s  host=%s  since=%s  advisory=%s\n' "$BD" "$N" "$HOST" "$SINCE" "$ADVISORY_ID"
printf 'App roots: %s\n' "${ROOTS[*]:-none found (use --root)}"
[ "$(id -u)" != 0 ] && printf '%sNot running as root: some areas may be unreadable.%s\n' "$Y" "$N"

JSX='\( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" -o -name "*.json" -o -name ".npmrc" -o -name ".env*" \)'

# 1. App source changed since the date (outside node_modules) -------------
section "1. App files (JS/TS/JSON/.npmrc/.env) modified since $SINCE, outside node_modules"
: > "$TMP/recent"
for r in "${ROOTS[@]}"; do
  eval "find \"\$r\" -xdev \( -name node_modules -o -name .git -o -name .next -o -name .nuxt -o -name .cache -o -name dist -o -name build -o -name coverage \) -prune -o -type f $JSX -newermt \"\$SINCE\" -print 2>/dev/null" >> "$TMP/recent"
done
show "$TMP/recent" "expected after deploys; review anything nobody shipped"

# 2. node_modules files newer than the lockfile -----------------------------
section "2. Dependency files changed after the lockfile (tampered packages)"
: > "$TMP/nm"
for r in "${ROOTS[@]}"; do
  lock=""; for l in package-lock.json yarn.lock pnpm-lock.yaml npm-shrinkwrap.json bun.lockb; do [ -f "$r/$l" ] && { lock="$r/$l"; break; }; done
  [ -d "$r/node_modules" ] && [ -n "$lock" ] || continue
  find "$r/node_modules" -xdev -type f \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' -o -name '*.node' \) -newer "$lock" -newermt "$SINCE" 2>/dev/null \
    | grep -vE '/node_modules/\.(cache|vite|pnpm/\.)' | head -500 >> "$TMP/nm"
done
show "$TMP/nm" "a clean 'npm ci' leaves dependencies no newer than the lockfile; edits afterwards are suspicious"

# 3. Backdoor-style code patterns --------------------------------------------
section "3. Backdoor-style code patterns (request input fed into exec/eval)"
PAT='(exec|execSync|spawn|spawnSync|execFile|execFileSync)\([[:space:]]*(`[^`]{0,40}\$\{)?req\.(query|body|params|headers)|eval\([[:space:]]*(req\.|Buffer\.from\([^)]{0,200}base64|atob\()|new[[:space:]]+Function\([^)]{0,80}req\.|vm\.run(InNewContext|InThisContext)\([^)]{0,40}req\.|Buffer\.from\(["'"'"'][A-Za-z0-9+/=]{60,}["'"'"'][[:space:]]*,[[:space:]]*["'"'"']base64'
: > "$TMP/pat"
if [ "$DEEP" -eq 1 ]; then
  for r in "${ROOTS[@]}"; do
    grep -rlE --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' "$PAT" "$r" 2>/dev/null >> "$TMP/pat"
  done
  scope="all JS/TS including node_modules (--deep)"
else
  sort -u "$TMP/recent" "$TMP/nm" | grep -E '\.(c|m)?(j|t)s$' | while IFS= read -r f; do grep -lE "$PAT" "$f" 2>/dev/null; done >> "$TMP/pat"
  scope="files from sections 1-2 (use --deep for everything)"
fi
show "$TMP/pat" "scope: $scope"

# 4. Persistence --------------------------------------------------------------
section "4. Persistence changed since $SINCE (cron, systemd, SSH keys, pm2, shell profiles, npm globals)"
: > "$TMP/persist"
find /etc/cron* /var/spool/cron /etc/systemd/system -type f -newermt "$SINCE" 2>/dev/null >> "$TMP/persist"
for h in /root /home/* /Users/*; do
  [ -d "$h" ] || continue
  find "$h/.ssh" -name 'authorized_keys*' -newermt "$SINCE" 2>/dev/null >> "$TMP/persist"
  find "$h" -maxdepth 1 \( -name .bashrc -o -name .profile -o -name .bash_profile -o -name .zshrc -o -name .npmrc \) -newermt "$SINCE" 2>/dev/null >> "$TMP/persist"
  find "$h/.pm2" -maxdepth 1 -name 'dump.pm2' -newermt "$SINCE" 2>/dev/null | sed 's/$/  (pm2 saved process list changed: compare with pm2 list)/' >> "$TMP/persist"
done
for g in /usr/lib/node_modules /usr/local/lib/node_modules; do
  [ -d "$g" ] && find "$g" -mindepth 1 -maxdepth 2 -type d -newermt "$SINCE" -not -name '.*' 2>/dev/null | sed 's/$/  (global npm package installed or changed)/' >> "$TMP/persist"
done
show "$TMP/persist" "ask the owner about each one; unknown entries are confirmed findings"

# 5. Shells or tools spawned by Node processes ------------------------------
section "5. Shells, downloaders or miners whose parent is a Node process"
: > "$TMP/proc"
if ps -eo pid=,ppid=,args= >/dev/null 2>&1; then
  ps -eo pid=,ppid=,args= 2>/dev/null > "$TMP/ps"
  awk '{print $1, $3}' "$TMP/ps" | awk '$2 ~ /(^|\/)(node|nodejs)$/ {print $1}' > "$TMP/nodepids"
  while read -r pid ppid args; do
    grep -qx "$ppid" "$TMP/nodepids" || continue
    echo "$args" | grep -qE '(^|[ /])(sh|bash|dash|nc|ncat|socat|curl|wget|perl|python[0-9.]*|base64|xmrig|kdevtmpfsi)( |$)' \
      && echo "pid $pid (parent node $ppid): $(echo "$args" | cut -c1-140)" >> "$TMP/proc"
  done < "$TMP/ps"
fi
show "$TMP/proc" "build tools may spawn shells legitimately; a web app spawning curl/sh/nc usually is not"

# 6. Outbound connections from Node ----------------------------------------
section "6. Established connections owned by node"
: > "$TMP/net"
command -v ss >/dev/null 2>&1 && ss -tnpH state established 2>/dev/null | grep -E '"node(js)?"' >> "$TMP/net"
show "$TMP/net" "DB, cache and API calls are normal; unknown hosts on odd ports are not"

# 7. Temp dirs --------------------------------------------------------------
section "7. New executables or scripts in temp dirs since $SINCE"
: > "$TMP/tmpd"
find /tmp /var/tmp /dev/shm -xdev -type f \( -perm -u+x -o -name '*.js' -o -name '*.sh' -o -name '*.so' \) -newermt "$SINCE" 2>/dev/null \
  | grep -vF "$TMP" | grep -vE '/(node-compile-cache|v8-compile-cache|jiti|npm-|yarn-|pnpm-|tsx-)' | while IFS= read -r f; do
      inroot=0; for r in "${ROOTS[@]}"; do case "$f" in "$r"/*) inroot=1;; esac; done
      [ "$inroot" -eq 0 ] && echo "$f"
    done >> "$TMP/tmpd"
show "$TMP/tmpd" "droppers often stage in /tmp or /dev/shm"

# 8. Secrets exposure reminder ------------------------------------------------
section "8. Secrets a compromised Node process could read"
: > "$TMP/env"
for r in "${ROOTS[@]}"; do find "$r" -maxdepth 2 -name '.env*' -type f 2>/dev/null; done | sed 's/$/  (rotate its secrets IF compromise is confirmed; contents not shown)/' >> "$TMP/env"
n=$(grep -c . "$TMP/env"); printf '%s%d .env file(s) found%s (informational, not counted as leads)\n' "$D" "${n:-0}" "$N"; head -n "$MAX" "$TMP/env" | sed 's/^/   /'

printf '\n%s== Summary ==%s\n' "$BD" "$N"
if [ "$LEADS" -gt 0 ]; then
  printf '%s%d lead(s) to review.%s Do not delete anything yet: copy suspicious files and logs aside first (evidence), then follow the nvr-compromise-check skill.\n' "$Y$BD" "$LEADS" "$N"
else
  printf '%sNo leads found in the areas checked.%s That lowers, but does not rule out, the chance of compromise.\n' "$G$BD" "$N"
fi
printf 'Report saved: %s\n\n' "$OUTF"
[ "$LEADS" -gt 0 ] && exit 1 || exit 0
