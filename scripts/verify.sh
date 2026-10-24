#!/usr/bin/env bash
# =====================================================================
#  verify.sh  -  prove the Node.js patch actually took effect. READ-ONLY.
#
#  1. Re-scans every Node binary on this machine, including STALE
#     processes still running a binary that was replaced on disk.
#  2. Asks PM2 which Node version each managed app is really running.
#  3. Runs `node -v` inside running Node containers (docker exec, read-only).
#  4. Optionally fingerprints public sites (--url).
#
#  Usage:  verify.sh [--url https://site ...] [--advisory file]
#  Exit:   0 PASS, 1 CONFIRM/FAIL (needs attention)
# =====================================================================

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
ADV=""; URLS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --advisory) ADV="$2"; shift 2;;
    --url)      URLS+=("$2"); shift 2;;
    -h|--help)  sed -n '2,/^# ====/p' "$0" | sed 's/^#//'; exit 0;;
    *) URLS+=("$1"); shift;;
  esac
done
load_advisory "$ADV"
FAIL=0; WARN=0
line() { # label version status note
  local col; case "$3" in PATCHED) col=$G;; VULNERABLE|EOL|STALE) col=$R; FAIL=1;; *) col=$Y; WARN=1;; esac
  local lbl="Node ${2:--}"; case "$2" in Bun*) lbl=$2;; esac
  printf '  %s%-10s%s %s  (%s)  %s%s%s\n' "$col$BD" "$3" "$N" "$1" "$lbl" "$D" "$4" "$N"
}

printf '\n%sNode.js VERIFY%s  %s(%s)%s\n' "$BD$C" "$N" "$D" "$ADVISORY_NAME" "$N"

printf '\n%s1. Node and Bun binaries, system Brotli library, running processes on this machine%s\n' "$BD" "$N"
bash "$HERE/scan.sh" --local ${ADV:+--advisory "$ADV"} -o "$TMP/local" | sed -n '/^[A-Z-]\{3,\} /,/^Summary/p' | grep -v '^Summary' | sed 's/^/  /'
rc=${PIPESTATUS[0]}
[ "$rc" -ge 2 ] && FAIL=1; [ "$rc" -eq 1 ] && WARN=1

printf '\n%s2. PM2-managed apps%s\n' "$BD" "$N"
if command -v pm2 >/dev/null 2>&1; then
  name=""; found=0
  while IFS= read -r tok; do
    case "$tok" in
      \"name\"*) name=$(echo "$tok" | cut -d'"' -f4);;
      \"node_version\"*) v=$(echo "$tok" | cut -d'"' -f4); classify_ver "$v"; line "pm2:$name" "$v" "$STATUS" ""; found=1;;
    esac
  done < <(pm2 jlist 2>/dev/null | grep -oE '"name":"[^"]*"|"node_version":"[^"]*"')
  [ "$found" -eq 0 ] && printf '  %sno PM2 apps for this user (run as the user that owns them)%s\n' "$D" "$N"
  printf '  %sIf any app shows an old version: pm2 update (restarts the PM2 daemon on the new Node), then pm2 save.%s\n' "$D" "$N"
else
  printf '  %snot installed%s\n' "$D" "$N"
fi

printf '\n%s3. Running Node containers%s\n' "$BD" "$N"
if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
  found=0
  while read -r cname img; do
    v=$(docker exec "$cname" node -v 2>/dev/null | head -1); v=${v#v}
    if [ -z "$v" ] && [ -n "$BUN_FIXED" ]; then
      v=$(docker exec "$cname" bun --version 2>/dev/null | head -1)
      [ -z "$v" ] && continue
      found=1; classify_bun "$v"; line "container:$cname ($img)" "Bun $v" "$STATUS" "$( [ "$STATUS" = PATCHED ] || echo 'rebuild with --pull and redeploy')"
      continue
    fi
    [ -z "$v" ] && continue
    found=1; classify_ver "$v"; line "container:$cname ($img)" "$v" "$STATUS" "$( [ "$STATUS" = PATCHED ] || echo 'rebuild with --pull and redeploy')"
  done < <(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null)
  [ "$found" -eq 0 ] && printf '  %sno running containers with Node%s\n' "$D" "$N"
else
  printf '  %sdocker not available or not permitted%s\n' "$D" "$N"
fi

if [ ${#URLS[@]} -gt 0 ]; then
  printf '\n%s4. Public view of the site(s)%s\n' "$BD" "$N"
  bash "$HERE/scan.sh" ${ADV:+--advisory "$ADV"} -o "$TMP/remote" "${URLS[@]}" | sed -n '/^[A-Z-]\{3,\} /,/^Summary/p' | grep -v '^Summary' | sed 's/^/  /'
  rc=${PIPESTATUS[0]}; [ "$rc" -ge 2 ] && FAIL=1
  printf '  %s(HIDDEN is normal for Node sites; the checks above are the real proof.)%s\n' "$D" "$N"
fi

printf '\n'
if [ "$FAIL" -eq 1 ]; then
  printf '%sFAIL%s  Something is still vulnerable, end-of-life, or running the old binary (see above).\n\n' "$R$BD" "$N"; exit 1
elif [ "$WARN" -eq 1 ]; then
  printf '%sCONFIRM%s  Nothing confirmed vulnerable, but some items need a manual check (distro builds, floating configs, hidden versions).\n\n' "$Y$BD" "$N"; exit 1
else
  printf '%sPASS%s  No vulnerable Node or Bun binaries, system Brotli library, apps or containers found.\n\n' "$G$BD" "$N"; exit 0
fi
