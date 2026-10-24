#!/usr/bin/env bash
# Shared helpers for node-vuln-responder scripts. Sourced, not executed.
# bash 3.2+ and coreutils only. Nothing in here changes the system.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ADVISORY="$LIB_DIR/../advisories/nodejs-2026-10.env"

# ---------- advisory (override with --advisory file.env) --------------------
ADVISORY_ID="nodejs-2026-10"
ADVISORY_NAME="Node.js October 2026 security releases"
CVES="CVE-2026-111497 CVE-2026-105482 CVE-2026-105483 CVE-2026-106069 CVE-2026-105481 CVE-2026-106072 CVE-2026-106074 CVE-2026-106070 CVE-2026-106071 CVE-2026-106073"
# High-severity CVEs affecting every supported line: a distro changelog must
# list all of these before a backport counts as confirmed.
BACKPORT_KEY_CVES="CVE-2026-111497 CVE-2026-106069 CVE-2026-105482"
FIXED_VERSIONS="26.12.1 24.22.1 22.23.4"
RECOMMENDED_UPGRADE_MAJOR="24"
LTS_CODENAMES="hydrogen=18 iron=20 jod=22 krypton=24"
SOURCE_URL="https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
LAST_VERIFIED="2026-10-24"
# HTTP2Shell (CVE-2026-111497) outside the Node binary. Clear these in a future
# advisory that is not about Brotli.
BUN_FIXED="1.4.4"
BROTLI_CVE="CVE-2026-111497"
BROTLI_AFFECTED="1.0.3 to 1.2.0"
BROTLI_FIXED_UPSTREAM="1.0.10 1.1.1 1.2.1"
BROTLI_FIXED_DISTRO="1.0.9-2+deb12u1 1.1.0-2+deb13u1"
BODYPARSER_FIXED="2.4.0 1.20.9"
BODYPARSER_ADVISORY="CVE-2026-111181 / GHSA-27r3-jxmh-p828"

TIMEOUT="${TIMEOUT:-12}"
UA="Mozilla/5.0 (compatible; node-sec-check/1.0; passive version audit)"

if [ -t 1 ]; then
  R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; D=$'\033[2m'; BD=$'\033[1m'; N=$'\033[0m'
else
  R=; G=; Y=; C=; D=; BD=; N=
fi

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t nsc)
trap 'rm -rf "$TMP"' EXIT
ROWS=(); WORST=0
CNT_RISK=0; CNT_CHK=0; CNT_OK=0; CNT_OTH=0


# ---------- version logic -------------------------------------------------------

ver_ge() { # true if $1 >= $2 (dotted, 3 parts)
  local IFS=.
  local a=($1) b=($2) i x y
  for i in 0 1 2; do
    x=${a[$i]:-0}; y=${b[$i]:-0}
    if (( 10#$x > 10#$y )); then return 0; fi
    if (( 10#$x < 10#$y )); then return 1; fi
  done
  return 0
}
fixed_for_major() { local f; for f in $FIXED_VERSIONS; do [ "${f%%.*}" = "$1" ] && { echo "$f"; return 0; }; done; return 1; }
max_major() { local f m=0; for f in $FIXED_VERSIONS; do (( ${f%%.*} > m )) && m=${f%%.*}; done; echo "$m"; }
supported_list() { echo $FIXED_VERSIONS | tr ' ' '\n' | cut -d. -f1 | sort -n | tr '\n' ' ' | sed 's/ $//; s/ /, /g'; }
codename_major() { local p; for p in $LTS_CODENAMES; do [ "${p%%=*}" = "$1" ] && { echo "${p#*=}"; return 0; }; done; return 1; }

eol_note() { # $1 major
  echo "Node $1 is end-of-life: no fix will ship. Upgrade to a supported line ($(supported_list)) at its latest patch. Commercial extended support only counts if the vendor confirms these CVEs are fixed."
}

# classify_ver <exact version, may carry a distro suffix>  -> STATUS NOTE
classify_ver() {
  local v="${1#v}" maj min pat base suffix fixed
  if [[ ! $v =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    STATUS="CHECK"; NOTE="Could not parse version '$1'. Verify manually."; return
  fi
  maj=${BASH_REMATCH[1]}; min=${BASH_REMATCH[2]}; pat=${BASH_REMATCH[3]}
  base="$maj.$min.$pat"; suffix=${v#"${BASH_REMATCH[0]}"}; suffix=${suffix# }
  fixed=$(fixed_for_major "$maj")
  if [ -z "$fixed" ]; then
    if (( maj > $(max_major) )); then STATUS="CHECK"; NOTE="Node $maj is newer than this advisory knows. Confirm on nodejs.org."
    else STATUS="EOL"; NOTE=$(eol_note "$maj"); fi
    return
  fi
  if ver_ge "$base" "$fixed"; then
    STATUS="PATCHED"; NOTE="At or above the fixed release $fixed."
  elif [ -n "$suffix" ] && [[ $suffix != *nodesource* ]]; then
    STATUS="CHECK"; NOTE="Upstream $base is below $fixed, but this is a distro build ($suffix) that may carry a backport. Check the package changelog for $BACKPORT_KEY_CVES."
  else
    STATUS="VULNERABLE"; NOTE="Below the fixed release $fixed. Upgrade Node now."
  fi
}

# classify_spec <version spec from a config file or docker tag>
classify_spec() {
  local s op maj min pat fixed fmm cn base rest="" re
  s=$(printf '%s' "$1" | tr -d '"'"'"' \r' | tr 'A-Z' 'a-z'); s=${s#=}; s=${s#v}
  case "$s" in
    *@sha256:*) STATUS="CHECK"; NOTE="Image pinned by digest. Check which Node version it contains (docker run --rm <image> node -v)."; return;;
    ""|latest|current|node|stable|alpine*|slim*|bookworm*|bullseye*|trixie*|buster*)
      STATUS="FLOATING"; NOTE="Tracks the newest Node release: picks up $(echo $FIXED_VERSIONS | cut -d' ' -f1) only after a reinstall or rebuild (docker build --pull / redeploy)."; return;;
    lts|'lts/*'|lts-*)
      STATUS="FLOATING"; NOTE="Tracks the latest LTS: picks up the fix only after a reinstall or rebuild (docker build --pull / redeploy)."; return;;
  esac
  base=${s#lts/}; base=${base%%-*}
  if cn=$(codename_major "$base"); then s="$cn"; rest=" (LTS codename $base)"; fi

  re='^(\^|~|>=)?v?([0-9]+)(\.([0-9]+|x|\*))?(\.([0-9]+|x|\*))?(-[a-z0-9._-]+)?$'
  if [[ ! $s =~ $re ]]; then
    STATUS="CHECK"; NOTE="Range or alias '$1': the installed version decides. Run --local where it executes."; return
  fi
  op=${BASH_REMATCH[1]}; maj=${BASH_REMATCH[2]}; min=${BASH_REMATCH[4]}; pat=${BASH_REMATCH[6]}
  fixed=$(fixed_for_major "$maj")
  if [ -z "$fixed" ]; then
    if (( maj > $(max_major) )); then STATUS="CHECK"; NOTE="Node $maj is newer than this advisory knows."
    elif [ "$op" = ">=" ]; then STATUS="CHECK"; NOTE="Minimum '$1' still allows end-of-life Node $maj. The installed version decides; raise the minimum to >= $(echo $FIXED_VERSIONS | tr ' ' '\n' | sort -t. -k1,1n | head -1)."
    else STATUS="EOL"; NOTE=$(eol_note "$maj"); fi
    return
  fi
  if [ -z "$op" ] && [[ $min =~ ^[0-9]+$ ]] && [[ $pat =~ ^[0-9]+$ ]]; then
    classify_ver "$maj.$min.$pat"; return                  # exact pin, e.g. 22.23.3-alpine
  fi
  if [ "$op" != "^" ] && [ "$op" != ">=" ] && [[ $min =~ ^[0-9]+$ ]]; then
    fmm=$(echo "$fixed" | cut -d. -f2)
    if (( min < fmm )); then STATUS="VULNERABLE"; NOTE="Pinned to $maj.$min.x, which can never reach the fixed $fixed. Change the pin."; return; fi
    if (( min > fmm )); then STATUS="PATCHED"; NOTE="Pinned at $maj.$min.x, above the fixed $fixed."; return; fi
  fi
  STATUS="FLOATING"; NOTE="Follows Node $maj$rest: gets $fixed only after a reinstall or rebuild (docker build --pull / redeploy). Pin to >= $fixed to enforce it."
}

classify_runtime() { # nodejs22.x / nodejs20
  local maj; maj=$(echo "$1" | grep -oE '[0-9]+' | head -1)
  if fixed_for_major "$maj" >/dev/null; then
    STATUS="MANAGED"; NOTE="Managed runtime $1: the cloud provider applies Node patches. Confirm in the provider's bulletin; container-image deployments must be rebuilt."
  elif (( maj > $(max_major) )); then
    STATUS="CHECK"; NOTE="Runtime $1 is newer than this advisory knows."
  else
    STATUS="EOL"; NOTE="Runtime $1 is end-of-life upstream; providers stop patching deprecated runtimes. Migrate to a supported runtime (nodejs$(echo $FIXED_VERSIONS | tr ' ' '\n' | cut -d. -f1 | sort -n | head -1).x or newer)."
  fi
}

# ---------- output ---------------------------------------------------------------

record() { # target version status note signals
  ROWS+=("$1|$2|$3|$4|$5")
  local col lvl
  case "$3" in
    PATCHED)                          col=$G; lvl=0; CNT_OK=$((CNT_OK+1));;
    VULNERABLE|EOL|STALE)             col=$R; lvl=2; CNT_RISK=$((CNT_RISK+1));;
    CHECK|HIDDEN|FLOATING|ERROR|EXPOSED) col=$Y; lvl=1; CNT_CHK=$((CNT_CHK+1));;
    *)                                col=$D; lvl=0; CNT_OTH=$((CNT_OTH+1));;
  esac
  (( lvl > WORST )) && WORST=$lvl
  printf '%s%-11s%s %s%s%s\n' "$col$BD" "$3" "$N" "$BD" "$1" "$N"
  printf '            %s\n' "$(ver_label "$2")"
  printf '            %s\n' "$4"
  [ -n "$5" ] && printf '            %s%s%s\n' "$D" "$5" "$N"
  echo
}

esc()  { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }
csvq() { local s=${1//\"/\"\"}; printf '"%s"' "$s"; }

write_csv() {
  local f="$1.csv" r t v s n g
  echo 'target,node_version,status,note,signals,advisory' > "$f"
  for r in "${ROWS[@]}"; do
    IFS='|' read -r t v s n g <<< "$r"
    printf '%s,%s,%s,%s,%s,%s\n' "$(csvq "$t")" "$(csvq "${v#@}")" "$(csvq "$s")" "$(csvq "$n")" "$(csvq "$g")" "$(csvq "$ADVISORY_ID")" >> "$f"
  done
}

write_html() {
  local f="$1.html" r t v s n g cls card risk="" chk="" ok="" oth="" when chips="" x
  when=$(date '+%Y-%m-%d %H:%M %Z')
  for x in $FIXED_VERSIONS; do chips="$chips<span class=\"chip\">$x</span>"; done
  for r in "${ROWS[@]}"; do
    IFS='|' read -r t v s n g <<< "$r"
    case "$s" in
      VULNERABLE|EOL|STALE) cls=risk;; CHECK|HIDDEN|FLOATING|ERROR|EXPOSED) cls=chk;; PATCHED) cls=ok;; *) cls=oth;;
    esac
    card="<div class=\"card $cls\"><div class=\"top\"><span class=\"badge\">$(esc "$s")</span><span class=\"ver\">$(esc "$(ver_label "$v")")</span></div><h3>$(esc "$t")</h3><p>$(esc "$n")</p>"
    [ -n "$g" ] && card="$card<p class=\"sig\">$(esc "$g")</p>"
    card="$card</div>"
    case "$cls" in risk) risk="$risk$card";; chk) chk="$chk$card";; ok) ok="$ok$card";; *) oth="$oth$card";; esac
  done
  cat > "$f" <<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Node.js Security Report</title>
<style>
:root{--bg:#f6f7f9;--fg:#14161a;--mut:#5d6470;--card:#fff;--line:#e3e6eb;--risk:#d92d20;--chk:#dc8a00;--ok:#16a34a;--oth:#7a828e;--accent:#3c873a}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#eef0f3;--mut:#9aa3af;--card:#181b21;--line:#2a2f37}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}
.wrap{max-width:1000px;margin:0 auto}h1{margin:0 0 4px;font-size:24px}h1 span{color:var(--accent)}.sub{color:var(--mut);margin:0 0 18px;font-size:13px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px;align-items:center}.chip{border:1px solid var(--line);background:var(--card);border-radius:999px;padding:4px 12px;font-size:13px}
.sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;border-top:5px solid var(--c)}
.stat b{display:block;font-size:30px;line-height:1.1;color:var(--c)}.stat span{color:var(--mut);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:14px;padding:14px 16px;min-width:0}
.card h3{margin:8px 0 6px;font-size:15px;word-break:break-all}.card p{margin:0 0 6px;font-size:14px}.sig{color:var(--mut);font-size:12px!important;word-break:break-word}
.top{display:flex;justify-content:space-between;align-items:center;gap:8px}.badge{background:var(--c);color:#fff;font-weight:700;font-size:11px;letter-spacing:.06em;padding:3px 9px;border-radius:6px}
.ver{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:var(--mut)}
.risk{--c:var(--risk)}.chk{--c:var(--chk)}.ok{--c:var(--ok)}.oth{--c:var(--oth)}
footer{color:var(--mut);font-size:12px;margin-top:28px}a{color:inherit}
</style></head><body><div class="wrap">
<h1><span>Node.js</span> exposure report</h1>
<p class="sub">$(esc "$ADVISORY_NAME") &middot; incl. HTTP2Shell, the Brotli decoder RCE ($(esc "$BROTLI_CVE")): Node, Bun, system Brotli, Express 5 body parsing &middot; generated $when</p>
<div class="chips"><b style="font-size:13px">Fixed:</b>$chips<span class="chip">Other lines: EOL, no fix</span></div>
<div class="sum">
<div class="stat risk"><b>$CNT_RISK</b><span>At risk (vulnerable / EOL / stale)</span></div>
<div class="stat chk"><b>$CNT_CHK</b><span>Needs action or check (floating, exposed, hidden...)</span></div>
<div class="stat ok"><b>$CNT_OK</b><span>Patched</span></div>
<div class="stat oth"><b>$CNT_OTH</b><span>Managed / no Node seen</span></div>
</div>
<div class="grid">$risk$chk$ok$oth</div>
<footer>EXPOSED means the app decodes Brotli request bodies (Express 5 / body-parser 2.x): safe only on a patched Node. FLOATING means the config will pick up the fix only after a reinstall, redeploy or image rebuild. Outside-in checks rarely see Node versions; --local and --project are the real evidence. Advisory $(esc "$ADVISORY_ID"), verified $(esc "$LAST_VERIFIED"): <a href="$(esc "$SOURCE_URL")">nodejs.org</a></footer>
</div></body></html>
HTML
}

# ---------- local: binaries + running processes ---------------------------------

pkg_of() { # owning package "name version" or empty
  local p="$1" pkg ver
  if command -v dpkg >/dev/null 2>&1; then
    pkg=$(dpkg -S "$p" 2>/dev/null | head -1 | cut -d: -f1)
    [ -n "$pkg" ] && ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
  elif command -v rpm >/dev/null 2>&1; then
    pkg=$(rpm -qf --qf '%{NAME}' "$p" 2>/dev/null | grep -v 'not owned')
    [ -n "$pkg" ] && ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null)
  fi
  [ -n "$pkg" ] && [ -n "$ver" ] && echo "$pkg $ver"
}
pkg_changelog() { # pkgname -> changelog text (dpkg or rpm)
  local f
  if command -v dpkg >/dev/null 2>&1; then
    for f in /usr/share/doc/"$1"/changelog.Debian.gz /usr/share/doc/"$1"/changelog.gz; do
      [ -r "$f" ] && { zcat "$f" 2>/dev/null; return; }
    done
  elif command -v rpm >/dev/null 2>&1; then
    rpm -q --changelog "$1" 2>/dev/null
  fi
}
pkg_has_backport() { # pkgname
  local log="" f cve
  if command -v dpkg >/dev/null 2>&1; then
    for f in /usr/share/doc/"$1"/changelog.Debian.gz /usr/share/doc/"$1"/changelog.gz; do
      [ -r "$f" ] && { log=$(zcat "$f" 2>/dev/null); break; }
    done
  elif command -v rpm >/dev/null 2>&1; then
    log=$(rpm -q --changelog "$1" 2>/dev/null)
  fi
  [ -z "$log" ] && return 1
  for cve in $BACKPORT_KEY_CVES; do echo "$log" | grep -q "$cve" || return 1; done
}

discover_node_bins() {
  local h b rb homes="$HOME"
  [ "$(id -u)" = 0 ] && homes="$homes /root $(ls -d /home/* /Users/* 2>/dev/null | tr '\n' ' ')"
  {
    type -ap node nodejs 2>/dev/null
    for b in /usr/bin/node /usr/bin/nodejs /usr/local/bin/node /opt/homebrew/bin/node /opt/homebrew/opt/node*/bin/node \
             /usr/local/opt/node*/bin/node /opt/nodejs/bin/node /usr/local/lib/nodejs/*/bin/node /usr/local/n/versions/node/*/bin/node \
             /opt/plesk/node/*/bin/node /opt/cpanel/ea-nodejs*/bin/node /opt/alt/alt-nodejs*/root/usr/bin/node; do
      echo "$b"
    done
    for h in $homes; do
      for b in "$h"/.nvm/versions/node/*/bin/node "$h"/.local/share/fnm/node-versions/*/installation/bin/node \
               "$h/Library/Application Support/fnm/node-versions"/*/installation/bin/node "$h"/.fnm/node-versions/*/installation/bin/node \
               "$h"/.volta/tools/image/node/*/bin/node "$h"/.asdf/installs/nodejs/*/bin/node "$h"/.local/share/mise/installs/node/*/bin/node \
               "$h"/.nodenv/versions/*/bin/node "$h"/n/versions/node/*/bin/node "$h"/nodevenv/*/*/bin/node; do
        echo "$b"
      done
    done
  } | while IFS= read -r b; do
    case "$b" in */.volta/bin/*) continue;; esac          # Volta shims, not real binaries
    if [ -f "$b" ] && [ -x "$b" ]; then
      rb=$(readlink -f "$b" 2>/dev/null) && b=$rb
      echo "$b"
    fi
  done | sort -u
}

local_scan() {
  local host b v pk running stale=0 exe pid sigl bins
  host=$(hostname 2>/dev/null || uname -n)

  # running processes: count per binary, and catch stale ones
  : > "$TMP/running"
  if [ -e /proc/self/exe ]; then
    for p in /proc/[0-9]*; do
      exe=$(readlink "$p/exe" 2>/dev/null) || continue
      case "$(basename "${exe% (deleted)}")" in node|nodejs) ;; *) continue;; esac
      pid=${p#/proc/}
      if [[ $exe == *"(deleted)"* ]]; then
        stale=$((stale+1))
        record "$host pid $pid" "replaced binary" "STALE" "This process still runs a Node binary that was replaced on disk (likely the old vulnerable one). Restart it: pm2 reload all, systemctl restart <service>, or redeploy." "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-120)"
      else
        echo "$exe" >> "$TMP/running"
      fi
    done
  fi

  bins=$(discover_node_bins)
  if [ -z "$bins" ]; then
    record "$host" "" "NO-NODE" "No Node.js binaries found in common locations or version managers." ""
  else
    while IFS= read -r b; do
      v=$("$b" -v </dev/null 2>/dev/null | head -1); v=${v#v}
      if [ -z "$v" ]; then record "$host:$b" "" "ERROR" "Could not read version from this binary." ""; continue; fi
      pk=$(pkg_of "$b")
      classify_ver "$v${pk:+ [pkg $pk]}"
      if [ "$STATUS" = CHECK ] && [ -n "$pk" ] && pkg_has_backport "${pk%% *}"; then
        STATUS="PATCHED"; NOTE="Distro backport confirmed: the ${pk%% *} changelog lists $BACKPORT_KEY_CVES."
      fi
      running=$(grep -cxF "$b" "$TMP/running" 2>/dev/null); running=${running:-0}
      sigl="running processes: $running"
      [ "$running" -gt 0 ] && [ "$STATUS" != PATCHED ] && sigl="$sigl (restart them after upgrading)"
      record "$host:$b" "$v${pk:+ [pkg $pk]}" "$STATUS" "$NOTE" "$sigl"
    done <<< "$bins"
  fi
  http2shell_local "$host"
  [ -e /proc/self/exe ] || printf '%sNote:%s no /proc on this OS, so running processes were not checked. Restart Node apps after upgrading.\n\n' "$Y" "$N"
  printf '%sNote:%s apps that bundle their own Node (Electron apps, SEA executables, vendor appliances) need their own updates and are not listed here.\n\n' "$D" "$N"
}

# ---------- HTTP2Shell: Brotli outside the Node binary -------------------------------
# Versions of non-Node components are stored with a leading "@" ("@Bun 1.4.3").
ver_label() { case "$1" in @*) printf '%s' "${1#@}";; *) printf 'Node %s' "${1:--}";; esac; }

classify_bun() { # exact Bun version
  local v="${1#v}"
  if [[ ! $v =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then STATUS="CHECK"; NOTE="Could not parse Bun version '$1'."; return; fi
  if ver_ge "${BASH_REMATCH[0]}" "$BUN_FIXED"; then
    STATUS="PATCHED"; NOTE="Bun at or above $BUN_FIXED (Brotli decoder fix)."
  else
    STATUS="VULNERABLE"; NOTE="Bun below $BUN_FIXED decodes Brotli with the vulnerable decoder (HTTP2Shell, $BROTLI_CVE). Upgrade to $BUN_FIXED or newer (bun upgrade) and restart Bun apps."
  fi
}
classify_bun_spec() { # tag, .bun-version or packageManager value
  local s base fm
  s=$(printf '%s' "$1" | tr -d '"'"'"' \r' | tr 'A-Z' 'a-z'); s=${s#v}
  case "$s" in *@sha256:*) STATUS="CHECK"; NOTE="Bun image pinned by digest: check with docker run --rm <image> bun --version."; return;; esac
  base=${s%%-*}; base=${base%%+*}
  if [[ $base =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then classify_bun "$base"; return; fi
  if [[ $base =~ ^([0-9]+)\.([0-9]+)$ ]]; then
    fm=${BUN_FIXED%.*}
    if ver_ge "$base.0" "$fm.0" && [ "$base" != "$fm" ]; then STATUS="PATCHED"; NOTE="Pinned to Bun $base.x, above $BUN_FIXED."; return; fi
    if [ "$base" != "$fm" ]; then STATUS="VULNERABLE"; NOTE="Pinned to Bun $base.x, which never gets the Brotli fix ($BUN_FIXED). Change the pin."; return; fi
  fi
  STATUS="FLOATING"; NOTE="Tracks a Bun line or tag: picks up $BUN_FIXED only after a reinstall or rebuild (docker build --pull). Pin $BUN_FIXED or newer to enforce it."
}

discover_bun_bins() {
  local h b rb homes="$HOME"
  [ "$(id -u)" = 0 ] && homes="$homes /root $(ls -d /home/* /Users/* 2>/dev/null | tr '\n' ' ')"
  {
    type -ap bun 2>/dev/null
    echo /usr/local/bin/bun; echo /usr/bin/bun; echo /opt/homebrew/bin/bun
    for h in $homes; do echo "$h/.bun/bin/bun"; done
  } | while IFS= read -r b; do
    if [ -f "$b" ] && [ -x "$b" ]; then rb=$(readlink -f "$b" 2>/dev/null) && b=$rb; echo "$b"; fi
  done | sort -u
}

discover_libbrotli() { # -> "package version" lines for the shared Brotli library
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}\n' 'libbrotli*' 2>/dev/null \
      | awk -F'|' '$1 ~ /^ii/ && $2 !~ /-dev$/ {print $2" "$3" dpkg"}'
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE} rpm\n' brotli libbrotli 2>/dev/null | grep -v 'not installed'
  fi
  if command -v apk >/dev/null 2>&1; then
    apk info -v 2>/dev/null | sed -nE 's/^(brotli-libs)-([0-9].*)$/\1 \2 apk/p'
  fi
  if command -v brew >/dev/null 2>&1; then brew list --versions brotli 2>/dev/null | awk '{print $1" "$NF" brew"}'; fi
}

brotli_upstream_ok() { # x.y.z -> true if outside the affected range or at a fixed release
  local v=$1 f mx
  ver_ge "$v" "1.0.3" || return 0
  for f in $BROTLI_FIXED_UPSTREAM; do
    [ "${v%.*}" = "${f%.*}" ] && { ver_ge "$v" "$f"; return; }
  done
  mx=$(echo $BROTLI_FIXED_UPSTREAM | tr ' ' '\n' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
  ver_ge "$v" "$mx"
}

classify_libbrotli() { # package version [dpkg|rpm|apk|brew]
  local name=$1 pv=$2 mgr=${3:-} up f
  up=$(printf '%s' "$pv" | sed -E 's/^[0-9]+://' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
  if [ -z "$up" ]; then STATUS="CHECK"; NOTE="Could not parse $name version '$pv'."; return; fi
  if brotli_upstream_ok "$up"; then STATUS="PATCHED"; NOTE="Brotli $up is outside the affected range ($BROTLI_AFFECTED) or at a fixed release."; return; fi
  if [ "$mgr" = dpkg ] && command -v dpkg >/dev/null 2>&1; then
    for f in $BROTLI_FIXED_DISTRO; do
      if [ "${f%%-*}" = "$up" ] && dpkg --compare-versions "$pv" ge "$f" 2>/dev/null; then
        STATUS="PATCHED"; NOTE="Distro build $pv includes the $BROTLI_CVE fix (fixed in $f)."; return
      fi
    done
  fi
  if { [ "$mgr" = dpkg ] || [ "$mgr" = rpm ]; } && pkg_changelog "$name" | grep -q "$BROTLI_CVE"; then
    STATUS="PATCHED"; NOTE="The $name changelog lists $BROTLI_CVE (backport)."; return
  fi
  STATUS="VULNERABLE"; NOTE="System Brotli $pv is in the affected range ($BROTLI_AFFECTED) with no backport found. Distro Node builds, curl --compressed and other tools decode with it: apply the OS security update for $name, then restart services that load it."
}

brotli_consumers() { # Node/curl binaries on this machine that load the shared Brotli library
  local b out=""
  for b in $(discover_node_bins | tr '\n' ' ') $(type -ap curl 2>/dev/null | head -1); do
    if command -v ldd >/dev/null 2>&1; then ldd "$b" 2>/dev/null | grep -q 'libbrotli' && out="$out $b"
    elif command -v otool >/dev/null 2>&1; then otool -L "$b" 2>/dev/null | grep -q 'libbrotli' && out="$out $b"; fi
  done
  echo $out
}

http2shell_local() { # host
  [ -n "$BROTLI_CVE" ] || return 0
  local host=$1 b v libs cons name pv mgr
  if [ -n "$BUN_FIXED" ]; then
    while IFS= read -r b; do
      [ -z "$b" ] && continue
      v=$("$b" --version </dev/null 2>/dev/null | head -1); v=${v#v}
      if [ -z "$v" ]; then record "$host:$b" "@Bun ?" "ERROR" "Could not read the Bun version." ""; continue; fi
      classify_bun "$v"; record "$host:$b" "@Bun $v" "$STATUS" "$NOTE" "HTTP2Shell ($BROTLI_CVE): Bun runtime"
    done <<< "$(discover_bun_bins)"
  fi
  libs=$(discover_libbrotli)
  if [ -n "$libs" ]; then
    cons=$(brotli_consumers)
    while read -r name pv mgr; do
      [ -z "$name" ] && continue
      classify_libbrotli "$name" "$pv" "$mgr"
      record "$host: system Brotli library ($name)" "@$name $pv" "$STATUS" "$NOTE" "loaded by: ${cons:-no Node or curl binary here links it (other programs may)}"
    done <<< "$libs"
  fi
}

classify_bodyparser() { # exact body-parser version
  local v=$1 maj=${1%%.*} f fx=""
  for f in $BODYPARSER_FIXED; do [ "${f%%.*}" = "$maj" ] && fx=$f; done
  if [ "$maj" = 2 ]; then
    if [ -n "$fx" ] && ! ver_ge "$v" "$fx"; then
      STATUS="VULNERABLE"; NOTE="body-parser $v (Express 5): one compressed request can crash the app ($BODYPARSER_ADVISORY, fixed in $fx), and it decodes Brotli request bodies by default, the inbound HTTP2Shell path on an unpatched Node. Update to $fx or newer (npm update body-parser) and patch the Node that runs it."
    else
      STATUS="EXPOSED"; NOTE="body-parser $v (Express 5) decodes Brotli request bodies by default: the inbound HTTP2Shell path. Safe once the Node that runs it is patched (scan --local where it runs). Until then: express.json({ inflate: false }) (also rejects gzip bodies) or block Content-Encoding: br at the proxy."
    fi
  elif [ -n "$fx" ]; then
    if ver_ge "$v" "$fx"; then STATUS="PATCHED"; NOTE="body-parser $v (Express 4) rejects Brotli bodies (415) and has the $BODYPARSER_ADVISORY fix."
    else STATUS="VULNERABLE"; NOTE="body-parser $v: one compressed request can crash the app ($BODYPARSER_ADVISORY, fixed in $fx). It rejects Brotli bodies, so it is not an HTTP2Shell path. Update: npm update body-parser (Express 4 accepts $fx)."; fi
  else
    STATUS="CHECK"; NOTE="body-parser $v: this advisory has no data for major $maj."
  fi
}

lock_bodyparser() { # lockfile basename -> "line|version" (deduplicated)
  case "$2" in
    package-lock.json|npm-shrinkwrap.json)
      awk '/"([^"]*node_modules\/)?body-parser"[[:space:]]*:[[:space:]]*\{/ {f=NR; next}
           f && /"version"[[:space:]]*:/ { if (match($0, /[0-9]+\.[0-9]+\.[0-9]+/)) print f "|" substr($0, RSTART, RLENGTH); f=0 }' "$1";;
    yarn.lock)
      awk '/^"?body-parser@/ {f=NR; next}
           f && /^[[:space:]]+version:?[[:space:]]/ { if (match($0, /[0-9]+\.[0-9]+\.[0-9]+/)) print f "|" substr($0, RSTART, RLENGTH); f=0; next }
           /^[^[:space:]]/ {f=0}' "$1";;
    pnpm-lock.yaml|bun.lock)
      grep -noE "(^|[[:space:]'\"/])body-parser[@/][0-9]+\.[0-9]+\.[0-9]+" "$1" | sed -E 's/^([0-9]+):.*body-parser[@/]/\1|/';;
  esac | awk -F'|' '!seen[$2]++'
}

has_lockfile() { local l; for l in package-lock.json npm-shrinkwrap.json pnpm-lock.yaml yarn.lock bun.lock bun.lockb; do [ -f "$1/$l" ] && return 0; done; return 1; }

emit_bun() { # file line spec kind
  local rel="${1#"$PROOT"/}"
  classify_bun_spec "$3"
  record "$rel:$2" "@Bun $3" "$STATUS" "$NOTE" "$4"
}
emit_bodyparser() { # file line version
  local rel="${1#"$PROOT"/}"
  classify_bodyparser "$3"
  record "$rel:$2" "@body-parser $3" "$STATUS" "$NOTE" "HTTP2Shell inbound path / $BODYPARSER_ADVISORY"
}
pkgjson_http2shell() { # package.json without a lockfile: declared Express 5 / body-parser 2
  local f=$1 ln line name spec maj rel="${1#"$PROOT"/}"
  has_lockfile "$(dirname "$f")" && return 0
  while IFS=: read -r ln line; do
    name=$(echo "$line" | sed -E 's/^"([^"]+)".*/\1/')
    spec=$(echo "$line" | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/')
    maj=$(echo "$spec" | sed -E 's/^[^0-9]*//' | grep -oE '^[0-9]+')
    case "$spec" in latest|\*|'') [ "$name" = express ] && maj=5 || maj=2;; esac
    if { [ "$name" = express ] && [ "$maj" = 5 ]; } || { [ "$name" = body-parser ] && [ "$maj" = 2 ]; }; then
      record "$rel:$ln" "@$name $spec" "EXPOSED" "$name $spec uses body-parser 2.x, which decodes Brotli request bodies by default (the inbound HTTP2Shell path) and below 2.4.0 can crash on compressed bodies ($BODYPARSER_ADVISORY). No lockfile here, so the installed version is unknown: run npm ls body-parser, update to 2.4.0 or newer, and patch Node." "declared dependency"
    fi
  done < <(grep -noE '"(express|body-parser)"[[:space:]]*:[[:space:]]*"[^"]*"' "$f")
}

# ---------- project: declared versions in code and config -----------------------

emit_spec() { # file line spec kind
  local rel="${1#"$PROOT"/}"
  classify_spec "$3"
  record "$rel:$2" "$3" "$STATUS" "$NOTE" "$4"
}
emit_runtime() { # file line runtime
  local rel="${1#"$PROOT"/}"
  classify_runtime "$3"
  record "$rel:$2" "$3" "$STATUS" "$NOTE" "cloud runtime setting"
}

project_scan() {
  PROOT="$(cd "$1" 2>/dev/null && pwd)" || { record "$1" "" "ERROR" "Directory not readable." ""; return; }
  local f base ln val line img tag one before=${#ROWS[@]}
  find "$PROOT" \( -name node_modules -o -name .git -o -name dist -o -name build -o -name .next -o -name .nuxt -o -name vendor -o -name .cache -o -name coverage \) -prune -o -type f \( \
      -name .nvmrc -o -name .node-version -o -name .tool-versions -o -name package.json -o -name 'Dockerfile*' \
      -o -name package-lock.json -o -name npm-shrinkwrap.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name bun.lock -o -name .bun-version -o -name '*.dockerfile' -o -name 'Containerfile' \
      -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' -o -name 'compose*.yaml' -o -name .gitlab-ci.yml -o -name bitbucket-pipelines.yml \
      -o -name netlify.toml -o -name 'serverless.yml' -o -name 'serverless.yaml' -o -name 'template.yml' -o -name 'template.yaml' -o -name '*.tf' -o -name app.yaml \
      -o -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \) -print 2>/dev/null > "$TMP/files"

  while IFS= read -r f; do
    base=$(basename "$f")
    case "$base" in
      .nvmrc|.node-version)
        val=$(grep -vE '^[[:space:]]*(#|$)' "$f" | head -1)
        [ -n "$val" ] && { emit_spec "$f" 1 "$val" "$base"; found=1; } ;;
      .tool-versions)
        while IFS=: read -r ln line; do
          emit_spec "$f" "$ln" "$(echo "$line" | awk '{print $2}')" ".tool-versions"
        done < <(grep -nE '^(nodejs|node)[[:space:]]+' "$f")
        [ -n "$BUN_FIXED" ] && while IFS=: read -r ln line; do
          emit_bun "$f" "$ln" "$(echo "$line" | awk '{print $2}')" ".tool-versions bun"
        done < <(grep -nE '^bun[[:space:]]+' "$f") ;;
      .bun-version)
        val=$(grep -vE '^[[:space:]]*(#|$)' "$f" | head -1)
        [ -n "$val" ] && [ -n "$BUN_FIXED" ] && emit_bun "$f" 1 "$val" ".bun-version" ;;
      package-lock.json|npm-shrinkwrap.json|pnpm-lock.yaml|yarn.lock|bun.lock)
        [ -n "$BODYPARSER_FIXED" ] && while IFS='|' read -r ln val; do
          [ -n "$val" ] && emit_bodyparser "$f" "$ln" "$val"
        done < <(lock_bodyparser "$f" "$base") ;;
      package.json)
        while IFS=: read -r ln line; do
          val=$(echo "$line" | sed -E 's/.*"node"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')
          emit_spec "$f" "$ln" "$val" "package.json engines/volta node"
        done < <(grep -nE '"node"[[:space:]]*:[[:space:]]*"[^"]*"' "$f")
        [ -n "$BUN_FIXED" ] && while IFS=: read -r ln line; do
          emit_bun "$f" "$ln" "$(echo "$line" | sed -E 's/.*"bun@([^"]*)".*/\1/')" "package.json packageManager"
        done < <(grep -nE '"packageManager"[[:space:]]*:[[:space:]]*"bun@' "$f")
        [ -n "$BODYPARSER_FIXED" ] && pkgjson_http2shell "$f" ;;
      Dockerfile*|*.dockerfile|Containerfile)
        while IFS=: read -r ln line; do
          img=$(echo "$line" | sed -E 's/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(--[^ ]+[[:space:]]+)*//' | awk '{print $1}')
          if echo "$img" | grep -qiE '(^|/)node(:|@|$)'; then
            tag=$(echo "$img" | sed -E 's#.*(^|/)node##I'); tag=${tag#:}
            emit_spec "$f" "$ln" "${tag:-latest}" "image: $img"
          elif [ -n "$BUN_FIXED" ] && echo "$img" | grep -qiE '(^|/)oven/bun(:|@|$)'; then
            tag=$(echo "$img" | sed -E 's#.*oven/bun##I'); tag=${tag#:}
            emit_bun "$f" "$ln" "${tag:-latest}" "image: $img"
          fi
        done < <(grep -niE '^[[:space:]]*FROM[[:space:]]' "$f") ;;
      *.yml|*.yaml)
        case "$f" in
          */.github/workflows/*)
            while IFS=: read -r ln line; do
              val=$(echo "$line" | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d "[]\"'" | tr ',' ' ')
              for one in $val; do emit_spec "$f" "$ln" "$one" "GitHub Actions node-version"; done
            done < <(grep -nE '^[[:space:]]*(-[[:space:]]*)?node(-version|_version|js)?[[:space:]]*:[[:space:]]*[^[:space:]]' "$f" | grep -v '\${{')
            [ -n "$BUN_FIXED" ] && while IFS=: read -r ln line; do
              emit_bun "$f" "$ln" "$(echo "$line" | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d "\"' ")" "GitHub Actions bun-version"
            done < <(grep -nE '^[[:space:]]*bun-version[[:space:]]*:[[:space:]]*[^[:space:]]' "$f" | grep -v '\${{') ;;
          *)
            while IFS=: read -r ln line; do
              img=$(echo "$line" | sed -E 's/.*image:[[:space:]]*//' | tr -d "\"' ")
              tag=$(echo "$img" | sed -E 's#.*(^|/)node##'); tag=${tag#:}
              emit_spec "$f" "$ln" "${tag:-latest}" "image: $img"
            done < <(grep -nE 'image:[[:space:]]*["'"'"']?([a-z0-9.-]+/)*node(:[^[:space:]"'"'"']*)?["'"'"']?[[:space:]]*$' "$f")
            while IFS=: read -r ln val; do emit_runtime "$f" "$ln" "$val"; done < <(grep -noE 'nodejs[0-9]+(\.x)?' "$f") ;;
        esac ;;
      netlify.toml)
        while IFS=: read -r ln line; do
          emit_spec "$f" "$ln" "$(echo "$line" | sed -E 's/.*=[[:space:]]*//')" "netlify NODE_VERSION"
        done < <(grep -nE 'NODE_VERSION[[:space:]]*=' "$f") ;;
      *.tf)
        while IFS=: read -r ln val; do emit_runtime "$f" "$ln" "$val"; done < <(grep -noE 'nodejs[0-9]+(\.x)?' "$f") ;;
    esac
  done < "$TMP/files"

  [ "${#ROWS[@]}" -eq "$before" ] && record "${PROOT}" "" "NO-NODE" "No Node.js version declarations found (no .nvmrc, package.json engines, Dockerfile, CI or runtime settings)." ""
  printf '%sTip:%s FLOATING entries pick up the fix on the next install/redeploy; for Docker add --pull (docker compose build --pull). EXPOSED body-parser entries are safe only on a patched Node. Also run "npm audit" for npm packages like undici installed directly.\n\n' "$D" "$N"
}

# ---------- remote: passive fingerprint -----------------------------------------

scan_url() {
  local target="$1" url h="$TMP/h" b="$TMP/b" xpb srv sig="" ver plat=""
  url="$target"; case "$url" in http://*|https://*) ;; *) url="https://$url";; esac
  : > "$h"; : > "$b"
  curl -sS -L --max-redirs 5 -m "$TIMEOUT" -A "$UA" -D "$h" "$url" 2>"$TMP/err" | head -c 400000 > "$b"
  if [ ! -s "$h" ]; then record "$target" "" "ERROR" "No response: $(head -1 "$TMP/err" | tr -d '|')" ""; return; fi

  xpb=$(grep -i '^x-powered-by:' "$h" | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
  srv=$(grep -i '^server:' "$h" | tail -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
  ver=$(printf '%s %s' "$xpb" "$srv" | grep -oiE 'node(\.js)?/v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

  [ -n "$xpb" ] && sig="$sig X-Powered-By: $xpb;"
  grep -qi 'set-cookie:.*connect\.sid' "$h"           && sig="$sig Express session cookie;"
  grep -qiE '^x-nextjs-|x-middleware' "$h"            && sig="$sig Next.js headers;"
  grep -qE '__NEXT_DATA__|/_next/static/' "$b"         && sig="$sig Next.js assets;"
  grep -qE '__NUXT__|/_nuxt/' "$b"                     && sig="$sig Nuxt assets;"
  grep -qE '/_app/immutable/|__sveltekit' "$b"         && sig="$sig SvelteKit assets;"
  grep -qE 'astro-island|/_astro/' "$b"                && sig="$sig Astro assets;"
  grep -qiE '^x-vercel-' "$h"                          && plat="Vercel"
  grep -qiE '^x-nf-request-id' "$h"                    && plat="Netlify"
  grep -qiE '^x-amz-cf-|^x-amzn-' "$h"                 && [ -z "$plat" ] && plat="AWS"
  [ -n "$plat" ] && sig="$sig hosted on $plat;"
  sig=$(echo "$sig" | sed 's/^ *//; s/;$//')

  if [ -n "$ver" ]; then
    classify_ver "$ver"; record "$target" "$ver" "$STATUS" "$NOTE" "$sig"
  elif echo "$sig" | grep -qE 'Express|Next|Nuxt|Svelte|Astro|Koa|Fastify|Nest'; then
    if [ "$plat" = Vercel ] || [ "$plat" = Netlify ]; then
      record "$target" "hidden" "HIDDEN" "Node-based site on $plat. Server code runs on the platform's Node runtime: check the project's Node version setting (must be a supported line) and redeploy so new functions get the patched runtime. Static-only sites run no Node at request time." "$sig"
    else
      record "$target" "hidden" "HIDDEN" "Node-based site; version is not exposed (normal). Check the server with --local or the repo with --project. Static exports run no Node at request time." "$sig"
    fi
  else
    record "$target" "" "NO-NODE" "No Node.js fingerprints from outside. Not proof: many Node APIs and proxies hide their stack." "${srv:+Server: $srv}"
  fi
}


# load_advisory [file]: built-in values above, overridden by the advisory file
load_advisory() {
  local f="${1:-$DEFAULT_ADVISORY}"
  if [ -r "$f" ]; then . "$f"; ADVISORY_FILE="$f"
  elif [ -n "$1" ]; then echo "Advisory file not readable: $1" >&2; exit 3
  fi
}

# node_install_method <binary path> [<"pkg ver">] -> nvm|fnm|volta|asdf|mise|n|nodenv|brew|cpanel|cloudlinux|plesk|nodesource|distro|manual
node_install_method() {
  case "$1" in
    */.nvm/*) echo nvm;; */fnm/*|*/.fnm/*) echo fnm;; */.volta/*) echo volta;; */.asdf/*) echo asdf;;
    */mise/*) echo mise;; */n/versions/*) echo n;; */.nodenv/*) echo nodenv;;
    /opt/homebrew/*|/usr/local/Cellar/*|/usr/local/opt/*|/home/linuxbrew/*) echo brew;;
    /opt/cpanel/ea-nodejs*) echo cpanel;; /opt/alt/alt-nodejs*|*/nodevenv/*) echo cloudlinux;; /opt/plesk/node/*) echo plesk;;
    *) case "$2" in *nodesource*) echo nodesource;; "") echo manual;; *) echo distro;; esac;;
  esac
}
