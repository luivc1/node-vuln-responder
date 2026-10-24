#!/usr/bin/env bash
# =====================================================================
#  scan.sh  (node-vuln-responder)
#  Node.js exposure scanner for the October 2026 security releases
#  (10 CVEs, max severity High, incl. CVE-2026-111497 Brotli RCE, now
#  called HTTP2Shell: also checks Bun, the system Brotli library and
#  Express 5 / body-parser request decoding)
#
#  Needs only: bash + coreutils (+ curl for --url checks)
#  Read-only:  reads versions and config files. No exploit payloads.
#  Only scan systems you own or are authorized to assess.
#
#  Fixed releases (nodejs.org, Oct 21 2026):  26.12.1 | 24.22.1 | 22.23.4
#  Node 20 and older, 21, 23, 25 are end-of-life: NO fix.
#
#  Usage:
#    scan.sh --local                    # this machine: every Node
#                                                 # install + running processes,
#                                                 # Bun, system Brotli library
#    scan.sh --project ~/code           # repos: .nvmrc, package.json
#                                                 # engines, Dockerfiles, CI,
#                                                 # Lambda/App Engine runtimes,
#                                                 # Bun pins, body-parser in lockfiles
#    scan.sh example.com app.example.com   # outside-in fingerprint
#    scan.sh --local --project . -o report # combine; -> report.html/.csv
#    scan.sh --advisory next.env ...    # reuse for a future release
#
#  Why mostly inside-out: Node servers almost never reveal their version
#  in HTTP headers. --url mode finds Node-based sites; --local and
#  --project tell you which version they actually run.
#
#  Statuses:
#    PATCHED     at/above the fixed release for its line
#    VULNERABLE  supported line, below the fixed release
#    EOL         end-of-life line: no fix exists, upgrade the major version
#    STALE       a running process still uses a binary replaced on disk
#    FLOATING    config tracks a major/LTS/latest: gets the fix only after a
#                reinstall/redeploy/rebuild (docker build --pull)
#    MANAGED     platform runtime (AWS Lambda, App Engine...): provider patches
#    CHECK       distro build or range: confirm the real installed version
#    EXPOSED     app decodes Brotli request bodies (Express 5 / body-parser 2.x):
#                safe only on a patched Node; inflate:false or block br until then
#    HIDDEN      site looks Node-based but hides its version
#    NO-NODE     nothing Node-related found
#    ERROR       target did not respond / unreadable
#
#  Exit codes: 0 all clear, 1 needs attention, 2 at-risk found, 3 usage error
# =====================================================================

. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
usage() { sed -n '2,/^# ====/p' "$0" | sed 's/^#//'; exit 0; }

# ---------- main ---------------------------------------------------------------------

FILE=""; OUT="node-sec-report"; LOCAL=0; TARGETS=(); PROJECTS=(); ADV=""
while [ $# -gt 0 ]; do
  case "$1" in
    -f|--file)   FILE="$2"; shift 2;;
    -o|--out)    OUT="$2"; shift 2;;
    --local)     LOCAL=1; shift;;
    --project)   PROJECTS+=("$2"); shift 2;;
    --advisory)  ADV="$2"; shift 2;;
    -h|--help)   usage;;
    -*)          echo "Unknown option: $1"; exit 3;;
    *)           TARGETS+=("$1"); shift;;
  esac
done
load_advisory "$ADV"
if [ -n "$FILE" ]; then
  [ -r "$FILE" ] || { echo "Cannot read $FILE"; exit 3; }
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | tr -d '\r' | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$line" ] && TARGETS+=("$line")
  done < "$FILE"
fi
if [ "$LOCAL" -eq 0 ] && [ ${#TARGETS[@]} -eq 0 ] && [ ${#PROJECTS[@]} -eq 0 ]; then usage; fi
if [ ${#TARGETS[@]} -gt 0 ] && ! command -v curl >/dev/null 2>&1; then echo "curl is required for URL checks"; exit 3; fi
mkdir -p "$(dirname "$OUT")" 2>/dev/null

printf '\n%sNode.js security check%s  %s(%s)%s\n' "$BD$C" "$N" "$D" "$ADVISORY_NAME" "$N"
printf '%sFixed: %s   Supported lines: %s   All other lines: EOL, no fix%s\n\n' "$D" "$(echo $FIXED_VERSIONS | sed 's/ / | /g')" "$(supported_list)" "$N"

[ "$LOCAL" -eq 1 ] && local_scan
for p in "${PROJECTS[@]}"; do project_scan "$p"; done
for t in "${TARGETS[@]}"; do scan_url "$t"; done

write_csv "$OUT"; write_html "$OUT"
printf '%sSummary:%s %s%d at risk%s, %s%d need action/check%s, %s%d patched%s, %d managed/no Node\n' \
  "$BD" "$N" "$R" "$CNT_RISK" "$N" "$Y" "$CNT_CHK" "$N" "$G" "$CNT_OK" "$N" "$CNT_OTH"
printf 'Report: %s.html  |  %s.csv\n\n' "$OUT" "$OUT"
exit "$WORST"
