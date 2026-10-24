#!/usr/bin/env bash
# Rebuilds standalone/node-sec-check.sh from scripts/scan.sh + scripts/lib.sh.
# Run after changing either file:  bash tools/build-standalone.sh
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/standalone/node-sec-check.sh"
VER="${1:-1.1.0}"
LIB="$ROOT/scripts/lib.sh"; SCAN="$ROOT/scripts/scan.sh"
{
  echo '#!/usr/bin/env bash'
  # header comment from scan.sh, renamed
  awk 'NR==2{print; next} NR>2 && /^# =====/{print; exit} NR>2{print}' "$SCAN" \
    | sed -e "s/scan\.sh  (node-vuln-responder)/node-sec-check  v$VER/" -e 's/scan\.sh /node-sec-check.sh /g'
  echo
  # advisory defaults and shared state (no file loading in the single-file build)
  awk '/^# ---------- advisory/{f=1} /^# ---------- version logic/{exit} f' "$LIB"
  echo "usage() { sed -n '2,/^# ====/p' \"\$0\" | sed 's/^#//'; exit 0; }"
  echo
  # everything else in lib.sh up to load_advisory
  awk '/^# ---------- version logic/{f=1} /^# load_advisory/{exit} f' "$LIB"
  # main from scan.sh, with inline advisory loading
  awk '/^# ---------- main/{f=1} f' "$SCAN" \
    | sed 's|^load_advisory "\$ADV"$|if [ -n "$ADV" ]; then [ -r "$ADV" ] \|\| { echo "Cannot read advisory $ADV"; exit 3; }; . "$ADV"; fi|'
} > "$OUT"
chmod +x "$OUT"
bash -n "$OUT"
echo "built $OUT"
