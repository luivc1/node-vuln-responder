#!/usr/bin/env bash
# =====================================================================
#  install.sh  -  one-shot installer for node-vuln-responder
#
#  ./install.sh --target claude          # skills -> ~/.claude/skills
#  ./install.sh --target hermes          # skills -> ~/.hermes/skills
#  ./install.sh --dest /path/to/skills   # any Agent Skills loader / project
#  ./install.sh --uninstall [--target X | --dest DIR]
#
#  Always installs the toolkit (scripts, advisories) to ~/.node-vuln-responder
#  (override with NVR_HOME=...). Skills look there automatically.
#
#  Claude Code users can instead install as a plugin (adds slash commands,
#  the nvr-verifier agent and the safety hook):
#    /plugin marketplace add <this folder or GitHub repo>
#    /plugin install node-vuln-responder@node-vuln-responder
# =====================================================================
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
NVR_HOME="${NVR_HOME:-$HOME/.node-vuln-responder}"
DEST=""; UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      case "$2" in
        claude) DEST="$HOME/.claude/skills";;
        hermes) DEST="$HOME/.hermes/skills";;
        *) echo "Unknown target '$2' (use claude, hermes, or --dest DIR)"; exit 3;;
      esac; shift 2;;
    --dest) DEST="$2"; shift 2;;
    --uninstall) UNINSTALL=1; shift;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^#//'; exit 0;;
    *) echo "Unknown option: $1"; exit 3;;
  esac
done

if [ "$UNINSTALL" -eq 1 ]; then
  if [ -n "$DEST" ]; then
    for s in "$SRC"/skills/nvr-*; do rm -rf "$DEST/$(basename "$s")"; done
    echo "Removed nvr-* skills from $DEST"
  fi
  rm -rf "$NVR_HOME"; echo "Removed $NVR_HOME"
  exit 0
fi

mkdir -p "$NVR_HOME"
cp -R "$SRC/scripts" "$SRC/advisories" "$SRC/standalone" "$SRC/AGENTS.md" "$NVR_HOME/"
chmod +x "$NVR_HOME"/scripts/*.sh
echo "Toolkit installed: $NVR_HOME"

if [ -n "$DEST" ]; then
  mkdir -p "$DEST"
  for s in "$SRC"/skills/nvr-*; do
    rm -rf "$DEST/$(basename "$s")"
    cp -R "$s" "$DEST/"
  done
  echo "Skills installed: $DEST ($(ls -d "$SRC"/skills/nvr-* | wc -l | tr -d ' ') skills)"
fi

echo
echo "Quick test:  bash $NVR_HOME/scripts/scan.sh --local"
echo "Ask your agent:  \"Are my Node apps affected by the October 2026 Node.js security release?\"  /  \"¿Mis apps de Node están vulnerables?\""
