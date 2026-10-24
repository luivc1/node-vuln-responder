#!/usr/bin/env bash
# PreToolUse guard (Claude Code). Reads the tool call JSON on stdin.
#  - DENY fetching/running exploit or PoC code (nvr rule 4)
#  - ASK for changes to Node runtimes or Node apps: version installs/switches,
#    package changes, PM2/service restarts, container redeploys, global npm
#    changes, edits/deletions in app folders. Read-only commands pass through.
IN=$(cat)
if command -v jq >/dev/null 2>&1; then
  CMD=$(printf '%s' "$IN" | jq -r '.tool_input.command // empty' 2>/dev/null)
elif command -v python3 >/dev/null 2>&1; then
  CMD=$(printf '%s' "$IN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))' 2>/dev/null)
else
  CMD=$IN
fi
[ -z "$CMD" ] && exit 0
LC=$(printf '%s' "$CMD" | tr 'A-Z' 'a-z')
decide() { printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' "$1" "$2"; exit 0; }

if echo "$LC" | grep -qE '(git clone|curl|wget|npm i(nstall)?|npx|pip install)[^|;&]*(poc|exploit|cve-20[0-9]{2}-[0-9]+-(poc|exploit|rce))'; then
  decide deny "node-vuln-responder: fetching or running exploit/PoC code is not allowed. Verify by version evidence instead."
fi

if echo "$LC" | grep -qE '(^|[;&|[:space:]])(nvm (install|alias|use|uninstall)|fnm (install|default|use|uninstall)|volta (install|pin|uninstall)|asdf (install|set|global|uninstall)|mise (use|install|uninstall)|nodenv (install|global)|sudo n |n [0-9]|brew (upgrade|install|uninstall|link)|[^[:space:]]*bun upgrade|bun[[:space:]]+(add|update|install)[[:space:]]+(-g|--global))'; then
  decide ask "node-vuln-responder: this installs or switches a Node or Bun version. Approve this exact command?"
fi
NODECTX='node|npm|nodesource|ea-nodejs|alt-nodejs|pm2|next|nuxt|express|docker compose|docker-compose|brotli|bun'
if echo "$LC" | grep -qE '(apt(-get)?|dnf|yum|apk|zypper)[[:space:]]+(-[a-z-]+[[:space:]]+)*(install|upgrade|update|remove|purge|erase|downgrade|history[[:space:]]+undo)' && echo "$LC" | grep -qE "$NODECTX"; then
  decide ask "node-vuln-responder: package change affecting Node. Confirm a backup and approve this exact command."
fi
if echo "$LC" | grep -qE 'pm2[[:space:]]+(update|restart|reload|stop|delete|kill|start|save)|systemctl[[:space:]]+(restart|stop|reload|disable)|docker( compose|-compose)[[:space:]]+(up|down|build|restart|rm)|docker[[:space:]]+(restart|stop|rm|run)|npm[[:space:]]+(i|install|uninstall|update|rebuild)[[:space:]].*(-g|--global)|plesk installer|touch[[:space:]][^;]*tmp/restart\.txt'; then
  decide ask "node-vuln-responder: restart/redeploy or global change (brief downtime possible). Approve?"
fi
if echo "$LC" | grep -qE '(^|[;&|[:space:]])(rm|mv|shred|truncate|unlink|sed[[:space:]]+-i|chmod|chown)[[:space:]]' && echo "$LC" | grep -qE '/(srv|var/www|opt/apps|app|home/[^/ ]+/(apps?|nodeapps))|node_modules|\.pm2|\.env'; then
  decide ask "node-vuln-responder: this modifies files in a Node app location. Evidence must be copied first. Approve?"
fi
exit 0
