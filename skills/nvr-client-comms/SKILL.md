---
name: nvr-client-comms
description: Bilingual (English/Spanish) messages for a Node.js security release - client or colleague advisory, hosting/platform ticket, patched confirmation, end-of-life upgrade proposal, compromise notice. Use for "tell my clients", "email the team", "ticket to the host", "avísale a mis clientes", "escribe al hosting", "redacta el correo".
---

# Client, Colleague and Provider Communications

Follow **nvr-navigator** rules: facts come from the advisory, the scan/verify reports
and `nvr-log.md`. Never call an app safe without verify PASS; never claim it was not
compromised, only what was checked.

| Situation | Template (`templates/`) |
|---|---|
| First notice: we know, we are checking | `client-advisory.md` |
| Managed host / PaaS must act or confirm | `host-ticket.md` |
| Patched and verified | `patched-confirmation.md` |
| App on an EOL Node line | `eol-upgrade-proposal.md` |
| Compromise confirmed or strongly suspected | `compromise-notice.md` |

## How to fill

1. Client's language (EN or ES; Puerto Rico clients often prefer Spanish, ask if unsure).
2. Replace every `{{placeholder}}` from real data: `{{RELEASE_DATE}}`,
   `{{FIXED_VERSIONS}}`, `{{CVE_COUNT}}` (10), `{{TOP_CVE}}` (CVE-2026-111497, Brotli
   decoder RCE, in the press as "HTTP2Shell" or "Node2Shell") come from the advisory.
   If clients ask about HTTP2Shell, it is the same issue: say whether their app's Node,
   Bun or server Brotli library was updated. Unknown value: ask or drop the sentence.
3. Short and calm: what happened, what it means, what we did, what they do (often
   nothing), when they hear next.
4. No exploit details, internal hostnames, IPs or secrets.
5. For colleagues, the HTML report from `scan.sh` is a good attachment.
6. Draft only; sending is an action the user approves.
