---
description: Show stored Logfire OAuth token status (expiry, scope, etc.)
allowed-tools: Bash(python3 *)
---

Print metadata about the OAuth token bundle the plugin is using: the base URL,
scope, client_id, time until expiry, and whether a refresh token is present.
Does not display the access token itself.

!`python3 "$CLAUDE_PLUGIN_ROOT/scripts/auth.py" status ${LOGFIRE_BASE_URL:+--base-url "$LOGFIRE_BASE_URL"}`
