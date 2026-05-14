---
description: Remove the stored Logfire OAuth token
allowed-tools: Bash(python3 *)
---

Delete the OAuth token bundle from `~/.logfire/claude-code-oauth.json` for the
configured base URL. After logout the plugin falls back to `LOGFIRE_TOKEN`
(or stays silent if no token is configured).

!`python3 "$CLAUDE_PLUGIN_ROOT/scripts/auth.py" logout ${LOGFIRE_BASE_URL:+--base-url "$LOGFIRE_BASE_URL"}`
