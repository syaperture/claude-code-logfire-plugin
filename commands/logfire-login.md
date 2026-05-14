---
description: Log in to Logfire via OAuth device flow (alternative to LOGFIRE_TOKEN)
allowed-tools: Bash(python3 *)
---

Run the OAuth device authorization flow against Logfire and persist a token
bundle the plugin will auto-refresh on every Claude Code session.

Use this instead of setting a fixed `LOGFIRE_TOKEN`. Once logged in, the plugin
silently refreshes the access token whenever it's near expiry (no manual
re-login until the refresh token itself is revoked).

Run the login script. Use `$LOGFIRE_BASE_URL` if set so the user keeps using
their chosen region (US/EU/staging/self-hosted); otherwise the script defaults
to the US region. Stream the output so the user sees the verification URL and
user code:

!`python3 "$CLAUDE_PLUGIN_ROOT/scripts/auth.py" login ${LOGFIRE_BASE_URL:+--base-url "$LOGFIRE_BASE_URL"}`
