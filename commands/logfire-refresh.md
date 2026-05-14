---
description: Force-refresh the stored Logfire OAuth access token
allowed-tools: Bash(python3 *)
---

Force an OAuth refresh against the Logfire authorization server using the
stored refresh token, even if the access token isn't near expiry. The plugin's
hooks already refresh lazily on every invocation, so this is mostly useful for
debugging or to deliberately cycle the access token without re-running the
device flow.

!`python3 "$CLAUDE_PLUGIN_ROOT/scripts/auth.py" refresh ${LOGFIRE_BASE_URL:+--base-url "$LOGFIRE_BASE_URL"}`
