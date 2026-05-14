"""OAuth token storage and refresh for the Logfire plugin.

Stdlib-only helpers shared by ``auth.py`` (interactive device flow login) and
``log-event.py`` (hot-path hook handler that needs a valid access token).

A token "bundle" is persisted per-base-URL at
``~/.logfire/claude-code-logfire-plugin.json`` with mode 0600:

```json
{
  "tokens": {
    "https://logfire-us.pydantic.dev": {
      "access_token": "...",
      "refresh_token": "...",
      "expires_at": 1234567890.0,
      "scope": "project:write_otlp",
      "client_id": "<DCR-registered>",
      "resource": "https://logfire-us.pydantic.dev/v1/traces"
    }
  }
}
```

The file is rewritten atomically (``mkstemp`` + ``os.replace``) and refresh is
serialised across sessions via an ``os.mkdir`` lock to keep refresh-token
rotation from racing when several Claude Code sessions start simultaneously.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_BASE_URL = "https://logfire-us.pydantic.dev"
DEFAULT_SCOPE = "project:write_otlp"

# Refresh the access token when this many seconds (or fewer) remain before
# expiry. Matches the buffer used by ``scripts/oauth_intake_example.py`` in
# the platform repo.
REFRESH_BUFFER_SECONDS = 60

# Cap how long we wait for the cross-session refresh lock. Hooks have a hard
# timeout (10s for Stop/PreToolUse, 30s for SessionEnd), so we must give up
# well before that to leave time for the OTLP send itself.
LOCK_MAX_WAIT_SECONDS = 5.0
LOCK_POLL_INTERVAL = 0.1
LOCK_STALE_SECONDS = 30

TOKEN_DIR = Path.home() / ".logfire"
TOKEN_FILE = TOKEN_DIR / "claude-code-logfire-plugin.json"
LOCK_DIR = TOKEN_DIR / ".claude-code-logfire-plugin.lock"


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def _read_store() -> dict:
    try:
        with open(TOKEN_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"tokens": {}}
    if not isinstance(data, dict) or "tokens" not in data:
        return {"tokens": {}}
    return data


def _write_store(data: dict) -> None:
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="claude-code-logfire-plugin.", dir=str(TOKEN_DIR))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(TOKEN_FILE))
        try:
            os.chmod(str(TOKEN_FILE), 0o600)
        except OSError:
            pass
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Cross-process lock (matches the pattern in log-event.py)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _lock():
    """Best-effort cross-process lock around the token store.

    Yields ``True`` if the lock was acquired, ``False`` if we timed out.
    Callers that mutate state should still proceed on ``False``
    (last-writer-wins beats dropping a freshly-issued token on the floor);
    callers that race refresh-token rotation should bail on ``False``.

    The release is gated on actual acquisition so a nested ``_lock()`` —
    e.g. a refresh path that re-enters via ``save_bundle`` — can't tear
    down its caller's lock.
    """
    acquired = False
    deadline = time.time() + LOCK_MAX_WAIT_SECONDS
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            os.mkdir(LOCK_DIR)
            acquired = True
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(LOCK_DIR) > LOCK_STALE_SECONDS:
                    try:
                        os.rmdir(LOCK_DIR)
                    except OSError:
                        pass
                    continue
            except OSError:
                pass
            if time.time() >= deadline:
                break
            time.sleep(LOCK_POLL_INTERVAL)
    try:
        yield acquired
    finally:
        if acquired:
            try:
                os.rmdir(LOCK_DIR)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Bundle accessors
# ---------------------------------------------------------------------------


def load_bundle(base_url: str) -> dict | None:
    return _read_store().get("tokens", {}).get(base_url.rstrip("/"))


def _save_bundle_unlocked(base_url: str, bundle: dict) -> None:
    """Write ``bundle`` for ``base_url`` without taking the lock. Callers
    must already hold ``_lock()`` (used by the refresh path, which can't
    re-enter the lock it already owns)."""
    key = base_url.rstrip("/")
    data = _read_store()
    data.setdefault("tokens", {})[key] = bundle
    _write_store(data)


def save_bundle(base_url: str, bundle: dict) -> None:
    with _lock():
        _save_bundle_unlocked(base_url, bundle)


def delete_bundle(base_url: str) -> None:
    key = base_url.rstrip("/")
    with _lock():
        data = _read_store()
        tokens = data.get("tokens", {})
        if key in tokens:
            del tokens[key]
            data["tokens"] = tokens
            _write_store(data)


def list_base_urls() -> list:
    return list(_read_store().get("tokens", {}).keys())


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------


def _http_get_json(url: str, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _http_post_form(url: str, fields: dict, timeout: float = 30.0) -> dict:
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _http_post_json(url: str, body: dict, timeout: float = 30.0) -> dict:
    raw = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=raw,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def discover_metadata(base_url: str) -> dict:
    """RFC 8414 OAuth Authorization Server Metadata."""
    return _http_get_json(base_url.rstrip("/") + "/.well-known/oauth-authorization-server")


def discover_resource(base_url: str) -> str:
    """RFC 9728 protected-resource metadata — the JWT ``aud`` value the
    intake expects. Falls back to ``base_url`` if the endpoint is unavailable
    (e.g. self-hosted deployments without the metadata route)."""
    try:
        data = _http_get_json(base_url.rstrip("/") + "/.well-known/oauth-protected-resource/v1")
    except (urllib.error.URLError, OSError, ValueError):
        return base_url.rstrip("/")
    resource = data.get("resource")
    if isinstance(resource, str) and resource:
        return resource
    return base_url.rstrip("/")


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------


def _bundle_from_token_response(
    token: dict,
    *,
    client_id: str,
    resource: str,
    fallback_refresh: str = "",
    fallback_scope: str = "",
) -> dict:
    return {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token") or fallback_refresh,
        "expires_at": time.time() + int(token.get("expires_in", 0)),
        "scope": token.get("scope") or fallback_scope,
        "client_id": client_id,
        "resource": resource,
    }


def _refresh(bundle: dict, base_url: str) -> dict:
    """Exchange the refresh_token for a new access token. Raises on failure."""
    metadata = discover_metadata(base_url)
    resource = bundle.get("resource") or discover_resource(base_url)
    fields = {
        "grant_type": "refresh_token",
        "refresh_token": bundle["refresh_token"],
        "client_id": bundle.get("client_id", ""),
        "scope": bundle.get("scope") or DEFAULT_SCOPE,
    }
    if resource:
        # RFC 8707 — required when the bundle was originally issued with
        # one, since the AS verifies the resource matches across refreshes.
        fields["resource"] = resource
    token = _http_post_form(metadata["token_endpoint"], fields)
    new_bundle = _bundle_from_token_response(
        token,
        client_id=bundle.get("client_id", ""),
        resource=resource,
        fallback_refresh=bundle["refresh_token"],
        fallback_scope=bundle.get("scope", ""),
    )
    # We're called from inside ``_lock()`` (via ``get_access_token``), so
    # use the unlocked save to avoid the lock's 5-second timeout waiting on
    # ourselves.
    _save_bundle_unlocked(base_url, new_bundle)
    return new_bundle


def force_refresh(base_url: str) -> dict:
    """Force a refresh of the stored bundle for ``base_url`` and return it.

    Raises ``LookupError`` if there's no stored bundle (or no refresh token
    to exchange), ``RuntimeError`` if the cross-process lock can't be
    acquired, and the underlying ``urllib`` error if the AS rejects the
    refresh. Intended for the ``/logfire-refresh`` slash command —
    ``get_access_token`` already refreshes lazily for the hook hot path.
    """
    key = base_url.rstrip("/")
    with _lock() as acquired:
        if not acquired:
            raise RuntimeError(f"Could not acquire token-store lock for {key}")
        bundle = load_bundle(key)
        if not bundle:
            raise LookupError(f"No stored token for {key}")
        if not bundle.get("refresh_token"):
            raise LookupError(f"Stored token for {key} has no refresh_token; run `login` again")
        return _refresh(bundle, key)


def get_access_token(base_url: str) -> str | None:
    """Return a valid access token for ``base_url``, refreshing if needed.

    Returns ``None`` if no bundle is stored, or if the token has expired and
    cannot be refreshed. Designed to be called from the hook hot path so it
    must never raise.
    """
    key = base_url.rstrip("/")
    bundle = load_bundle(key)
    if not bundle:
        return None

    now = time.time()
    expires_at = float(bundle.get("expires_at") or 0)
    if expires_at > now + REFRESH_BUFFER_SECONDS:
        return bundle.get("access_token") or None

    if not bundle.get("refresh_token"):
        # No refresh capability — return what we have if it's still valid,
        # else give up.
        if expires_at > now:
            return bundle.get("access_token") or None
        return None

    # Serialise refresh across sessions so refresh-token rotation doesn't
    # race itself into a 4xx.
    with _lock() as acquired:
        if not acquired:
            # Couldn't lock — fall back to the existing access token if it
            # still has any life in it.
            if expires_at > now:
                return bundle.get("access_token") or None
            return None
        # Another session may have already refreshed while we waited.
        latest = load_bundle(key) or bundle
        latest_expires = float(latest.get("expires_at") or 0)
        if latest_expires > now + REFRESH_BUFFER_SECONDS:
            return latest.get("access_token") or None
        try:
            refreshed = _refresh(latest, key)
            return refreshed.get("access_token") or None
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError, KeyError):
            if latest_expires > now:
                return latest.get("access_token") or None
            return None
