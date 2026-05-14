#!/usr/bin/env python3
"""OAuth 2.0 Device Authorization Grant CLI for the Logfire plugin.

Lets a user log in to Logfire interactively and persist an access /
refresh-token bundle that ``log-event.py`` then uses on every hook
invocation instead of a fixed ``LOGFIRE_TOKEN``.

Subcommands
-----------
    login    Run the device flow against ``LOGFIRE_BASE_URL`` (or --base-url)
             and save the resulting tokens under ``~/.logfire/claude-code-oauth.json``.
    logout   Remove the stored tokens for a base URL.
    status   Show whether a token is stored, when it expires, and which scopes
             it carries.

The flow performs Dynamic Client Registration (RFC 7591) for a public client
on first login, then RFC 8628 device authorization with PKCE (RFC 7636). The
``project:write_otlp`` scope is requested by default — the same scope the
Fusionfire intake checks on ``/v1/traces``.

Usage
-----
    python3 scripts/auth.py login
    python3 scripts/auth.py login --base-url https://logfire-eu.pydantic.dev
    python3 scripts/auth.py status
    python3 scripts/auth.py logout

Stdlib only — runs on the same Python 3.7+ baseline as the rest of the plugin.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

# Allow ``python3 scripts/auth.py ...`` to import ``oauth_token`` without
# needing the directory on PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from oauth_token import (  # noqa: E402
    DEFAULT_BASE_URL,
    DEFAULT_SCOPE,
    _bundle_from_token_response,
    delete_bundle,
    discover_metadata,
    discover_resource,
    load_bundle,
    save_bundle,
)

CLIENT_NAME = "claude-code-logfire-plugin"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------


def _pkce_pair() -> tuple:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


# ---------------------------------------------------------------------------
# Network helpers (stdlib + readable error surfacing)
# ---------------------------------------------------------------------------


def _extract_oauth_error(body: bytes) -> tuple:
    """Pull a (code, description) tuple out of an OAuth error response.

    Logfire wraps OAuth errors in a FastAPI ``detail`` envelope; spec-pure
    servers put the fields at the top level. Handle both.
    """
    try:
        data = json.loads(body.decode())
    except (ValueError, UnicodeDecodeError):
        return "", body[:200].decode(errors="replace")
    if isinstance(data, dict):
        detail = data.get("detail") if isinstance(data.get("detail"), dict) else None
        source = detail or data
        return source.get("error", ""), source.get("error_description", "")
    return "", ""


def _post_form(url: str, fields: dict, timeout: float = 30.0) -> dict:
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


def _post_json(url: str, body: dict, timeout: float = 30.0) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


# ---------------------------------------------------------------------------
# Device flow
# ---------------------------------------------------------------------------


def register_client(metadata: dict, scope: str) -> str:
    """RFC 7591 Dynamic Client Registration — produces a public client_id
    bound to the device-code + refresh-token grants and the requested scope."""
    if "registration_endpoint" not in metadata:
        raise SystemExit(
            "Authorization server does not advertise a registration_endpoint. "
            "Pass --client-id to use a pre-registered OAuth client instead."
        )
    body = {
        "client_name": CLIENT_NAME,
        "grant_types": [DEVICE_CODE_GRANT, "refresh_token"],
        "token_endpoint_auth_method": "none",
        "redirect_uris": [],
        "scope": scope,
    }
    return _post_json(metadata["registration_endpoint"], body)["client_id"]


def request_device_code(
    metadata: dict,
    *,
    client_id: str,
    code_challenge: str,
    scope: str,
    resource: str,
) -> dict:
    fields = {
        "client_id": client_id,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if resource:
        fields["resource"] = resource
    return _post_form(metadata["device_authorization_endpoint"], fields)


def poll_for_token(
    metadata: dict,
    *,
    client_id: str,
    device_code: str,
    code_verifier: str,
    resource: str,
    interval: int,
    expires_in: int,
) -> dict:
    deadline = time.time() + expires_in
    delay = max(interval, 1)
    while time.time() < deadline:
        time.sleep(delay)
        fields = {
            "grant_type": DEVICE_CODE_GRANT,
            "device_code": device_code,
            "client_id": client_id,
            "code_verifier": code_verifier,
        }
        if resource:
            fields["resource"] = resource
        try:
            return _post_form(metadata["token_endpoint"], fields)
        except urllib.error.HTTPError as e:
            code, desc = _extract_oauth_error(e.read())
            if code == "authorization_pending":
                continue
            if code == "slow_down":
                delay += 5
                continue
            if code == "access_denied":
                raise SystemExit("Authorization denied") from None
            if code == "expired_token":
                raise SystemExit("Device code expired before authorization completed") from None
            raise SystemExit(f"Device flow failed: {code or e.code} {desc}".rstrip()) from None
    raise SystemExit("Device code expired before authorization completed")


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_login(args: argparse.Namespace) -> int:
    base_url = args.base_url.rstrip("/")
    scope = args.scope
    print(f"Discovering OAuth metadata for {base_url} ...")
    metadata = discover_metadata(base_url)
    resource = "" if args.no_resource else discover_resource(base_url)

    if args.client_id:
        client_id = args.client_id
        print(f"Using pre-registered client_id={client_id}")
    else:
        print("Registering OAuth client (RFC 7591) ...")
        client_id = register_client(metadata, scope)
        print(f"Registered client_id={client_id}")

    verifier, challenge = _pkce_pair()
    device = request_device_code(
        metadata,
        client_id=client_id,
        code_challenge=challenge,
        scope=scope,
        resource=resource,
    )

    verification_url = device.get("verification_uri_complete") or device["verification_uri"]
    user_code = device.get("user_code", "")
    expires_in = int(device.get("expires_in", 600))
    interval = int(device.get("interval", 5))

    print()
    print(f"User code: {user_code}")
    print(f"Open this URL to authorize: {verification_url}")
    print(f"Code expires in {expires_in}s")
    print()

    if not args.no_browser:
        try:
            webbrowser.open(verification_url)
        except webbrowser.Error:
            pass

    print("Waiting for browser authorization (Ctrl+C to cancel) ...")
    token = poll_for_token(
        metadata,
        client_id=client_id,
        device_code=device["device_code"],
        code_verifier=verifier,
        resource=resource,
        interval=interval,
        expires_in=expires_in,
    )

    bundle = _bundle_from_token_response(
        token,
        client_id=client_id,
        resource=resource,
        fallback_scope=scope,
    )
    save_bundle(base_url, bundle)
    print()
    print(f"Logged in to {base_url}")
    print(f"  scope:      {bundle.get('scope', '')}")
    print(f"  expires in: {int(bundle['expires_at'] - time.time())}s")
    print("  stored at:  ~/.logfire/claude-code-oauth.json")
    print()
    print("To use OAuth instead of LOGFIRE_TOKEN, unset LOGFIRE_TOKEN in your shell")
    print("and (optionally) export LOGFIRE_BASE_URL if you're not using the US region.")
    return 0


def cmd_logout(args: argparse.Namespace) -> int:
    base_url = args.base_url.rstrip("/")
    if not load_bundle(base_url):
        print(f"No stored token for {base_url}")
        return 0
    delete_bundle(base_url)
    print(f"Removed stored token for {base_url}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    base_url = args.base_url.rstrip("/")
    bundle = load_bundle(base_url)
    if not bundle:
        print(f"Not logged in to {base_url}")
        return 1
    remaining = int(float(bundle.get("expires_at", 0)) - time.time())
    state = "valid" if remaining > 0 else "expired (refresh on next use)"
    print(f"Base URL:   {base_url}")
    print(f"Client ID:  {bundle.get('client_id', '')}")
    print(f"Scope:      {bundle.get('scope', '')}")
    print(f"Resource:   {bundle.get('resource', '') or '(none)'}")
    print(f"Expires in: {remaining}s ({state})")
    print(f"Has refresh token: {'yes' if bundle.get('refresh_token') else 'no'}")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _default_base_url() -> str:
    return os.environ.get("LOGFIRE_BASE_URL", DEFAULT_BASE_URL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--base-url",
        default=_default_base_url(),
        help="Logfire base URL (default: $LOGFIRE_BASE_URL or %(default)s)",
    )
    sub = parser.add_subparsers(dest="cmd")

    login_p = sub.add_parser("login", help="Run device flow and store a token bundle")
    login_p.add_argument(
        "--client-id",
        default=None,
        help="Pre-registered OAuth client_id to use instead of Dynamic Client Registration",
    )
    login_p.add_argument(
        "--scope",
        default=DEFAULT_SCOPE,
        help=f"OAuth scope to request (default: {DEFAULT_SCOPE})",
    )
    login_p.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't try to open the verification URL in a browser",
    )
    login_p.add_argument(
        "--no-resource",
        action="store_true",
        help="Skip RFC 8707 resource discovery (use only for non-standard backends)",
    )

    sub.add_parser("logout", help="Remove the stored token for --base-url")
    sub.add_parser("status", help="Print info about the stored token for --base-url")

    args = parser.parse_args()
    if args.cmd == "login":
        return cmd_login(args)
    if args.cmd == "logout":
        return cmd_logout(args)
    if args.cmd == "status":
        return cmd_status(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        sys.exit(130)
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        code, desc = _extract_oauth_error(body)
        if code:
            print(f"HTTP {exc.code}: {code} {desc}".rstrip(), file=sys.stderr)
        else:
            print(f"HTTP {exc.code}: {body[:500].decode(errors='replace')}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Network error: {exc.reason}", file=sys.stderr)
        sys.exit(1)
