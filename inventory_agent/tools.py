"""Inventory tool for the agent: a client of the token issuer and the inventory service.

The model calls get_stock(sku), exactly as on Days 01-02. Inside:

    1. Get an access token for (issuer, client, requested scope):
         - reuse a cached token while it has > REFRESH_MARGIN_SECONDS left, or
         - POST {issuer}/token with X-Client-ID / X-Client-Secret / X-Scope
    2. GET {service}/stock/{sku} with Authorization: Bearer <jwt>
         - 401 on a CACHED token -> discard it, get a new one, retry ONCE
         - 403 -> stop: a fresh token with the same scope can't fix it

Day 05.5: the requested scope comes from INVENTORY_REQUESTED_SCOPE (config,
never the model). Day 05.6: tokens have a lifecycle (issue, reuse, renew,
expire). No refresh tokens: renewal re-authenticates with client credentials.

This module never touches a private key, the jwt library, sqlite3, or
inventory_service. Any failure fails closed: no local database fallback.
"""

import hashlib
import logging
import os
import threading
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from dotenv import load_dotenv

# Agent-side configuration only (inventory_agent/.env).
load_dotenv(Path(__file__).resolve().parent / ".env")

DEFAULT_SERVICE_URL = "http://127.0.0.1:8000"
DEFAULT_ISSUER_URL = "http://127.0.0.1:8001"
DEFAULT_DELEGATION_URL = "http://127.0.0.1:8004"
DELEGATION_REQUEST_SCOPE = "delegation.request"
TIMEOUT_SECONDS = 5.0
REFRESH_MARGIN_SECONDS = 30  # renew a token this long before it expires

_UNAVAILABLE = {"status": "error", "message": "Inventory is temporarily unavailable."}
_UNAUTHENTICATED = {
    "status": "unauthenticated",
    "message": "Inventory access could not be authenticated.",
}
_FORBIDDEN = {
    "status": "forbidden",
    "message": "This agent is not permitted to read inventory.",
}

# Shows each step of the security flow. Never logs secrets or tokens.
logger = logging.getLogger("inventory_agent.flow")

# Token cache: {cache_key: (token, expires_at)}. One entry per authority boundary:
# a class_b token is never handed out for a class_a request.
_cache: dict[tuple, tuple[str, float]] = {}
_cache_lock = threading.Lock()


def _now() -> float:
    """Monotonic clock: unaffected by wall-clock changes. Tests replace this."""
    return time.monotonic()


def get_stock(sku: str) -> dict:
    """Return the inventory record for a SKU.

    Args:
        sku: The stock-keeping unit to look up, for example "WIDGET-A".
             Surrounding whitespace is ignored and the value is upper-cased.

    Returns:
        A dict whose "status" is one of:
        - "found": includes "sku", "name", and "quantity". A quantity of 0
          means the item exists but is out of stock.
        - "not_found": the SKU is not in the inventory.
        - "unauthenticated": inventory access could not be authenticated.
        - "forbidden": this agent is authenticated but not permitted to read inventory.
        - "error": inventory could not be reached; includes "message".
    """
    return fetch_stock(sku)


def fetch_stock(sku: str, *, forwarded_human: str | None = None,
                delegation_token: str | None = None) -> dict:
    """get_stock for application code (not the model).

    06.09A: forwarded_human -> X-Human-User, an UNVERIFIED assertion (logged only).
    06.09B: delegation_token -> X-Delegation-Token, a signed grant the service verifies."""
    normalized_sku = sku.strip().upper()

    request, failure = _token_request()
    if failure:
        return failure

    # Step 1: a token for exactly this client and scope (cached or new).
    token, from_cache, failure = _get_token(request)
    if failure:
        return failure

    # Step 2: call the service.
    response = _call_service(normalized_sku, token, forwarded_human, delegation_token)
    if response is None:
        return dict(_UNAVAILABLE)

    # 401 on a token we reused: it may have expired or been invalidated early.
    # Renew once and retry once. Never loop.
    if response.status_code == 401 and from_cache:
        logger.warning("    cached token rejected (401): discarding it, renewing once, retrying once")
        _invalidate(request["key"])
        token, _, failure = _get_token(request, force_new=True)
        if failure:
            return failure
        response = _call_service(normalized_sku, token, forwarded_human, delegation_token)
        if response is None:
            return dict(_UNAVAILABLE)

    return _map_service_response(response, normalized_sku, request["key"])


# --------------------------------------------------------------------------- #
# Token lifecycle
# --------------------------------------------------------------------------- #
def _token_request(scope_override: str | None = None) -> tuple[dict | None, dict | None]:
    """Collect issuer settings from config. Fail closed if anything is missing."""
    client_id = os.environ.get("INVENTORY_CLIENT_ID")
    client_secret = os.environ.get("INVENTORY_CLIENT_SECRET")
    if not client_id or not client_secret:
        logger.warning("1/2 no client credentials configured; not calling the issuer")
        return None, dict(_UNAUTHENTICATED)

    raw_scope = scope_override if scope_override is not None else os.environ.get("INVENTORY_REQUESTED_SCOPE", "")
    scope = " ".join(sorted(set(raw_scope.split())))
    if not scope:
        logger.warning("1/2 no INVENTORY_REQUESTED_SCOPE configured; not calling the issuer")
        return None, dict(_UNAVAILABLE)  # never ask for "whatever I'm entitled to"

    issuer_url = os.environ.get("INVENTORY_ISSUER_URL", DEFAULT_ISSUER_URL).rstrip("/")
    # The secret itself is never stored in the key, only a fingerprint of it.
    secret_fp = hashlib.sha256(client_secret.encode()).hexdigest()[:16]
    return {
        "issuer_url": issuer_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "key": (issuer_url, client_id, secret_fp, scope),
    }, None


def _get_token(request: dict, *, force_new: bool = False) -> tuple[str | None, bool, dict | None]:
    """Return (token, came_from_cache, failure)."""
    key = request["key"]
    if not force_new:
        with _cache_lock:
            cached = _cache.get(key)
        if cached:
            token, expires_at = cached
            remaining = expires_at - _now()
            if remaining > REFRESH_MARGIN_SECONDS:
                logger.info("1/2 reusing cached token  scope=%r  (%ds left)", request["scope"], remaining)
                return token, True, None
            logger.info("1/2 cached token has %ds left (margin %ds): renewing", max(remaining, 0),
                        REFRESH_MARGIN_SECONDS)
            _invalidate(key)

    token, failure = _fetch_token(request)
    return token, False, failure


def _fetch_token(request: dict) -> tuple[str | None, dict | None]:
    """Authenticate to the issuer and cache the result."""
    logger.info("1/2 agent -> issuer   POST /token  as client_id=%s scope=%r",
                request["client_id"], request["scope"])
    requested_at = _now()  # measure lifetime from BEFORE the request: conservative
    try:
        response = httpx.post(
            f"{request['issuer_url']}/token",
            headers={"X-Client-ID": request["client_id"], "X-Client-Secret": request["client_secret"],
                     "X-Scope": request["scope"]},
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.RequestError:
        logger.warning("    issuer unreachable")
        return None, dict(_UNAVAILABLE)
    logger.info("    issuer -> agent   HTTP %s", response.status_code)

    if response.status_code == 401:
        return None, dict(_UNAUTHENTICATED)
    if response.status_code == 403:
        logger.warning("    issuer refused scope %r for this client", request["scope"])
        return None, dict(_FORBIDDEN)
    if response.status_code != 200:
        return None, dict(_UNAVAILABLE)

    try:
        body = response.json()
        token = body["access_token"]
    except (ValueError, KeyError, TypeError):
        return None, dict(_UNAVAILABLE)

    try:
        expires_in = int(body.get("expires_in", 0))
    except (TypeError, ValueError):
        expires_in = 0
    if expires_in > 0:
        with _cache_lock:
            _cache[request["key"]] = (token, requested_at + expires_in)
    else:
        logger.warning("    issuer gave no usable expires_in: using this token once, not caching it")
    return token, None


def _invalidate(key: tuple) -> None:
    with _cache_lock:
        _cache.pop(key, None)


def _clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


# --------------------------------------------------------------------------- #
# Service call
# --------------------------------------------------------------------------- #
def _call_service(normalized_sku: str, token: str, forwarded_human: str | None = None,
                  delegation_token: str | None = None) -> httpx.Response | None:
    base_url = os.environ.get("INVENTORY_SERVICE_URL", DEFAULT_SERVICE_URL).rstrip("/")
    # quote(..., safe="") stops a SKU like "A/../B" from changing the URL path.
    url = f"{base_url}/stock/{quote(normalized_sku, safe='')}"
    logger.info("2/2 agent -> service  GET /stock/%s  (Authorization: Bearer <jwt>)", normalized_sku)
    try:
        response = httpx.get(
            url,
            headers=_service_headers(token, forwarded_human, delegation_token),
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.RequestError:
        logger.warning("    service unreachable")
        return None
    logger.info("    service -> agent  HTTP %s", response.status_code)
    return response


def _service_headers(token: str, forwarded_human: str | None, delegation_token: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if forwarded_human is not None:
        headers["X-Human-User"] = forwarded_human   # an assertion, NOT a credential
    if delegation_token is not None:
        headers["X-Delegation-Token"] = delegation_token   # a signed, verifiable grant
    return headers


def _map_service_response(response: httpx.Response, normalized_sku: str, key: tuple) -> dict:
    if response.status_code == 200:
        try:
            return response.json()
        except ValueError:
            return dict(_UNAVAILABLE)
    if response.status_code == 404:
        return {"status": "not_found", "sku": normalized_sku}
    if response.status_code == 401:
        _invalidate(key)  # never keep a token the service has rejected
        return dict(_UNAUTHENTICATED)
    if response.status_code == 403:
        # Valid token, insufficient authority. Renewing with the same scope can't
        # help, so no retry. The token stays cached: it is still good for what it allows.
        return dict(_FORBIDDEN)
    return dict(_UNAVAILABLE)


# --------------------------------------------------------------------------- #
# Day 06.09B: exchange the human's token for a delegation token
# --------------------------------------------------------------------------- #
_DELEGATION_DENIED = {"status": "forbidden", "message": "This agent may not act for this user on that item."}


def get_delegation(subject_token: str) -> tuple[str | None, dict | None]:
    """Ask the Delegation Authority to let THIS agent act for the human in `subject_token`.

    Proves the actor with a machine JWT minted for the authority (scope delegation.request)
    and the human with HER own signed token. Requests INVENTORY_REQUESTED_SCOPE.
    Returns (delegation_token, None) or (None, failure_dict). Not cached: one per request.
    """
    request, failure = _token_request(scope_override=DELEGATION_REQUEST_SCOPE)
    if failure:
        return None, failure
    actor_token, _, failure = _get_token(request)
    if failure:
        return None, failure

    scope = " ".join(sorted(set(os.environ.get("INVENTORY_REQUESTED_SCOPE", "").split())))
    url = os.environ.get("INVENTORY_DELEGATION_URL", DEFAULT_DELEGATION_URL).rstrip("/")
    logger.info("1b  agent -> delegation authority  POST /delegate  scope=%r", scope)
    try:
        response = httpx.post(f"{url}/delegate", headers={"Authorization": f"Bearer {actor_token}"},
                              json={"subject_token": subject_token, "scope": scope}, timeout=TIMEOUT_SECONDS)
    except httpx.RequestError:
        logger.warning("    delegation authority unreachable")
        return None, dict(_UNAVAILABLE)
    logger.info("    delegation authority -> agent  HTTP %s", response.status_code)
    if response.status_code == 200:
        try:
            return response.json()["delegation_token"], None
        except (ValueError, KeyError, TypeError):
            return None, dict(_UNAVAILABLE)
    if response.status_code == 403:
        return None, dict(_DELEGATION_DENIED)
    if response.status_code == 401:
        _invalidate(request["key"])
        return None, dict(_UNAUTHENTICATED)
    return None, dict(_UNAVAILABLE)
