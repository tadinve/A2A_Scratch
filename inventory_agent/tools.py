"""Inventory tool for the agent. Stage 03D: an HTTP client of inventory_service.

The model calls get_stock(sku), exactly as on Days 01-02. Inside, this module
sends GET /stock/{sku} to the inventory service with an X-API-Key header.

This module never imports sqlite3 or inventory_service, and never reads the
service's secret. If the service can't be reached, it fails closed: there is
no fallback to local database access.
"""

import os
from pathlib import Path
from urllib.parse import quote

import httpx
from dotenv import load_dotenv

# Agent-side configuration only (inventory_agent/.env).
load_dotenv(Path(__file__).resolve().parent / ".env")

DEFAULT_SERVICE_URL = "http://127.0.0.1:8000"
TIMEOUT_SECONDS = 5.0

_UNAVAILABLE = {"status": "error", "message": "Inventory is temporarily unavailable."}
_UNAUTHENTICATED = {
    "status": "unauthenticated",
    "message": "Inventory access could not be authenticated.",
}
_FORBIDDEN = {
    "status": "forbidden",
    "message": "This agent is not permitted to read inventory.",
}


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
    normalized_sku = sku.strip().upper()

    # Application code, not the model, supplies the credential.
    client_secret = os.environ.get("INVENTORY_CLIENT_SECRET")
    if not client_secret:
        # Fail closed locally: don't send an unauthenticated request.
        return dict(_UNAUTHENTICATED)

    base_url = os.environ.get("INVENTORY_SERVICE_URL", DEFAULT_SERVICE_URL).rstrip("/")
    # quote(..., safe="") stops a SKU like "A/../B" from changing the URL path.
    url = f"{base_url}/stock/{quote(normalized_sku, safe='')}"

    try:
        response = httpx.get(
            url,
            headers={"X-API-Key": client_secret, "Accept": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.RequestError:
        # Connection refused, timeout, DNS failure... No HTTP status at all.
        # Fail closed: never fall back to opening SQLite directly.
        return dict(_UNAVAILABLE)

    if response.status_code == 200:
        try:
            return response.json()  # found, or the service's own "error" dict
        except ValueError:
            return dict(_UNAVAILABLE)
    if response.status_code == 404:
        return {"status": "not_found", "sku": normalized_sku}
    if response.status_code == 401:
        return dict(_UNAUTHENTICATED)
    if response.status_code == 403:
        return dict(_FORBIDDEN)

    # Anything else (500, 503, unexpected codes): don't guess.
    return dict(_UNAVAILABLE)
