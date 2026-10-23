"""SQLite lookup tool for the inventory agent.

Two layers:

- ``get_stock`` is the only function the model sees. It takes a SKU, fetches the
  configured credential from the environment, and delegates.
- ``protected_get_stock`` verifies that credential before touching SQLite.

The model supplies the SKU. This module owns the credential; the SQL lives in
inventory_service/repository.py.
"""

import logging
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

# Day 03A: the SQLite query now lives in the service package. Stage 03D replaces
# this direct import with an HTTP call.
from inventory_service.repository import lookup_sku as _lookup_sku

_PACKAGE_DIR = Path(__file__).resolve().parent

# Make the credential available even when this module is used outside `adk web`.
load_dotenv(_PACKAGE_DIR / ".env")

logger = logging.getLogger(__name__)

_UNAUTHENTICATED = {
    "status": "unauthenticated",
    "message": "Inventory access could not be authenticated.",
}


# --------------------------------------------------------------------------- #
# Model-facing tool
# --------------------------------------------------------------------------- #
def get_stock(sku: str) -> dict:
    """Return the inventory record for a SKU.

    Args:
        sku: The stock-keeping unit to look up, for example "WIDGET-A".
             Surrounding whitespace is ignored and the value is upper-cased.

    Returns:
        A dict whose "status" is one of:
        - "found": includes "sku", "name", and "quantity". A quantity of 0
          means the item exists but is out of stock.
        - "not_found": the SKU is not in the inventory table.
        - "unauthenticated": inventory access could not be authenticated.
        - "error": the database could not be read; includes "message".
    """
    # Application code, not the model, supplies the credential.
    credential = os.environ.get("INVENTORY_SHARED_SECRET")
    return protected_get_stock(sku, credential)


# --------------------------------------------------------------------------- #
# Protected lookup (never exposed to the model)
# --------------------------------------------------------------------------- #
def protected_get_stock(sku: str, credential: str | None) -> dict:
    """Verify the shared-secret credential, then run the inventory lookup."""
    principal = _authenticate(credential)
    if principal is None:
        logger.warning("inventory lookup rejected: unauthenticated")
        return dict(_UNAUTHENTICATED)

    logger.info("inventory lookup by principal=%s sku=%r", principal, sku)
    return _lookup_sku(sku)


def _authenticate(credential: str | None) -> str | None:
    """Return the configured principal if the credential is valid, else None.

    Fails closed: no expected secret, an empty secret, or a missing credential
    all reject. The comparison is constant-time.
    """
    expected = os.environ.get("INVENTORY_SHARED_SECRET")
    principal = os.environ.get("INVENTORY_PRINCIPAL")

    if not expected or not principal or not credential:
        return None
    if not secrets.compare_digest(credential.encode(), expected.encode()):
        return None
    return principal
