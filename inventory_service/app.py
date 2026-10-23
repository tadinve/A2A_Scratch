"""Inventory HTTP service. Stage 03C: API-key authentication.

Run:
    INVENTORY_SERVICE_SECRET=demo-local-secret \
        uv run uvicorn inventory_service.app:app --host 127.0.0.1 --port 8000
"""

import logging
import os
import secrets

from fastapi import FastAPI, Header, HTTPException

from inventory_service.repository import lookup_sku

# 2. The expected key comes from the service's own environment.
#    Fail closed: refuse to start if it is missing or empty.
SERVICE_SECRET = os.getenv("INVENTORY_SERVICE_SECRET")
if not SERVICE_SECRET:
    raise RuntimeError("INVENTORY_SERVICE_SECRET must be set")

# uvicorn already prints this logger to the terminal. Never log the key itself.
logger = logging.getLogger("uvicorn.error")

app = FastAPI(title="Inventory Service")


@app.get("/stock/{sku}")
def get_stock(
    sku: str,
    # 1. Read the X-API-Key header. default=None lets a missing header reach
    #    our code (-> 401) instead of failing FastAPI validation (-> 422).
    api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    # 3. Constant-time comparison. Compare bytes so a non-ASCII header value
    #    is simply "wrong" (401) rather than a TypeError (500).
    # 4. Missing or incorrect key -> 401. Raising stops the function here.
    if api_key is None or not secrets.compare_digest(
        api_key.encode(), SERVICE_SECRET.encode()
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthenticated",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 5. Only reached after successful authentication.
    logger.info("AUTH OK -> SQLite lookup for sku=%s", sku)
    result = lookup_sku(sku)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="SKU not found")
    return result
