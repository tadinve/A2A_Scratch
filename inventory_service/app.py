"""Inventory HTTP service.

Day 04: authorization depends on the caller AND the resource.

    authenticate (401) -> classify the SKU (404) -> authorize for that class (403) -> details (200)
Every error body has the same shape: {"status": "...", "message": "..."}.

Run (keys come from inventory_service/.env):
    uv run uvicorn inventory_service.app:app --host 127.0.0.1 --port 8000
"""

import logging

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from inventory_service.auth import authenticate
from inventory_service.authz import is_allowed, read_permission_for, role_for
from inventory_service.repository import get_classification, lookup_sku

# uvicorn already prints this logger to the terminal. Never log the key itself.
logger = logging.getLogger("uvicorn.error")

app = FastAPI(title="Inventory Service")

# Machine-readable status for each HTTP error the service can produce.
_ERROR_STATUS = {
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    503: "error",
}


@app.exception_handler(StarletteHTTPException)
async def consistent_error_body(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Render every HTTP error (ours, and FastAPI's own 404/405) as {status, message}.

    The message is a fixed string; keys, roles, and identities are never echoed back.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": _ERROR_STATUS.get(exc.status_code, "error"), "message": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.get("/stock/{sku}")
def get_stock(
    sku: str,
    # default=None lets a missing header reach our code (-> 401, not 422).
    api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    # Step 1 - Authentication: key -> identity.
    identity = authenticate(api_key)
    if identity is None:
        raise HTTPException(
            status_code=401,
            detail="Inventory access could not be authenticated.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Step 2 - Role: looked up on the server from the trusted identity.
    #          Nothing in the request (headers, query, body) can change it.
    role = role_for(identity)

    # Step 3 - Classification: metadata only, read after authentication so we
    #          know which permission this specific record requires.
    classification = get_classification(sku)
    if classification["status"] == "not_found":
        raise HTTPException(status_code=404, detail="SKU not found")
    if classification["status"] != "found":
        # Can't classify -> can't authorize -> fail closed.
        raise HTTPException(status_code=503, detail="Inventory is temporarily unavailable.")

    required = read_permission_for(classification["inventory_class"])

    # Step 4 - Authorization: does this role grant the permission for this record's class?
    if not is_allowed(role, required):
        logger.warning(
            "FORBIDDEN identity=%s role=%s sku=%s lacks %s (no detail lookup)",
            identity, role, classification["sku"], required,
        )
        raise HTTPException(status_code=403, detail="Caller is not permitted to read this inventory item.")

    # Step 5 - Only now read the protected details.
    logger.info("AUTHZ OK identity=%s role=%s sku=%s has %s -> detail lookup",
                identity, role, classification["sku"], required)
    result = lookup_sku(sku)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="SKU not found")
    if result["status"] != "found":
        raise HTTPException(status_code=503, detail="Inventory is temporarily unavailable.")
    return result
