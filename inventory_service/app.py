"""Inventory HTTP service.

Day 04: authorization depends on the caller AND the resource.

    authenticate JWT (401) -> classify the SKU (404) -> authorize for that class (403) -> details (200)
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


# Day 06.01: INTENTIONALLY INSECURE. Echoes whatever identity the caller claims.
# No token, no database, no relation to the protected /stock endpoint below.
@app.get("/whoami")
def whoami(user: str):
    return {"claimed_user": user, "authenticated": False}


@app.get("/stock/{sku}")
def get_stock(
    sku: str,
    # default=None lets a missing header reach our code (-> 401, not 422).
    authorization: str | None = Header(default=None),
    # Day 06.09 Experiment A: read ONLY to log it. Never used for any decision.
    x_human_user: str | None = Header(default=None, alias="X-Human-User"),
):
    # Step 1 - Authentication: verified JWT -> principal (`sub` + `scope`).
    principal = authenticate(authorization)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Inventory access could not be authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    identity = principal.identity
    if x_human_user is not None:
        # %r quotes the value and escapes newlines, and [:64] bounds it, so a forged
        # header can't inject fake log lines.
        logger.warning("UNTRUSTED CLAIM X-Human-User=%r asserted by machine=%s "
                       "(logged only; not used for authorization)", x_human_user[:64], identity)

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

    # Step 4a - Token scope: did the issuer approve THIS authority for THIS token?
    #           A token scoped to class B can't read class A, whatever the role allows.
    if required not in principal.scopes:
        logger.warning(
            "FORBIDDEN identity=%s sku=%s token scope %s lacks %s (no detail lookup)",
            identity, classification["sku"], sorted(principal.scopes), required,
        )
        raise HTTPException(status_code=403, detail="Caller is not permitted to read this inventory item.")

    # Step 4b - Role: does this identity's role grant the permission for this class?
    #           Both checks must pass. Scope narrows a token; it never exceeds the role.
    if not is_allowed(role, required):
        logger.warning(
            "FORBIDDEN identity=%s role=%s sku=%s lacks %s (no detail lookup)",
            identity, role, classification["sku"], required,
        )
        raise HTTPException(status_code=403, detail="Caller is not permitted to read this inventory item.")

    # Step 5 - Only now read the protected details.
    logger.info("AUTHZ OK identity=%s role=%s sku=%s scope+role grant %s -> detail lookup",
                identity, role, classification["sku"], required)
    result = lookup_sku(sku)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="SKU not found")
    if result["status"] != "found":
        raise HTTPException(status_code=503, detail="Inventory is temporarily unavailable.")
    return result
