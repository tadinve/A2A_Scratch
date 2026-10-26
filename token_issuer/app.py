"""Token issuer HTTP service (Days 05.3-05.5).

    POST /token
    X-Client-ID: inventory-agent
    X-Client-Secret: <secret>
    X-Scope: inventory.read.class_b            (one or more, space-delimited)

    -> 200 {"access_token", "token_type": "Bearer", "expires_in": 300, "scope": "..."}
    -> 401 client can't be authenticated            (checked first)
    -> 400 scope missing or unknown to this issuer
    -> 403 scope outside this client's entitlement

The caller authenticates; the ISSUER decides `sub` and approves `scope`.
A caller may request authority but can never grant it to itself.

Run:  uv run uvicorn token_issuer.app:app --host 127.0.0.1 --port 8001
"""

import logging

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from token_issuer.auth import KNOWN_SCOPES, audience_for, authenticate_client, parse_scope
from token_issuer import issuer
from token_issuer.issuer import LIFETIME_SECONDS, format_scope, issue_access_token

logger = logging.getLogger("uvicorn.error")

app = FastAPI(title="Token Issuer")

# Day 05.8: show which key this process signs with. Config is read once at
# startup, so after editing config/issuer.json this line only changes on restart.
logger.info("SIGNING KEY active_kid=%s (from %s)", issuer.ACTIVE_KID, issuer.CONFIG_PATH)

_ERROR_STATUS = {
    400: "invalid_scope",
    401: "unauthenticated",
    403: "scope_not_allowed",
    404: "not_found",
    405: "method_not_allowed",
}


@app.exception_handler(StarletteHTTPException)
async def consistent_error_body(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": _ERROR_STATUS.get(exc.status_code, "error"), "message": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.post("/token")
def token(
    client_id: str | None = Header(default=None, alias="X-Client-ID"),
    client_secret: str | None = Header(default=None, alias="X-Client-Secret"),
    scope: str | None = Header(default=None, alias="X-Scope"),
):
    # 1. "Who are you?" Authenticate BEFORE looking at scopes, so an
    #    unauthenticated caller learns nothing about what exists.
    client = authenticate_client(client_id, client_secret)
    if client is None:
        logger.warning("TOKEN DENIED client_id=%r reason=bad credentials", client_id)
        raise HTTPException(
            status_code=401,
            detail="Client could not be authenticated.",
            headers={"WWW-Authenticate": "ClientCredentials"},
        )

    # 2. "What are you asking for?" A scope is required: no silent default to
    #    the client's full entitlement.
    requested = parse_scope(scope)
    if requested is None:
        logger.warning("TOKEN DENIED client_id=%s reason=no scope requested", client_id)
        raise HTTPException(status_code=400, detail="A scope must be requested.")
    unknown = requested - KNOWN_SCOPES
    if unknown:
        logger.warning("TOKEN DENIED client_id=%s reason=unknown scope %s", client_id, sorted(unknown))
        raise HTTPException(status_code=400, detail="Requested scope is not recognized.")

    # 3. "May you have it?" Every requested scope must be inside the entitlement.
    #    All or nothing: one disallowed scope refuses the whole request.
    not_allowed = requested - client.allowed_scopes
    if not_allowed:
        logger.warning("TOKEN DENIED client_id=%s reason=not entitled to %s", client_id, sorted(not_allowed))
        raise HTTPException(status_code=403, detail="Client is not entitled to the requested scope.")

    # 4. One token, one audience: the scopes decide where the token may be used.
    audience = audience_for(requested)
    if audience is None:
        logger.warning("TOKEN DENIED client_id=%s reason=scopes span several audiences", client_id)
        raise HTTPException(status_code=400, detail="Requested scopes belong to different audiences.")

    # 5. Mint: identity from authentication, scope from the approved request.
    granted = format_scope(requested)
    access_token = issue_access_token(client.identity, requested, audience=audience)
    logger.info("TOKEN ISSUED client_id=%s sub=%s aud=%s scope=%r kid=%s expires_in=%s",
                client_id, client.identity, audience, granted, issuer.ACTIVE_KID, LIFETIME_SECONDS)

    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer",
         "expires_in": LIFETIME_SECONDS, "scope": granted},
        # Token responses must not be cached by browsers or proxies (OAuth 2.0, RFC 6749 5.1).
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
