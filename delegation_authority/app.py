"""Delegation Authority HTTP API (Day 06.09B), shaped after OAuth 2.0 Token Exchange (RFC 8693).

    POST /delegate
    Authorization: Bearer <ACTOR token: machine JWT, aud=a2a-delegation-authority, scope delegation.request>
    {"subject_token": "<HUMAN JWT from the Identity Service>", "scope": "inventory.read.class_b"}

    -> 200 {"delegation_token": "<jwt>", "token_type": "Bearer", "expires_in": N, "scope": "..."}

Four checks, in order, before anything is signed:
    1. actor:   who is asking?          machine JWT verified        -> 401
    2. subject: who is it for?          human JWT verified          -> 401
                and was that human token issued TO this actor? (aud == actor)
    3. policy:  may this actor act for this human?                  -> 403
    4. scope:   requested ⊆ human permissions ∩ actor permissions   -> 403 (400 if unknown)

The authority NEVER signs an identity the agent merely names: the human comes only
from a verified human token. The output binds human (sub), actor (act.sub),
audience, scope and a short expiry that never outlives the human token.

Run:  uv run uvicorn delegation_authority.app:app --host 127.0.0.1 --port 8004
"""

import logging
import time

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from delegation_authority.config import Trust, load_config

logger = logging.getLogger("uvicorn.error")

CONFIG = load_config()
logger.info("DELEGATION AUTHORITY kid=%s iss=%s aud=%s", CONFIG.active_kid, CONFIG.issuer, CONFIG.token_audience)

app = FastAPI(title="Delegation Authority")

ALLOWED_ALGORITHMS = ["RS256"]
REQUIRED = ["iss", "sub", "aud", "iat", "exp"]


class DelegationRequest(BaseModel):
    subject_token: str = Field(min_length=1, max_length=8192)
    scope: str = Field(min_length=1, max_length=512)


@app.exception_handler(StarletteHTTPException)
async def consistent_error_body(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status = {400: "invalid_scope", 401: "unauthenticated", 403: "delegation_denied",
              404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
    return JSONResponse(status_code=exc.status_code, content={"status": status, "message": exc.detail},
                        headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"status": "invalid_request",
                                                  "message": "subject_token and scope are required"})


def _verify(token: str, trust: Trust, audience: str) -> dict:
    kid = jwt.get_unverified_header(token).get("kid")
    key = trust.keys.get(kid) if isinstance(kid, str) else None
    if key is None:
        raise jwt.InvalidTokenError("untrusted kid")
    return jwt.decode(token, key, algorithms=ALLOWED_ALGORITHMS, issuer=trust.issuer, audience=audience,
                      options={"require": REQUIRED})


def _deny(status: int, message: str, reason: str, **ctx):
    logger.warning("DELEGATION DENIED reason=%s %s", reason, " ".join(f"{k}={v}" for k, v in ctx.items()))
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    raise HTTPException(status_code=status, detail=message, headers=headers)


@app.post("/delegate")
def delegate(body: DelegationRequest, authorization: str | None = Header(default=None)):
    # 1. ACTOR: the calling machine, proven by its own JWT minted for this authority.
    scheme, _, actor_token = (authorization or "").strip().partition(" ")
    if scheme.lower() != "bearer" or not actor_token.strip():
        _deny(401, "Actor authentication required.", "no actor token")
    try:
        actor = _verify(actor_token.strip(), CONFIG.actor, CONFIG.actor.audience)
    except jwt.InvalidTokenError as exc:
        _deny(401, "Actor authentication required.", f"actor {type(exc).__name__}")
    actor_sub = actor["sub"]
    if CONFIG.actor.required_scope not in str(actor.get("scope", "")).split():
        _deny(403, "Actor is not permitted to request delegation.", "actor lacks delegation.request", actor=actor_sub)

    # 2. SUBJECT: the human, proven by HER token, which must have been issued to this actor.
    try:
        human = _verify(body.subject_token, CONFIG.human, audience=actor_sub)
    except jwt.InvalidTokenError as exc:
        _deny(401, "Subject token is not valid for this actor.", f"subject {type(exc).__name__}", actor=actor_sub)
    human_sub = human["sub"]

    # 3. POLICY: may this actor act for this human at all?
    if human_sub not in CONFIG.policy.may_act_for.get(actor_sub, frozenset()):
        _deny(403, "Actor may not act for this human.", "no delegation relationship", actor=actor_sub, human=human_sub)

    # 4. SCOPE: never more than BOTH parties may do, all or nothing.
    requested = frozenset(body.scope.split())
    allowed = CONFIG.policy.human_permissions.get(human_sub, frozenset()) & \
        CONFIG.policy.actor_permissions.get(actor_sub, frozenset())
    if not requested:
        _deny(400, "A scope must be requested.", "empty scope")
    if not requested <= allowed:
        _deny(403, "Requested scope exceeds what this human and actor may jointly do.", "scope not allowed",
              actor=actor_sub, human=human_sub, denied=sorted(requested - allowed))

    # Sign: human as sub, actor as act.sub, short-lived, never outliving the human token.
    now = int(time.time())
    exp = min(now + CONFIG.token_lifetime_seconds, int(human["exp"]))
    scope = " ".join(sorted(requested))
    claims = {"iss": CONFIG.issuer, "sub": human_sub, "act": {"sub": actor_sub},
              "aud": CONFIG.token_audience, "scope": scope, "iat": now, "exp": exp}
    token = jwt.encode(claims, CONFIG.private_key, algorithm="RS256", headers={"kid": CONFIG.active_kid})
    logger.info("DELEGATION ISSUED human=%s actor=%s aud=%s scope=%r expires_in=%s",
                human_sub, actor_sub, CONFIG.token_audience, scope, exp - now)
    return JSONResponse({"delegation_token": token, "token_type": "Bearer", "expires_in": exp - now, "scope": scope},
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
