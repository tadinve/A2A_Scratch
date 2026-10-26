"""Identity Service HTTP API (Day 06.04: login issues a signed human JWT).

    POST /login   {"username": "alice", "password": "..."}
    -> 200 {"status": "authenticated", "user_id": "user-001", "username": "alice",
            "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 300}
    -> 401 {"status": "unauthenticated", "message": "Invalid username or password"}

The JWT is signed with the Identity Service's RSA PRIVATE key, which never leaves
this service. Its audience is the Inventory Agent, which verifies it with the
matching PUBLIC key:  {iss, sub: user_id, aud: "inventory-agent", iat, exp}.

The password is checked with verify_password() against the stored Argon2id hash
and then discarded. It is never stored, logged or echoed. An unknown username
and a wrong password get the same 401 and cost the same hashing time.

The token carries the stable user_id as `sub`, never the username, email or password.

Run:  uv run uvicorn identity_service.app:app --host 127.0.0.1 --port 8002
"""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from identity_service import users
from identity_service.config import load_config
from identity_service.passwords import (
    DUMMY_HASH, MAX_PASSWORD_LENGTH, hash_password, needs_rehash, verify_password,
)
from identity_service.tokens import issue_user_token, load_private_key

logger = logging.getLogger("uvicorn.error")

# Loaded once at startup: a bad config or signing key stops the service.
CONFIG = load_config()
_SIGNING_KEY = load_private_key(CONFIG.private_key_path)
logger.info("IDENTITY SIGNING KEY kid=%s iss=%s aud=%s", CONFIG.active_kid, CONFIG.issuer, CONFIG.audience)

app = FastAPI(title="Identity Service")

INVALID_CREDENTIALS = "Invalid username or password"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


@app.exception_handler(StarletteHTTPException)
async def consistent_error_body(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status = {401: "unauthenticated", 404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
    return JSONResponse(status_code=exc.status_code, content={"status": status, "message": exc.detail},
                        headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default 422 body echoes the submitted input, which here could be a password.
    return JSONResponse(status_code=422, content={"status": "invalid_request",
                                                  "message": "username and password are required"})


def authenticate(username: str, password: str) -> tuple[str, str] | None:
    """Return (user_id, username) if the password matches, else None. Same cost either way."""
    record = users.find_user(CONFIG.users_db, username)
    if record is None:
        verify_password(password, DUMMY_HASH)   # burn the same time as a real check
        return None
    user_id, stored_username, stored_hash = record
    if not verify_password(password, stored_hash):
        return None
    if needs_rehash(stored_hash):
        # Settings were raised since this hash was made: upgrade it now, while we
        # briefly have the correct password in hand.
        users.update_hash(CONFIG.users_db, user_id, hash_password(password))
        logger.info("PASSWORD HASH UPGRADED user_id=%s", user_id)
    return user_id, stored_username


@app.post("/login")
def login(body: LoginRequest):
    result = authenticate(body.username, body.password)
    if result is None:
        logger.warning("LOGIN FAILED")          # no username, no password in logs
        raise HTTPException(status_code=401, detail=INVALID_CREDENTIALS)
    user_id, username = result
    # Steps 3-4: construct the JWT and sign it with the PRIVATE key.
    token = issue_user_token(CONFIG, _SIGNING_KEY, user_id)
    logger.info("LOGIN OK user_id=%s kid=%s aud=%s", user_id, CONFIG.active_kid, CONFIG.audience)
    return JSONResponse(
        {"status": "authenticated", "user_id": user_id, "username": username,
         "access_token": token, "token_type": "Bearer", "expires_in": CONFIG.token_lifetime_seconds},
        # Token responses must not be cached (OAuth 2.0, RFC 6749 5.1).
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
