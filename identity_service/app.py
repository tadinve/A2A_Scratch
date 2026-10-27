"""Identity Service HTTP API (Day 08: Google sign-in only, state in Firestore).

    GET /auth/google            -> 302 to Google
    GET /auth/google/callback   -> 200 {"status": "authenticated", "human_sub": "user-001",
                                        "token_type": "Bearer", "expires_in": 300, "access_token": "<jwt>"}

Google authenticates the person; this service maps the verified Google `sub` to
an internal user through an explicit link in Firestore, checks that user is
enabled, and signs a human JWT with its RSA PRIVATE key, which never leaves this
service. Its audience is the Inventory Agent, which verifies it with the matching
PUBLIC key:  {iss, sub: user_id, aud: "inventory-agent", iat, exp}.

There is no password login: no password is accepted, stored or hashed here.

Startup fails closed on a bad config or signing key, missing or partial Google
settings, or a Firestore store that can't be set up (see identity_service/datastore.py).

Run:  uv run uvicorn identity_service.app:app --host 127.0.0.1 --port 8002 --workers 1
"""

import logging
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from identity_service import google_login
from identity_service.config import load_config
from identity_service.datastore import build_stores
from identity_service.google_oidc import GoogleOIDC, load_google_settings
from identity_service.tokens import load_private_key

logger = logging.getLogger("uvicorn.error")
logging.getLogger("uvicorn.access").addFilter(google_login.RedactAuthQueryStrings())

load_dotenv(Path(__file__).resolve().parent / ".env")

# Loaded once at startup: a bad config or signing key stops the service.
CONFIG = load_config()
_SIGNING_KEY = load_private_key(CONFIG.private_key_path)
logger.info("IDENTITY SIGNING KEY kid=%s iss=%s aud=%s", CONFIG.active_kid, CONFIG.issuer, CONFIG.audience)

_GOOGLE = load_google_settings()
if _GOOGLE is None:
    raise RuntimeError("Google sign-in is the only login: set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET "
                       "and GOOGLE_REDIRECT_URI (see identity_service/.env.example)")
STORES = build_stores()
logger.info("GOOGLE SIGN-IN client_id=%s redirect_uri=%s", _GOOGLE.client_id, _GOOGLE.redirect_uri)
logger.info("IDENTITY STORE %s", STORES.description)

app = FastAPI(title="Identity Service")
app.state.google_login = google_login.GoogleLogin(CONFIG, _SIGNING_KEY, GoogleOIDC(_GOOGLE), users=STORES.users,
                                                  links=STORES.links, store=STORES.transactions)
app.include_router(google_login.router)


@app.exception_handler(StarletteHTTPException)
async def consistent_error_body(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status = {401: "unauthenticated", 404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
    return JSONResponse(status_code=exc.status_code, content={"status": status, "message": exc.detail},
                        headers=getattr(exc, "headers", None))
