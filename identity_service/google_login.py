"""Google sign-in routes (Days 07-08). Google proves who the person is; WE decide who they are here.

This is the only way a human signs in: password login was removed in Day 08.

    GET /auth/google            -> 302 to Google (state, nonce, PKCE S256, prompt=select_account)
    GET /auth/google/callback   -> 200 {"status": "authenticated", "human_sub": "user-001",
                                        "token_type": "Bearer", "expires_in": 300,
                                        "access_token": "<OUR application human JWT>"}

`access_token` is the Identity-Service-signed human JWT from issue_user_token(),
unchanged since Day 06. It is NOT Google's access token, which is discarded, as
is Google's ID token once validated.

Errors (our API contract):  400 invalid_login_transaction | 400 login_cancelled |
401 google_authentication_failed | 403 account_not_allowed |
503 identity_provider_unavailable (Google) | 503 identity_store_unavailable (Firestore).
Each carries a generic message and a correlation_id that matches the log lines.
"""

import logging
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from identity_service.config import IdentityConfig
from identity_service.datastore import StoreUnavailable
from identity_service.google_oidc import AuthenticationFailed, GoogleOIDC, ProviderUnavailable
from identity_service.oauth_transactions import TRANSACTION_TTL_SECONDS, TransactionStoreFull
from identity_service.tokens import issue_user_token

logger = logging.getLogger("uvicorn.error")

COOKIE_NAME = "a2a_google_login"
COOKIE_PATH = "/auth/google"
AUTH_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}

MESSAGES = {
    "invalid_login_transaction": (400, "The sign-in attempt is missing, expired or already used. Start again."),
    "login_cancelled": (400, "Google sign-in was cancelled."),
    "google_authentication_failed": (401, "Google sign-in could not be verified."),
    "account_not_allowed": (403, "This account is not allowed to use this service."),
    "identity_provider_unavailable": (503, "Google sign-in is temporarily unavailable. Try again later."),
    "identity_store_unavailable": (503, "Sign-in is temporarily unavailable. Try again later."),
}


class GoogleLogin:
    def __init__(self, cfg: IdentityConfig, signing_key, oidc: GoogleOIDC, *, users, links, store):
        self.cfg, self.signing_key, self.oidc = cfg, signing_key, oidc
        self.users, self.links, self.store = users, links, store

    # -- responses -------------------------------------------------------------
    def _clear_cookie(self, response: Response) -> Response:
        response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, secure=self.oidc.settings.cookie_secure,
                               httponly=True, samesite="lax")
        return response

    def _fail(self, error: str, stage: str, correlation_id: str, user_id: str | None = None) -> JSONResponse:
        status, message = MESSAGES[error]
        logger.warning("GOOGLE LOGIN FAILED outcome=%s stage=%s correlation_id=%s user_id=%s",
                       error, stage, correlation_id, user_id or "-")
        return self._clear_cookie(JSONResponse(
            status_code=status, headers=AUTH_HEADERS,
            content={"status": error, "message": message, "correlation_id": correlation_id}))

    # -- GET /auth/google ------------------------------------------------------
    def start(self) -> Response:
        correlation_id = secrets.token_hex(8)
        try:
            binding_id, tx = self.store.begin(correlation_id)
        except TransactionStoreFull:
            return self._fail("identity_provider_unavailable", "transaction_store_full", correlation_id)
        except StoreUnavailable as exc:
            return self._fail("identity_store_unavailable", exc.operation, correlation_id)
        try:
            url = self.oidc.authorization_url(tx.state, tx.nonce, tx.code_verifier)
        except ProviderUnavailable as exc:
            try:
                self.store.discard(binding_id)
            except StoreUnavailable:
                pass                                # it expires on its own
            return self._fail("identity_provider_unavailable", exc.stage, correlation_id)
        logger.info("GOOGLE LOGIN STARTED correlation_id=%s", correlation_id)
        response = RedirectResponse(url, status_code=302, headers=AUTH_HEADERS)
        # Host-only (no Domain), HttpOnly, SameSite=Lax: Lax still rides along on
        # Google's top-level redirect back. It holds only a random lookup id.
        response.set_cookie(COOKIE_NAME, binding_id, max_age=TRANSACTION_TTL_SECONDS, path=COOKIE_PATH,
                            secure=self.oidc.settings.cookie_secure, httponly=True, samesite="lax")
        return response

    # -- GET /auth/google/callback ---------------------------------------------
    def callback(self, request: Request) -> Response:
        params = request.query_params
        # Claim the transaction FIRST, even when Google reports an error: a callback
        # without our state, cookie and live transaction is never acted on.
        try:
            tx = self.store.claim(request.cookies.get(COOKIE_NAME), params.get("state"))
        except StoreUnavailable as exc:
            return self._fail("identity_store_unavailable", exc.operation, secrets.token_hex(8))
        if tx is None:
            return self._fail("invalid_login_transaction", "transaction", secrets.token_hex(8))
        correlation_id = tx.correlation_id          # the same id the start logged
        if params.get("error"):
            if params.get("error") == "access_denied":
                return self._fail("login_cancelled", "google_error", correlation_id)
            return self._fail("google_authentication_failed", "google_error", correlation_id)
        code = params.get("code")
        if not code:
            return self._fail("invalid_login_transaction", "missing_code", correlation_id)

        try:
            identity = self.oidc.complete(code, tx.code_verifier, tx.nonce)
        except ProviderUnavailable as exc:
            return self._fail("identity_provider_unavailable", exc.stage, correlation_id)
        except AuthenticationFailed as exc:
            return self._fail("google_authentication_failed", exc.stage, correlation_id)

        try:
            user_id = self.links.resolve(identity)
            if user_id is None:
                return self._fail("account_not_allowed", "unlinked_subject", correlation_id)
            if not self.users.is_enabled(user_id):
                return self._fail("account_not_allowed", "account_disabled", correlation_id, user_id)
        except StoreUnavailable as exc:
            return self._fail("identity_store_unavailable", exc.operation, correlation_id)

        token = issue_user_token(self.cfg, self.signing_key, user_id)
        logger.info("GOOGLE LOGIN OK correlation_id=%s user_id=%s kid=%s aud=%s",
                    correlation_id, user_id, self.cfg.active_kid, self.cfg.audience)
        return self._clear_cookie(JSONResponse(
            headers=AUTH_HEADERS,
            content={"status": "authenticated", "human_sub": user_id, "token_type": "Bearer",
                     "expires_in": self.cfg.token_lifetime_seconds, "access_token": token}))


router = APIRouter()


@router.get("/auth/google")
def google_start(request: Request):
    return request.app.state.google_login.start()


@router.get("/auth/google/callback")
def google_callback(request: Request):
    return request.app.state.google_login.callback(request)


class RedactAuthQueryStrings(logging.Filter):
    """uvicorn's access log prints the full path; callback query strings carry the
    authorization code and state. Keep the path, drop the query."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str) \
                and args[2].startswith("/auth/") and "?" in args[2]:
            record.args = (*args[:2], args[2].split("?", 1)[0] + "?[redacted]", *args[3:])
        return True
