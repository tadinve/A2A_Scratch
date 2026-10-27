"""Google OpenID Connect: discovery, the code exchange, and ID-token validation (Day 07).

Authlib builds the authorization URL (PKCE S256, nonce) and performs the
confidential-client code exchange. PyJWT verifies the ID token against Google's
keys from the jwks_uri in the FIXED discovery document, cached by PyJWKClient,
which refetches once when a token names an unknown kid (key rotation). No key
is ever fetched from a URL a token supplies.

Configuration comes from the environment (identity_service/.env, git-ignored):
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
    GOOGLE_OIDC_DISCOVERY_URL (optional; may only be Google's own).

Only `openid email` is requested: no Gmail, Drive, offline access or refresh token.
"""

import hmac
import os
import threading
import time
import warnings
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import jwt
from authlib.integrations.base_client import OAuthError
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError

with warnings.catch_warnings():
    # Authlib 1.9 prefers the separate `httpx2` package and warns when it falls back
    # to `httpx`, which the rest of this project uses. The fallback is fully supported.
    warnings.simplefilter("ignore")
    from authlib.integrations.httpx_client import OAuth2Client

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
CANONICAL_ISSUER = "https://accounts.google.com"
GOOGLE_ISSUERS = [CANONICAL_ISSUER, "accounts.google.com"]   # Google uses both spellings
CALLBACK_PATH = "/auth/google/callback"
SCOPES = "openid email"
ALLOWED_ALGORITHMS = ["RS256"]                               # pinned: the token's alg header is not trusted
REQUIRED_CLAIMS = ["iss", "sub", "aud", "exp", "iat", "nonce"]
CLOCK_LEEWAY_SECONDS = 30
HTTP_TIMEOUT_SECONDS = 10


class GoogleError(Exception):
    """Base class. `stage` names where it failed, for logs; it is never shown to callers."""

    def __init__(self, stage: str):
        super().__init__(stage)
        self.stage = stage


class ProviderUnavailable(GoogleError):
    """Google timed out, was unreachable, or its metadata/keys could not be fetched."""


class AuthenticationFailed(GoogleError):
    """Google answered, but the code or ID token was rejected."""


@dataclass(frozen=True)
class GoogleSettings:
    client_id: str
    client_secret: str
    redirect_uri: str
    discovery_url: str = GOOGLE_DISCOVERY_URL

    @property
    def cookie_secure(self) -> bool:
        return urlsplit(self.redirect_uri).scheme == "https"

    def __repr__(self) -> str:                              # keep the secret out of tracebacks
        return f"GoogleSettings(client_id={self.client_id!r}, redirect_uri={self.redirect_uri!r})"


@dataclass(frozen=True)
class GoogleIdentity:
    issuer: str             # canonical, after validation
    subject: str            # Google `sub`: the stable external identifier
    email: str              # verified, but NEVER used to choose the internal user


def load_google_settings(env=os.environ) -> GoogleSettings | None:
    """None when Google sign-in is not configured at all. Partial or unsafe config fails."""
    names = ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI")
    values = {n: (env.get(n) or "").strip() for n in names}
    if not any(values.values()):
        return None
    missing = [n for n, v in values.items() if not v]
    if missing:
        raise RuntimeError(f"Google sign-in is partly configured; missing {', '.join(missing)}")
    discovery = (env.get("GOOGLE_OIDC_DISCOVERY_URL") or GOOGLE_DISCOVERY_URL).strip()
    if discovery != GOOGLE_DISCOVERY_URL:
        raise RuntimeError(f"GOOGLE_OIDC_DISCOVERY_URL must be {GOOGLE_DISCOVERY_URL}")
    redirect = urlsplit(values["GOOGLE_REDIRECT_URI"])
    local_http = redirect.scheme == "http" and redirect.hostname == "localhost"
    if not (redirect.scheme == "https" or local_http) or redirect.path != CALLBACK_PATH \
            or redirect.query or redirect.fragment:
        raise RuntimeError(f"GOOGLE_REDIRECT_URI must be https (or http://localhost) and end in {CALLBACK_PATH}")
    return GoogleSettings(values["GOOGLE_CLIENT_ID"], values["GOOGLE_CLIENT_SECRET"],
                          values["GOOGLE_REDIRECT_URI"], discovery)


class _GoogleJWKClient(PyJWKClient):
    """PyJWKClient's caching and rotation, fetching over the provider's httpx client."""

    def __init__(self, uri: str, http: httpx.Client):
        super().__init__(uri, lifespan=3600, timeout=HTTP_TIMEOUT_SECONDS)
        self._http = http

    def fetch_data(self):
        try:
            response = self._http.get(self.uri)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise PyJWKClientConnectionError(type(exc).__name__) from None
        self._last_successful_fetch = time.monotonic()      # starts PyJWKClient's refresh cooldown
        return self._as_jwk_set_payload(data)


class GoogleOIDC:
    """One Google OAuth web client. `transport` lets tests stand in for Google."""

    def __init__(self, settings: GoogleSettings, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        self._transport = transport
        self._http = httpx.Client(transport=transport, timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False)
        self._metadata: dict | None = None
        self._jwks: _GoogleJWKClient | None = None
        self._lock = threading.Lock()

    # -- discovery -------------------------------------------------------------
    def metadata(self) -> dict:
        """The fixed discovery document, fetched once and checked before it is trusted."""
        with self._lock:
            if self._metadata is None:
                try:
                    response = self._http.get(self.settings.discovery_url)
                    response.raise_for_status()
                    doc = response.json()
                except (httpx.HTTPError, ValueError):
                    raise ProviderUnavailable("discovery") from None
                endpoints = [doc.get(k) for k in ("authorization_endpoint", "token_endpoint", "jwks_uri")]
                if doc.get("issuer") != CANONICAL_ISSUER or not all(
                        isinstance(u, str) and urlsplit(u).scheme == "https" for u in endpoints):
                    raise ProviderUnavailable("discovery_document")
                self._metadata = doc
                self._jwks = _GoogleJWKClient(doc["jwks_uri"], self._http)
            return self._metadata

    def _oauth_client(self) -> OAuth2Client:
        return OAuth2Client(self.settings.client_id, self.settings.client_secret,
                            redirect_uri=self.settings.redirect_uri, scope=SCOPES,
                            code_challenge_method="S256", timeout=HTTP_TIMEOUT_SECONDS,
                            transport=self._transport)

    # -- step 4: send the browser to Google ------------------------------------
    def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        endpoint = self.metadata()["authorization_endpoint"]
        with self._oauth_client() as client:
            url, _ = client.create_authorization_url(endpoint, state=state, nonce=nonce,
                                                     code_verifier=code_verifier, prompt="select_account")
        return url

    # -- step 7: exchange the code (once; never retried) -----------------------
    def exchange_code(self, code: str, code_verifier: str) -> str:
        """Return Google's ID token. The access token in the response is dropped here."""
        endpoint = self.metadata()["token_endpoint"]
        try:
            with self._oauth_client() as client:
                # client_secret_basic auth, the same redirect_uri, and the original verifier.
                token = client.fetch_token(endpoint, code=code, code_verifier=code_verifier)
        except OAuthError:
            raise AuthenticationFailed("code_exchange") from None   # invalid_grant: bad, reused, wrong verifier
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code >= 500:
                raise ProviderUnavailable("code_exchange") from None
            raise AuthenticationFailed("code_exchange") from None
        except (httpx.HTTPError, ValueError):
            raise ProviderUnavailable("code_exchange") from None
        id_token = token.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise AuthenticationFailed("code_exchange")
        return id_token

    # -- step 8: validate the ID token -----------------------------------------
    def verify_id_token(self, id_token: str, expected_nonce: str) -> GoogleIdentity:
        self.metadata()
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(id_token)
        except PyJWKClientConnectionError:
            raise ProviderUnavailable("signing_keys") from None
        except (PyJWKClientError, jwt.InvalidTokenError):
            raise AuthenticationFailed("id_token_key") from None
        try:
            claims = jwt.decode(id_token, signing_key.key, algorithms=ALLOWED_ALGORITHMS,
                                audience=self.settings.client_id, issuer=GOOGLE_ISSUERS,
                                leeway=CLOCK_LEEWAY_SECONDS, options={"require": REQUIRED_CLAIMS})
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("id_token") from None

        # OIDC Core 3.1.3.7: with several audiences, or any azp, azp must be our client.
        aud, azp = claims.get("aud"), claims.get("azp")
        if (isinstance(aud, list) and len(aud) > 1 and azp is None) or \
                (azp is not None and azp != self.settings.client_id):
            raise AuthenticationFailed("id_token_azp")
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not hmac.compare_digest(nonce.encode(), expected_nonce.encode()):
            raise AuthenticationFailed("id_token_nonce")
        sub, email = claims.get("sub"), claims.get("email")
        if not isinstance(sub, str) or not sub.strip() or len(sub) > 255:
            raise AuthenticationFailed("id_token_sub")
        if claims.get("email_verified") is not True or not isinstance(email, str) or not email:
            raise AuthenticationFailed("id_token_email")
        return GoogleIdentity(issuer=CANONICAL_ISSUER, subject=sub, email=email)

    def complete(self, code: str, code_verifier: str, expected_nonce: str) -> GoogleIdentity:
        return self.verify_id_token(self.exchange_code(code, code_verifier), expected_nonce)
