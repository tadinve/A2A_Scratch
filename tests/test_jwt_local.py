"""Day 05.1 acceptance tests: issue and verify RS256 JWTs locally (no HTTP).

Keys are generated fresh in memory, so these tests never touch ~/secrets.
Expired tokens are built with an old `now`, not by sleeping.
"""

import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.issue_jwt import issue_token
from scripts.verify_jwt import verify_token


def make_keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(scope="module")
def keys():
    return make_keypair()


@pytest.fixture(scope="module")
def other_keys():
    return make_keypair()


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# 1 --------------------------------------------------------------------------
def test_valid_token_verifies(keys):
    private_pem, public_pem = keys
    claims = verify_token(issue_token(private_pem, "inventory-agent"), public_pem)
    assert claims["sub"] == "inventory-agent"
    assert claims["exp"] - claims["iat"] == 300


# 2 --------------------------------------------------------------------------
def test_payload_modified_after_signing_fails(keys):
    private_pem, public_pem = keys
    header, payload, signature = issue_token(private_pem, "inventory-agent").split(".")

    claims = json.loads(b64url_decode(payload))
    claims["sub"] = "admin-agent"  # perfectly valid JSON, correct aud, not expired...
    forged = ".".join([header, b64url_encode(json.dumps(claims).encode()), signature])

    with pytest.raises(jwt.InvalidSignatureError):
        verify_token(forged, public_pem)  # ...but the signature no longer matches


# 3 --------------------------------------------------------------------------
def test_different_signing_key_fails(keys, other_keys):
    _, public_pem = keys
    attacker_private, _ = other_keys
    with pytest.raises(jwt.InvalidSignatureError):
        verify_token(issue_token(attacker_private, "inventory-agent"), public_pem)


# 4 --------------------------------------------------------------------------
def test_expired_token_fails(keys):
    private_pem, public_pem = keys
    ten_minutes_ago = int(time.time()) - 600
    token = issue_token(private_pem, "inventory-agent", now=ten_minutes_ago)  # exp was 5 min ago
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_token(token, public_pem)


# 5 --------------------------------------------------------------------------
def test_wrong_issuer_fails(keys):
    private_pem, public_pem = keys
    token = issue_token(private_pem, "inventory-agent", iss="some-other-issuer")
    with pytest.raises(jwt.InvalidIssuerError):
        verify_token(token, public_pem)


# 6 --------------------------------------------------------------------------
def test_wrong_audience_fails(keys):
    private_pem, public_pem = keys
    token = issue_token(private_pem, "inventory-agent", aud="billing-service")
    with pytest.raises(jwt.InvalidAudienceError):
        verify_token(token, public_pem)


# 7 --------------------------------------------------------------------------
@pytest.mark.parametrize("missing", ["exp", "iss", "sub", "aud", "iat"])
def test_missing_required_claim_fails(keys, missing):
    private_pem, public_pem = keys
    now = int(time.time())
    claims = {"iss": "a2a-local-issuer", "sub": "inventory-agent",
              "aud": "inventory-service", "iat": now, "exp": now + 300}
    del claims[missing]
    token = jwt.encode(claims, private_pem, algorithm="RS256")  # correctly signed, incomplete
    with pytest.raises(jwt.MissingRequiredClaimError):
        verify_token(token, public_pem)


# 8 --------------------------------------------------------------------------
def _claims():
    now = int(time.time())
    return {"iss": "a2a-local-issuer", "sub": "inventory-agent",
            "aud": "inventory-service", "iat": now, "exp": now + 300}


def test_alg_none_fails(keys):
    _, public_pem = keys
    unsigned = jwt.encode(_claims(), None, algorithm="none")  # no signature at all
    with pytest.raises(jwt.InvalidAlgorithmError):
        verify_token(unsigned, public_pem)


def test_hs256_token_fails(keys):
    _, public_pem = keys
    hmac_token = jwt.encode(_claims(), "a-shared-secret-of-at-least-32-bytes!!", algorithm="HS256")
    with pytest.raises(jwt.InvalidAlgorithmError):
        verify_token(hmac_token, public_pem)


def test_rs512_with_the_right_key_still_fails(keys):
    # Even a genuine signature from the real key is refused if the algorithm isn't pinned.
    private_pem, public_pem = keys
    token = jwt.encode(_claims(), private_pem, algorithm="RS512")
    with pytest.raises(jwt.InvalidAlgorithmError):
        verify_token(token, public_pem)
