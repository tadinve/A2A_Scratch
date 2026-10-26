"""Load config/delegation_authority.json (override with DELEGATION_AUTHORITY_CONFIG). Fail closed."""

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.getenv("DELEGATION_AUTHORITY_CONFIG",
                             PROJECT_ROOT / "config" / "delegation_authority.json")).expanduser()


def _path(raw: str) -> Path:
    p = Path(raw).expanduser()
    return p if p.is_absolute() else PROJECT_ROOT / p


def _public_keys(entries: dict, label: str) -> dict[str, RSAPublicKey]:
    if not isinstance(entries, dict) or not entries:
        raise RuntimeError(f"{label}: at least one trusted key is required")
    keys = {}
    for kid, raw in entries.items():
        try:
            key = load_pem_public_key(_path(raw).read_bytes())
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"{label} key {kid!r}: {exc}") from None
        if not isinstance(key, RSAPublicKey):
            raise RuntimeError(f"{label} key {kid!r} is not an RSA public key")
        keys[kid] = key
    return keys


@dataclass(frozen=True)
class Trust:
    issuer: str
    keys: dict[str, RSAPublicKey]
    audience: str | None = None          # actor tokens must be minted for THIS authority
    required_scope: str | None = None


@dataclass(frozen=True)
class Policy:
    human_permissions: dict[str, frozenset[str]]
    actor_permissions: dict[str, frozenset[str]]
    may_act_for: dict[str, frozenset[str]]


@dataclass(frozen=True)
class AuthorityConfig:
    issuer: str
    token_audience: str
    token_lifetime_seconds: int
    active_kid: str
    private_key: RSAPrivateKey
    human: Trust
    actor: Trust
    policy: Policy


def load_config(path: Path = CONFIG_PATH) -> AuthorityConfig:
    try:
        raw = json.loads(Path(path).read_text())
        h, a, pol = raw["trusted_human"], raw["trusted_actor"], raw["policy"]
        try:
            private_key = load_pem_private_key(_path(raw["private_key_path"]).read_bytes(), password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise RuntimeError(f"delegation signing key: {exc}") from None
        if not isinstance(private_key, RSAPrivateKey):
            raise RuntimeError("delegation signing key is not an RSA private key")
        cfg = AuthorityConfig(
            issuer=str(raw["issuer"]),
            token_audience=str(raw["token_audience"]),
            token_lifetime_seconds=int(raw["token_lifetime_seconds"]),
            active_kid=str(raw["active_kid"]),
            private_key=private_key,
            human=Trust(str(h["issuer"]), _public_keys(h["keys"], "trusted_human")),
            actor=Trust(str(a["issuer"]), _public_keys(a["keys"], "trusted_actor"),
                        audience=str(a["audience"]), required_scope=str(a["required_scope"])),
            policy=Policy(
                human_permissions={k: frozenset(v) for k, v in pol["human_permissions"].items()},
                actor_permissions={k: frozenset(v) for k, v in pol["actor_permissions"].items()},
                may_act_for={k: frozenset(v) for k, v in pol["may_act_for"].items()},
            ),
        )
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise RuntimeError(f"delegation config not usable at {path}: {exc}") from None
    if cfg.token_lifetime_seconds <= 0:
        raise RuntimeError("token_lifetime_seconds must be positive")
    return cfg
