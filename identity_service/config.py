"""Load config/identity_service.json (override path with IDENTITY_SERVICE_CONFIG). Fail closed.

IDENTITY_PRIVATE_KEY_PATH overrides the file's private_key_path. On Cloud Run the key is
a Secret Manager secret mounted as a file there (Day 08); nothing else changes.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.getenv("IDENTITY_SERVICE_CONFIG", PROJECT_ROOT / "config" / "identity_service.json")).expanduser()


def resolve_path(raw: str) -> Path:
    """'~' expands to home; relative paths are relative to the project root."""
    path = Path(raw).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True)
class IdentityConfig:
    issuer: str
    audience: str
    token_lifetime_seconds: int
    active_kid: str
    private_key_path: Path


def load_config(path: Path = CONFIG_PATH) -> IdentityConfig:
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"identity config not readable at {path}: {exc}") from None
    try:
        cfg = IdentityConfig(
            issuer=str(raw["issuer"]),
            audience=str(raw["audience"]),
            token_lifetime_seconds=int(raw["token_lifetime_seconds"]),
            active_kid=str(raw["active_kid"]),
            private_key_path=resolve_path(os.getenv("IDENTITY_PRIVATE_KEY_PATH") or raw["private_key_path"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"{path}: missing or invalid setting: {exc}") from None
    if not all([cfg.issuer, cfg.audience, cfg.active_kid]) or cfg.token_lifetime_seconds <= 0:
        raise RuntimeError(f"{path}: issuer, audience, active_kid and a positive lifetime are required")
    return cfg
