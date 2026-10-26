"""Password hashing (Day 06.02). The service stores ONLY these hashes, never a password.

Argon2id: a deliberately slow, memory-hard hash. The library generates a fresh
random salt on every hash_password() call, and the stored string carries the
algorithm, its cost settings and the salt:

    $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

Nothing in this module logs or prints a password.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # library defaults: argon2id, t=3, m=64 MiB, p=4

MAX_PASSWORD_LENGTH = 1024  # stop absurdly long inputs from being hashed


def hash_password(password: str) -> str:
    """Return a salted Argon2id hash. Each call uses a new random salt."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError("password is too long")
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """True if `password` matches `stored_hash`. Re-hashes with the stored salt and
    settings, then compares in constant time. Never raises for a bad password or hash."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when the hash was made with weaker settings than today's."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return False


# Verified against when a username doesn't exist, so "no such user" costs the
# same hashing time as "wrong password" and timing can't reveal real accounts.
DUMMY_HASH = _hasher.hash("dummy-password-never-matches")
