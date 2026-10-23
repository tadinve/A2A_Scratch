# Day 02 — Learnings: A Credential Check Inside the Tool

**Built:** `get_stock(sku)` (model-facing) now delegates to `protected_get_stock(sku, credential)`, which verifies a shared secret before any SQLite lookup.
**Evidence:** `scripts/check_auth.py` passed: correct secret gave `found` with a lookup, `None` and a wrong secret gave `unauthenticated` with no lookup.

## Key ideas

- **The model never needs the credential.** The tool schema still has only `sku`. Python code fetches the secret from the environment and attaches it. A model can't leak, forget, or be tricked into sending what it never sees.
- **Identity is established by application code,** at the point where `get_stock` reads `INVENTORY_SHARED_SECRET` and the verifier maps it to `INVENTORY_PRINCIPAL`.
- **Fail closed.** If the expected secret is missing or empty, every call is rejected. An empty string must never match an empty string.
- **`secrets.compare_digest`** compares in constant time, so response timing doesn't reveal how many characters of a guess were right.
- **Verify, then act.** The lookup is unreachable unless authentication returns a principal.
- **Tell the model how to report failures.** One added instruction line makes it say "could not be authenticated" and never ask the user for a credential.
- **Authentication is not authorization.** Day 02 proves *who* is calling. Deciding *what* they may do comes later.

## The limit we discovered

This was a teaching check inside one process. `get_stock` reads the credential from the same environment variable the verifier checks, so both sides always match. Through `adk web`, you can't produce a wrong-token case, only a missing-secret case. Any code in the process could also read the secret or call the lookup directly. **A check isn't a boundary while the caller and the verifier share one process and one secret store.** That is the motivation for Day 03.

## How to test a credential check

- **Test the protected function directly,** so you control the credential you pass in.
- **Count lookups, don't just read statuses.** The check script wraps `_lookup_sku` with a counter to prove the rejected cases never touch SQLite.
- `ok &= passed` keeps a running "all passed so far". Once one case fails, `ok` stays `False`, but every case still runs and prints.

## Gotcha we hit

Renaming `correct` to `INVENTORY_SHARED_SECRET` in the check script left one `if not correct:` behind, which raises a NameError. When renaming a variable, search for every use.
