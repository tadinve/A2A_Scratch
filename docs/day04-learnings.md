# Day 04 — Learnings: Authorization (Who Is Allowed to Do What?)

**Built:** role-based access control (RBAC) inside the Day 03 inventory service, in four increments. The endpoint, SQLite schema, and agent tool interface are unchanged.
**Evidence:** 19 pytest tests passed, with `sqlite_lookup=False` for every unauthorized case. Live curl returned 403 for the restricted key, and the Day 03 agent check still printed ALL PASS.

## The chain

```
X-API-Key  ->  identity           ->  role               ->  permissions        ->  decision
(credential)   (principal)            (server-assigned)      (granted by role)
auth.py        auth.py                authz.py               authz.py               app.py
```

| Step | Fails with | Lives in | Knows about |
|---|---|---|---|
| Authenticate: key to identity | 401 | `auth.py` | Keys and identities only |
| Resolve the role | (no role means denied) | `authz.py` | Identities and roles |
| Check `inventory.read` | 403 | `authz.py` | Roles and permissions |
| Look up the SKU | 404 if absent | `repository.py` | SQL only, with no keys or roles |

## 401 vs 403

- **401 Unauthorized:** "I can't tell who you are." The key is missing or matches no one. The response includes `WWW-Authenticate: ApiKey`, a challenge to try again with a credential.
- **403 Forbidden:** "I know exactly who you are, and you may not do this." Sending the same request again won't help, so no challenge header.

## How it was built, increment by increment

| Increment | Change | What we observed |
|---|---|---|
| 1. Identity | Two keys map to `inventory-agent` and `restricted-agent` | Both 200. The log shows which identity called. |
| 2. Roles | Identity maps to `inventory_reader` or `restricted` | Still both 200. A spoofed `X-Role` header changed nothing in the log. |
| 3. Permissions | `inventory_reader` grants `inventory.read`, `restricted` grants nothing | Restricted got 403, and its log said FORBIDDEN with no lookup |
| 4. Hardening | Consistent `{status, message}` errors and the test suite | 19 passed |

## Key ideas

- **The server assigns roles, never the caller.** The endpoint doesn't read any role, identity, or permission from the request. `X-Role`, `X-Identity`, and `X-Permissions` had nothing to override, and all got 403.
- **Permissions attach to roles, not names.** No code says `if identity == "restricted-agent"`. A test proved it: granting `inventory.read` to the `restricted` role made the same restricted key pass, without touching code.
- **Deny by default.** An identity with no role, a role missing from the permission table, and a role without the permission are all denied.
- **Check order matters.** Restricted asking for unknown WIDGET-X got 403, not 404. Authorization runs before the lookup, so a forbidden caller can't learn whether a SKU exists.
- **The business function is auth-free.** `lookup_sku(sku)` takes only a SKU. A test asserts its module contains no key, role, or permission code.
- **Fail closed at startup.** A missing key, or two identities sharing one key, stops the service. A shared key would make "who is calling" ambiguous.
- **Errors never echo secrets.** Every error body is a fixed `{status, message}`. Tests check that no key appears in any response.
- **Compare every key.** Authentication loops over all known keys with `compare_digest`, rather than stopping at the first match.

## Testing technique

- **Spy on the lookup, don't just read statuses.** The test replaces `lookup_sku` with a recorder. A 403 alone doesn't prove the database was skipped. `sqlite_lookup=False` does.
- **Patch the name the caller uses.** `app.py` does `from repository import lookup_sku`, so the spy must replace `inventory_service.app.lookup_sku`, not the repository's copy.
- **Set config before import.** `conftest.py` sets test keys before the service loads, and `load_dotenv` never overrides variables already set.
- **Change config to prove design.** `monkeypatch` on the role and permission tables turned "the code doesn't hard-code names" into a passing test.

## The interview answer

> *An agent sends a valid API key, but the service responds 403. Explain the sequence.*

The **credential** (the `X-API-Key` value) is compared in constant time against the service's configured keys. It matches, so authentication succeeds and resolves the **identity**, or principal, `restricted-agent`. Otherwise it would be 401. The service looks up that identity's **role** in its own table, getting `restricted`, and ignores any role the caller claims. The endpoint protects a **resource**, inventory records, and requires the **permission** `inventory.read`. The role-to-permission table shows `restricted` grants nothing, so the **authorization decision** is deny. The service returns 403 with `{"status":"forbidden",...}` and never calls the SQLite lookup. The same request with the `inventory-agent` key resolves to `inventory_reader`, which grants `inventory.read`, so it gets 200.

## Limitation to remember

**Possession of the key is the identity.** The service can't tell whether the real `inventory-agent` process sent the request or someone who copied its key. A stolen key impersonates that identity fully, including its role and permissions. The keys are also static, never expire, and are compared to plain values in a `.env` file. Stronger identity, such as short-lived tokens and workload identity, comes on later days.

## Small notes

- The agent tool now maps 403 to `forbidden`, and the agent instructions say to report that the assistant isn't permitted to read inventory.
- pytest warns that `starlette.testclient` wants `httpx2`. This is a dependency deprecation and harmless for now.

## Final increment — Class-based authorization: the resource matters too

**Built:** an `inventory_class` column (A, B, or C) on each record, and a policy where each class needs its own permission.

| Caller | Class A | Class B | Class C |
|---|---|---|---|
| inventory-agent (`inventory_reader`) | 200 | 200 | 200 |
| restricted-agent (`restricted`) | **403** | 200 | 200 |
| Invalid key | 401 | 401 | 401 |

**Evidence:** reproducible with two commands.

- `uv run pytest -v` gives **43 passed**. That covers the full 12-cell grid with detail-lookup counts, the original seven scenarios, deny by default, header and query spoofing, and migration tests on a throwaway database.
- `uv run python scripts/check_remote_auth.py` against the live service gives **28/28 checks passed**:

```
              class A  class B  class C
privileged        200      200      200
restricted        403      200      200
invalid           401      401      401
missing           401      401      401
```

The live run also showed that every denied body was exactly `{status, message}`, with no name, quantity, or key. Spoofed `X-Inventory-Class`, `X-Role`, and `X-Permissions` headers and an `?inventory_class=C` query parameter all still got 403.

### The new flow

```
authenticate key     -> 401 if unknown
read class only      -> 404 if SKU absent, 503 if unreadable (fail closed)
check permission     -> 403 if role lacks inventory.read.class_<x>
read name + quantity -> 200
```

### Key ideas

- **Authorization is caller × action × resource.** Up to increment 3, the decision used only who was calling. Now the same identity gets different answers for different records. That is the step from role-based toward attribute-based access control (ABAC).
- **The class is data, not a naming convention.** It is stored in SQLite and never derived from the SKU text. A test reclassified WIDGET-C as A, and the restricted caller was denied immediately with no code change.
- **Metadata before data.** To decide, the service must first read the class. That read happens only after authentication and returns only the class. The protected name and quantity are read only after the permission check passes. A 403 body carries nothing but `status` and `message`.
- **The cost: an existence oracle.** Increment 3 denied restricted callers before touching the database, so an unknown SKU looked the same as a forbidden one: 403 either way. Now a restricted caller gets 404 for a missing SKU and 403 for a class A SKU, so it can learn which SKUs exist. If that mattered, the service could return 404 for both, hiding forbidden items as if absent, the way GitHub hides private repositories.
- **Fail closed everywhere.** Rows without a class default to A, the most restrictive. The database rejects any class outside A, B, and C. A class no role grants, such as D, is denied. A failed class lookup returns 503, never a guess.
- **Safe migrations.** The column is added only if missing, seed classes are applied once during that migration, and reruns never overwrite a class someone changed. The real database was backed up first and migrated, and a second run changed nothing.

### Behavior changes from increment 3

| Request | Before | Now |
|---|---|---|
| Restricted, WIDGET-B or WIDGET-C | 403 | 200 |
| Restricted, unknown SKU | 403, no database access | 404, after a class lookup |
| Database unreadable | 200 with an `error` body | 503 `error` |
