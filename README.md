# Day 01 — ADK Inventory Agent

One agent, one tool, one table. The agent answers stock questions by calling
`get_stock(sku)`, which runs a fixed parameterized query against a local SQLite
database.

## Who does what

| Part | Role |
|---|---|
| **Model (Gemini)** | Reads the user's question, decides to call `get_stock`, extracts the SKU, and phrases the final answer from the tool result. |
| **ADK** | Wraps the model in an agent, turns the Python function into a tool schema, runs the call loop, and provides the local dev UI with tool-call tracing. |
| **Python tool** | `get_stock` normalizes the SKU, runs the SQL, and returns a structured `found` / `not_found` / `error` dict. It owns the SQL; the model never writes any. |
| **SQLite** | Holds the `inventory` table in `data/inventory.db`. |

## Setup

```bash
export UV_PROJECT_ENVIRONMENT="$HOME/venv/a2aS"
uv sync
cp inventory_agent/.env.example inventory_agent/.env   # then edit
uv run python scripts/init_db.py
```

`scripts/init_db.py` is idempotent: rerunning it never duplicates rows or resets quantities.

## Run

```bash
uv run adk web --port 8080   # the inventory service uses 8000
```

Open the URL it prints and pick `inventory_agent`. The Events panel shows each
tool call's arguments and result.

## Checks

| Ask | Expected |
|---|---|
| How many WIDGET-A do we have? | Calls the tool, reports 30 Standard Widgets |
| Do we have WIDGET-C? | Item exists but has zero stock |
| How many WIDGET-X? | Item not found |
| How much stock do we have? | Asks for the SKU |
| Rename `data/inventory.db`, ask about WIDGET-A | Reports inventory unavailable, no guessing |

Restore the database afterwards (`mv data/inventory.db.bak data/inventory.db`).

## Project layout

| File | Purpose |
|---|---|
| `inventory_agent/__init__.py` | Exposes the agent module to ADK |
| `inventory_agent/agent.py` | Agent definition, instructions, tool registration |
| `inventory_agent/tools.py` | SQLite lookup function |
| `inventory_agent/.env` | Local model config and credentials (git-ignored) |
| `inventory_agent/.env.example` | Configuration placeholders |
| `scripts/init_db.py` | Create and seed the database |
| `data/inventory.db` | Generated SQLite database (git-ignored) |
| `pyproject.toml`, `uv.lock` | Dependencies |
| `graphify/` | Knowledge graph of this repo and how to rebuild it (see [graphify/README.md](graphify/README.md)) |

## Example trace

See [local-implementation-docs/day01-example.md](local-implementation-docs/day01-example.md) for a captured tool call, result, and final answer, plus the other four checks.

## Day 02: credential check

`get_stock(sku)` is still the only tool the model sees, and its schema still has only `sku`.
Inside, it reads `INVENTORY_SHARED_SECRET` from the environment and calls
`protected_get_stock(sku, credential)`, which verifies it with `secrets.compare_digest`
before running the SQLite query. A missing expected secret, a missing credential, or a
wrong credential all return:

```json
{ "status": "unauthenticated", "message": "Inventory access could not be authenticated." }
```

Add to `inventory_agent/.env` (generate the secret locally, never commit it):

```dotenv
INVENTORY_PRINCIPAL=inventory_agent
INVENTORY_SHARED_SECRET=<python3 -c "import secrets; print(secrets.token_urlsafe(32))">
```

Check the three cases directly:

```bash
uv run python scripts/check_auth.py
```

This is a teaching check inside one process. Any code in the process can read the secret
or call the lookup directly, so it is not an enforcement boundary yet.

## Learnings

- [Day 01: ADK inventory agent](local-implementation-docs/day01-learnings.md)
- [Day 02: credential check inside the tool](local-implementation-docs/day02-learnings.md)
- [Day 03: HTTP, headers, Postman, API-key auth](local-implementation-docs/day03-learnings.md)
- [Day 04: authorization with roles and permissions](local-implementation-docs/day04-learnings.md)
- [Day 05: JWTs, token issuer, scopes, token lifecycle, key rotation](local-implementation-docs/day05-learnings.md) · [rotation runbook](local-implementation-docs/day05-key-rotation-runbook.txt)
- [Day 06: acting on behalf of a human (deck)](local-implementation-docs/day06-acting-for-humans.pptx) · [end-to-end JWT flow](<local-implementation-docs/End-to-End JWT Inventory Flow.png>)
