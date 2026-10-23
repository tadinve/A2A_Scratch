# Day 01 — Learnings: ADK Inventory Agent

**Built:** one ADK agent (`inventory_agent`), one tool (`get_stock`), one SQLite table.
**Evidence:** [day01-example.md](day01-example.md) has the captured tool call, result, and answer.

## Who does what

| Layer | Job | What it never does |
|---|---|---|
| Model (Gemini) | Decides whether to call a tool, extracts the SKU, words the reply | Writes SQL, sees the database |
| ADK | Turns the Python function into a tool schema, runs the call loop, shows events in `adk web` | Decides the answer |
| Python tool | Normalizes the SKU, runs one fixed parameterized query, returns a status dict | Trusts the model with anything beyond the SKU string |
| SQLite | Stores the `inventory` table | Knows anything about agents |

## Key ideas

- **The model supplies data, your code owns the SQL.** The SKU is a bound `?` parameter, so the model's text can never change the query.
- **ADK builds the tool schema from the function.** The request trace showed `function_declarations` generated from `get_stock`'s signature and docstring. The docstring is model-facing text, so treat it as part of the prompt.
- **Structured results beat prose.** `found`, `not_found`, and `error` let the model distinguish cases instead of guessing.
- **Zero is not "not found".** WIDGET-C exists with quantity 0, and the agent must say "out of stock", not "unknown item".
- **The instructions changed behavior without code.** "How many widgets do we have?" produced no tool call, only a request for the SKU.

## Engineering details worth remembering

- **Read-only connection:** `sqlite3.connect("file:...?mode=ro", uri=True)`. A plain `connect()` on a missing file silently creates an empty database, which would turn "database gone" into "item not found".
- **Paths relative to `__file__`,** not the working directory, so `adk web` works from any terminal location.
- **Idempotent seeding:** `CREATE TABLE IF NOT EXISTS` plus `INSERT OR IGNORE`. Reruns never duplicate rows or reset quantities.
- **Always close the connection** in `finally`.

## Environment gotchas we hit

- **uv environment outside the repo:** `UV_PROJECT_ENVIRONMENT="$HOME/venv/a2aS"` keeps `.venv` out of the project folder.
- **Renaming a venv's prompt:** the name shown as `(name)` is baked into `pyvenv.cfg` and every `bin/activate*` script when the venv is created. Changing `name` in `pyproject.toml` does not update it.
- **`.env` stays out of Git.** The agent folder's `.env` is a symlink to the root `.env`, and both are in `.gitignore`.

## Checks passed

| Ask | Result |
|---|---|
| WIDGET-A / WIDGET-B | Tool called, correct quantity reported |
| WIDGET-C | "Out of stock", not "not found" |
| WIDGET-X | Not found |
| No SKU given | Agent asked for the SKU, no tool call |
| Database renamed | "Temporarily unavailable", no invented number |
