# Day 01 — Example tool call

Captured from the ADK dev UI request trace (model: `gemini-3.6-flash`).

## Found item

**User:** WIDGET-B

**Tool call (model → ADK):**

```json
{ "name": "get_stock", "args": { "sku": "WIDGET-B" } }
```

**Tool result (Python → ADK → model):**

```json
{ "status": "found", "sku": "WIDGET-B", "name": "Heavy-duty Widget", "quantity": 12 }
```

**Agent:** We have 12 units of Heavy-duty Widget (SKU: WIDGET-B) in stock.

## Other cases from the same session

| User | Tool result | Agent answer |
|---|---|---|
| how many widgets do we have? | *(no call)* | Could you please provide the specific SKU for the widget you would like to check? |
| WIDGET-C | `{"status": "found", "quantity": 0, ...}` | Mini Widget (SKU: WIDGET-C) is currently out of stock (0 units remaining). |
| WIDGET-X | `{"status": "not_found", "sku": "WIDGET-X"}` | SKU WIDGET-X was not found in the inventory database. |
| WIDGET-C *(db renamed)* | `{"status": "error", "message": "Inventory is temporarily unavailable."}` | Inventory is temporarily unavailable. Please try checking SKU WIDGET-C again later. |
| WIDGET-C *(db restored)* | `{"status": "found", "quantity": 0, ...}` | Out of stock again, confirming the database was restored. |

## What each layer did

- **Model (Gemini):** decided when a tool call was needed, extracted the SKU, and worded the reply. It never saw SQL.
- **ADK:** turned `get_stock`'s signature and docstring into the `function_declarations` schema, ran the call/response loop, and logged every event.
- **Python tool:** normalized the SKU, ran one fixed parameterized `SELECT`, and returned a status dict.
- **SQLite:** served the `inventory` table read-only from `data/inventory.db`.
