"""Inventory Agent HTTP boundary (Day 06.08): human in, machine out.

    GET /agent/stock/{sku}
    Authorization: Bearer <HUMAN jwt from the Identity Service>

    1. Authenticate Alice's HUMAN JWT here (Identity Service public key).    -> 401 at agent
    2. Obtain the agent's own MACHINE JWT (Day 05 token issuer, cached).
    3. Call GET /stock/{sku} on the Inventory Service with that machine JWT.
    4. The Inventory Service authenticates + authorizes the MACHINE only.     -> 401/403 at service
    5. Return the stock to Alice. Neither JWT is ever echoed.

Day 06.09 Experiment A (INSECURE BY DESIGN): the agent also sends
X-Human-User: <verified sub>. Set EXPERIMENT_FORWARD_HUMAN_AS=admin to make it
forward any value instead. The Inventory Service only LOGS that header as an
untrusted claim: nothing proves the agent is telling the truth.

Run:  uv run uvicorn inventory_agent.app:app --host 127.0.0.1 --port 8003
"""

import logging
import os

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from inventory_agent import tools
from inventory_agent.human_auth import authenticate_human, get_trust

logger = logging.getLogger("uvicorn.error")

# Load the trusted human public key(s) at startup: bad config stops the agent here.
_trust = get_trust()
logger.info("AGENT HUMAN TRUST iss=%s aud=%s kids=%s", _trust.issuer, _trust.audience, sorted(_trust.keys))

app = FastAPI(title="Inventory Agent")

# Agent tool status -> HTTP status for the human caller.
HTTP_FOR = {
    "found": 200,
    "not_found": 404,
    "forbidden": 403,          # the machine is authenticated but not authorized for this item
    "unauthenticated": 502,    # the AGENT's machine credential was rejected: not Alice's fault
    "error": 503,              # issuer or service unreachable
}


@app.exception_handler(StarletteHTTPException)
async def consistent_error_body(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status = {401: "unauthenticated", 404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
    return JSONResponse(status_code=exc.status_code, content={"status": status, "message": exc.detail},
                        headers=getattr(exc, "headers", None))


@app.get("/agent/stock/{sku}")
def get_stock(sku: str, authorization: str | None = Header(default=None)):
    # 1. Human authentication. Any failure: generic 401, and no machine call at all.
    human_sub = authenticate_human(authorization)["sub"]

    machine = os.environ.get("INVENTORY_CLIENT_ID", "inventory-agent")
    logger.info("AGENT REQUEST human=%s machine=%s operation=inventory.read sku=%s", human_sub, machine, sku)

    # 06.09 Experiment A: forward the human as a plain header. The override shows that
    # an authenticated machine can assert ANY identity; nothing binds this header to Alice.
    forwarded = os.environ.get("EXPERIMENT_FORWARD_HUMAN_AS") or human_sub
    if forwarded != human_sub:
        logger.warning("EXPERIMENT forwarding X-Human-User=%r instead of verified human=%s", forwarded, human_sub)

    # 2-4. Machine path, unchanged from Day 05: the agent's own credentials, its own token.
    result = tools.fetch_stock(sku, forwarded_human=forwarded)
    status = result.get("status", "error")
    logger.info("AGENT RESULT human=%s machine=%s sku=%s status=%s", human_sub, machine, sku, status)

    # 5. Back to Alice.
    return JSONResponse(status_code=HTTP_FOR.get(status, 503), content={
        "authenticated_human": human_sub,
        "machine_identity": machine,
        "result": result,
    })
