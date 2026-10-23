"""Day 01 inventory agent: one agent, one tool, one table."""

import os
from pathlib import Path

from dotenv import load_dotenv
from google.adk.agents import Agent

from .tools import get_stock

# Load inventory_agent/.env so the model name and credentials are available
# regardless of the working directory. ADK also loads it, but this makes the
# module usable outside `adk web`.
load_dotenv(Path(__file__).resolve().parent / ".env")

MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

INSTRUCTION = """You are an inventory assistant.

For stock questions, use the get_stock tool with the requested SKU.
Always check the tool before answering a stock question.
If the user does not provide a SKU, ask for it.
Answer briefly using the tool result.
Distinguish an item with zero stock from an item that was not found.
If the tool reports an error, explain that inventory is temporarily unavailable.
If the tool returns unauthenticated, report that inventory access could not be authenticated. Do not ask the user for a credential.
If the tool returns forbidden, report that this assistant is not permitted to read inventory.
Do not invent quantities.
You can check stock but cannot update inventory or create purchases.
"""

root_agent = Agent(
    name="inventory_agent",
    model=MODEL,
    description="Answers stock-level questions by looking up SKUs in the inventory database.",
    instruction=INSTRUCTION,
    tools=[get_stock],
)
