"""Test configuration for the inventory service.

Keys are set here, before the service is imported, so tests never depend on
inventory_service/.env. load_dotenv does not override variables already set.
"""

import os

READER_KEY = "test-reader-key"
RESTRICTED_KEY = "test-restricted-key"

os.environ["INVENTORY_AGENT_API_KEY"] = READER_KEY
os.environ["RESTRICTED_AGENT_API_KEY"] = RESTRICTED_KEY
