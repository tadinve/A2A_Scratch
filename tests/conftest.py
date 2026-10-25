"""pytest fixtures. Shared state (keys, tokens, spy class) lives in tests/support.py."""

import pytest
from fastapi.testclient import TestClient

from tests.support import RepoSpy, service


@pytest.fixture
def spy(monkeypatch):
    s = RepoSpy()
    # app.py imported these names directly, so patch the names app uses.
    monkeypatch.setattr(service, "get_classification", s.get_classification)
    monkeypatch.setattr(service, "lookup_sku", s.lookup_sku)
    return s


@pytest.fixture
def client():
    return TestClient(service.app)
