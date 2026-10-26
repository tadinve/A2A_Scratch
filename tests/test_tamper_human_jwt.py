"""Day 06.05: the payload-tampering experiment stays green in the regular suite."""

import pytest

from tests.support import IDENTITY_PRIVATE_FILE, IDENTITY_PUBLIC_PEM

from identity_service import tokens  # noqa: E402
from identity_service.config import load_config
from scripts.tamper_human_jwt import run_experiments


@pytest.mark.parametrize("target", ["user-002", "admin"])
def test_every_forgery_is_rejected_and_the_original_accepted(target):
    token = tokens.issue_user_token(load_config(), tokens.load_private_key(IDENTITY_PRIVATE_FILE), "user-001")
    results = run_experiments(token, IDENTITY_PUBLIC_PEM, target, verbose=False)
    assert [label for label, ok in results if not ok] == []
    assert len(results) == 7
