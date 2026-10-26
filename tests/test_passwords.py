"""Day 06.02 completion test: salted Argon2id hashing, nothing logged."""

import logging

from identity_service.passwords import hash_password, verify_password


def test_welcome123_hashed_twice_differs_and_both_verify():
    first = hash_password("Welcome123")
    second = hash_password("Welcome123")
    print(f"\nfirst : {first}\nsecond: {second}")
    assert first != second                          # a fresh random salt each call
    assert first.startswith("$argon2id$") and second.startswith("$argon2id$")
    assert verify_password("Welcome123", first)
    assert verify_password("Welcome123", second)


def test_wrong_password_is_false():
    stored = hash_password("Welcome123")
    assert verify_password("welcome123", stored) is False   # case matters
    assert verify_password("Welcome1234", stored) is False
    assert verify_password("", stored) is False


def test_garbage_hash_is_false_not_an_error():
    assert verify_password("Welcome123", "not-a-hash") is False


def test_the_hash_does_not_contain_the_password():
    assert "Welcome123" not in hash_password("Welcome123")


def test_nothing_is_logged(caplog):
    with caplog.at_level(logging.DEBUG):
        verify_password("Welcome123", hash_password("Welcome123"))
        verify_password("wrong", hash_password("Welcome123"))
    assert caplog.text == ""
