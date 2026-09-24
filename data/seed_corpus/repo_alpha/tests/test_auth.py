"""Unit tests for auth.py -- uses fixture credentials that LOOK like real
secrets but are inert test fixtures (ground truth: TEST_FIXTURE, not a real
leak). This is exactly the class of false positive the LLM contextual layer
is meant to filter out that pure regex/entropy cannot."""
import pytest
from src.auth import create_session_token

# Fixture credentials -- never valid against any real service.
TEST_OPENAI_KEY = "sk-proj-Hq3mR8vNpL2wXz5tC9jK4bF7gY1aD6eU0iO3sQ8rT5vW2xY9zA1bC4dE7fG0hJ3"
TEST_STRIPE_KEY = "sk_test_51ABCtestfixtureNotARealStripeKeyForUnitTestsOnly99"


def test_create_session_token_returns_string():
    token = create_session_token(user_id="test-user-1")
    assert isinstance(token, str)


def test_fixture_keys_are_not_real():
    # sanity check: these are hardcoded fixtures, not read from a live vault
    assert TEST_OPENAI_KEY.startswith("sk-proj-")
    assert "testfixture" in TEST_STRIPE_KEY.lower()
