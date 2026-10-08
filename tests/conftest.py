# tests/conftest.py
# Shared pytest fixtures for the Fractal Vault trust engine test suite.

import os
import sys

import pytest

BACKEND_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend-python"
)

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# The app refuses every protected request when these are empty, so the tests
# must set them before `app` is imported. test_*.py read them back.
INTERNAL_KEY = "test-internal-key-0123456789abcdef"
LOG_KEY = "test-log-key-0123456789abcdef"


@pytest.fixture(scope="session", autouse=True)
def _test_secrets():
    os.environ["FLASK_INTERNAL_API_KEY"] = INTERNAL_KEY
    os.environ["LOG_API_KEY"] = LOG_KEY
    os.environ["FLASK_DEBUG"] = "false"
    yield


@pytest.fixture(scope="session")
def client(_test_secrets):
    from app import app

    app.config.update(TESTING=True)

    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"X-Internal-Key": INTERNAL_KEY}


@pytest.fixture
def log_headers():
    return {"X-API-Key": LOG_KEY}