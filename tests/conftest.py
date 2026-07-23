import os

import pytest
from starlette.testclient import TestClient

_old_init = TestClient.__init__


def new_init(self, app, *args, **kwargs):
    _old_init(self, app, *args, **kwargs)
    self.headers["X-Ops-Internal-Token"] = os.environ.get(
        "OPS_INTERNAL_API_TOKEN",
        "test-secret-token",
    )


TestClient.__init__ = new_init


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("OPS_INTERNAL_API_TOKEN", "test-secret-token")
    monkeypatch.setenv("LANGGRAPH_AES_KEY", "")
    monkeypatch.setenv("BROWSER_USE_API_KEY", "")
    monkeypatch.setenv("COMPOSIO_API_KEY", "")
    monkeypatch.setenv("SECRET_VAULT_KEY", "")
    monkeypatch.setenv("ALLOW_LIVE_BROWSER", "false")
