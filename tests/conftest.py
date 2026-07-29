import os

import pytest
from starlette.testclient import TestClient

_old_init = TestClient.__init__
TEST_INTERNAL_API_TOKEN = "test-internal-api-token-" + ("t" * 32)


def new_init(self, app, *args, **kwargs):
    _old_init(self, app, *args, **kwargs)
    self.headers["X-Ops-Internal-Token"] = os.environ.get(
        "OPS_INTERNAL_API_TOKEN",
        TEST_INTERNAL_API_TOKEN,
    )


TestClient.__init__ = new_init


def _never_load_developer_dotenv() -> None:
    """Keep the developer's ``.env`` out of the test process.

    ``Settings.from_env`` calls ``load_dotenv(".env")``, which mutates
    ``os.environ`` for the WHOLE process. A local file that enables live providers
    (a real API key, ALLOW_LIVE_BROWSER, BROWSER_PROVIDER) then leaks into every
    later test, silently changing which provider path is exercised — and could
    point a test at a real vendor account. Tests must assert code defaults and
    explicitly injected environments only.

    Applied at conftest IMPORT time, because test modules and fixtures build
    settings during collection, before any fixture could run.
    """

    import ops.config

    ops.config.load_dotenv = lambda *args, **kwargs: False


_never_load_developer_dotenv()


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("OPS_INTERNAL_API_TOKEN", TEST_INTERNAL_API_TOKEN)
    monkeypatch.setenv("LANGGRAPH_AES_KEY", "")
    monkeypatch.setenv("BROWSER_USE_API_KEY", "")
    monkeypatch.setenv("COMPOSIO_API_KEY", "")
    monkeypatch.setenv("SECRET_VAULT_KEY", "")
    monkeypatch.setenv("ALLOW_LIVE_BROWSER", "false")
