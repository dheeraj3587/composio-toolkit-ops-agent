"""Streamlit AppTest coverage for the operations-ledger shell."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "streamlit_app.py"
UNCONFIGURED_WORK_EMAIL_REF = "vault://company/work_email/unconfigured"


def _rendered_text(app: AppTest) -> str:
    values: list[str] = []
    for collection_name in (
        "caption",
        "header",
        "info",
        "markdown",
        "metric",
        "success",
        "warning",
    ):
        for element in getattr(app, collection_name):
            value = getattr(element, "value", None)
            if value is not None:
                values.append(str(value))
    return "\n".join(values)


def test_streamlit_shell_renders_honest_phase_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPS_DB_PATH", str(tmp_path / "ops.db"))

    app = AppTest.from_file(str(APP), default_timeout=15).run()

    assert not app.exception
    rendered = _rendered_text(app)
    assert "The research this ledger inherits" in rendered
    assert "Open a dry-run entry" in rendered
    assert "Run status & sanitized timeline" in rendered
    assert "Browser" in rendered
    assert "Email" in rendered
    assert "No vendor is contacted" in rendered
    assert "No IntegratorBundle exists" in rendered
    assert "Reveal secret" not in rendered
    assert "prefers-reduced-motion" in rendered


def test_streamlit_form_records_a_local_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPS_DB_PATH", str(tmp_path / "ops.db"))
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not app.exception

    app.text_input[0].set_value("Linear")
    submit = next(button for button in app.button if button.label == "Record local run")
    submit.click()
    app.run()

    assert not app.exception
    assert app.success
    assert "Local run recorded: run_" in app.success[0].value
    rendered = _rendered_text(app)
    assert "Local dry run" in rendered
    assert "Route Selected" in rendered
    assert "self_serve" in rendered
    assert "external actions: false" in rendered
    assert (tmp_path / "ops.db").is_file()


def test_streamlit_never_prefills_an_invalid_work_email_environment_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_marker = "raw-secret-marker-must-not-render"
    monkeypatch.setenv("OPS_DB_PATH", str(tmp_path / "ops.db"))
    monkeypatch.setenv("COMPANY_WORK_EMAIL_REF", raw_marker)

    app = AppTest.from_file(str(APP), default_timeout=15).run()

    assert not app.exception
    work_email_input = next(
        item for item in app.text_input if item.label == "Work email vault reference"
    )
    assert work_email_input.value == UNCONFIGURED_WORK_EMAIL_REF
    assert raw_marker not in _rendered_text(app)
    assert raw_marker not in "\n".join(str(item.value) for item in app.text_input)
