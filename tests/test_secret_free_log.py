from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "assert_secret_free_log.py"


def _run(tmp_path: Path, text: str, **environment: str) -> subprocess.CompletedProcess[str]:
    logfile = tmp_path / "service.log"
    logfile.write_text(text, encoding="utf-8")
    env = os.environ.copy()
    env.update(environment)
    return subprocess.run(
        [sys.executable, str(CHECKER), str(logfile)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_accepts_sanitized_service_log(tmp_path: Path) -> None:
    result = _run(tmp_path, "browser worker ready; capacity=2\n")
    assert result.returncode == 0
    assert "free of secret-shaped content" in result.stdout


def test_rejects_every_configured_secret_suffix_without_echoing_value(tmp_path: Path) -> None:
    sentinel = "never-print-this-deployment-sentinel"  # pragma: allowlist secret
    for name in (
        "OPS_INTERNAL_API_TOKEN",
        "BROWSER_SESSION_CAPABILITY_KEY",
        "OPS_AUTH_SESSION_SECRET",
        "OPS_AUTH_TOTP_SECRET",
        "OPS_AUTH_PASSWORD",
        "GOOGLE_GENAI_API_KEY",
    ):
        result = _run(tmp_path, f"accidental={sentinel}\n", **{name: sentinel})
        assert result.returncode == 1
        assert "configured_environment_secret" in result.stderr
        assert sentinel not in result.stdout
        assert sentinel not in result.stderr


def test_rejects_fernet_key_at_line_end(tmp_path: Path) -> None:
    key = "A" * 43 + "="  # pragma: allowlist secret - shape-only fixture
    result = _run(tmp_path, f"key={key}\n")
    assert result.returncode == 1
    assert "fernet_key" in result.stderr
    assert key not in result.stderr


def test_rejects_provider_key_shape_without_echoing_value(tmp_path: Path) -> None:
    provider_key = "gsk_" + "A" * 24  # pragma: allowlist secret - shape-only fixture
    result = _run(tmp_path, f"provider={provider_key}\n")
    assert result.returncode == 1
    assert "provider_key" in result.stderr
    assert provider_key not in result.stderr
