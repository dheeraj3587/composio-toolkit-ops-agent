"""The capture write is pattern-gated, and both transports go through one gate.

These tests exist because ``SQLiteSecretStore.capture_with_grant`` applies NO
pattern of its own. The anchored ``credential_value_pattern`` is the only thing
standing between a value read off an untrusted page and a durable vault row, so the
tests assert on WRITES OBSERVED, not on the return value: a refusal that still wrote
would pass a return-value assertion and fail these.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from ops.credentials.capture_boundary import CaptureRefused, capture_validated_credential
from ops.credentials.capture_specs import CredentialCaptureSpec
from ops.onboarding.adapters import SessionCredentialSurface

# The checked-in api_key contract, anchored end to end.
_PATTERN = r"\A[A-Za-z0-9_.~+/=-]{16,4096}\Z"
_VALID = "sk_live_0123456789abcdef"


def _spec() -> CredentialCaptureSpec:
    return CredentialCaptureSpec(
        app_slug="acme",
        url="https://acme.example/keys",
        vendor_domain="acme.example",
        field_kind="api_key",
        value_pattern=_PATTERN,
        selectors=(),
    )


@dataclass
class _RecordingVault:
    """Records every write it is asked to perform, so a refusal is observable."""

    writes: list[str] = field(default_factory=list)

    def capture_with_grant(
        self,
        grant: str,
        *,
        app_slug: str,
        kind: str,
        scope_id: str,
        session_id: str,
        value: str,
        expected_operation_key: str,
    ) -> str:
        del grant, app_slug, scope_id, session_id, expected_operation_key
        self.writes.append(value)
        return f"vault://acme/{kind}/rowid123"


def _capture(vault: _RecordingVault, value: str, *, kind: str = "api_key") -> str:
    return capture_validated_credential(
        store=vault,
        spec=_spec(),
        grant="bsg_" + "a" * 43,
        app_slug="acme",
        kind=kind,
        scope_id="run_" + "0" * 32,
        session_id="bs_" + "0" * 32,
        value=value,
        operation_key="key:capture:browser_capture_api_key",
    )


def test_a_conforming_value_is_stored_once() -> None:
    vault = _RecordingVault()
    assert _capture(vault, _VALID).startswith("vault://acme/api_key/")
    assert vault.writes == [_VALID]


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("short", "below the 16-character floor"),
        (f"{_VALID} and then some page prose", "trailing page text is not the credential"),
        (f"prefix {_VALID}", "leading page text is not the credential"),
        (f"{_VALID}\nsecond-line", "a newline cannot smuggle a second value past the anchors"),
        ("", "an empty read is not a credential"),
    ],
)
def test_a_nonconforming_value_is_refused_with_no_write(value: str, why: str) -> None:
    vault = _RecordingVault()
    with pytest.raises(CaptureRefused):
        _capture(vault, value)
    # The point of the test: nothing reached the vault.
    assert vault.writes == [], why


def test_a_kind_the_contract_does_not_declare_is_refused_with_no_write() -> None:
    vault = _RecordingVault()
    with pytest.raises(CaptureRefused):
        _capture(vault, _VALID, kind="oauth_client_secret")
    assert vault.writes == []


# --- the in-process surface: broad read, single-candidate rule ----------------


@dataclass
class _Element:
    index: int
    secretish: bool = True
    visible: bool = True


@dataclass
class _Inspection:
    elements: tuple[_Element, ...]
    url: str = "https://acme.example/keys"


@dataclass
class _Observation:
    status: str = "credential_page_ready"
    credential_field_labels: tuple[str, ...] = ("API key",)
    human_action_type: None = None
    reason_code: None = None
    developer_app_id: None = None


@dataclass
class _LoopObservation:
    observation: _Observation


@dataclass
class _FakeSession:
    """A loop session that reports a fixed page and a fixed set of read values."""

    candidates: tuple[str, ...]
    observation: _Observation = field(default_factory=_Observation)
    elements: tuple[_Element, ...] = (_Element(index=3),)
    session_id: str = "bs_" + "0" * 32
    reads: int = 0

    async def observe(self) -> _LoopObservation:
        return _LoopObservation(observation=self.observation)

    async def inspect(self) -> _Inspection:
        return _Inspection(elements=self.elements)

    async def read_pattern_matched(
        self, *, element_indexes: Any, inspection: Any, value_pattern: str
    ) -> tuple[str, ...]:
        del inspection
        self.reads += 1
        assert value_pattern == _PATTERN, "the read is filtered by the checked-in pattern"
        assert tuple(element_indexes) == (3,), "the read is index-addressed, not selector-addressed"
        return self.candidates


def _surface(session: _FakeSession, vault: _RecordingVault) -> SessionCredentialSurface:
    return SessionCredentialSurface(
        session=session,  # type: ignore[arg-type]
        store=vault,
        spec_for=lambda kind: _spec(),
        run_id="run_" + "0" * 32,
        app_slug="acme",
        operation_key="key:capture:browser_capture_api_key",
    )


def test_arming_refuses_when_the_page_is_not_the_credential_surface() -> None:
    # ``credential_visible`` requires BOTH the status and the labels; drop the labels.
    session = _FakeSession(
        candidates=(_VALID,),
        observation=_Observation(credential_field_labels=()),
    )
    vault = _RecordingVault()
    assert asyncio.run(_surface(session, vault).arm_credential_surface()) is False
    assert vault.writes == []


def test_one_passing_candidate_is_captured() -> None:
    session = _FakeSession(candidates=(_VALID,))
    vault = _RecordingVault()
    surface = _surface(session, vault)

    async def _run() -> str:
        assert await surface.arm_credential_surface() is True
        return await surface.capture_credential(grant="bsg_" + "a" * 43, kind="api_key")

    assert asyncio.run(_run()).startswith("vault://acme/api_key/")
    assert vault.writes == [_VALID]


def test_two_passing_candidates_pause_rather_than_guess() -> None:
    """Ambiguity must not be resolved by picking the first one.

    Storing the wrong value fails later at credential validation, where it is far
    harder to diagnose than a paused run.
    """

    session = _FakeSession(candidates=(_VALID, "sk_live_fedcba9876543210"))
    vault = _RecordingVault()
    surface = _surface(session, vault)

    async def _run() -> None:
        assert await surface.arm_credential_surface() is True
        await surface.capture_credential(grant="bsg_" + "a" * 43, kind="api_key")

    with pytest.raises(CaptureRefused):
        asyncio.run(_run())
    assert vault.writes == []


def test_capturing_without_arming_is_refused() -> None:
    """Arming is the proof of place; a read without it skips that proof entirely."""

    session = _FakeSession(candidates=(_VALID,))
    vault = _RecordingVault()
    with pytest.raises(CaptureRefused):
        asyncio.run(_surface(session, vault).capture_credential(grant="g", kind="api_key"))
    assert vault.writes == []
    assert session.reads == 0


def test_a_page_with_no_secretish_element_is_refused() -> None:
    session = _FakeSession(candidates=(_VALID,), elements=(_Element(index=1, secretish=False),))
    vault = _RecordingVault()
    surface = _surface(session, vault)

    async def _run() -> None:
        assert await surface.arm_credential_surface() is True
        await surface.capture_credential(grant="bsg_" + "a" * 43, kind="api_key")

    with pytest.raises(CaptureRefused):
        asyncio.run(_run())
    assert vault.writes == []
    assert session.reads == 0, "nothing is read off a page with no candidate element"
