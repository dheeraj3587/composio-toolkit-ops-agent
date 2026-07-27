"""Playwright adapter for deterministic post-submit signup classification.

The adapter captures one bounded, value-free DOM observation at a time and
polls for a stable contract-proven result. It deliberately avoids
``networkidle`` and fixed sleeps: modern signup pages may keep long-lived
connections or update in place without navigation.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from ops.automation_contracts import BrowserAutomationContract
from ops.signup_result import (
    SignupResultClassification,
    SignupResultObservation,
    classify_signup_result,
)
from ops.signup_submission_gates import (
    SignupSubmissionGateInspection,
    inspect_signup_submission_gates,
)

_MAX_RESULT_CONTROLS = 160
_DEFAULT_TIMEOUT_SECONDS = 20.0
_DEFAULT_POLL_SECONDS = 0.25
_DEFAULT_STABLE_OBSERVATIONS = 2

_RESULT_OBSERVATION_SCRIPT = r"""
() => {
  const clean = (value, maximum) => {
    if (typeof value !== "string") return "";
    return value.replace(/\s+/g, " ").trim().slice(0, maximum);
  };
  const visible = (el) => {
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const selector = [
    "[role='alert']",
    "[role='status']",
    "[role='dialog']",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "button", "a", "label",
    "input:not([type='hidden'])", "select", "textarea",
  ].join(", ");
  const all = Array.from(document.querySelectorAll(selector));
  if (all.length > 160) {
    return {
      tooLarge: true,
      controlCount: all.length,
      href: location.href,
      title: document.title || "",
    };
  }

  const names = [];
  const status = [];
  let visibleFeedbackPresent = false;
  for (const el of all) {
    if (!visible(el)) continue;
    const role = (el.getAttribute("role") || "").toLowerCase();
    const tag = (el.tagName || "").toLowerCase();
    const labels = Array.from(el.labels || [])
      .map((label) => clean(label.textContent || "", 240))
      .filter(Boolean);
    const name = clean(
      el.getAttribute("aria-label")
        || labels[0]
        || el.getAttribute("placeholder")
        || el.getAttribute("title")
        || el.textContent
        || "",
      240,
    );
    if (name) names.push(name);

    if (
      role === "alert"
      || role === "status"
      || role === "dialog"
      || /^h[1-6]$/.test(tag)
    ) {
      const text = clean(el.textContent || el.getAttribute("aria-label") || "", 500);
      if (text) status.push(text);
    }
    if (role === "alert" || role === "status" || role === "dialog") {
      visibleFeedbackPresent = true;
    }
  }

  const passwordInputs = Array.from(
    document.querySelectorAll("input[type='password']")
  ).filter(visible);
  const nativePasswordInvalid = passwordInputs.some(
    (input) => input.willValidate === true
      && input.validity
      && input.validity.valid === false
  );

  return {
    tooLarge: false,
    controlCount: all.length,
    href: location.href,
    title: clean(document.title || "", 500),
    bodyText: clean(document.body ? document.body.innerText : "", 12000),
    statusText: clean(status.join(" "), 4000),
    accessibleNames: names.slice(0, 160),
    nativePasswordInvalid,
    visibleFeedbackPresent,
  };
}
"""


class SignupResultPage(Protocol):
    async def evaluate(self, expression: str) -> object: ...

    def locator(self, selector: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class SignupResultCapture:
    status: Literal["captured", "retryable", "safe_stop"]
    reason_code: str
    observation: SignupResultObservation | None = None


ObservationReader = Callable[
    [SignupResultPage, BrowserAutomationContract],
    Awaitable[SignupResultCapture],
]
GateReader = Callable[
    [SignupResultPage, BrowserAutomationContract],
    Awaitable[SignupSubmissionGateInspection],
]


async def capture_signup_result_observation(
    page: SignupResultPage,
    contract: BrowserAutomationContract,
) -> SignupResultCapture:
    """Capture one atomic, bounded browser observation without reading values."""

    try:
        contract.assert_usable()
    except Exception:
        return SignupResultCapture(
            status="safe_stop",
            reason_code="signup_result_contract_inactive",
        )
    try:
        raw = await page.evaluate(_RESULT_OBSERVATION_SCRIPT)
    except Exception:
        return SignupResultCapture(
            status="retryable",
            reason_code="signup_result_surface_unavailable",
        )
    if not isinstance(raw, Mapping):
        return SignupResultCapture(
            status="retryable",
            reason_code="signup_result_observation_invalid",
        )
    if bool(raw.get("tooLarge")):
        return SignupResultCapture(
            status="safe_stop",
            reason_code="signup_result_surface_too_large",
        )

    names_raw = raw.get("accessibleNames")
    if not isinstance(names_raw, list) or any(
        not isinstance(item, str) for item in names_raw
    ):
        return SignupResultCapture(
            status="retryable",
            reason_code="signup_result_observation_invalid",
        )
    try:
        count = int(raw.get("controlCount") or 0)
    except (TypeError, ValueError):
        return SignupResultCapture(
            status="retryable",
            reason_code="signup_result_observation_invalid",
        )
    if not 0 <= count <= _MAX_RESULT_CONTROLS:
        return SignupResultCapture(
            status="safe_stop",
            reason_code="signup_result_surface_too_large",
        )

    return SignupResultCapture(
        status="captured",
        reason_code="signup_result_observation_captured",
        observation=SignupResultObservation(
            page_url=str(raw.get("href") or ""),
            title=str(raw.get("title") or ""),
            visible_text=str(raw.get("bodyText") or ""),
            status_text=str(raw.get("statusText") or ""),
            accessible_names=tuple(names_raw),
            native_password_invalid=bool(raw.get("nativePasswordInvalid")),
            # The public field name remains backward compatible; the captured
            # signal covers alert, status, and dialog feedback surfaces.
            visible_alert_present=bool(raw.get("visibleFeedbackPresent")),
            inspected_controls=count,
        ),
    )


async def wait_for_signup_result(
    page: SignupResultPage,
    contract: BrowserAutomationContract,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    poll_seconds: float = _DEFAULT_POLL_SECONDS,
    stable_observations: int = _DEFAULT_STABLE_OBSERVATIONS,
    observation_reader: ObservationReader = capture_signup_result_observation,
    gate_reader: GateReader = inspect_signup_submission_gates,
) -> SignupResultClassification:
    """Wait for one stable, contract-proven post-submit result.

    Two equal positive observations are required by default. This prevents a
    transient loading message or intermediate redirect from becoming durable
    workflow truth. Unproven timeouts remain ``outcome_unknown``.
    """

    if not 0.5 <= timeout_seconds <= 120.0:
        raise ValueError("signup result timeout is outside the supported range")
    if not 0.05 <= poll_seconds <= 2.0:
        raise ValueError("signup result poll interval is outside the supported range")
    if not 1 <= stable_observations <= 4:
        raise ValueError("stable observation count is outside the supported range")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    previous_key: tuple[str, str] | None = None
    stable_count = 0
    last_unknown: SignupResultClassification | None = None
    last_retry_reason = "signup_result_not_yet_proven"

    while loop.time() < deadline:
        capture = await observation_reader(page, contract)
        if capture.status == "safe_stop":
            return _unresolved_result(
                contract,
                status="safe_stop",
                reason_code=capture.reason_code,
            )
        if capture.status == "retryable" or capture.observation is None:
            last_retry_reason = capture.reason_code
            await asyncio.sleep(poll_seconds)
            continue

        gates = await gate_reader(page, contract)
        if gates.status == "safe_stop":
            if gates.reason_code in {
                "signup_gate_surface_unavailable",
                "signup_gate_inspection_failed",
            }:
                last_retry_reason = gates.reason_code
                await asyncio.sleep(poll_seconds)
                continue
            return _unresolved_result(
                contract,
                status="safe_stop",
                reason_code=gates.reason_code,
            )

        classified = classify_signup_result(capture.observation, contract, gates)
        if classified.status == "safe_stop":
            return classified
        if classified.status == "outcome_unknown":
            last_unknown = classified
            previous_key = None
            stable_count = 0
            await asyncio.sleep(poll_seconds)
            continue

        key = (classified.outcome, classified.reason_code)
        if key == previous_key:
            stable_count += 1
        else:
            previous_key = key
            stable_count = 1
        if stable_count >= stable_observations:
            return classified.with_stable_observations(stable_count)
        await asyncio.sleep(poll_seconds)

    if last_unknown is not None and last_unknown.reason_code != "signup_result_not_yet_proven":
        return last_unknown.model_copy(update={"stable_observations": 0})
    return _unresolved_result(
        contract,
        status="outcome_unknown",
        reason_code=(
            "signup_result_unproven_timeout"
            if last_retry_reason == "signup_result_not_yet_proven"
            else "signup_result_observation_timeout"
        ),
    )


def _unresolved_result(
    contract: BrowserAutomationContract,
    *,
    status: Literal["outcome_unknown", "safe_stop"],
    reason_code: str,
) -> SignupResultClassification:
    from ops.signup_state_machine import SignupState

    return SignupResultClassification(
        status=status,
        outcome="outcome_unknown",
        reason_code=reason_code,
        contract_version=contract.contract_version,
        durable_state=SignupState.SIGNUP_SUBMITTED,
        next_phase="reconcile",
        retryable=True,
        stable_observations=0,
    )


__all__ = [
    "SignupResultCapture",
    "SignupResultPage",
    "capture_signup_result_observation",
    "wait_for_signup_result",
]
