"""Free-tier multi-provider JSON inference with ordered fallback.

Every backend returns a single JSON object validated against a caller-supplied
schema. Providers are tried in a fixed order and the first schema-valid response
wins; a rate limit (429) or transient error advances to the next provider, so a
free-tier quota on one vendor never stalls a run.

Contracts below were verified against the vendors' official docs (2026-07-25,
Inception added 2026-07-31):

* Inception Mercury — ``https://api.inceptionlabs.ai/v1/chat/completions``,
  OpenAI-shaped, model ``mercury-2``, strict ``json_schema`` documented, and
  ``max_tokens`` rather than ``max_completion_tokens``. A ``reasoning_effort``
  dial trades deliberation for latency ("instant"/"low" are the fast settings).
* OpenRouter — ``https://openrouter.ai/api/v1/chat/completions``, OpenAI-shaped,
  ``response_format={"type":"json_object"}``.
* Groq — ``https://api.groq.com/openai/v1/chat/completions``. Strict
  ``json_schema`` (with ``strict: true``) is supported ONLY on the ``gpt-oss``
  models, which Groq names with an ``openai/`` prefix; other models fall back to
  ``json_object``. ``max_tokens`` is deprecated in favour of
  ``max_completion_tokens``; ``logprobs``/``logit_bias``/``n>1`` are rejected.
* Cerebras — ``https://api.cerebras.ai/v1/chat/completions``. Strict
  ``json_schema`` supported; model ids carry NO ``openai/`` prefix. Only
  ``max_completion_tokens`` exists. Strict schemas must set
  ``additionalProperties: false`` on every object and cannot use ``pattern``,
  ``format``, ``minItems``/``maxItems``, or recursion.
* Gemini — ``google.genai`` structured output (``response_mime_type`` JSON).

Both Groq and Cerebras forbid streaming alongside their JSON modes, so all calls
here are non-streaming. No prompt sent from this module may contain a secret: the
browser decider passes only sanitized, non-secret page structure.
"""

from __future__ import annotations

import importlib
import json
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast, get_args

import httpx
from pydantic import SecretStr

_TIMEOUT_SECONDS = 45.0
_MAX_COMPLETION_TOKENS = 1_024
_SYSTEM_JSON = (
    "You output only a single valid JSON object matching the requested schema. "
    "No prose, no markdown, no code fences."
)

# Models that support strict constrained decoding (documented per vendor).
_GROQ_STRICT_MODELS = ("openai/gpt-oss-120b", "openai/gpt-oss-20b")
_CEREBRAS_STRICT_MODELS = ("gpt-oss-120b", "gemma-4-31b")


class InferenceError(RuntimeError):
    """Raised when every configured backend failed to return valid JSON."""


class RateLimited(RuntimeError):
    """A provider reported HTTP 429; the caller should advance to the next one."""


@dataclass(frozen=True, slots=True)
class InferenceResult:
    """A validated JSON payload plus which backend produced it."""

    payload: dict[str, object]
    provider: str


class JsonBackend(Protocol):
    name: str

    def generate_json(
        self, prompt: str, schema: Mapping[str, object] | None
    ) -> dict[str, object]: ...


def _loads_json_object(text: str) -> dict[str, object]:
    """Parse a JSON object, tolerating code fences or surrounding prose."""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped[:4].casefold() == "json":
            stripped = stripped[4:]
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(stripped[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("model response was not a JSON object")
    return parsed


class _OpenAICompatibleBackend:
    """Shared implementation for the OpenAI-shaped chat-completions vendors."""

    name = "openai_compatible"

    def __init__(
        self,
        api_key: SecretStr,
        *,
        url: str,
        model: str,
        strict_models: Sequence[str] = (),
        use_max_completion_tokens: bool = True,
        max_completion_tokens: int = _MAX_COMPLETION_TOKENS,
        extra_payload: Mapping[str, object] | None = None,
    ) -> None:
        self._api_key = api_key
        self._url = url
        self._model = model
        self._strict_models = tuple(strict_models)
        self._use_max_completion_tokens = use_max_completion_tokens
        self._max_completion_tokens = max_completion_tokens
        # Vendor-specific, non-secret request fields (for example Inception's
        # reasoning dial). Kept separate so the shared request shape stays honest.
        self._extra_payload = dict(extra_payload or {})

    def _response_format(self, schema: Mapping[str, object] | None) -> dict[str, object]:
        # Strict constrained decoding when the vendor documents it for this model;
        # otherwise plain JSON mode (the prompt always names JSON explicitly, which
        # Groq and Cerebras both require for json_object).
        if schema is not None and self._model in self._strict_models:
            return {
                "type": "json_schema",
                "json_schema": {"name": "decision", "strict": True, "schema": dict(schema)},
            }
        return {"type": "json_object"}

    def _payload(self, prompt: str, response_format: Mapping[str, object]) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_JSON},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "stream": False,  # every vendor here forbids streaming with JSON modes
            "response_format": dict(response_format),
            **self._extra_payload,
        }
        token_key = "max_completion_tokens" if self._use_max_completion_tokens else "max_tokens"
        payload[token_key] = self._max_completion_tokens
        return payload

    def generate_json(self, prompt: str, schema: Mapping[str, object] | None) -> dict[str, object]:
        headers = {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        strict = self._response_format(schema)
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            response = client.post(self._url, headers=headers, json=self._payload(prompt, strict))
            # A vendor that documents strict schemas can still reject a specific
            # one (unsupported keyword, nesting depth, or a model that quietly
            # lost the capability). That is a 400, not a provider outage, so retry
            # once in plain JSON mode rather than dropping to the next provider:
            # the prompt already names the schema, and the caller validates.
            if response.status_code == 400 and strict.get("type") == "json_schema":
                response = client.post(
                    self._url,
                    headers=headers,
                    json=self._payload(prompt, {"type": "json_object"}),
                )
            if response.status_code == 429:
                raise RateLimited(f"{self.name} rate limited")
            response.raise_for_status()
            data = response.json()
        content = data["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise ValueError("model response content was not text")
        return _loads_json_object(content)


class OpenRouterJsonBackend(_OpenAICompatibleBackend):
    name = "openrouter"

    def __init__(
        self,
        api_key: SecretStr,
        *,
        model: str,
        max_completion_tokens: int = _MAX_COMPLETION_TOKENS,
    ) -> None:
        super().__init__(
            api_key,
            url="https://openrouter.ai/api/v1/chat/completions",
            model=model,
            strict_models=(),  # varies by upstream model: use plain JSON mode
            use_max_completion_tokens=False,
            max_completion_tokens=max_completion_tokens,
        )


class MercuryJsonBackend(_OpenAICompatibleBackend):
    """Inception Mercury (diffusion LLM), OpenAI-shaped and strict-schema capable.

    Verified against Inception's documentation (2026-07-31):
    ``https://api.inceptionlabs.ai/v1/chat/completions``, bearer key, model
    ``mercury-2``, and ``response_format={"type":"json_schema","json_schema":
    {"name":..., "strict":true, "schema":...}}``. Inception documents
    ``max_tokens`` rather than ``max_completion_tokens``, and exposes
    ``reasoning_effort`` where "low"/"instant" are the low-latency settings.
    """

    name = "mercury"

    def __init__(
        self,
        api_key: SecretStr,
        *,
        model: str,
        reasoning_effort: str = "low",
        max_completion_tokens: int = _MAX_COMPLETION_TOKENS,
    ) -> None:
        super().__init__(
            api_key,
            url="https://api.inceptionlabs.ai/v1/chat/completions",
            model=model,
            # Strict schemas are documented for the chat models, and the shared
            # 400 fallback covers a schema this account or model will not take.
            strict_models=(model,),
            use_max_completion_tokens=False,
            max_completion_tokens=max_completion_tokens,
            extra_payload={"reasoning_effort": reasoning_effort},
        )


class GroqJsonBackend(_OpenAICompatibleBackend):
    name = "groq"

    def __init__(
        self,
        api_key: SecretStr,
        *,
        model: str,
        max_completion_tokens: int = _MAX_COMPLETION_TOKENS,
    ) -> None:
        super().__init__(
            api_key,
            url="https://api.groq.com/openai/v1/chat/completions",
            model=model,
            strict_models=_GROQ_STRICT_MODELS,
            use_max_completion_tokens=True,
            max_completion_tokens=max_completion_tokens,
        )


class CerebrasJsonBackend(_OpenAICompatibleBackend):
    name = "cerebras"

    def __init__(
        self,
        api_key: SecretStr,
        *,
        model: str,
        max_completion_tokens: int = _MAX_COMPLETION_TOKENS,
    ) -> None:
        super().__init__(
            api_key,
            url="https://api.cerebras.ai/v1/chat/completions",
            model=model,
            strict_models=_CEREBRAS_STRICT_MODELS,
            use_max_completion_tokens=True,
            max_completion_tokens=max_completion_tokens,
        )


class GeminiJsonBackend:
    """Gemini structured-output backend via ``google.genai``."""

    name = "gemini"

    def __init__(self, api_key: SecretStr, *, models: Sequence[str]) -> None:
        self._api_key = api_key
        self._models = tuple(dict.fromkeys(name for name in models if name))

    def generate_json(self, prompt: str, schema: Mapping[str, object] | None) -> dict[str, object]:
        del schema  # the prompt carries the shape; response_mime_type enforces JSON
        genai = importlib.import_module("google.genai")
        types = importlib.import_module("google.genai.types")
        client = genai.Client(api_key=self._api_key.get_secret_value())
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,
            http_options=types.HttpOptions(timeout=int(_TIMEOUT_SECONDS * 1000)),
        )
        last: Exception | None = None
        for model in self._models:
            try:
                response = client.models.generate_content(
                    model=model, contents=prompt, config=config
                )
            except Exception as exc:
                last = exc
                continue
            text = getattr(response, "text", None)
            if isinstance(text, str) and text:
                return _loads_json_object(text)
            last = RuntimeError("Gemini returned no content")
        raise RuntimeError("all Gemini models failed") from last


@dataclass(frozen=True, slots=True)
class DecisionBudget:
    """Hard bounds so one decision can never consume the browser-loop budget.

    ``total_seconds`` caps the WHOLE decision across providers;
    ``provider_seconds`` caps each individual attempt; ``max_providers`` caps how
    many providers are tried at all.
    """

    total_seconds: float = 15.0
    provider_seconds: float = 6.0
    max_providers: int = 3


# Typed, sanitized decision reason codes (never provider payload text).
DecisionReasonCode = Literal[
    "rate_limited",
    "authentication_failed",
    "provider_timeout",
    "invalid_json",
    "schema_invalid",
    "all_providers_failed",
]

# How one attempt ended: usable, or the typed reason it was not. Spelled out
# rather than unpacked from ``DecisionReasonCode`` because a type checker cannot
# read a computed Literal; the assert below is what keeps the two in step.
DecisionOutcome = Literal[
    "usable",
    "rate_limited",
    "authentication_failed",
    "provider_timeout",
    "invalid_json",
    "schema_invalid",
    "all_providers_failed",
]
assert get_args(DecisionOutcome) == ("usable", *get_args(DecisionReasonCode)), (
    "a decision outcome is 'usable' or one of the decision reason codes"
)


class DecisionAttemptSink(Protocol):
    """Where one inference attempt is recorded (reliability R4.3).

    Declared beside the producer so ``ops/core/`` never imports the onboarding
    telemetry that implements it. Provider name, outcome and latency only: no
    prompt, no payload, no answer.
    """

    def record_attempt(self, *, provider: str, outcome: DecisionOutcome, latency_ms: int) -> None:
        """Record one attempt of the chain."""
        ...


# Programming errors must propagate out of the decision path, never be recorded
# as a provider failure.
_PROGRAMMING_ERRORS: tuple[type[Exception], ...] = (
    TypeError,
    AttributeError,
    NameError,
    ImportError,
    ModuleNotFoundError,
    AssertionError,
)


class DecisionFailed(RuntimeError):
    """A bounded decision failure carrying only a typed reason code."""

    def __init__(self, reason_code: DecisionReasonCode) -> None:
        self.reason_code: DecisionReasonCode = reason_code
        super().__init__(f"decision failed: {reason_code}")


def _classify_backend_error(exc: Exception) -> DecisionReasonCode:
    """Map a provider exception to a sanitized reason code (status/type only)."""

    if isinstance(exc, RateLimited):
        return "rate_limited"
    if isinstance(exc, TimeoutError | httpx.TimeoutException):
        return "provider_timeout"
    status = getattr(exc, "status_code", None)
    if status in (401, 403):
        return "authentication_failed"
    if isinstance(exc, json.JSONDecodeError):
        return "invalid_json"
    if isinstance(exc, ValueError):
        # pydantic ValidationError and our validate() callables raise ValueError.
        return "schema_invalid"
    return "all_providers_failed"


@dataclass(slots=True)
class _Breaker:
    """A minimal per-provider circuit breaker (opens after repeated failures)."""

    failures: int = 0
    open_until: float = 0.0

    def is_open(self, now: float) -> bool:
        return now < self.open_until

    def record_failure(self, now: float, *, threshold: int = 2, cooldown: float = 60.0) -> None:
        self.failures += 1
        if self.failures >= threshold:
            self.open_until = now + cooldown
            self.failures = 0

    def record_success(self) -> None:
        self.failures = 0
        self.open_until = 0.0


def _call_with_timeout(
    func: Any, prompt: str, schema: Mapping[str, object] | None, *, timeout: float
) -> dict[str, object]:
    """Run a blocking backend call with a hard wall-clock timeout.

    The backend is blocking HTTP, so it runs on a worker thread and the caller
    stops waiting at ``timeout``; a late reply is abandoned, so a slow provider
    can never overrun the decision (or the browser) budget.
    """

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="inference")
    future = executor.submit(func, prompt, schema)
    try:
        return cast("dict[str, object]", future.result(timeout=timeout))
    except FuturesTimeout:
        future.cancel()
        raise TimeoutError("provider exceeded its per-attempt budget") from None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


class JsonInference:
    """Try each backend in order under a bounded decision budget.

    The first schema-valid JSON object wins. A provider that times out, is rate
    limited, or repeatedly fails is skipped (circuit breaker) so the browser loop
    keeps its own deadline. Programming errors propagate.
    """

    def __init__(
        self,
        backends: Sequence[JsonBackend],
        *,
        budget: DecisionBudget | None = None,
        attempts: DecisionAttemptSink | None = None,
    ) -> None:
        if not backends:
            raise ValueError("at least one inference backend is required")
        self._backends = tuple(backends)
        self._budget = budget or DecisionBudget()
        self._attempts = attempts
        self._breakers: dict[str, _Breaker] = {}
        # Sanitized record of the last decision's failures, for reporting.
        self.last_reason_codes: tuple[DecisionReasonCode, ...] = ()

    @property
    def provider_names(self) -> tuple[str, ...]:
        return tuple(backend.name for backend in self._backends)

    def with_attempts(self, attempts: DecisionAttemptSink) -> JsonInference:
        """This chain, recording each attempt into ``attempts``.

        The breakers are shared rather than copied: a provider this deployment has
        already found to be failing must stay skipped for every run.
        """

        view = JsonInference(self._backends, budget=self._budget, attempts=attempts)
        view._breakers = self._breakers
        return view

    @property
    def budget(self) -> DecisionBudget:
        return self._budget

    def generate(
        self,
        prompt: str,
        *,
        schema: Mapping[str, object] | None = None,
        validate: Any | None = None,
    ) -> InferenceResult:
        """Return the first backend response that parses (and validates) cleanly.

        ``validate`` may be a callable raising on an unacceptable payload (e.g. a
        pydantic ``model_validate``), so a malformed decision falls through to the
        next provider instead of reaching the browser. Raises
        :class:`DecisionFailed` with a typed reason code when the budget is spent.
        """

        deadline = time.monotonic() + self._budget.total_seconds
        reasons: list[DecisionReasonCode] = []
        attempted = 0

        for backend in self._backends:
            if attempted >= self._budget.max_providers:
                break
            now = time.monotonic()
            if now >= deadline:
                reasons.append("provider_timeout")
                break
            breaker = self._breakers.setdefault(backend.name, _Breaker())
            if breaker.is_open(now):
                continue  # skip a provider that recently failed repeatedly
            # Each attempt is bounded by BOTH the per-provider cap and whatever
            # remains of the total budget.
            per_attempt = min(self._budget.provider_seconds, deadline - now)
            if per_attempt <= 0:
                reasons.append("provider_timeout")
                break
            attempted += 1
            started = time.monotonic()
            try:
                payload = _call_with_timeout(
                    backend.generate_json, prompt, schema, timeout=per_attempt
                )
                if validate is not None:
                    validate(payload)
                breaker.record_success()
                self._record(backend.name, "usable", started)
                self.last_reason_codes = tuple(reasons)
                return InferenceResult(payload=payload, provider=backend.name)
            except _PROGRAMMING_ERRORS:
                raise  # a broken integration must surface
            except Exception as exc:
                reason = _classify_backend_error(exc)
                reasons.append(reason)
                self._record(backend.name, reason, started)
                breaker.record_failure(time.monotonic())

        self.last_reason_codes = tuple(reasons)
        raise DecisionFailed(reasons[-1] if reasons else "all_providers_failed")

    def _record(self, provider: str, outcome: DecisionOutcome, started: float) -> None:
        """One row per attempt, so a provider skipped by its breaker is visible."""

        if self._attempts is not None:
            latency_ms = max(int((time.monotonic() - started) * 1000), 0)
            self._attempts.record_attempt(provider=provider, outcome=outcome, latency_ms=latency_ms)


def build_json_inference(
    settings: object,
    *,
    budget: DecisionBudget | None = None,
    max_completion_tokens: int = _MAX_COMPLETION_TOKENS,
    attempts: DecisionAttemptSink | None = None,
) -> JsonInference | None:
    """Build the ordered chain, skipping unconfigured providers.

    Order favours latency first, then strict-schema-capable high-throughput free
    tiers: Mercury -> Groq -> Cerebras -> OpenRouter -> Gemini. Mercury leads
    because the autonomous action loop pays one decision per page state, so token
    latency, not raw capability, is what bounds a run. Returns None when no key is
    set, and every later provider still runs unchanged when Mercury is absent,
    rate limited, or fails its schema.
    """

    backends: list[JsonBackend] = []

    mercury_key = getattr(settings, "mercury_api_key", None)
    if isinstance(mercury_key, SecretStr):
        model = getattr(settings, "mercury_model", "") or "mercury-2"
        backends.append(
            MercuryJsonBackend(
                mercury_key,
                model=model,
                reasoning_effort=getattr(settings, "mercury_reasoning_effort", "") or "low",
                max_completion_tokens=max_completion_tokens,
            )
        )

    groq_key = getattr(settings, "groq_api_key", None)
    if isinstance(groq_key, SecretStr):
        model = getattr(settings, "groq_model", "") or "openai/gpt-oss-120b"
        backends.append(
            GroqJsonBackend(
                groq_key,
                model=model,
                max_completion_tokens=max_completion_tokens,
            )
        )

    cerebras_key = getattr(settings, "cerebras_api_key", None)
    if isinstance(cerebras_key, SecretStr):
        model = getattr(settings, "cerebras_model", "") or "gpt-oss-120b"
        backends.append(
            CerebrasJsonBackend(
                cerebras_key,
                model=model,
                max_completion_tokens=max_completion_tokens,
            )
        )

    openrouter_key = getattr(settings, "openrouter_api_key", None)
    if isinstance(openrouter_key, SecretStr):
        model = getattr(settings, "openrouter_model", "") or "openai/gpt-oss-120b"
        backends.append(
            OpenRouterJsonBackend(
                openrouter_key,
                model=model,
                max_completion_tokens=max_completion_tokens,
            )
        )

    gemini_key = getattr(settings, "google_genai_api_key", None)
    if isinstance(gemini_key, SecretStr):
        models = tuple(getattr(settings, "gemini_model_chain", ()) or ())
        if models:
            backends.append(GeminiJsonBackend(gemini_key, models=models))

    return JsonInference(backends, budget=budget, attempts=attempts) if backends else None


__all__ = [
    "CerebrasJsonBackend",
    "DecisionAttemptSink",
    "DecisionBudget",
    "DecisionFailed",
    "DecisionOutcome",
    "DecisionReasonCode",
    "GeminiJsonBackend",
    "GroqJsonBackend",
    "InferenceError",
    "InferenceResult",
    "JsonBackend",
    "JsonInference",
    "MercuryJsonBackend",
    "OpenRouterJsonBackend",
    "RateLimited",
    "build_json_inference",
]
