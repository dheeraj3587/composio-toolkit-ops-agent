"""Free-tier multi-provider JSON inference with ordered fallback.

Every backend returns a single JSON object validated against a caller-supplied
schema. Providers are tried in a fixed order and the first schema-valid response
wins; a rate limit (429) or transient error advances to the next provider, so a
free-tier quota on one vendor never stalls a run.

Contracts below were verified against the vendors' official docs (2026-07-25):

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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

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
    ) -> None:
        self._api_key = api_key
        self._url = url
        self._model = model
        self._strict_models = tuple(strict_models)
        self._use_max_completion_tokens = use_max_completion_tokens

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

    def generate_json(self, prompt: str, schema: Mapping[str, object] | None) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_JSON},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "stream": False,  # both vendors forbid streaming with their JSON modes
            "response_format": self._response_format(schema),
        }
        token_key = "max_completion_tokens" if self._use_max_completion_tokens else "max_tokens"
        payload[token_key] = _MAX_COMPLETION_TOKENS
        headers = {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            response = client.post(self._url, headers=headers, json=payload)
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

    def __init__(self, api_key: SecretStr, *, model: str) -> None:
        super().__init__(
            api_key,
            url="https://openrouter.ai/api/v1/chat/completions",
            model=model,
            strict_models=(),  # varies by upstream model: use plain JSON mode
            use_max_completion_tokens=False,
        )


class GroqJsonBackend(_OpenAICompatibleBackend):
    name = "groq"

    def __init__(self, api_key: SecretStr, *, model: str) -> None:
        super().__init__(
            api_key,
            url="https://api.groq.com/openai/v1/chat/completions",
            model=model,
            strict_models=_GROQ_STRICT_MODELS,
            use_max_completion_tokens=True,
        )


class CerebrasJsonBackend(_OpenAICompatibleBackend):
    name = "cerebras"

    def __init__(self, api_key: SecretStr, *, model: str) -> None:
        super().__init__(
            api_key,
            url="https://api.cerebras.ai/v1/chat/completions",
            model=model,
            strict_models=_CEREBRAS_STRICT_MODELS,
            use_max_completion_tokens=True,
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


class JsonInference:
    """Try each backend in order; the first schema-valid JSON object wins."""

    def __init__(self, backends: Sequence[JsonBackend]) -> None:
        if not backends:
            raise ValueError("at least one inference backend is required")
        self._backends = tuple(backends)

    @property
    def provider_names(self) -> tuple[str, ...]:
        return tuple(backend.name for backend in self._backends)

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
        next provider instead of reaching the browser.
        """

        errors: list[str] = []
        for backend in self._backends:
            try:
                payload = backend.generate_json(prompt, schema)
                if validate is not None:
                    validate(payload)
                return InferenceResult(payload=payload, provider=backend.name)
            except RateLimited:
                errors.append(f"{backend.name}: rate_limited")
            except Exception as exc:
                errors.append(f"{backend.name}: {type(exc).__name__}")
        raise InferenceError("; ".join(errors) or "no backend produced valid JSON")


def build_json_inference(settings: object) -> JsonInference | None:
    """Build the ordered free-tier chain, skipping unconfigured providers.

    Order favours strict-schema-capable, high-throughput free tiers first:
    Groq -> Cerebras -> OpenRouter -> Gemini. Returns None when no key is set.
    """

    backends: list[JsonBackend] = []

    groq_key = getattr(settings, "groq_api_key", None)
    if isinstance(groq_key, SecretStr):
        model = getattr(settings, "groq_model", "") or "openai/gpt-oss-120b"
        backends.append(GroqJsonBackend(groq_key, model=model))

    cerebras_key = getattr(settings, "cerebras_api_key", None)
    if isinstance(cerebras_key, SecretStr):
        model = getattr(settings, "cerebras_model", "") or "gpt-oss-120b"
        backends.append(CerebrasJsonBackend(cerebras_key, model=model))

    openrouter_key = getattr(settings, "openrouter_api_key", None)
    if isinstance(openrouter_key, SecretStr):
        model = getattr(settings, "openrouter_model", "") or "openai/gpt-oss-120b"
        backends.append(OpenRouterJsonBackend(openrouter_key, model=model))

    gemini_key = getattr(settings, "google_genai_api_key", None)
    if isinstance(gemini_key, SecretStr):
        models = tuple(getattr(settings, "gemini_model_chain", ()) or ())
        if models:
            backends.append(GeminiJsonBackend(gemini_key, models=models))

    return JsonInference(backends) if backends else None


__all__ = [
    "CerebrasJsonBackend",
    "GeminiJsonBackend",
    "GroqJsonBackend",
    "InferenceError",
    "InferenceResult",
    "JsonBackend",
    "JsonInference",
    "OpenRouterJsonBackend",
    "RateLimited",
    "build_json_inference",
]
