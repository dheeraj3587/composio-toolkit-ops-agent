"""LLM-backed outreach composition and reply analysis for the Gmail loop.

Primary backend is OpenRouter (OpenAI-compatible chat completions); Gemini is
the fallback. Callers keep a deterministic template fallback for when every LLM
backend is unavailable. Inputs use only supplied company facts and the already
sanitized (secret-free) reply text; no secret value is ever sent or emitted.
"""

from __future__ import annotations

import importlib
import json
from typing import Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from ops.models import CompanyProfile, OperationalResearch

_TIMEOUT_SECONDS = 45.0
_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

ReplyClass = Literal[
    "no_reply",
    "more_information_required",
    "meeting_requested",
    "approved_setup_required",
    "credentials_received",
    "rejected",
    "automated_response",
    "unclear",
]


class OutreachDraftAI(BaseModel):
    model_config = ConfigDict(extra="ignore")

    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=6_000)


class ReplyAnalysisAI(BaseModel):
    model_config = ConfigDict(extra="ignore")

    classification: ReplyClass
    reply_body: str = Field(default="", max_length=6_000)
    questions: list[str] = Field(default_factory=list, max_length=20)
    setup_urls: list[str] = Field(default_factory=list, max_length=20)
    reason: str | None = Field(default=None, max_length=1_000)
    start_browser_onboarding: bool = False


def _outreach_prompt(app_name: str, company: CompanyProfile, research: OperationalResearch) -> str:
    scopes = ", ".join(scope.name for scope in research.scopes) or "the documented scopes"
    return (
        "You are an integration engineer requesting official API/developer access from a software "
        "vendor. Write a concise, professional outreach email using ONLY the facts below. Do not "
        "invent customers, volumes, partnerships, certifications, or timelines. No secrets. Ask "
        "clearly for: the developer/API access process, required OAuth scopes or permissions, any "
        "approval/review steps, whether a sandbox exists, and the credential issuance process for "
        "production.\n\n"
        f"APP: {app_name}\n"
        f"COMPANY: {company.legal_name} ({company.website})\n"
        f"USE CASE: {company.use_case[:800]}\n"
        f"REQUESTED SCOPES: {scopes}\n\n"
        'Respond with ONLY a JSON object: {"subject": string, "body": string}. The body is '
        "plain text, first person, signed with the company legal name, under ~200 words."
    )


def _analyze_prompt(app_name: str, company: CompanyProfile, reply_text: str) -> str:
    return (
        "You are handling a vendor's reply in an API-access email thread. The text is already "
        "sanitized: any '[REDACTED_SECRET:...]' marker means a secret was removed and stored; "
        "never ask to reconstruct it. Classify the reply and, if it asks for information or a "
        "meeting, draft a concise professional reply using ONLY the company facts below (never "
        "invent facts).\n\n"
        f"APP: {app_name}\n"
        f"COMPANY: {company.legal_name} ({company.website})\n"
        f"USE CASE: {company.use_case[:800]}\n\n"
        f"PROVIDER REPLY:\n{reply_text[:6000]}\n\n"
        "Respond with ONLY a JSON object with keys: classification (one of no_reply, "
        "more_information_required, meeting_requested, approved_setup_required, "
        "credentials_received, rejected, automated_response, unclear); reply_body (a professional "
        "answer ONLY when classification is more_information_required or meeting_requested, else "
        '""); questions (array of strings); setup_urls (array of official URLs the provider '
        "shared); reason (short string or null); start_browser_onboarding (boolean, true only when "
        "approved with a setup URL)."
    )


class _Backend(Protocol):
    def generate_json(self, prompt: str) -> dict[str, object]: ...


class OpenRouterBackend:
    """OpenAI-compatible chat-completions backend (OpenRouter)."""

    def __init__(self, api_key: SecretStr, *, model: str) -> None:
        self._api_key = api_key
        self._model = model

    def generate_json(self, prompt: str) -> dict[str, object]:
        headers = {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Content-Type": "application/json",
            "X-Title": "Composio Toolkit Ops Agent",
        }
        payload = {
            "model": self._model,
            "messages": [
                {
                    "role": "system",
                    "content": "You output only a single valid JSON object, no prose or markdown.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "response_format": {"type": "json_object"},
        }
        with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
            response = client.post(_OPENROUTER_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
        content = data["choices"][0]["message"]["content"]
        return _loads_json_object(content)


class GeminiBackend:
    """Gemini structured-output backend (google.genai)."""

    def __init__(self, api_key: SecretStr, *, models: tuple[str, ...]) -> None:
        self._api_key = api_key
        self._models = tuple(dict.fromkeys(name for name in models if name))

    def generate_json(self, prompt: str) -> dict[str, object]:
        genai = importlib.import_module("google.genai")
        types = importlib.import_module("google.genai.types")
        client = genai.Client(api_key=self._api_key.get_secret_value())
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.3,
            http_options=types.HttpOptions(timeout=int(_TIMEOUT_SECONDS * 1000)),
        )
        last_error: Exception | None = None
        for model in self._models:
            try:
                response = client.models.generate_content(
                    model=model, contents=prompt, config=config
                )
            except Exception as exc:
                last_error = exc
                continue
            text = getattr(response, "text", None)
            if isinstance(text, str) and text:
                return _loads_json_object(text)
            last_error = RuntimeError("Gemini returned no content")
        raise RuntimeError("all Gemini models failed") from last_error


class EmailAssistant:
    """Try each configured backend in order (OpenRouter first, Gemini fallback)."""

    def __init__(self, backends: tuple[_Backend, ...]) -> None:
        if not backends:
            raise ValueError("at least one LLM backend is required")
        self._backends = backends

    def _generate(self, prompt: str, schema: type[BaseModel]) -> BaseModel:
        last_error: Exception | None = None
        for backend in self._backends:
            try:
                payload = backend.generate_json(prompt)
                return schema.model_validate(payload)
            except Exception as exc:
                last_error = exc
                continue
        raise RuntimeError("all email LLM backends failed") from last_error

    def compose_outreach(
        self, *, app_name: str, company: CompanyProfile, research: OperationalResearch
    ) -> OutreachDraftAI:
        result = self._generate(_outreach_prompt(app_name, company, research), OutreachDraftAI)
        assert isinstance(result, OutreachDraftAI)
        return result

    def analyze_reply(
        self, *, app_name: str, company: CompanyProfile, reply_text: str
    ) -> ReplyAnalysisAI:
        result = self._generate(_analyze_prompt(app_name, company, reply_text), ReplyAnalysisAI)
        assert isinstance(result, ReplyAnalysisAI)
        return result


def _loads_json_object(text: str) -> dict[str, object]:
    """Parse a JSON object, tolerating code fences or surrounding prose."""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:]
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(stripped[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("LLM response was not a JSON object")
    return parsed


def build_email_assistant(settings: object) -> EmailAssistant | None:
    """Build the assistant with OpenRouter primary and Gemini fallback."""

    backends: list[_Backend] = []
    openrouter_key = getattr(settings, "openrouter_api_key", None)
    if isinstance(openrouter_key, SecretStr):
        model = (
            getattr(settings, "openrouter_model", "") or "nvidia/nemotron-3-ultra-550b-a55b:free"
        )
        backends.append(OpenRouterBackend(openrouter_key, model=model))
    gemini_key = getattr(settings, "google_genai_api_key", None)
    if isinstance(gemini_key, SecretStr):
        models = tuple(getattr(settings, "gemini_model_chain", ()) or ())
        if models:
            backends.append(GeminiBackend(gemini_key, models=models))
    if not backends:
        return None
    return EmailAssistant(tuple(backends))


__all__ = [
    "EmailAssistant",
    "GeminiBackend",
    "OpenRouterBackend",
    "OutreachDraftAI",
    "ReplyAnalysisAI",
    "ReplyClass",
    "build_email_assistant",
]
