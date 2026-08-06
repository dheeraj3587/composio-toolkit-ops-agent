"""Which decision models this deployment can actually offer, and on what terms.

Until now the model behind the action loop was a deployment fact: whichever
provider keys happened to be set decided the chain, and
``ops.core.config.Settings`` pinned the model id. An operator watching a run had
no way to see which model was choosing, let alone to choose it themselves.

This module is the single answer to "what may a run ask for?", and it is built to
make one class of lie impossible: **a model can never be offered that the chain
would not build.** :func:`available_models` tests exactly the ``Settings``
attributes :func:`ops.core.inference.build_json_inference` reads — the same
attribute, the same ``SecretStr`` check — so an option in the picker and a backend
in the chain succeed and fail together. There is no second list to keep in sync.

Two further decisions are worth stating.

**Effort is reported honestly, per provider.**
    ``reasoning_effort`` is a real request field on Inception's Mercury and on the
    gpt-oss models Groq and Cerebras serve, and the backends pass it through.
    Gemini has no such field — it budgets thinking tokens instead — and OpenRouter
    forwards to whatever upstream model the id names, which may or may not have a
    dial. Those two report :attr:`ModelOption.supports_effort` as ``False`` and the
    UI disables the control rather than showing a dial that does nothing.

**A selection pins the front of the chain; it does not become the chain.**
    :func:`ops.core.inference.build_json_inference` moves the selected provider to
    the front and overrides its model and effort, leaving every other configured
    provider behind it. An operator who picks a model that starts refusing schemas
    mid-run still gets a run — the fallback that protects an unattended overnight
    onboarding is not something a dropdown should be able to switch off.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from pydantic import SecretStr

# The dial's values, in increasing order of deliberation. These are the values
# Inception documents and the ones the gpt-oss models take; ``instant`` is
# Mercury-only, so it is not offered to the providers that would reject it.
EFFORT_VALUES: Final[tuple[str, ...]] = ("instant", "low", "medium", "high")
_GPT_OSS_EFFORTS: Final[tuple[str, ...]] = ("low", "medium", "high")

# What a provider with a dial runs at when the operator expresses no preference.
#
# ``high`` is the top of ``EFFORT_VALUES`` and of ``_GPT_OSS_EFFORTS`` alike, so
# this is the maximum every dialled provider here accepts — there is no level
# above it to ask for. It used to be ``low``, on the argument that the loop is
# choosing between a handful of candidates on a page it can already see. The
# pages that actually end runs are the ambiguous ones, where a misread costs the
# whole run and deliberation costs seconds, so the default now favours the
# reading over the latency. ``ops.core.config.Settings.mercury_reasoning_effort``
# is set to match, and MERCURY_REASONING_EFFORT still overrides it per deployment.
DEFAULT_EFFORT: Final = "high"


@dataclass(frozen=True, slots=True)
class ModelOption:
    """One model a run may be pinned to.

    ``id`` is ``"<provider>:<model>"`` — provider-qualified because the same model
    id is served by more than one vendor (``openai/gpt-oss-120b`` on Groq is
    ``gpt-oss-120b`` on Cerebras) and a bare model id could not say which chain
    position to move.
    """

    id: str
    provider: str
    model: str
    label: str
    description: str
    supports_effort: bool
    effort_values: tuple[str, ...]
    # True for the model the deployment's chain would reach first with no
    # selection. The UI marks it so "leave it alone" is a visible choice.
    is_default: bool = False


@dataclass(frozen=True, slots=True)
class ModelSelection:
    """One run's pinned decision model, resolved against the catalog.

    Only ever constructed by :func:`resolve_selection`, so a selection in hand is
    already known to name a configured provider. ``effort`` is ``""`` when the
    provider has no dial or the operator expressed no preference.
    """

    provider: str
    model: str
    effort: str = ""


# What each provider is called in the picker, and how its effort dial behaves.
# The ``settings`` attribute names are the ones ``build_json_inference`` reads;
# they are named here rather than re-derived so the two lists cannot drift.
@dataclass(frozen=True, slots=True)
class _Provider:
    name: str
    label: str
    key_attribute: str
    model_attribute: str
    fallback_model: str
    supports_effort: bool
    effort_values: tuple[str, ...]
    description: str
    # Extra model ids this vendor serves that an operator may reasonably want.
    # The deployment's own configured model is always offered on top of these.
    alternates: tuple[str, ...] = ()


_PROVIDERS: Final[tuple[_Provider, ...]] = (
    _Provider(
        name="mercury",
        label="Mercury",
        key_attribute="mercury_api_key",
        model_attribute="mercury_model",
        fallback_model="mercury-2",
        supports_effort=True,
        effort_values=EFFORT_VALUES,
        description="Inception's diffusion model. Lowest latency per page decision.",
    ),
    _Provider(
        name="groq",
        label="Groq",
        key_attribute="groq_api_key",
        model_attribute="groq_model",
        fallback_model="openai/gpt-oss-120b",
        supports_effort=True,
        effort_values=_GPT_OSS_EFFORTS,
        description="gpt-oss on Groq. Strict JSON schemas, high throughput.",
        alternates=("openai/gpt-oss-20b",),
    ),
    _Provider(
        name="cerebras",
        label="Cerebras",
        key_attribute="cerebras_api_key",
        model_attribute="cerebras_model",
        fallback_model="gpt-oss-120b",
        supports_effort=True,
        effort_values=_GPT_OSS_EFFORTS,
        description="gpt-oss on Cerebras. Strict JSON schemas, fastest tokens.",
        alternates=("gpt-oss-20b",),
    ),
    _Provider(
        name="openrouter",
        label="OpenRouter",
        key_attribute="openrouter_api_key",
        model_attribute="openrouter_model",
        fallback_model="openai/gpt-oss-120b",
        # OpenRouter forwards to whichever upstream model the id names, and only
        # some of those have a dial. Claiming one here would be a dial that
        # silently does nothing for most ids.
        supports_effort=False,
        effort_values=(),
        description="Routes to a chosen upstream model. Plain JSON mode.",
    ),
    _Provider(
        name="gemini",
        label="Gemini",
        key_attribute="google_genai_api_key",
        model_attribute="gemini_model",
        fallback_model="gemini-3.6-flash",
        # Gemini budgets thinking tokens rather than taking an effort level.
        supports_effort=False,
        effort_values=(),
        description="Google's structured-output model. No reasoning-effort dial.",
    ),
)

_PROVIDERS_BY_NAME: Final[dict[str, _Provider]] = {
    provider.name: provider for provider in _PROVIDERS
}


def _configured(settings: object, provider: _Provider) -> bool:
    """Whether the chain would build this provider's backend.

    The same test ``build_json_inference`` makes, deliberately: a ``SecretStr`` on
    the same attribute. Anything else — an empty string, a plain ``str`` left by a
    partial config, ``None`` — is not configured, on both sides.
    """

    return isinstance(getattr(settings, provider.key_attribute, None), SecretStr)


def _models_for(settings: object, provider: _Provider) -> tuple[str, ...]:
    """This provider's offerable model ids, the deployment's own one first."""

    configured = getattr(settings, provider.model_attribute, "") or provider.fallback_model
    ordered = [str(configured), *provider.alternates]
    return tuple(dict.fromkeys(model for model in ordered if model))


def available_models(settings: object) -> tuple[ModelOption, ...]:
    """Every model this deployment can actually run a decision on.

    Ordered by the chain's own preference — Mercury, Groq, Cerebras, OpenRouter,
    Gemini — so the first entry is the model a run with no selection would reach
    first, and it is the one flagged :attr:`ModelOption.is_default`.

    Returns an empty tuple when no provider key is set, which is the same
    condition under which ``build_json_inference`` returns ``None``: the UI shows
    "no decision provider configured" rather than an empty dropdown that looks
    like a loading state.
    """

    options: list[ModelOption] = []
    for provider in _PROVIDERS:
        if not _configured(settings, provider):
            continue
        for model in _models_for(settings, provider):
            options.append(
                ModelOption(
                    id=f"{provider.name}:{model}",
                    provider=provider.name,
                    model=model,
                    label=f"{provider.label} · {model}",
                    description=provider.description,
                    supports_effort=provider.supports_effort,
                    effort_values=provider.effort_values,
                    is_default=not options,
                )
            )
    return tuple(options)


def default_effort_for(settings: object, provider_name: str) -> str:
    """The effort a provider runs at when the operator names none."""

    provider = _PROVIDERS_BY_NAME.get(provider_name)
    if provider is None or not provider.supports_effort:
        return ""
    if provider.name == "mercury":
        configured = getattr(settings, "mercury_reasoning_effort", "") or DEFAULT_EFFORT
        return str(configured)
    return DEFAULT_EFFORT


def resolve_selection(
    settings: object,
    *,
    model_id: str | None,
    effort: str | None = None,
) -> ModelSelection | None:
    """Turn an operator's picks into a selection, or refuse them.

    PRE:  ``model_id`` is a catalog id (``"<provider>:<model>"``) or ``None``.
    POST: ``None`` when nothing was selected — the run uses the deployment chain
          unchanged. Otherwise a selection naming a provider whose key is set.

    Raises :class:`ValueError` for an id that is unknown, malformed, or names a
    provider this deployment has no key for, and for an effort the selected
    provider does not accept. Refusing is the point: silently falling back to the
    default would show the operator a model on the run record that never ran.
    """

    if model_id is None or not model_id.strip():
        return None
    catalog = {option.id: option for option in available_models(settings)}
    option = catalog.get(model_id.strip())
    if option is None:
        raise ValueError("that decision model is not available in this deployment")
    chosen = (effort or "").strip()
    if not chosen:
        return ModelSelection(
            provider=option.provider,
            model=option.model,
            effort=default_effort_for(settings, option.provider),
        )
    if not option.supports_effort:
        raise ValueError("that decision model does not take a reasoning effort")
    if chosen not in option.effort_values:
        raise ValueError("that reasoning effort is not one this model accepts")
    return ModelSelection(provider=option.provider, model=option.model, effort=chosen)


def selection_from_record(
    settings: object,
    *,
    model_id: str | None,
    effort: str | None,
) -> ModelSelection | None:
    """Rebuild a stored selection, tolerating a deployment that has moved on.

    A run record outlives the configuration that created it: a key can be rotated
    out, a model retired. Where :func:`resolve_selection` refuses at the API
    boundary — the operator is right there to be told — this one returns ``None``
    so an already-accepted run falls back to the deployment chain and continues.
    """

    try:
        return resolve_selection(settings, model_id=model_id, effort=effort)
    except ValueError:
        return None


def model_ids(settings: object) -> tuple[str, ...]:
    """Just the catalog ids, for validating a request field."""

    return tuple(option.id for option in available_models(settings))


def effort_values(provider_name: str) -> Sequence[str]:
    """The efforts one provider accepts, empty when it has no dial."""

    provider = _PROVIDERS_BY_NAME.get(provider_name)
    return () if provider is None else provider.effort_values


__all__ = [
    "DEFAULT_EFFORT",
    "EFFORT_VALUES",
    "ModelOption",
    "ModelSelection",
    "available_models",
    "default_effort_for",
    "effort_values",
    "model_ids",
    "resolve_selection",
    "selection_from_record",
]
