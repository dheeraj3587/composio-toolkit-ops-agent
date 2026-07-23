"""Steps 8-9: pick a browser-fallback self-serve app, then one real session.

Read-only Composio preflight is run over up to five verified P1 self-serve apps.
The first app whose real capability result truthfully permits browser fallback
(custom auth / vendor approval, or no Composio toolkit) is selected. That app is
enriched once (Perplexity + Gemini) to obtain its verified official URLs, then a
single real Browser Use v3 session is created and one bounded navigation task is
run. No Gmail is sent and no credentials are captured.
"""

from __future__ import annotations

import asyncio

import httpx

from ops.browser_worker import BrowserWorker
from ops.composio_capability import ComposioCapabilityPreflight
from ops.config import load_settings
from ops.operational_research import (
    GeminiStructuredExtractor,
    OperationalResearchEnricher,
    PerplexitySearchDiscovery,
)
from ops.p1_adapter import load_verified_snapshot, to_operational_research

MAX_CANDIDATES = 5


def _line(text: str) -> None:
    print(text, flush=True)


def _self_serve_candidates() -> list[object]:
    snapshot = load_verified_snapshot()
    candidates: list[object] = []
    for record in snapshot.records:
        if to_operational_research(record).access_route == "self_serve":
            candidates.append(record)
        if len(candidates) >= MAX_CANDIDATES:
            break
    return candidates


async def main() -> None:
    settings = load_settings()
    if settings.composio_api_key is None:
        raise SystemExit("COMPOSIO_API_KEY is required for the preflight matrix")

    preflight = ComposioCapabilityPreflight(settings=settings)
    candidates = _self_serve_candidates()
    _line(f"Read-only Composio preflight over {len(candidates)} P1 self-serve apps:")
    selected = None
    for record in candidates:
        slug = record.slug  # type: ignore[attr-defined]
        report = await preflight.evaluate(app_name=record.app, app_slug=slug)  # type: ignore[attr-defined]
        _line(
            f"  - {record.app:<22} slug={report.toolkit_slug} "  # type: ignore[attr-defined]
            f"available={report.toolkit_available} active={report.active_connected_account} "
            f"state={report.capability_state} fallback_allowed={report.p1_fallback_allowed}"
        )
        if selected is None and report.p1_fallback_allowed:
            selected = record

    if selected is None:
        _line("No self-serve app in the sampled set permits browser fallback; stopping.")
        return

    app_name = selected.app  # type: ignore[attr-defined]
    _line(f"\nSelected browser-fallback app: {app_name}")

    baseline = to_operational_research(selected)  # type: ignore[arg-type]
    discovery = (
        PerplexitySearchDiscovery(settings.perplexity_api_key)
        if settings.perplexity_api_key is not None
        else None
    )
    extractor = (
        GeminiStructuredExtractor(settings.google_genai_api_key, model=settings.gemini_model)
        if settings.google_genai_api_key is not None
        else None
    )
    research = baseline
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=10.0)) as client:
        enricher = OperationalResearchEnricher(
            discovery=discovery, extractor=extractor, http_client=client
        )
        outcome = await enricher.enrich(
            app_name=app_name,
            p1_record=selected.model_dump(mode="json"),  # type: ignore[attr-defined]
            baseline=baseline,
        )
        research = outcome.research
    _line(
        f"enrichment: capability={outcome.capability.status} "
        f"developer_portal_url={research.developer_portal_url} signup_url={research.signup_url} "
        f"api_base_url={research.api_base_url}"
    )

    if settings.browser_use_api_key is None or not settings.allow_live_browser:
        _line(
            "Browser Use is not enabled (need BROWSER_USE_API_KEY + ALLOW_LIVE_BROWSER); stopping."
        )
        return

    worker = BrowserWorker(settings=settings)
    context = await worker.start(profile_id=None)
    live = worker.live_url(context.session_id)
    _line("\nReal Browser Use v3 session:")
    _line(f"  app                 : {app_name}")
    _line(f"  session_id          : {context.session_id}")
    _line(f"  live_view_available : {context.live_view_available}")
    _line(f"  live_url            : {live or '(none returned)'}")
    try:
        observation = await worker.navigate_onboarding(context, research)
    except Exception as exc:  # noqa: BLE001 - report the concrete blocker truthfully
        _line(f"  navigation          : FAILED ({type(exc).__name__}: {exc})")
        _line(f"  NOTE: session {context.session_id} left alive; stop it when done.")
        return
    _line(f"  official_start_url  : {research.developer_portal_url or research.signup_url}")
    _line(f"  current_url         : {observation.current_url}")
    _line(f"  state               : {observation.status}")
    _line(
        f"  hitl_required       : {observation.status == 'human_action_required'} "
        f"({observation.human_action_type or 'none'})"
    )
    _line(f"  NOTE: session {context.session_id} left alive for owner interaction.")


if __name__ == "__main__":
    asyncio.run(main())
