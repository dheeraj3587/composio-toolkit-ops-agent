"""One-at-a-time live provider smokes for the real end-to-end demo.

Run only with explicit owner authorization. Each provider makes at most one
bounded request and prints sanitized evidence (no secrets, no signed live URLs
persisted). Gmail sending is intentionally excluded. Providers with a missing
key are skipped truthfully.

Usage (keys read from the process env or ./.env):

    PYTHONPATH=. .venv/bin/python scripts/live_smoke.py perplexity
    PYTHONPATH=. .venv/bin/python scripts/live_smoke.py gemini
    PYTHONPATH=. .venv/bin/python scripts/live_smoke.py composio
    PYTHONPATH=. .venv/bin/python scripts/live_smoke.py browser
    PYTHONPATH=. .venv/bin/python scripts/live_smoke.py all
"""

from __future__ import annotations

import asyncio
import sys

import httpx

from ops.composio_capability import ComposioCapabilityPreflight
from ops.config import load_settings
from ops.operational_research import (
    GeminiStructuredExtractor,
    OperationalResearchEnricher,
    PerplexitySearchDiscovery,
)
from ops.p1_adapter import P1LookupFound, P1OperationalAdapter, to_operational_research

PROOF_APP = "HubSpot"


def _line(text: str) -> None:
    print(text, flush=True)


def _p1_record() -> object:
    lookup = P1OperationalAdapter().lookup(PROOF_APP)
    if not isinstance(lookup, P1LookupFound):
        raise SystemExit(f"{PROOF_APP} is not in the verified P1 snapshot")
    return lookup.record


async def smoke_perplexity() -> None:
    settings = load_settings()
    if settings.perplexity_api_key is None:
        _line("perplexity: SKIPPED (PERPLEXITY_API_KEY missing)")
        return
    discovery = PerplexitySearchDiscovery(settings.perplexity_api_key)
    urls = await discovery.discover(app_name=PROOF_APP)
    _line("perplexity: provider=Perplexity method=AsyncPerplexity.search.create requests=1")
    _line(f"perplexity: external_action=True sanitized_result_count={len(urls)}")
    for url in urls:
        _line(f"  - {url}")


async def smoke_gemini() -> None:
    settings = load_settings()
    if settings.google_genai_api_key is None:
        _line("gemini: SKIPPED (GOOGLE_GENAI_API_KEY missing)")
        return
    record = _p1_record()
    baseline = to_operational_research(record)  # type: ignore[arg-type]
    discovery = (
        PerplexitySearchDiscovery(settings.perplexity_api_key)
        if settings.perplexity_api_key is not None
        else None
    )
    extractor = GeminiStructuredExtractor(
        settings.google_genai_api_key, model=settings.gemini_model_chain
    )
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=10.0)) as client:
        enricher = OperationalResearchEnricher(
            discovery=discovery, extractor=extractor, http_client=client
        )
        outcome = await enricher.enrich(
            app_name=PROOF_APP,
            p1_record=record.model_dump(mode="json"),  # type: ignore[attr-defined]
            baseline=baseline,
        )
    _line(
        "gemini: provider=Gemini method=client.aio.models.generate_content "
        f"model_chain={settings.gemini_model_chain} model_used={extractor.model_used} requests>=1"
    )
    _line(
        f"gemini: capability={outcome.capability.status} "
        f"reason={outcome.capability.reason_code} documents={outcome.documents_fetched}"
    )
    research = outcome.research
    _line(
        "gemini: sanitized_fields "
        f"auth_scheme_methods={research.auth_methods} "
        f"token_url={research.token_url} scopes={[s.name for s in research.scopes]}"
    )


async def smoke_composio() -> None:
    settings = load_settings()
    if settings.composio_api_key is None:
        _line("composio: SKIPPED (COMPOSIO_API_KEY missing)")
        return
    preflight = ComposioCapabilityPreflight(settings=settings)
    report = await preflight.evaluate(app_name=PROOF_APP, app_slug="hubspot")
    _line("composio: provider=Composio method=toolkits.get+connected_accounts.list requests=2")
    _line(
        "composio: "
        f"toolkit_slug={report.toolkit_slug} toolkit_available={report.toolkit_available} "
        f"active_account={report.active_connected_account} state={report.capability_state} "
        f"reason={report.reason_code} external_action=False"
    )


async def smoke_browser() -> None:
    settings = load_settings()
    if settings.browser_use_api_key is None:
        _line("browser: SKIPPED (BROWSER_USE_API_KEY missing)")
        return
    if not settings.allow_live_browser:
        _line("browser: SKIPPED (ALLOW_LIVE_BROWSER is false)")
        return
    from ops.browser_worker import BrowserWorker

    worker = BrowserWorker(settings=settings)
    context = await worker.start(profile_id=None)
    _line("browser: provider=BrowserUse method=sessions.create requests=1 external_action=True")
    _line(
        "browser: "
        f"session_id={context.session_id} live_view_available={context.live_view_available} "
        f"(signed live URL kept ephemeral, not printed/persisted)"
    )
    _line("browser: session left alive for owner interaction; stop it explicitly when done")


_SMOKES = {
    "perplexity": smoke_perplexity,
    "gemini": smoke_gemini,
    "composio": smoke_composio,
    "browser": smoke_browser,
}


async def _run(target: str) -> None:
    if target == "all":
        for name in ("perplexity", "gemini", "composio", "browser"):
            await _SMOKES[name]()
        return
    smoke = _SMOKES.get(target)
    if smoke is None:
        raise SystemExit(f"unknown smoke target {target!r}; choose {sorted(_SMOKES)} or 'all'")
    await smoke()


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    asyncio.run(_run(target))


if __name__ == "__main__":
    main()
