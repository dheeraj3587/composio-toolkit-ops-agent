"""Deterministic refresh boundary for BrowserAutomationContract.

Discovery and an LLM may propose facts, but only this validator can authorize a
contract. Invalid refreshes never replace the last verified contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit

from ops.automation_contracts import (
    BrowserAutomationContract,
    ContractValidationError,
    SQLiteAutomationContractRegistry,
    evidence_hash_for,
)


class ContractEvidenceDiscovery(Protocol):
    async def discover(self, *, app_slug: str, app_name: str) -> tuple[str, ...]: ...


class ContractProposalGenerator(Protocol):
    async def propose(
        self,
        *,
        app_slug: str,
        app_name: str,
        official_source_urls: tuple[str, ...],
        previous_contract: BrowserAutomationContract | None,
    ) -> BrowserAutomationContract | dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class RefreshSignals:
    observed_divergence: bool = False
    verified_url_failed: bool = False
    credential_surface_disappeared: bool = False


@dataclass(frozen=True, slots=True)
class ContractResolution:
    contract: BrowserAutomationContract
    refreshed: bool
    trigger: str
    retained_previous: bool = False


class ContractRefreshService:
    """Resolve a fresh contract and call discovery only for explicit triggers."""

    def __init__(
        self,
        *,
        registry: SQLiteAutomationContractRegistry,
        discovery: ContractEvidenceDiscovery,
        proposal_generator: ContractProposalGenerator,
    ) -> None:
        self._registry = registry
        self._discovery = discovery
        self._proposal_generator = proposal_generator

    async def resolve(
        self,
        *,
        app_slug: str,
        app_name: str,
        official_domains: tuple[str, ...],
        signals: RefreshSignals | None = None,
        now: datetime | None = None,
    ) -> ContractResolution:
        current_time = now or datetime.now(UTC)
        previous = self._registry.latest(app_slug)
        trigger = _refresh_trigger(previous, signals or RefreshSignals(), now=current_time)
        if trigger == "fresh_cache":
            assert previous is not None
            return ContractResolution(previous, refreshed=False, trigger=trigger)

        try:
            discovered = tuple(
                dict.fromkeys(
                    await self._discovery.discover(app_slug=app_slug, app_name=app_name)
                )
            )
            if not discovered:
                raise ContractValidationError("contract refresh returned no official evidence")
            _validate_official_sources(discovered, official_domains)
            proposal_raw = await self._proposal_generator.propose(
                app_slug=app_slug,
                app_name=app_name,
                official_source_urls=discovered,
                previous_contract=previous,
            )
            proposal = (
                proposal_raw
                if isinstance(proposal_raw, BrowserAutomationContract)
                else BrowserAutomationContract.model_validate(proposal_raw)
            )
            validate_contract_proposal(
                proposal,
                app_slug=app_slug,
                app_name=app_name,
                official_domains=official_domains,
                discovered_sources=discovered,
                now=current_time,
            )
        except Exception as exc:
            if previous is not None:
                return ContractResolution(
                    previous,
                    refreshed=False,
                    trigger=f"{trigger}:invalid_refresh:{type(exc).__name__}",
                    retained_previous=True,
                )
            if isinstance(exc, ContractValidationError):
                raise
            raise ContractValidationError("contract refresh proposal was rejected") from exc

        self._registry.put(proposal)
        return ContractResolution(proposal, refreshed=True, trigger=trigger)


def validate_contract_proposal(
    contract: BrowserAutomationContract,
    *,
    app_slug: str,
    app_name: str,
    official_domains: tuple[str, ...],
    discovered_sources: tuple[str, ...],
    now: datetime | None = None,
) -> None:
    """Approve only evidence-backed hosts and a current active contract."""

    if contract.app_slug != app_slug or contract.app_name != app_name:
        raise ContractValidationError("contract identity does not match the requested app")
    contract.assert_usable(now=now)
    if contract.confidence < 0.5:
        raise ContractValidationError("contract confidence is below the execution threshold")

    discovered = set(discovered_sources)
    if not set(contract.evidence.source_urls).issubset(discovered):
        raise ContractValidationError("contract cites evidence that was not fetched")
    if contract.evidence_hash != evidence_hash_for(contract.evidence.source_urls):
        raise ContractValidationError("contract evidence hash does not match its sources")
    _validate_official_sources(contract.evidence.source_urls, official_domains)

    all_hosts = (
        contract.hosts.vendor_hosts
        + contract.hosts.authentication_hosts
        + contract.hosts.email_verification_hosts
        + contract.hosts.developer_console_hosts
        + contract.hosts.credential_surface_hosts
        + contract.hosts.passive_asset_hosts
    )
    for pattern in all_hosts:
        host = pattern[2:] if pattern.startswith("*.") else pattern
        if not _host_is_official(host, official_domains):
            raise ContractValidationError("contract proposed a host outside reviewed domains")

    entrypoints = (
        contract.signup.entrypoints
        + contract.login.entrypoints
        + contract.developer_app.console_entrypoints
    )
    for url in entrypoints:
        host = (urlsplit(url).hostname or "").casefold()
        if not _host_is_official(host, official_domains):
            raise ContractValidationError("contract proposed an unofficial entrypoint")


def _refresh_trigger(
    previous: BrowserAutomationContract | None,
    signals: RefreshSignals,
    *,
    now: datetime,
) -> str:
    if previous is None:
        return "contract_missing"
    if previous.status != "active" or previous.is_expired(now=now):
        return "contract_stale"
    if signals.observed_divergence:
        return "observed_divergence"
    if signals.verified_url_failed:
        return "verified_url_failed"
    if signals.credential_surface_disappeared:
        return "credential_surface_disappeared"
    return "fresh_cache"


def _validate_official_sources(
    source_urls: tuple[str, ...], official_domains: tuple[str, ...]
) -> None:
    if not official_domains:
        raise ContractValidationError("no reviewed official domains were supplied")
    for url in source_urls:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").casefold()
        if parsed.scheme != "https" or not _host_is_official(host, official_domains):
            raise ContractValidationError("unofficial evidence source was rejected")


def _host_is_official(host: str, official_domains: tuple[str, ...]) -> bool:
    normalized = host.rstrip(".").casefold()
    for domain in official_domains:
        reviewed = domain.rstrip(".").casefold()
        if normalized == reviewed or normalized.endswith(f".{reviewed}"):
            return True
    return False


__all__ = [
    "ContractEvidenceDiscovery",
    "ContractProposalGenerator",
    "ContractRefreshService",
    "ContractResolution",
    "RefreshSignals",
    "validate_contract_proposal",
]
