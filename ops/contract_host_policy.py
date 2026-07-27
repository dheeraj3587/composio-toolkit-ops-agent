"""Dynamic staged browser host policy derived from a verified contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from ops.automation_contracts import BrowserAutomationContract, ContractValidationError
from ops.browser_host_policy import host_matches_patterns


class ContractEgressStage(StrEnum):
    PRE_SIGNUP = "pre_signup"
    SIGNUP = "signup"
    EMAIL_VERIFICATION = "email_verification"
    AUTHENTICATING = "authenticating"
    POST_AUTH = "post_auth"
    DEVELOPER_CONSOLE = "developer_console"
    CREDENTIAL_SURFACE = "credential_surface"


@dataclass(frozen=True, slots=True)
class ReviewedDomainRules:
    """Human-reviewed domain boundary; contracts cannot expand beyond it."""

    exact_hosts: tuple[str, ...]
    wildcard_domains: tuple[str, ...] = ()
    passive_asset_hosts: tuple[str, ...] = ()

    def patterns(self) -> tuple[str, ...]:
        return (
            *self.exact_hosts,
            *(f"*.{domain}" for domain in self.wildcard_domains),
        )


@dataclass(frozen=True, slots=True)
class ContractBrowserAllowedHosts:
    app_slug: str
    vendor_hosts: tuple[str, ...]
    authentication_hosts: tuple[str, ...]
    email_verification_hosts: tuple[str, ...]
    developer_console_hosts: tuple[str, ...]
    credential_surface_hosts: tuple[str, ...]
    passive_asset_hosts: tuple[str, ...]
    prohibited_hosts: tuple[str, ...]

    def active_patterns(self, stage: ContractEgressStage, *, passive: bool = False) -> tuple[str, ...]:
        vendor = self.vendor_hosts
        if stage is ContractEgressStage.PRE_SIGNUP:
            active = vendor
        elif stage is ContractEgressStage.SIGNUP:
            active = (*vendor, *self.authentication_hosts)
        elif stage is ContractEgressStage.EMAIL_VERIFICATION:
            active = (*vendor, *self.email_verification_hosts)
        elif stage is ContractEgressStage.AUTHENTICATING:
            active = (*vendor, *self.authentication_hosts)
        elif stage is ContractEgressStage.POST_AUTH:
            active = vendor
        elif stage is ContractEgressStage.DEVELOPER_CONSOLE:
            active = (*vendor, *self.developer_console_hosts)
        else:
            # Strictest stage: credential hosts only. No IdP, analytics, email,
            # passive CDN, or general developer-console expansion is retained.
            active = self.credential_surface_hosts
        if passive and stage is not ContractEgressStage.CREDENTIAL_SURFACE:
            active = (*active, *self.passive_asset_hosts)
        return tuple(dict.fromkeys(active))

    def permits(
        self,
        *,
        url: str,
        stage: ContractEgressStage,
        passive_resource: bool = False,
    ) -> bool:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return False
        host = parsed.hostname.rstrip(".").casefold()
        if host_matches_patterns(host, self.prohibited_hosts):
            return False
        patterns = self.active_patterns(stage, passive=passive_resource)
        return bool(patterns) and host_matches_patterns(host, patterns)


def build_contract_allowed_hosts(
    contract: BrowserAutomationContract,
    *,
    reviewed_rules: ReviewedDomainRules,
) -> ContractBrowserAllowedHosts:
    """Activate only contract hosts independently approved by reviewed rules."""

    contract.assert_usable()
    reviewed_patterns = reviewed_rules.patterns()
    categories = {
        "vendor_hosts": contract.hosts.vendor_hosts,
        "authentication_hosts": contract.hosts.authentication_hosts,
        "email_verification_hosts": contract.hosts.email_verification_hosts,
        "developer_console_hosts": contract.hosts.developer_console_hosts,
        "credential_surface_hosts": contract.hosts.credential_surface_hosts,
        "passive_asset_hosts": contract.hosts.passive_asset_hosts,
    }
    if not categories["vendor_hosts"]:
        raise ContractValidationError("verified contract has no vendor host")

    for name, patterns in categories.items():
        for pattern in patterns:
            host = pattern[2:] if pattern.startswith("*.") else pattern
            if not host_matches_patterns(host, reviewed_patterns):
                raise ContractValidationError(f"{name} contains an unreviewed host")

    for pattern in contract.hosts.prohibited_hosts:
        host = pattern[2:] if pattern.startswith("*.") else pattern
        if host_matches_patterns(host, reviewed_patterns):
            # A reviewed domain may still be explicitly prohibited, but it must not
            # overlap an active category. The contract model enforces that overlap.
            continue

    passive = tuple(
        dict.fromkeys((*contract.hosts.passive_asset_hosts, *reviewed_rules.passive_asset_hosts))
    )
    return ContractBrowserAllowedHosts(
        app_slug=contract.app_slug,
        vendor_hosts=contract.hosts.vendor_hosts,
        authentication_hosts=contract.hosts.authentication_hosts,
        email_verification_hosts=contract.hosts.email_verification_hosts,
        developer_console_hosts=contract.hosts.developer_console_hosts,
        credential_surface_hosts=contract.hosts.credential_surface_hosts,
        passive_asset_hosts=passive,
        prohibited_hosts=contract.hosts.prohibited_hosts,
    )


__all__ = [
    "ContractBrowserAllowedHosts",
    "ContractEgressStage",
    "ReviewedDomainRules",
    "build_contract_allowed_hosts",
]
