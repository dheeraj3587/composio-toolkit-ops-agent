"""The owner's standing authorization to create accounts, read from deployment config.

This is the concrete :class:`~ops.onboarding.admission.StandingSignupAuthority`
behind unattended signup. It exists because the alternative — a boolean capability
flag consulted at signup time — loses the only thing that makes autonomous account
creation defensible: the identity of the person who authorized it and the moment
they did.

Why deployment configuration rather than a database table
---------------------------------------------------------
An authorization to enter into vendor agreements on the owner's behalf is not
run-time data that the running system should be able to grant itself. Holding it
in configuration means granting it requires an edit to a file that is reviewed,
version-controlled in its ``.example`` form, and deployed — the same path as every
other capability in this deployment — rather than an API call the agent's own
control plane could make. Revoking it is likewise a deploy, not a race with an
in-flight run.

The wildcard is expanded, never stored
--------------------------------------
``ONBOARDING_SIGNUP_AUTHORIZED_APPS=*`` authorizes the whole reviewed catalog, and
:meth:`SettingsStandingSignupAuthority.signup_authorization` still answers with the
concrete slug it was asked about. So the durable admission row records
``pipedrive``, never ``*``, and reading the decisions back later reports which
providers accounts were actually created on rather than an intent.

Unknown slugs are refused
-------------------------
A slug that is not in the reviewed catalog is not authorized even when it is
listed, and even under the wildcard. A typo in the list would otherwise silently
authorize nothing (harmless) or, on the recipe-free path Phase 6 opens, authorize a
provider name that arrived from research rather than from review (not harmless).
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from ops.core.config import Settings
from ops.onboarding.admission import StandingSignupAuthorization
from ops.recipes.app_recipes import load_app_recipe_catalog

# The one token that means "every reviewed app". Deliberately not a per-slug
# prefix or glob language: a grant this broad should be unmistakable in a diff,
# and a pattern language would invite grants nobody can evaluate by reading.
CATALOG_WILDCARD = "*"


@dataclass(frozen=True, slots=True)
class SettingsStandingSignupAuthority:
    """Answers ``may this deployment create an account on <app>?`` from settings.

    Structurally satisfies ``StandingSignupAuthority``. Frozen and precomputed:
    the authorized set is resolved once at construction, so a lookup is a set
    membership test and cannot re-read a mutated environment mid-run.
    """

    authorized: frozenset[str]
    authorized_by: str
    authorized_at: str

    @classmethod
    def from_settings(cls, settings: Settings) -> SettingsStandingSignupAuthority | None:
        """Build the authority this deployment configures, or ``None`` for none.

        PRE:  ``settings`` has passed its own validation, so an author and a
              timestamp are present whenever the app list is non-empty.
        POST: ``None`` when no apps are listed — the fail-closed state, in which
              every run with no stored credentials asks a person. Otherwise an
              authority whose ``authorized`` set is the listed slugs intersected
              with the reviewed catalog, which may be empty if every listed slug
              was unknown. An empty set is not ``None``: the difference is
              "authorized nothing" versus "configured nothing", and only the
              first is worth a puzzled operator finding the typo.
        """

        listed = frozenset(
            slug.strip().casefold()
            for slug in settings.onboarding_signup_authorized_apps
            if slug.strip()
        )
        if not listed:
            return None
        catalog = frozenset(recipe.app_slug for recipe in load_app_recipe_catalog().apps)
        authorized = catalog if CATALOG_WILDCARD in listed else catalog & listed
        # Non-null by the model validator in ``ops.core.config``; restated as a
        # local default so a future caller constructing Settings directly cannot
        # produce an authorization attributed to the empty string.
        return cls(
            authorized=authorized,
            authorized_by=(settings.onboarding_signup_authorized_by or "").strip(),
            authorized_at=(settings.onboarding_signup_authorized_at or "").strip(),
        )

    def signup_authorization(self, *, app_slug: str) -> StandingSignupAuthorization | None:
        """The authorization covering ``app_slug``, or ``None`` if there is none.

        POST: the returned record names ``app_slug`` itself, so the caller's
              equality check against the slug it asked about holds and the durable
              decision names one provider.
        """

        slug = app_slug.strip().casefold()
        if not slug or slug not in self.authorized:
            return None
        return StandingSignupAuthorization(
            app_slug=slug,
            authorized_by=self.authorized_by,
            authorized_at=self.authorized_at,
        )

    def summary(self) -> MappingProxyType[str, object]:
        """A log- and response-safe view: counts and attribution, no secrets.

        Used by the operations surface so "why did this sign itself up?" is
        answerable without reading the container's environment.
        """

        return MappingProxyType(
            {
                "authorized_app_count": len(self.authorized),
                "authorized_by": self.authorized_by,
                "authorized_at": self.authorized_at,
            }
        )


__all__ = ["CATALOG_WILDCARD", "SettingsStandingSignupAuthority"]
