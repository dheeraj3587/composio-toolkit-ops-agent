"""Secure operations foundation for the Composio P2 pipeline."""

import os

from ops.core.models import (
    AccountMode,
    CompanyProfile,
    IntegratorBundle,
    OperationalResearch,
    OperationsRequest,
    ScopeRequirement,
)
from ops.core.redaction import install_redacting_filter
from ops.core.state import AccessRoute, OperationsState, RunStatus

# The process owns every runtime artifact. Set this once at application import
# so SQLite journals and any later checkpoints inherit owner-only defaults.
os.umask(0o077)
install_redacting_filter()

__all__ = [
    "AccountMode",
    "AccessRoute",
    "CompanyProfile",
    "IntegratorBundle",
    "OperationalResearch",
    "OperationsRequest",
    "OperationsState",
    "RunStatus",
    "ScopeRequirement",
]
