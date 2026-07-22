Select scopes only from the supplied documented scope catalog.
Never invent a scope. Respect requested policy:
- minimum: smallest set required for the target starter tools
- recommended: read/write coverage for the target starter tools without account-admin scopes
- maximum: all documented integration scopes except billing, organization ownership,
  destructive admin, or security-management scopes unless the target tools explicitly require them

Return requested scopes, excluded scopes with reason, and source URL for every scope.
