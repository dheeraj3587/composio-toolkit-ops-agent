# Sanitized fixture policy

Fixtures must be synthetic, minimal, and safe to commit. Never copy a production provider export,
real mailbox content, browser storage state, cookies, authorization headers, credentials, tokens,
private account identifiers, or credential-page screenshots into this tree.

Use conspicuous placeholders such as `[REDACTED_SECRET:client_secret]`, `.invalid` domains, and
invented IDs. A fixture must contain only the fields required by its test and must pass the repository
secret scan before commit. Raw source material is not retained after a sanitized fixture is built.
