# Gmail fixtures

Persist only synthetic or deterministically sanitized threads. Never store `.eml` exports, message
headers with real addresses, attachments, signatures, OAuth data, or unredacted credential-bearing
content. Replace suspected values before the fixture touches disk with
`[REDACTED_SECRET:<type>]`; use `example.invalid` addresses and invented thread/message IDs.
