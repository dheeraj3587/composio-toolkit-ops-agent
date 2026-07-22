Classify a sanitized reply in an API-access conversation.
The strings [REDACTED_SECRET:<type>] indicate that deterministic code already
removed and stored a possible secret. Never ask for or reconstruct the value.

Allowed classes:
- no_reply
- more_information_required
- meeting_requested
- approved_setup_required
- credentials_received
- rejected
- automated_response
- unclear

Extract:
- explicit questions asked by the provider
- official setup URLs
- stated approval/rejection reason
- required next action
- whether a browser onboarding flow should start

Use only the supplied email thread. Return the exact schema; no prose.
