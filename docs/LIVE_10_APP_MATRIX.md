# Live Composio 10-App Capability Matrix

Generated: 2026-07-23T06:15:44.987662Z

Real, read-only Composio checks (toolkit lookup + ACTIVE connected-account lookup). No browser session, no Gmail, no connection creation, no credentials.

| App | Slug | P1 Route | Toolkit Slug | Toolkit Avail | Active Conn | Capability State | Resulting Action | Provider Error | External Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HubSpot | hubspot | self_serve | hubspot | True | False | connection_required | composio_connection_required | None | False |
| Pipedrive | pipedrive | self_serve | pipedrive | True | False | custom_auth_or_approval_required | browser_fallback | None | False |
| Attio | attio | self_serve | attio | True | False | connection_required | composio_connection_required | None | False |
| Twenty | twenty | self_serve | None | False | False | toolkit_unavailable | browser_fallback | None | False |
| Zendesk | zendesk | approval_required | zendesk | True | False | connection_required | composio_connection_required | None | False |
| Google Ads | google-ads | approval_required | None | False | False | toolkit_unavailable | gated_outreach | None | False |
| WhatsApp Business | whatsapp-business | approval_required | None | False | False | toolkit_unavailable | gated_outreach | None | False |
| Salesforce | salesforce | partner_gated | salesforce | True | False | connection_required | composio_connection_required | None | False |
| Close | close | partner_gated | close | True | False | custom_auth_or_approval_required | gated_outreach | None | False |
| Sherlock | sherlock | blocked | None | False | False | toolkit_unavailable | configuration_required | None | False |
