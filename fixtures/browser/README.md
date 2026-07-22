# Browser fixtures

Browser fixtures are handcrafted observations only. They must not contain page storage, cookies,
headers, raw HTML from login or credential pages, recordings, screenshots, OTPs, or real form values.
Represent a credential page with labels/selectors and replace any value with
`[REDACTED_SECRET:<type>]`. Use `.invalid` URLs and explicitly synthetic provider/app IDs.
