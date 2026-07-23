---
name: official-evidence-enrichment
description: Integrate Perplexity discovery, guarded official-document fetching, and Gemini structured extraction without SSRF, hallucinated facts, or P1 mutation. Use for missing operational research fields.
---

# Official-evidence enrichment

- Treat search results as discovery candidates only.
- Derive official host allowlists from verified P1 evidence.
- Require HTTPS, public DNS results, standard ports, bounded redirects, bounded size, and approved content types.
- Revalidate every redirect target.
- Fetch at most the configured document limit.
- Send only bounded non-secret excerpts to the extractor.
- Use structured Pydantic output; do not parse markdown JSON.
- Preserve canonical app name and slug.
- Every evidence URL and scope source must be one of the fetched official documents.
- Missing configuration returns a truthful baseline plus missing fields.
- Never write enrichment into canonical P1 files.

Test SSRF, redirect, MIME, size, unsupported evidence, changed identity, hallucinated scope, one-probe limit, and successful fixtures.
