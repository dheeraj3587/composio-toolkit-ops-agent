---
name: frontend-control-plane-design
description: Design and implement a beautiful, accessible Next.js developer-infrastructure control plane for runs, evidence, HITL, providers, and IntegratorBundle output. Use for frontend pages, components, visual polish, responsive behavior, and accessibility.
---

# Frontend control-plane design

## Visual language

- Dark graphite navigation rail, warm off-white canvas, white cards, restrained violet accent.
- Crisp 1px borders, 10–12px cards, 6–8px controls, minimal shadows.
- Geist Sans for interface text and Geist Mono for IDs, labels, and evidence metadata.
- Information-dense but calm. Prefer grids, timelines, compact tables, split panes, and clear empty states.
- No glassmorphism, neon gradients, chatbot bubbles, fake AI sparkle, giant hero text, stock art, or fabricated charts.

## Layout

- Expanded rail 248px; collapsed rail 72px.
- Header 64px.
- Main max width 1440px.
- Desktop padding 40px; tablet 24px; mobile 16px.
- Run detail uses an 8/12 primary column and 4/12 context column above 1100px; one column below.
- Use container queries where a reusable card must adapt to its allocated width.

## Components

- App search command/combobox.
- Real metrics strip.
- Provenance card.
- Run table with status, route, mode, update time, and attention state.
- Phase grid with backend-reported status only.
- Route explanation card.
- Evidence list with safe HTTPS links.
- Sanitized timeline.
- Provider capability cards.
- Conditional HITL card with one clear action.
- Browser and Gmail metadata cards without sensitive URLs or message bodies.
- IntegratorBundle summary with JSON download and vault-reference count.

## Interaction

- Server Components for initial data; Client Components only for interactivity.
- Zod validate every API response.
- Disable controls that are illegal in the current backend state and explain why.
- Use Sonner for concise action receipts, not success claims unsupported by state.
- Poll only active runs with bounded intervals; stop on terminal states and when tab is hidden.
- Preserve non-secret form values after validation errors.
- Use skeletons matching final geometry.
- Respect reduced motion.

## Accessibility

- Semantic landmarks and heading order.
- Real buttons and links.
- Visible focus rings.
- Keyboard support for all composite controls.
- Labels, hints, and error association for forms.
- Color plus icon/text status encoding.
- WCAG AA contrast.
- axe checks for dashboard, new run, run detail, app research, system page, dialogs, and active HITL.

## Security

- `OPS_API_URL` remains server-only.
- No credentials in browser storage, query parameters, console logs, or analytics.
- No `dangerouslySetInnerHTML` for provider content.
- No reveal, copy, or export secret actions.
- Do not silently enable demo mode.

Before implementing a visual change, inspect existing tokens and components, reuse them, and show the improvement through screenshots or component tests.
