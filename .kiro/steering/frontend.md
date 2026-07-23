---
inclusion: fileMatch
fileMatchPattern: "web/**/*.{ts,tsx,css}"
---
# Frontend standards

Build a polished developer-infrastructure control plane, not a marketing page or chatbot.

Use the existing dark rail, warm off-white canvas, restrained violet accent, crisp border system, small radii, Geist typography, and dense information hierarchy. Avoid glassmorphism, noisy gradients, fake AI animations, giant headings, stock illustrations, and fabricated metrics.

Server Components fetch initial state. Client Components are limited to interactivity. Keep `OPS_API_URL` server-only. Validate all backend responses with Zod. Never store run or credential data in browser storage. Never render provider HTML with `dangerouslySetInnerHTML`.

Use semantic HTML, Radix/shadcn interaction primitives, visible focus, keyboard support, accessible error messaging, reduced-motion support, and axe checks.
