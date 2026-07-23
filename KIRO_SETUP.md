# Kiro setup

1. Copy `PLAN.md`, `AGENTS.md`, and the `.kiro/` directory into the repository root.
2. Open the repository as a trusted Kiro workspace.
3. Restart Kiro if the custom agent or skills are not visible.
4. Select Claude Opus 4.8. Use XHigh or Max effort for architecture, security, and provider integration.
5. Select the workspace agent `opus-implementation-lead`.
6. Confirm skills are visible in Agent Steering & Skills or through `/` commands.
7. Create a Design-First Feature Spec named `end-to-end-operations-runtime` using the prompt at the end of PLAN.md.
8. Run tasks in vertical milestones rather than one giant implementation task.

Official shadcn frontend skill:

```bash
cd web
pnpm dlx skills add shadcn/ui
pnpm dlx shadcn@latest mcp init
```

Review generated files and MCP permissions before enabling them. Do not place provider keys in Kiro steering, skills, agent files, or MCP configuration committed to Git.

For Kiro CLI, verify the model ID first with `/model`; the current documented ID is `claude-opus-4.8`.
