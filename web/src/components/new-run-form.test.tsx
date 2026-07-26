import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"

import { NewRunForm } from "@/components/new-run-form"

vi.mock("@/app/runs/new/actions", () => ({
  createRunAction: vi.fn(),
}))

describe("NewRunForm", () => {
  it("shows the required company fields and makes execute-mode boundaries explicit", () => {
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "configured_not_verified", detail: "Configured." },
          { provider: "browser_use", status: "configured_not_verified", detail: "Configured." },
        ]}
      />,
    )

    expect(screen.getByRole("textbox", { name: "Application name" })).toHaveValue("Pipedrive")
    expect(screen.getByRole("textbox", { name: "Legal name" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Company website" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Integration use case" })).toBeInTheDocument()

    const mode = screen.getByRole("combobox", { name: "Execution mode" })
    expect(mode).toHaveTextContent("Execute when configured")
    expect(screen.getByText(/may perform approved provider actions only when backend policy/i)).toBeInTheDocument()
    expect(screen.getByText(/execution can proceed only when backend policy and provider configuration permit each action/i)).toBeInTheDocument()
    expect(screen.getByRole("radio", { name: /playwright/i })).toBeChecked()
    expect(screen.getByRole("combobox", { name: "Credential creation" })).toHaveTextContent(
      "Create if missing",
    )
  })

  it("falls back to Browser Use and keeps unavailable engines visible", () => {
    render(
      <NewRunForm
        providerStates={[
          { provider: "playwright", status: "not_configured", detail: "Service token missing." },
          { provider: "browser_use", status: "ready", detail: "Ready." },
        ]}
      />,
    )

    expect(screen.getByRole("radio", { name: /playwright/i })).toBeDisabled()
    expect(screen.getByText("Service token missing.")).toBeVisible()
    expect(screen.getByRole("radio", { name: /browser use/i })).toBeChecked()
  })

  it("leaves the group unselected when neither provider is available", () => {
    render(
      <NewRunForm
        providerStates={[
          { provider: "playwright", status: "disabled", detail: "Policy disabled." },
          { provider: "browser_use", status: "not_configured", detail: "Key missing." },
        ]}
      />,
    )

    const radios = screen.getAllByRole("radio")
    expect(radios).toHaveLength(2)
    for (const radio of radios) expect(radio).not.toBeChecked()
  })

  it("supports native keyboard selection between available engines", async () => {
    const user = userEvent.setup()
    render(
      <NewRunForm
        providerStates={[
          { provider: "playwright", status: "ready", detail: "Ready." },
          { provider: "browser_use", status: "ready", detail: "Ready." },
        ]}
      />,
    )

    const playwright = screen.getByRole("radio", { name: /playwright/i })
    const browserUse = screen.getByRole("radio", { name: /browser use/i })
    playwright.focus()
    await user.keyboard("{ArrowRight}")
    expect(browserUse).toBeChecked()
  })
})
