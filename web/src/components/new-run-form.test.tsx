import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"

import { NewRunForm } from "@/components/new-run-form"

vi.mock("@/app/runs/new/actions", () => ({
  createRunAction: vi.fn(),
}))

// The app field is now a selector over the verified catalog. The catalog hook is
// stubbed so these tests stay about the form, not about fetching.
vi.mock("@/lib/app-catalog", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/app-catalog")>()
  return {
    ...actual,
    useAppCatalog: () => ({
      data: {
        items: [
          {
            app_name: "Pipedrive",
            app_slug: "pipedrive",
            category: "CRM",
            api_type: "REST",
            access_route: "self_serve",
            auth_methods: ["API Key"],
            confidence: 0.9,
            buildability: "Easy",
            verification_status: "Hand-Checked",
          },
        ],
        total: 1,
      },
      isPending: false,
      isError: false,
    }),
  }
})

describe("NewRunForm", () => {
  it("shows required company fields and independent creation boundaries", () => {
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "configured_not_verified", detail: "Configured." },
          { provider: "browser_use", status: "configured_not_verified", detail: "Configured." },
        ]}
      />,
    )

    // The prefilled app is selected in the catalog selector, so nobody has to
    // know or retype its exact name.
    expect(screen.getByRole("combobox", { name: "Application" })).toHaveTextContent("Pipedrive")
    expect(screen.getByRole("textbox", { name: "Legal name" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Company website" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Integration use case" })).toBeInTheDocument()

    const mode = screen.getByRole("combobox", { name: "Execution mode" })
    expect(mode).toHaveTextContent("Execute when configured")
    expect(screen.getByText(/may perform approved provider actions only when backend policy/i)).toBeInTheDocument()
    expect(screen.getByText(/execution can proceed only when backend policy and provider configuration permit each action/i)).toBeInTheDocument()
    expect(screen.getByRole("radio", { name: /playwright/i })).toBeChecked()
    expect(screen.getByRole("combobox", { name: "Account handling" })).toHaveTextContent(
      "Create if missing",
    )
    expect(screen.getByRole("combobox", { name: "Developer application" })).toHaveTextContent(
      "Create if missing",
    )
    expect(screen.getByRole("combobox", { name: "Credential handling" })).toHaveTextContent(
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
