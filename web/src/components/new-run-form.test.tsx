import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach } from "vitest"

import { NewRunForm } from "@/components/new-run-form"

const appMocks = vi.hoisted(() => ({
  useAppCapabilities: vi.fn(),
}))
const actionMocks = vi.hoisted(() => ({
  createRunAction: vi.fn(),
}))

vi.mock("@/app/runs/new/actions", () => ({
  createRunAction: actionMocks.createRunAction,
}))

// The app field is now a selector over the verified catalog. The catalog hook is
// stubbed so these tests stay about the form, not about fetching.
vi.mock("@/lib/app-catalog", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/app-catalog")>()
  return {
    ...actual,
    useAppCapabilities: appMocks.useAppCapabilities,
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
  beforeEach(() => {
    actionMocks.createRunAction.mockReset()
    actionMocks.createRunAction.mockResolvedValue({
      error: null,
      fields: [],
      idempotencyKey: null,
      requestFingerprint: null,
    })
    appMocks.useAppCapabilities.mockReturnValue({
      data: {
        app_slug: "pipedrive",
        account_creation_supported: true,
        reason_code: "reviewed_signup_route",
      },
      isPending: false,
      isError: false,
    })
  })

  it("shows the required company and browser fields with truthful execution controls", async () => {
    const user = userEvent.setup()
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "configured_not_verified", detail: "Configured." },
          { provider: "browser_use", status: "configured_not_verified", detail: "Configured." },
          {
            provider: "gmail",
            status: "configured_not_verified",
            detail: "Gmail inbox verification is configured; outreach remains disabled.",
          },
        ]}
      />,
    )

    // The prefilled app is selected in the catalog selector, so nobody has to
    // know or retype its exact name.
    expect(screen.getByRole("combobox", { name: "Application" })).toHaveTextContent("Pipedrive")
    expect(screen.getByRole("textbox", { name: "Company name" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Company website" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "What will this integration do?" })).toBeInTheDocument()
    expect(screen.getByRole("radio", { name: /playwright/i })).toBeChecked()

    await user.click(screen.getByText("Advanced settings"))
    const mode = screen.getByRole("combobox", { name: "Run mode" })
    expect(mode).toHaveTextContent("Run the agent")
    expect(screen.getByText("Runs approved live browser and provider actions.")).toBeInTheDocument()
    expect(screen.getByRole("combobox", { name: "Credential handling" })).toHaveTextContent(
      "Use existing, or create if missing",
    )
    expect(screen.getByText(/vault destination is created automatically/i)).toBeInTheDocument()
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

    const browserGroup = screen.getByRole("group", { name: "Browser engine" })
    const radios = within(browserGroup).getAllByRole("radio")
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

  it("disables account creation until the connected signup inbox is ready", () => {
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "ready", detail: "Ready." },
        ]}
      />,
    )

    expect(screen.getByRole("radio", { name: /create a new account/i })).toBeDisabled()
    expect(screen.getByText("Signup email readiness could not be verified.")).toBeInTheDocument()
  })

  it("enables account creation only with a reviewed signup route and ready Gmail", async () => {
    const user = userEvent.setup()
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "ready", detail: "Ready." },
          {
            provider: "gmail",
            status: "ready",
            detail: "A fresh read-only signup inbox preflight passed.",
          },
        ]}
      />,
    )

    const createAccount = screen.getByRole("radio", { name: /create a new account/i })
    expect(createAccount).toBeEnabled()
    await user.click(createAccount)
    expect(screen.getByText("Connected signup inbox ready")).toBeInTheDocument()
  })

  it("keeps account creation disabled when Gmail is configured but not verified", () => {
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "ready", detail: "Ready." },
          {
            provider: "gmail",
            status: "configured_not_verified",
            detail: "Signup inbox access has not passed a fresh read-only preflight.",
          },
        ]}
      />,
    )

    expect(screen.getByRole("radio", { name: /create a new account/i })).toBeDisabled()
    expect(
      screen.getByText("Signup inbox access has not passed a fresh read-only preflight."),
    ).toBeInTheDocument()
  })

  it("disables account creation when the selected app lacks a reviewed signup route", () => {
    appMocks.useAppCapabilities.mockReturnValue({
      data: {
        app_slug: "pipedrive",
        account_creation_supported: false,
        reason_code: "signup_route_unavailable",
      },
      isPending: false,
      isError: false,
    })

    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "ready", detail: "Ready." },
          {
            provider: "gmail",
            status: "ready",
            detail: "A fresh read-only signup inbox preflight passed.",
          },
        ]}
      />,
    )

    expect(screen.getByRole("radio", { name: /create a new account/i })).toBeDisabled()
    expect(
      screen.getByText("Pipedrive does not have a reviewed signup route in this deployment."),
    ).toBeInTheDocument()
  })

  it("clears a one-time login password after the action receives FormData", async () => {
    const user = userEvent.setup()
    actionMocks.createRunAction.mockResolvedValue({
      error: "Provider is temporarily unavailable.",
      fields: [],
      idempotencyKey: null,
      requestFingerprint: null,
    })
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "ready", detail: "Ready." },
          { provider: "gmail", status: "ready", detail: "Ready." },
        ]}
      />,
    )

    await user.type(screen.getByRole("textbox", { name: "Company name" }), "Example Labs")
    await user.type(
      screen.getByRole("textbox", { name: "Company website" }),
      "https://example.com",
    )
    await user.type(
      screen.getByRole("textbox", { name: "What will this integration do?" }),
      "Synchronize approved customer records.",
    )
    await user.type(
      screen.getByRole("textbox", { name: "Account email or username" }),
      "operator@example.com",
    )
    const password = screen.getByLabelText("Account password")
    await user.type(password, "temporary browser password")

    await user.click(screen.getByRole("button", { name: /start agent/i }))

    await waitFor(() => expect(actionMocks.createRunAction).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(password).toHaveValue(""))
  })

  it("opens advanced settings and focuses a server-rejected hidden field", async () => {
    const user = userEvent.setup()
    actionMocks.createRunAction.mockResolvedValue({
      error: "Review the marked fields. No run was created.",
      fields: ["callback_urls"],
      idempotencyKey: null,
      requestFingerprint: null,
    })
    render(
      <NewRunForm
        defaultAppName="Pipedrive"
        providerStates={[
          { provider: "playwright", status: "ready", detail: "Ready." },
          { provider: "gmail", status: "ready", detail: "Ready." },
        ]}
      />,
    )

    await user.type(screen.getByRole("textbox", { name: "Company name" }), "Example Labs")
    await user.type(
      screen.getByRole("textbox", { name: "Company website" }),
      "https://example.com",
    )
    await user.type(
      screen.getByRole("textbox", { name: "What will this integration do?" }),
      "Synchronize approved customer records.",
    )
    await user.click(screen.getByRole("button", { name: /start agent/i }))

    const details = screen.getByText("Advanced settings").closest("details")
    await waitFor(() => expect(details).toHaveAttribute("open"))
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: "OAuth callback URLs" })).toHaveFocus(),
    )
  })
})
