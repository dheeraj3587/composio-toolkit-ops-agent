import { render, screen } from "@testing-library/react"

import { NewRunForm } from "@/components/new-run-form"

vi.mock("@/app/runs/new/actions", () => ({
  createRunAction: vi.fn(),
}))

describe("NewRunForm", () => {
  it("shows the required company fields and makes plan-only behavior explicit", () => {
    render(<NewRunForm defaultAppName="Pipedrive" />)

    expect(screen.getByRole("textbox", { name: "Application name" })).toHaveValue("Pipedrive")
    expect(screen.getByRole("textbox", { name: "Legal name" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Company website" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Integration use case" })).toBeInTheDocument()

    const mode = screen.getByRole("combobox", { name: "Execution mode" })
    expect(mode).toHaveTextContent("Plan only")
    expect(screen.getByText(/browser, email, hitl, validation, and other external actions are not attempted/i)).toBeInTheDocument()
    expect(screen.getByText(/choose execute when configured to request an approved live path/i)).toBeInTheDocument()
  })
})
