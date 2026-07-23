import { render, screen } from "@testing-library/react"

import { NewRunForm } from "@/components/new-run-form"

vi.mock("@/app/runs/new/actions", () => ({
  createRunAction: vi.fn(),
}))

describe("NewRunForm", () => {
  it("shows the required company fields and defaults execution to plan only", () => {
    render(<NewRunForm defaultAppName="Linear" />)

    expect(screen.getByRole("textbox", { name: "Application name" })).toHaveValue("Linear")
    expect(screen.getByRole("textbox", { name: "Legal name" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Company website" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Integration use case" })).toBeInTheDocument()

    const mode = screen.getByRole("combobox", { name: "Execution mode" })
    expect(mode).toHaveTextContent("Plan only")
    expect(screen.getByText(/no provider side effects/i)).toBeInTheDocument()
  })
})
