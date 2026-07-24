import { render, screen } from "@testing-library/react"

import { NewRunForm } from "@/components/new-run-form"

vi.mock("@/app/runs/new/actions", () => ({
  createRunAction: vi.fn(),
}))

describe("NewRunForm", () => {
  it("shows the required company fields and makes execute-mode boundaries explicit", () => {
    render(<NewRunForm defaultAppName="Pipedrive" />)

    expect(screen.getByRole("textbox", { name: "Application name" })).toHaveValue("Pipedrive")
    expect(screen.getByRole("textbox", { name: "Legal name" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Company website" })).toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Integration use case" })).toBeInTheDocument()

    const mode = screen.getByRole("combobox", { name: "Execution mode" })
    expect(mode).toHaveTextContent("Execute when configured")
    expect(screen.getByText(/may perform approved provider actions only when backend policy/i)).toBeInTheDocument()
    expect(screen.getByText(/execution can proceed only when backend policy and provider configuration permit each action/i)).toBeInTheDocument()
  })
})
