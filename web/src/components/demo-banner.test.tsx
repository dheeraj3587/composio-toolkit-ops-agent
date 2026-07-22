import { render, screen } from "@testing-library/react"

import { DemoBanner } from "@/components/demo-banner"

describe("DemoBanner", () => {
  it("does not render outside explicit demo mode", () => {
    render(<DemoBanner enabled={false} />)
    expect(screen.queryByText(/demo mode/i)).not.toBeInTheDocument()
  })

  it("permanently labels fixture-backed demo mode", () => {
    render(<DemoBanner enabled />)
    expect(screen.getByRole("status")).toHaveTextContent(/fixture-backed states/i)
  })
})
