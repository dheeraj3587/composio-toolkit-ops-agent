import { readFileSync, readdirSync, statSync } from "node:fs"
import { join } from "node:path"

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry)
    return statSync(path).isDirectory() ? sourceFiles(path) : /\.(ts|tsx)$/.test(path) ? [path] : []
  })
}

describe("frontend source boundary", () => {
  it("does not use persistent browser storage or raw HTML injection", () => {
    const productionFiles = sourceFiles(join(process.cwd(), "src")).filter((path) => !path.endsWith(".test.ts") && !path.endsWith(".test.tsx"))
    const source = productionFiles.map((path) => readFileSync(path, "utf8")).join("\n")

    expect(source).not.toMatch(/\b(?:localStorage|sessionStorage)\b/)
    expect(source).not.toContain("dangerouslySetInnerHTML")
  })
})
