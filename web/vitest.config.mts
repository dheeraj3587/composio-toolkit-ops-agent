import react from "@vitejs/plugin-react"
import tsconfigPaths from "vite-tsconfig-paths"
import { defineConfig } from "vitest/config"

export default defineConfig({
  plugins: [tsconfigPaths(), react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    clearMocks: true,
    // jsdom environment startup for the heavier form/panel components can exceed
    // the 5s default under full-suite parallel load, so allow more headroom.
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
})
