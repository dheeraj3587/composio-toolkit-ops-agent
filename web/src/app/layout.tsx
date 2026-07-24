import type { Metadata, Viewport } from "next"
import localFont from "next/font/local"
import { JetBrains_Mono } from "next/font/google"

import { AppShell } from "@/components/app-shell"
import { DemoBanner } from "@/components/demo-banner"
import { Providers } from "@/components/providers"

import "./globals.css"

const diatype = localFont({
  variable: "--font-abc-diatype",
  display: "swap",
  fallback: ["Arial", "sans-serif"],
  src: [
    {
      path: "./fonts/ABCDiatype-Regular.woff2",
      weight: "400",
      style: "normal",
    },
    {
      path: "./fonts/ABCDiatype-Medium.woff2",
      weight: "500",
      style: "normal",
    },
  ],
})

const jetBrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
})

export const metadata: Metadata = {
  title: {
    default: "Composio Operations",
    template: "%s · Composio Operations",
  },
  description: "A secure operations control plane for toolkit access and credential delivery.",
  robots: { index: false, follow: false },
}

export const viewport: Viewport = {
  colorScheme: "light",
  themeColor: "#0f0f0f",
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const demoMode = process.env.OPS_DEMO_MODE === "true"

  return (
    <html lang="en" className={`${diatype.variable} ${jetBrainsMono.variable}`} suppressHydrationWarning>
      {/* suppressHydrationWarning: browser extensions (password managers, etc.)
          inject attributes like bis_register/__processed_* onto <body> before
          React hydrates. This suppresses that one-level attribute mismatch; it
          does not mask mismatches in our own rendered content. */}
      <body suppressHydrationWarning>
        <Providers>
          <DemoBanner enabled={demoMode} />
          <AppShell demoMode={demoMode}>{children}</AppShell>
        </Providers>
      </body>
    </html>
  )
}
