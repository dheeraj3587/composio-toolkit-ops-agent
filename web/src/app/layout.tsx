import type { Metadata, Viewport } from "next"
import { Geist, Geist_Mono } from "next/font/google"

import { AppShell } from "@/components/app-shell"
import { DemoBanner } from "@/components/demo-banner"
import { Providers } from "@/components/providers"

import "./globals.css"

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
  display: "swap",
})

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
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
  themeColor: "#0b0b0e",
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const demoMode = process.env.OPS_DEMO_MODE === "true"

  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <body>
        <Providers>
          <DemoBanner enabled={demoMode} />
          <AppShell demoMode={demoMode}>{children}</AppShell>
        </Providers>
      </body>
    </html>
  )
}
