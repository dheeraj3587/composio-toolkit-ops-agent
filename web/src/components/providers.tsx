"use client"

import { useState } from "react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { Toaster } from "sonner"

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            gcTime: 5 * 60 * 1_000,
            retry: 1,
            staleTime: 20_000,
            refetchOnWindowFocus: false,
          },
          mutations: { retry: false },
        },
      }),
  )

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <Toaster
        position="top-right"
        theme="dark"
        visibleToasts={3}
        duration={5_000}
        gap={8}
        closeButton
        toastOptions={{ className: "ops-toast font-sans text-sm" }}
      />
    </QueryClientProvider>
  )
}
