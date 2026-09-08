/**
 * Test render helpers: a `QueryClient` with retries and caching off, a provider wrapper,
 * and `renderWithClient` that combines them and hands the client back for assertions.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";

export function makeTestClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
}

export function withClient(client: QueryClient) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  };
}

export function renderWithClient(ui: ReactElement, client: QueryClient = makeTestClient()) {
  return { client, ...render(ui, { wrapper: withClient(client) }) };
}
