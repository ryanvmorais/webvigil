import { expect, test, vi } from "vitest";

const redirect = vi.fn();
vi.mock("next/navigation", () => ({
  redirect: (path: string) => redirect(path),
}));

test("the root route redirects to the scan list", async () => {
  const { default: RootPage } = await import("./page");
  RootPage();
  expect(redirect).toHaveBeenCalledWith("/scans");
});
