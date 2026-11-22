/**
 * `DisabledChecksField` (RF-19), held by a small controlled wrapper as the form holds it. The
 * catalogue comes from MSW.
 */
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { DisabledChecksField } from "@/components/disabled-checks-field";
import { makeCheck } from "@/test/fixtures";
import { server } from "@/test/msw/server";
import { renderWithClient } from "@/test/render";

/** The field is controlled; this holds its value the way the form does, and reports each change. */
function Controlled({
  initial = [],
  onChange,
}: {
  initial?: string[];
  onChange: (v: string[]) => void;
}) {
  const [value, setValue] = useState(initial);
  return (
    <DisabledChecksField
      value={value}
      onChange={(next) => {
        setValue(next);
        onChange(next);
      }}
    />
  );
}

const catalogue = [
  makeCheck({ id: "headers.csp", name: "CSP" }),
  makeCheck({ id: "tls.version", name: "TLS version" }),
];

describe("DisabledChecksField", () => {
  it("adds a check when ticked, removes it when unticked, and counts them on the button", async () => {
    server.use(http.get("*/api/checks", () => HttpResponse.json(catalogue)));
    const user = userEvent.setup();
    const onChange = vi.fn();
    renderWithClient(<Controlled initial={["headers.csp"]} onChange={onChange} />);

    await user.click(screen.getByRole("button", { name: "Disabled checks (1)" }));
    const csp = await screen.findByRole("checkbox", { name: /headers\.csp/ });
    expect(csp).toBeChecked();

    await user.click(screen.getByRole("checkbox", { name: /tls\.version/ }));
    expect(onChange).toHaveBeenLastCalledWith(["headers.csp", "tls.version"]);
    expect(screen.getByRole("button", { name: "Disabled checks (2)" })).toBeInTheDocument();

    await user.click(csp);
    expect(onChange).toHaveBeenLastCalledWith(["tls.version"]);
    await user.click(screen.getByRole("checkbox", { name: /tls\.version/ }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    expect(screen.getByRole("button", { name: "Disabled checks" })).toBeInTheDocument();
  });

  it("stays closed until opened", async () => {
    server.use(http.get("*/api/checks", () => HttpResponse.json(catalogue)));
    renderWithClient(<Controlled onChange={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Disabled checks" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    // checked before the catalogue arrives too: the panel itself is not there
    expect(document.getElementById("disabled-checks-panel")).toBeNull();
  });

  it("says so while the catalogue loads, and when it cannot be loaded", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    server.use(
      http.get("*/api/checks", async () => {
        await gate;
        return HttpResponse.json({ detail: "boom" }, { status: 500 });
      }),
    );
    const user = userEvent.setup();
    renderWithClient(<Controlled onChange={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Disabled checks" }));

    expect(screen.getByText("Loading checks…")).toBeInTheDocument();
    expect(screen.queryByText("Could not load the check catalogue.")).not.toBeInTheDocument();
    release();
    expect(await screen.findByText("Could not load the check catalogue.")).toBeInTheDocument();
    expect(screen.queryByText("Loading checks…")).not.toBeInTheDocument();
  });
});
