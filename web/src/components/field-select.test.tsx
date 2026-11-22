/**
 * `FieldSelect`: every page test swaps it for a native `<select>`, so this is where the real
 * Radix select runs: its name, the value it shows, and a choice made with the keyboard.
 */
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { FieldSelect } from "@/components/field-select";

const options = [
  { value: "host", label: "This host only" },
  { value: "subdomains", label: "Host + subdomains" },
];

describe("FieldSelect", () => {
  it("is named by its label and shows the label of the chosen value", () => {
    render(
      <FieldSelect label="Scope" value="subdomains" onValueChange={vi.fn()} options={options} />,
    );
    expect(screen.getByRole("combobox", { name: "Scope" })).toHaveTextContent("Host + subdomains");
  });

  it("hands the value, not the label, to onValueChange", async () => {
    const user = userEvent.setup();
    const onValueChange = vi.fn();
    render(
      <FieldSelect label="Scope" value="host" onValueChange={onValueChange} options={options} />,
    );
    screen.getByRole("combobox", { name: "Scope" }).focus();
    await user.keyboard("{Enter}");
    await user.click(await screen.findByRole("option", { name: "Host + subdomains" }));
    expect(onValueChange).toHaveBeenCalledWith("subdomains");
  });

  it("passes the id on, so a <label for> outside can point at it", () => {
    render(
      <FieldSelect
        id="scan-scope"
        label="Scope"
        value="host"
        onValueChange={vi.fn()}
        options={options}
      />,
    );
    expect(screen.getByRole("combobox", { name: "Scope" })).toHaveAttribute("id", "scan-scope");
  });
});
