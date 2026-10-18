/**
 * `SubmitButton`: while a request is pending it is `aria-disabled` (so it keeps the keyboard
 * focus) and it swallows the click, so the form is not submitted twice.
 *
 * Nothing is mocked; the form's `onSubmit` is a spy.
 */
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SubmitButton } from "@/components/submit-button";

function renderForm(isPending: boolean) {
  const onSubmit = vi.fn((event: React.FormEvent) => event.preventDefault());
  render(
    <form onSubmit={onSubmit}>
      <SubmitButton isPending={isPending}>Save</SubmitButton>
    </form>,
  );
  return { onSubmit, button: screen.getByRole("button", { name: "Save" }) };
}

describe("SubmitButton", () => {
  it("submits the form when idle", async () => {
    const { onSubmit, button } = renderForm(false);
    await userEvent.setup().click(button);
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(button).not.toHaveAttribute("aria-disabled");
  });

  it("stays focusable and enabled while pending, but does not submit", async () => {
    const user = userEvent.setup();
    const { onSubmit, button } = renderForm(true);

    await user.click(button);
    button.focus();
    await user.keyboard("{Enter}");

    expect(button).not.toBeDisabled();
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).toHaveFocus();
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
