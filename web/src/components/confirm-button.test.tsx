/**
 * `ConfirmButton`: the page tests replace it with a plain button, so this is where the dialog
 * itself runs: nothing happens until the visitor confirms. Nothing is mocked.
 */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ConfirmButton } from "@/components/confirm-button";

/** Render the button with a spy for `onConfirm`, which it returns. */
function renderButton(props: Partial<React.ComponentProps<typeof ConfirmButton>> = {}) {
  const onConfirm = vi.fn();
  render(
    <ConfirmButton
      label="Delete"
      title="Delete this scan?"
      description="The scan and its findings are removed permanently."
      confirmLabel="Delete scan"
      onConfirm={onConfirm}
      {...props}
    />,
  );
  return onConfirm;
}

describe("ConfirmButton", () => {
  it("asks first, and runs the action once on confirm", async () => {
    const user = userEvent.setup();
    const onConfirm = renderButton();

    await user.click(screen.getByRole("button", { name: "Delete" }));
    const dialog = screen.getByRole("dialog", { name: "Delete this scan?" });
    expect(dialog).toHaveAccessibleDescription(/removed permanently/);
    expect(onConfirm).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Delete scan" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("closes without running the action on Cancel", async () => {
    const user = userEvent.setup();
    const onConfirm = renderButton();

    await user.click(screen.getByRole("button", { name: "Delete" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("cannot be opened while disabled", async () => {
    const user = userEvent.setup();
    renderButton({ disabled: true });
    const trigger = screen.getByRole("button", { name: "Delete" });
    expect(trigger).toBeDisabled();
    await user.click(trigger);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("disables the confirm button while the action runs", async () => {
    const user = userEvent.setup();
    renderButton({ pending: true });
    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(screen.getByRole("button", { name: "Delete scan" })).toBeDisabled();
  });
});
