import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Logo } from "@/components/logo";

describe("Logo", () => {
  it("draws one decorative path in the colour of the text", () => {
    const { container } = render(<Logo className="text-primary h-5 w-auto" />);
    const svg = container.querySelector("svg");

    expect(svg).toHaveAttribute("aria-hidden", "true");
    expect(svg).toHaveAttribute("fill", "currentColor");
    expect(svg).toHaveClass("text-primary", "h-5", "w-auto");
    expect(svg?.querySelectorAll("path")).toHaveLength(1);
    expect(svg?.querySelector("path")).toHaveAttribute("fill-rule", "evenodd");
  });
});
