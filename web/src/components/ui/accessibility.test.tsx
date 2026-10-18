/**
 * Accessibility edits made to the vendored shadcn primitives: the focus ring on a highlighted
 * menu or list item, the 2 px ring of buttons, inputs and select triggers, the 44 px dialog
 * close target, and the labelled scroll region of `Table`.
 *
 * Nothing is mocked. jsdom has no layout and computes no CSS, so each rule is pinned as the
 * Tailwind classes that implement it; the numbers behind them (the item fill is 1.10:1 in the
 * light theme and 1.37:1 in the dark one, a 2 px ring is 20:1 and 13.5:1) came from a real
 * browser run, not from here. The ring is a `ring`, never an `outline`: with `outline-none`
 * on the item, Tailwind v4 ignores a later `outline-2`.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";

const RING = [
  "data-[highlighted]:ring-2",
  "data-[highlighted]:ring-ring",
  "data-[highlighted]:ring-inset",
];

describe("highlighted menu items", () => {
  it("get a 2 px ring on every kind of dropdown item, not just a fill", () => {
    render(
      <DropdownMenu open>
        <DropdownMenuTrigger>Open</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Plain</DropdownMenuItem>
          <DropdownMenuCheckboxItem checked>Checkbox</DropdownMenuCheckboxItem>
          <DropdownMenuRadioGroup value="a">
            <DropdownMenuRadioItem value="a">Radio</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>Sub</DropdownMenuSubTrigger>
          </DropdownMenuSub>
        </DropdownMenuContent>
      </DropdownMenu>,
    );
    expect(screen.getByRole("menuitem", { name: "Plain" })).toHaveClass(...RING);
    expect(screen.getByRole("menuitemcheckbox", { name: "Checkbox" })).toHaveClass(...RING);
    expect(screen.getByRole("menuitemradio", { name: "Radio" })).toHaveClass(...RING);
    expect(screen.getByRole("menuitem", { name: "Sub" })).toHaveClass(...RING);
  });

  it("get the same ring on a select option", () => {
    render(
      <Select open value="a">
        <SelectTrigger aria-label="Pick" />
        <SelectContent>
          <SelectItem value="a">Alpha</SelectItem>
        </SelectContent>
      </Select>,
    );
    expect(screen.getByRole("option", { name: "Alpha" })).toHaveClass(...RING);
  });
});

describe("focus ring of the controls", () => {
  it("is 2 px on buttons, inputs and select triggers", () => {
    render(
      <>
        <Button>Go</Button>
        <Input aria-label="Name" />
        <Select value="a">
          <SelectTrigger aria-label="Pick" />
        </Select>
      </>,
    );
    expect(screen.getByRole("button", { name: "Go" })).toHaveClass("focus-visible:ring-2");
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveClass("focus-visible:ring-2");
    expect(screen.getByRole("combobox", { name: "Pick" })).toHaveClass("focus:ring-2");
  });
});

describe("dialog close button", () => {
  it("has a 44 px target (16 px icon + 14 px padding each side) without moving the icon", () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>,
    );
    expect(screen.getByRole("button", { name: "Close" })).toHaveClass("p-3.5", "-m-3.5");
  });
});

describe("Table", () => {
  it("is a labelled, focusable region only when it is given a label", () => {
    const { rerender } = render(
      <Table label="Scans">
        <TableBody>
          <TableRow>
            <TableCell>one</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    );
    const region = screen.getByRole("region", { name: "Scans" });
    expect(region).toHaveAttribute("tabindex", "0");
    expect(region).toHaveClass("overflow-auto");

    rerender(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>one</TableCell>
          </TableRow>
        </TableBody>
      </Table>,
    );
    expect(screen.queryByRole("region")).not.toBeInTheDocument();
  });

  it("takes the border from the one scroll container, so there is no second scroller", () => {
    render(
      <Table label="Scans" containerClassName="rounded-md border">
        <TableBody />
      </Table>,
    );
    expect(screen.getByRole("region", { name: "Scans" })).toHaveClass("rounded-md", "border");
  });
});
