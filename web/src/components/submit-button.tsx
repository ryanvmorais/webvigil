/**
 * The submit button of a form. While the request is in flight it is `aria-disabled`, not
 * `disabled`: a `disabled` button that held the focus hands it to `<body>`, and a keyboard user
 * has to Tab in from the top of the page after an error. `aria-disabled` keeps the focus, and
 * the click handler swallows the submit (implicit submission with Enter clicks this button too).
 */
import { Button, type ButtonProps } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function SubmitButton({
  isPending,
  className,
  onClick,
  ...props
}: Omit<ButtonProps, "type" | "asChild"> & { isPending: boolean }) {
  return (
    <Button
      type="submit"
      aria-disabled={isPending || undefined}
      className={cn("aria-disabled:pointer-events-none aria-disabled:opacity-50", className)}
      onClick={(event) => {
        if (isPending) event.preventDefault();
        else onClick?.(event);
      }}
      {...props}
    />
  );
}
