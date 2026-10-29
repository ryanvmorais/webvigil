/**
 * The WebVigil logo: a browser window with an open eye, drawn as one filled path
 * (`evenodd`) in the colour of the text around it.
 *
 * The same path is `assets/webvigil-web-vulnerability-scanner-logo.svg` (the README), the
 * app icon (`app/icon.svg`) and the HTML report; `tests/unit/test_logo_assets.py` keeps the
 * four equal. The drawing is cropped to the window, so a height sets the size.
 */

// The window, the title-bar line and the eye are holes; the pupil is the island inside the eye.
const PATH =
  "M12 8H52A9 9 0 0 1 61 17V47A9 9 0 0 1 52 56H12A9 9 0 0 1 3 47V17A9 9 0 0 1 12 8Z" +
  "M8 20.5H56A2 2 0 0 1 56 24.5H8A2 2 0 0 1 8 20.5Z" +
  "M15 40Q32 28 49 40Q32 52 15 40Z" +
  "M27.4 40a4.6 4.6 0 1 0 9.2 0a4.6 4.6 0 1 0-9.2 0Z";

type LogoProps = { className?: string };

/**
 * Decorative: the name of the product is written beside it, so it is hidden from screen readers.
 *
 * @example
 * <Logo className="text-primary h-5 w-auto" />
 */
export function Logo({ className }: LogoProps) {
  return (
    <svg
      viewBox="3 8 58 48"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
      className={className}
    >
      <path fillRule="evenodd" d={PATH} />
    </svg>
  );
}
