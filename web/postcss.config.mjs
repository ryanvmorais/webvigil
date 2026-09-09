/**
 * @file PostCSS configuration for the web UI.
 *
 * Next picks this file up automatically and runs it over every stylesheet.
 * Tailwind v4 ships its PostCSS integration as a separate plugin; it is the
 * only pass we need. It reads `@import "tailwindcss"` in `src/app/globals.css`
 * and generates the utility classes at build time.
 */

/** @type {import('postcss-load-config').Config} */
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
