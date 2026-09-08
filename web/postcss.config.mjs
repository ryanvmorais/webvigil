/**
 * @file PostCSS configuration for the web UI.
 *
 * Next picks this file up automatically and runs it over every stylesheet.
 * Tailwind is the only pass we need: it expands the `@tailwind` directives in
 * `src/app/globals.css` into generated utility classes at build time.
 */

/** @type {import('postcss-load-config').Config} */
const config = {
  plugins: {
    tailwindcss: {},
  },
};

export default config;
