# Web UI design reference

The visual language of the dashboard in `web/`: where the design tokens live, the severity
scale, and the one accessibility rule that shapes every badge. This is a reference — for
running the dashboard see [web-ui.md](web-ui.md), and for why Tailwind and shadcn/ui were
chosen see [stack.md](stack.md).

The UI has no component catalogue (no Storybook, no static style guide) on purpose: the
components are React, so a copy would drift from the code. The code and `globals.css` are
the source of truth; this page maps them.

## Where things live

| What | Where |
|---|---|
| Design tokens, theme mapping, base reset | `web/src/app/globals.css` |
| Severity names, labels, colour classes | `web/src/lib/severity.ts` |
| App icon (the header's shield, light and dark; Next serves it as the favicon) | `web/src/app/icon.svg` |
| Vendored shadcn/ui primitives | `web/src/components/ui/` |
| Domain components (badges, tables, forms) | `web/src/components/` |
| Class merging helper (`cn`) | `web/src/lib/utils.ts` |
| shadcn CLI configuration | `web/components.json` |

## Design tokens

Every token is a bare HSL channel triple (`H S% L%`) on `:root`, consumed as
`hsl(var(--token))` through an `@theme inline` block. That is what makes utilities such as
`bg-background` or `text-severity-high` resolve to the token. `inline` matters: the
`prefers-color-scheme` override still applies at the point of use.

The semantic set is the shadcn "slate" palette:

| Token | Light | Dark | Used for |
|---|---|---|---|
| `--background` | `0 0% 100%` | `222.2 84% 4.9%` | Page background |
| `--foreground` | `222.2 84% 4.9%` | `210 40% 98%` | Body text |
| `--primary` | `222.2 47.4% 11.2%` | `210 40% 98%` | Primary button, default badge |
| `--secondary`, `--muted`, `--accent` | `210 40% 96.1%` | `217.2 32.6% 17.5%` | Subtle surfaces |
| `--muted-foreground` | `215.4 16.3% 46.9%` | `215 20.2% 65.1%` | Secondary text |
| `--destructive` | `0 72.2% 50.6%` | `0 62.8% 30.6%` | Destructive actions |
| `--success` | `163 100% 24%` | `160 84% 45%` | Positive state text ("Completed", "Password changed") |
| `--border`, `--input` | `214.3 31.8% 91.4%` | `217.2 32.6% 17.5%` | Borders and field outlines |
| `--ring` | `222.2 84% 4.9%` | `212.7 26.8% 83.9%` | Focus ring |

`--card` and `--popover` follow `--background`; each `*-foreground` pairs with its surface.
The full list is in `globals.css`.

**Radius.** One base value, `--radius: 0.5rem`, with `lg` equal to the base, `md` two pixels
smaller and `sm` four pixels smaller.

**Typography.** A system font stack only (`ui-sans-serif`, `system-ui`, `Segoe UI`,
`Roboto`, …). The UI ships no web font, so there is no external request and no layout shift
on load.

**Layout width.** Content is centred with `mx-auto w-full max-w-[1200px] px-6` (header,
the mobile logout row, main). Tailwind v4's `container` utility is not configurable that way, so the
shell uses the explicit classes instead.

**Dark mode.** The theme follows the operating system through
`@media (prefers-color-scheme: dark)`. There is no `.dark` class and no toggle (spec 003,
RF-02 and ADR-8). The trade-off is that users cannot override the OS preference.

## Severity scale

Five tokens, one hue per level, with names and order mirroring the engine's `Severity` enum.
Lightness rises in the dark set so the colours keep their contrast on a dark background.

| Level | Token | Light | Dark | Hue |
|---|---|---|---|---|
| `INFO` | `--severity-info` | `215.4 16.3% 46.9%` | `215 20.2% 65.1%` | slate grey |
| `LOW` | `--severity-low` | `199 89% 35%` | `199 89% 60%` | sky blue |
| `MEDIUM` | `--severity-medium` | `38 92% 31%` | `38 92% 60%` | amber |
| `HIGH` | `--severity-high` | `24 95% 37%` | `24 95% 63%` | orange |
| `CRITICAL` | `--severity-critical` | `0 72.2% 50.6%` | `0 72% 60%` | red |

These colours are badge *text*, so every level has to reach the WCAG AA ratio of 4.5:1, on
the page background and on the muted surface a table row takes on hover. In the light set
`LOW`, `MEDIUM` and `HIGH` sit at the lowest lightness that does, keeping the hue (the mid-tone
values they had before measured 2.1 to 2.9:1). `globals.test.ts` computes the ratios from
`globals.css` for every text token in both themes, so a token change that breaks the floor
fails the unit suite.

`SEVERITY_CLASS` in `severity.ts` maps each level to its utility classes:
`border-severity-<level>/40 text-severity-<level>` (the border opacity is `/50` for
`CRITICAL`). `SEVERITY_DESC` lists the levels highest first — the order the API returns
findings in, which the UI never re-sorts.

## Colour is never the only signal

The accessibility baseline (spec 003, RNF-05) says colour must not be the only way a
severity or status is conveyed: an icon or a text label comes with it. Every badge applies
the rule:

| Component | Signal besides colour |
|---|---|
| `SeverityBadge` | A distinct icon per level (`Info`, `ShieldQuestion`, `ShieldAlert`, `AlertTriangle`, `AlertOctagon`) and the level name |
| `StatusBadge` | A distinct icon per status and the status name; `running` also spins |
| `ModeBadge` | The words "Active" / "Passive"; only "Active" takes the `severity-high` colour |
| `ConfidenceBadge` | Text only ("Low confidence" …), in `text-muted-foreground` |
| `SeveritySummary` | One chip per non-zero severity, highest first, with the count in words |

Icons come from `lucide-react` and are decorative (`aria-hidden`); the label carries the
meaning for assistive technology. Unknown values fall back to a neutral `Info` or the raw
string instead of throwing.

The rule is checked in two places: unit tests assert the label and the icon for each badge
(`badges.test.tsx`), and component-level axe checks (`web/src/test/a11y.test.tsx`, helper in
`web/src/test/axe.ts`) fail on serious or critical violations. The page-structure axe rules
are off there because a component render has no `<html>` or `<main>`; the layouts and the
Playwright run cover them.

## Primitives

`web/src/components/ui/` holds the vendored shadcn/ui components: `badge`, `button`,
`dialog`, `dropdown-menu`, `form`, `input`, `label`, `select`, `sonner`, `table` and
`tabs`. They use the `new-york` style on the `slate` base colour, CSS variables for theming
and `lucide` for icons (`components.json`). The behaviour comes from Radix UI; the look comes
from the tokens above.

- **Variants** are declared with `class-variance-authority`. `Button` has the variants
  `default`, `destructive`, `outline`, `secondary`, `ghost` and `link`, and the sizes
  `default`, `sm`, `lg` and `icon`. `Badge` has `default`, `secondary`, `destructive` and
  `outline`; the severity, status and mode badges all use `outline` plus colour classes.
- **Class merging** goes through `cn()` (`clsx` + `tailwind-merge`), so a caller's
  `className` overrides a variant's classes predictably.
- **They are vendored**, not a dependency: the source is copied into the repo and owned
  here. New ones are added with `pnpm dlx shadcn@latest add <name>` from `web/`.

## Where a new colour has to be declared

A new colour token exists in three places in `globals.css`: the light value on `:root`, the
dark value inside the `prefers-color-scheme` block, and the `--color-*` mapping in
`@theme inline`. Components then use it through a utility (`bg-<name>`, `text-<name>`);
a raw Tailwind colour such as `emerald-600` bypasses the dark set.
