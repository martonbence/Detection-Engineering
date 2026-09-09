---
name: web-visual-system
description: Use when styling, redesigning, or adding to any generated HTML/CSS/JS page in this repo — the rule browser (docs/index.html, scripts/docs/assets/page.css) or the internal team-ops dashboard (.claude/generate_dashboard.py) — so new work matches the established visual language instead of re-deriving colors, spacing, or component patterns from scratch. Not a general design tutorial; every rule here is extracted from what this repo's own pages actually do, with file:line anchors.
---

This repo settled on its current look deliberately (user sign-off,
2026-09-07, after reviewing the rule browser as-is and choosing to keep it
rather than pick one of four drafted reskins) — the rule below captures
*that* system, not a hypothetical one. Anchors are file:line as of
2026-09-07 (`page.css`/`page.template.html`/`page.js` in
`scripts/docs/assets/`, `.claude/generate_dashboard.py`) — they drift over
time like any other line reference; search the selector/property name if a
cited line looks wrong.

Two generators produce two separate pages from this one visual language:
`scripts/docs/generate_stats.py` (the public rule browser, `docs/index.html`
— Sienna's) and `.claude/generate_dashboard.py` (the internal team-ops
dashboard, `.claude/team-ops.html` + `docs/team-ops.html` — also Sienna's).
As of 2026-09-07 their palettes, radii and font fallback are in sync
(commit `c622628`); a few *structural* differences remain and are
**intentional, not drift** — see "Where the two pages still differ" at the
end.

## Color

**The page background is not the legacy `--bg` token.** `page.css:8` still
declares `--bg: #0d1117` (GitHub-dark-theme era) and it's still read by a
few secondary surfaces (legend/drawer panels), but the actual `body`
background is set directly at `page.css:47-56`, labeled "PREVIEW v5" in a
comment: solid `#0f172a` navy, plus exactly two radial gradients (blue
top-left `rgba(64,116,244,.26)`, purple top-right `rgba(132,98,230,.30)`,
each fading to transparent by 70-72% of its radius). If you add a new
full-page surface, start from this recipe, not from `--bg`.

**"Glass panel" is the one recurring surface treatment** — the strip/filter
panel, chart cards, and the table wrapper all use a variant of the same
formula (`page.css:107-120`, `283-300`, `1234-1244`, `2320-2333`):
- fill: a dark, translucent `rgba(20-22,25-27,34,.45-.82)` (denser/more
  opaque where text needs to stay crisp, e.g. the data table at `.82`)
- `backdrop-filter: blur(8-16px) saturate(1.15-1.3)`
- a **bright** hairline border, `1px solid rgba(255,255,255,.10)` — not the
  `--border` token, which reads too dark against this background
- `box-shadow: inset 0 1px 0 rgba(255,255,255,.06-.08)` (inner top
  highlight) plus one soft outward shadow, never a hard-edged one

Why the fill alpha barely matters: `page.css:66-69` notes that on this dark
wash, a dark translucent fill only shifts the composited color by a few
points versus fully opaque — imperceptible. The "distinct floating surface"
read has to come from the edges (hairline + inset highlight), not from
fill transparency. Any new floating panel should follow the same logic
rather than reaching for a heavier/lighter fill to make it "pop."

**`#ffaa00` (solid amber) is the repo's actual primary brand/interactive
color** — stated outright at `page.css:1263-1264`. `--accent` (`#58a6ff`,
blue) is a secondary/informational accent (links, informational states),
not the primary. Every interactive control's hover/active state converges
on the same amber-plus-glow idiom: `border/color → #ffaa00` plus
`box-shadow: 0 0 0 2px rgba(255,170,0,.14)` — confirmed identical across
`.export-btn:hover` (`page.css:1008-1012`), `.tab-btn.active`
(`242-246`), and the table header (`1266-1272`, `1293-1295` — text flips to
pure black on hover since the header background is already solid amber).
**Default to amber for anything meant to read as "the brand," and reserve
blue for links/info states** — a new component defaulting to blue as "the
accent" is picking the wrong one.

**Semantic status colors (Pass / Fail / Not Verified / N/A / Lapsed) are
defined independently in three places and must be kept in sync by hand**
— there is no shared source of truth:
1. CSS badge fills: `page.css:1624-1665` (`.verdict-pass` etc.; the
   "lapsed/superseded" state is a dashed `rgba(188,140,255,.65)` outline,
   not a fill — the same "drift purple" also used on the Navigator's
   superseded markers)
2. JS hex maps: `page.js:42-43` (`SEV_HEX`/`STATUS_HEX`), `page.js:51`
   (`LEVEL_COLORS`) — deliberately matching the shields.io/quickchart hex
   codes in `generate_stats.py` byte-for-byte (comment at `page.js:46-48`)
   so the in-page charts and the README badges agree.
3. Badge/chart color args inside `generate_stats.py` itself (the
   shields.io URL builders, `~lines 113-132, 554-613`).

Adding a new verdict/status category means touching all three, not one —
this has been a real source of drift before.

**The contrast-fix pattern, when a color fails WCAG AA on a real composited
background: reuse a sibling hue already used elsewhere on the page, cite
one measured ratio in a comment — don't just brighten in isolation.**
Documented repeatedly: `page.css:14-25` (`--text2`/`--text3`, was
`#8b949e`/`#6e7681` at 4.03:1/3.02:1 on the glass-button surfaces, now
`#a2a9b1`/`#9a9fa7` at 5.22:1+), and the same pattern at `1508-1514`,
`1526-1533`, `1580-1586`, `1601-1611`. **Always measure against the actual
composited background the text sits on, not the nominal page background**
— a translucent surface changes the real contrast, and the two can differ
by more than a full AA-pass/fail step (confirmed directly in this repo:
team-ops' `--text-dim` measured 4.95:1 on its own *flat* hover background
where the same-era rule-browser color failed on a *translucent* one —
same hex, different verdict, because the two pages composite differently).
When porting a color between the rule browser and team-ops (or to any new
page), re-measure on the destination's own real surfaces rather than
copying the hex on the assumption "it passed before."

**Badges/pills are opaque fills, not translucent tints — load-bearing, not
a style preference.** `page.css:1462-1483` explains why: a translucent
badge sitting on a hovered/selected table row composites toward a washed
gray no foreground color can hit 4.5:1 against without destroying the
color-coding. The fix bakes each badge's fill as "that tint pre-composited
over the at-rest row," independent of whatever's actually behind it at
render time. Don't revert a badge to `rgba(...)` because it looks cleaner
in isolation — check it against the hover/selected row state, not just the
default one.

**Two independent categorical palettes exist and should stay
independent**: verdict/status colors (above) answer "did this rule pass,"
while team-ops' org-chart `TREE`/`AREA_COLORS`
(`.claude/generate_dashboard.py:103-110, 198-200` — purple/green/blue/
amber/teal per reporting group) answer "where does this person sit in the
hierarchy." Don't try to unify these into one semantic palette; they're
not the same kind of information.

**One dead reference, now removed:** a comment used to describe the MITRE
Coverage badge's purple (`#8f95d6`) as reused from "this repo's established
green→blue→purple→coral phase palette... see the mermaid classDefs... in
README.md" — that diagram was retired with `TEAM.md` on 2026-09-01 and no
longer exists anywhere in the repo (fixed in `generate_stats.py`,
commit `eee93e7`). `#8f95d6` itself is still real and still used exactly
where it was — just don't cite the retired diagram as its origin if you
see it mentioned in an older commit message or an agent's own memory of
this repo; the color survived, the four-phase framing it was described
under did not.

## Typography

Two system-font stacks, no webfont, defined at `page.css:41-42`:
- `--font` (mono: `SFMono-Regular, Consolas, 'Liberation Mono', Menlo,
  monospace`) — for anything code-like: rule/technique IDs, metadata
  values, every badge's text.
- `--font-ui` (sans: `-apple-system, BlinkMacSystemFont, 'Segoe UI',
  Helvetica, Arial, sans-serif`) — for every heading/title/label. Deliberately
  unified across the Rule Library, Navigator and Dashboards tabs
  (`page.css:90-104` names this explicitly) so headings read as one system
  regardless of which tab you're on. Team-ops' font stack was a near-miss
  (`Roboto` instead of `Helvetica, Arial` as the fallback) until it was
  synced to match, 2026-09-07 (commit `c622628`).

**There are no `<h1>`–`<h4>` elements anywhere in `page.template.html`.**
Every heading-like element is a styled `div`/`span` with a semantic class
name instead — don't introduce real heading tags expecting them to inherit
the existing type scale; they won't, and it'll look inconsistent.

**Big, bold numerals are reserved for one thing: a hero stat centered in a
donut/gauge** — `.gauge-pct` (34px/800, `page.css:2462`) and
`.verify-overlay-pct` (24px/800, `2587`), always in brand amber. Every
structural heading tops out at 14-15px. A new stat tile that wants a large
number should follow this pattern (gauge/donut + centered hero number), not
just render a big number as a plain heading.

**Section labels on the Dashboards tab are rendered as small solid-amber
pills, not as plain heading text** — `.dash-section-title`
(`page.css:2274-2286`): 12px/700, uppercase, `letter-spacing: .6px`,
`border-radius: 5px`, `padding: 3px 10px`, filled `#ffaa00`. A new
dashboard section should label itself the same way, not with a bare
`<div>` of bold text.

## Layout & spacing

No named spacing-token scale (no `--space-1` etc.) — spacing is hand-tuned
per component, mostly 4-20px, with `14px` recurring as the page-level unit
(`.main { gap: 14px; padding: 14px; }`). Two named radii only:
`--radius: 6px` (small controls) and `--radius-lg: 10px` (panels/cards),
`page.css:39-40` — team-ops' cards were `12px` until synced to `10px` to
match, 2026-09-07. Pills/tabs/badges use a separate literal `20px`
(fully-rounded), not either named radius.

Dashboard grids are bespoke per section, not one generic grid component —
`page.css:2288-2410` has four distinct `grid-template-columns` patterns,
each with an explicit comment on *why* `auto-fit` vs. fixed tracks was
chosen for that specific row (auto-fit collapses empty tracks and lets a
lone card stretch full-width, which is right in some rows and wrong in
others where the row should look like N equal-width cards regardless of
count). Read the comment for the row you're extending before copying its
grid pattern elsewhere — the choice was deliberate per-section, not
arbitrary.

Shadows are one consistent recipe everywhere something "floats": an inset
top highlight (`inset 0 1px 0 rgba(255,255,255,.06-.08)`) plus a soft,
diffuse outward shadow (`0 12px 30-34px -10/-14px rgba(0,0,0,.55-.6)`).
Never a hard/sharp-edged shadow anywhere in either page.

## Recurring components

**Badges/pills**: `inline-block`, `padding: 2px 7px`, `border-radius: 20px`,
`font-size: 10px/600`, **mono font** (badges are treated as code-like
tokens, not prose), `letter-spacing: .3px`. Pattern per variant: opaque
dark-tinted fill + bright hue text + `1px solid` border at ~.25-.4 alpha of
the same hue (`page.css:1484-1665`). `.badge-mitre` additionally needs
`min-height/width: 24px` + inline-flex centering to hit the 24×24 WCAG
touch-target minimum, since it's individually clickable.

**Cards** (`.chart-card`, `page.css:2320-2333`): same glass recipe as
above, `padding: 20px`, `--radius-lg`, flex column, `gap: 12px`. Two
"annotation strip" variants exist for sub-text that isn't just descriptive:
`.chart-card-sub-scope` (orange left border — "something's excluded from
this number, a caveat") and `.chart-card-sub-lastlive` (blue left border —
"informational context, not a caveat"), `page.css:2357-2373`. Reuse this
orange-vs-blue idiom for any new caveat-vs-info annotation rather than
inventing a new visual marker.

**Table** (`page.css:1234-1400`+): `table-layout: fixed` with explicit
per-column pixel widths; sticky header rendered **solid amber**, not
translucent (a comment at `1266-1272` notes a translucent header was tried
and deliberately reverted); zebra striping via `oklch(80% 0.03 300 / .16 |
.05)` — the one and only `oklch()` use in the file, not `rgba`; hover and
"row open in drawer" states share the exact same cream wash
(`rgba(245,242,235,.32)`) so they read as visually identical.

## Icons

One master illustration (`docs/pictures/branding/logo.png`, a shield),
every other image is a purpose-sized export/crop of it: favicons and the
header mark are pre-exported base64 data URIs baked into `docs/index.html`
(`generate_stats.py`, so the page stays one self-contained file);
`docs/pictures/branding/{rule_browser,mitre_navigator,dashboards}.png` are
`width="150"` in `README.md`, `architecture.png` is `125`, `team.png` is
`120`, the main logo is `200` (`README.md:1,23,27,31,42,53`). **The one
deliberate exception**: `social_preview.png` is a normal *linked* file, not
a data URI, and has a **solid** (not transparent) background at 1280×640 —
because link-preview scrapers (Slack/Twitter/LinkedIn/iMessage) fetch
OpenGraph images over plain HTTP and don't reliably render inline data
URIs or transparency, and the source shield art is square/transparent and
crops badly into a 2:1 card. If you regenerate this image, keep it a
linked file with a solid background — reverting either "for consistency"
with the other assets breaks link previews.

## Theme

No light mode, no `prefers-color-scheme`, no theme toggle anywhere in
either page — one fixed dark theme (`#0f172a` navy + two radial gradients),
by design. Frame this as "the page's one committed look," not as "dark
mode" — there's no light variant it's contrasted against, so don't add
theme-switching machinery expecting a light palette to already exist
somewhere; it doesn't.

## Where the two pages still differ (intentional, last checked 2026-09-07)

After the 2026-09-07 palette sync (colors/radii/font fallback, commit
`c622628`), team-ops and the rule browser still differ in ways that were
explicitly left alone rather than missed:

- **No glass-panel/backdrop-filter treatment in team-ops** — its cards are
  flat, opaque, `1px solid var(--border)` boxes. Bigger visual lift than a
  color sync; not undertaken.
- **Units**: rule browser CSS is ~100% `px`; team-ops CSS is ~100% `rem`.
  Different authoring convention, not a bug.
- **Org-chart categorical palette** (`TREE`/`AREA_COLORS`) is team-ops-only
  and answers a different question than verdict colors — see above, don't
  merge these.

Don't "fix" these reflexively as leftover drift — they were reviewed and
intentionally scoped out. If a future task wants to close this gap (e.g.
bring the glass-panel treatment to team-ops), that's a real, separate
design decision to raise with the user first, not a bug this skill implies
should just be finished.
