---
name: team-avatars
description: Use when generating a profile-picture prompt for a Detection-Engineering team member (TEAM.md roster) — Bjorn's portrait is the locked reference; every other member reuses its style and camera/pose blocks unchanged and only swaps the per-person description block.
---

Produces the AI-image-generation prompt text for one team member's avatar.
This skill does not call an image model itself (none is wired into this
project) — it produces the prompt text the user pastes into whatever
generator they're using (Canva Magic Media, Midjourney, DALL-E, etc.), and
records where the resulting file goes once it's generated.

## The locked reference prompt (Bjorn)

Bjorn — Detection Quality Engineer — was the first one generated and fixes
two blocks that must carry over **unchanged, word-for-word**, to every other
team member's prompt:

```
16-bit pixel art character portrait bust, rendered in a clean vector-art style
(scalable flat vector shapes, crisp geometric edges, no raster noise or texture
grain), in the style of a SNES/Genesis-era JRPG character-select screen.
[[PER-PERSON DESCRIPTION BLOCK — see below]]
Flat solid [[PER-PERSON BACKGROUND COLOR + MOOD]] background, no gradient.
Waist-up framing, square canvas, crisp pixel-perfect edges, no anti-aliasing blur.
Target output: 1254x1254 px square canvas — match the pixelation density of a
~64x64 sprite grid scaled up with hard edges (consistent chunkiness across the
whole team roster, not finer/smoother and not blockier).

CAMERA/POSE LOCK (reuse identically for all characters):
Three-quarter view portrait, head turned approximately 15-20 degrees to the
viewer's left, eyes looking directly into the camera regardless of head angle,
direct steady eye contact with the viewer, shoulders angled slightly toward the
front (less rotated than the head), centered composition, subject occupies roughly
the middle 70% of frame width, waist-up crop with equal headroom above hair,
square 1:1 canvas, camera at eye level, no tilt.
```

Bjorn's full per-person block, as generated (kept here as the worked example):

```
Scandinavian man in his late 30s, sharp jawline read through blocky pixel shading,
long blond pixel hair tied back into a topknot/bun, a few loose strands framing the
face, long braided blond beard with natural loose texture (not stiff or rigid),
soft downward drape and gentle sway to the braid, a few stray beard strands
escaping the braid similar to the loose hair strands, 2-3 silver Norse-style beard
rings/beads woven into the braid, pale blue-grey pixel eyes, fair skin tone
rendered in a limited palette with visible dithering, calm and slightly skeptical
expression. Wearing a charcoal knit crewneck sweater, clean minimal Scandinavian
styling, bold 1px dark outline around the silhouette.
```
Background used for Bjorn: flat solid frosty glacier-blue-grey (cold Nordic fjord tone).

## What to change per team member, what never changes

**Never changes** (copy verbatim every time):
- The opening style sentence ("16-bit pixel art character portrait bust,
  rendered in a clean vector-art style…").
- The `Waist-up framing, square canvas, crisp pixel-perfect edges, no
  anti-aliasing blur.` line.
- The `Target output: 1254x1254 px…` resolution/pixelation-density line —
  added after confirming Bjorn.jpg, Yuki.png and Kwame.png all render at
  exactly 1254x1254 px despite never having been asked for a size; stating
  it explicitly keeps that consistent across generators/sessions instead of
  relying on a platform default that could silently change.
- The entire `CAMERA/POSE LOCK` block.

**Changes per person** — derive from that member's row in `TEAM.md` and
`CLAUDE.md`, not invented freely:
- **Nationality/ethnicity + physical traits** (hair, eyes, skin tone, build,
  facial structure) — reflect it honestly in the description, the same way
  Bjorn's Nordic features and Norse beard-braid details were drawn from
  "Scandinavian, characterful." **This is a decision for the user to make
  per person, not one to assume** — confirm nationality/look before writing
  the block, the same way Bjorn's was confirmed in conversation before
  drafting.
- **Expression** — should read from the role's real function (Bjorn's
  "calm and slightly skeptical" comes from him being the quality
  gatekeeper who never self-approves a rule — see his `TEAM.md` bio).
- **Clothing** — professional, minimal, culturally consistent with the
  chosen nationality; vary silhouette/color per person so the 11 avatars
  don't look like reskins of each other.
- **Background color** — flat solid color, no gradient, thematically tied
  to the person (Bjorn got a cold Nordic fjord tone); pick a distinct hue
  per person so the roster reads as a set, not duplicates.

## Where the finished image goes

No avatar directory existed before Bjorn's; the agreed location is next to
the agent persona files themselves:

```
.claude/agents/avatars/<firstname-lowercase>.png
```

e.g. `.claude/agents/avatars/bjorn.png`. Once a file lands there, wire it
into that person's `*Avatar: pending*` line in `TEAM.md` (repo root) as a
relative image link: `![Bjorn](.claude/agents/avatars/bjorn.png)`.

## Where the prompt text goes

Since this skill only produces prompt text (no image model is wired in —
see top), each finished prompt is saved as its own file next to where the
eventual image will land, so the two stay paired and the prompt is
reproducible later without re-deriving it from a conversation:

```
.claude/agents/avatars/prompts/<firstname-lowercase>.txt
```

## Background colors used so far (keep each new one distinct)

Pick a flat solid hue, no gradient, thematically tied to the person, and
different enough from every row below to read as a set rather than
reskins:

| Person | Background |
|---|---|
| Bjorn | frosty glacier-blue-grey (cold Nordic fjord tone) |
| Kwame | deep amber-gold (warm ledger/parchment tone) |
| Masha | deep oxblood-red (cold Moscow winter-dusk tone) |
| Jamal | deep copper-bronze (circuit-board/copper-wire tone) |
| Chloe | deep indigo-ink-blue (fountain-pen-ink tone) |
| Sienna | deep burnt-sienna terracotta (Tuscan clay-earth tone) |
| Kai | deep turquoise-teal (Pacific-ocean tone) |
| Yara | deep emerald river-green (Amazon-river tone) |
| Gaz | deep mahogany-brown (leather armchair / cigar-lounge tone) |
| Priya | deep saffron-marigold (marigold-garland tone) |

Yuki's background wasn't recorded when it was generated — check
`.claude/agents/avatars/yuki.png` directly if it needs to be distinguished
from a future person's color choice.
