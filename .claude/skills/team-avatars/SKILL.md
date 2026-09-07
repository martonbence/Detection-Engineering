---
name: team-avatars
description: Use when generating a profile-picture prompt for a Detection-Engineering team member (the CLAUDE.md roster) — reuses the locked style/camera/resolution blocks unchanged, follows Jamal's block as the worked example, and only swaps in a new per-person description.
---

Produces the AI-image-generation prompt text for one team member's avatar.
This skill does not call an image model itself (none is wired into this
project) — it produces the prompt text to paste into whatever generator
is in use (Canva Magic Media, Midjourney, DALL-E, etc.).

## The locked blocks (copy unchanged for every new person)

```
Character portrait bust, rendered as a clean vector illustration that emulates the
aesthetic of 16-bit pixel art (SNES/Genesis-era JRPG character-select screen), using
flat, evenly-filled color blocks and crisp hard-edged vector geometry to create the
blocky pixel-art look — no dithering, no raster noise, no gradient texture, purely
flat vector shapes with sharp geometric transitions between color fields.
[[PER-PERSON DESCRIPTION BLOCK — see worked example below]]
Flat solid [[PER-PERSON BACKGROUND COLOR + MOOD]] background, no gradient. Waist-up
framing, square canvas, crisp vector-clean edges, no anti-aliasing blur. Target
output: 1254x1254 px square canvas — match the pixelation density of a ~64x64 sprite
grid scaled up with hard edges (consistent chunkiness across the whole team roster,
not finer/smoother and not blockier).

CAMERA/POSE LOCK (reuse identically for all characters):
Three-quarter view portrait, head turned approximately 15-20 degrees to the viewer's
left, eyes looking directly into the camera regardless of head angle — pupils and
irises shifted toward the inner corner of each eye (toward the viewer) to maintain
true direct eye contact despite the turned head, asymmetric visible eye-white
consistent with this gaze correction, direct steady eye contact with the viewer,
shoulders angled slightly toward the front (less rotated than the head), centered
composition, subject occupies roughly the middle 70% of frame width, waist-up crop
with equal headroom above hair, square 1:1 canvas, camera at eye level, no tilt.
```

Never alter the resolution/pixelation-density line or the CAMERA/POSE LOCK
block — every generated file has landed at exactly 1254x1254 px on this
wording, and the pose lock is what keeps all portraits reading as one set.

## Worked example (Jamal — DevOps Engineer)

```
African American man in his early-to-mid 30s, strong squared jawline read through
blocky flat-color shading, short tightly-coiled black hair cut close in a low fade,
neatly-trimmed short black beard along the jawline, dark brown eyes with a steady,
unflappable gaze, deep brown skin tone rendered in a limited flat-color palette, calm
and quietly capable expression — the look of someone who's already watched a pipeline
fail in every way it can and no longer panics, just fixes it. Wearing a heather-grey
crewneck with an employee badge on a lanyard at the chest, practical unfussy styling,
bold 1px dark outline around the silhouette.
```
Background: flat solid deep copper-bronze (circuit-board/copper-wire tone).

This is the level of specificity every new block should hit: age range,
face/jaw structure, hair (cut, color, texture), facial hair if any, eyes
(color + what the gaze says about the person), skin tone, one expression
phrase tied to *why* — what about their role produces that look — then
clothing (garment, fit, one or two accent details), and a background color
with a short thematic tag in parentheses. A held prop tied to the role is
fair game (Jamal's lanyard badge; other members have used a drink, a
tool) as long as it still fits the one-hand-raised-into-frame, waist-up
pose the camera lock allows.

## What to decide per new person

- **Nationality/ethnicity + physical traits** — this is the user's call to
  make, not something to assume; confirm it in conversation before
  drafting the block.
- **Expression** — derive from the role's real function, the way Jamal's
  "calm and quietly capable" comes from being the one who owns CI/CD and
  has seen every way a pipeline can fail.
- **Clothing** — professional, minimal, culturally consistent with the
  chosen nationality; keep it visually distinct from every existing member
  so the set doesn't read as reskins of each other.
- **Background color** — flat solid hue, no gradient, thematically tied to
  the person, distinct from every color already in use (see table below).

## Where the finished image goes

```
docs/pictures/avatars/<Name>.png
```

Capitalized first name, directly in `avatars/`, no subdirectory — this is
the convention all current files follow. A `<Name>_transparent.png`
companion (same directory) is what the team-ops dashboard renders. Once
generated, the avatar is picked up automatically by
`.claude/generate_dashboard.py` from its filename — no roster line to
edit — so just regenerate the dashboard (`python3
.claude/generate_dashboard.py`).

Save the finished prompt text itself as a new entry in this skill file
(a short addition to or replacement of the worked example above), not as
a loose `.txt` next to the image — that convention was tried twice in
this repo and the files were deleted both times, so nothing outside
version control has held up as durable storage for these prompts.

## Background colors already in use (pick something distinct)

Bjorn: frosty glacier-blue-grey · Kwame: deep amber-gold · Masha: deep
oxblood-red · Jamal: deep copper-bronze · Chloe: deep indigo-ink-blue ·
Sienna: deep burnt-sienna terracotta · Kai: deep turquoise-teal · Yara:
deep emerald river-green · Gaz: deep mahogany-brown · Priya: deep
saffron-marigold · Yuki: not recorded, check `Yuki.png` directly.

The roster is full at 11 right now — this table only matters again once
it grows.
