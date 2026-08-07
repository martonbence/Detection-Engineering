"""
Shared vocabulary for GitHub Actions step summaries.

Why this module exists: five different places write to $GITHUB_STEP_SUMMARY --
two validators, the deploy, the verification, and two inline bash blocks in the
dev workflow -- and until now each picked its own heading level, its own emoji
and its own escaping rules. The Actions run page shows them stacked together,
so the inconsistency is visible in exactly the place the summaries exist to
serve. One vocabulary, imported by everyone, is the fix.

The two bash writers in ci_dev_workflow.yml cannot import this (and neither can
run_atomic.ps1), so they carry literals with a comment pointing back here. If a
mark changes, it changes in three places -- there is no way around that across
three languages, but there is exactly one place that says what the mark *means*.

On the marks themselves: these are text-style glyphs, not emoji, deliberately.

  - They inherit the reader's text colour, so they render correctly in both the
    light and dark GitHub themes rather than punching a coloured hole in a
    sentence.
  - They are single-width. Emoji are not, and a table column whose cells mix
    emoji and text loses its alignment -- which is why the verification table
    looked ragged.
  - U+2705 (the "big green square" check) carries roughly three times the
    visual weight of the words it annotates. In a 27-row table the marks became
    the content and the rule names became the decoration, which is backwards.
"""

# Outcome marks. Paired with a word in every use -- the glyph is an accent on
# the label, never a replacement for it, because a bare symbol is unreadable to
# a screen reader and ambiguous to anyone who has not learned the convention.
MARK_PASS = "✓"
MARK_FAIL = "✕"
# "Unknown", not "bad": NOT_VERIFIED means the attack or the measurement did not
# complete, so nothing is known about the detection. A warning triangle would
# claim more than the data supports.
MARK_UNKNOWN = "?"
MARK_WARN = "!"
MARK_INFO = "·"

# GitHub Flavored Markdown alert kinds, rendered by the job-summary page as
# native coloured callouts. Documented as supported: job summaries "support
# GitHub flavored Markdown".
ALERT_PASS = "TIP"        # green
ALERT_FAIL = "CAUTION"    # red
ALERT_WARN = "WARNING"    # amber
ALERT_INFO = "NOTE"       # blue


def escape_cell(value: object) -> str:
    """
    Make a value safe to drop into a markdown table cell.

    A literal pipe ends the cell and shifts every column after it. This is not
    hypothetical: the deploy writes Splunk error text into its Outcome column,
    and Splunk error text contains JSON. Run #69 was one pipe away from a
    broken table.
    """
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def alert(kind: str, body: str) -> list[str]:
    """
    A GFM alert block as summary lines.

    Degrades to an ordinary blockquote on any renderer that does not know the
    syntax, which is why the body must read correctly on its own -- the marker
    line carries colour, not meaning.
    """
    lines = [f"> [!{kind}]"]
    lines.extend(f"> {line}" if line else ">" for line in body.splitlines())
    return lines
