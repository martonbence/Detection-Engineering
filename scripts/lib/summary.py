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

On the marks themselves. The first attempt used text-style glyphs (✓ ✕ ?) to
avoid two real problems with U+2705, the "big green square" check: it carries
several times the visual weight of the words it annotates, and it is wider than
a text character, so a column mixing it with plain text loses its alignment.

Read on an actual run, those glyphs turned out to be too quiet -- the verdict
disappeared into the sentence next to it, which for the one column a reader
scans first is the worse failure of the two.

Coloured circles are the middle ground and are what this module now uses. They
are unmistakable at a glance, they carry the state in colour as well as in the
word beside them, and -- unlike ✅ next to ✕ -- all four are the same emoji
width, so a column of them stays straight. The traffic-light reading is also
already the repo's: docs/index.html uses green/amber/red for exactly these
three verdicts, and the summaries now match the dashboard.
"""

# Outcome marks. Paired with a word in every use -- the circle is an accent on
# the label, never a replacement for it, because a bare colour is invisible to
# a screen reader and meaningless to anyone reading in monochrome.
MARK_PASS = "🟢"
MARK_FAIL = "🔴"
# Amber, not red: NOT_VERIFIED means the attack or the measurement did not
# complete, so nothing is known about the detection. Colouring it like a failure
# would claim more than the data supports. Matches the dashboard's
# .verdict-notverified treatment.
MARK_UNKNOWN = "🟡"
MARK_WARN = "🟡"
# Neutral: a deliberate skip is neither success nor failure.
MARK_INFO = "⚪"

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
