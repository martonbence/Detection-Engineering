# scripts/new_rule.py
#
# Register item 4.5 (scaffolder half only -- the Makefile and the optional
# ATT&CK-technique-to-atomic-test lookup described in the same item are not
# built here, by choice, to keep this change reviewable).
#
# Before this, a new rule started from a copy-pasted snippet with every value
# -- including detect_id -- edited by hand. Two problems with that: picking
# the next free detect_id means scanning the directory yourself (and the
# space already has gaps: 0001, 0002, 0004, 0017 are missing, from rules
# deleted or renamed since), and nothing stops two people picking the same
# one in parallel branches. This script only fixes the first half -- it
# computes "next free" from THIS checkout, which two branches started from
# the same base commit can still both compute identically. The actual
# backstop against that is check_detect_id_uniqueness.py, wired into CI
# separately: it runs on the merged tree, where a real collision would
# otherwise surface only as one rule's Splunk saved search silently
# overwriting the other's (rule_naming.saved_search_name is
# detect_id + slug(title), so two rules sharing a detect_id collide on the
# same object name).
#
# The generated file is schema-valid on its own -- every TODO placeholder
# satisfies sigma_schema.json's length/pattern constraints -- so
# validate_sigma.py passes on it unedited. It is not meant to stay unedited:
# check_mitre_tags.py (item 4.3) will flag the placeholder attack.TODO tactic
# tag and the attack.t0000 technique tag as unknown, on purpose, as the
# visible nudge to replace both.

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rule_naming import slugify
from lib.rules import RuleLoadError, detect_id, discover, load_rule

REPO_ROOT = Path(__file__).resolve().parent.parent

# Absolute, not lib.rules.DEFAULT_RULES_DIR (which is relative to whatever the
# caller's cwd happens to be) -- every other script here is always invoked
# from the repo root by CI, but this one is meant to be run by hand from
# wherever the author's shell is sitting.
DEFAULT_RULES_DIR = REPO_ROOT / "rules" / "sigma"

# Hardcoded rather than read from `git config user.name`: the git identity
# this repo pushes with (the account name, e.g. martonbnc9) is not the same
# string every existing rule's `author:` field carries -- git_author() used
# to read the former and get it wrong. There is one rule author today, so
# this is a fact about the project, not a guess.
DEFAULT_AUTHOR = "Bence Marton"

# Every enum-constrained field below (level, mode, severity, runner) gets a
# real, schema-valid value plus a `# TODO: review` comment rather than the
# literal string "TODO" -- unlike the free-form tags/logsource/description
# fields, the schema enums for these have no free-text branch, so a literal
# "TODO" would make validate_sigma.py reject the file it just scaffolded.
SKELETON = """\
title: {title}
detect_id: {detect_id}
status: experimental
description: >
  TODO: describe what this rule detects and why it matters.
references:
  - https://attack.mitre.org/techniques/TODO/
author: {author}
date: {today}
modified: {today}
version: "1.0"
tags:
  - attack.TODO   # TODO: tactic, e.g. attack.credential_access
  - attack.t0000  # TODO: technique/sub-technique, e.g. attack.t1003.001

logsource:
  product_category: TODO  # os | cloud | firewall | web | edr | ips | iam | exchange | proxy
  product: TODO            # e.g. windows, linux, aws, okta
  service: TODO             # e.g. sysmon, security, sshd
  event_type: TODO          # e.g. process_creation, authentication_success

detection:
  selection:
    TODO_field: TODO_value
  condition: selection

fields:
  - _time
  - TODO_field

falsepositives:
  - "TODO: describe expected benign triggers"

level: medium  # TODO: review -- low | medium | high | critical

custom:
  splunk:
    index: TODO
    mode: alert
    cron: "*/5 * * * *"
    earliest: "-5m"
    latest: "now"
    severity: medium  # TODO: review -- low | medium | high | critical

  testing:
    enabled: false
    runner: windows-victim  # TODO: review -- windows-victim | windows-dc | linux-victim
    type: atomic
"""


def next_detect_id(rules_dir: Path, year: int | None = None) -> str:
    """The lowest DETECT-<year>-NNNN not already used by a rule in `rules_dir`.

    Deliberately never fills a gap left by a deleted/renamed rule (0001, 0002,
    0004, 0017 today) -- a retired id staying retired matters more than a
    tidy sequence, since old verdict history, coverage_history.json points,
    and Splunk audit trails may still reference it.
    """
    year = year or datetime.date.today().year
    prefix = f"DETECT-{year}-"
    highest = 0
    for path in discover(rules_dir):
        try:
            rule = load_rule(path)
        except RuleLoadError:
            continue
        did = detect_id(rule)
        if did.startswith(prefix):
            try:
                highest = max(highest, int(did[len(prefix):]))
            except ValueError:
                continue
    return f"{prefix}{highest + 1:04d}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scaffold a new Sigma rule with the next free detect_id and a schema-valid skeleton."
    )
    p.add_argument("title", help="Rule title, e.g. \"Suspicious LSASS Access\"")
    p.add_argument(
        "--rules-dir", default=str(DEFAULT_RULES_DIR),
        help=f"Where to look for existing rules and write the new one (default: {DEFAULT_RULES_DIR})",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    title = args.title.strip()
    if len(title) < 5:
        print(f"[FATAL] Title too short ({len(title)} chars) -- the schema requires at least 5.", file=sys.stderr)
        return 2

    rules_dir = Path(args.rules_dir)
    new_id = next_detect_id(rules_dir)
    slug = slugify(title)
    out_path = rules_dir / f"{new_id}_{slug}.yml"

    if out_path.exists():
        print(f"[FATAL] {out_path} already exists.", file=sys.stderr)
        return 2

    rules_dir.mkdir(parents=True, exist_ok=True)
    content = SKELETON.format(
        title=title,
        detect_id=new_id,
        author=DEFAULT_AUTHOR,
        today=datetime.date.today().isoformat(),
    )
    out_path.write_text(content, encoding="utf-8")

    print(f"Created {out_path} with {new_id}.")
    print("Every TODO in it is a placeholder that passes schema validation but means nothing yet --")
    print("replace them, then: python scripts/validate/validate_sigma.py --schema docs/schemas/sigma_schema.json " + str(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
