# scripts/validate/check_mitre_tags.py
#
# Register item 4.3: nothing in the pipeline checks that a rule's ATT&CK tags
# mean anything.
#
# The schema (docs/schemas/sigma_schema.json) looks like it validates them, but
# its `tags` item ends in a free-form `{"type": "string"}` branch -- so the
# enum of tactic names and the `^attack\.[Tt]\d{4}(\.\d{3})?$` technique pattern
# are editor suggestions, not gates. `attack.t1059.999`, `attack.t1O59.001` and
# `attack.defense_evasion` all validate today. Downstream nothing catches them
# either: generate_stats.py's extract_techniques() turns whatever matches
# `attack.t\d+` into a badge and a Navigator cell, and extract_tactics() maps an
# unrecognised tactic through `.title()` into a column name that exists in no
# matrix. A mistyped tag therefore produces a rule that looks tagged, ships,
# and is invisible in the coverage view it was supposed to appear in.
#
# The map this checks against is ALREADY IN THE REPO: generate_stats.py caches
# the full technique map in outputs/reports/mitre_technique_map.json (7-day TTL)
# to draw the coverage matrix. This checker only reads that file. It performs no
# network I/O of any kind -- validation must not depend on GitHub raw being up,
# and a validator that silently degrades to "could not fetch, everything is
# fine" is worse than no validator. If the cache is missing or unusable the
# checker exits 2 (its own failure) rather than reporting every rule as broken.
#
# What the cache can and cannot tell us about revoked techniques:
# generate_stats.py drops objects marked `revoked` / `x_mitre_deprecated` while
# building the cache, so a withdrawn technique is simply absent -- it looks
# exactly like a typo. One piece of the numbering separates them. Main technique
# IDs are sparse (222 live techniques scattered over the T1001-T1690 range), so
# an absent T#### says nothing about whether that number was ever allocated. Sub
# technique numbering under a parent is dense (475 sub-techniques, 11 gaps), and
# ATT&CK does not reuse a sub-technique number after retiring it. An absent sub
# that falls *inside* its parent's allocated range was therefore allocated once
# and withdrawn since; an absent sub *above* the range was never allocated. That
# is the revoked/deprecated finding, and it is honest about its own confidence.
#
# On this repo's tactic vocabulary: it is not upstream ATT&CK's. `Stealth` and
# `Defense Impairment` are tactics here (30 and 18 main techniques in the cached
# map claim them), where upstream has Defense Evasion. The vocabulary is
# therefore DERIVED FROM THE CACHE rather than hardcoded from upstream -- a
# hardcoded upstream list would report a third of the repo's rules as wrong on
# its first run. See ALWAYS_VALID_TACTIC_TAGS.
#
# Exit codes:
# 0 = no findings, or findings reported advisory (default)
# 1 = error-severity findings, with --strict
# 2 = checker setup failure (deps / cache missing, unreadable or empty)

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.summary import MARK_FAIL, MARK_WARN, escape_cell

REPO_ROOT = Path(__file__).resolve().parents[2]

# Written by generate_stats.py. This checker is a pure reader of it.
DEFAULT_CACHE = REPO_ROOT / "outputs" / "reports" / "mitre_technique_map.json"
DEFAULT_RULES_DIR = REPO_ROOT / "rules" / "sigma"

# Advisory only, and generous: generate_stats.py refreshes the cache on a 7-day
# TTL, so anything under a month means the docs job simply has not run lately.
# An old map can only cause false "unknown technique" findings on brand-new
# ATT&CK content, which is worth a line of output and nothing more. It must
# never trigger a fetch here.
CACHE_STALE_DAYS = 30

# A well-formed technique tag. Same shape as the schema's pattern.
TECHNIQUE_TAG_RE = re.compile(r"^t(\d{4})(?:\.(\d{3}))?$")

# Anything that starts like a technique tag but is not one: attack.t123,
# attack.t1059.1, attack.t1059.001.002. These match the schema's free-form
# branch and, worse, generate_stats.py's looser `attack\.t\d+(?:\.\d+)?` regex
# happily renders them as technique badges.
TECHNIQUE_LOOKALIKE_RE = re.compile(r"^t\d")

# ATT&CK object references that are not tactics and not techniques: groups
# (G####), software (S####), mitigations (M####), campaigns (C####), data
# sources (DS####) and tactic IDs (TA####). Sigma allows them and this repo does
# not use them today, but treating a legitimate `attack.g0016` as an unknown
# tactic would be a false positive on the checker's first contact with one. The
# cache holds no group/software objects, so there is nothing to validate them
# against -- they are skipped, deliberately and visibly.
OBJECT_REF_RE = re.compile(r"^(g|s|m|c|ds|ta)\d{3,4}$")

# `attack.stealth` is VALID IN THIS REPO. It is not a carve-out for a broken
# tag: this repo's ATT&CK taxonomy uses Stealth (TA0005) where upstream uses
# Defense Evasion, the schema enumerates it, 30 techniques in the cached map
# claim it, and 8 rules tag it. The vocabulary check below derives its accepted
# tactic names from the cache precisely so that repo-specific tactics validate
# on their own merit and nobody has to maintain a second list.
#
# It is listed here anyway as a belt-and-braces exemption from the *vocabulary*
# check, so that a truncated or half-written cache can never turn `attack.stealth`
# into a finding and start a conversation about removing a correct tag. This
# does not exempt it from the tactic/technique pairing check further down --
# that check asks a different question ("does any technique on this rule
# actually belong to the tactic it claims?"), and answering it for Stealth is
# not the same as calling the tag invalid.
ALWAYS_VALID_TACTIC_TAGS = frozenset({"attack.stealth"})

ERROR = "error"
WARNING = "warning"


class CacheError(Exception):
    """The technique map could not be loaded. A checker failure, not a rule failure."""


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def tactic_key(name: str) -> str:
    """Normalize a tactic so the tag form and the map's display form compare equal.

    `attack.command_and_control` and "Command & Control" are the same tactic
    written for two different audiences. Rather than keeping a third copy of
    generate_stats.py's TACTIC_MAP in sync with this file, both sides are
    reduced to letters and digits, with `&` spelled out first.
    """
    return re.sub(r"[^a-z0-9]", "", str(name).lower().replace("&", "and"))


class TechniqueMap:
    """The cached ATT&CK map, indexed for lookups.

    Sub-techniques are flattened into the same index as their parents, because a
    tag does not say which of the two it is -- the ID shape does.
    """

    def __init__(self, entries: list, fetched_at: str | None = None) -> None:
        self.fetched_at = fetched_at
        self.by_id: dict[str, dict] = {}
        self.sub_ceiling: dict[str, int] = {}
        self.tactics: dict[str, str] = {}

        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            tech_id = str(entry.get("id") or "").upper()
            if not tech_id:
                continue
            self._add(tech_id, entry, parent=None)

            highest = 0
            for sub in entry.get("subs") or []:
                if not isinstance(sub, dict):
                    continue
                sub_id = str(sub.get("id") or "").upper()
                if not sub_id.startswith(tech_id + "."):
                    continue
                self._add(sub_id, sub, parent=tech_id)
                try:
                    highest = max(highest, int(sub_id.split(".", 1)[1]))
                except ValueError:
                    continue
            if highest:
                self.sub_ceiling[tech_id] = highest

    def _add(self, tech_id: str, entry: dict, parent: str | None) -> None:
        tactics = [str(t) for t in (entry.get("tactics") or [])]
        self.by_id[tech_id] = {
            "id": tech_id,
            "name": str(entry.get("name") or ""),
            "tactics": tactics,
            "parent": parent,
        }
        for tactic in tactics:
            self.tactics.setdefault(tactic_key(tactic), tactic)

    def __len__(self) -> int:
        return len(self.by_id)

    def get(self, tech_id: str) -> dict | None:
        return self.by_id.get(tech_id.upper())

    def main_count(self) -> int:
        return sum(1 for e in self.by_id.values() if e["parent"] is None)

    def tactic_name(self, key: str) -> str | None:
        return self.tactics.get(key)


def load_technique_map(path: Path) -> TechniqueMap:
    """Read the cache generate_stats.py maintains. Never fetches."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as ex:
        raise CacheError(
            f"Could not read the MITRE technique map: {path} ({ex}). "
            f"It is written by scripts/docs/generate_stats.py -- run that once, or pass --cache. "
            f"This checker will not fetch it."
        ) from ex

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as ex:
        raise CacheError(f"The MITRE technique map is not valid JSON: {path} ({ex})") from ex

    if not isinstance(payload, dict) or not isinstance(payload.get("techniques"), list):
        raise CacheError(
            f"The MITRE technique map has an unexpected shape: {path} "
            f"(expected an object with a 'techniques' list)"
        )

    tmap = TechniqueMap(payload["techniques"], str(payload.get("fetched_at") or "") or None)

    if not len(tmap):
        # Without this guard an empty cache would make every technique tag in
        # the repo "unknown" -- which reads as 27 broken rules when the truth is
        # one broken input file.
        raise CacheError(
            f"The MITRE technique map is empty: {path}. Refusing to report every rule as "
            f"untagged; regenerate it with scripts/docs/generate_stats.py."
        )

    return tmap


def cache_age_note(tmap: TechniqueMap) -> str | None:
    """A line about a stale cache, or None. Advisory: staleness never fails a run."""
    if not tmap.fetched_at:
        return "The technique map has no fetched_at timestamp, so its age is unknown."
    try:
        age = datetime.now(UTC) - datetime.fromisoformat(tmap.fetched_at)
    except ValueError:
        return f"The technique map's fetched_at is unparseable: {tmap.fetched_at!r}"
    if age > timedelta(days=CACHE_STALE_DAYS):
        return (
            f"The technique map is {age.days} days old (fetched {tmap.fetched_at}). "
            f"Newly published ATT&CK techniques may be reported as unknown."
        )
    return None


def split_tags(tags: list) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """Split a rule's tags into (techniques, tactics, malformed technique tags).

    techniques: [(tag, 'T1059.001')]
    tactics:    [(tag, 'execution')]
    """
    techniques: list[tuple[str, str]] = []
    tactics: list[tuple[str, str]] = []
    malformed: list[str] = []

    for raw in tags or []:
        tag = str(raw).strip().lower()
        if not tag.startswith("attack."):
            continue  # free-form tags (cve.*, internal taxonomies) are not ours
        body = tag[len("attack.") :]
        if not body or OBJECT_REF_RE.match(body):
            continue

        m = TECHNIQUE_TAG_RE.match(body)
        if m:
            techniques.append((tag, body.upper()))
        elif TECHNIQUE_LOOKALIKE_RE.match(body):
            malformed.append(tag)
        else:
            tactics.append((tag, body))

    return techniques, tactics, malformed


def _finding(path: Path, detect_id: str, severity: str, reason: str, tag: str, message: str) -> dict:
    return {
        "rule": str(path).replace("\\", "/"),
        "detect_id": detect_id,
        "severity": severity,
        "reason": reason,
        "tag": tag,
        "message": message,
    }


def _unresolved_finding(path: Path, detect_id: str, tag: str, tech_id: str, tmap: TechniqueMap) -> dict:
    """Classify a technique ID the map does not contain.

    Three outcomes, in descending confidence:
      revoked_technique   -- a sub-technique inside its parent's allocated range.
                             ATT&CK does not reuse sub-technique numbers, so the
                             number was handed out once and has been withdrawn.
      unknown_subtechnique -- parent exists, number is above anything ever
                             allocated under it: an invented or mistyped suffix.
      unknown_technique   -- the ID (or its parent) is not in the map at all.
    """
    parent = tech_id.split(".", 1)[0] if "." in tech_id else None

    if parent and tmap.get(parent):
        ceiling = tmap.sub_ceiling.get(parent, 0)
        try:
            number = int(tech_id.split(".", 1)[1])
        except ValueError:
            number = 0
        parent_name = tmap.get(parent)["name"]
        if 0 < number <= ceiling:
            return _finding(
                path, detect_id, ERROR, "revoked_technique", tag,
                f"{detect_id} tags {tech_id}, which is missing from the technique map even though "
                f"its parent {parent} ({parent_name}) has sub-techniques up to .{ceiling:03d}. "
                f"ATT&CK does not reuse sub-technique numbers, so this one was allocated and has "
                f"since been revoked or deprecated -- the cache is built from live techniques only. "
                f"The coverage matrix will not show this rule anywhere.",
            )
        return _finding(
            path, detect_id, ERROR, "unknown_subtechnique", tag,
            f"{detect_id} tags {tech_id}, but {parent} ({parent_name}) has never had a "
            f"sub-technique numbered that high (highest allocated: .{ceiling:03d}). "
            f"Most likely a typo in the suffix.",
        )

    return _finding(
        path, detect_id, ERROR, "unknown_technique", tag,
        f"{detect_id} tags {tech_id}, which does not exist in the technique map. Either the ID is "
        f"mistyped or the whole technique has been revoked. The rule still deploys, but it covers "
        f"nothing on the ATT&CK matrix.",
    )


def check_rule(path: Path, data: object, tmap: TechniqueMap) -> list[dict]:
    """Every ATT&CK tag problem on one rule. Empty list means the tags hold up."""
    if not isinstance(data, dict):
        return []
    tags = data.get("tags")
    if not isinstance(tags, list):
        # The schema owns "tags is missing or is not a list"; failing the same
        # rule twice for one cause helps nobody.
        return []

    detect_id = str(data.get("detect_id") or path.stem)
    techniques, tactics, malformed = split_tags(tags)
    findings: list[dict] = []

    for tag in malformed:
        findings.append(_finding(
            path, detect_id, ERROR, "malformed_technique_tag", tag,
            f"{detect_id} carries {tag!r}, which is not a valid ATT&CK technique tag "
            f"(expected attack.t#### or attack.t####.###). The schema's free-form branch accepts "
            f"it and the stats generator will still render it as a technique badge.",
        ))

    covered_tactics: set[str] = set()
    resolved: list[tuple[str, str, dict]] = []
    tagged_ids = {tech_id for _, tech_id in techniques}

    for tag, tech_id in techniques:
        entry = tmap.get(tech_id)
        if entry is None:
            findings.append(_unresolved_finding(path, detect_id, tag, tech_id, tmap))
            continue
        resolved.append((tag, tech_id, entry))
        covered_tactics |= {tactic_key(t) for t in entry["tactics"]}

        # Parent/sub consistency: tagging T1003 next to T1003.001 adds no
        # coverage the sub-technique does not already carry, and it double-counts
        # the rule in the matrix -- once on the parent row, once on the child.
        parent = entry["parent"]
        if parent and parent in tagged_ids:
            findings.append(_finding(
                path, detect_id, WARNING, "redundant_parent", f"attack.{parent.lower()}",
                f"{detect_id} tags both {parent} and its sub-technique {tech_id}. The parent adds "
                f"no coverage the sub-technique does not already provide, and the rule is counted "
                f"on both rows of the matrix.",
            ))

    # "The technique side of this rule is not fully readable." Both an
    # unresolvable ID and a malformed tag mean the set of tactics this rule
    # legitimately covers is incomplete, so any conclusion drawn from that set
    # would be an artefact of the finding already reported above.
    incomplete = bool(malformed) or len(resolved) != len(techniques)

    tactic_errors: list[dict] = []
    for tag, body in tactics:
        if tag in ALWAYS_VALID_TACTIC_TAGS:
            continue  # see ALWAYS_VALID_TACTIC_TAGS
        key = tactic_key(body)

        if tmap.tactic_name(key) is None:
            tactic_errors.append(_finding(
                path, detect_id, ERROR, "unknown_tactic", tag,
                f"{detect_id} carries the tactic tag {tag!r}, which matches no tactic any technique "
                f"in the map belongs to. The rule browser will invent a column name for it that no "
                f"matrix has, so the rule drops out of the coverage view.",
            ))
            continue

        if incomplete:
            continue  # see `incomplete` above

        if key not in covered_tactics:
            names = ", ".join(sorted(f"{tid} ({e['name']})" for _, tid, e in resolved)) or "none"
            tactic_errors.append(_finding(
                path, detect_id, ERROR, "tactic_mismatch", tag,
                f"{detect_id} claims the {tmap.tactic_name(key)} tactic, but none of the techniques "
                f"it tags belongs to it: {names}. Either the tactic tag or the technique list is "
                f"wrong -- as tagged, the rule shows up in a column it does not support.",
            ))

    findings.extend(tactic_errors)

    # The undeclared-tactic warning reads the same disagreement from the other
    # side: something the techniques bring is not declared. Once an error above
    # has already said the two sides do not line up, repeating it in the opposite
    # direction is one mistake reported twice -- and the warning is the weaker of
    # the two statements. It fires only for the pure case: every declared tactic
    # is supported, but a technique contributes one nobody wrote down.
    if not tactic_errors:
        declared = {tactic_key(body) for _, body in tactics}
        for _, tech_id, entry in resolved:
            for tactic in entry["tactics"]:
                if tactic_key(tactic) not in declared:
                    findings.append(_finding(
                        path, detect_id, WARNING, "undeclared_tactic", f"attack.{tech_id.lower()}",
                        f"{detect_id} tags {tech_id} ({entry['name']}), which belongs to the "
                        f"{tactic} tactic, but the rule declares no attack.{tactic_key(tactic)}-style "
                        f"tag for it. Every other rule in the repo lists both, and the tactic tags "
                        f"are what the by-tactic statistics count.",
                    ))

    return findings


def annotate(findings: list[dict], strict: bool) -> None:
    """One GitHub annotation per finding.

    Error severity is only raised to `::error` when --strict is on, i.e. when the
    finding actually fails the step. A red annotation on a step that then exits 0
    trains people to ignore annotations.
    """
    for f in findings:
        level = "error" if (strict and f["severity"] == ERROR) else "warning"
        title = f["reason"].replace("_", " ").capitalize()
        print(f"::{level} file={f['rule']},title=ATT&CK tag: {title}::{f['message']}")


def write_step_summary(findings: list[dict]) -> None:
    """Put the findings where a human sees them without opening the job log."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path or not findings:
        return

    lines = [
        "### MITRE ATT&CK tag findings",
        "",
        "Checked against the cached technique map in `outputs/reports/mitre_technique_map.json`.",
        "",
        "| Rule | Tag | Problem | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for f in findings:
        mark = MARK_FAIL if f["severity"] == ERROR else MARK_WARN
        lines.append(
            f"| `{escape_cell(f['detect_id'])}` | `{escape_cell(f['tag'])}` "
            f"| {mark} {escape_cell(f['reason'])} | {escape_cell(f['message'])} |"
        )
    lines.append("")

    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as ex:
        eprint(f"WARNING: could not write the step summary: {ex}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check Sigma ATT&CK tags against the cached MITRE technique map (offline).",
    )
    p.add_argument(
        "--cache",
        default=str(DEFAULT_CACHE),
        help=f"Technique map written by generate_stats.py (default: {DEFAULT_CACHE})",
    )
    p.add_argument("--json", dest="json_out", help="Write the findings to this JSON file")
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when a rule has an error-severity finding, instead of only warning",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the per-rule OK lines; findings and the summary are still printed",
    )
    p.add_argument(
        "rules",
        nargs="*",
        help=f"Rule files to check (default: every *.yml in {DEFAULT_RULES_DIR})",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Imported here rather than at module scope to keep this guard reachable.
    # lib.rules imports pyyaml, so a top-level import would raise before main()
    # ran -- turning a friendly "install pyyaml" into a traceback, and exit 2
    # ("setup is broken") into exit 1, which CI reads as "this script found
    # problems with the rules". Nothing above main() needs these names.
    try:
        from lib.rules import RuleLoadError, discover, load_rule
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency: pyyaml. ({ex})")
        return 2

    try:
        tmap = load_technique_map(Path(args.cache))
    except CacheError as ex:
        eprint(f"[FATAL] {ex}")
        return 2

    stale = cache_age_note(tmap)
    if stale:
        print(f"::warning title=Stale ATT&CK technique map::{stale}")

    rule_paths = [Path(r) for r in args.rules] if args.rules else discover(DEFAULT_RULES_DIR)

    findings: list[dict] = []
    checked = 0
    clean = 0

    for path in rule_paths:
        try:
            data = load_rule(path)
        except RuleLoadError as ex:
            # validate_sigma.py owns malformed rules and already fails the run
            # for them; saying it twice for one cause only splits the diagnosis.
            eprint(f"SKIP: {ex}")
            continue

        checked += 1
        rule_findings = check_rule(path, data, tmap)
        findings.extend(rule_findings)
        if rule_findings:
            continue
        clean += 1
        if not args.quiet:
            print(f"[OK] {path}")

    errors = [f for f in findings if f["severity"] == ERROR]
    warnings = [f for f in findings if f["severity"] == WARNING]

    print("")
    print("=== MITRE ATT&CK Tag Validation Summary ===")
    print(f"Technique map: {args.cache}")
    print(
        f"  {tmap.main_count()} techniques + {len(tmap) - tmap.main_count()} sub-techniques, "
        f"{len(tmap.tactics)} tactics, fetched {tmap.fetched_at or 'unknown'}"
    )
    print(f"Checked:  {checked} rule(s)")
    print(f"Clean:    {clean}")
    print(f"Errors:   {len(errors)}")
    print(f"Warnings: {len(warnings)}")

    annotate(findings, args.strict)
    write_step_summary(findings)

    if findings:
        print("")
        for f in findings:
            print(f"[{f['severity'].upper()}] {f['rule']}: {f['reason']}: {f['message']}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "cache": str(args.cache).replace("\\", "/"),
                    "cache_fetched_at": tmap.fetched_at,
                    "technique_count": len(tmap),
                    "checked": checked,
                    "errors": len(errors),
                    "warnings": len(warnings),
                    "findings": findings,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {out}")

    if errors and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
