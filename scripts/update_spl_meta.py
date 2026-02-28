#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo


NATIVE_SIGMA_FILE_SENTINEL = (
    "No Sigma source is associated with this detection; it was authored natively as an SPL rule."
)


@dataclass
class MetaUpdateResult:
    path: Path
    changed: bool
    reason: str


def get_git_sha() -> str:
    # Prefer CI env
    import os

    sha = os.environ.get("GITHUB_SHA") or os.environ.get("CI_COMMIT_SHA")
    if sha:
        return sha[:7]

    try:
        return (
            subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL)
            .decode()
            .strip()
        )
    except Exception:
        return "unknown"


def get_rule_version_for_file(file_path: Path) -> str:
    """
    1.0 = first commit for that file
    1.1 = second commit
    1.2 = third commit ...
    """
    try:
        count_raw = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD", "--", str(file_path)],
            stderr=subprocess.DEVNULL,
        ).decode().strip()

        count = int(count_raw)
        if count <= 1:
            return "1.0"
        return f"1.{count - 1}"
    except Exception:
        return "1.0"


def now_budapest_iso() -> str:
    return datetime.now(ZoneInfo("Europe/Budapest")).isoformat()


def iter_native_spl_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for p in root.rglob("*.spl"):
        # Skip generated sigma outputs: *.sigma.spl
        if p.name.endswith(".sigma.spl"):
            continue
        files.append(p)
    return sorted(files)


def extract_meta_block(text: str) -> Optional[Dict[str, Any]]:
    if "META_START" not in text or "META_END" not in text:
        return None

    before, rest = text.split("META_START", 1)
    meta_part, after = rest.split("META_END", 1)

    meta_json_str = meta_part.strip()

    # meta_json_str should be JSON object, not including META_START/END
    try:
        meta = json.loads(meta_json_str)
        if not isinstance(meta, dict):
            return None
        return meta
    except json.JSONDecodeError:
        return None


def replace_meta_block(text: str, new_meta_json_pretty: str) -> str:
    before, rest = text.split("META_START", 1)
    _, after = rest.split("META_END", 1)

    # Keep exact framing: META_START\n{json}\nMETA_END
    out = []
    out.append(before.rstrip("\n"))
    out.append("META_START")
    out.append(new_meta_json_pretty)
    out.append("META_END")
    out.append(after.lstrip("\n"))
    return "\n".join(out).rstrip("\n") + "\n"


def format_meta_with_spacing(meta: Dict[str, Any]) -> str:
    """
    Pretty-print JSON with your preferred blank lines:
      - blank line after "modified"
      - blank line before "references"
      - blank line before "tags"
      - blank line before and after "logsource"
    Also enforces key order for the 'header' section.
    """

    # Build ordered dict in the exact order you standardized
    ordered: Dict[str, Any] = {}

    def add(k: str):
        if k in meta:
            ordered[k] = meta[k]

    # Header order
    add("title")
    add("detect_id")
    add("description")
    add("sigma_file")
    add("level")
    add("status")
    add("author")
    add("date")
    add("modified")

    # Build/CI fields
    add("convert_time")
    add("rule_version")
    add("git_sha")

    add("ci_managed")
    add("origin")
    add("convert_mode")
    add("sigma_pipeline")

    # Remaining keys (stable order)
    for k in meta.keys():
        if k in ordered:
            continue
        ordered[k] = meta[k]

    # Now pretty dump, then inject blank lines
    raw = json.dumps(ordered, indent=2, ensure_ascii=False, sort_keys=False)

    lines = raw.splitlines()
    out: List[str] = []

    # helper to see current line key
    def is_key_line(line: str, key: str) -> bool:
        s = line.lstrip()
        return s.startswith(f"\"{key}\":")  # exact

    for i, line in enumerate(lines):
        stripped = line.lstrip()

        # Insert blank line AFTER modified line (i.e., before next key), but only if next non-empty is not closing brace
        out.append(line)

        if is_key_line(line, "modified"):
            # add blank line if not already next is '}'.
            out.append("")

        # blank line BEFORE references
        if is_key_line(line, "references"):
            # we just appended the line; need blank line before it -> move by inserting earlier
            # easiest: if previous out[-2] isn't blank and we're not at start, insert blank line before current line
            # But we're past that. We'll handle by checking and adjusting at the moment we see 'references' line:
            # Remove the last appended line, add blank line, re-add line.
            out.pop()  # remove references line
            if out and out[-1] != "":
                out.append("")
            out.append(line)

        # blank line BEFORE tags
        if is_key_line(line, "tags"):
            out.pop()
            if out and out[-1] != "":
                out.append("")
            out.append(line)

        # blank line BEFORE logsource
        if is_key_line(line, "logsource"):
            out.pop()
            if out and out[-1] != "":
                out.append("")
            out.append(line)

        # blank line AFTER logsource object (after the closing "}" of logsource, i.e. the line that begins with "  }" but only within logsource)
        # We'll detect the end of logsource by looking ahead minimally: when we are in logsource and indentation closes.
        # Simpler: after we print a line that is exactly '  },' or '  }' AND previously we were inside logsource block.
    # Second pass to add blank line after logsource block
    # We'll track when we enter logsource and when it closes.
    final: List[str] = []
    in_logsource = False
    logsource_indent = None

    for line in out:
        if not in_logsource and line.lstrip().startswith("\"logsource\":"):
            in_logsource = True
            logsource_indent = len(line) - len(line.lstrip())
            final.append(line)
            continue

        if in_logsource:
            final.append(line)
            # Detect close of logsource object:
            # logsource structure is:
            # "logsource": {
            #   ...
            # }
            # so line that starts with same indent and is '}' or '},'
            if logsource_indent is not None:
                s = line.strip()
                # close brace could be '},' or '}'
                if (s == "}" or s == "},") and (len(line) - len(line.lstrip()) == logsource_indent):
                    # add blank line after logsource close
                    final.append("")
                    in_logsource = False
                    logsource_indent = None
            continue

        final.append(line)

    # Remove excessive trailing blank lines inside JSON
    # (but keep as-is if user prefers)
    while len(final) > 2 and final[-2] == "" and final[-1].strip() == "}":
        # keep one blank line max before closing brace
        break

    return "\n".join(final)


def update_meta(meta: Dict[str, Any], file_path: Path) -> Dict[str, Any]:
    meta = dict(meta)  # copy

    meta["convert_time"] = now_budapest_iso()
    meta["git_sha"] = get_git_sha()
    meta["rule_version"] = get_rule_version_for_file(file_path)

    # Ensure native sentinel
    if not meta.get("sigma_file"):
        meta["sigma_file"] = NATIVE_SIGMA_FILE_SENTINEL

    # Ensure origin is present (do not override if already set)
    meta.setdefault("origin", "spl-rule")

    return meta


def process_file(path: Path, dry_run: bool) -> MetaUpdateResult:
    text = path.read_text(encoding="utf-8", errors="replace")

    meta = extract_meta_block(text)
    if meta is None:
        return MetaUpdateResult(path, False, "No valid META_START/META_END JSON block found")

    # Hard safety: never touch generated sigma outputs, even if called directly
    if path.name.endswith(".sigma.spl"):
        return MetaUpdateResult(path, False, "Skipped generated *.sigma.spl")

    updated = update_meta(meta, path)
    new_meta_json = format_meta_with_spacing(updated)

    # Compare if change needed
    current_meta_raw = json.dumps(meta, sort_keys=True, ensure_ascii=False)
    updated_meta_raw = json.dumps(updated, sort_keys=True, ensure_ascii=False)

    if current_meta_raw == updated_meta_raw:
        return MetaUpdateResult(path, False, "META already up-to-date")

    if not dry_run:
        new_text = replace_meta_block(text, new_meta_json)
        path.write_text(new_text, encoding="utf-8")

    return MetaUpdateResult(path, True, "META updated")


def main() -> int:
    ap = argparse.ArgumentParser(description="Update META fields for native SPL rules (convert_time/git_sha/rule_version).")
    ap.add_argument("--root", required=True, help="Root folder to scan (e.g., rules/splunk)")
    ap.add_argument("--dry-run", action="store_true", help="Do not write changes, only report")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"[ERROR] Root folder not found: {root}")
        return 2

    files = iter_native_spl_files(root)
    if not files:
        print("[INFO] No native SPL files found.")
        return 0

    changed_any = False
    for f in files:
        res = process_file(f, dry_run=args.dry_run)
        prefix = "[CHANGED]" if res.changed else "[SKIP]"
        print(f"{prefix} {res.path.relative_to(root)} - {res.reason}")
        changed_any = changed_any or res.changed

    return 0


if __name__ == "__main__":
    raise SystemExit(main())