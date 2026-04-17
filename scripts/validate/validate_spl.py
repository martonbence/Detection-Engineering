# scripts/validate/validate_spl.py
#
# Validates the META_START/META_END JSON block in native SPL files
# against a Draft-07 JSON schema (spl_schema.json).
#
# Exit codes:
# 0 = all valid
# 1 = one or more files invalid
# 2 = validator setup failure (deps/schema/etc.)

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate native SPL META blocks against a Draft-07 JSON schema.")
    p.add_argument("--schema", required=True, help="Path to spl_schema.json")
    p.add_argument("--max-errors", type=int, default=25, help="Max validation errors to print per file")
    p.add_argument("files", nargs="+", help="Paths to .spl files")
    return p.parse_args()


def extract_meta(text: str, path: Path) -> dict | None:
    """Extract and parse the META_START/META_END JSON block from an SPL file."""
    start_marker = "META_START"
    end_marker = "META_END"

    start = text.find(start_marker)
    end = text.find(end_marker)

    if start == -1 or end == -1 or start >= end:
        print(f"[INVALID] {path}: missing or malformed META_START/META_END block")
        return None

    json_text = text[start + len(start_marker):end].strip()

    try:
        return json.loads(json_text)
    except json.JSONDecodeError as ex:
        print(f"[INVALID] {path}: META JSON parse error: {ex}")
        return None


def main() -> int:
    args = parse_args()

    try:
        from jsonschema import Draft7Validator
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency: jsonschema. ({ex})")
        return 2

    schema_path = Path(args.schema)
    if not schema_path.exists():
        eprint(f"[FATAL] Schema not found: {schema_path}")
        return 2

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as ex:
        eprint(f"[FATAL] Failed to read/parse schema: {ex}")
        return 2

    try:
        validator = Draft7Validator(schema)
    except Exception as ex:
        eprint(f"[FATAL] Failed to initialize Draft7 validator: {ex}")
        return 2

    max_errors = max(1, int(args.max_errors))
    validated = 0
    ok = 0
    invalid = 0
    invalid_files: list[str] = []

    for file_str in args.files:
        file_path = Path(file_str.strip())
        if not file_path.exists():
            print(f"[SKIP] {file_path}: not found")
            continue

        validated += 1

        try:
            text = file_path.read_text(encoding="utf-8")
        except Exception as ex:
            invalid += 1
            invalid_files.append(str(file_path))
            print(f"[INVALID] {file_path}: read error: {ex}")
            continue

        data = extract_meta(text, file_path)
        if data is None:
            invalid += 1
            invalid_files.append(str(file_path))
            continue

        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        if errors:
            invalid += 1
            invalid_files.append(str(file_path))
            print(f"[INVALID] {file_path}")
            for e in errors[:max_errors]:
                inst = "/" + "/".join(str(x) for x in e.path) if e.path else ""
                print(f"  - {inst}: {e.message}")
            if len(errors) > max_errors:
                print(f"  ... {len(errors) - max_errors} more error(s) not shown")
        else:
            ok += 1
            print(f"[OK] {file_path}")

    print("")
    print("=== SPL META Schema Validation Summary ===")
    print(f"Validated: {validated}")
    print(f"OK:        {ok}")
    print(f"INVALID:   {invalid}")

    if invalid_files:
        print("Invalid files:")
        for f in invalid_files:
            print(f"  - {f}")

    return 1 if invalid > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
