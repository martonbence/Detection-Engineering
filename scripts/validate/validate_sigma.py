# scripts/validate/validate_sigma.py
#
# Implements:
# - YAML parse (safe_load)
# - Draft-07 JSON schema validation
# - Clear schema/dependency errors
# - Empty YAML detection
# - Per-rule OK/INVALID output + summary
#
# Exit codes:
# 0 = all valid
# 1 = one or more rules invalid
# 2 = validator setup failure (deps/schema read/parse/etc.)

from __future__ import annotations

import argparse
import json
import sys
import datetime
from pathlib import Path


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate Sigma YAML rules against a Draft-07 JSON schema.")
    p.add_argument("--schema", required=True, help="Absolute path to schema.json")
    p.add_argument("--max-errors", type=int, default=25, help="Max validation errors to print per rule")
    p.add_argument("rules", nargs="+", help="Absolute paths to YAML rule files")
    return p.parse_args()

def normalize_dates(obj):
    # Convert YAML-parsed datetime/date into ISO strings so JSON Schema "string" works
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.date().isoformat() if isinstance(obj, datetime.datetime) else obj.isoformat()
    if isinstance(obj, dict):
        return {k: normalize_dates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_dates(v) for v in obj]
    return obj


def main() -> int:
    args = parse_args()

    # (9) Dependency preflight with clear errors
    try:
        import yaml  # type: ignore
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency: pyyaml. ({ex})")
        return 2

    try:
        from jsonschema import Draft7Validator  # type: ignore
    except Exception as ex:
        eprint(f"[FATAL] Missing dependency: jsonschema. ({ex})")
        return 2

    schema_path = Path(args.schema)
    if not schema_path.exists():
        eprint(f"[FATAL] Schema not found: {schema_path}")
        return 2

    # (5) Clear schema JSON parse errors
    try:
        schema_text = schema_path.read_text(encoding="utf-8")
    except Exception as ex:
        eprint(f"[FATAL] Failed to read schema: {schema_path} ({ex})")
        return 2

    try:
        schema = json.loads(schema_text)
    except Exception as ex:
        eprint(f"[FATAL] Schema is not valid JSON: {schema_path} ({ex})")
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

    for rule_str in args.rules:
        rule_path = Path(rule_str)
        validated += 1

        # PowerShell already filtered existence, but keep robust:
        if not rule_path.exists():
            print(f"[SKIP] {rule_path}: not found")
            continue

        # Parse YAML
        try:
            raw = rule_path.read_text(encoding="utf-8")
        except Exception as ex:
            invalid += 1
            invalid_files.append(str(rule_path))
            print(f"[INVALID] {rule_path}: read error: {ex}")
            continue

        try:
            data = yaml.safe_load(raw)
        except Exception as ex:
            invalid += 1
            invalid_files.append(str(rule_path))
            print(f"[INVALID] {rule_path}: YAML parse error: {ex}")
            continue

        # Normalize dates
        data = normalize_dates(data)

        # (6) Empty YAML detection
        if data is None:
            invalid += 1
            invalid_files.append(str(rule_path))
            print(f"[INVALID] {rule_path}: empty YAML (safe_load returned null)")
            continue

        # Schema validation
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        if errors:
            invalid += 1
            invalid_files.append(str(rule_path))
            print(f"[INVALID] {rule_path}")
            for e in errors[:max_errors]:
                inst = "/" + "/".join(str(x) for x in e.path) if e.path else ""
                # keep messages compact + CI-friendly
                print(f"  - {inst}: {e.message}")
            if len(errors) > max_errors:
                print(f"  ... {len(errors) - max_errors} more error(s) not shown")
        else:
            ok += 1
            print(f"[OK] {rule_path}")

    # (8) Summary
    print("")
    print("=== Sigma Schema Validation Summary ===")
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
