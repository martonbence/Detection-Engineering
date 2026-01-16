#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml
from jsonschema import Draft7Validator


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "docs" / "schemas" / "schema.json"
RULES_DIR = REPO_ROOT / "rules"

# Validation outputs (JSON)
OUT_DIR = REPO_ROOT / "outputs" / "validate"
REPORT_PATH = OUT_DIR / "sigma_schema_validation_report.json"


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml_file(path: Path) -> Any:
    # Sigma rule YAML -> Python object
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def find_sigma_rule_files(root: Path) -> List[Path]:
    exts = {".yml", ".yaml"}
    return [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts]


def format_jsonschema_error(err) -> Dict[str, Any]:
    return {
        "message": err.message,
        "instance_path": "/" + "/".join(str(x) for x in err.path) if err.path else "",
        "schema_path": "/" + "/".join(str(x) for x in err.schema_path) if err.schema_path else ""
    }


def validate_rule(validator: Draft7Validator, rule_path: Path) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Returns:
      ok: bool
      errors: list
      meta: best-effort extracted fields to help triage
    """
    meta = {"title": None, "id": None, "status": None, "level": None}

    try:
        data = load_yaml_file(rule_path)
    except Exception as e:
        return False, [{
            "message": f"YAML parse error: {e}",
            "instance_path": "",
            "schema_path": ""
        }], meta

    if isinstance(data, dict):
        meta["title"] = data.get("title")
        meta["id"] = data.get("id")
        meta["status"] = data.get("status")
        meta["level"] = data.get("level")

    errors = [format_jsonschema_error(e) for e in sorted(validator.iter_errors(data), key=lambda x: list(x.path))]
    return (len(errors) == 0), errors, meta


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"[FATAL] Schema not found: {SCHEMA_PATH}", file=sys.stderr)
        return 2

    if not RULES_DIR.exists():
        print(f"[FATAL] Rules directory not found: {RULES_DIR}", file=sys.stderr)
        return 2

    schema = load_json(SCHEMA_PATH)
    validator = Draft7Validator(schema)

    rule_files = find_sigma_rule_files(RULES_DIR)
    results = []

    valid_count = 0
    invalid_count = 0
    parse_error_count = 0

    for rp in sorted(rule_files):
        ok, errs, meta = validate_rule(validator, rp)

        if (len(errs) == 1) and errs[0]["message"].startswith("YAML parse error:"):
            parse_error_count += 1

        results.append({
            "rule_file": str(rp.relative_to(REPO_ROOT)),
            "valid": ok,
            "meta": meta,
            "errors": errs
        })

        if ok:
            valid_count += 1
        else:
            invalid_count += 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "schema_file": str(SCHEMA_PATH.relative_to(REPO_ROOT)),
        "rules_root": str(RULES_DIR.relative_to(REPO_ROOT)),
        "rules_scanned": len(rule_files),
        "valid_rules": valid_count,
        "invalid_rules": invalid_count,
        "yaml_parse_errors": parse_error_count,
        "results": results
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[INFO] Rules scanned: {len(rule_files)} | valid: {valid_count} | invalid: {invalid_count}")
    print(f"[INFO] Report written: {REPORT_PATH.relative_to(REPO_ROOT)}")

    return 1 if invalid_count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
