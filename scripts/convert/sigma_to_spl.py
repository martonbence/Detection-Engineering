# scripts/convert/sigma_to_spl.py
import argparse
import os
import subprocess
import datetime
import json
from zoneinfo import ZoneInfo
import sys
from pathlib import Path

import yaml

PIPELINE_WINDOWS = "splunk_windows"
PIPELINE_SYSMON = "splunk_sysmon_acceleration"



def _normalize_service(rule: dict) -> str:
    ls = rule.get("logsource") or {}
    return str(ls.get("service") or "").strip().lower()


def pick_pipeline(rule: dict) -> str:
    """
    Pipeline selection:
      - service == "sysmon"     -> splunk_sysmon_acceleration
      - service == "security"   -> splunk_windows
      - anything else / missing -> NO pipeline (fallback to --without-pipeline)

    Optional override:
      custom:
        splunk_pipeline: <pipeline_name>
    """
    custom = rule.get("custom") or {}
    if isinstance(custom, dict) and custom.get("splunk_pipeline"):
        return str(custom["splunk_pipeline"]).strip()

    service = _normalize_service(rule)

    if service == "sysmon":
        return PIPELINE_SYSMON
    if service == "security":
        return PIPELINE_WINDOWS

    # everything else: no pipeline
    return ""


def output_name_for_rule(rule_path: Path) -> str:
    # rules/sigma/foo.sigma.yml -> foo.sigma.spl (always keep .sigma marker)
    name = rule_path.name
    if name.endswith(".yml"):
        name = name[:-4]
    elif name.endswith(".yaml"):
        name = name[:-5]
    if name.endswith(".sigma"):
        name = name[:-6]
    return f"{name}.sigma.spl"


def run_sigma_convert(rule_path: Path, out_path: Path, pipeline: str) -> None:
    cmd = ["sigma", "convert", "-t", "splunk"]

    # pipeline is required for some backends, but CIM pipeline is not universal.
    # For non-security/sysmon rules, we intentionally fall back to --without-pipeline.
    if pipeline:
        cmd += ["-p", pipeline]
    else:
        cmd += ["--without-pipeline"]

    cmd += [str(rule_path), "-o", str(out_path)]
    subprocess.run(cmd, check=True)


def _safe_str(v) -> str:
    return str(v).strip() if v is not None else ""


def build_ci_header(rule_path: Path, rule: dict, mode: str, pipeline: str) -> str:
    """
    Output format:
      - Everything that is NOT the SPL query is stored inside a single JSON block
        between META_START and META_END.
      - The converted SPL query follows below META_END.
    """
    # CI context
    git_sha = (os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or "").strip()
    git_ref = (os.getenv("GITHUB_REF_NAME") or "").strip()

    # Sigma file reference (or native SPL message)
    sigma_file_value = rule_path.as_posix() if rule_path and rule_path.name else (
        "No Sigma source is associated with this detection; it was authored natively as an SPL rule."
    )

    # Rule version (X.X). Prefer explicit rule_version/version fields from the YAML (or custom.splunk),
    # otherwise default to 1.0
    custom = rule.get("custom") or {}
    splunk_meta = custom.get("splunk") if isinstance(custom, dict) else None
    yaml_rule_version = _safe_str(rule.get("rule_version")) or _safe_str(rule.get("version"))
    splunk_rule_version = _safe_str(splunk_meta.get("rule_version")) if isinstance(splunk_meta, dict) else ""
    rule_version = splunk_rule_version or yaml_rule_version or "1.0"

    # Convert time in Hungary (Europe/Budapest) with offset (CET/CEST)
    convert_time = datetime.datetime.now(ZoneInfo("Europe/Budapest")).replace(microsecond=0).isoformat()

    git_sha_value = git_sha or "unknown"

    # Base Sigma meta (everything except 'detection')
    sigma_meta = {}
    for k, v in (rule or {}).items():
        if k == "detection":
            continue
        if k in ("id", "fields"):  # 'id' is redundant next to detect_id; 'fields' not needed
            continue
        sigma_meta[k] = v

    # Build ordered JSON meta:
    # title -> detect_id -> description -> sigma_file -> status -> author -> date -> modified
    # then convert_time -> rule_version -> git_sha
    # then CI fields (ci_managed/origin/convert_mode/sigma_pipeline[/git_ref])
    # then the remaining Sigma meta keys (references/tags/logsource/falsepositives/level/custom/...)
    meta = {}

    # Primary identification block
    if "title" in sigma_meta:
        meta["title"] = sigma_meta.pop("title")
    detect_id = _safe_str(sigma_meta.pop("detect_id", ""))
    if detect_id:
        meta["detect_id"] = detect_id
    if "description" in sigma_meta:
        meta["description"] = sigma_meta.pop("description")

    meta["sigma_file"] = sigma_file_value

    if "status" in sigma_meta:
        meta["status"] = sigma_meta.pop("status")

    if "author" in sigma_meta:
        meta["author"] = sigma_meta.pop("author")

    if "date" in sigma_meta:
        meta["date"] = sigma_meta.pop("date")
    if "modified" in sigma_meta:
        meta["modified"] = sigma_meta.pop("modified")

    # Enrichment fields (directly under modified/date section)
    meta["convert_time"] = convert_time
    meta["rule_version"] = rule_version
    meta["git_sha"] = git_sha_value

    # CI/conversion context (kept in JSON only)
    meta["ci_managed"] = True
    meta["origin"] = "sigma_to_spl.py"
    meta["convert_mode"] = mode
    meta["sigma_pipeline"] = pipeline or "without-pipeline"
    if git_ref:
        meta["git_ref"] = git_ref

    # Append remaining Sigma meta keys (preserve their original order)
    for k, v in sigma_meta.items():
        # Avoid accidental overwrites
        if k in meta:
            continue
        meta[k] = v

    meta_json = json.dumps(meta, ensure_ascii=False, indent=2, default=str)
    return "META_START\n" + meta_json + "\nMETA_END\n---\n"


def prepend_header(out_path: Path, header: str) -> None:
    content = out_path.read_text(encoding="utf-8")
    out_path.write_text(header + content, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("rules", nargs="+")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    failed = 0

    for rp in args.rules:
        rule_path = Path(rp)

        if not rule_path.exists():
            print(f"ERROR: Rule not found: {rule_path}", file=sys.stderr)
            failed += 1
            continue

        try:
            with rule_path.open("r", encoding="utf-8") as f:
                rule = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"ERROR: YAML parse failed for {rule_path}: {e}", file=sys.stderr)
            failed += 1
            continue

        pipeline = pick_pipeline(rule)
        out_path = outdir / output_name_for_rule(rule_path)

        mode = f"pipeline={pipeline}" if pipeline else "without-pipeline"
        service = _normalize_service(rule)

        print(f"Converting: {rule_path} -> {out_path} ({mode}, service={service or 'N/A'})")

        try:
            run_sigma_convert(rule_path, out_path, pipeline)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: sigma convert failed for {rule_path}: {e}", file=sys.stderr)
            failed += 1
            continue  # do not write header if conversion failed

        # Always prepend header AFTER successful conversion
        try:
            header = build_ci_header(rule_path, rule, mode=mode, pipeline=pipeline)
            prepend_header(out_path, header)
        except Exception as e:
            print(f"ERROR: failed writing header for {out_path}: {e}", file=sys.stderr)
            failed += 1
            continue

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())