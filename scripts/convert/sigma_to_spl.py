# scripts/convert/sigma_to_spl.py
import argparse
import os
import subprocess
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
    Header is intentionally comments only.
    Deploy script will strip leading '#' lines before sending SPL to Splunk.
    """
    sigma_id = _safe_str(rule.get("id"))
    detect_id = _safe_str(rule.get("detect_id"))
    title = _safe_str(rule.get("title"))
    description = _safe_str(rule.get("description"))
    status = _safe_str(rule.get("status"))
    date = _safe_str(rule.get("date"))
    modified = _safe_str(rule.get("modified"))
    service = _normalize_service(rule) or "N/A"

    git_sha = (os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or "").strip()
    git_ref = (os.getenv("GITHUB_REF_NAME") or "").strip()

    lines = [
        "# CI-MANAGED: true",
        "# ORIGIN: sigma_to_spl.py",
        f"# SIGMA_FILE: {rule_path.as_posix()}",
        f"# SIGMA_ID: {sigma_id}",
        f"# DETECT_ID: {detect_id}",
        f"# SIGMA_TITLE: {title}",
        f"# SIGMA_DESCRIPTION: {description}",
        f"# SIGMA_STATUS: {status}",
        f"# SIGMA_DATE: {date}",
        f"# SIGMA_MODIFIED: {modified}",
        f"# LOGSOURCE_SERVICE: {service}",
        f"# CONVERT_MODE: {mode}",
        f"# SIGMA_PIPELINE: {pipeline or 'without-pipeline'}",
    ]

    if git_sha:
        lines.append(f"# GIT_SHA: {git_sha}")
    if git_ref:
        lines.append(f"# GIT_REF: {git_ref}")

    custom = rule.get("custom") or {}
    splunk_meta = custom.get("splunk") if isinstance(custom, dict) else None
    if isinstance(splunk_meta, dict):
        mode_v = _safe_str(splunk_meta.get("mode"))
        cron_v = _safe_str(splunk_meta.get("cron"))
        earliest_v = _safe_str(splunk_meta.get("earliest"))
        latest_v = _safe_str(splunk_meta.get("latest"))
        sev_v = _safe_str(splunk_meta.get("severity"))

        if mode_v:
            lines.append(f"# SPLUNK_MODE: {mode_v}")
        if cron_v:
            lines.append(f"# SPLUNK_CRON: {cron_v}")
        if earliest_v:
            lines.append(f"# SPLUNK_EARLIEST: {earliest_v}")
        if latest_v:
            lines.append(f"# SPLUNK_LATEST: {latest_v}")
        if sev_v:
            lines.append(f"# SPLUNK_SEVERITY: {sev_v}")

    lines.append("# ---")
    return "\n".join(lines) + "\n"


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
