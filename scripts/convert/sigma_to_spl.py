# scripts/convert/sigma_to_spl.py
import argparse
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
    # rules/sigma/foo.sigma.yml -> foo.spl
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

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
