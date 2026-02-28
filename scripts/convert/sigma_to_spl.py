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


def _git_commit_count_for_path(rule_path: Path) -> int:
    """
    Returns how many commits touched the given file in the current git repo.
    If git is unavailable (e.g., running outside a repo), returns 0.
    """
    try:
        # Use relative path for git, but fall back to absolute if needed.
        rel = str(rule_path)
        # 'git rev-list --count HEAD -- <path>'
        res = subprocess.run(
            ["git", "rev-list", "--count", "HEAD", "--", rel],
            check=True,
            capture_output=True,
            text=True,
        )
        return int(res.stdout.strip() or "0")
    except Exception:
        return 0


def _compute_rule_version(rule_path: Path) -> str:
    """
    Rule versioning scheme:
      - First commit of the file -> 1.0
      - Second commit -> 1.1
      - Third commit -> 1.2
    Derived from commit count for the file. If unavailable, defaults to 1.0.
    """
    cnt = _git_commit_count_for_path(rule_path)
    minor = max(0, cnt - 1)
    return f"1.{minor}"


def _format_meta_json_with_spacing(meta: dict) -> str:
    """
    JSON is still valid with extra blank lines. We insert a few empty lines for readability:
      - after "modified"
      - before "references"
      - before "tags"
      - before and after "logsource"
    """
    raw = json.dumps(meta, ensure_ascii=False, indent=2, default=str)
    lines = raw.splitlines()

    out = []
    inside_logsource = False
    depth = 0

    for i, line in enumerate(lines):
        stripped = line.lstrip()

        # blank line before logsource
        if stripped.startswith('"logsource":') or stripped.startswith('"logsource" :'):
            if out and out[-1] != "":
                out.append("")
            inside_logsource = True
            depth = 0  # will be updated below

        # blank line before references
        if stripped.startswith('"references":') or stripped.startswith('"references" :'):
            if out and out[-1] != "":
                out.append("")

        # blank line before tags
        if stripped.startswith('"tags":') or stripped.startswith('"tags" :'):
            if out and out[-1] != "":
                out.append("")

        out.append(line)

        # blank line after modified
        if stripped.startswith('"modified":'):
            out.append("")

        # Track logsource object depth to add blank line after it ends
        if inside_logsource:
            depth += line.count("{") - line.count("}")
            # When we reach the end of the logsource object, depth will hit 0
            # after consuming the closing brace line.
            if depth == 0:
                inside_logsource = False
                out.append("")

    # Remove trailing blank lines right before closing brace if any
    # (keep JSON clean-looking)
    while len(out) > 1 and out[-1] == "" and out[-2].strip() == "}":
        out.pop(-1)

    return "\n".join(out)


def build_ci_header(rule_path: Path, rule: dict, convert_mode: str, pipeline: str) -> str:
    """
    Output format:
      - Everything that is NOT the SPL query is stored inside a single JSON block
        between META_START and META_END.
      - The converted SPL query follows below META_END (after a '---' delimiter).
    """

    # Sigma file reference (or native SPL message)
    sigma_file_value = rule_path.as_posix() if rule_path and rule_path.name else (
        "No Sigma source is associated with this detection; it was authored natively as an SPL rule."
    )

    # Rule version derived from git commit count (1.0, 1.1, 1.2, ...)
    rule_version = _compute_rule_version(rule_path)

    # Convert time in Hungary (Europe/Budapest) with offset (CET/CEST)
    convert_time = datetime.datetime.now(ZoneInfo("Europe/Budapest")).replace(microsecond=0).isoformat()

    # CI context
    git_sha = (os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or "").strip()
    git_sha_value = git_sha or "unknown"

    # Sigma meta (everything except 'detection' and keys we don't want to carry)
    sigma_meta = {}
    for k, v in (rule or {}).items():
        if k == "detection":
            continue
        if k in ("id", "fields", "custom"):  # id redundant; fields not needed; custom omitted at end
            continue
        sigma_meta[k] = v

    # Build ordered JSON meta:
    # title -> detect_id -> description -> sigma_file -> level -> status -> author -> date -> modified
    meta = {}

    if "title" in sigma_meta:
        meta["title"] = sigma_meta.pop("title")

    detect_id = _safe_str(sigma_meta.pop("detect_id", ""))
    if detect_id:
        meta["detect_id"] = detect_id

    if "description" in sigma_meta:
        meta["description"] = sigma_meta.pop("description")

    meta["sigma_file"] = sigma_file_value

    if "level" in sigma_meta:
        meta["level"] = sigma_meta.pop("level")

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
    meta["convert_mode"] = convert_mode
    meta["sigma_pipeline"] = pipeline or "without-pipeline"

    # Append remaining Sigma meta keys (preserve their original order)
    for k, v in sigma_meta.items():
        if k in meta:
            continue
        meta[k] = v

    meta_json = _format_meta_json_with_spacing(meta)
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
        # convert_mode must come from the Sigma rule's custom.splunk.mode (report|alert)
        custom = rule.get("custom") or {}
        splunk_custom = custom.get("splunk") if isinstance(custom, dict) else None
        convert_mode = ""
        if isinstance(splunk_custom, dict):
            convert_mode = _safe_str(splunk_custom.get("mode"))
        if not convert_mode:
            convert_mode = _safe_str(custom.get("mode")) if isinstance(custom, dict) else ""
        if not convert_mode:
            convert_mode = "alert"

        service = _normalize_service(rule)
        print_mode = f"pipeline={pipeline}" if pipeline else "without-pipeline"

        print(f"Converting: {rule_path} -> {out_path} ({print_mode}, service={service or 'N/A'}, mode={convert_mode})")

        try:
            run_sigma_convert(rule_path, out_path, pipeline)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: sigma convert failed for {rule_path}: {e}", file=sys.stderr)
            failed += 1
            continue  # do not write header if conversion failed

        # Always prepend header AFTER successful conversion
        try:
            header = build_ci_header(rule_path, rule, convert_mode, pipeline)
            prepend_header(out_path, header)
        except Exception as e:
            print(f"ERROR: failed writing header for {out_path}: {e}", file=sys.stderr)
            failed += 1
            continue

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())