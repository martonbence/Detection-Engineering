# scripts/convert/sigma_to_spl.py
import argparse
import os
import re
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
    # rules/sigma/foo.yml -> foo.spl (also handles legacy foo.sigma.yml -> foo.spl)
    name = rule_path.name
    if name.endswith(".yml"):
        name = name[:-4]
    elif name.endswith(".yaml"):
        name = name[:-5]
    if name.endswith(".sigma"):
        name = name[:-6]
    return f"{name}.spl"


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


def _get_splunk_index(rule: dict) -> str:
    custom = rule.get("custom") or {}
    splunk_custom = custom.get("splunk") if isinstance(custom, dict) else None
    if not isinstance(splunk_custom, dict):
        return ""
    return _safe_str(splunk_custom.get("index"))


def _get_splunk_custom(rule: dict) -> dict:
    custom = rule.get("custom") or {}
    splunk_custom = custom.get("splunk") if isinstance(custom, dict) else None
    return splunk_custom if isinstance(splunk_custom, dict) else {}


def _get_raw_query(rule: dict) -> str:
    return _safe_str(_get_splunk_custom(rule).get("raw_query"))


def _get_testing_custom(rule: dict) -> dict:
    custom = rule.get("custom") or {}
    testing_custom = custom.get("testing") if isinstance(custom, dict) else None
    return testing_custom if isinstance(testing_custom, dict) else {}


def _flatten_testing_meta(rule: dict) -> dict:
    testing_custom = _get_testing_custom(rule)
    if not testing_custom:
        return {}

    testing_meta = {}

    if "enabled" in testing_custom:
        testing_meta["testing enabled"] = testing_custom.get("enabled")

    runner = _safe_str(testing_custom.get("runner"))
    if runner:
        testing_meta["runner"] = runner

    tester = _safe_str(testing_custom.get("type"))
    if tester:
        testing_meta["tester"] = tester

    atomics = testing_custom.get("atomics")
    if isinstance(atomics, list):
        atomic_tests = []
        for atomic in atomics:
            if not isinstance(atomic, dict):
                continue

            atomic_entry = {}
            technique = _safe_str(atomic.get("technique"))
            if technique:
                atomic_entry["technique"] = technique

            test_numbers = atomic.get("test_numbers")
            if test_numbers is not None:
                atomic_entry["test_numbers"] = test_numbers

            if atomic_entry:
                atomic_tests.append(atomic_entry)

        if atomic_tests:
            testing_meta["atomic tests"] = atomic_tests

    custom_tests = testing_custom.get("custom")
    if isinstance(custom_tests, list):
        custom_test_entries = []
        for test in custom_tests:
            if not isinstance(test, dict):
                continue
            entry = {}
            for key in ("name", "description", "executor", "command", "cleanup", "prerequisites"):
                if key in test:
                    entry[key] = test[key]
            if entry:
                custom_test_entries.append(entry)
        if custom_test_entries:
            testing_meta["custom tests"] = custom_test_entries

    return testing_meta


def _inject_index_prefix(query: str, index_value: str) -> str:
    """
    Ensure SPL starts with the Sigma-defined index.

    Behavior:
      - "search <...>" -> "search index=<idx> <...>"
      - "index=<...> <...>" -> replace leading index with Sigma index
      - everything else -> prefix with "index=<idx> "
    """
    q = (query or "").strip()
    idx = _safe_str(index_value)

    if not q or not idx:
        return q

    m = re.match(r"(?i)^search\s+", q)
    if m:
        return f"search index={idx} {q[m.end():].lstrip()}"

    m = re.match(r"(?i)^index=[^\s]+\s*", q)
    if m:
        return f"index={idx} {q[m.end():].lstrip()}".rstrip()

    return f"index={idx} {q}"


def write_raw_query(out_path: Path, raw_query: str) -> None:
    out_path.write_text(raw_query.strip() + "\n", encoding="utf-8")


def enforce_index_prefix(out_path: Path, index_value: str) -> None:
    content = out_path.read_text(encoding="utf-8")
    updated = _inject_index_prefix(content, index_value)
    out_path.write_text(updated + "\n", encoding="utf-8")


def _git_commit_count_for_path(rule_path: Path) -> int:
    """
    Returns how many commits touched the given file in the current git repo,
    following renames (git log --follow) so renaming/restructuring a rule
    file never resets its version count. If git is unavailable (e.g., running
    outside a repo), returns 0.
    """
    try:
        rel = str(rule_path)
        res = subprocess.run(
            ["git", "log", "--follow", "--format=%H", "--", rel],
            check=True,
            capture_output=True,
            text=True,
        )
        lines = [l for l in res.stdout.splitlines() if l.strip()]
        return len(lines)
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


def build_meta_dict(rule_path: Path, rule: dict, deploy_mode: str, pipeline: str, is_raw_query: bool) -> dict:
    """
    Build the CI metadata dict for a rule. This is written out as a sidecar
    <name>.meta.json next to the generated <name>.spl (never merged into it) --
    it is CI-runtime metadata for the deploy/verify/atomic-runner steps, not
    something that belongs in the query file itself.
    """

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

    meta["sigma_file"] = rule_path.as_posix()

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

    # Enrichment fields
    meta["convert_time"] = convert_time
    meta["rule_version"] = rule_version
    meta["git_sha"] = git_sha_value

    # CI/conversion context
    meta["ci_managed"] = True
    meta["origin"] = "raw_query" if is_raw_query else "sigma"
    meta["sigma_pipeline"] = "raw_query" if is_raw_query else (pipeline or "without-pipeline")
    meta["deploy_mode"] = deploy_mode

    splunk_custom = _get_splunk_custom(rule)
    for key in ("index", "cron", "earliest", "latest", "severity"):
        value = _safe_str(splunk_custom.get(key))
        if value:
            meta[key] = value

    meta.update(_flatten_testing_meta(rule))

    # Append remaining Sigma meta keys (preserve their original order)
    for k, v in sigma_meta.items():
        if k in meta:
            continue
        meta[k] = v

    return meta


def write_meta_sidecar(out_path: Path, meta: dict) -> None:
    meta_path = out_path.parent / (out_path.stem + ".meta.json")
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


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
        # deploy_mode must come from the Sigma rule's custom.splunk.mode (report|alert)
        custom = rule.get("custom") or {}
        splunk_custom = _get_splunk_custom(rule)
        splunk_index = _get_splunk_index(rule)
        raw_query = _get_raw_query(rule)
        deploy_mode = ""
        if splunk_custom:
            deploy_mode = _safe_str(splunk_custom.get("mode"))
        if not deploy_mode:
            deploy_mode = _safe_str(custom.get("mode")) if isinstance(custom, dict) else ""
        if not deploy_mode:
            deploy_mode = "report"

        service = _normalize_service(rule)

        if raw_query:
            print(f"Converting: {rule_path} -> {out_path} (raw_query, mode={deploy_mode})")
            write_raw_query(out_path, raw_query)
        else:
            print_mode = f"pipeline={pipeline}" if pipeline else "without-pipeline"
            print(f"Converting: {rule_path} -> {out_path} ({print_mode}, service={service or 'N/A'}, mode={deploy_mode})")

            try:
                run_sigma_convert(rule_path, out_path, pipeline)
            except subprocess.CalledProcessError as e:
                print(f"ERROR: sigma convert failed for {rule_path}: {e}", file=sys.stderr)
                failed += 1
                continue  # do not write meta if conversion failed

        # Burn Sigma custom.splunk.index into the beginning of the generated SPL query
        try:
            enforce_index_prefix(out_path, splunk_index)
        except Exception as e:
            print(f"ERROR: failed applying index prefix for {out_path}: {e}", file=sys.stderr)
            failed += 1
            continue

        # Always write the meta sidecar AFTER successful query generation
        try:
            meta = build_meta_dict(rule_path, rule, deploy_mode, pipeline, is_raw_query=bool(raw_query))
            write_meta_sidecar(out_path, meta)
        except Exception as e:
            print(f"ERROR: failed writing meta sidecar for {out_path}: {e}", file=sys.stderr)
            failed += 1
            continue

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
