<#  scripts/validate/validate_sigma.ps1

Improvements implemented (1..10):
1) Single Python run for all rules (no per-file process spawn)
2) Reliable stdout/stderr visibility (call operator &, optional transcript)
3) Deleted rule handling (log + skip)
4) Path normalization (\ -> /) for cross-platform git outputs
5) Clear schema JSON parse errors (handled in python)
6) Empty/None YAML detection (handled in python)
7) Max errors parameter ($MaxErrors)
8) End-of-run summary (validated/ok/invalid/skipped/deleted)
9) Python dependency preflight check (handled in python)
10) Python moved to separate file validate_sigma.py (maintainable)

#>

param(
  [Parameter(Mandatory = $false)]
  [string]$SchemaPath = "docs/schemas/schema.json",

  [Parameter(Mandatory = $false)]
  [string[]]$Files = @(),

  [Parameter(Mandatory = $false)]
  [int]$MaxErrors = 25,

  # If set, fail the run if a deleted rules/*.yml is detected
  [Parameter(Mandatory = $false)]
  [switch]$FailOnDeleted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
  # scripts/validate/validate_sigma.ps1 -> repo root: ../../
  return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function Normalize-RepoPath([string]$p) {
  # normalize to forward slashes (git diff output can vary)
  return ($p -replace '\\','/').Trim()
}

$RepoRoot   = Resolve-RepoRoot
$SchemaFull = Join-Path $RepoRoot $SchemaPath
$PyScript   = Join-Path $PSScriptRoot "validate_sigma.py"

if (-not (Test-Path -LiteralPath $SchemaFull)) {
  Write-Error "Schema not found: $SchemaFull"
  exit 2
}

if (-not (Test-Path -LiteralPath $PyScript)) {
  Write-Error "Python validator not found: $PyScript"
  exit 2
}

# If no files were passed, nothing to validate (workflow passes changed files)
if ($Files.Count -eq 0) {
  Write-Host "No changed files provided -> skipping Sigma validation."
  exit 0
}

# Python availability pre-check (clear error early)
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
  Write-Error "python executable not found on PATH."
  exit 2
}

$RuleFilesAbs   = New-Object System.Collections.Generic.List[string]
$DeletedRules   = New-Object System.Collections.Generic.List[string]
$SkippedNonRule = New-Object System.Collections.Generic.List[string]
$SkippedMissing = New-Object System.Collections.Generic.List[string]

foreach ($fRaw in $Files) {
  if ([string]::IsNullOrWhiteSpace($fRaw)) { continue }

  $f = Normalize-RepoPath $fRaw

  # Only validate rules/*.yml|yaml
  if ($f -notmatch '^rules/.*\.(yml|yaml)$') {
    $SkippedNonRule.Add($f) | Out-Null
    continue
  }

  $full = Join-Path $RepoRoot $f
  if (-not (Test-Path -LiteralPath $full)) {
    # Treat as deleted/missing in workspace (deleted or not checked out)
    $DeletedRules.Add($f) | Out-Null
    $SkippedMissing.Add($f) | Out-Null
    continue
  }

  $RuleFilesAbs.Add((Resolve-Path -LiteralPath $full).Path) | Out-Null
}

if ($DeletedRules.Count -gt 0) {
  Write-Host "Detected deleted/missing rule files (skipping validation for these):"
  foreach ($d in $DeletedRules) { Write-Host "  - $d" }

  if ($FailOnDeleted) {
    Write-Error "FailOnDeleted is set and deleted/missing rules were detected."
    exit 1
  }
}

if ($RuleFilesAbs.Count -eq 0) {
  Write-Host "No existing changed Sigma rule files to validate -> skipping."
  exit 0
}

Write-Host ""
Write-Host "=== Sigma rules to validate (changed + filtered) ==="
foreach ($rf in $RuleFilesAbs) {
  # print repo-relative if you want nicer output:
  $rel = $rf.Replace($RepoRoot, "").TrimStart("\","/")
  Write-Host " - $rel"
}
Write-Host "==============================================="
Write-Host ""


# Run one Python process for all rule files
$schemaPathAbs = (Resolve-Path -LiteralPath $SchemaFull).Path

# Build args: validate_sigma.py --schema <schema> --max-errors <n> <rule1> <rule2> ...
$pyArgs = @(
  $PyScript,
  "--schema", $schemaPathAbs,
  "--max-errors", "$MaxErrors"
) + @($RuleFilesAbs)

Write-Host "Validating $($RuleFilesAbs.Count) changed rule(s) against schema: $SchemaPath"
Write-Host "Python: $($pythonCmd.Source)"
Write-Host "Max errors per rule: $MaxErrors"

# Call operator (&) reliably streams stdout/stderr into CI logs
& python @pyArgs
$exit = $LASTEXITCODE

if ($exit -ne 0) {
  Write-Error "Schema validation failed. Python exit code: $exit"
  exit 1
}

Write-Host "All changed rules are valid."
exit 0
