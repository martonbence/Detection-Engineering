param(
    [Parameter(Mandatory = $true)]
    [string[]]$SplFiles,

    [string]$Runner = $(if ($env:ATOMIC_RUNNER) { $env:ATOMIC_RUNNER } else { "linux-victim" }),

    # Unlike run_atomic.ps1's Windows default, there is no single well-known
    # install path for Invoke-AtomicRedTeam on Linux -- it is a PowerShell
    # module (this script itself only runs because pwsh is installed on
    # linux-victim; Invoke-AtomicRedTeam is cross-platform PowerShell, not a
    # native Linux tool) and where it lands depends on how it was installed
    # (Install-Module scope, $env:PSModulePath). Left empty by default so
    # Import-AtomicModule below falls back to name-based auto-discovery,
    # exactly like run_atomic.ps1 does when its own explicit path is unset or
    # missing -- an explicit path is only used when one is actually configured.
    [string]$DefaultModulePath = $(if ($env:ATOMIC_RED_TEAM_MODULE_PATH_LINUX) { $env:ATOMIC_RED_TEAM_MODULE_PATH_LINUX } else { "" }),

    [string]$AtomicsPath = $(if ($env:ATOMIC_RED_TEAM_PATH_LINUX) { $env:ATOMIC_RED_TEAM_PATH_LINUX } else { "" }),

    [string]$TesterType = $(if ($env:ATOMIC_TESTER_TYPE) { $env:ATOMIC_TESTER_TYPE } else { "" }),

    [string]$ProgressDir = $(if ($env:ATOMIC_PROGRESS_DIR) { $env:ATOMIC_PROGRESS_DIR } else { "outputs/verify/atomic_progress" }),

    # Same reasoning as run_atomic.ps1: on by default so a self-hosted runner
    # reused across pipeline runs doesn't accumulate atomic artefacts.
    [string]$SkipCleanup = $(if ($env:ATOMIC_SKIP_CLEANUP) { $env:ATOMIC_SKIP_CLEANUP } else { "false" }),

    [string]$SkipPrereqs = $(if ($env:ATOMIC_SKIP_PREREQS) { $env:ATOMIC_SKIP_PREREQS } else { "false" }),

    # Same 900s default and same reasoning as run_atomic.ps1's -TimeoutSeconds
    # -- kept in sync rather than re-derived so a multi-target atomic behaves
    # the same on either OS unless a rule's metadata says otherwise.
    [int]$TimeoutSeconds = $(if ($env:ATOMIC_TEST_TIMEOUT_SECONDS) { [int]$env:ATOMIC_TEST_TIMEOUT_SECONDS } else { 900 }),

    [switch]$PreflightOnly,

    [switch]$ShowDetails,

    [switch]$DryRun
)

<#
.SYNOPSIS
    Linux counterpart to run_atomic.ps1 (windows-victim / windows-dc).

.DESCRIPTION
    Same contract as run_atomic.ps1, deliberately kept in lockstep with it:
    read the deployed SPL bundle's embedded .meta.json sidecars, filter by
    an exact (tester type, runner) match against $TesterType/$Runner, invoke
    Atomic Red Team (or a rule's custom emulation command) for each matched
    test, and flush the same {"detect_id","status","tester","updated_at"}
    JSON progress markers to $ProgressDir that pass_fail_eval.py and
    wait_for_indexing.py already read regardless of which OS produced them --
    neither script cares what wrote the marker, only that it exists and says
    "completed".

    Deliberately NOT a from-scratch reimplementation of the metadata-parsing
    logic: doing that in a second language would give this pipeline two
    parsers of the same meta.json shape that could quietly drift apart (the
    exact failure mode check_test_routing.py's header comment warns about for
    routing -- one canonical reader, not two). This runs under `pwsh` (this
    script is PowerShell, executed via the `pwsh` shell keyword, not
    Windows PowerShell) specifically so it can share Invoke-AtomicTestCompat's
    parameter-compat logic and the exact marker-writing code path with
    run_atomic.ps1 line for line, rather than reinventing both against a
    Python/bash reading of the same JSON.

    What is intentionally NOT ported from run_atomic.ps1: everything Defender-
    related (Register-DefenderRestoreFailsafe, Disable/Enable-
    DefenderRealtimeIfRequested, the scheduled-task failsafe). Microsoft
    Defender does not exist on Linux, so there is nothing there to disable or
    to guard the re-enable of. If linux-victim ever needs an equivalent
    "temporarily relax detection tooling for the attack window" step (e.g.
    auditd rule suspension, an EDR agent), that would be a new,
    Linux-specific mechanism -- not a translation of the Defender one -- and
    is out of scope here until a rule actually needs it.
#>

$ErrorActionPreference = "Stop"

function Read-MetaFromSplFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "SPL file not found: $Path"
    }

    $metaPath = [System.IO.Path]::ChangeExtension($Path, ".meta.json")
    if (-not (Test-Path -LiteralPath $metaPath)) {
        throw "Meta sidecar not found: $metaPath"
    }

    $content = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8
    return $content | ConvertFrom-Json
}

function ConvertTo-Bool {
    param($Value)

    if ($Value -is [bool]) {
        return $Value
    }

    if ($null -eq $Value) {
        return $false
    }

    return @("true", "1", "yes", "y", "on") -contains $Value.ToString().Trim().ToLowerInvariant()
}

function ConvertTo-SafeMarkerName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DetectId
    )

    # Must stay byte-for-byte the same transform as run_atomic.ps1's (and
    # pass_fail_eval.py's _sanitize_marker_name, which exists specifically to
    # mirror this) -- pass_fail_eval.py reads whichever OS's job produced the
    # marker without knowing which one it was, so the three have to agree.
    return [regex]::Replace($DetectId, '[^A-Za-z0-9_.-]', '_')
}

function Write-AtomicProgressMarker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProgressDir,

        [Parameter(Mandatory = $true)]
        [string]$DetectId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("started", "completed")]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [ValidateSet("atomic", "emulation")]
        [string]$Tester = "atomic"
    )

    if (-not (Test-Path -LiteralPath $ProgressDir)) {
        New-Item -ItemType Directory -Path $ProgressDir -Force | Out-Null
    }

    $safeName = ConvertTo-SafeMarkerName -DetectId $DetectId
    $markerPath = Join-Path $ProgressDir "$safeName.json"

    $payload = [ordered]@{
        detect_id  = $DetectId
        status     = $Status
        tester     = $Tester
        updated_at = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json -Compress

    # Same synchronous, unbuffered write as run_atomic.ps1 -- this step also
    # carries a GitHub Actions timeout-minutes, so whatever is on disk at the
    # moment of a hard kill has to already be the ground truth.
    [System.IO.File]::WriteAllText($markerPath, $payload)
}

function Import-AtomicModule {
    param(
        [string]$ModulePath
    )

    if ($ModulePath -and (Test-Path -LiteralPath $ModulePath)) {
        Write-Host "Importing Invoke-AtomicRedTeam module from explicit path: $ModulePath"
        Import-Module -Name $ModulePath -Force -ErrorAction Stop
        return
    }

    Write-Host "Importing Invoke-AtomicRedTeam module by name (auto-discovery via `$env:PSModulePath)."
    Import-Module -Name Invoke-AtomicRedTeam -Force -ErrorAction Stop
}

function Test-AtomicPrerequisite {
    param(
        [string]$ModulePath,
        [string]$AtomicsFolder
    )

    Write-Host "Running Atomic preflight checks (Linux)."

    if ($ModulePath) {
        if (Test-Path -LiteralPath $ModulePath) {
            Write-Host "Module path exists: $ModulePath"
        }
        else {
            Write-Warning "Configured module path does not exist: $ModulePath"
        }
    }
    else {
        Write-Host "No explicit module path configured. Falling back to module auto-discovery."
    }

    if ($AtomicsFolder) {
        if (Test-Path -LiteralPath $AtomicsFolder) {
            Write-Host "Atomics folder exists: $AtomicsFolder"
        }
        else {
            throw "Configured ATOMIC_RED_TEAM_PATH_LINUX does not exist: $AtomicsFolder"
        }
    }
    else {
        Write-Host "No explicit atomics folder configured."
    }

    # No Defender-equivalent status check here -- see the file header comment.

    Import-AtomicModule -ModulePath $ModulePath

    $cmd = Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Invoke-AtomicTest command is not available after module import."
    }

    Write-Host "Invoke-AtomicTest command is available."
}

function Invoke-AtomicTestCompat {
    # Identical to run_atomic.ps1's function of the same name -- the
    # parameter-compat logic (older/newer Invoke-AtomicTest signatures) is an
    # Invoke-AtomicRedTeam-module concern, not an OS concern, so there is
    # nothing Linux-specific to change here.
    param(
        [Parameter(Mandatory = $true)]
        [string]$Technique,

        [Parameter(Mandatory = $true)]
        [int[]]$TestNumbers,

        [string]$AtomicsFolder,

        [ValidateSet("Run", "GetPrereqs", "Cleanup")]
        [string]$Mode = "Run",

        [switch]$ShowDetails,

        [int]$TimeoutSeconds = 0,

        [switch]$DryRun
    )

    $cmd = Get-Command Invoke-AtomicTest -ErrorAction Stop
    $parameters = $cmd.Parameters

    $invokeParams = @{
        TestNumbers = $TestNumbers
    }

    if ($parameters.ContainsKey("Confirm")) {
        $invokeParams["Confirm"] = $false
    }

    if ($Mode -ne "Run") {
        if (-not $parameters.ContainsKey($Mode)) {
            Write-Warning "Installed Invoke-AtomicTest has no -$Mode parameter; skipping the $Mode pass for $Technique test $($TestNumbers -join ',')."
            return
        }
        $invokeParams[$Mode] = $true
    }

    if ($Mode -eq "Run") {
        if ($parameters.ContainsKey("ShowDetails")) {
            if ($ShowDetails.IsPresent) {
                $invokeParams["ShowDetails"] = $true
            }
        }
        elseif ($parameters.ContainsKey("ShowDetailsBrief")) {
            if ($ShowDetails.IsPresent) {
                $invokeParams["ShowDetails"] = $true
            }
            else {
                $invokeParams["ShowDetailsBrief"] = $true
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($AtomicsFolder) -and $parameters.ContainsKey("PathToAtomicsFolder")) {
        $invokeParams["PathToAtomicsFolder"] = $AtomicsFolder
    }

    if ($Mode -eq "Run" -and $TimeoutSeconds -gt 0 -and $parameters.ContainsKey("TimeoutSeconds")) {
        $invokeParams["TimeoutSeconds"] = $TimeoutSeconds
    }

    if ($DryRun.IsPresent) {
        Write-Host "Resolved Invoke-AtomicTest invocation ($Mode):"
        Write-Host "  Technique = $Technique"
        $invokeParams.GetEnumerator() | Sort-Object Key | ForEach-Object {
            Write-Host ("  {0} = {1}" -f $_.Key, $_.Value)
        }
        return
    }

    if ($parameters.ContainsKey("Technique")) {
        & $cmd -Technique $Technique @invokeParams
        return
    }

    if ($parameters.ContainsKey("AtomicTechnique")) {
        & $cmd -AtomicTechnique $Technique @invokeParams
        return
    }

    & $cmd $Technique @invokeParams
}

$normalizedRunner = $Runner.Trim().ToLowerInvariant()
$collected = [ordered]@{}
$collectedCustom = [System.Collections.Generic.List[pscustomobject]]::new()
$matchedFiles = 0

$detectIdTestKeys = @{}
$detectIdCustomKeys = @{}
$testKeyToDetectIds = @{}
$malformed = 0

foreach ($splFile in $SplFiles) {
    try {
        $meta = Read-MetaFromSplFile -Path $splFile
    }
    catch {
        $malformed++
        Write-Warning "Skipping $splFile : $($_.Exception.Message)"
        continue
    }

    $detectId = [string]$meta.detect_id
    if ([string]::IsNullOrWhiteSpace($detectId)) {
        $detectId = [System.IO.Path]::GetFileNameWithoutExtension($splFile)
    }

    if (-not (ConvertTo-Bool $meta.'testing enabled')) {
        Write-Host "Skipping $splFile : testing is disabled"
        continue
    }

    $metaRunner = [string]$meta.runner
    if (-not [string]::IsNullOrWhiteSpace($normalizedRunner) -and $metaRunner.Trim().ToLowerInvariant() -ne $normalizedRunner) {
        Write-Host "Skipping $splFile : runner mismatch ($metaRunner)"
        continue
    }

    $tester = [string]$meta.tester

    if (-not [string]::IsNullOrWhiteSpace($TesterType) -and $tester.Trim().ToLowerInvariant() -ne $TesterType.Trim().ToLowerInvariant()) {
        Write-Host "Skipping $splFile : tester type filter (expected $TesterType, got $tester)"
        continue
    }

    if ($tester.Trim().ToLowerInvariant() -eq "emulation") {
        if ($null -eq $meta.'custom tests' -or $meta.'custom tests'.Count -eq 0) {
            $malformed++
            Write-Warning "Skipping $splFile : tester is 'emulation' but no custom tests are defined."
            continue
        }

        $matchedFiles++
        Write-Host "Collected custom emulation tests from $splFile"

        if (-not $detectIdCustomKeys.Contains($detectId)) {
            $detectIdCustomKeys[$detectId] = [System.Collections.Generic.HashSet[string]]::new()
        }

        $customIndex = 0
        foreach ($test in $meta.'custom tests') {
            $customKey = "$detectId|$customIndex"
            [void]$detectIdCustomKeys[$detectId].Add($customKey)

            $collectedCustom.Add([pscustomobject]@{
                Name          = [string]$test.name
                Executor      = [string]$test.executor
                Command       = [string]$test.command
                Cleanup       = [string]$test.cleanup
                Prerequisites = $test.prerequisites
                DetectId      = $detectId
                CustomKey     = $customKey
            })
            $customIndex++
        }
        continue
    }

    if ($tester.Trim().ToLowerInvariant() -ne "atomic") {
        Write-Host "Skipping $splFile : tester is not atomic or emulation"
        continue
    }

    if ($null -eq $meta.'atomic tests' -or $meta.'atomic tests'.Count -eq 0) {
        $malformed++
        Write-Warning "Skipping $splFile : tester is 'atomic' but no atomic tests are defined."
        continue
    }

    $matchedFiles++
    Write-Host "Collected atomic mappings from $splFile"

    if (-not $detectIdTestKeys.Contains($detectId)) {
        $detectIdTestKeys[$detectId] = New-Object System.Collections.Generic.HashSet[string]
    }

    foreach ($atomic in $meta.'atomic tests') {
        $technique = ([string]$atomic.technique).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($technique)) {
            $malformed++
            Write-Warning "Skipping one atomic entry in $splFile : technique is missing."
            continue
        }

        if (-not $collected.Contains($technique)) {
            $collected[$technique] = New-Object System.Collections.Generic.HashSet[int]
        }

        foreach ($testNumber in $atomic.test_numbers) {
            [void]$collected[$technique].Add([int]$testNumber)

            $testKey = "$technique|$testNumber"
            [void]$detectIdTestKeys[$detectId].Add($testKey)

            if (-not $testKeyToDetectIds.Contains($testKey)) {
                $testKeyToDetectIds[$testKey] = New-Object System.Collections.Generic.HashSet[string]
            }
            [void]$testKeyToDetectIds[$testKey].Add($detectId)
        }
    }
}

if ($malformed -gt 0) {
    Write-Warning "$malformed rule(s)/entry(ies) were skipped because their test metadata was unusable."
    Write-Host "::warning title=Unusable atomic test metadata::$malformed rule(s)/entry(ies) were skipped; they will report as not verified rather than failing the batch."
}

if ($matchedFiles -eq 0) {
    if ($malformed -gt 0) {
        Write-Warning "No usable tests found for the selected runner: all $malformed candidate rule(s) had unusable test metadata."
        Write-Host "::error title=No usable atomic tests::Every candidate rule for this runner had unusable test metadata."
        exit 1
    }

    Write-Host "No matching tests found for the selected runner."
    exit 0
}

if ($collected.Count -gt 0) {
    Test-AtomicPrerequisite -ModulePath $DefaultModulePath -AtomicsFolder $AtomicsPath
}

if ($PreflightOnly.IsPresent) {
    Write-Host "Preflight completed successfully."
    exit 0
}

# Same reasoning as run_atomic.ps1: self-hosted runners reuse the same
# workspace across runs with no checkout/clean step, so start every real run
# from a clean progress directory.
if (Test-Path -LiteralPath $ProgressDir) {
    Write-Host "Clearing stale progress markers from a previous run in $ProgressDir"
    Get-ChildItem -LiteralPath $ProgressDir -Filter "*.json" -File | Remove-Item -Force
}

$markedRules = $detectIdTestKeys.Count + $detectIdCustomKeys.Count
Write-Host "Writing 'started' progress markers for $markedRules tested rule(s) to $ProgressDir"
foreach ($dId in $detectIdTestKeys.Keys) {
    Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $dId -Status "started"
}
foreach ($dId in $detectIdCustomKeys.Keys) {
    Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $dId -Status "started" -Tester "emulation"
}

$remainingTestKeys = @{}
foreach ($dId in $detectIdTestKeys.Keys) {
    $remainingTestKeys[$dId] = [System.Collections.Generic.HashSet[string]]::new($detectIdTestKeys[$dId])
}

$remainingCustomKeys = @{}
foreach ($dId in $detectIdCustomKeys.Keys) {
    $remainingCustomKeys[$dId] = [System.Collections.Generic.HashSet[string]]::new($detectIdCustomKeys[$dId])
}

$failures = 0
$skipCleanupResolved = ConvertTo-Bool $SkipCleanup
$skipPrereqsResolved = ConvertTo-Bool $SkipPrereqs

if ($skipPrereqsResolved) {
    Write-Warning "Atomic prerequisite setup (-GetPrereqs) is disabled; tests with unmet prerequisites may report a false FAIL."
}
if ($skipCleanupResolved) {
    Write-Warning "Atomic cleanup (-Cleanup) is disabled; test artifacts will accumulate on this runner between runs."
}

# No Defender-equivalent disable/restore wrapping here -- see the file header
# comment for why. The test loop itself is otherwise identical to
# run_atomic.ps1's, deliberately, so a difference in verdicts between a
# Windows-tested and a Linux-tested rule cannot be traced to divergent
# execution logic here.
foreach ($technique in $collected.Keys) {
    $testNumbers = @($collected[$technique] | Sort-Object)

    foreach ($testNum in $testNumbers) {
        Write-Host "Invoking Atomic Red Team: $technique test [$testNum]"

        if (-not $skipPrereqsResolved) {
            try {
                Invoke-AtomicTestCompat `
                    -Technique $technique `
                    -TestNumbers @($testNum) `
                    -AtomicsFolder $AtomicsPath `
                    -Mode "GetPrereqs" `
                    -DryRun:$DryRun.IsPresent
            }
            catch {
                Write-Warning "Prerequisite setup failed for $technique test $testNum : $($_.Exception.Message)"
            }
        }

        try {
            Invoke-AtomicTestCompat `
                -Technique $technique `
                -TestNumbers @($testNum) `
                -AtomicsFolder $AtomicsPath `
                -Mode "Run" `
                -ShowDetails:$ShowDetails.IsPresent `
                -TimeoutSeconds $TimeoutSeconds `
                -DryRun:$DryRun.IsPresent
        }
        catch {
            $failures++
            Write-Warning "Atomic execution failed for $technique test $testNum : $($_.Exception.Message)"
        }
        finally {
            if (-not $skipCleanupResolved) {
                try {
                    Invoke-AtomicTestCompat `
                        -Technique $technique `
                        -TestNumbers @($testNum) `
                        -AtomicsFolder $AtomicsPath `
                        -Mode "Cleanup" `
                        -DryRun:$DryRun.IsPresent
                }
                catch {
                    Write-Warning "Cleanup failed for $technique test $testNum : $($_.Exception.Message)"
                }
            }
        }

        $testKey = "$technique|$testNum"
        if ($testKeyToDetectIds.Contains($testKey)) {
            foreach ($dId in $testKeyToDetectIds[$testKey]) {
                if ($remainingTestKeys.Contains($dId)) {
                    [void]$remainingTestKeys[$dId].Remove($testKey)
                    if ($remainingTestKeys[$dId].Count -eq 0) {
                        Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $dId -Status "completed"
                    }
                }
            }
        }
    }
}

foreach ($test in $collectedCustom) {
    Write-Host "Running custom emulation test: $($test.Name)"

    if ($test.Prerequisites) {
        Write-Host "Prerequisites: $($test.Prerequisites -join ', ')"
    }

    try {
        if ($DryRun.IsPresent) {
            Write-Host "DryRun: Would execute ($($test.Executor)): $($test.Command)"
        }
        else {
            # "cmd" as a custom-test executor is a Windows-only concept (see
            # run_atomic.ps1); on Linux every custom test is run the same way
            # regardless of the executor label a rule's metadata carries,
            # since pySigma/the meta sidecar do not currently distinguish
            # "sh"/"bash" from a bare shell command the way Windows
            # distinguishes cmd.exe from PowerShell.
            Invoke-Expression $test.Command
        }
    }
    catch {
        $failures++
        Write-Warning "Custom test failed '$($test.Name)': $($_.Exception.Message)"
    }
    finally {
        $cleanupCmd = $test.Cleanup
        if (-not [string]::IsNullOrWhiteSpace($cleanupCmd) -and $cleanupCmd -ne "~") {
            Write-Host "Running cleanup for: $($test.Name)"
            try {
                if (-not $DryRun.IsPresent) {
                    Invoke-Expression $cleanupCmd
                }
            }
            catch {
                Write-Warning "Cleanup failed for '$($test.Name)': $($_.Exception.Message)"
            }
        }

        if ($test.DetectId -and $remainingCustomKeys.Contains($test.DetectId)) {
            [void]$remainingCustomKeys[$test.DetectId].Remove($test.CustomKey)
            if ($remainingCustomKeys[$test.DetectId].Count -eq 0) {
                Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $test.DetectId -Status "completed" -Tester "emulation"
            }
        }
    }
}

if ($failures -gt 0) {
    exit 2
}

Write-Host "All tests completed successfully."
