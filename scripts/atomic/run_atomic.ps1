param(
    [Parameter(Mandatory = $true)]
    [string[]]$SplFiles,

    [string]$Runner = $(if ($env:ATOMIC_RUNNER) { $env:ATOMIC_RUNNER } else { "windows-victim" }),

    [string]$DefaultModulePath = $(if ($env:ATOMIC_RED_TEAM_MODULE_PATH) { $env:ATOMIC_RED_TEAM_MODULE_PATH } else { "C:\Program Files\WindowsPowerShell\Modules\Invoke-AtomicRedTeam\2.3.0\Invoke-AtomicRedTeam.psd1" }),

    [string]$AtomicsPath = $(if ($env:ATOMIC_RED_TEAM_PATH) { $env:ATOMIC_RED_TEAM_PATH } else { "" }),

    [string]$DisableDefender = $(if ($env:ATOMIC_DISABLE_REALTIME_MONITORING) { $env:ATOMIC_DISABLE_REALTIME_MONITORING } else { "false" }),

    [string]$TesterType = $(if ($env:ATOMIC_TESTER_TYPE) { $env:ATOMIC_TESTER_TYPE } else { "" }),

    [string]$ProgressDir = $(if ($env:ATOMIC_PROGRESS_DIR) { $env:ATOMIC_PROGRESS_DIR } else { "outputs/verify/atomic_progress" }),

    [switch]$PreflightOnly,

    [switch]$ShowDetails,

    [switch]$DryRun
)

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

    return [regex]::Replace($DetectId, '[^A-Za-z0-9_.-]', '_')
}

function Write-AtomicProgressMarker {
    <#
    .SYNOPSIS
        Immediately flushes a {"detect_id","status","updated_at"} JSON marker to
        $ProgressDir for one detect_id.

    .DESCRIPTION
        This is the ground truth read by pass_fail_eval.py to distinguish
        "Atomic Red Team test completed but Splunk saw nothing" (FAIL) from
        "the whole step got killed by its 10-minute GitHub Actions timeout
        before this rule's test ran" (NOT_VERIFIED). Because a hard
        timeout-minutes kill can happen at any point, this must be written
        synchronously with no buffering -- [System.IO.File]::WriteAllText is
        used instead of Out-File/Set-Content so nothing is left sitting in a
        stream buffer when the process is torn down.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProgressDir,

        [Parameter(Mandatory = $true)]
        [string]$DetectId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("started", "completed")]
        [string]$Status
    )

    if (-not (Test-Path -LiteralPath $ProgressDir)) {
        New-Item -ItemType Directory -Path $ProgressDir -Force | Out-Null
    }

    $safeName = ConvertTo-SafeMarkerName -DetectId $DetectId
    $markerPath = Join-Path $ProgressDir "$safeName.json"

    $payload = [ordered]@{
        detect_id  = $DetectId
        status     = $Status
        updated_at = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json -Compress

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

    Write-Host "Importing Invoke-AtomicRedTeam module by name."
    Import-Module -Name Invoke-AtomicRedTeam -Force -ErrorAction Stop
}

function Test-AtomicPrerequisites {
    param(
        [string]$ModulePath,
        [string]$AtomicsFolder
    )

    Write-Host "Running Atomic preflight checks."

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
            throw "Configured ATOMIC_RED_TEAM_PATH does not exist: $AtomicsFolder"
        }
    }
    else {
        Write-Host "No explicit atomics folder configured."
    }

    try {
        $defenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled
        Write-Host "Defender status:"
        $defenderStatus | Format-List | Out-String | Write-Host
    }
    catch {
        Write-Warning "Unable to query Defender status: $($_.Exception.Message)"
    }

    Import-AtomicModule -ModulePath $ModulePath

    $cmd = Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Invoke-AtomicTest command is not available after module import."
    }

    Write-Host "Invoke-AtomicTest command is available."
}

function Invoke-AtomicTestCompat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Technique,

        [Parameter(Mandatory = $true)]
        [int[]]$TestNumbers,

        [string]$AtomicsFolder,

        [switch]$ShowDetails,

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

    if (-not [string]::IsNullOrWhiteSpace($AtomicsFolder) -and $parameters.ContainsKey("PathToAtomicsFolder")) {
        $invokeParams["PathToAtomicsFolder"] = $AtomicsFolder
    }

    if ($DryRun.IsPresent) {
        Write-Host "Resolved Invoke-AtomicTest invocation:"
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

function Disable-DefenderRealtimeIfRequested {
    param(
        [string]$Requested
    )

    if (-not (ConvertTo-Bool $Requested)) {
        return $false
    }

    Write-Host "Disabling Microsoft Defender real-time monitoring for Atomic execution."
    Set-MpPreference -DisableRealtimeMonitoring $true
    Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled | Out-String | Write-Host
    return $true
}

function Enable-DefenderRealtimeIfNeeded {
    param(
        [bool]$WasDisabledByScript
    )

    if (-not $WasDisabledByScript) {
        return
    }

    Write-Host "Re-enabling Microsoft Defender real-time monitoring after Atomic execution."
    Set-MpPreference -DisableRealtimeMonitoring $false
    Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
}

$normalizedRunner = $Runner.Trim().ToLowerInvariant()
$collected = [ordered]@{}
$collectedCustom = [System.Collections.Generic.List[pscustomobject]]::new()
$matchedFiles = 0

# detect_id -> HashSet[string] of "TECHNIQUE|TESTNUM" keys required for that rule
# to be considered "completed" (only populated for tester == atomic; emulation
# tests are not part of the NOT_VERIFIED progress-marker mechanism).
$detectIdTestKeys = @{}
# "TECHNIQUE|TESTNUM" -> HashSet[string] of detect_ids that key belongs to
# (a technique/test can be shared by more than one rule).
$testKeyToDetectIds = @{}

foreach ($splFile in $SplFiles) {
    $meta = Read-MetaFromSplFile -Path $splFile

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
            throw "No custom tests found in $splFile"
        }

        $matchedFiles++
        Write-Host "Collected custom emulation tests from $splFile"

        foreach ($test in $meta.'custom tests') {
            $collectedCustom.Add([pscustomobject]@{
                Name          = [string]$test.name
                Executor      = [string]$test.executor
                Command       = [string]$test.command
                Cleanup       = [string]$test.cleanup
                Prerequisites = $test.prerequisites
            })
        }
        continue
    }

    if ($tester.Trim().ToLowerInvariant() -ne "atomic") {
        Write-Host "Skipping $splFile : tester is not atomic or emulation"
        continue
    }

    if ($null -eq $meta.'atomic tests' -or $meta.'atomic tests'.Count -eq 0) {
        throw "No atomic tests found in $splFile"
    }

    $matchedFiles++
    Write-Host "Collected atomic mappings from $splFile"

    if (-not $detectIdTestKeys.Contains($detectId)) {
        $detectIdTestKeys[$detectId] = New-Object System.Collections.Generic.HashSet[string]
    }

    foreach ($atomic in $meta.'atomic tests') {
        $technique = ([string]$atomic.technique).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($technique)) {
            throw "Atomic technique is missing in $splFile"
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

if ($matchedFiles -eq 0) {
    Write-Host "No matching tests found for the selected runner."
    exit 0
}

if ($collected.Count -gt 0) {
    Test-AtomicPrerequisites -ModulePath $DefaultModulePath -AtomicsFolder $AtomicsPath
}

if ($PreflightOnly.IsPresent) {
    Write-Host "Preflight completed successfully."
    exit 0
}

# Self-hosted runners reuse the same workspace across runs and this job has no
# checkout/clean step, so $ProgressDir can still hold marker files from an
# earlier, unrelated run (e.g. a detect_id that isn't even in $SplFiles this
# time). Left alone, pass_fail_eval.py treats any leftover marker as ground
# truth for the current run and synthesizes a phantom 0-event verdict for a
# rule that was never attacked here. Start every real run from a clean
# directory so it only ever reflects detect_ids actually in scope this time.
if (Test-Path -LiteralPath $ProgressDir) {
    Write-Host "Clearing stale progress markers from a previous run in $ProgressDir"
    Get-ChildItem -LiteralPath $ProgressDir -Filter "*.json" -File | Remove-Item -Force
}

# Mark every atomic-tested rule as "started" up front, before any test actually
# runs. This is what makes a rule distinguishable as NOT_VERIFIED (started but
# never reached "completed") rather than FAIL if the whole step gets killed by
# GitHub Actions' timeout-minutes partway through. Written synchronously so
# whatever is on disk at the moment of a hard kill is the ground truth.
Write-Host "Writing 'started' progress markers for $($detectIdTestKeys.Count) atomic-tested rule(s) to $ProgressDir"
foreach ($dId in $detectIdTestKeys.Keys) {
    Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $dId -Status "started"
}

# Remaining required "TECHNIQUE|TESTNUM" keys per detect_id -- a rule is
# flipped to "completed" the moment its set empties out, regardless of
# whether the individual atomic test invocations succeeded or threw.
$remainingTestKeys = @{}
foreach ($dId in $detectIdTestKeys.Keys) {
    $remainingTestKeys[$dId] = [System.Collections.Generic.HashSet[string]]::new($detectIdTestKeys[$dId])
}

$failures = 0
$defenderDisabledByScript = $false

try {
    $defenderDisabledByScript = Disable-DefenderRealtimeIfRequested -Requested $DisableDefender

    foreach ($technique in $collected.Keys) {
        $testNumbers = @($collected[$technique] | Sort-Object)

        foreach ($testNum in $testNumbers) {
            Write-Host "Invoking Atomic Red Team: $technique test [$testNum]"

            try {
                Invoke-AtomicTestCompat `
                    -Technique $technique `
                    -TestNumbers @($testNum) `
                    -AtomicsFolder $AtomicsPath `
                    -ShowDetails:$ShowDetails.IsPresent `
                    -DryRun:$DryRun.IsPresent
            }
            catch {
                $failures++
                Write-Warning "Atomic execution failed for $technique test $testNum : $($_.Exception.Message)"
            }

            # The atomic execution itself ran to completion for this test
            # (pass/fail of the technique doesn't matter here) -- update
            # progress for every rule that references this technique/test.
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
                switch ($test.Executor.Trim().ToLowerInvariant()) {
                    "cmd" { cmd.exe /c $test.Command }
                    default { Invoke-Expression $test.Command }
                }
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
        }
    }
}
finally {
    Enable-DefenderRealtimeIfNeeded -WasDisabledByScript $defenderDisabledByScript
}

if ($failures -gt 0) {
    exit 2
}

Write-Host "All tests completed successfully."
