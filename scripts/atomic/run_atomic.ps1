param(
    [Parameter(Mandatory = $true)]
    [string[]]$SplFiles,

    [string]$Runner = $(if ($env:ATOMIC_RUNNER) { $env:ATOMIC_RUNNER } else { "windows-victim" }),

    [string]$DefaultModulePath = $(if ($env:ATOMIC_RED_TEAM_MODULE_PATH) { $env:ATOMIC_RED_TEAM_MODULE_PATH } else { "C:\Program Files\WindowsPowerShell\Modules\Invoke-AtomicRedTeam\2.3.0\Invoke-AtomicRedTeam.psd1" }),

    [string]$AtomicsPath = $(if ($env:ATOMIC_RED_TEAM_PATH) { $env:ATOMIC_RED_TEAM_PATH } else { "" }),

    [string]$DisableDefender = $(if ($env:ATOMIC_DISABLE_REALTIME_MONITORING) { $env:ATOMIC_DISABLE_REALTIME_MONITORING } else { "false" }),

    # Minutes after which the independent failsafe re-enables Defender even if
    # this process never gets to run its finally block. Must comfortably exceed
    # the step's own timeout-minutes (10 in ci_dev_workflow.yml) so it can only
    # ever fire after this script is already dead, never mid-test.
    [int]$DefenderDeadmanMinutes = $(if ($env:ATOMIC_DEFENDER_DEADMAN_MINUTES) { [int]$env:ATOMIC_DEFENDER_DEADMAN_MINUTES } else { 20 }),

    # Escape hatch for hosts where a scheduled task cannot be registered. Off by
    # default: without the failsafe there is nothing guaranteeing Defender comes
    # back, which is exactly the state this is here to prevent.
    [string]$AllowUnprotectedDisable = $(if ($env:ATOMIC_ALLOW_UNPROTECTED_DISABLE) { $env:ATOMIC_ALLOW_UNPROTECTED_DISABLE } else { "false" }),

    [string]$TesterType = $(if ($env:ATOMIC_TESTER_TYPE) { $env:ATOMIC_TESTER_TYPE } else { "" }),

    [string]$ProgressDir = $(if ($env:ATOMIC_PROGRESS_DIR) { $env:ATOMIC_PROGRESS_DIR } else { "outputs/verify/atomic_progress" }),

    # Atomic Red Team's own -Cleanup pass after each test. On by default: a
    # self-hosted runner reuses the same machine every run, so skipped cleanup
    # accumulates artifacts that later tests trip over.
    [string]$SkipCleanup = $(if ($env:ATOMIC_SKIP_CLEANUP) { $env:ATOMIC_SKIP_CLEANUP } else { "false" }),

    # Atomic Red Team's -GetPrereqs pass before each test.
    [string]$SkipPrereqs = $(if ($env:ATOMIC_SKIP_PREREQS) { $env:ATOMIC_SKIP_PREREQS } else { "false" }),

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
        [string]$Status,

        # Register item 2.8. Recorded so pass_fail_eval.py can name the right
        # thing when a marker exists but no hits.json does -- before emulation
        # rules had markers at all, that case could only ever be atomic, and
        # the tester was assumed rather than known.
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

        # Which of Invoke-AtomicTest's three modes to run. They are mutually
        # exclusive switches on the same cmdlet, not additive flags, so each one
        # is a separate invocation of the same technique/test pair.
        [ValidateSet("Run", "GetPrereqs", "Cleanup")]
        [string]$Mode = "Run",

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

    # The prereq and cleanup passes are best-effort by design, so an older
    # module that lacks the switch is a skip with a warning, not an error --
    # the same compat posture the rest of this function takes.
    if ($Mode -ne "Run") {
        if (-not $parameters.ContainsKey($Mode)) {
            Write-Warning "Installed Invoke-AtomicTest has no -$Mode parameter; skipping the $Mode pass for $Technique test $($TestNumbers -join ',')."
            return
        }
        $invokeParams[$Mode] = $true
    }

    # Detail output is about the test run itself; forcing it on the prereq and
    # cleanup passes triples the log for no added information.
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

# Name of the failsafe scheduled task. Fixed rather than per-run: a leftover
# task from a previous hard-killed run must be findable and reusable, and
# Register-ScheduledTask -Force then overwrites it in place instead of piling up
# one dead task per run.
$script:DefenderFailsafeTaskName = "DetectionEngineering-RestoreDefenderRealtime"

function Register-DefenderRestoreFailsafe {
    <#
    .SYNOPSIS
        Installs a scheduled task that re-enables Defender real-time monitoring
        independently of this process.

    .DESCRIPTION
        The try/finally around the test loop only helps when this process gets
        to run its finally block. It does not when the process tree is torn down
        -- which is exactly what GitHub Actions' timeout-minutes does, and the
        atomic steps carry timeout-minutes: 10. In that case Defender was
        already switched off and nothing switches it back: the runner sits
        unprotected until somebody notices.

        So the guarantee has to live outside this process. The task carries two
        triggers, covering the two ways the machine can end up stuck:
          - Once, at now + $DeadmanMinutes -- the process was killed but the
            machine kept running.
          - AtStartup -- the machine was rebooted while monitoring was off, so
            the one-shot trigger never fired.
        It runs as SYSTEM because Set-MpPreference needs elevation and there may
        be no interactive user on a self-hosted runner.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [int]$DeadmanMinutes
    )

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'

    $triggers = @(
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($DeadmanMinutes)),
        (New-ScheduledTaskTrigger -AtStartup)
    )

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # StartWhenAvailable matters for the one-shot trigger: if the machine is
    # asleep or busy at the deadman moment, the task still runs late rather than
    # being dropped, which would leave monitoring off indefinitely.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
        -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null

    Write-Host "Defender restore failsafe registered as scheduled task '$TaskName' (deadman fires in $DeadmanMinutes minute(s), plus at next startup)."
}

function Unregister-DefenderRestoreFailsafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )

    try {
        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            Write-Host "Defender restore failsafe '$TaskName' removed (monitoring restored in-process)."
        }
    }
    catch {
        # Leaving the task behind is the safe direction to fail: it only ever
        # turns protection back ON, so a stale one costs nothing but noise.
        Write-Warning "Could not remove the Defender restore failsafe '$TaskName': $($_.Exception.Message)"
    }
}

function Test-LeftoverDefenderFailsafe {
    <#
    .SYNOPSIS
        Reports a failsafe task left behind by a previous run.

    .DESCRIPTION
        Its presence at startup means the previous run never reached its own
        cleanup -- it was hard-killed. That is precisely the situation the
        failsafe exists for, and it is otherwise invisible, so surface it as a
        CI warning rather than silently overwriting the task.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )

    # -ErrorAction covers "no such task", but not "no such cmdlet" -- and with
    # $ErrorActionPreference = 'Stop' a missing ScheduledTasks module would
    # abort the whole run from a diagnostic that is not allowed to be fatal.
    try {
        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Unable to check for a leftover Defender restore failsafe: $($_.Exception.Message)"
        return
    }

    if (-not $existing) {
        return
    }

    Write-Warning "A Defender restore failsafe from a previous run is still registered ('$TaskName') -- that run did not shut down cleanly."
    Write-Host "::warning title=Previous atomic run was killed::A leftover Defender restore failsafe task was found on this runner, meaning an earlier atomic step did not exit cleanly."

    try {
        $rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled
        Write-Host "Defender real-time protection is currently: $rtp"
    }
    catch {
        Write-Warning "Unable to query Defender status: $($_.Exception.Message)"
    }
}

function Wait-DefenderRealtimeState {
    <#
        .SYNOPSIS
        Block until Defender's effective real-time state matches $Expected.

        Set-MpPreference returns once the *preference* is written;
        Get-MpComputerStatus reports the *engine's* state, which catches up a
        moment later. Reading it on the very next line therefore returns the
        state from before the call -- wrong in both directions. That is why the
        log's last word about Defender used to be
        "RealTimeProtectionEnabled: False" immediately after a re-enable that
        had in fact worked, and "True" right after a disable.

        Worth more than the cosmetics: this is the only way the script can
        notice Tamper Protection. With it on -- the default on current Windows
        -- Set-MpPreference completes without error and the engine ignores the
        change entirely. Nothing else here would ever find out, and the caller
        would go on to remove the restore failsafe on the strength of an
        exception that was never thrown.

        Returns an object rather than a bool so the caller can report what it
        actually saw, and can tell "disagreed" apart from "could not ask".
    #>
    param(
        [Parameter(Mandatory = $true)][bool]$Expected,
        [int]$TimeoutSeconds = 20
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $observed = $null

    do {
        try {
            # Split rather than [bool](Get-MpComputerStatus).Prop -- the cast
            # and member access bind correctly there, but not obviously so to a
            # reader, and this file has no local way to run a parse check.
            $status = Get-MpComputerStatus
            $observed = [bool]$status.RealTimeProtectionEnabled
        }
        catch {
            return [pscustomobject]@{
                Confirmed = $false
                Observed  = $null
                Error     = $_.Exception.Message
            }
        }

        if ($observed -eq $Expected) {
            return [pscustomobject]@{ Confirmed = $true; Observed = $observed; Error = $null }
        }

        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    return [pscustomobject]@{ Confirmed = $false; Observed = $observed; Error = $null }
}

function Disable-DefenderRealtimeIfRequested {
    param(
        [string]$Requested,
        [int]$DeadmanMinutes,
        [string]$AllowUnprotected
    )

    if (-not (ConvertTo-Bool $Requested)) {
        return $false
    }

    # Register the failsafe BEFORE switching protection off, so there is no
    # window in which monitoring is disabled with nothing scheduled to undo it.
    try {
        Register-DefenderRestoreFailsafe -TaskName $script:DefenderFailsafeTaskName -DeadmanMinutes $DeadmanMinutes
    }
    catch {
        $msg = "Could not register the Defender restore failsafe: $($_.Exception.Message)"
        if (ConvertTo-Bool $AllowUnprotected) {
            Write-Warning "$msg -- continuing anyway because ATOMIC_ALLOW_UNPROTECTED_DISABLE is set. If this run is killed, Defender will stay disabled on this host."
            Write-Host "::warning title=Defender failsafe unavailable::Real-time monitoring is being disabled without a restore failsafe."
        }
        else {
            throw "$msg. Refusing to disable Defender real-time monitoring without a guaranteed way to restore it. Set ATOMIC_ALLOW_UNPROTECTED_DISABLE=true to override."
        }
    }

    Write-Host "Disabling Microsoft Defender real-time monitoring for Atomic execution."
    Set-MpPreference -DisableRealtimeMonitoring $true

    $state = Wait-DefenderRealtimeState -Expected $false
    if ($state.Confirmed) {
        Write-Host "Defender real-time monitoring is OFF (confirmed by Get-MpComputerStatus)."
    }
    elseif ($null -ne $state.Error) {
        Write-Warning "Could not confirm Defender was disabled: $($state.Error). Proceeding; the failsafe is registered."
    }
    else {
        # Almost always Tamper Protection. Not fatal -- the tests can still run
        # -- but the operator needs to know, because a FAIL from here on may be
        # Defender eating the attack rather than the rule missing it.
        Write-Warning "Set-MpPreference reported success, but real-time monitoring is still reported as ON after polling. Tamper Protection is the usual cause."
        Write-Host "::warning title=Defender still active::Real-time monitoring did not switch off despite Set-MpPreference succeeding -- most likely Tamper Protection. Atomic tests may be blocked or altered, so a FAIL verdict from this run may be Defender, not the detection."
    }

    # True regardless: the preference was written and the failsafe is
    # registered, so the caller must still run the restore path and clean up.
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
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
    }
    catch {
        # Do not remove the failsafe in this case -- it is now the only thing
        # that will bring protection back.
        Write-Warning "Failed to re-enable Defender real-time monitoring in-process: $($_.Exception.Message). Leaving the failsafe task in place to restore it."
        return
    }

    # The gate that decides whether the failsafe may be removed.
    #
    # It used to be "Set-MpPreference did not throw", which is a weaker claim
    # than it looks: with Tamper Protection on, the call succeeds and the engine
    # ignores it. That combination -- protection still off, restore task
    # deleted, step exits 0 -- left a lab VM unprotected with nothing scheduled
    # to fix it and nothing in the log saying so.
    #
    # Now the failsafe is removed only once the engine itself reports
    # protection back on. Every other path leaves the task registered: the
    # deadman timer and the at-startup trigger then remain the safety net they
    # were built to be.
    $state = Wait-DefenderRealtimeState -Expected $true
    if (-not $state.Confirmed) {
        if ($null -ne $state.Error) {
            $reason = "could not query Defender ($($state.Error))"
        }
        else {
            $reason = "Defender still reports real-time monitoring as OFF"
        }
        Write-Warning "Set-MpPreference succeeded but $reason. Leaving the failsafe task in place to restore protection."
        Write-Host "::warning title=Defender not confirmed restored::Real-time monitoring could not be confirmed back on after the Atomic run. The restore failsafe task has deliberately been left registered on this runner; it fires on its deadman timer and at next startup."
        return
    }

    Write-Host "Defender real-time monitoring is ON (confirmed by Get-MpComputerStatus)."
    Unregister-DefenderRestoreFailsafe -TaskName $script:DefenderFailsafeTaskName
}

$normalizedRunner = $Runner.Trim().ToLowerInvariant()
$collected = [ordered]@{}
$collectedCustom = [System.Collections.Generic.List[pscustomobject]]::new()
$matchedFiles = 0

# detect_id -> HashSet[string] of "TECHNIQUE|TESTNUM" keys required for that rule
# to be considered "completed" (tester == atomic).
$detectIdTestKeys = @{}

# Register item 2.8. The same thing for emulation-tested rules, which used to be
# outside this mechanism entirely: no marker was ever written for them, so
# pass_fail_eval.py could not tell "the emulation command never ran" from "it
# ran and Splunk saw nothing" and scored both as FAIL. That is exactly the
# false-verdict class NOT_VERIFIED exists to prevent, and 8 of 27 rules sat
# outside it.
#
# Keyed "detect_id|index" rather than by test name: names are free text and two
# tests in one rule may share one, which a name-keyed set would silently
# collapse into a rule that completes early.
$detectIdCustomKeys = @{}
# "TECHNIQUE|TESTNUM" -> HashSet[string] of detect_ids that key belongs to
# (a technique/test can be shared by more than one rule).
$testKeyToDetectIds = @{}

# Rules whose metadata could not be used. Counted rather than thrown on: this
# loop is shared by every rule in the batch, so one malformed sidecar used to
# abort collection for all of them -- 26 healthy rules going untested because of
# the 27th. A skipped rule simply never gets a progress marker, which
# pass_fail_eval.py already reads as "not attempted", so degrading to a skip
# keeps the verdict honest instead of inventing one.
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
            # Register item 2.8: the detect_id has to travel with the test.
            # $collectedCustom used to be a flat list of commands with no idea
            # which rule they belonged to, which is why no marker could be
            # written for them.
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
    # "Nothing to run" and "everything was broken" both leave $matchedFiles at
    # zero but mean opposite things, and only one of them is a green tick.
    if ($malformed -gt 0) {
        # Deliberately not Write-Error: $ErrorActionPreference is 'Stop', so it
        # would throw and bury a clear message under a stack trace, and the
        # explicit exit code below would never be reached.
        Write-Warning "No usable tests found for the selected runner: all $malformed candidate rule(s) had unusable test metadata."
        Write-Host "::error title=No usable atomic tests::Every candidate rule for this runner had unusable test metadata."
        exit 1
    }

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
$markedRules = $detectIdTestKeys.Count + $detectIdCustomKeys.Count
Write-Host "Writing 'started' progress markers for $markedRules tested rule(s) to $ProgressDir"
foreach ($dId in $detectIdTestKeys.Keys) {
    Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $dId -Status "started"
}
foreach ($dId in $detectIdCustomKeys.Keys) {
    Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $dId -Status "started" -Tester "emulation"
}

# Remaining required "TECHNIQUE|TESTNUM" keys per detect_id -- a rule is
# flipped to "completed" the moment its set empties out, regardless of
# whether the individual atomic test invocations succeeded or threw.
$remainingTestKeys = @{}
foreach ($dId in $detectIdTestKeys.Keys) {
    $remainingTestKeys[$dId] = [System.Collections.Generic.HashSet[string]]::new($detectIdTestKeys[$dId])
}

# Same, for the emulation side (register item 2.8).
$remainingCustomKeys = @{}
foreach ($dId in $detectIdCustomKeys.Keys) {
    $remainingCustomKeys[$dId] = [System.Collections.Generic.HashSet[string]]::new($detectIdCustomKeys[$dId])
}

$failures = 0
$defenderDisabledByScript = $false
$skipCleanupResolved = ConvertTo-Bool $SkipCleanup
$skipPrereqsResolved = ConvertTo-Bool $SkipPrereqs

if ($skipPrereqsResolved) {
    Write-Warning "Atomic prerequisite setup (-GetPrereqs) is disabled; tests with unmet prerequisites may report a false FAIL."
}
if ($skipCleanupResolved) {
    Write-Warning "Atomic cleanup (-Cleanup) is disabled; test artifacts will accumulate on this runner between runs."
}

# Surfaced before anything else touches Defender: a task still sitting here is
# evidence that the previous run was hard-killed, and -Force below would quietly
# overwrite that evidence.
if (ConvertTo-Bool $DisableDefender) {
    Test-LeftoverDefenderFailsafe -TaskName $script:DefenderFailsafeTaskName
}

try {
    $defenderDisabledByScript = Disable-DefenderRealtimeIfRequested `
        -Requested $DisableDefender `
        -DeadmanMinutes $DefenderDeadmanMinutes `
        -AllowUnprotected $AllowUnprotectedDisable

    foreach ($technique in $collected.Keys) {
        $testNumbers = @($collected[$technique] | Sort-Object)

        foreach ($testNum in $testNumbers) {
            Write-Host "Invoking Atomic Red Team: $technique test [$testNum]"

            # Prerequisites first. Without this a test whose prereqs are missing
            # simply does not do the thing it claims to do, and the resulting
            # "Splunk saw nothing" reads as a broken detection rather than an
            # unprepared host -- a false FAIL against the rule.
            # Best-effort: a prereq failure is reported but does not count as a
            # test failure, because the run below is what actually decides.
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
                    -DryRun:$DryRun.IsPresent
            }
            catch {
                $failures++
                Write-Warning "Atomic execution failed for $technique test $testNum : $($_.Exception.Message)"
            }
            finally {
                # Cleanup runs even when the test threw, and its own failure is
                # never a test failure -- the verdict is about the detection,
                # not about housekeeping.
                #
                # Safe with respect to verification: Splunk verifies from events
                # already shipped by the forwarder as they were written, so
                # undoing the artifacts afterwards cannot un-send them. The one
                # real trade-off is that a cleanup command can itself trip a
                # rule (deleting a registry key, removing a file); that is
                # inherent to Atomic Red Team's cleanup model, and
                # ATOMIC_SKIP_CLEANUP is the way out when it bites.
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

            # Register item 2.8, and in `finally` on purpose: the marker records
            # that the emulation command *ran*, not that it worked. A command
            # that threw was still attempted, and the verdict for that is FAIL
            # on the Splunk evidence -- not NOT_VERIFIED, which is reserved for
            # "we never got to try". Mirrors how the atomic side treats a test
            # that ran and failed.
            if ($test.DetectId -and $remainingCustomKeys.Contains($test.DetectId)) {
                [void]$remainingCustomKeys[$test.DetectId].Remove($test.CustomKey)
                if ($remainingCustomKeys[$test.DetectId].Count -eq 0) {
                    Write-AtomicProgressMarker -ProgressDir $ProgressDir -DetectId $test.DetectId -Status "completed" -Tester "emulation"
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
