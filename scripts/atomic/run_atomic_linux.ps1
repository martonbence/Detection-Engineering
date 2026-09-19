#!/usr/bin/env pwsh
#
# Shebang required for `./run_atomic_linux.ps1 ...` (ci_dev_workflow.yml's
# atomic_verify_linux job invokes it exactly that way, not `pwsh -File ...`).
# On Linux, pwsh resolves a relative `./script.ps1` invocation through the
# same command-discovery path the OS uses for any native command -- it needs
# both this shebang AND the executable bit (see the file's git mode, and
# FIXED_SCRIPTS in scripts/state/build_pipeline_bundle.py, which copies this
# file with shutil.copy2 to preserve that bit into the bundle). `#` is a
# PowerShell comment character, so this line is inert to the pwsh parser
# itself -- it only matters to the OS's own exec() resolution. run_atomic.ps1
# (the Windows counterpart) is deliberately left without this: Windows has
# no equivalent requirement, so there is nothing to fix there.
[CmdletBinding(DefaultParameterSetName = 'Batch')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Batch')]
    [string[]]$SplFiles,

    # -ElevatedChild and the -Elevated* params below are a second, internal
    # entry point into this same script file: Invoke-ElevatedAtomicTest (see
    # below) re-invokes this script as `sudo -n --preserve-env=... pwsh -File
    # <this file> -ElevatedChild ...` to run exactly one (technique, test,
    # mode) Invoke-AtomicTest call as root, for atomics whose own metadata
    # says elevation_required: true. This is not a second script -- it is
    # the only way to get a *specific* nested pwsh process elevated without
    # re-touching the workflow step's own `shell:` field, which already
    # broke once (see ci_dev_workflow.yml's comment on the atomic_verify_linux
    # job) when `sudo` was prepended to the outer step's shell template
    # instead. A separate parameter set (rather than adding -ElevatedChild
    # to the normal -SplFiles set) keeps -SplFiles genuinely mandatory for
    # the batch entry point while making it a no-op here.
    [Parameter(Mandatory = $true, ParameterSetName = 'ElevatedChild')]
    [switch]$ElevatedChild,

    [Parameter(Mandatory = $true, ParameterSetName = 'ElevatedChild')]
    [string]$ElevatedTechnique,

    # A single test number, not int[] -- every real call site (see
    # Invoke-ElevatedAtomicTest below) only ever elevates one test at a time,
    # and a scalar avoids CLI argument-array marshalling entirely: a single
    # comma-joined string token like "1,3" does not auto-split back into
    # [int[]] across a process boundary the way an in-process array literal
    # would, it would just fail to bind. Simpler and correct beats generic
    # and subtly wrong here.
    [Parameter(Mandatory = $true, ParameterSetName = 'ElevatedChild')]
    [int]$ElevatedTestNumber,

    [Parameter(ParameterSetName = 'ElevatedChild')]
    [string]$ElevatedAtomicsFolder,

    [Parameter(ParameterSetName = 'ElevatedChild')]
    [string]$ElevatedModulePath,

    [Parameter(ParameterSetName = 'ElevatedChild')]
    [ValidateSet("GetPrereqs", "Run", "Cleanup")]
    [string]$ElevatedMode = "Run",

    [Parameter(ParameterSetName = 'ElevatedChild')]
    [switch]$ElevatedShowDetails,

    [Parameter(ParameterSetName = 'ElevatedChild')]
    [int]$ElevatedTimeoutSeconds = 0,

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

# Must match the VM's `/etc/sudoers.d/` env_keep grant for adminben exactly
# (each of these plus PSModulePath is explicitly `env_keep`-listed there,
# confirmed via `visudo -c` when that sudoers change was applied) --
# `sudo -n --preserve-env=<list>` only survives for variables the sudoers
# policy actually allows a caller to preserve; NOPASSWD alone (the earlier
# fix, .../90-ci-nopasswd) says nothing about env_reset/env_keep. PSModulePath
# is in this list even though it's never one of this script's own -Elevated*
# params: it is pwsh's own module auto-discovery variable, and sudo changes
# HOME to root's, so Import-AtomicModule's name-based fallback (see
# Import-AtomicModule below) would stop finding Invoke-AtomicRedTeam under an
# elevated child unless this specific var survives the sudo boundary.
$script:ElevatedEnvKeepVars = @(
    "ATOMIC_RUNNER",
    "ATOMIC_TESTER_TYPE",
    "ATOMIC_RED_TEAM_MODULE_PATH_LINUX",
    "ATOMIC_RED_TEAM_PATH_LINUX",
    "PSModulePath"
)

# Per-technique cache of Get-AtomicTechnique's parsed atomic_tests array, so
# a technique with several matched test numbers only pays for one metadata
# load. Never reset across techniques in a single script invocation -- there
# is no correctness reason to, and this script's whole lifetime is one CI
# step anyway.
$script:ElevationCache = @{}

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

function Test-AtomicTestElevationRequired {
    # Reads whether a specific (technique, test number) atomic declares
    # `executor.elevation_required: true` via Invoke-AtomicRedTeam's own
    # Get-AtomicTechnique accessor -- deliberately not a from-scratch YAML
    # parse of our own, same reasoning as the file header comment gives for
    # not reimplementing the module's meta-parsing logic a second time.
    #
    # Any failure here (cmdlet missing on an older module version, technique
    # yaml not found, unexpected shape) falls back to "assume not elevation
    # required" -- i.e. the same unprivileged behaviour this script always
    # had. That fallback cannot cause a false PASS: if a test genuinely needs
    # root and doesn't get it, the underlying shell command still fails and
    # the rule's expected event still never lands in Splunk, so
    # pass_fail_eval.py still reports the honest FAIL/NOT_VERIFIED verdict --
    # this function only decides *how* a test is invoked, never whether its
    # result counts.
    param(
        [Parameter(Mandatory = $true)]
        [string]$Technique,

        [Parameter(Mandatory = $true)]
        [int]$TestNumber,

        [string]$AtomicsFolder
    )

    if (-not $script:ElevationCache.ContainsKey($Technique)) {
        $script:ElevationCache[$Technique] = $null
        try {
            $getTechniqueCmd = Get-Command Get-AtomicTechnique -ErrorAction SilentlyContinue
            if (-not $getTechniqueCmd) {
                Write-Warning "Get-AtomicTechnique is not available from the imported Invoke-AtomicRedTeam module; cannot read elevation_required for $Technique. Running its tests unprivileged (existing default)."
            }
            else {
                # Get-AtomicTechnique upstream only has -Path/-Yaml parameter
                # sets, no by-name -Technique lookup -- so this can only ever
                # run when $AtomicsFolder actually resolves to a real yaml
                # file. No by-name fallback is attempted; if the path can't
                # be built, this falls straight to the catch below via the
                # explicit `throw`, landing on the same "assume unprivileged"
                # behaviour as any other detection failure.
                $yamlPath = $null
                if ($AtomicsFolder) {
                    $candidate = Join-Path $AtomicsFolder (Join-Path $Technique "$Technique.yaml")
                    if (Test-Path -LiteralPath $candidate) {
                        $yamlPath = $candidate
                    }
                }

                if (-not $yamlPath) {
                    throw "No atomics folder/technique yaml available to resolve elevation_required for $Technique (AtomicsFolder='$AtomicsFolder')."
                }

                $techniqueObj = Get-AtomicTechnique -Path $yamlPath
                $script:ElevationCache[$Technique] = @($techniqueObj.atomic_tests)
            }
        }
        catch {
            Write-Warning "Could not load technique metadata for $Technique to determine elevation requirements: $($_.Exception.Message). Running its tests unprivileged (existing default)."
        }
    }

    $tests = $script:ElevationCache[$Technique]
    if (-not $tests -or $TestNumber -lt 1 -or $TestNumber -gt $tests.Count) {
        return $false
    }

    return [bool]($tests[$TestNumber - 1].executor.elevation_required)
}

function Invoke-ElevatedAtomicTest {
    # Spawns a nested, elevated pwsh child process for exactly one
    # (technique, test, mode) Invoke-AtomicTest call -- used only when
    # Test-AtomicTestElevationRequired says the atomic actually needs it.
    #
    # This exists instead of elevating the whole outer step because
    # prepending `sudo` to the workflow step's own `shell:` field was tried
    # first and broke GitHub Actions' custom-shell templating outright (see
    # ci_dev_workflow.yml's atomic_verify_linux job comment, CI run
    # 35452945096) -- a different, worse failure than the permission-denied
    # one this is fixing. Spawning our own subprocess here never touches
    # that mechanism: `sudo`/`pwsh` are just external programs from the
    # outer script's point of view, identical in kind to the `bash -c "sudo
    # cat ..."` that T1003.008 already runs successfully today.
    #
    # Uses the call operator (`&`) with an argument array, not
    # Invoke-Expression or a hand-built command string -- every element is
    # passed as one literal argv entry directly to `sudo`, then to `pwsh
    # -File`, with no intermediate shell re-parsing/re-quoting either hop
    # (unlike the workflow step's custom `shell:` field, this is a normal
    # external-process invocation, so PowerShell's own array-to-argv
    # marshalling is all that's involved). `-File` (not `-Command` string
    # concatenation) is used for the same reason: technique IDs and folder
    # paths reach the child exactly as typed, with no escaping to get wrong.
    param(
        [Parameter(Mandatory = $true)]
        [string]$Technique,

        [Parameter(Mandatory = $true)]
        [int[]]$TestNumbers,

        [string]$AtomicsFolder,

        [ValidateSet("GetPrereqs", "Run", "Cleanup")]
        [string]$Mode = "Run",

        [switch]$ShowDetails,

        [int]$TimeoutSeconds = 0,

        [string]$ModulePath,

        [switch]$DryRun
    )

    # -ElevatedTestNumber is a scalar on the child's side (see its param
    # declaration for why) -- this function still accepts $TestNumbers as
    # int[] to match Invoke-AtomicTestCompat's own signature, but every real
    # caller here only ever passes a single-element array (the outer loop
    # already iterates test-by-test), so that is enforced explicitly rather
    # than silently dropping any extra elements.
    if ($TestNumbers.Count -ne 1) {
        throw "Invoke-ElevatedAtomicTest only supports a single test number per call, got: $($TestNumbers -join ',')"
    }

    $childArgs = @(
        "-NoLogo", "-NoProfile",
        "-File", $PSCommandPath,
        "-ElevatedChild",
        "-ElevatedTechnique", $Technique,
        "-ElevatedTestNumber", $TestNumbers[0],
        "-ElevatedMode", $Mode
    )
    if ($AtomicsFolder) {
        $childArgs += @("-ElevatedAtomicsFolder", $AtomicsFolder)
    }
    if ($ModulePath) {
        $childArgs += @("-ElevatedModulePath", $ModulePath)
    }
    if ($ShowDetails.IsPresent) {
        $childArgs += "-ElevatedShowDetails"
    }
    if ($TimeoutSeconds -gt 0) {
        $childArgs += @("-ElevatedTimeoutSeconds", $TimeoutSeconds)
    }

    $preserveEnvList = ($script:ElevatedEnvKeepVars -join ",")

    if ($DryRun.IsPresent) {
        Write-Host "DryRun: would execute (elevated): sudo -n --preserve-env=$preserveEnvList pwsh $($childArgs -join ' ')"
        return 0
    }

    $pwshCmd = Get-Command pwsh -ErrorAction Stop

    # Explicitly captured, not a bare unassigned `&` statement: an external
    # process's uncaptured/unredirected stdout becomes part of whatever this
    # function returns, exactly like any other emitted value in PowerShell.
    # The elevated child is verbose (module-import banner,
    # Invoke-AtomicTest's own command output), so a bare `&` here would make
    # this function's actual return value an array of every output line plus
    # the real exit code tacked on at the end -- and the caller's `$rc -ne 0`
    # would then be PowerShell's array-filter form (matches every element
    # not equal to 0, which is virtually every text line once compared
    # against an int), always truthy regardless of what the elevated call
    # actually did. Captured here and re-emitted via Write-Host instead, so
    # the elevated child's output still reaches the step log (useful for
    # debugging a failed elevated run) while this function's own `return` is
    # a clean scalar exit code and nothing else.
    $output = & sudo -n "--preserve-env=$preserveEnvList" $pwshCmd.Source @childArgs
    $exitCode = $LASTEXITCODE
    if ($output) {
        Write-Host ($output -join "`n")
    }

    # $LASTEXITCODE is how PowerShell surfaces an external process's exit
    # code after `&` -- sudo exits with the elevated pwsh child's own code
    # (0 success, 2 failure, matching this script's own convention below)
    # once it has actually started the child; `-n` makes an unexpected auth
    # failure exit non-zero too, which the caller correctly treats the same
    # as any other failed elevated call rather than needing to tell them
    # apart.
    return $exitCode
}

if ($ElevatedChild) {
    # This invocation of the script IS the nested elevated child that
    # Invoke-ElevatedAtomicTest spawns above. Deliberately skips the entire
    # $SplFiles-driven batch flow below (meta.json parsing, progress
    # markers, the technique loop) -- it exists purely to make exactly one
    # Invoke-AtomicTestCompat call as root and hand the result back to the
    # unprivileged parent via this process's own exit code, which
    # Invoke-ElevatedAtomicTest reads via $LASTEXITCODE.
    try {
        Import-AtomicModule -ModulePath $ElevatedModulePath
        Invoke-AtomicTestCompat `
            -Technique $ElevatedTechnique `
            -TestNumbers @($ElevatedTestNumber) `
            -AtomicsFolder $ElevatedAtomicsFolder `
            -Mode $ElevatedMode `
            -ShowDetails:$ElevatedShowDetails `
            -TimeoutSeconds $ElevatedTimeoutSeconds
        exit 0
    }
    catch {
        Write-Warning "Elevated child failed ($ElevatedMode) for $ElevatedTechnique test $ElevatedTestNumber : $($_.Exception.Message)"
        exit 2
    }
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

        # Decided once per test, applied consistently to GetPrereqs/Run/
        # Cleanup: an elevation_required atomic's prereq/cleanup commands are
        # part of the same `executor` block in its yaml as the main command,
        # so there is no basis for elevating one phase and not the others.
        $needsElevation = Test-AtomicTestElevationRequired -Technique $technique -TestNumber $testNum -AtomicsFolder $AtomicsPath
        if ($needsElevation) {
            Write-Host "  -> $technique test $testNum declares elevation_required: true; running via a nested elevated pwsh (sudo), not the unprivileged outer process."
        }

        if (-not $skipPrereqsResolved) {
            try {
                if ($needsElevation) {
                    $rc = Invoke-ElevatedAtomicTest -Technique $technique -TestNumbers @($testNum) -AtomicsFolder $AtomicsPath -Mode "GetPrereqs" -ModulePath $DefaultModulePath -DryRun:$DryRun.IsPresent
                    if ($rc -ne 0) {
                        Write-Warning "Elevated prerequisite setup failed for $technique test $testNum (exit $rc)"
                    }
                }
                else {
                    Invoke-AtomicTestCompat `
                        -Technique $technique `
                        -TestNumbers @($testNum) `
                        -AtomicsFolder $AtomicsPath `
                        -Mode "GetPrereqs" `
                        -DryRun:$DryRun.IsPresent
                }
            }
            catch {
                Write-Warning "Prerequisite setup failed for $technique test $testNum : $($_.Exception.Message)"
            }
        }

        try {
            if ($needsElevation) {
                $rc = Invoke-ElevatedAtomicTest -Technique $technique -TestNumbers @($testNum) -AtomicsFolder $AtomicsPath -Mode "Run" -ShowDetails:$ShowDetails.IsPresent -TimeoutSeconds $TimeoutSeconds -ModulePath $DefaultModulePath -DryRun:$DryRun.IsPresent
                if ($rc -ne 0) {
                    $failures++
                    Write-Warning "Elevated atomic execution failed for $technique test $testNum (exit $rc)"
                }
            }
            else {
                Invoke-AtomicTestCompat `
                    -Technique $technique `
                    -TestNumbers @($testNum) `
                    -AtomicsFolder $AtomicsPath `
                    -Mode "Run" `
                    -ShowDetails:$ShowDetails.IsPresent `
                    -TimeoutSeconds $TimeoutSeconds `
                    -DryRun:$DryRun.IsPresent
            }
        }
        catch {
            $failures++
            Write-Warning "Atomic execution failed for $technique test $testNum : $($_.Exception.Message)"
        }
        finally {
            if (-not $skipCleanupResolved) {
                try {
                    if ($needsElevation) {
                        $rc = Invoke-ElevatedAtomicTest -Technique $technique -TestNumbers @($testNum) -AtomicsFolder $AtomicsPath -Mode "Cleanup" -ModulePath $DefaultModulePath -DryRun:$DryRun.IsPresent
                        if ($rc -ne 0) {
                            Write-Warning "Elevated cleanup failed for $technique test $testNum (exit $rc)"
                        }
                    }
                    else {
                        Invoke-AtomicTestCompat `
                            -Technique $technique `
                            -TestNumbers @($testNum) `
                            -AtomicsFolder $AtomicsPath `
                            -Mode "Cleanup" `
                            -DryRun:$DryRun.IsPresent
                    }
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
