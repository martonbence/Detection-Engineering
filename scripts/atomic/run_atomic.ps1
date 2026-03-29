param(
    [Parameter(Mandatory = $true)]
    [string[]]$SplFiles,

    [string]$Runner = $(if ($env:ATOMIC_RUNNER) { $env:ATOMIC_RUNNER } else { "windows-victim" }),

    [string]$DefaultModulePath = $(if ($env:ATOMIC_RED_TEAM_MODULE_PATH) { $env:ATOMIC_RED_TEAM_MODULE_PATH } else { "C:\Program Files\WindowsPowerShell\Modules\Invoke-AtomicRedTeam\2.3.0\Invoke-AtomicRedTeam.psd1" }),

    [string]$AtomicsPath = $(if ($env:ATOMIC_RED_TEAM_PATH) { $env:ATOMIC_RED_TEAM_PATH } else { "" }),

    [string]$DisableDefender = $(if ($env:ATOMIC_DISABLE_REALTIME_MONITORING) { $env:ATOMIC_DISABLE_REALTIME_MONITORING } else { "false" }),

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

    $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $match = [regex]::Match($content, 'META_START\s*(\{.*?\})\s*META_END', [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if (-not $match.Success) {
        throw "META block not found in file: $Path"
    }

    return $match.Groups[1].Value | ConvertFrom-Json
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
        return
    }

    Write-Host "Disabling Microsoft Defender real-time monitoring for Atomic execution."
    Set-MpPreference -DisableRealtimeMonitoring $true
    Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
}

$normalizedRunner = $Runner.Trim().ToLowerInvariant()
$collected = [ordered]@{}
$matchedFiles = 0

foreach ($splFile in $SplFiles) {
    $meta = Read-MetaFromSplFile -Path $splFile

    if (-not (ConvertTo-Bool $meta.'testing enabled')) {
        Write-Host "Skipping $splFile : testing is disabled"
        continue
    }

    $tester = [string]$meta.tester
    if ($tester.Trim().ToLowerInvariant() -ne "atomic") {
        Write-Host "Skipping $splFile : tester is not atomic"
        continue
    }

    $metaRunner = [string]$meta.runner
    if (-not [string]::IsNullOrWhiteSpace($normalizedRunner) -and $metaRunner.Trim().ToLowerInvariant() -ne $normalizedRunner) {
        Write-Host "Skipping $splFile : runner mismatch ($metaRunner)"
        continue
    }

    if ($null -eq $meta.'atomic tests' -or $meta.'atomic tests'.Count -eq 0) {
        throw "No atomic tests found in $splFile"
    }

    $matchedFiles++
    Write-Host "Collected atomic mappings from $splFile"

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
        }
    }
}

if ($matchedFiles -eq 0) {
    Write-Host "No matching atomic tests found for the selected runner."
    exit 0
}

Test-AtomicPrerequisites -ModulePath $DefaultModulePath -AtomicsFolder $AtomicsPath

if ($PreflightOnly.IsPresent) {
    Write-Host "Atomic preflight completed successfully."
    exit 0
}

Disable-DefenderRealtimeIfRequested -Requested $DisableDefender

$failures = 0

foreach ($technique in $collected.Keys) {
    $testNumbers = @($collected[$technique] | Sort-Object)
    $printableTests = $testNumbers -join ", "

    Write-Host "Invoking Atomic Red Team: $technique tests [$printableTests]"

    try {
        Invoke-AtomicTestCompat `
            -Technique $technique `
            -TestNumbers $testNumbers `
            -AtomicsFolder $AtomicsPath `
            -ShowDetails:$ShowDetails.IsPresent `
            -DryRun:$DryRun.IsPresent
    }
    catch {
        $failures++
        Write-Error "Atomic execution failed for $technique : $($_.Exception.Message)"
    }
}

if ($failures -gt 0) {
    exit 2
}

Write-Host "Atomic execution completed successfully."
