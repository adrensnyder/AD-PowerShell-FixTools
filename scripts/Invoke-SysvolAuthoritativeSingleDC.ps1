#requires -version 5.1
<#
.SYNOPSIS
    DFSR SYSVOL authoritative recovery helper for a single remaining Domain Controller.

.DESCRIPTION
    This script audits and, when explicitly requested, repairs a very specific DFSR SYSVOL
    failure scenario:

      - The local server is the only remaining/reachable Domain Controller.
      - The local server owns all five FSMO roles.
      - DFSR SYSVOL is stuck in State 5 / In Error with Content Freshness evidence, or
      - DFSR SYSVOL is stuck in State 2 / Initial Sync because the local seeding
        registry Parent Computer points to a stale/non-local Domain Controller.
      - For State 5, the DFS Replication event log shows Content Freshness evidence, usually
        Event ID 4012, MaxOfflineTimeInDays, stale SYSVOL data, or Error 9061.
      - Active Directory Sites and Services must not contain non-local/stale server objects.
        The script detects those objects and blocks --fix until they are manually verified and removed.

    The script is intentionally NOT a generic SYSVOL repair tool. It is designed for the case
    where a single surviving FSMO-owning DC must make its local SYSVOL authoritative again.

    The script will block the fix when another Domain Controller is reachable or when AD Sites
    and Services still contains non-local/stale server objects. In a healthy multi-DC environment,
    you must not run this recovery procedure; use the appropriate authoritative/non-authoritative
    DFSR SYSVOL recovery workflow for your topology instead.

    Before running the full sanity checks, the script performs a prerequisite gate. If required
    management tools are missing, it asks whether to install them. Only after the missing
    prerequisites are installed and re-validated does the script continue with the full checks.
    If installation is declined or fails, the script stops and explains what is missing.

    When run with --fix, the script first performs the same checks. It continues only if the
    detected condition matches a supported single-DC DFSR SYSVOL problem: Content Freshness /
    stale SYSVOL, or Initial Sync with a stale/non-local SYSVOL seeding Parent Computer.

    During --fix, the script:
      1. Creates and verifies a SYSVOL backup next to this script by default, unless --backup-path is supplied.
      2. Stops DFSR and, if needed, corrects the local SYSVOL seeding registry Parent Computer
         to the local DC FQDN. If corrected, DFSR is started once to reload the registry value,
         then stopped again before the authoritative D4 sequence begins.
      3. Disables the local DFSR SYSVOL subscription.
      4. Sets msDFSR-Options=1 to mark the local SYSVOL as authoritative.
      5. Forces DFSR to poll Active Directory, with retries because DFSR/WMI can need
         a short time to expose PollDsNow immediately after the DFSR service starts.
      5. Re-enables the local DFSR SYSVOL subscription.
      6. Restarts DFSR and Netlogon.
      7. Validates DFSR State 4 / Normal, SYSVOL and NETLOGON shares, recent DFSR events,
         service state, and dcdiag results where available.

    The script never deletes orphaned AD Sites and Services server objects. If it finds objects
    such as old server containers below CN=Sites that are not the local DC, --fix is blocked.
    Empty obsolete server containers should be removed manually only after verification. Objects
    that still contain NTDS Settings require proper AD metadata cleanup, not blind deletion.

    In --check mode, when those stale/non-local Sites and Services server objects are detected,
    the script asks at the end of the check whether to open the Active Directory Sites and
    Services console (dssite.msc). This is only a convenience launcher; the script still does
    not remove, edit, or clean up any Sites and Services object automatically.

    The output is split into colored sections. Errors are printed in red. If an error occurs,
    the script stops immediately and prints what was completed, what is missing, the error and
    warning summaries, suggested next actions, and the state of the required services: DFSR,
    NTDS, Netlogon, DNS, KDC, W32Time, and ADWS.

.USAGE
    Show this help:
        .\Invoke-SysvolAuthoritativeSingleDC.ps1
        .\Invoke-SysvolAuthoritativeSingleDC.ps1 --help

    Run sanity checks only, without changing DFSR/AD settings:
        .\Invoke-SysvolAuthoritativeSingleDC.ps1 --check

    In --check mode, if required management tools are missing, the script asks whether to install
    them before continuing with the full sanity checks.

    Run checks first, then repair only if the supported problem is detected:
        .\Invoke-SysvolAuthoritativeSingleDC.ps1 --fix

    Run fix mode and store the SYSVOL backup under a custom directory:
        .\Invoke-SysvolAuthoritativeSingleDC.ps1 --fix --backup-path D:\SafeBackups
        .\Invoke-SysvolAuthoritativeSingleDC.ps1 --fix --backup-path "D:\Safe Backups"

.EXECUTION POLICY BYPASS
    If Windows blocks .ps1 execution because of the local execution policy, start the script
    through powershell.exe with -ExecutionPolicy Bypass. This bypass applies only to that
    PowerShell process and does not permanently change the system policy.

    Check mode with execution policy bypass:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SysvolAuthoritativeSingleDC.ps1 --check

    Fix mode with execution policy bypass:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SysvolAuthoritativeSingleDC.ps1 --fix
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SysvolAuthoritativeSingleDC.ps1 --fix --backup-path D:\SafeBackups

    If you use PowerShell 7, use pwsh instead:
        pwsh -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SysvolAuthoritativeSingleDC.ps1 --check
        pwsh -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SysvolAuthoritativeSingleDC.ps1 --fix

    Important: there is no internal --bypass mode in this script. Execution policy is evaluated
    before the script starts, so the bypass must be passed to powershell.exe or pwsh, not to the
    script itself.

.LOGGING
    When run with --check or --fix, the script writes a transcript log in the same directory as
    the script file. The log file name is derived dynamically from the script name.

    Example:
        Script: .\Invoke-SysvolAuthoritativeSingleDC_v8_NoCache.ps1
        Log:    .\Invoke-SysvolAuthoritativeSingleDC_v7_NoCache.log

    The log is appended on subsequent runs so that previous executions are preserved.

.BACKUP LOCATION
    During --fix, the SYSVOL backup is stored under the same directory as this script by default.
    A timestamped subfolder is created automatically, for example:
        .\SYSVOL_Backup_20260615_091814

    Use --backup-path to place that timestamped backup folder under another directory.
    The script validates that the backup root is usable before changing DFSR/AD settings.
    Backup verification compares the SYSVOL domain tree while excluding junctions/reparse
    points, matching Robocopy /XJ behavior, and prints exact missing/extra paths if a
    consistency problem is detected. If Robocopy itself fails, the script captures the
    Robocopy output and adds the most relevant error lines to the final Errors / Suggested
    actions summary.

.PARAMETER --check
    Runs prerequisite checks first, asks before installing missing tools, then runs safety checks only.
    No DFSR/AD recovery changes are made.

.PARAMETER --fix
    Runs all checks first. If the checks match the supported problem, it performs an authoritative
    SYSVOL DFSR recovery on the local DC.

.PARAMETER --backup-path <path>
    Optional. Changes the backup root used by --fix. If omitted, the backup root is the directory
    where this script file is located. The script creates a timestamped SYSVOL backup subfolder
    below that root.

.PARAMETER --help
    Shows help.

.NOTES
    Author:
        Created and maintained by AdrenSnyder.

    Disclaimer:
        This script is provided AS IS, without warranty of any kind.

        Use it at your own risk. Always read the code, understand what it does,
        test where possible, and make sure you have valid backups before running
        any fix operation in a production environment.

        The author is not responsible for service outages, data loss, broken
        domains, failed replications, lost SYSVOL content, angry users,
        unexpected side effects, thermonuclear war, or any other consequence
        caused directly or indirectly by the use or misuse of this script.

    Operational note:
        Run from an elevated PowerShell session on the remaining FSMO-owning DC.
        Review the output carefully before running --fix.

CHANGE NOTE:
- Backup consistency validation intentionally excludes domain\DfsrPrivate. This is DFSR internal private metadata, not the usable SYSVOL GPO/script payload. Protected ConflictAndDeleted/Deleted/Installing/PreExisting entries there can fail inventory comparison even when the Policies and scripts backup is valid.
- Robocopy now also excludes DfsrPrivate explicitly with /XD DfsrPrivate, in addition to /XJ.
- Added DFSR SYSVOL seeding Parent Computer validation and correction. In --fix, a stale/non-local Parent Computer is corrected to the local DC while DFSR is stopped. DFSR is then started once to reload the registry value, stopped again, and only then the authoritative D4 sequence begins.
- Added pre-change registry export of HKLM\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols into the SYSVOL backup folder before any DFSR/AD/registry recovery changes are made.
- The shared check orchestrator is mode-aware. When invoked by --fix, it does not suggest running --fix again; it reports whether the fix preflight passed, was blocked, or must stop.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:RunStart = Get-Date
$Script:ActionsDone = New-Object System.Collections.Generic.List[string]
$Script:ActionsMissing = New-Object System.Collections.Generic.List[string]
$Script:Warnings = New-Object System.Collections.Generic.List[string]
$Script:Errors = New-Object System.Collections.Generic.List[string]
$Script:MissingPrerequisites = New-Object System.Collections.Generic.List[object]
$Script:Context = [ordered]@{}
$Script:TranscriptPath = $null
$Script:CustomBackupRoot = $null
$Script:RunMode = $null

function Remove-WarningsMatching {
    param([Parameter(Mandatory=$true)][string[]]$Patterns)

    if (-not $Script:Warnings -or $Script:Warnings.Count -eq 0) { return }

    for ($idx = $Script:Warnings.Count - 1; $idx -ge 0; $idx--) {
        $warningText = [string]$Script:Warnings[$idx]
        foreach ($pattern in $Patterns) {
            if ($warningText -match $pattern) {
                $Script:Warnings.RemoveAt($idx)
                break
            }
        }
    }
}

function Clear-ResolvedRecoveryWarnings {
    <#
        During --fix the shared preflight intentionally records the initial broken state
        (State 5 / In Error and Event ID 4012 evidence). If the recovery later validates
        State 4 / Normal, Event ID 4602, SYSVOL/NETLOGON shares, and dcdiag successfully,
        those initial diagnostic warnings are no longer unresolved final warnings.
    #>
    if (-not $Script:Context.Contains('RecoverySucceeded')) { return }
    if (-not [bool]$Script:Context['RecoverySucceeded']) { return }

    Remove-WarningsMatching -Patterns @(
        '^DFSR SYSVOL state is In Error\.$',
        '^DFSR SYSVOL state is Initial Sync\.$',
        '^DFSR SYSVOL seeding Parent Computer points to a non-local or stale computer: .+$',
        '^Found DFSR problem evidence matching Event ID 4012 / Content Freshness / Error 9061\. Count in latest scan: \d+$'
    )
}

function Write-Blank {
    Write-Host ""
}

function Write-Section {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )
    Write-Blank
    Write-Host ("=" * 78) -ForegroundColor $Color
    Write-Host ("  {0}" -f $Title) -ForegroundColor $Color
    Write-Host ("=" * 78) -ForegroundColor $Color
}

function Write-SubSection {
    param([Parameter(Mandatory=$true)][string]$Title)
    Write-Blank
    Write-Host ("-- {0}" -f $Title) -ForegroundColor Yellow
}

function Write-Ok {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host ("[OK]   {0}" -f $Message) -ForegroundColor Green
}

function Write-Info {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host ("[INFO] {0}" -f $Message) -ForegroundColor Gray
}

function Write-Caution {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host ("[WARN] {0}" -f $Message) -ForegroundColor DarkYellow
}

function Write-WarnMsg {
    param([Parameter(Mandatory=$true)][string]$Message)
    $Script:Warnings.Add($Message) | Out-Null
    Write-Host ("[WARN] {0}" -f $Message) -ForegroundColor DarkYellow
}

function Write-ErrMsg {
    param([Parameter(Mandatory=$true)][string]$Message)
    Write-Host ("[ERR]  {0}" -f $Message) -ForegroundColor Red
}

function Add-ErrorSummary {
    param([Parameter(Mandatory=$true)][string]$Message)
    foreach ($item in $Script:Errors) {
        if ($item -eq $Message) { return }
    }
    $Script:Errors.Add($Message) | Out-Null
}

function Add-Done {
    param([Parameter(Mandatory=$true)][string]$Message)
    $Script:ActionsDone.Add($Message) | Out-Null
}

function Add-Missing {
    param([Parameter(Mandatory=$true)][string]$Message)
    $Script:ActionsMissing.Add($Message) | Out-Null
}

function Add-MissingPrerequisite {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [Parameter(Mandatory=$true)][string]$FeatureName,
        [Parameter(Mandatory=$true)][string]$ValidationCommand,
        [Parameter(Mandatory=$true)][string]$Reason
    )

    foreach ($item in $Script:MissingPrerequisites) {
        if ($item.Key -eq $Key) {
            return
        }
    }

    $Script:MissingPrerequisites.Add([pscustomobject]@{
        Key               = $Key
        DisplayName       = $DisplayName
        FeatureName       = $FeatureName
        ValidationCommand = $ValidationCommand
        Reason            = $Reason
    }) | Out-Null
}

function Test-PrerequisiteAvailable {
    param([Parameter(Mandatory=$true)][string]$Key)

    switch ($Key) {
        'ActiveDirectoryModule' {
            $module = Get-Module -ListAvailable -Name ActiveDirectory
            if ($module) {
                Import-Module ActiveDirectory -ErrorAction Stop
                return $true
            }
            return $false
        }
        'DfsrDiag' {
            $cmd = Get-Command dfsrdiag.exe -ErrorAction SilentlyContinue
            return [bool]$cmd
        }
        default {
            return $false
        }
    }
}

function Show-MissingPrerequisites {
    if ($Script:MissingPrerequisites.Count -eq 0) {
        return
    }

    Write-Section "Missing prerequisites" Yellow
    $Script:MissingPrerequisites |
        Select-Object DisplayName, FeatureName, Reason |
        Format-Table -AutoSize |
        Out-String |
        ForEach-Object { Write-Host $_ }
}

function Install-MissingPrerequisitesInteractive {
    param([switch]$RequiredForFix)

    if ($Script:MissingPrerequisites.Count -eq 0) {
        return $true
    }

    Show-MissingPrerequisites
    Write-WarnMsg "The script found missing Windows management tools. They are required before the full sanity checks can continue."
    Write-Info "Nothing will be installed unless you explicitly type YES."
    $answer = Read-Host "Install missing prerequisites now? Type YES to install, or anything else to stop"

    if ($answer -ne 'YES') {
        Add-Missing "Missing prerequisite installation was skipped by the operator."
        if ($RequiredForFix) {
            Stop-WithError "Required prerequisites are missing and installation was not approved. The fix cannot continue." @('Run --check again and approve prerequisite installation, or install the listed Windows features manually.')
        }
        Write-WarnMsg "Prerequisite installation skipped. The full sanity checks cannot continue until the missing tools are installed."
        return $false
    }

    $installCmd = Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue
    if (-not $installCmd) {
        Stop-WithError "Install-WindowsFeature is not available on this system." @('Install the missing RSAT / DFSR management tools manually, then run --check again.')
    }

    $features = @($Script:MissingPrerequisites | Select-Object -ExpandProperty FeatureName -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($feature in $features) {
        Write-Info "Installing Windows feature: $feature"
        try {
            $result = Install-WindowsFeature -Name $feature -IncludeManagementTools -ErrorAction Stop
            $result | Format-List | Out-String | ForEach-Object { Write-Host $_ }
            if ($result.Success -ne $true) {
                Stop-WithError "Windows feature installation did not report success: $feature" @('Review the installation output above and install the prerequisite manually if required.')
            }
        }
        catch {
            Stop-WithError "Failed to install Windows feature $feature. Error: $($_.Exception.Message)" @('Install the prerequisite manually, then run --check again.')
        }
    }

    Write-SubSection "Prerequisite re-check"
    $stillMissing = New-Object System.Collections.Generic.List[object]
    foreach ($prereq in $Script:MissingPrerequisites) {
        if (Test-PrerequisiteAvailable -Key $prereq.Key) {
            Write-Ok ("Prerequisite available: {0}" -f $prereq.DisplayName)
        }
        else {
            $stillMissing.Add($prereq) | Out-Null
            Write-ErrMsg ("Still missing after installation attempt: {0}" -f $prereq.DisplayName)
        }
    }

    if ($stillMissing.Count -gt 0) {
        Stop-WithError "One or more prerequisites are still missing after the installation attempt." @('Review the Windows feature installation output and install the missing tools manually if required.')
    }

    $Script:MissingPrerequisites.Clear()
    Remove-WarningsMatching -Patterns @(
        '^Active Directory PowerShell module is missing\.$',
        '^dfsrdiag\.exe was not found in PATH\.$',
        '^The script found missing Windows management tools\.',
        '^Prerequisite installation skipped\.'
    )
    Write-Ok "All missing prerequisites are now available."
    Add-Done "Missing prerequisite installation and validation completed."
    return $true
}

function Invoke-PrerequisiteGate {
    param([switch]$ForFix)

    Write-Section "Prerequisite checks" Cyan

    Write-SubSection "Privilege check"
    Assert-Administrator

    Write-SubSection "Required Windows management tools"
    $Script:MissingPrerequisites.Clear()

    $adModule = Get-Module -ListAvailable -Name ActiveDirectory
    if (-not $adModule) {
        Add-MissingPrerequisite -Key 'ActiveDirectoryModule' -DisplayName 'Active Directory PowerShell module' -FeatureName 'RSAT-AD-PowerShell' -ValidationCommand 'Import-Module ActiveDirectory' -Reason 'Required to query AD DS, DC topology, FSMO owners, and DFSR SYSVOL subscription objects.'
        Write-WarnMsg "Active Directory PowerShell module is missing."
    }
    else {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Ok "ActiveDirectory PowerShell module loaded."
        Add-Done "ActiveDirectory module check completed."
    }

    $dfsrdiag = Get-Command dfsrdiag.exe -ErrorAction SilentlyContinue
    if (-not $dfsrdiag) {
        Add-MissingPrerequisite -Key 'DfsrDiag' -DisplayName 'DFSRDIAG command-line tool' -FeatureName 'RSAT-DFS-Mgmt-Con' -ValidationCommand 'dfsrdiag.exe' -Reason 'Required to force DFSR to poll Active Directory with dfsrdiag pollad during the supported recovery procedure.'
        Write-WarnMsg "dfsrdiag.exe was not found in PATH."
    }
    else {
        Write-Ok "dfsrdiag.exe found: $($dfsrdiag.Source)"
        Add-Done "DFSRDIAG availability check completed."
    }

    if ($Script:MissingPrerequisites.Count -gt 0) {
        $installed = Install-MissingPrerequisitesInteractive -RequiredForFix:$ForFix
        if (-not $installed) {
            Stop-WithError "Required prerequisites are missing and installation was not approved. The full sanity checks cannot continue." @('Install the listed Windows features manually or run the script again and approve prerequisite installation.')
        }
    }

    Write-SubSection "Final prerequisite validation"
    $requiredPrereqs = @('ActiveDirectoryModule','DfsrDiag')
    $failedPrereqs = New-Object System.Collections.Generic.List[string]
    foreach ($key in $requiredPrereqs) {
        if (-not (Test-PrerequisiteAvailable -Key $key)) {
            $failedPrereqs.Add($key) | Out-Null
            Write-ErrMsg ("Prerequisite validation failed: {0}" -f $key)
        }
    }

    if ($failedPrereqs.Count -gt 0) {
        Stop-WithError "One or more prerequisites are still missing. The full sanity checks cannot continue." @('Install the missing Windows management tools, then run --check again.')
    }

    Remove-WarningsMatching -Patterns @(
        '^Active Directory PowerShell module is missing\.$',
        '^dfsrdiag\.exe was not found in PATH\.$',
        '^The script found missing Windows management tools\.'
    )

    Write-Ok "Prerequisite gate passed. Continuing with full sanity checks."
    Add-Done "Prerequisite gate completed."
}

function Show-Help {
    $scriptName = Get-ScriptDisplayName
    $scriptLogPath = Get-ScriptLogPath
    $defaultBackupRoot = Get-DefaultBackupRoot

    Write-Section "Help - Invoke-SysvolAuthoritativeSingleDC" Cyan

    Write-Host "This script checks and repairs a specific DFSR SYSVOL Content Freshness failure on a single remaining FSMO-owning Domain Controller." -ForegroundColor White
    Write-Host "It blocks unsafe scenarios, such as reachable additional DCs or stale AD Sites and Services server objects." -ForegroundColor Gray
    Write-Blank

    Write-Host "Parameters:" -ForegroundColor White
    @(
        [pscustomobject]@{
            Parameter = '--help'
            Required  = 'No'
            Description = 'Shows this help screen.'
        }
        [pscustomobject]@{
            Parameter = '--check'
            Required  = 'No'
            Description = 'Runs prerequisite and safety checks only. No DFSR/AD recovery changes are made.'
        }
        [pscustomobject]@{
            Parameter = '--fix'
            Required  = 'No'
            Description = 'Runs checks first, then repairs only if the supported single-DC DFSR SYSVOL problem is confirmed.'
        }
        [pscustomobject]@{
            Parameter = '--backup-path <path>'
            Required  = 'No'
            Description = 'Optional with --fix. Stores the timestamped SYSVOL backup under the specified root path.'
        }
    ) | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }

    Write-Host "Notes:" -ForegroundColor White
    Write-Host ("  Log file: {0}" -f $scriptLogPath) -ForegroundColor Gray
    Write-Host ("  Default backup root: {0}" -f $defaultBackupRoot) -ForegroundColor Gray
    Write-Host "  Run from an elevated PowerShell session on the remaining FSMO-owning DC." -ForegroundColor Gray
    Write-Blank

    Write-Host "Examples:" -ForegroundColor White
    Write-Host ("  .\{0} --help" -f $scriptName) -ForegroundColor Gray
    Write-Host ("  .\{0} --check" -f $scriptName) -ForegroundColor Gray
    Write-Host ("  .\{0} --fix" -f $scriptName) -ForegroundColor Gray
    Write-Host ("  .\{0} --fix --backup-path D:\SafeBackups" -f $scriptName) -ForegroundColor Gray
    Write-Host ("  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\{0} --check" -f $scriptName) -ForegroundColor Gray
    Write-Blank
}

function Get-ScriptRuntimePath {
    if ($PSCommandPath) {
        return $PSCommandPath
    }
    if ($MyInvocation.MyCommand.Path) {
        return $MyInvocation.MyCommand.Path
    }
    return $null
}

function Get-ScriptDisplayName {
    $scriptPath = Get-ScriptRuntimePath
    if ($scriptPath) {
        return (Split-Path -Leaf $scriptPath)
    }
    return 'Invoke-SysvolAuthoritativeSingleDC.ps1'
}

function Get-ScriptDirectory {
    $scriptPath = Get-ScriptRuntimePath
    if ($scriptPath) {
        return (Split-Path -Parent $scriptPath)
    }
    return (Get-Location).Path
}

function Get-DefaultBackupRoot {
    return (Get-ScriptDirectory)
}

function Get-EffectiveBackupRoot {
    if ($Script:CustomBackupRoot) {
        return $Script:CustomBackupRoot
    }
    return (Get-DefaultBackupRoot)
}

function Get-PlannedBackupPath {
    $backupRoot = Get-EffectiveBackupRoot
    return (Join-Path $backupRoot ("SYSVOL_Backup_{0}" -f (Get-Date -Format yyyyMMdd_HHmmss)))
}

function Get-ScriptLogPath {
    $scriptPath = Get-ScriptRuntimePath
    if ($scriptPath) {
        $scriptDir = Split-Path -Parent $scriptPath
        $scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptPath)
        return (Join-Path $scriptDir ($scriptBaseName + '.log'))
    }

    return (Join-Path (Get-Location).Path 'Invoke-SysvolAuthoritativeSingleDC.log')
}

function Start-LogTranscript {
    try {
        $Script:TranscriptPath = Get-ScriptLogPath
        $logDir = Split-Path -Parent $Script:TranscriptPath
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }

        Start-Transcript -Path $Script:TranscriptPath -Append | Out-Null
        Write-Info "Transcript started: $Script:TranscriptPath"
    }
    catch {
        Write-WarnMsg "Unable to start transcript logging in the script directory: $($_.Exception.Message)"
    }
}

function Stop-LogTranscript {
    try {
        if ($Script:TranscriptPath) {
            Stop-Transcript | Out-Null
        }
    }
    catch {
        # Avoid masking the original result.
    }
}

function Show-ServiceDiagnostics {
    Write-Section "Required service diagnostics" Magenta
    $serviceNames = @('DFSR','NTDS','Netlogon','DNS','KDC','W32Time','ADWS')
    $rows = foreach ($name in $serviceNames) {
        try {
            $svc = Get-Service -Name $name -ErrorAction Stop
            $startMode = 'Unknown'
            try {
                $cim = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                $startMode = $cim.StartMode
            }
            catch {
                $startMode = 'Unknown'
            }
            [pscustomobject]@{
                Service   = $name
                Exists    = 'Yes'
                Status    = $svc.Status
                StartMode = $startMode
            }
        }
        catch {
            [pscustomobject]@{
                Service   = $name
                Exists    = 'No'
                Status    = 'Not installed or not visible'
                StartMode = '-'
            }
        }
    }
    $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
}


function New-SuggestedActionObject {
    param(
        [Parameter(Mandatory=$true)][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Message
    )

    return [pscustomobject]@{
        Severity = $Severity
        Message  = $Message
    }
}

function Get-SuggestedActions {
    $actions = New-Object System.Collections.Generic.List[object]
    $scriptName = Get-ScriptDisplayName

    $siteBlockers = @()
    if ($Script:Context.Contains('SitesServerObjectBlockers') -and $Script:Context['SitesServerObjectBlockers']) {
        $siteBlockers = @($Script:Context['SitesServerObjectBlockers'])
    }
    $hasSiteBlockers = ($siteBlockers.Count -gt 0)

    $problemMatches = $false
    if ($Script:Context.Contains('ProblemMatches')) {
        $problemMatches = [bool]$Script:Context['ProblemMatches']
    }

    $dfsrState = $null
    if ($Script:Context.Contains('DfsrInfo') -and $Script:Context['DfsrInfo']) {
        try { $dfsrState = [int]$Script:Context['DfsrInfo'].State } catch { $dfsrState = $null }
    }

    $recoverySucceeded = $false
    if ($Script:Context.Contains('RecoverySucceeded')) {
        $recoverySucceeded = [bool]$Script:Context['RecoverySucceeded']
    }

    if ($recoverySucceeded) {
        $actions.Add((New-SuggestedActionObject -Severity 'OK' -Message 'Take no further recovery action at this time. The authoritative SYSVOL recovery completed successfully.')) | Out-Null
        $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Keep the generated SYSVOL backup and log file. They document the recovery and provide a restore/reference point if you need to review the operation later.')) | Out-Null
        return $actions
    }

    if ($Script:Errors.Count -gt 0) {
        $errorText = (($Script:Errors | ForEach-Object { [string]$_ }) -join ' ')

        if ($errorText -match 'already State 4 / Normal|No fix is required') {
            $actions.Add((New-SuggestedActionObject -Severity 'OK' -Message 'Take no recovery action. DFSR SYSVOL is already State 4 / Normal.')) | Out-Null
            $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message ("Run .\{0} --check for confirmation. This repeats the sanity checks and verifies that the final result remains conformant." -f $scriptName))) | Out-Null
            return $actions
        }

        if ($errorText -match 'AD Sites and Services|stale server object|server objects') {
            $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message 'Validate or remove the listed stale server objects in Active Directory Sites and Services, then run --check again. This clears the safety blocker that prevents the recovery from running while orphaned DC references remain.')) | Out-Null
            return $actions
        }

        if ($errorText -match 'prerequisite|dfsrdiag|ActiveDirectory|RSAT|management tools') {
            $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message 'Install the missing management tools, or accept the script prompt to install them, then run --check again. This makes the required AD/DFSR validation commands available before any recovery is attempted.')) | Out-Null
            return $actions
        }

        $actions.Add((New-SuggestedActionObject -Severity 'ERR' -Message 'Resolve the error or errors listed above, then run --check again. This prevents --fix from running while the environment is not in a safe and supported state.')) | Out-Null
        return $actions
    }

    if ($hasSiteBlockers) {
        $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message 'Validate or remove the listed stale server objects in Active Directory Sites and Services, then run --check again. This clears the safety blocker that prevents the recovery from running while orphaned DC references remain.')) | Out-Null
        return $actions
    }

    if ($problemMatches) {
        $runMode = $null
        if ($Script:Context.Contains('RunMode')) { $runMode = [string]$Script:Context['RunMode'] }
        if ([string]::IsNullOrWhiteSpace($runMode)) { $runMode = [string]$Script:RunMode }

        if ($runMode -eq 'Fix') {
            $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Wait for the current --fix run to complete. The shared preflight has confirmed a supported single-DC DFSR SYSVOL recovery scenario and the recovery phase is now responsible for continuing or stopping safely.')) | Out-Null
            return $actions
        }

        $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message ("Run .\{0} --fix from an elevated PowerShell session. This starts the supported single-DC DFSR SYSVOL recovery and validates the SYSVOL backup before modifying DFSR/AD." -f $scriptName))) | Out-Null
        $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Review the backup validation result shown during --fix. This confirms SYSVOL was copied consistently before the recovery makes DFSR/AD changes.')) | Out-Null
        return $actions
    }

    if ($dfsrState -eq 4) {
        $actions.Add((New-SuggestedActionObject -Severity 'OK' -Message 'Take no action. DFSR SYSVOL is State 4 / Normal and the checks are conformant for this scenario.')) | Out-Null
        return $actions
    }

    if ($null -ne $dfsrState) {
        $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message 'Do not run --fix. The supported single-DC recovery pattern was not detected. The script supports State 5 with Content Freshness evidence, or State 2 Initial Sync with a stale/non-local SYSVOL seeding Parent Computer.')) | Out-Null
        return $actions
    }

    $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Run --check before deciding whether --fix is applicable. This performs the required safety gates and determines whether the supported recovery scenario is present.')) | Out-Null
    return $actions
}

function Show-SuggestedActions {
    Write-SubSection "Suggested actions"
    $actions = @(Get-SuggestedActions)
    if ($actions.Count -eq 0) {
        Write-Host "No suggested action could be derived from the current run." -ForegroundColor Gray
        return
    }

    foreach ($action in $actions) {
        switch ($action.Severity) {
            'OK'   { Write-Host ("{0}" -f $action.Message) -ForegroundColor Green }
            'WARN' { Write-Host ("{0}" -f $action.Message) -ForegroundColor DarkYellow }
            'ERR'  { Write-Host ("{0}" -f $action.Message) -ForegroundColor Red }
            default { Write-Host ("{0}" -f $action.Message) -ForegroundColor Gray }
        }
    }
}

function Show-ActionSummary {
    param([string]$Result = 'Summary')

    Write-Section "Execution summary - $Result" Cyan

    Write-SubSection "Completed actions"
    if ($Script:ActionsDone.Count -eq 0) {
        Write-Info "No actions were completed."
    }
    else {
        foreach ($item in $Script:ActionsDone) { Write-Ok $item }
    }

    Write-SubSection "Missing or skipped actions"
    if ($Script:ActionsMissing.Count -eq 0) {
        Write-Ok "No missing actions."
    }
    else {
        foreach ($item in $Script:ActionsMissing) { Write-ErrMsg $item }
    }

    Write-SubSection "Errors"
    if ($Script:Errors.Count -eq 0) {
        Write-Ok "No errors recorded."
    }
    else {
        foreach ($item in @($Script:Errors)) { Write-Host ("[ERR]  {0}" -f $item) -ForegroundColor Red }
    }

    Write-SubSection "Warnings"
    if ($Script:Warnings.Count -eq 0) {
        Write-Ok "No warnings recorded."
    }
    else {
        foreach ($item in @($Script:Warnings)) { Write-Host ("[WARN] {0}" -f $item) -ForegroundColor DarkYellow }
    }

    if ($Script:TranscriptPath) {
        Write-SubSection "Log file"
        Write-Host ("  {0}" -f $Script:TranscriptPath) -ForegroundColor Gray
    }

    Show-SuggestedActions
}

function Stop-WithError {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string[]]$Missing
    )

    Write-Section "Stopped because of an error" Red
    Write-ErrMsg $Message
    Add-ErrorSummary $Message
    if ($Missing) {
        foreach ($m in $Missing) { Add-Missing $m }
    }
    Show-ServiceDiagnostics
    Show-ActionSummary -Result 'FAILED'
    Stop-LogTranscript
    exit 1
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-WithError "This script must be run from an elevated PowerShell session." @('Run PowerShell as Administrator.')
    }
    Write-Ok "PowerShell is elevated."
    Add-Done "Privilege check completed."
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [int]$Port = 389,
        [int]$TimeoutMs = 1500
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $success) {
            $client.Close()
            return $false
        }
        $client.EndConnect($async)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Get-LocalNames {
    $names = New-Object System.Collections.Generic.List[string]
    $names.Add($env:COMPUTERNAME.ToLowerInvariant()) | Out-Null
    try {
        $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
        if ($fqdn) { $names.Add($fqdn.ToLowerInvariant()) | Out-Null }
    }
    catch {}
    try {
        $fqdn2 = "$($env:COMPUTERNAME).$((Get-ADDomain).DNSRoot)"
        $names.Add($fqdn2.ToLowerInvariant()) | Out-Null
    }
    catch {}
    return $names.ToArray() | Select-Object -Unique
}

function Test-IsLocalName {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string[]]$LocalNames
    )

    $lower = $Name.ToLowerInvariant()
    $short = ($lower -split '\.')[0]
    return (($LocalNames -contains $lower) -or ($LocalNames -contains $short))
}


function Get-DfsrSysvolSeedingParentInfo {
    param(
        [Parameter(Mandatory=$true)][string]$DomainDnsRoot,
        [Parameter(Mandatory=$true)][string]$LocalDcHostName,
        [Parameter(Mandatory=$true)][string[]]$LocalNames
    )

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols\Seeding SysVols\$DomainDnsRoot"
    $expectedParent = [string]$LocalDcHostName
    if ([string]::IsNullOrWhiteSpace($expectedParent)) {
        $expectedParent = "$env:COMPUTERNAME.$DomainDnsRoot"
    }

    $exists = Test-Path -LiteralPath $registryPath
    $parentComputer = $null
    $readError = $null

    if ($exists) {
        try {
            $props = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
            $parentComputer = [string]$props.'Parent Computer'
        }
        catch {
            $readError = $_.Exception.Message
        }
    }

    $hasParent = -not [string]::IsNullOrWhiteSpace($parentComputer)
    $isLocalParent = $false
    if ($hasParent) {
        $isLocalParent = Test-IsLocalName -Name $parentComputer -LocalNames $LocalNames
    }

    $needsCorrection = ($exists -and $hasParent -and -not $isLocalParent)

    return [pscustomobject]@{
        RegistryPath           = $registryPath
        Exists                 = [bool]$exists
        ParentComputer         = $parentComputer
        ExpectedParentComputer = $expectedParent
        HasParentComputer      = [bool]$hasParent
        IsLocalParent          = [bool]$isLocalParent
        NeedsCorrection        = [bool]$needsCorrection
        ReadError              = $readError
    }
}

function Set-DfsrSysvolSeedingParentToLocal {
    param(
        [Parameter(Mandatory=$true)][object]$Info
    )

    if (-not [bool]$Info.Exists) {
        Write-Info "DFSR SYSVOL seeding registry key does not exist. No registry correction is required."
        return $false
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Info.ReadError)) {
        Stop-WithError "Unable to read DFSR SYSVOL seeding registry key before correction: $($Info.ReadError)" @(
            "Registry path: $($Info.RegistryPath)",
            'No DFSR/AD recovery changes were made after this registry read failure.'
        )
    }

    if (-not [bool]$Info.HasParentComputer) {
        Write-Info "DFSR SYSVOL seeding Parent Computer is empty. No registry correction is required."
        return $false
    }

    if (-not [bool]$Info.NeedsCorrection) {
        Write-Ok "DFSR SYSVOL seeding Parent Computer already points to the local DC."
        return $false
    }

    $oldParent = [string]$Info.ParentComputer
    $newParent = [string]$Info.ExpectedParentComputer

    Write-WarnMsg "Correcting DFSR SYSVOL seeding Parent Computer from '$oldParent' to '$newParent'."
    Set-ItemProperty -LiteralPath ([string]$Info.RegistryPath) -Name 'Parent Computer' -Value $newParent -ErrorAction Stop

    $verify = Get-ItemProperty -LiteralPath ([string]$Info.RegistryPath) -ErrorAction Stop
    $actual = [string]$verify.'Parent Computer'
    if ($actual -ne $newParent) {
        Stop-WithError "DFSR SYSVOL seeding Parent Computer verification failed after registry correction." @(
            "Registry path: $($Info.RegistryPath)",
            "Expected: $newParent",
            "Actual: $actual"
        )
    }

    Write-Ok "DFSR SYSVOL seeding Parent Computer corrected to local DC: $newParent"
    Add-Done "DFSR SYSVOL seeding Parent Computer corrected."
    return $true
}

function Invoke-DfsrServiceReloadAfterSeedingParentCorrection {
    Write-Section "Reload DFSR after SYSVOL seeding parent registry correction" Cyan
    Write-Info "Starting DFSR once after the registry correction so the service reloads the SYSVOL seeding Parent Computer value before the authoritative D4 sequence."

    Start-Service DFSR
    Write-Ok "DFSR service started after SYSVOL seeding Parent Computer correction."

    try {
        Invoke-DfsrPollAd -Context 'after SYSVOL seeding Parent Computer registry correction'
    }
    catch {
        Write-WarnMsg "DFSR AD polling after registry correction failed or was unavailable: $($_.Exception.Message)"
    }

    Stop-Service DFSR -Force
    Write-Ok "DFSR service stopped again before authoritative D4 attribute changes."
    Add-Done "DFSR service reloaded after SYSVOL seeding Parent Computer correction."
}

function Test-IsReparsePoint {
    param([Parameter(Mandatory=$true)][System.IO.FileSystemInfo]$Item)

    return (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Test-RelativePathExcluded {
    param(
        [Parameter(Mandatory=$true)][string]$RelativePath,
        [string[]]$ExcludeRelativePrefixes = @()
    )

    if ($null -eq $ExcludeRelativePrefixes -or $ExcludeRelativePrefixes.Count -eq 0) { return $false }

    $normalized = $RelativePath.TrimStart('\')
    foreach ($prefix in $ExcludeRelativePrefixes) {
        if ([string]::IsNullOrWhiteSpace($prefix)) { continue }
        $normalizedPrefix = $prefix.Trim('\')
        if ($normalized -ieq $normalizedPrefix) { return $true }
        if ($normalized.StartsWith($normalizedPrefix + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }

    return $false
}

function Get-InventoryItemsForBackupValidation {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$ExcludeReparsePoints,
        [string[]]$ExcludeRelativePrefixes = @()
    )

    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $root = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName.TrimEnd('\')
    $items = New-Object System.Collections.Generic.List[System.IO.FileSystemInfo]

    function Add-InventoryItemsForBackupValidation {
        param([Parameter(Mandatory=$true)][string]$CurrentPath)

        $children = @(Get-ChildItem -LiteralPath $CurrentPath -Force -ErrorAction Stop)
        foreach ($child in $children) {
            if ($child.FullName.Length -le $root.Length) { continue }

            $relative = $child.FullName.Substring($root.Length).TrimStart('\')
            if ([string]::IsNullOrWhiteSpace($relative)) { continue }

            if (Test-RelativePathExcluded -RelativePath $relative -ExcludeRelativePrefixes $ExcludeRelativePrefixes) {
                continue
            }

            $isReparsePoint = Test-IsReparsePoint -Item $child
            if ($ExcludeReparsePoints -and $isReparsePoint) {
                continue
            }

            $items.Add($child) | Out-Null

            if ($child.PSIsContainer) {
                Add-InventoryItemsForBackupValidation -CurrentPath $child.FullName
            }
        }
    }

    Add-InventoryItemsForBackupValidation -CurrentPath $root
    return @($items)
}

function Get-TreeStats {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$ExcludeReparsePoints,
        [string[]]$ExcludeRelativePrefixes = @()
    )

    $relativeExclusionsText = if ($ExcludeRelativePrefixes -and $ExcludeRelativePrefixes.Count -gt 0) { ($ExcludeRelativePrefixes -join '; ') } else { '' }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Path = $Path; Exists = $false; Directories = 0; Files = 0; Bytes = 0; ReparseExcluded = [bool]$ExcludeReparsePoints; RelativeExclusions = $relativeExclusionsText }
    }

    $items = @(Get-InventoryItemsForBackupValidation -Path $Path -ExcludeReparsePoints:$ExcludeReparsePoints -ExcludeRelativePrefixes $ExcludeRelativePrefixes)

    $dirs = @($items | Where-Object { $_.PSIsContainer }).Count
    $fileItems = @($items | Where-Object { -not $_.PSIsContainer })
    $files = $fileItems.Count
    $bytes = ($fileItems | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $bytes) { $bytes = 0 }

    return [pscustomobject]@{
        Path               = $Path
        Exists             = $true
        Directories        = $dirs
        Files              = $files
        Bytes              = [int64]$bytes
        ReparseExcluded    = [bool]$ExcludeReparsePoints
        RelativeExclusions = $relativeExclusionsText
    }
}

function Get-RelativeTreeEntries {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][ValidateSet('File','Directory')][string]$Kind,
        [switch]$ExcludeReparsePoints,
        [string[]]$ExcludeRelativePrefixes = @()
    )

    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $root = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName.TrimEnd('\')
    $items = @(Get-InventoryItemsForBackupValidation -Path $root -ExcludeReparsePoints:$ExcludeReparsePoints -ExcludeRelativePrefixes $ExcludeRelativePrefixes)

    if ($Kind -eq 'Directory') {
        $items = @($items | Where-Object { $_.PSIsContainer })
    }
    else {
        $items = @($items | Where-Object { -not $_.PSIsContainer })
    }

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($item in $items) {
        if ($item.FullName.Length -le $root.Length) { continue }
        $relative = $item.FullName.Substring($root.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($relative)) { continue }
        $result.Add($relative) | Out-Null
    }

    return @($result | Sort-Object)
}

function Show-RelativeEntryDifferences {
    param(
        [Parameter(Mandatory=$true)][string[]]$SourceEntries,
        [Parameter(Mandatory=$true)][string[]]$BackupEntries,
        [Parameter(Mandatory=$true)][string]$EntryType,
        [int]$MaxToShow = 30
    )

    $diff = @(Compare-Object -ReferenceObject $SourceEntries -DifferenceObject $BackupEntries)
    if ($diff.Count -eq 0) { return $false }

    $missing = @($diff | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject)
    $extra = @($diff | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject)

    if ($missing.Count -gt 0) {
        Write-ErrMsg ("Missing {0} in backup: {1}" -f $EntryType, $missing.Count)
        $missing | Select-Object -First $MaxToShow | ForEach-Object {
            Write-Host ("  - {0}" -f $_) -ForegroundColor Red
        }
        if ($missing.Count -gt $MaxToShow) {
            Write-Host ("  ... {0} more not shown" -f ($missing.Count - $MaxToShow)) -ForegroundColor Red
        }
    }

    if ($extra.Count -gt 0) {
        Write-WarnMsg ("Extra {0} in backup: {1}" -f $EntryType, $extra.Count)
        $extra | Select-Object -First $MaxToShow | ForEach-Object {
            Write-Host ("  + {0}" -f $_) -ForegroundColor DarkYellow
        }
        if ($extra.Count -gt $MaxToShow) {
            Write-Host ("  ... {0} more not shown" -f ($extra.Count - $MaxToShow)) -ForegroundColor DarkYellow
        }
    }

    return $true
}

function Test-SysvolBackupConsistency {
    param(
        [Parameter(Mandatory=$true)][string]$SourceDomain,
        [Parameter(Mandatory=$true)][string]$BackupDomain
    )

    Write-SubSection "Backup consistency check"

    $backupValidationExclusions = @('DfsrPrivate')

    Write-Info "Comparing SYSVOL domain trees while excluding reparse points/junctions, matching Robocopy /XJ behavior."
    Write-Info "Excluding DFSR internal private metadata from backup validation: DfsrPrivate. This folder is not part of the usable GPO/script payload and may contain protected conflict/deleted staging data."

    $sourceStats = Get-TreeStats -Path $SourceDomain -ExcludeReparsePoints -ExcludeRelativePrefixes $backupValidationExclusions
    $backupStats = Get-TreeStats -Path $BackupDomain -ExcludeReparsePoints -ExcludeRelativePrefixes $backupValidationExclusions

    @($sourceStats, $backupStats) | Format-Table Path,Exists,Directories,Files,Bytes,ReparseExcluded,RelativeExclusions -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

    $sourceDirs = @(Get-RelativeTreeEntries -Path $SourceDomain -Kind Directory -ExcludeReparsePoints -ExcludeRelativePrefixes $backupValidationExclusions)
    $backupDirs = @(Get-RelativeTreeEntries -Path $BackupDomain -Kind Directory -ExcludeReparsePoints -ExcludeRelativePrefixes $backupValidationExclusions)
    $sourceFiles = @(Get-RelativeTreeEntries -Path $SourceDomain -Kind File -ExcludeReparsePoints -ExcludeRelativePrefixes $backupValidationExclusions)
    $backupFiles = @(Get-RelativeTreeEntries -Path $BackupDomain -Kind File -ExcludeReparsePoints -ExcludeRelativePrefixes $backupValidationExclusions)

    $dirDiff = Show-RelativeEntryDifferences -SourceEntries $sourceDirs -BackupEntries $backupDirs -EntryType 'directories'
    $fileDiff = Show-RelativeEntryDifferences -SourceEntries $sourceFiles -BackupEntries $backupFiles -EntryType 'files'

    if ($sourceStats.Files -ne $backupStats.Files -or $sourceStats.Bytes -ne $backupStats.Bytes -or $fileDiff) {
        Stop-WithError "Backup verification failed. Source and backup file inventory do not match." @('No DFSR/AD changes were made after backup consistency failure.', 'Review the missing/extra file list above, then rerun --fix.')
    }

    if ($sourceStats.Directories -ne $backupStats.Directories -or $dirDiff) {
        Stop-WithError "Backup verification failed. Source and backup directory inventory do not match." @('No DFSR/AD changes were made after backup consistency failure.', 'Review the missing/extra directory list above, then rerun --fix.')
    }

    Write-Ok "Backup consistency check passed."
}

function Get-DfsrSysvolInfo {
    try {
        return Get-CimInstance -Namespace 'root\MicrosoftDFS' -ClassName 'DfsrReplicatedFolderInfo' -Filter "ReplicatedFolderName='SYSVOL Share'" -ErrorAction Stop
    }
    catch {
        try {
            return Get-WmiObject -Namespace 'root\MicrosoftDFS' -Class 'DfsrReplicatedFolderInfo' -Filter "ReplicatedFolderName='SYSVOL Share'" -ErrorAction Stop
        }
        catch {
            return $null
        }
    }
}

function Convert-DfsrState {
    param([int]$State)
    switch ($State) {
        0 { return '0 - Uninitialized' }
        1 { return '1 - Initialized' }
        2 { return '2 - Initial Sync' }
        3 { return '3 - Auto Recovery' }
        4 { return '4 - Normal' }
        5 { return '5 - In Error' }
        default { return "$State - Unknown" }
    }
}

function Get-DfsrProblemEvents {
    try {
        $all = Get-WinEvent -LogName 'DFS Replication' -MaxEvents 300 -ErrorAction Stop
        return @($all | Where-Object {
            ($_.Id -eq 4012) -or
            ($_.Message -match '9061') -or
            ($_.Message -match 'MaxOfflineTimeInDays') -or
            ($_.Message -match 'Content Freshness') -or
            ($_.Message -match 'stale') -or
            ($_.Message -match 'offline too long') -or
            ($_.Message -match 'troppo a lungo') -or
            ($_.Message -match 'rimasta offline')
        })
    }
    catch {
        Write-WarnMsg "Unable to read the DFS Replication event log: $($_.Exception.Message)"
        return @()
    }
}

function Show-RecentDfsrEvents {
    Write-SubSection "Recent relevant DFS Replication events"
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; Id = 4012,4114,4602,4604,4612,4614,5002,5008,5014 } -MaxEvents 20 -ErrorAction Stop
        if (-not $events) {
            Write-Info "No relevant DFS Replication events found in the latest event scan."
            return
        }
        $rows = $events | Select-Object TimeCreated, Id, @{Name='ShortMessage'; Expression={
            $msg = $_.Message -replace "`r|`n", ' '
            if ($msg.Length -gt 180) { $msg.Substring(0,180) + '...' } else { $msg }
        }}
        $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    }
    catch {
        Write-WarnMsg "Unable to read recent DFS Replication events: $($_.Exception.Message)"
    }
}

function Test-BackupRootReadiness {
    param([switch]$ForFix)

    Write-SubSection "Backup location checks"

    $backupRoot = Get-EffectiveBackupRoot
    $isCustom = [bool]$Script:CustomBackupRoot
    $Script:Context['BackupRoot'] = $backupRoot

    Write-Info ("Backup root: {0}" -f $backupRoot)
    if ($isCustom) {
        Write-Info "Backup root source: --backup-path"
    }
    else {
        Write-Info "Backup root source: script directory default"
    }

    if ([string]::IsNullOrWhiteSpace($backupRoot)) {
        Stop-WithError "Backup root is empty." @('Provide a valid path using --backup-path or run the script from a normal filesystem directory.')
    }

    if (Test-Path -LiteralPath $backupRoot -PathType Leaf) {
        Stop-WithError "Backup root points to a file, not a directory: $backupRoot" @('Provide a directory path with --backup-path.')
    }

    if (Test-Path -LiteralPath $backupRoot -PathType Container) {
        Write-Ok "Backup root directory exists."
    }
    else {
        if ($ForFix) {
            $parent = Split-Path -Parent $backupRoot
            if ([string]::IsNullOrWhiteSpace($parent)) {
                Stop-WithError "Backup root does not exist and its parent path cannot be determined: $backupRoot" @('Create the backup directory manually or provide a different --backup-path.')
            }
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                Stop-WithError "Backup root does not exist and parent directory is missing: $parent" @('Create the parent directory first or provide a different --backup-path.')
            }
            Write-WarnMsg "Backup root does not exist. It will be created during --fix: $backupRoot"
        }
        else {
            Write-WarnMsg "Backup root does not exist. In --fix mode, the script will create it if the parent directory exists: $backupRoot"
        }
    }

    $plannedBackup = Join-Path $backupRoot ("SYSVOL_Backup_{0}" -f (Get-Date -Format yyyyMMdd_HHmmss))
    $Script:Context['PlannedBackupPath'] = $plannedBackup
    Write-Info ("Planned backup folder example for this run: {0}" -f $plannedBackup)

    if ($ForFix) {
        if (-not (Test-Path -LiteralPath $backupRoot -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $backupRoot -Force -ErrorAction Stop | Out-Null
                Write-Ok "Backup root directory created."
            }
            catch {
                Stop-WithError "Unable to create backup root directory: $backupRoot. Error: $($_.Exception.Message)" @('No DFSR/AD changes were made. Create the directory manually or use --backup-path with a writable location.')
            }
        }

        $probePath = Join-Path $backupRoot (".sysvol_backup_write_test_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
        try {
            Set-Content -LiteralPath $probePath -Value 'write test' -Encoding ASCII -ErrorAction Stop
            Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
            Write-Ok "Backup root is writable."
        }
        catch {
            Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
            Stop-WithError "Backup root is not writable: $backupRoot. Error: $($_.Exception.Message)" @('No DFSR/AD changes were made. Use --backup-path with a writable location.')
        }
    }

    Add-Done "Backup location check completed."
}


function Get-AdSitesAndServicesServerObjectReport {
    param(
        [Parameter(Mandatory=$true)][object[]]$KnownDcs,
        [Parameter(Mandatory=$true)]$LocalNames
    )

    $rootDse = Get-ADRootDSE -ErrorAction Stop
    $configurationNc = [string]$rootDse.ConfigurationNamingContext
    $sitesBase = "CN=Sites,$configurationNc"

    $knownDcNames = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($dc in $KnownDcs) {
        foreach ($candidate in @($dc.Name, $dc.HostName)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
                $null = $knownDcNames.Add(([string]$candidate).ToLowerInvariant())
                $short = (([string]$candidate) -split '\.')[0]
                if (-not [string]::IsNullOrWhiteSpace($short)) {
                    $null = $knownDcNames.Add($short.ToLowerInvariant())
                }
            }
        }
    }

    $serverObjects = @(Get-ADObject -SearchBase $sitesBase -LDAPFilter '(objectClass=server)' -SearchScope Subtree -Properties dNSHostName,serverReference -ErrorAction Stop)

    foreach ($server in $serverObjects) {
        $dnsHostName = $null
        if ($server.PSObject.Properties.Name -contains 'dNSHostName') {
            $dnsHostName = [string]$server.dNSHostName
        }

        $siteName = 'Unknown'
        if ($server.DistinguishedName -match '^CN=[^,]+,CN=Servers,CN=([^,]+),CN=Sites,') {
            $siteName = $Matches[1]
        }

        $nameCandidates = @($server.Name, $dnsHostName) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }

        $isLocal = $false
        foreach ($candidate in $nameCandidates) {
            if (Test-IsLocalName -Name ([string]$candidate) -LocalNames $LocalNames) {
                $isLocal = $true
            }
        }

        $isKnownDc = $false
        foreach ($candidate in $nameCandidates) {
            $candidateString = [string]$candidate
            $candidateShort = ($candidateString -split '\.')[0]
            if ($knownDcNames.Contains($candidateString.ToLowerInvariant()) -or $knownDcNames.Contains($candidateShort.ToLowerInvariant())) {
                $isKnownDc = $true
            }
        }

        $ntdsObjects = @()
        try {
            $ntdsObjects = @(Get-ADObject -SearchBase $server.DistinguishedName -LDAPFilter '(objectClass=nTDSDSA)' -SearchScope OneLevel -Properties DistinguishedName -ErrorAction Stop)
        }
        catch {
            $ntdsObjects = @()
        }

        $connectionCount = 0
        foreach ($ntdsObject in $ntdsObjects) {
            try {
                $connections = @(Get-ADObject -SearchBase $ntdsObject.DistinguishedName -LDAPFilter '(objectClass=nTDSConnection)' -SearchScope OneLevel -ErrorAction Stop)
                $connectionCount += $connections.Count
            }
            catch {
                # Keep the report readable even when a child query fails.
            }
        }

        $serverReferenceValue = $null
        if ($server.PSObject.Properties.Name -contains 'serverReference') {
            $serverReferenceValue = [string]$server.serverReference
        }

        $serverReferenceExists = $false
        if (-not [string]::IsNullOrWhiteSpace($serverReferenceValue)) {
            try {
                $null = Get-ADObject -Identity $serverReferenceValue -ErrorAction Stop
                $serverReferenceExists = $true
            }
            catch {
                $serverReferenceExists = $false
            }
        }

        $hasNtdsSettings = ($ntdsObjects.Count -gt 0)
        $blocksFix = $false
        $classification = 'OK'

        if ($isLocal) {
            if ($hasNtdsSettings) {
                $classification = 'Local DC server object'
            }
            else {
                $classification = 'Local server object without NTDS Settings'
                $blocksFix = $true
            }
        }
        else {
            $blocksFix = $true
            if ($hasNtdsSettings) {
                $classification = 'Non-local or stale DC metadata; NTDS Settings present'
            }
            elseif (-not $isKnownDc) {
                $classification = 'Orphaned non-local site server object'
            }
            else {
                $classification = 'Non-local Domain Controller server object'
            }
        }

        [pscustomobject]@{
            Site                    = $siteName
            ServerName              = [string]$server.Name
            DnsHostName             = $dnsHostName
            IsLocal                 = $isLocal
            KnownAsDomainController = $isKnownDc
            HasNtdsSettings         = $hasNtdsSettings
            ConnectionObjects       = $connectionCount
            ServerReferenceExists   = $serverReferenceExists
            BlocksFix               = $blocksFix
            Classification          = $classification
            DistinguishedName       = [string]$server.DistinguishedName
        }
    }
}

function Test-SitesAndServicesServerObjectGate {
    param(
        [Parameter(Mandatory=$true)][object[]]$KnownDcs,
        [Parameter(Mandatory=$true)]$LocalNames,
        [switch]$ForFix
    )

    Write-SubSection "AD Sites and Services stale server object gate"

    try {
        $report = @(Get-AdSitesAndServicesServerObjectReport -KnownDcs $KnownDcs -LocalNames $LocalNames)
    }
    catch {
        Stop-WithError "Unable to inspect AD Sites and Services server objects: $($_.Exception.Message)" @('Verify Configuration partition access and AD DS health before running the fix.')
    }

    if ($report.Count -eq 0) {
        Stop-WithError "No server objects were found under AD Sites and Services." @('Investigate AD Sites and Services metadata before running any SYSVOL repair.')
    }

    $report |
        Select-Object Site,ServerName,DnsHostName,IsLocal,KnownAsDomainController,HasNtdsSettings,ConnectionObjects,ServerReferenceExists,BlocksFix,Classification |
        Format-Table -AutoSize |
        Out-String |
        ForEach-Object { Write-Host $_ }

    $blockers = @($report | Where-Object { $_.BlocksFix })
    $Script:Context['SitesServerObjects'] = $report
    $Script:Context['SitesServerObjectBlockers'] = $blockers

    if ($blockers.Count -gt 0) {
        Write-WarnMsg ("Found {0} non-local/stale AD Sites and Services server object(s). --fix is blocked until they are manually verified and cleaned up." -f $blockers.Count)
        Write-Info "This script will not delete AD Sites and Services objects."
        Write-Info "If an obsolete server object is empty and has no NTDS Settings, remove it manually from Active Directory Sites and Services after verification."
        Write-Info "If an obsolete object still has NTDS Settings, perform proper AD metadata cleanup instead of blind deletion."

        $blockers |
            Select-Object Site,ServerName,HasNtdsSettings,ConnectionObjects,ServerReferenceExists,Classification,DistinguishedName |
            Format-List |
            Out-String |
            ForEach-Object { Write-Host $_ }

        Add-Missing "Clean up or validate the non-local/stale AD Sites and Services server objects before running --fix. This script does not remove them."

        if ($ForFix) {
            Stop-WithError "AD Sites and Services is not conformant for this single-DC recovery procedure." @('Remove only confirmed obsolete empty server containers manually, or perform proper metadata cleanup for stale DC metadata with NTDS Settings, then run --check again.')
        }
    }
    else {
        Write-Ok "No non-local/stale AD Sites and Services server objects detected."
    }

    Add-Done "AD Sites and Services stale object gate completed."
}

function Test-HasSitesAndServicesBlockers {
    if ($Script:Context.Contains('SitesServerObjectBlockers') -and $Script:Context['SitesServerObjectBlockers']) {
        $blockers = @($Script:Context['SitesServerObjectBlockers'])
        return ($blockers.Count -gt 0)
    }
    return $false
}

function Invoke-SitesAndServicesConsolePrompt {
    param([string]$Reason = 'Stale or non-local AD Sites and Services server objects were detected.')

    if (-not (Test-HasSitesAndServicesBlockers)) {
        return
    }

    Write-Section "Optional console launch - Active Directory Sites and Services" DarkCyan
    Write-WarnMsg $Reason
    Write-Info "The script will not delete or modify any AD Sites and Services object."
    Write-Info "Use the console only to review and manually clean up confirmed obsolete server objects."
    Write-Info "If an obsolete server object still contains NTDS Settings, perform proper AD metadata cleanup instead of blind deletion."

    $mscPath = Join-Path $env:SystemRoot 'System32\dssite.msc'
    if (-not (Test-Path -LiteralPath $mscPath)) {
        Write-WarnMsg "dssite.msc was not found at: $mscPath"
        Write-Info "Open Active Directory Sites and Services manually from Server Manager / Tools, or install the AD DS management tools."
        return
    }

    try {
        $answer = Read-Host "Type YES to open Active Directory Sites and Services now, or press ENTER to skip"
    }
    catch {
        Write-WarnMsg "Unable to read interactive input, so the console was not opened: $($_.Exception.Message)"
        return
    }

    if ($answer -eq 'YES') {
        try {
            Start-Process -FilePath 'mmc.exe' -ArgumentList @('"' + $mscPath + '"') | Out-Null
            Write-Ok "Active Directory Sites and Services console launched."
        }
        catch {
            Write-WarnMsg "Unable to launch Active Directory Sites and Services: $($_.Exception.Message)"
            Write-Info "You can open it manually by running: dssite.msc"
        }
    }
    else {
        Write-Info "Console launch skipped by user."
    }
}

function Invoke-SanityCheck {
    param([switch]$ForFix)

    Write-Section "Sanity checks" Cyan

    Write-SubSection "Prerequisite status"
    Write-Ok "Prerequisite gate already completed. AD/DFSR sanity checks can continue."

    Test-BackupRootReadiness -ForFix:$ForFix

    Write-SubSection "Domain and local DC identity"
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        $localDc = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
        $localComputer = Get-ADComputer -Identity $env:COMPUTERNAME -Properties DistinguishedName -ErrorAction Stop
    }
    catch {
        Stop-WithError "Unable to query Active Directory from this server: $($_.Exception.Message)" @('Confirm this server is a working Domain Controller and AD DS is running.')
    }

    $localNames = Get-LocalNames
    $Script:Context['Domain'] = $domain
    $Script:Context['Forest'] = $forest
    $Script:Context['LocalDc'] = $localDc
    $Script:Context['LocalComputer'] = $localComputer
    $Script:Context['LocalNames'] = $localNames

    Write-Info "Domain DNS root: $($domain.DNSRoot)"
    Write-Info "Forest name: $($forest.Name)"
    Write-Info "Local DC: $($localDc.HostName)"
    Write-Ok "Local server is a Domain Controller."
    Add-Done "Domain identity check completed."

    Write-SubSection "Domain Controller topology safety gate"
    $allDcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
    if ($allDcs.Count -eq 0) {
        Stop-WithError "No Domain Controllers were returned by Active Directory." @('Investigate AD DS health before running any SYSVOL repair.')
    }

    $dcReport = foreach ($dc in $allDcs) {
        $isLocal = Test-IsLocalName -Name $dc.HostName -LocalNames $localNames
        if (-not $isLocal) {
            $isLocal = Test-IsLocalName -Name $dc.Name -LocalNames $localNames
        }
        $reachable = $false
        if ($isLocal) {
            $reachable = $true
        }
        else {
            $reachable = Test-TcpPort -ComputerName $dc.HostName -Port 389 -TimeoutMs 1500
        }
        [pscustomobject]@{
            Name          = $dc.Name
            HostName      = $dc.HostName
            Site          = $dc.Site
            IsLocal       = $isLocal
            LDAPReachable = $reachable
        }
    }

    $dcReport | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

    $nonLocalReachable = @($dcReport | Where-Object { -not $_.IsLocal -and $_.LDAPReachable })
    $nonLocalUnreachable = @($dcReport | Where-Object { -not $_.IsLocal -and -not $_.LDAPReachable })

    if ($nonLocalReachable.Count -gt 0) {
        Stop-WithError "Another Domain Controller is reachable. This fix is blocked because it is only for a single-DC recovery scenario." @('Do not run this authoritative SYSVOL recovery while another DC is reachable. Use the standard multi-DC DFSR recovery procedure instead.')
    }

    if ($nonLocalUnreachable.Count -gt 0) {
        Write-WarnMsg "AD still contains non-local DC objects that are not reachable on LDAP/389. They look like stale DC references. This script will not remove them."
    }
    else {
        Write-Ok "No reachable non-local Domain Controllers detected."
    }
    Add-Done "Single reachable DC safety gate completed."

    Test-SitesAndServicesServerObjectGate -KnownDcs $allDcs -LocalNames $localNames

    Write-SubSection "FSMO role ownership safety gate"
    $roleRows = @(
        [pscustomobject]@{ Role = 'PDCEmulator';        Holder = [string]$domain.PDCEmulator },
        [pscustomobject]@{ Role = 'RIDMaster';          Holder = [string]$domain.RIDMaster },
        [pscustomobject]@{ Role = 'InfrastructureMaster'; Holder = [string]$domain.InfrastructureMaster },
        [pscustomobject]@{ Role = 'SchemaMaster';       Holder = [string]$forest.SchemaMaster },
        [pscustomobject]@{ Role = 'DomainNamingMaster'; Holder = [string]$forest.DomainNamingMaster }
    )

    $roleRows = foreach ($row in $roleRows) {
        $isLocalHolder = Test-IsLocalName -Name $row.Holder -LocalNames $localNames
        [pscustomobject]@{
            Role          = $row.Role
            Holder        = $row.Holder
            LocalDC       = $isLocalHolder
        }
    }
    $roleRows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

    $notLocalRoles = @($roleRows | Where-Object { -not $_.LocalDC })
    if ($notLocalRoles.Count -gt 0) {
        Stop-WithError "The local DC does not own all FSMO roles. The fix is blocked." @('Move or seize all FSMO roles to this DC first, then run --check again.')
    }
    Write-Ok "The local DC owns all FSMO roles."
    Add-Done "FSMO ownership safety gate completed."

    Write-SubSection "SYSVOL folder content checks"
    $sysvolRoot = Join-Path $env:SystemRoot 'SYSVOL'
    $sysvolDomain = Join-Path $sysvolRoot 'domain'
    $policiesPath = Join-Path $sysvolDomain 'Policies'
    $scriptsPath = Join-Path $sysvolDomain 'scripts'
    $sysvolNamespace = Join-Path $sysvolRoot ("sysvol\{0}" -f $domain.DNSRoot)

    $Script:Context['SysvolRoot'] = $sysvolRoot
    $Script:Context['SysvolDomain'] = $sysvolDomain
    $Script:Context['PoliciesPath'] = $policiesPath
    $Script:Context['ScriptsPath'] = $scriptsPath
    $Script:Context['SysvolNamespace'] = $sysvolNamespace

    $pathRows = @(
        [pscustomobject]@{ Path = $sysvolDomain;     Exists = Test-Path $sysvolDomain },
        [pscustomobject]@{ Path = $policiesPath;     Exists = Test-Path $policiesPath },
        [pscustomobject]@{ Path = $scriptsPath;      Exists = Test-Path $scriptsPath },
        [pscustomobject]@{ Path = $sysvolNamespace;  Exists = Test-Path $sysvolNamespace }
    )
    $pathRows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

    if (-not (Test-Path $sysvolDomain)) { Stop-WithError "SYSVOL domain folder is missing: $sysvolDomain" @('Restore SYSVOL content before attempting an authoritative recovery.') }
    if (-not (Test-Path $policiesPath)) { Stop-WithError "SYSVOL Policies folder is missing: $policiesPath" @('Restore SYSVOL Policies before attempting an authoritative recovery.') }
    if (-not (Test-Path $scriptsPath)) { Stop-WithError "SYSVOL scripts folder is missing: $scriptsPath" @('Restore SYSVOL scripts before attempting an authoritative recovery.') }

    $gptIniFiles = @(Get-ChildItem -LiteralPath $policiesPath -Filter 'gpt.ini' -Recurse -Force -ErrorAction SilentlyContinue)
    if ($gptIniFiles.Count -lt 1) {
        Stop-WithError "No gpt.ini files were found under SYSVOL Policies. SYSVOL content does not look consistent enough to make authoritative." @('Restore a valid SYSVOL Policies tree first.')
    }
    Write-Ok "SYSVOL folder structure looks present. gpt.ini files found: $($gptIniFiles.Count)"
    Add-Done "SYSVOL folder content checks completed."

    Write-SubSection "DFSR SYSVOL subscription checks"
    $sysvolSubDn = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,$($localComputer.DistinguishedName)"
    $Script:Context['SysvolSubDn'] = $sysvolSubDn
    try {
        $sysvolSub = Get-ADObject -Identity $sysvolSubDn -Properties msDFSR-Enabled,msDFSR-Options -ErrorAction Stop
    }
    catch {
        Stop-WithError "Unable to find the local SYSVOL Subscription object: $sysvolSubDn" @('Verify the DFSR SYSVOL AD objects before running the fix.')
    }

    $Script:Context['SysvolSub'] = $sysvolSub
    $sysvolSub | Select-Object DistinguishedName,msDFSR-Enabled,msDFSR-Options | Format-List | Out-String | ForEach-Object { Write-Host $_ }
    Write-Ok "Local SYSVOL Subscription object found."
    Add-Done "DFSR SYSVOL subscription check completed."

    Write-SubSection "DFSR SYSVOL seeding parent registry check"
    $seedingParentInfo = Get-DfsrSysvolSeedingParentInfo -DomainDnsRoot $domain.DNSRoot -LocalDcHostName $localDc.HostName -LocalNames $localNames
    $Script:Context['DfsrSeedingParentInfo'] = $seedingParentInfo
    $seedingParentInfo | Select-Object RegistryPath,Exists,ParentComputer,ExpectedParentComputer,IsLocalParent,NeedsCorrection,ReadError | Format-List | Out-String | ForEach-Object { Write-Host $_ }

    if (-not $seedingParentInfo.Exists) {
        Write-Info "DFSR SYSVOL seeding registry key was not found. This can be normal after SYSVOL is already initialized."
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$seedingParentInfo.ReadError)) {
        Stop-WithError "Unable to read DFSR SYSVOL seeding registry key: $($seedingParentInfo.ReadError)" @("Registry path: $($seedingParentInfo.RegistryPath)")
    }
    elseif (-not $seedingParentInfo.HasParentComputer) {
        Write-Info "DFSR SYSVOL seeding Parent Computer is empty."
    }
    elseif ($seedingParentInfo.NeedsCorrection) {
        Write-WarnMsg "DFSR SYSVOL seeding Parent Computer points to a non-local or stale computer: $($seedingParentInfo.ParentComputer)"
        if ($ForFix) {
            Write-Info "The value will be corrected to the local DC during --fix while DFSR is stopped. DFSR will then be started once to reload the registry value before the authoritative D4 sequence."
        }
        else {
            Write-Info "Run --fix only if the remaining safety checks also identify a supported single-DC recovery scenario."
        }
    }
    else {
        Write-Ok "DFSR SYSVOL seeding Parent Computer is local."
    }
    Add-Done "DFSR SYSVOL seeding parent registry check completed."

    Write-SubSection "DFSR replicated folder state"
    $dfsrInfo = Get-DfsrSysvolInfo
    if (-not $dfsrInfo) {
        Stop-WithError "Unable to read DFSR SYSVOL replicated folder WMI/CIM information." @('Confirm the DFS Replication service is installed and the WMI provider is healthy.')
    }
    $Script:Context['DfsrInfo'] = $dfsrInfo

    $stateText = Convert-DfsrState -State ([int]$dfsrInfo.State)
    [pscustomobject]@{
        ReplicationGroupName = $dfsrInfo.ReplicationGroupName
        ReplicatedFolderName = $dfsrInfo.ReplicatedFolderName
        State                = $stateText
    } | Format-List | Out-String | ForEach-Object { Write-Host $_ }

    if ([int]$dfsrInfo.State -eq 4) {
        Write-Ok "DFSR SYSVOL state is already Normal."
    }
    elseif ([int]$dfsrInfo.State -eq 5) {
        Write-WarnMsg "DFSR SYSVOL state is In Error."
    }
    elseif ([int]$dfsrInfo.State -eq 2) {
        Write-WarnMsg "DFSR SYSVOL state is Initial Sync."
    }
    else {
        Write-WarnMsg "DFSR SYSVOL state is not Normal and not one of the expected supported error states: $stateText"
    }
    Add-Done "DFSR state check completed."

    Write-SubSection "DFSR Content Freshness / stale SYSVOL evidence"
    $problemEvents = @(Get-DfsrProblemEvents)
    $Script:Context['ProblemEvents'] = $problemEvents
    if ($problemEvents.Count -gt 0) {
        Write-WarnMsg "Found DFSR problem evidence matching Event ID 4012 / Content Freshness / Error 9061. Count in latest scan: $($problemEvents.Count)"
        $problemEvents | Select-Object -First 5 TimeCreated, Id, @{Name='ShortMessage'; Expression={
            $msg = $_.Message -replace "`r|`n", ' '
            if ($msg.Length -gt 220) { $msg.Substring(0,220) + '...' } else { $msg }
        }} | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    }
    else {
        Write-Info "No Event ID 4012 / Content Freshness / Error 9061 evidence found in the latest DFS Replication event scan."
    }
    Add-Done "DFSR event evidence check completed."

    Show-RecentDfsrEvents

    Write-SubSection "Service state snapshot"
    Show-ServiceDiagnostics
    Add-Done "Service diagnostics completed."


    $contentFreshnessMatches = (([int]$dfsrInfo.State -eq 5) -and ($problemEvents.Count -gt 0))
    $initialSyncSeedingParentMatches = $false
    if ($Script:Context.Contains('DfsrSeedingParentInfo') -and $Script:Context['DfsrSeedingParentInfo']) {
        $initialSyncSeedingParentMatches = (([int]$dfsrInfo.State -eq 2) -and [bool]$Script:Context['DfsrSeedingParentInfo'].NeedsCorrection)
    }
    $problemMatches = ($contentFreshnessMatches -or $initialSyncSeedingParentMatches)

    $Script:Context['ProblemMatches'] = $problemMatches
    $Script:Context['ContentFreshnessMatches'] = $contentFreshnessMatches
    $Script:Context['InitialSyncSeedingParentMatches'] = $initialSyncSeedingParentMatches
    $siteBlockers = @()
    if ($Script:Context.Contains('SitesServerObjectBlockers')) {
        $siteBlockers = @($Script:Context['SitesServerObjectBlockers'])
    }
    $hasSiteBlockers = ($siteBlockers.Count -gt 0)

    if ($contentFreshnessMatches) {
        Write-Info "Supported recovery pattern: DFSR State 5 / In Error with Content Freshness evidence."
    }
    if ($initialSyncSeedingParentMatches) {
        Write-Info "Supported recovery pattern: DFSR State 2 / Initial Sync with stale or non-local SYSVOL seeding Parent Computer."
    }

    if ($problemMatches) {
        if ($hasSiteBlockers) {
            if ($ForFix) {
                Write-WarnMsg "Fix preflight result: supported problem detected, but the fix is blocked until AD Sites and Services stale server objects are cleaned up."
            }
            else {
                Write-WarnMsg "Check result: supported problem detected, but --fix is blocked until AD Sites and Services stale server objects are cleaned up."
            }
        }
        else {
            if ($ForFix) {
                Write-Ok "Fix preflight result: supported problem detected and all safety gates passed. Continuing with recovery."
            }
            else {
                Write-WarnMsg "Check result: supported problem detected. Run --fix only if you want to perform the repair on this server."
            }
        }
    }
    else {
        if ($hasSiteBlockers) {
            if ($ForFix) {
                Write-WarnMsg "Fix preflight result: the supported DFSR problem was not fully confirmed, and the fix is blocked because AD Sites and Services is not conformant."
            }
            else {
                Write-WarnMsg "Check result: the supported DFSR problem was not fully confirmed, and --fix is blocked because AD Sites and Services is not conformant."
            }
        }
        else {
            if ($ForFix) {
                Write-Ok "Fix preflight result: the supported problem was not detected, or SYSVOL is already healthy. No recovery will be executed."
            }
            else {
                Write-Ok "Check result: the supported problem was not detected, or SYSVOL is already healthy."
            }
        }
    }
}


function Get-RobocopyErrorSummary {
    param(
        [Parameter(Mandatory=$true)][object[]]$RobocopyOutput,
        [int]$ContextBefore = 2,
        [int]$ContextAfter = 2,
        [int]$MaxLines = 20
    )

    $lines = @($RobocopyOutput | ForEach-Object { $_.ToString() })
    $interestingIndexes = New-Object System.Collections.Generic.List[int]

    for ($idx = 0; $idx -lt $lines.Count; $idx++) {
        $line = $lines[$idx]
        if ($line -match '(?i)\bERROR\b|\bFAILED\b|cannot find the file|cannot access|access is denied|the system cannot find|impossibile trovare|accesso negato') {
            $start = [Math]::Max(0, $idx - $ContextBefore)
            $end = [Math]::Min($lines.Count - 1, $idx + $ContextAfter)
            for ($j = $start; $j -le $end; $j++) {
                $interestingIndexes.Add($j) | Out-Null
            }
        }
    }

    $seen = @{}
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($idx in ($interestingIndexes | Sort-Object -Unique)) {
        $line = $lines[$idx]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if (-not $seen.ContainsKey($line)) {
            $seen[$line] = $true
            $result.Add($line) | Out-Null
        }
        if ($result.Count -ge $MaxLines) { break }
    }

    return @($result)
}


function Export-DfsrSysvolRegistryBackup {
    param(
        [Parameter(Mandatory=$true)][string]$BackupPath
    )

    Write-SubSection "DFSR SYSVOL registry backup"

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path $BackupPath -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Stop-WithError "Unable to create backup folder before registry export: $BackupPath. Error: $($_.Exception.Message)" @(
                'No DFSR/AD/registry recovery changes were made.',
                'Create the backup folder manually or use --backup-path with a writable location.'
            )
        }
    }

    $registryKey = 'HKLM\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols'
    $registryExportPath = Join-Path $BackupPath 'DFSR_SysVols_registry_backup.reg'
    $registrySnapshotPath = Join-Path $BackupPath 'DFSR_SysVols_registry_snapshot.txt'

    Write-Info "Registry key: $registryKey"
    Write-Info "Registry export: $registryExportPath"

    $regOutput = @(& reg.exe export $registryKey $registryExportPath /y 2>&1)
    $regExitCode = $LASTEXITCODE
    $regOutput | ForEach-Object { Write-Host $_ }
    Write-Info "reg.exe export exit code: $regExitCode"

    if ($regExitCode -ne 0 -or -not (Test-Path -LiteralPath $registryExportPath -PathType Leaf)) {
        Stop-WithError "Unable to export DFSR SYSVOL registry key before recovery changes." @(
            "Registry key: $registryKey",
            "Expected export file: $registryExportPath",
            'No DFSR/AD/registry recovery changes were made after this registry backup failure.'
        )
    }

    try {
        Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols' -Recurse -Force -ErrorAction Stop |
            ForEach-Object {
                $_.Name
                try {
                    Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop | Format-List | Out-String
                }
                catch {
                    "Unable to read values for $($_.Name): $($_.Exception.Message)"
                }
                ''
            } | Out-File -LiteralPath $registrySnapshotPath -Encoding UTF8 -Force
        Write-Info "Readable registry snapshot: $registrySnapshotPath"
    }
    catch {
        Write-WarnMsg "Registry .reg export succeeded, but the readable text snapshot could not be created: $($_.Exception.Message)"
    }

    $Script:Context['DfsrSysvolRegistryBackupPath'] = $registryExportPath
    Write-Ok "DFSR SYSVOL registry key exported before recovery changes."
    Add-Done "DFSR SYSVOL registry backup completed: $registryExportPath"
}

function Invoke-BackupSysvol {
    Write-Section "SYSVOL backup and consistency verification" Cyan

    $source = [string]$Script:Context['SysvolRoot']
    $backupRoot = Get-EffectiveBackupRoot
    if (-not (Test-Path -LiteralPath $backupRoot -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path $backupRoot -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Stop-WithError "Unable to create backup root directory: $backupRoot. Error: $($_.Exception.Message)" @('No DFSR/AD changes were made. Create the directory manually or use --backup-path with a writable location.')
        }
    }
    $backupPath = Join-Path $backupRoot ("SYSVOL_Backup_{0}" -f (Get-Date -Format yyyyMMdd_HHmmss))
    $Script:Context['BackupPath'] = $backupPath

    Write-Info "Source: $source"
    Write-Info "Backup root: $backupRoot"
    Write-Info "Backup: $backupPath"

    try {
        New-Item -ItemType Directory -Path $backupPath -Force -ErrorAction Stop | Out-Null
        Write-Ok "Backup folder created: $backupPath"
    }
    catch {
        Stop-WithError "Unable to create backup folder: $backupPath. Error: $($_.Exception.Message)" @(
            'No DFSR/AD/registry recovery changes were made.',
            'Create the backup folder manually or use --backup-path with a writable location.'
        )
    }

    Export-DfsrSysvolRegistryBackup -BackupPath $backupPath

    Write-Info "Robocopy options: /MIR /R:1 /W:1 /XJ /XD DfsrPrivate /COPY:DAT /DCOPY:DAT"
    Write-Info "Note: /XJ excludes junctions/reparse points. /XD DfsrPrivate explicitly excludes DFSR internal private metadata from the backup."
    Write-Info "Backup verification uses the same DfsrPrivate exclusion to avoid false failures."

    $robocopyArgs = @($source, $backupPath, '/MIR', '/R:1', '/W:1', '/XJ', '/XD', 'DfsrPrivate', '/COPY:DAT', '/DCOPY:DAT')
    $robocopyOutput = @(& robocopy @robocopyArgs 2>&1)
    $rc = $LASTEXITCODE
    $robocopyOutput | ForEach-Object { Write-Host $_ }
    Write-Info "Robocopy exit code: $rc"

    if ($rc -gt 7) {
        $robocopyDetails = @(Get-RobocopyErrorSummary -RobocopyOutput $robocopyOutput)
        if ($robocopyDetails.Count -gt 0) {
            Write-SubSection "Robocopy error details"
            foreach ($detail in $robocopyDetails) {
                Write-Host ("  {0}" -f $detail) -ForegroundColor Red
            }
        }

        $missing = New-Object System.Collections.Generic.List[string]
        $missing.Add('Review the Robocopy output and complete a clean backup before running the recovery.') | Out-Null
        if ($robocopyDetails.Count -gt 0) {
            $missing.Add('Robocopy failure details detected:') | Out-Null
            foreach ($detail in ($robocopyDetails | Select-Object -First 10)) {
                $missing.Add(("  {0}" -f $detail)) | Out-Null
            }
        }
        Stop-WithError "Robocopy failed with exit code $rc. SYSVOL backup is not reliable." @($missing)
    }

    $backupDomain = Join-Path $backupPath 'domain'
    $backupPolicies = Join-Path $backupDomain 'Policies'
    $backupScripts = Join-Path $backupDomain 'scripts'

    if (-not (Test-Path -LiteralPath $backupDomain)) { Stop-WithError "Backup verification failed. Missing folder: $backupDomain" @('No DFSR/AD changes were made after backup failure.') }
    if (-not (Test-Path -LiteralPath $backupPolicies)) { Stop-WithError "Backup verification failed. Missing folder: $backupPolicies" @('No DFSR/AD changes were made after backup failure.') }
    if (-not (Test-Path -LiteralPath $backupScripts)) { Stop-WithError "Backup verification failed. Missing folder: $backupScripts" @('No DFSR/AD changes were made after backup failure.') }

    $sourceDomain = Join-Path $source 'domain'
    Test-SysvolBackupConsistency -SourceDomain $sourceDomain -BackupDomain $backupDomain

    $backupGptIni = @(Get-ChildItem -LiteralPath $backupPolicies -Filter 'gpt.ini' -Recurse -Force -ErrorAction SilentlyContinue)
    if ($backupGptIni.Count -lt 1) {
        Stop-WithError "Backup verification failed. No gpt.ini files found in the backup Policies tree." @('No DFSR/AD changes were made after backup consistency failure.')
    }

    Write-Ok ("gpt.ini files found in backup: {0}" -f $backupGptIni.Count)
    Write-Ok "SYSVOL backup completed and verified."
    Add-Done "SYSVOL backup completed: $backupPath"
}

function Invoke-DfsrPollAd {
    param(
        [int]$Attempts = 12,
        [int]$SleepSeconds = 5,
        [string]$Context = 'DFSR AD polling'
    )

    Write-Info ("Running dfsrdiag pollad for: {0}" -f $Context)
    Write-Info ("Retry policy: {0} attempt(s), {1} second(s) between attempts." -f $Attempts, $SleepSeconds)
    Write-Info "Success detection is locale-independent: the script uses the dfsrdiag.exe process exit code, not localized output text."

    $dfsrdiagCommand = Get-Command dfsrdiag.exe -ErrorAction SilentlyContinue
    if (-not $dfsrdiagCommand) {
        Stop-WithError "dfsrdiag.exe was not found before polling AD." @(
            'Install the DFS Replication management tools, then run --check again.',
            'On Windows Server this is normally provided by RSAT-DFS-Mgmt-Con / DFS Management Tools.'
        )
    }

    $dfsrdiagPath = $dfsrdiagCommand.Source
    $lastExitCode = $null
    $lastOutput = @()
    $lastStdOutPath = $null
    $lastStdErrPath = $null

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        Write-Info ("dfsrdiag pollad attempt {0}/{1}..." -f $attempt, $Attempts)

        try {
            $svc = Get-Service -Name DFSR -ErrorAction Stop
            if ($svc.Status -ne 'Running') {
                Write-WarnMsg ("DFSR service is {0}. Attempting to start it before polling AD." -f $svc.Status)
                Start-Service DFSR -ErrorAction Stop
                Start-Sleep -Seconds 3
            }
        }
        catch {
            Write-WarnMsg ("Unable to query/start DFSR before pollad attempt {0}: {1}" -f $attempt, $_.Exception.Message)
        }

        $stdOutPath = Join-Path $env:TEMP ("dfsrdiag_pollad_stdout_{0}_{1}.txt" -f $PID, $attempt)
        $stdErrPath = Join-Path $env:TEMP ("dfsrdiag_pollad_stderr_{0}_{1}.txt" -f $PID, $attempt)
        Remove-Item -LiteralPath $stdOutPath,$stdErrPath -Force -ErrorAction SilentlyContinue
        $lastStdOutPath = $stdOutPath
        $lastStdErrPath = $stdErrPath

        try {
            $process = Start-Process -FilePath $dfsrdiagPath -ArgumentList @('pollad') -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdOutPath -RedirectStandardError $stdErrPath -ErrorAction Stop
            $lastExitCode = $process.ExitCode
        }
        catch {
            $lastExitCode = $null
            $lastOutput = @($_.Exception.Message)
            Write-WarnMsg ("Unable to start dfsrdiag.exe on attempt {0}/{1}: {2}" -f $attempt, $Attempts, $_.Exception.Message)
        }

        $output = New-Object System.Collections.Generic.List[string]
        if (Test-Path -LiteralPath $stdOutPath) {
            Get-Content -LiteralPath $stdOutPath -ErrorAction SilentlyContinue | ForEach-Object { $output.Add([string]$_) | Out-Null }
        }
        if (Test-Path -LiteralPath $stdErrPath) {
            Get-Content -LiteralPath $stdErrPath -ErrorAction SilentlyContinue | ForEach-Object { $output.Add([string]$_) | Out-Null }
        }
        $lastOutput = @($output)

        if ($lastOutput.Count -gt 0) {
            $lastOutput | ForEach-Object { Write-Host $_ }
        }

        $exitCodeText = if ($null -eq $lastExitCode) { '<null>' } else { [string]$lastExitCode }
        Write-Info ("dfsrdiag.exe process exit code: {0}" -f $exitCodeText)

        if ($lastExitCode -eq 0) {
            Write-Ok ("dfsrdiag pollad succeeded on attempt {0}/{1}." -f $attempt, $Attempts)
            Remove-Item -LiteralPath $stdOutPath,$stdErrPath -Force -ErrorAction SilentlyContinue
            return $true
        }

        $outputText = ($lastOutput | Out-String)
        $isTransientWmi = ($outputText -match '0x80041002') -or ($outputText -match 'PollDsNow') -or ($outputText -match 'Operation Failed') -or ($outputText -match 'Failed to execute')

        if ($attempt -lt $Attempts) {
            if ($isTransientWmi) {
                Write-WarnMsg ("dfsrdiag pollad returned a WMI/DFSR provider error on attempt {0}/{1}. DFSR may not have registered the PollDsNow WMI method yet after restart. Waiting and retrying." -f $attempt, $Attempts)
            }
            else {
                Write-WarnMsg ("dfsrdiag pollad failed with process exit code {0} on attempt {1}/{2}. Waiting and retrying." -f $exitCodeText, $attempt, $Attempts)
            }
            Start-Sleep -Seconds $SleepSeconds
        }
    }

    Write-ErrMsg "dfsrdiag pollad did not succeed after all retry attempts. Last output follows:"
    if ($lastOutput.Count -gt 0) {
        $lastOutput | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    }

    $finalExitCodeText = if ($null -eq $lastExitCode) { '<null>' } else { [string]$lastExitCode }
    Stop-WithError ("dfsrdiag pollad failed after {0} attempt(s). Last process exit code: {1}." -f $Attempts, $finalExitCodeText) @(
        'The script no longer relies on localized text such as Operation Succeeded; it uses the native process exit code.',
        'DFSR may still be initializing its WMI provider after service start/restart.',
        'Run dfsrdiag pollad manually after a short wait. If it returns exit code 0, re-run --check and then --fix only if the supported problem is still detected.',
        'Check DFSR service health, AD connectivity, and the DFS Replication event log.'
    )
}

function Wait-DfsrState {
    param(
        [int]$ExpectedState,
        [int]$Attempts = 12,
        [int]$SleepSeconds = 5
    )

    for ($i = 1; $i -le $Attempts; $i++) {
        $info = Get-DfsrSysvolInfo
        if ($info) {
            $state = [int]$info.State
            Write-Info ("DFSR SYSVOL state check {0}/{1}: {2}" -f $i, $Attempts, (Convert-DfsrState -State $state))
            if ($state -eq $ExpectedState) {
                return $true
            }
        }
        Start-Sleep -Seconds $SleepSeconds
    }
    return $false
}

function Test-RecentEventId {
    param(
        [int]$Id,
        [datetime]$Since
    )
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; Id = $Id; StartTime = $Since } -ErrorAction Stop
        return @($events).Count -gt 0
    }
    catch {
        return $false
    }
}


function Assert-FixEligibilityFromSharedChecks {
    Write-Section "Fix eligibility decision" Cyan
    Write-Info "The decision below is based only on the results produced by the shared prerequisite and sanity-check orchestrator."

    $siteBlockers = @()
    if ($Script:Context.Contains('SitesServerObjectBlockers')) {
        $siteBlockers = @($Script:Context['SitesServerObjectBlockers'])
    }

    if ($siteBlockers.Count -gt 0) {
        Stop-WithError "The supported failure pattern may be present, but --fix is blocked because AD Sites and Services contains non-local/stale server objects." @(
            'Clean up the listed Sites and Services objects manually, then run --check again.',
            'This script intentionally does not delete AD Sites and Services server objects.'
        )
    }

    if (-not $Script:Context.Contains('DfsrInfo') -or -not $Script:Context['DfsrInfo']) {
        Stop-WithError "Fix eligibility cannot be evaluated because DFSR SYSVOL state was not collected." @('Run --check and review the earlier sanity-check errors.')
    }

    $dfsrInfo = $Script:Context['DfsrInfo']
    $problemMatches = $false
    if ($Script:Context.Contains('ProblemMatches')) {
        $problemMatches = [bool]$Script:Context['ProblemMatches']
    }

    if (-not $problemMatches) {
        if ([int]$dfsrInfo.State -eq 4) {
            Stop-WithError "The supported failure pattern was not detected because DFSR SYSVOL is already State 4 / Normal. No fix is required." @('No authoritative SYSVOL recovery was executed.')
        }
        else {
            Stop-WithError "The supported failure pattern was not detected. DFSR is neither State 5 with Event ID 4012 / Content Freshness / Error 9061 evidence, nor State 2 Initial Sync with a stale/non-local SYSVOL seeding Parent Computer." @('Investigate the current DFSR state, DFS Replication events, and SYSVOL seeding registry value before using this specific recovery procedure.')
        }
    }

    if ($Script:Context.Contains('InitialSyncSeedingParentMatches') -and [bool]$Script:Context['InitialSyncSeedingParentMatches']) {
        Write-Ok "The detected condition matches the supported single-DC DFSR SYSVOL Initial Sync / stale seeding parent recovery scenario."
    }
    elseif ($Script:Context.Contains('ContentFreshnessMatches') -and [bool]$Script:Context['ContentFreshnessMatches']) {
        Write-Ok "The detected condition matches the supported single-DC DFSR SYSVOL Content Freshness recovery scenario."
    }
    else {
        Write-Ok "The detected condition matches a supported single-DC DFSR SYSVOL recovery scenario."
    }
    Add-Done "Fix eligibility confirmed by shared check orchestrator."
}

function Invoke-SharedCheckOrchestrator {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Check','Fix')]
        [string]$Mode
    )

    $isFix = ($Mode -eq 'Fix')
    $Script:RunMode = $Mode
    $Script:Context['RunMode'] = $Mode

    Write-Section "Shared prerequisite and sanity-check orchestrator" DarkCyan
    Write-Info "Mode: $Mode"
    Write-Info "The same prerequisite and sanity-check functions are used by --check and --fix."

    Invoke-PrerequisiteGate -ForFix:$isFix
    Invoke-SanityCheck -ForFix:$isFix

    if (Test-HasSitesAndServicesBlockers) {
        Invoke-SitesAndServicesConsolePrompt -Reason 'AD Sites and Services is not conformant for this single-DC recovery procedure. --fix is blocked until the listed object(s) are manually verified and cleaned up.'
    }

    if ($isFix) {
        Assert-FixEligibilityFromSharedChecks
    }
}

function Invoke-Fix {
    Write-Section "Starting authoritative SYSVOL DFSR recovery" Cyan
    Write-Caution "This operation changes the local DFSR SYSVOL AD subscription and restarts DFSR. It is blocked unless all safety checks passed."

    Invoke-BackupSysvol

    $sysvolSubDn = [string]$Script:Context['SysvolSubDn']
    $seedingParentInfo = $null
    if ($Script:Context.Contains('DfsrSeedingParentInfo')) {
        $seedingParentInfo = $Script:Context['DfsrSeedingParentInfo']
    }

    try {
        Write-Section "Step 1 - Stop DFSR and correct SYSVOL seeding parent if needed" Cyan
        Set-Service DFSR -StartupType Manual
        Write-Ok "DFSR startup type set to Manual."
        Stop-Service DFSR -Force
        Write-Ok "DFSR service stopped."

        $seedingParentChanged = $false
        if ($seedingParentInfo) {
            $seedingParentChanged = [bool](Set-DfsrSysvolSeedingParentToLocal -Info $seedingParentInfo)
        }
        else {
            Write-Info "DFSR SYSVOL seeding Parent Computer information was not collected during preflight. No registry correction was attempted."
        }

        if ($seedingParentChanged) {
            Invoke-DfsrServiceReloadAfterSeedingParentCorrection
        }

        Write-Section "Step 2 - Disable local SYSVOL subscription and mark authoritative" Cyan
        Set-ADObject -Identity $sysvolSubDn -Replace @{ 'msDFSR-Enabled' = $false; 'msDFSR-Options' = 1 }
        Write-Ok "Set msDFSR-Enabled=FALSE and msDFSR-Options=1 on local SYSVOL Subscription."
        Add-Done "Local SYSVOL Subscription disabled and marked authoritative."

        Write-Section "Step 3 - Start DFSR and force AD polling" Cyan
        Start-Service DFSR
        Write-Ok "DFSR service started."
        Invoke-DfsrPollAd -Context 'after disabling local SYSVOL subscription'
        Add-Done "DFSR AD polling completed after disabling subscription."

        Write-Info "Checking for Event ID 4114 after disabling the subscription..."
        if (Test-RecentEventId -Id 4114 -Since $Script:RunStart) {
            Write-Ok "Event ID 4114 detected."
        }
        else {
            Write-WarnMsg "Event ID 4114 was not detected in the current run window. Continuing because some systems log it late or not in the expected query window."
        }

        Write-Section "Step 4 - Re-enable local SYSVOL subscription" Cyan
        Set-ADObject -Identity $sysvolSubDn -Replace @{ 'msDFSR-Enabled' = $true }
        Write-Ok "Set msDFSR-Enabled=TRUE on local SYSVOL Subscription."
        Invoke-DfsrPollAd -Context 'after re-enabling local SYSVOL subscription'
        Add-Done "Local SYSVOL Subscription re-enabled and DFSR AD polling completed."

        Write-Section "Step 5 - Restore service startup and restart required services" Cyan
        Set-Service DFSR -StartupType Automatic
        Write-Ok "DFSR startup type set to Automatic."
        Restart-Service DFSR -Force
        Write-Ok "DFSR service restarted."
        Restart-Service Netlogon -Force
        Write-Ok "Netlogon service restarted."
        Add-Done "DFSR and Netlogon services restarted."
    }
    catch {
        Stop-WithError "Recovery procedure failed: $($_.Exception.Message)" @('Review the completed actions above and the service diagnostics below before retrying.')
    }

    Write-Section "Final validation" Cyan

    $stateOk = Wait-DfsrState -ExpectedState 4 -Attempts 12 -SleepSeconds 5
    if (-not $stateOk) {
        Stop-WithError "DFSR SYSVOL did not reach State 4 / Normal during validation." @('Review DFS Replication events and the service diagnostics below.')
    }
    Write-Ok "DFSR SYSVOL reached State 4 / Normal."
    Add-Done "DFSR SYSVOL final state validated as State 4 / Normal."

    if (Test-RecentEventId -Id 4602 -Since $Script:RunStart) {
        Write-Ok "Event ID 4602 detected after authoritative recovery."
        Add-Done "Authoritative initialization event 4602 detected."
    }
    else {
        Write-WarnMsg "Event ID 4602 was not detected in the current run window. DFSR state is Normal, but review the DFS Replication log manually."
    }

    Write-SubSection "SYSVOL and NETLOGON share validation"
    $netShare = & net.exe share
    $hasSysvol = ($netShare -match '^SYSVOL\s') -or ($netShare -match '\bSYSVOL\b')
    $hasNetlogon = ($netShare -match '^NETLOGON\s') -or ($netShare -match '\bNETLOGON\b')
    $netShare | Out-String | ForEach-Object { Write-Host $_ }

    if (-not $hasSysvol -or -not $hasNetlogon) {
        Stop-WithError "SYSVOL and/or NETLOGON shares are missing after recovery." @('Review Netlogon and DFSR service state, then run dcdiag manually.')
    }
    Write-Ok "SYSVOL and NETLOGON shares are present."
    Add-Done "SYSVOL and NETLOGON shares validated."

    Write-SubSection "DCDIAG SYSVOL and advertising tests"
    $dcdiag = Get-Command dcdiag.exe -ErrorAction SilentlyContinue
    if ($dcdiag) {
        & dcdiag.exe /test:sysvolcheck /test:advertising
        $dcdiagRc = $LASTEXITCODE
        Write-Info "dcdiag exit code: $dcdiagRc"
        if ($dcdiagRc -ne 0) {
            Stop-WithError "dcdiag reported a failure." @('Review dcdiag output above and the service diagnostics below.')
        }
        Write-Ok "dcdiag SYSVOL/advertising tests completed successfully."
        Add-Done "dcdiag validation completed."
    }
    else {
        Write-WarnMsg "dcdiag.exe not found. Skipping dcdiag validation."
    }

    $Script:Context['RecoverySucceeded'] = $true
    Clear-ResolvedRecoveryWarnings
    Write-Info "Initial DFSR State 5 / 4012 preflight warnings were resolved by the successful final validation."

    Show-RecentDfsrEvents
    Show-ServiceDiagnostics
    Show-ActionSummary -Result 'SUCCESS'
    Stop-LogTranscript
    exit 0
}

function Parse-Mode {
    param([string[]]$RawArgs)

    if (-not $RawArgs -or $RawArgs.Count -eq 0) {
        Show-Help
        exit 0
    }

    $mode = $null
    $i = 0
    while ($i -lt $RawArgs.Count) {
        $arg = $RawArgs[$i]
        $argLower = $arg.ToLowerInvariant()

        switch -Regex ($argLower) {
            '^--check$|^-check$' {
                if ($mode) { Stop-WithError "Only one mode can be specified." @('Use either --check or --fix.') }
                $mode = 'Check'
                $i++
                continue
            }
            '^--fix$|^-fix$' {
                if ($mode) { Stop-WithError "Only one mode can be specified." @('Use either --check or --fix.') }
                $mode = 'Fix'
                $i++
                continue
            }
            '^--backup-path=(.+)$|^-backup-path=(.+)$' {
                $value = $arg.Substring($arg.IndexOf('=') + 1).Trim()
                if ([string]::IsNullOrWhiteSpace($value)) {
                    Stop-WithError "--backup-path was provided without a value." @('Use --backup-path C:\Backups or --backup-path "D:\Safe Backups".')
                }
                if ($Script:CustomBackupRoot) {
                    Stop-WithError "--backup-path was specified more than once." @('Specify a single backup root path.')
                }
                $Script:CustomBackupRoot = $value
                $i++
                continue
            }
            '^--backup-path$|^-backup-path$' {
                if (($i + 1) -ge $RawArgs.Count) {
                    Stop-WithError "--backup-path was provided without a value." @('Use --backup-path C:\Backups or --backup-path "D:\Safe Backups".')
                }
                $value = $RawArgs[$i + 1]
                if ($value.ToLowerInvariant().StartsWith('-')) {
                    Stop-WithError "--backup-path value looks missing or invalid: $value" @('Use --backup-path C:\Backups or --backup-path "D:\Safe Backups".')
                }
                if ($Script:CustomBackupRoot) {
                    Stop-WithError "--backup-path was specified more than once." @('Specify a single backup root path.')
                }
                $Script:CustomBackupRoot = $value
                $i += 2
                continue
            }
            '^--help$|^-help$|^-h$|^/\?$' {
                Show-Help
                exit 0
            }
            default {
                Show-Help
                Stop-WithError "Unknown argument: $arg" @('Use --check, --fix, --backup-path <path>, or --help.')
            }
        }
    }

    if (-not $mode) {
        Show-Help
        exit 0
    }

    if ($Script:CustomBackupRoot -and $mode -ne 'Fix') {
        Write-WarnMsg "--backup-path was provided in check mode. No backup will be created, but the path will be validated as part of the check."
    }

    return $mode
}

$mode = Parse-Mode -RawArgs $args
$Script:RunMode = $mode
$Script:Context['RunMode'] = $mode
Start-LogTranscript

try {
    if ($mode -eq 'Check') {
        Invoke-SharedCheckOrchestrator -Mode 'Check'
        Show-ActionSummary -Result 'CHECK COMPLETED'
        Stop-LogTranscript
        exit 0
    }
    elseif ($mode -eq 'Fix') {
        Invoke-SharedCheckOrchestrator -Mode 'Fix'
        Invoke-Fix
    }
    else {
        Show-Help
        Stop-LogTranscript
        exit 0
    }
}
catch {
    Stop-WithError "Unexpected unhandled error: $($_.Exception.Message)" @('Review the transcript log and diagnostics above.')
}
