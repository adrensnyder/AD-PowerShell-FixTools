#requires -version 5.1
<#!
.SYNOPSIS
    Safe DFSR SYSVOL authoritative recovery helper for multi-DC domains.

.DESCRIPTION
    This script audits and, when explicitly requested, performs a controlled
    authoritative DFSR SYSVOL re-initialization in a domain with two or more
    reachable Domain Controllers.

    It must be started on the Domain Controller that you intend to make
    authoritative. By default, the script requires that the local DC owns all
    five FSMO roles. This keeps the workflow aligned with the safest common
    SYSVOL practice: make the PDC/FSMO holder authoritative, and make every
    other DC non-authoritative.

    The script is deliberately conservative. In --fix mode it blocks if:
      - the local server is not a Domain Controller;
      - the local server is not the holder of all FSMO roles;
      - any DC known to AD is unreachable;
      - structured AD replication cmdlets report current replication errors;
      - stale/orphan server objects exist under AD Sites and Services;
      - any DC is missing the DFSR SYSVOL Subscription object;
      - remote service control cannot be performed on every DC;
      - SYSVOL backup cannot be created for every reachable DC;
      - the local SYSVOL payload does not contain a usable Policies tree;
      - a DFSR SYSVOL seeding registry Parent Computer value points to a DC
        name that is not part of the current domain controller list.

    The script checks the registry path:
        HKLM\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols\Seeding SysVols\<domain DNS name>
        Value: Parent Computer

    A wrong or orphaned Parent Computer value is reported as a blocker. The
    script does not silently rewrite this registry value during the SYSVOL
    authoritative workflow, because this value is diagnostic/seeding metadata
    and may be important evidence of the original failure. The output prints
    the affected DC, current value, and a safe suggested target.

    During --fix, the script:
      1. Creates a timestamped SYSVOL backup for every DC.
      2. Sets DFSR startup type to Manual and stops DFSR on every DC.
      3. Sets msDFSR-Enabled=FALSE and msDFSR-Options=1 on the local/auth DC.
      4. Sets msDFSR-Enabled=FALSE and msDFSR-Options=0 on every other DC.
      5. Forces AD replication with repadmin, then validates the result with structured AD cmdlets before continuing.
      6. Starts DFSR only on the authoritative DC.
      7. Re-enables the authoritative DC and forces DFSR AD polling.
      8. Starts and re-enables every other DC as non-authoritative.
      9. Restores DFSR startup type to Automatic on every DC.
     10. Waits for every DC to report DFSR SYSVOL State 4 / Normal.
     11. Checks SYSVOL/NETLOGON shares and runs dcdiag where available.

    This is NOT the right tool to repair one broken DC while other DCs are
    healthy. In that case, perform a non-authoritative recovery only on the
    affected DC.

    Version 17.0 note:
      - Fixed early-blocker summary handling. If the script stops before DFSR
        state rows exist, the final Summary no longer throws a secondary
        ParameterBindingValidationError for empty Rows/Items arrays.
      - The multi-DC guard remains unchanged: the script blocks when fewer
        than two DC objects are discovered.

    Version 16.0 note:
      - Corrected DFSR AD polling in --fix: the script now uses dfsrdiag.exe
        pollad as the primary mechanism. For remote DCs it first tries to run
        dfsrdiag pollad locally on that DC through PowerShell remoting, then
        falls back to dfsrdiag PollAD /Member:<domain\server> from the current
        host.
      - Removed WMI PollDsNow from the recovery path. The script no longer
        depends on DFSR WMI PollDsNow provider/class behavior during SYSVOL
        recovery.
      - Replaced sc.exe service operations with PowerShell/WMI Win32_Service
        operations for DFSR startup mode, stop, and start.
      - Final DFSR convergence wait is bounded: 300 seconds, checked every
        15 seconds, with visible elapsed/remaining time.
      - If convergence is not complete after 60 seconds, the script retries
        dfsrdiag pollad once on every involved DC.
      - When the authoritative DC reaches State 4 / Normal, the wait window is
        extended once by another 300 seconds for non-authoritative DCs.
      - If the authoritative DC is normal but other DCs remain stuck, the script
        stops with targeted guidance for the affected non-authoritative DCs
        instead of recommending another global authoritative recovery.
      - --check is read-only with respect to SYSVOL, DFSR registry values, AD
        DFSR Subscription attributes, DFSR service state, and backup folders.
        It still writes the PowerShell transcript/log file by design.
      - The SYSVOL robocopy comparison in --check is explicitly executed with
        /L, so it is a preview only: it must not copy, delete, or change files.
      - The backup root check no longer creates a temporary write-test file in
        --check. Actual backup-root creation/writability validation is deferred
        to --fix.
      - Get-ADReplicationFailure rows are blocking only when FailureCount > 0.
        LastError is logged as diagnostic context. A row with FailureCount=0
        and LastError non-zero is treated as a stale/recent-failure warning,
        not as a current blocker, provided partner metadata also reports
        ConsecutiveReplicationFailures=0 and LastReplicationResult=0.
      - Required PowerShell object properties are validated explicitly before
        being used for safety gates.
      - A final --check decision section now prints recommended next actions,
        including the exact --fix command and post-fix verification commands.
      - When every DC is State 2 / Initial Sync and all safety gates pass,
        --check now explicitly treats the environment as eligible for the
        multi-DC authoritative workflow, provided the local SYSVOL payload is
        confirmed as the source of truth. It no longer suggests waiting as the
        primary action for the stuck-all-DCs recovery scenario.
      - --fix creates and verifies a separate backup of
        C:\Windows\SYSVOL\domain from every DC before any DFSR service, AD
        subscription, or registry-affecting recovery action is attempted.
      - The --check recommendation is explicit: when all DCs are State 2 and
        every safety gate passes, the environment is eligible for this
        multi-DC authoritative workflow. The recommended next step is --fix
        from the intended source DC, after confirming its SYSVOL content.
      - The log file name follows the script file name, for example
        Invoke-SysvolAuthoritativeMultiDC_v16.log, to avoid mixing logs from
        older versions.
      - The final Summary section separates Notes from Suggested actions.
        Notes describe context, impact, backup behavior, and expected final
        state. Suggested actions contains only direct operator actions or
        commands, for example the exact --fix command.
      - Fixed a PowerShell 5.1 compatibility issue: [ordered] dictionaries are
        System.Collections.Specialized.OrderedDictionary and do not expose a
        ContainsKey() method. The script now uses the existing Test-ContextKey
        helper for context lookups.

    The script does not parse localized text from repadmin, dcdiag, net.exe, or
    robocopy to decide safety gates. AD replication health is evaluated with
    Get-ADReplicationPartnerMetadata and Get-ADReplicationFailure. repadmin is
    used only to trigger AD replication during --fix; its output text is logged
    but not parsed.

.USAGE
    Show help:
        .\Invoke-SysvolAuthoritativeMultiDC.ps1 --help

    Run safety checks only:
        .\Invoke-SysvolAuthoritativeMultiDC.ps1 --check

    Run checks, back up every DC, then perform the multi-DC authoritative workflow:
        .\Invoke-SysvolAuthoritativeMultiDC.ps1 --fix

    Use a custom backup root:
        .\Invoke-SysvolAuthoritativeMultiDC.ps1 --fix --backup-path D:\SafeBackups

    Bypass execution policy only for this PowerShell process:
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SysvolAuthoritativeMultiDC.ps1 --check
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SysvolAuthoritativeMultiDC.ps1 --fix --backup-path D:\SafeBackups

.PARAMETER --check
    Runs prerequisite, topology, DFSR, registry, and safety checks only. No
    DFSR/AD recovery changes are made. No SYSVOL/registry/AD/service/backup
    changes are made; the script still writes its transcript/log file.

.PARAMETER --fix
    Runs all checks first. If every safety gate passes, creates SYSVOL backups
    for all DCs and performs the authoritative/non-authoritative DFSR SYSVOL
    workflow.

.PARAMETER --backup-path <path>
    Optional. Root folder for timestamped SYSVOL backups. If omitted, the script
    directory is used.

.PARAMETER --help
    Shows help.

.NOTES
    Run from an elevated Windows PowerShell 5.1 session on the DC that must be
    authoritative. Read the output carefully. Have a system-state backup or VM
    snapshot strategy before using --fix in production.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:Version = '18.0'
$Script:RunStart = Get-Date
$Script:Mode = $null
$Script:CustomBackupRoot = $null
$Script:TranscriptPath = $null
$Script:Errors = New-Object System.Collections.Generic.List[string]
$Script:Warnings = New-Object System.Collections.Generic.List[string]
$Script:Actions = New-Object System.Collections.Generic.List[string]
$Script:Context = [ordered]@{}

function Write-Blank { Write-Host '' }
function Write-Section {
    param([Parameter(Mandatory=$true)][string]$Title, [ConsoleColor]$Color = [ConsoleColor]::Cyan)
    Write-Blank
    Write-Host ('=' * 78) -ForegroundColor $Color
    Write-Host ('  {0}' -f $Title) -ForegroundColor $Color
    Write-Host ('=' * 78) -ForegroundColor $Color
}
function Write-SubSection {
    param([Parameter(Mandatory=$true)][string]$Title)
    Write-Blank
    Write-Host ('-- {0}' -f $Title) -ForegroundColor Yellow
}
function Write-Info { param([string]$Message) Write-Host ('[INFO] {0}' -f $Message) -ForegroundColor Gray }
function Write-Ok { param([string]$Message) Write-Host ('[OK]   {0}' -f $Message) -ForegroundColor Green }
function Write-WarnMsg { param([string]$Message) $Script:Warnings.Add($Message) | Out-Null; Write-Host ('[WARN] {0}' -f $Message) -ForegroundColor DarkYellow }
function Write-ErrMsg { param([string]$Message) $Script:Errors.Add($Message) | Out-Null; Write-Host ('[ERR]  {0}' -f $Message) -ForegroundColor Red }
function Add-Action { param([string]$Message) $Script:Actions.Add($Message) | Out-Null }


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

function Test-ContextKey {
    param([Parameter(Mandatory=$true)][string]$Key)
    return ($null -ne $Script:Context -and $Script:Context.Contains($Key) -and $null -ne $Script:Context[$Key])
}

function Get-ContextString {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [string]$Default = ''
    )
    if (Test-ContextKey -Key $Key) { return [string]$Script:Context[$Key] }
    return $Default
}

function Get-DcShortName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    return (($Name -split '\.' )[0]).ToUpperInvariant()
}

function Test-DcNameEqual {
    param([string]$A, [string]$B)
    return ((Get-DcShortName $A) -eq (Get-DcShortName $B))
}

function Test-DfsrStateTextNormal {
    param([object]$StateText)
    return ([string]$StateText -match '^4 - Normal')
}

function Test-DfsrStateTextInitial {
    param([object]$StateText)
    return ([string]$StateText -match '^2 - Initial Sync')
}

function Get-DfsrStateRowForDc {
    param(
        [object[]]$Rows = @(),
        [Parameter(Mandatory=$true)][string]$ComputerName
    )
    if ($null -eq $Rows -or @($Rows).Count -eq 0) { return $null }
    foreach ($row in @($Rows)) {
        if (Test-DcNameEqual ([string]$row.DC) $ComputerName) { return $row }
    }
    return $null
}

function Get-NonNormalDfsrStateRows {
    param([object[]]$Rows = @())
    if ($null -eq $Rows -or @($Rows).Count -eq 0) { return @() }
    return @($Rows | Where-Object { -not (Test-DfsrStateTextNormal $_.State) })
}

function Get-NonAuthoritativeNonNormalRows {
    param(
        [object[]]$Rows = @(),
        [string]$AuthoritativeComputerName
    )
    if ($null -eq $Rows -or @($Rows).Count -eq 0) { return @() }
    return @($Rows | Where-Object {
        -not (Test-DcNameEqual ([string]$_.DC) $AuthoritativeComputerName) -and
        -not (Test-DfsrStateTextNormal $_.State)
    })
}

function Format-DcStateList {
    param([object[]]$Rows)
    if ($null -eq $Rows -or @($Rows).Count -eq 0) { return '<none>' }
    return ((@($Rows) | ForEach-Object { '{0}={1}' -f $_.DC,$_.State }) -join '; ')
}

function Get-SummaryNotes {
    param([string]$Result = 'Summary')

    $notes = New-Object System.Collections.Generic.List[object]
    $scriptName = Get-ScriptDisplayName
    $mode = $Script:Mode
    $backupRoot = Get-BackupRoot
    if ((Test-ContextKey -Key 'BackupRoot') -and -not [string]::IsNullOrWhiteSpace([string]$Script:Context['BackupRoot'])) {
        $backupRoot = [string]$Script:Context['BackupRoot']
    }

    $localHost = '<local DC not resolved>'
    $localShort = '<local DC>'
    if (Test-ContextKey -Key 'LocalDC') {
        $localHost = [string]$Script:Context['LocalDC'].HostName
        $localShort = [string]$Script:Context['LocalDC'].Name
    }

    $dcs = @()
    if (Test-ContextKey -Key 'DCs') { $dcs = @($Script:Context['DCs']) }
    $nonAuth = @($dcs | Where-Object { -not (Test-DcNameEqual ([string]$_.HostName) $localHost) } | ForEach-Object { [string]$_.HostName })
    $stateRows = @()
    if (Test-ContextKey -Key 'DfsrStateRows') { $stateRows = @($Script:Context['DfsrStateRows']) }
    $allNormal = ($stateRows.Count -gt 0 -and @(Get-NonNormalDfsrStateRows -Rows $stateRows).Count -eq 0)
    $allInitial = ($stateRows.Count -gt 0 -and @($stateRows | Where-Object { -not (Test-DfsrStateTextInitial $_.State) }).Count -eq 0)
    $authRow = Get-DfsrStateRowForDc -Rows $stateRows -ComputerName $localHost
    $authNormal = ($null -ne $authRow -and (Test-DfsrStateTextNormal $authRow.State))
    $nonAuthNonNormalRows = @(Get-NonAuthoritativeNonNormalRows -Rows $stateRows -AuthoritativeComputerName $localHost)

    if ($Result -eq 'BLOCKED') {
        if ((Test-ContextKey -Key 'WaitPartialRecovery') -and [bool]$Script:Context['WaitPartialRecovery']) {
            $stuck = '<non-authoritative DC>'
            if (Test-ContextKey -Key 'WaitStuckNonAuthoritativeDcs') { $stuck = ([string[]]$Script:Context['WaitStuckNonAuthoritativeDcs']) -join ', ' }
            $notes.Add((New-SuggestedActionObject -Severity 'OK' -Message ("The authoritative DC reached DFSR SYSVOL State 4 / Normal."))) | Out-Null
            $notes.Add((New-SuggestedActionObject -Severity 'WARN' -Message ("The remaining issue is limited to non-authoritative DC(s): {0}." -f $stuck))) | Out-Null
            $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Do not rerun the global authoritative recovery while the authoritative source is already normal.')) | Out-Null
            return $notes
        }
        if ((Test-ContextKey -Key 'UnsupportedWorkflow') -and [bool]$Script:Context['UnsupportedWorkflow']) {
            $reason = 'This environment is outside the supported multi-DC workflow for this script.'
            if (Test-ContextKey -Key 'UnsupportedWorkflowReason') { $reason = [string]$Script:Context['UnsupportedWorkflowReason'] }
            $notes.Add((New-SuggestedActionObject -Severity 'ERR' -Message $reason)) | Out-Null
            $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'No SYSVOL recovery action was attempted. Do not rerun this MultiDC script unless the domain has two or more DCs.')) | Out-Null
            return $notes
        }
        $notes.Add((New-SuggestedActionObject -Severity 'ERR' -Message 'The script stopped before making recovery changes. Review the blocker above before choosing any recovery action.')) | Out-Null
        return $notes
    }

    if ($mode -eq 'Fix') {
        $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'The recovery workflow has started after passing preflight. Do not start another SYSVOL recovery in parallel.')) | Out-Null
        $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'The expected final state is DFSR SYSVOL State 4 / Normal on every DC.')) | Out-Null
        return $notes
    }

    if ($mode -eq 'Check' -and $allNormal) {
        $notes.Add((New-SuggestedActionObject -Severity 'OK' -Message 'Every DC already reports DFSR SYSVOL State 4 / Normal. Authoritative recovery is not indicated by DFSR state.')) | Out-Null
        return $notes
    }

    if ($mode -eq 'Check' -and $allInitial) {
        $notes.Add((New-SuggestedActionObject -Severity 'WARN' -Message ("Eligible for multi-DC authoritative recovery if {0} is confirmed as the SYSVOL source of truth." -f $localHost))) | Out-Null
        if ($nonAuth.Count -gt 0) {
            $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message ("The fix will make only {0} authoritative and will make these DCs non-authoritative: {1}." -f $localHost,($nonAuth -join ', ')))) | Out-Null
        }
        $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Before any DFSR/AD change, --fix will create and verify a separate C:\Windows\SYSVOL\domain backup from every DC.')) | Out-Null
        $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Post-fix verification must confirm every DC is State 4 / Normal and exposes SYSVOL and NETLOGON.')) | Out-Null
        return $notes
    }

    if ($mode -eq 'Check' -and $authNormal -and $nonAuthNonNormalRows.Count -gt 0) {
        $notes.Add((New-SuggestedActionObject -Severity 'OK' -Message ("The intended authoritative DC {0} already reports DFSR SYSVOL State 4 / Normal." -f $localHost))) | Out-Null
        $notes.Add((New-SuggestedActionObject -Severity 'WARN' -Message ("One or more non-authoritative DCs are still not State 4 / Normal: {0}." -f (Format-DcStateList $nonAuthNonNormalRows)))) | Out-Null
        $notes.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Do not rerun the multi-DC authoritative recovery for this mixed state. Troubleshoot only the non-authoritative DCs that are still in Initial Sync or No data.')) | Out-Null
        return $notes
    }

    if ($mode -eq 'Check' -and $stateRows.Count -gt 0) {
        $notes.Add((New-SuggestedActionObject -Severity 'WARN' -Message 'One or more DCs are not State 4 / Normal. Review the DFSR states before choosing the local DC as SYSVOL source of truth.')) | Out-Null
        return $notes
    }

    return $notes
}

function Get-SuggestedActions {
    param([string]$Result = 'Summary')

    $actions = New-Object System.Collections.Generic.List[object]
    $scriptName = Get-ScriptDisplayName
    $mode = $Script:Mode
    $backupRoot = Get-BackupRoot
    if ((Test-ContextKey -Key 'BackupRoot') -and -not [string]::IsNullOrWhiteSpace([string]$Script:Context['BackupRoot'])) {
        $backupRoot = [string]$Script:Context['BackupRoot']
    }

    $localHost = '<local DC not resolved>'
    $localShort = '<local DC>'
    if (Test-ContextKey -Key 'LocalDC') {
        $localHost = [string]$Script:Context['LocalDC'].HostName
        $localShort = [string]$Script:Context['LocalDC'].Name
    }

    $stateRows = @()
    if (Test-ContextKey -Key 'DfsrStateRows') { $stateRows = @($Script:Context['DfsrStateRows']) }
    $allNormal = ($stateRows.Count -gt 0 -and @(Get-NonNormalDfsrStateRows -Rows $stateRows).Count -eq 0)
    $allInitial = ($stateRows.Count -gt 0 -and @($stateRows | Where-Object { -not (Test-DfsrStateTextInitial $_.State) }).Count -eq 0)
    $authRow = Get-DfsrStateRowForDc -Rows $stateRows -ComputerName $localHost
    $authNormal = ($null -ne $authRow -and (Test-DfsrStateTextNormal $authRow.State))
    $nonAuthNonNormalRows = @(Get-NonAuthoritativeNonNormalRows -Rows $stateRows -AuthoritativeComputerName $localHost)

    if ($Result -eq 'BLOCKED') {
        if ((Test-ContextKey -Key 'WaitPartialRecovery') -and [bool]$Script:Context['WaitPartialRecovery']) {
            $stuck = '<non-authoritative DC>'
            if (Test-ContextKey -Key 'WaitStuckNonAuthoritativeDcs') { $stuck = ([string[]]$Script:Context['WaitStuckNonAuthoritativeDcs']) -join ', ' }
            $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message ("On {0}: run dfsrdiag pollad, restart DFSR if it remains State 2, then reboot only that DC and run dfsrdiag pollad again if still stuck." -f $stuck))) | Out-Null
            $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message ("After the affected DCs reach State 4, run validation: .\{0} --check" -f $scriptName))) | Out-Null
            return $actions
        }
        if ((Test-ContextKey -Key 'UnsupportedWorkflow') -and [bool]$Script:Context['UnsupportedWorkflow']) {
            return $actions
        }
        return $actions
    }

    if ($mode -eq 'Fix') {
        $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message 'Wait for the workflow to finish; do not start another SYSVOL recovery in parallel.')) | Out-Null
        return $actions
    }

    if ($mode -eq 'Check' -and $allNormal) {
        return $actions
    }

    if ($mode -eq 'Check' -and $allInitial) {
        $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message ('Run the recovery only from {0}: .\{1} --fix --backup-path "{2}"' -f $localShort,$scriptName,$backupRoot))) | Out-Null
        return $actions
    }

    if ($mode -eq 'Check' -and $authNormal -and $nonAuthNonNormalRows.Count -gt 0) {
        $stuck = ((@($nonAuthNonNormalRows) | ForEach-Object { [string]$_.DC }) -join ', ')
        $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message ("On {0}: run dfsrdiag pollad; if it remains State 2, restart DFSR; if still stuck, reboot only the affected DC and run dfsrdiag pollad again." -f $stuck))) | Out-Null
        return $actions
    }

    if ($mode -eq 'Check' -and $stateRows.Count -gt 0) {
        $actions.Add((New-SuggestedActionObject -Severity 'WARN' -Message ("Do not run --fix automatically in this mixed state. Review DFSR states and event logs first; use --fix only if all DCs are stuck and the local SYSVOL is the confirmed source of truth."))) | Out-Null
        return $actions
    }

    if ($mode -eq 'Check') {
        $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message ("Run validation again after correcting any warning or incomplete prerequisite: .\{0} --check" -f $scriptName))) | Out-Null
        return $actions
    }

    $actions.Add((New-SuggestedActionObject -Severity 'INFO' -Message ("Run validation first: .\{0} --check" -f $scriptName))) | Out-Null
    return $actions
}

function Write-MessageList {
    param(
        [object[]]$Items = @(),
        [switch]$ShowNone,
        [string]$NoneMessage = 'None.'
    )

    if ($Items.Count -eq 0) {
        if ($ShowNone) { Write-Host ('  - {0}' -f $NoneMessage) -ForegroundColor Gray }
        return
    }

    foreach ($item in $Items) {
        switch ($item.Severity) {
            'OK'   { Write-Host ("  - {0}" -f $item.Message) -ForegroundColor Green }
            'WARN' { Write-Host ("  - {0}" -f $item.Message) -ForegroundColor DarkYellow }
            'ERR'  { Write-Host ("  - {0}" -f $item.Message) -ForegroundColor Red }
            default { Write-Host ("  - {0}" -f $item.Message) -ForegroundColor Gray }
        }
    }
}

function Show-NotesAndSuggestedActions {
    param([string]$Result = 'Summary')

    $notes = @(Get-SummaryNotes -Result $Result)
    if ($notes.Count -gt 0) {
        Write-Blank
        Write-Host 'Notes:' -ForegroundColor White
        Write-MessageList -Items $notes
    }

    if ($Result -eq 'BLOCKED' -and (Test-ContextKey -Key 'UnsupportedWorkflow') -and [bool]$Script:Context['UnsupportedWorkflow']) {
        return
    }

    Write-Blank
    Write-Host 'Suggested actions:' -ForegroundColor White
    $actions = @(Get-SuggestedActions -Result $Result)
    Write-MessageList -Items $actions -ShowNone -NoneMessage 'No direct action required.'
}

function Show-Summary {
    param([string]$Result)
    Write-Section ('Summary - {0}' -f $Result) Cyan

    if ($Script:Actions.Count -gt 0) {
        Write-Host 'Completed actions:' -ForegroundColor White
        foreach ($a in $Script:Actions) { Write-Host ('  - {0}' -f $a) -ForegroundColor Gray }
    }

    if ($Script:Warnings.Count -gt 0) {
        Write-Blank
        Write-Host 'Warnings:' -ForegroundColor DarkYellow
        foreach ($w in $Script:Warnings) { Write-Host ('  - {0}' -f $w) -ForegroundColor DarkYellow }
    }

    if ($Script:Errors.Count -gt 0) {
        Write-Blank
        Write-Host 'Errors / blockers:' -ForegroundColor Red
        foreach ($e in $Script:Errors) { Write-Host ('  - {0}' -f $e) -ForegroundColor Red }
    }

    Show-NotesAndSuggestedActions -Result $Result

    if ($Script:TranscriptPath) {
        Write-Blank
        Write-Host ('Log: {0}' -f $Script:TranscriptPath) -ForegroundColor Gray
    }
}

function Stop-WithError {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string[]]$SuggestedActions = @()
    )
    Write-ErrMsg $Message
    if ($SuggestedActions.Count -gt 0) {
        Write-Blank
        Write-Host 'Suggested next actions:' -ForegroundColor White
        foreach ($s in $SuggestedActions) { Write-Host ('  - {0}' -f $s) -ForegroundColor Gray }
    }
    Show-Summary -Result 'BLOCKED'
    Stop-TranscriptSafe
    exit 1
}

function Get-ScriptRuntimePath {
    if ($PSCommandPath) { return $PSCommandPath }
    if ($MyInvocation.MyCommand.Path) { return $MyInvocation.MyCommand.Path }
    return $null
}
function Get-ScriptDisplayName {
    $p = Get-ScriptRuntimePath
    if ($p) { return (Split-Path -Leaf $p) }
    return 'Invoke-SysvolAuthoritativeMultiDC.ps1'
}
function Get-ScriptDirectory {
    $p = Get-ScriptRuntimePath
    if ($p) { return (Split-Path -Parent $p) }
    return (Get-Location).Path
}
function Get-BackupRoot {
    if ($Script:CustomBackupRoot) { return $Script:CustomBackupRoot }
    return (Get-ScriptDirectory)
}
function Get-LogPath {
    $p = Get-ScriptRuntimePath
    if ($p) {
        return (Join-Path (Split-Path -Parent $p) (([System.IO.Path]::GetFileNameWithoutExtension($p)) + '.log'))
    }
    return (Join-Path (Get-Location).Path 'Invoke-SysvolAuthoritativeMultiDC.log')
}
function Start-TranscriptSafe {
    $Script:TranscriptPath = Get-LogPath
    $dir = Split-Path -Parent $Script:TranscriptPath
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try {
        Start-Transcript -Path $Script:TranscriptPath -Append | Out-Null
        Write-Info ('Transcript started: {0}' -f $Script:TranscriptPath)
        Write-Info ('Script version: {0}' -f $Script:Version)
    }
    catch {
        Write-WarnMsg ('Unable to start transcript: {0}' -f $_.Exception.Message)
    }
}
function Stop-TranscriptSafe {
    try { Stop-Transcript | Out-Null } catch { }
}

function Show-Help {
    $scriptName = Get-ScriptDisplayName
    $logPath = Get-LogPath
    $backupRoot = Get-BackupRoot

    Write-Section ('Help - Invoke-SysvolAuthoritativeMultiDC v{0}' -f $Script:Version) Cyan
    Write-Host 'Checks and safely runs an authoritative DFSR SYSVOL recovery in a multi-DC domain.' -ForegroundColor White
    Write-Host 'Run it on the one DC that must become authoritative; all other DCs are treated as non-authoritative.' -ForegroundColor Gray
    Write-Blank

    Write-Host 'Parameters:' -ForegroundColor White
    @(
        [pscustomobject]@{ Parameter='--help'; Required='No'; Description='Shows this help screen.' }
        [pscustomobject]@{ Parameter='--check'; Required='No'; Description='Runs safety checks only. No AD, DFSR, service, or file changes are made.' }
        [pscustomobject]@{ Parameter='--fix'; Required='No'; Description='Runs checks, backs up SYSVOL on every DC, then performs the multi-DC authoritative workflow.' }
        [pscustomobject]@{ Parameter='--backup-path <path>'; Required='No'; Description='Optional with --fix. Stores timestamped per-DC SYSVOL backups under this root.' }
    ) | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }

    Write-Host 'Notes:' -ForegroundColor White
    Write-Host ('  Log file: {0}' -f $logPath) -ForegroundColor Gray
    Write-Host ('  Default backup root: {0}' -f $backupRoot) -ForegroundColor Gray
    Write-Host '  The local DC must own all five FSMO roles and is the only DC that can become authoritative.' -ForegroundColor Gray
    Write-Host '  If all DCs are stuck in State 2 / Initial Sync, a passed --check recommends --fix from the intended source DC.' -ForegroundColor Gray
    Write-Host '  Safety gates use structured AD/DFSR data, not localized command output text.' -ForegroundColor Gray
    Write-Host '  All DCs known to AD must be reachable before --fix can continue.' -ForegroundColor Gray
    Write-Host '  --fix backs up C:\Windows\SYSVOL\domain from every DC before recovery changes.' -ForegroundColor Gray
    Write-Blank

    Write-Host 'Examples:' -ForegroundColor White
    Write-Host ('  .\{0} --help' -f $scriptName) -ForegroundColor Gray
    Write-Host ('  .\{0} --check' -f $scriptName) -ForegroundColor Gray
    Write-Host ('  .\{0} --fix' -f $scriptName) -ForegroundColor Gray
    Write-Host ('  .\{0} --fix --backup-path D:\SafeBackups' -f $scriptName) -ForegroundColor Gray
    Write-Host ('  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\{0} --check' -f $scriptName) -ForegroundColor Gray
    Write-Blank
}

function Parse-Arguments {
    param([string[]]$RawArgs)
    if (-not $RawArgs -or $RawArgs.Count -eq 0) { Show-Help; exit 0 }

    $mode = $null
    for ($i = 0; $i -lt $RawArgs.Count; ) {
        $arg = [string]$RawArgs[$i]
        $lower = $arg.ToLowerInvariant()
        switch -Regex ($lower) {
            '^--help$|^-help$|^-h$|^/\?$' { Show-Help; exit 0 }
            '^--check$|^-check$' {
                if ($mode) { Stop-WithError 'Only one mode can be specified.' @('Use either --check or --fix.') }
                $mode = 'Check'; $i++; continue
            }
            '^--fix$|^-fix$' {
                if ($mode) { Stop-WithError 'Only one mode can be specified.' @('Use either --check or --fix.') }
                $mode = 'Fix'; $i++; continue
            }
            '^--backup-path=(.+)$|^-backup-path=(.+)$' {
                $value = $arg.Substring($arg.IndexOf('=') + 1).Trim()
                if ([string]::IsNullOrWhiteSpace($value)) { Stop-WithError '--backup-path was provided without a value.' }
                $Script:CustomBackupRoot = $value; $i++; continue
            }
            '^--backup-path$|^-backup-path$' {
                if (($i + 1) -ge $RawArgs.Count) { Stop-WithError '--backup-path was provided without a value.' }
                $Script:CustomBackupRoot = [string]$RawArgs[$i + 1]; $i += 2; continue
            }
            default { Show-Help; Stop-WithError ('Unknown argument: {0}' -f $arg) }
        }
    }

    if (-not $mode) { Show-Help; Stop-WithError 'No mode specified.' @('Use --check or --fix.') }
    $Script:Mode = $mode
}

function Assert-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-WithError 'This script must be run from an elevated PowerShell session.' @('Start PowerShell as Administrator on the intended authoritative DC.')
    }
    Write-Ok 'PowerShell is elevated.'
}

function Import-ADModuleSafe {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Ok 'ActiveDirectory module imported.'
    }
    catch {
        Stop-WithError ('Unable to import the ActiveDirectory module: {0}' -f $_.Exception.Message) @('Run this script on a Domain Controller or install RSAT Active Directory tools.')
    }
}

function Normalize-ComputerName {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim().TrimEnd('.').ToUpperInvariant()
    return $n
}
function Get-NetbiosFromFqdn { param([string]$Name) return (($Name -split '\.')[0]) }
function Test-NameInDcList {
    param([string]$Name)
    $n = Normalize-ComputerName $Name
    if (-not $n) { return $true }
    foreach ($candidate in $Script:Context['ValidDcNames']) {
        if ($n -eq $candidate) { return $true }
    }
    return $false
}

function Convert-DfsrState {
    param([Nullable[int]]$State)
    if ($null -eq $State) { return 'No data' }
    switch ([int]$State) {
        0 { return '0 - Uninitialized' }
        1 { return '1 - Initialized' }
        2 { return '2 - Initial Sync' }
        3 { return '3 - Auto Recovery' }
        4 { return '4 - Normal' }
        5 { return '5 - In Error' }
        default { return ('{0} - Unknown' -f $State) }
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [switch]$AllowFailure
    )
    Write-Info ('Running: {0} {1}' -f $FilePath, ($Arguments -join ' '))
    $output = & $FilePath @Arguments 2>&1
    foreach ($line in @($output)) { Write-Host $line }
    $rc = [int]$LASTEXITCODE
    Write-Info ('Exit code: {0}' -f $rc)
    if (($rc -ne 0) -and (-not $AllowFailure)) {
        Stop-WithError ('Command failed: {0} {1}' -f $FilePath, ($Arguments -join ' '))
    }
    return $rc
}


function Get-Win32ExitCodeSummary {
    param([Parameter(Mandatory=$true)][int]$Code)
    if ($Code -eq 0) { return '0 / ERROR_SUCCESS' }
    if ($Code -eq 234) { return '234 / ERROR_MORE_DATA' }
    try {
        $message = (New-Object System.ComponentModel.Win32Exception -ArgumentList $Code).Message
        return ('{0} / {1}' -f $Code,$message)
    }
    catch {
        return [string]$Code
    }
}

function Get-SafePropertyValue {
    param(
        [Parameter(Mandatory=$true)]$InputObject,
        [Parameter(Mandatory=$true)][string]$Name,
        $Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property -and $null -ne $property.Value) { return $property.Value }
    return $Default
}

function Get-MissingObjectProperties {
    param(
        [Parameter(Mandatory=$true)]$InputObject,
        [Parameter(Mandatory=$true)][string[]]$Names
    )
    $missing = @()
    foreach ($name in $Names) {
        if ($null -eq $InputObject.PSObject.Properties[$name]) { $missing += $name }
    }
    return $missing
}

function Initialize-TopologyContext {
    Write-Section 'Topology discovery' Cyan
    Assert-Administrator
    Import-ADModuleSafe

    $localCs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ([int]$localCs.DomainRole -lt 4) {
        Stop-WithError 'The local server is not a Domain Controller.' @('Run this script on the DC that should become authoritative.')
    }

    $localNetbios = Normalize-ComputerName $env:COMPUTERNAME
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Sort-Object HostName)
    if ($dcs.Count -lt 2) {
        $Script:Context['UnsupportedWorkflow'] = $true
        $Script:Context['UnsupportedWorkflowReason'] = ('Only {0} DC object(s) found. This script supports only multi-DC domains.' -f $dcs.Count)
        Stop-WithError ('Only {0} DC object(s) found. This is not a multi-DC workflow.' -f $dcs.Count)
    }

    $localDc = $dcs | Where-Object {
        (Normalize-ComputerName $_.Name) -eq $localNetbios -or
        (Normalize-ComputerName (Get-NetbiosFromFqdn $_.HostName)) -eq $localNetbios
    } | Select-Object -First 1

    if (-not $localDc) {
        Stop-WithError 'The local DC was not found in Get-ADDomainController output.'
    }

    $validNames = New-Object System.Collections.Generic.List[string]
    foreach ($dc in $dcs) {
        $validNames.Add((Normalize-ComputerName $dc.Name)) | Out-Null
        $validNames.Add((Normalize-ComputerName $dc.HostName)) | Out-Null
        $validNames.Add((Normalize-ComputerName (Get-NetbiosFromFqdn $dc.HostName))) | Out-Null
    }

    $Script:Context['Domain'] = $domain
    $Script:Context['Forest'] = $forest
    $Script:Context['DomainDnsRoot'] = [string]$domain.DNSRoot
    $Script:Context['DomainNetBIOS'] = [string]$domain.NetBIOSName
    $Script:Context['DomainDN'] = [string]$domain.DistinguishedName
    $Script:Context['ConfigNC'] = [string]$forest.PartitionsContainer.Replace('CN=Partitions,', '')
    $Script:Context['DCs'] = $dcs
    $Script:Context['LocalDC'] = $localDc
    $Script:Context['LocalNetbios'] = $localNetbios
    $Script:Context['ValidDcNames'] = @($validNames | Select-Object -Unique)

    Write-Ok ('Domain: {0}' -f $domain.DNSRoot)
    Write-Ok ('Domain Controllers discovered: {0}' -f $dcs.Count)
    Write-Ok ('Local intended authoritative DC: {0}' -f $localDc.HostName)

    $rows = $dcs | Select-Object Name, HostName, Site, IPv4Address, IsGlobalCatalog
    $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
}

function Test-FsmoOwnership {
    Write-Section 'FSMO ownership safety gate' Cyan
    $domain = $Script:Context['Domain']
    $forest = $Script:Context['Forest']
    $local = Normalize-ComputerName $Script:Context['LocalDC'].HostName
    $localNb = Normalize-ComputerName $Script:Context['LocalDC'].Name

    $roles = @(
        [pscustomobject]@{ Role='PDC Emulator'; Holder=$domain.PDCEmulator }
        [pscustomobject]@{ Role='RID Master'; Holder=$domain.RIDMaster }
        [pscustomobject]@{ Role='Infrastructure Master'; Holder=$domain.InfrastructureMaster }
        [pscustomobject]@{ Role='Schema Master'; Holder=$forest.SchemaMaster }
        [pscustomobject]@{ Role='Domain Naming Master'; Holder=$forest.DomainNamingMaster }
    )

    $bad = @()
    foreach ($r in $roles) {
        $h = Normalize-ComputerName $r.Holder
        $hNb = Normalize-ComputerName (Get-NetbiosFromFqdn $r.Holder)
        $isLocal = ($h -eq $local) -or ($hNb -eq $localNb)
        $r | Add-Member -NotePropertyName IsLocal -NotePropertyValue $isLocal -Force
        if (-not $isLocal) { $bad += $r }
    }

    $roles | Format-Table Role,Holder,IsLocal -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }

    if ($bad.Count -gt 0) {
        Stop-WithError 'The local DC does not own all FSMO roles. --fix is blocked.' @(
            'Run this script on the FSMO/PDC holder that has the SYSVOL copy you want to make authoritative.',
            'If FSMO ownership is wrong, fix FSMO/seizure/transfer first, then run --check again.'
        )
    }
    Write-Ok 'The local DC owns all five FSMO roles.'
}

function Test-SitesAndServicesObjects {
    Write-Section 'AD Sites and Services stale object gate' Cyan
    $configNc = $Script:Context['ConfigNC']
    $sitesBase = 'CN=Sites,{0}' -f $configNc
    $serverObjects = @(Get-ADObject -SearchBase $sitesBase -LDAPFilter '(objectClass=server)' -Properties dNSHostName -ErrorAction Stop)
    $blockers = @()

    foreach ($s in $serverObjects) {
        $nameOk = Test-NameInDcList -Name $s.Name
        $dnsOk = $true
        if ($s.dNSHostName) { $dnsOk = Test-NameInDcList -Name $s.dNSHostName }
        if (-not $nameOk -or -not $dnsOk) {
            $blockers += [pscustomobject]@{ Name=$s.Name; DNSHostName=$s.dNSHostName; DistinguishedName=$s.DistinguishedName }
        }
    }

    if ($serverObjects.Count -gt 0) {
        $serverObjects | Select-Object Name,dNSHostName,DistinguishedName | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
    }

    if ($blockers.Count -gt 0) {
        $blockers | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Red }
        Stop-WithError 'Stale or non-DC server objects were found under AD Sites and Services. --fix is blocked.' @(
            'Verify and clean up obsolete server/NTDS Settings objects using proper AD metadata cleanup.',
            'Run --check again after the Sites and Services topology matches the real DC list.'
        )
    }
    Write-Ok 'AD Sites and Services server objects match the current DC list.'
}

function Test-DcReachability {
    Write-Section 'DC reachability and remote control gate' Cyan
    $dcs = $Script:Context['DCs']
    $failures = @()
    foreach ($dc in $dcs) {
        $target = [string]$dc.HostName
        Write-SubSection $target
        $pingOk = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($pingOk) { Write-Ok 'ICMP ping succeeded.' } else { Write-WarnMsg ('ICMP ping failed for {0}. Continuing with service/WMI tests because ICMP may be blocked.' -f $target) }

        try {
            $svc = Get-WmiObject -Class Win32_Service -ComputerName $target -Filter "Name='DFSR'" -ErrorAction Stop
            if ($svc) { Write-Ok ('Remote DFSR service query succeeded. State={0}; StartMode={1}' -f $svc.State,$svc.StartMode) }
            else { throw 'DFSR service was not returned by WMI.' }
        }
        catch {
            $failures += ('{0}: DFSR service cannot be queried remotely: {1}' -f $target,$_.Exception.Message)
            Write-ErrMsg $failures[-1]
        }

        try {
            $null = Get-WmiObject -Namespace root\MicrosoftDFS -Class DfsrReplicatedFolderInfo -ComputerName $target -Filter "ReplicatedFolderName='SYSVOL Share'" -ErrorAction Stop
            Write-Ok 'Remote DFSR WMI namespace is reachable.'
        }
        catch {
            $failures += ('{0}: root\MicrosoftDFS cannot be queried remotely: {1}' -f $target,$_.Exception.Message)
            Write-ErrMsg $failures[-1]
        }
    }

    if ($failures.Count -gt 0) {
        Stop-WithError 'One or more DCs are not reachable for the operations required by --fix.' @(
            'All AD-known DCs must be reachable before a multi-DC authoritative workflow.',
            'Fix DNS, firewall, RPC/WMI, permissions, or stale DC metadata first.'
        )
    }
    Write-Ok 'All DCs passed remote DFSR/WMI reachability checks.'
}

function Get-DfsrSysvolInfoRemote {
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    try {
        return Get-WmiObject -Namespace root\MicrosoftDFS -Class DfsrReplicatedFolderInfo -ComputerName $ComputerName -Filter "ReplicatedFolderName='SYSVOL Share'" -ErrorAction Stop
    }
    catch {
        Write-WarnMsg ('Unable to read DFSR SYSVOL state from {0}: {1}' -f $ComputerName,$_.Exception.Message)
        return $null
    }
}

function Test-DfsrStatesAndSubscriptions {
    Write-Section 'DFSR SYSVOL state and AD subscription checks' Cyan
    $dcs = $Script:Context['DCs']
    $subRows = @()
    $stateRows = @()
    $blockers = @()

    foreach ($dc in $dcs) {
        $hostName = [string]$dc.HostName
        $info = Get-DfsrSysvolInfoRemote -ComputerName $hostName
        $state = $null
        $lastError = $null
        if ($info) {
            $state = [int]$info.State
            $lastError = [int]$info.LastErrorCode
        }
        $stateRows += [pscustomobject]@{
            DC = $hostName
            State = (Convert-DfsrState $state)
            LastErrorCode = $lastError
        }

        $subDn = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,{0}' -f $dc.ComputerObjectDN
        try {
            $sub = Get-ADObject -Identity $subDn -Properties 'msDFSR-Enabled','msDFSR-Options' -ErrorAction Stop
            $enabled = $sub.'msDFSR-Enabled'
            $options = $sub.'msDFSR-Options'
            if ($null -eq $options) { $options = 0 }
            $subRows += [pscustomobject]@{ DC=$hostName; Enabled=$enabled; Options=$options; DN=$subDn }
        }
        catch {
            $blockers += ('{0}: missing or unreadable SYSVOL Subscription object: {1}' -f $hostName,$_.Exception.Message)
        }
    }

    Write-SubSection 'Remote DFSR WMI state'
    $stateRows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
    Write-SubSection 'AD SYSVOL Subscription attributes'
    $subRows | Format-Table DC,Enabled,Options -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }

    $Script:Context['DfsrStateRows'] = $stateRows
    $Script:Context['SubscriptionRows'] = $subRows

    if ($blockers.Count -gt 0) {
        foreach ($b in $blockers) { Write-ErrMsg $b }
        Stop-WithError 'One or more DFSR SYSVOL Subscription objects are missing or unreadable.'
    }

    $authDc = [string]$Script:Context['LocalDC'].HostName
    $localState = @($stateRows | Where-Object { $_.DC -eq $authDc })[0]
    if ($localState.State -match '^No data') {
        Stop-WithError 'The intended authoritative DC does not report a DFSR SYSVOL state.'
    }

    $nonLocalAuthoritativeFlags = @($subRows | Where-Object { $_.DC -ne $authDc -and [int]$_.Options -eq 1 })
    if ($nonLocalAuthoritativeFlags.Count -gt 0) {
        Stop-WithError 'A non-local DC already has msDFSR-Options=1. --fix is blocked to avoid multiple authoritative SYSVOL sources.' @(
            'Review the listed SYSVOL Subscription attributes.',
            'There must be exactly one intended authoritative DC for this recovery workflow.'
        )
    }

    Write-Ok 'DFSR SYSVOL Subscription objects are present and no other DC is marked authoritative.'
}

function Get-RemoteWindowsDirectory {
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
    return [string]$os.WindowsDirectory
}

function Convert-LocalPathToAdminSharePath {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][string]$LocalPath
    )
    $full = $LocalPath.TrimEnd('\')
    if ($full -notmatch '^[A-Za-z]:\\') { throw ('Unexpected local path format: {0}' -f $LocalPath) }
    $drive = $full.Substring(0,1)
    $rest = $full.Substring(2).TrimStart('\')
    return ('\\{0}\{1}$\{2}' -f $ComputerName,$drive,$rest)
}

function Get-SysvolDomainPathRemote {
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    $winDir = Get-RemoteWindowsDirectory -ComputerName $ComputerName
    $localPath = Join-Path (Join-Path $winDir 'SYSVOL') 'domain'
    return (Convert-LocalPathToAdminSharePath -ComputerName $ComputerName -LocalPath $localPath)
}

function Test-LocalSourcePayload {
    Write-Section 'Authoritative SYSVOL payload check' Cyan
    $auth = [string]$Script:Context['LocalDC'].HostName
    $path = Get-SysvolDomainPathRemote -ComputerName $auth
    $Script:Context['AuthoritativeSysvolPath'] = $path
    Write-Info ('Authoritative SYSVOL path: {0}' -f $path)

    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        Stop-WithError ('Authoritative SYSVOL domain path does not exist: {0}' -f $path) @('Do not run an authoritative recovery until the intended source SYSVOL payload is present.')
    }

    $policies = Join-Path $path 'Policies'
    if (-not (Test-Path -LiteralPath $policies -PathType Container)) {
        Stop-WithError ('Authoritative SYSVOL Policies folder is missing: {0}' -f $policies)
    }

    $gpt = @(Get-ChildItem -LiteralPath $policies -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\{[0-9A-Fa-f-]{36}\}$' })
    if ($gpt.Count -lt 1) {
        Stop-WithError 'No GPO GUID folders were found under the authoritative SYSVOL Policies tree.' @('Verify manually that this DC contains the SYSVOL copy you want to publish to all other DCs.')
    }

    Write-Ok ('Authoritative SYSVOL payload exists and contains {0} GPO folder(s).' -f $gpt.Count)
}


function Test-SysvolComparisonPreview {
    Write-Section 'SYSVOL comparison preview from authoritative DC to other DCs' Cyan
    $auth = [string]$Script:Context['LocalDC'].HostName
    $source = [string]$Script:Context['AuthoritativeSysvolPath']
    $Script:Context['RobocopyPreviewHadDifferences'] = $false
    $Script:Context['RobocopyPreviewRan'] = $false
    $robocopy = Get-Command robocopy.exe -ErrorAction SilentlyContinue
    if (-not $robocopy) {
        Write-WarnMsg 'robocopy.exe was not found. Skipping SYSVOL comparison preview.'
        return
    }

    foreach ($dc in @($Script:Context['DCs'] | Where-Object { $_.HostName -ne $auth })) {
        $target = Get-SysvolDomainPathRemote -ComputerName ([string]$dc.HostName)
        Write-SubSection ('Preview {0} -> {1}' -f $auth,$dc.HostName)
        Write-Info ('Source: {0}' -f $source)
        Write-Info ('Target: {0}' -f $target)

        if (-not (Test-Path -LiteralPath $target -PathType Container)) {
            Write-WarnMsg ('Target SYSVOL path is not reachable for comparison: {0}' -f $target)
            continue
        }

        Write-Info 'Robocopy preview mode: /L is present. No file copy, delete, or timestamp/ACL change is intended in --check.'
        Write-Info ('Command: robocopy.exe "{0}" "{1}" /MIR /L /XJ /R:0 /W:0 /COPY:DAT /DCOPY:DAT /XD DfsrPrivate /NP /NJH /NJS /NFL /NDL' -f $source,$target)
        $Script:Context['RobocopyPreviewRan'] = $true
        & $robocopy.Source $source $target /MIR /L /XJ /R:0 /W:0 /COPY:DAT /DCOPY:DAT /XD DfsrPrivate /NP /NJH /NJS /NFL /NDL
        $rc = $LASTEXITCODE
        Write-Info ('Robocopy preview exit code: {0}' -f $rc)
        if ($rc -eq 0) {
            Write-Ok ('No payload differences reported between {0} and {1}.' -f $auth,$dc.HostName)
        }
        elseif ($rc -le 7) {
            $Script:Context['RobocopyPreviewHadDifferences'] = $true
            Write-WarnMsg ('Differences were reported between authoritative SYSVOL and {0}. This is not changed in --check. In --fix, {1} is still treated as source of truth after explicit confirmation.' -f $dc.HostName,$auth)
        }
        else {
            Stop-WithError ('Robocopy comparison preview failed for {0} with exit code {1}.' -f $dc.HostName,$rc)
        }
    }
}

function Test-ParentComputerRegistry {
    Write-Section 'DFSR SYSVOL seeding Parent Computer registry check' Cyan
    $domainDns = [string]$Script:Context['DomainDnsRoot']
    $subKey = 'SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols\Seeding SysVols\{0}' -f $domainDns
    $dcs = $Script:Context['DCs']
    $rows = @()
    $invalid = @()
    $suggested = [string]$Script:Context['LocalDC'].HostName

    foreach ($dc in $dcs) {
        $target = [string]$dc.HostName
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $target)
            $key = $base.OpenSubKey($subKey, $false)
            if (-not $key) {
                $rows += [pscustomobject]@{ DC=$target; Exists=$false; ParentComputer=''; Status='Key missing'; SuggestedParent=$suggested }
                Write-WarnMsg ('{0}: Parent Computer key missing: HKLM\{1}' -f $target,$subKey)
                continue
            }
            $value = [string]$key.GetValue('Parent Computer', '')
            $status = 'OK'
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                if (-not (Test-NameInDcList -Name $value)) {
                    $status = 'INVALID - not a current DC'
                    $invalid += [pscustomobject]@{ DC=$target; ParentComputer=$value; SuggestedParent=$suggested }
                }
            }
            $rows += [pscustomobject]@{ DC=$target; Exists=$true; ParentComputer=$value; Status=$status; SuggestedParent=$suggested }
        }
        catch {
            $rows += [pscustomobject]@{ DC=$target; Exists=$false; ParentComputer=''; Status=('Unreadable: {0}' -f $_.Exception.Message); SuggestedParent=$suggested }
            $invalid += [pscustomobject]@{ DC=$target; ParentComputer='<unreadable>'; SuggestedParent=$suggested }
        }
    }

    $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
    $Script:Context['ParentComputerRows'] = $rows

    if ($invalid.Count -gt 0) {
        Write-Blank
        Write-Host 'Suggested manual correction target for invalid Parent Computer values:' -ForegroundColor White
        $invalid | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
        Stop-WithError 'One or more DFSR SYSVOL Parent Computer registry values point to a nonexistent/non-current DC. --fix is blocked.' @(
            ('Correct the invalid Parent Computer value to a real DC FQDN, commonly {0}, then restart DFSR and run --check again.' -f $suggested),
            'Do not leave references to removed/orphaned DCs in this key before a multi-DC authoritative recovery.'
        )
    }

    Write-Ok 'No invalid DFSR SYSVOL Parent Computer registry value was found.'
}

function Test-ADReplicationHealth {
    Write-Section 'Active Directory replication health gate' Cyan
    Write-Info 'Using structured AD cmdlets only for the blocking decision. Localized repadmin text and repadmin exit codes are not parsed.'

    $rows = @()
    $metadataFailures = @()
    $replicationFailureRows = @()
    $replicationFailures = @()
    $replicationWarnings = @()
    $readFailures = @()

    $metadataRequiredProps = @('ConsecutiveReplicationFailures','LastReplicationResult','LastReplicationSuccess','LastReplicationAttempt','Partition','Partner')
    $failureRequiredProps = @('FailureCount','LastError','Server','Partner','Partition','FirstFailureTime','LastErrorMessage')

    foreach ($dc in $Script:Context['DCs']) {
        $target = [string]$dc.HostName

        try {
            $metadata = @(Get-ADReplicationPartnerMetadata -Target $target -Scope Server -PartnerType Inbound -ErrorAction Stop)
        }
        catch {
            $readFailures += ('{0}: unable to read AD replication partner metadata: {1}' -f $target,$_.Exception.Message)
            continue
        }

        if ($metadata.Count -eq 0) {
            $readFailures += ('{0}: no inbound AD replication partner metadata was returned.' -f $target)
            continue
        }

        foreach ($m in $metadata) {
            $missingMetadataProps = @(Get-MissingObjectProperties -InputObject $m -Names $metadataRequiredProps)
            if ($missingMetadataProps.Count -gt 0) {
                $readFailures += ('{0}: unexpected Get-ADReplicationPartnerMetadata object format. Missing properties: {1}' -f $target,($missingMetadataProps -join ', '))
                continue
            }

            $consecutive = [int](Get-SafePropertyValue -InputObject $m -Name 'ConsecutiveReplicationFailures' -Default 0)
            $lastResult = [int](Get-SafePropertyValue -InputObject $m -Name 'LastReplicationResult' -Default 0)
            $lastSuccess = Get-SafePropertyValue -InputObject $m -Name 'LastReplicationSuccess' -Default $null
            $lastAttempt = Get-SafePropertyValue -InputObject $m -Name 'LastReplicationAttempt' -Default $null
            $partition = [string](Get-SafePropertyValue -InputObject $m -Name 'Partition' -Default '')
            $partner = [string](Get-SafePropertyValue -InputObject $m -Name 'Partner' -Default '')

            $row = [pscustomobject]@{
                TargetDC = $target
                Partner = $partner
                Partition = $partition
                ConsecutiveFailures = $consecutive
                LastResult = $lastResult
                LastAttempt = $lastAttempt
                LastSuccess = $lastSuccess
            }
            $rows += $row

            # These two fields describe the current inbound replication state.
            # They are the primary blocking signal.
            if ($consecutive -gt 0 -or $lastResult -ne 0) {
                $metadataFailures += $row
            }
        }

        try {
            $failures = @(Get-ADReplicationFailure -Target $target -Scope Server -ErrorAction Stop)
            foreach ($f in $failures) {
                $missingFailureProps = @(Get-MissingObjectProperties -InputObject $f -Names $failureRequiredProps)
                if ($missingFailureProps.Count -gt 0) {
                    $readFailures += ('{0}: unexpected Get-ADReplicationFailure object format. Missing properties: {1}' -f $target,($missingFailureProps -join ', '))
                    continue
                }

                $failureCount = [int](Get-SafePropertyValue -InputObject $f -Name 'FailureCount' -Default 0)
                $lastError = [int](Get-SafePropertyValue -InputObject $f -Name 'LastError' -Default 0)
                $failureRow = [pscustomobject]@{
                    TargetDC = $target
                    Server = [string](Get-SafePropertyValue -InputObject $f -Name 'Server' -Default '')
                    Partner = [string](Get-SafePropertyValue -InputObject $f -Name 'Partner' -Default '')
                    Partition = [string](Get-SafePropertyValue -InputObject $f -Name 'Partition' -Default '')
                    FailureCount = $failureCount
                    LastError = $lastError
                    FirstFailureTime = Get-SafePropertyValue -InputObject $f -Name 'FirstFailureTime' -Default $null
                    LastErrorMessage = [string](Get-SafePropertyValue -InputObject $f -Name 'LastErrorMessage' -Default '')
                }
                $replicationFailureRows += $failureRow

                # Get-ADReplicationFailure can retain the most recent failure details.
                # For the safety gate, the active blocker is FailureCount > 0.
                # LastError is diagnostic context; when FailureCount=0 it is logged as a warning only,
                # and the current-state decision remains with partner metadata above.
                if ($failureCount -gt 0) {
                    $replicationFailures += $failureRow
                }
                elseif ($lastError -ne 0) {
                    $replicationWarnings += $failureRow
                }
            }
        }
        catch {
            $readFailures += ('{0}: unable to read AD replication failures: {1}' -f $target,$_.Exception.Message)
        }
    }

    if ($rows.Count -gt 0) {
        Write-SubSection 'Inbound AD replication partner metadata'
        $rows | Sort-Object TargetDC,Partition,Partner | Format-Table TargetDC,Partner,Partition,ConsecutiveFailures,LastResult,LastAttempt,LastSuccess -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
    }

    if ($replicationFailureRows.Count -gt 0) {
        Write-SubSection 'Get-ADReplicationFailure output'
        $replicationFailureRows | Sort-Object TargetDC,Partition,Partner | Format-List TargetDC,Server,Partner,Partition,FailureCount,LastError,FirstFailureTime,LastErrorMessage | Out-String | ForEach-Object {
            $line = $_.TrimEnd()
            if ($replicationFailures.Count -gt 0) {
                Write-Host $line -ForegroundColor Red
            }
            elseif ($replicationWarnings.Count -gt 0) {
                Write-Host $line -ForegroundColor DarkYellow
            }
            else {
                Write-Host $line -ForegroundColor Gray
            }
        }
        if ($replicationFailures.Count -eq 0 -and $replicationWarnings.Count -gt 0) {
            foreach ($w in $replicationWarnings) {
                Write-WarnMsg ('{0}: Get-ADReplicationFailure reports FailureCount=0 but LastError={1}. Treating as diagnostic/stale failure data because partner metadata reports no current inbound replication error.' -f $w.TargetDC,$w.LastError)
            }
        }
        elseif ($replicationFailures.Count -eq 0) {
            Write-Info 'Get-ADReplicationFailure returned only non-blocking rows with FailureCount=0 and LastError=0, or no rows.'
        }
    }

    if ($readFailures.Count -gt 0) {
        foreach ($f in $readFailures) { Write-ErrMsg $f }
        Stop-WithError 'Unable to validate AD replication health from structured AD cmdlets. --fix is blocked.' @(
            'Fix AD replication visibility/permissions first.',
            'Do not rely on localized repadmin output for this safety gate.'
        )
    }

    if ($metadataFailures.Count -gt 0 -or $replicationFailures.Count -gt 0) {
        if ($metadataFailures.Count -gt 0) {
            Write-Blank
            Write-Host 'Replication metadata failures:' -ForegroundColor Red
            $metadataFailures | Format-Table TargetDC,Partner,Partition,ConsecutiveFailures,LastResult,LastAttempt,LastSuccess -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Red }
        }
        if ($replicationFailures.Count -gt 0) {
            Write-Blank
            Write-Host 'Replication failure rows with active FailureCount > 0:' -ForegroundColor Red
            $replicationFailures | Format-Table TargetDC,Partner,Partition,FailureCount,LastError,FirstFailureTime -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Red }
        }
        Stop-WithError 'Structured AD replication checks report one or more current replication failures. --fix is blocked.' @(
            'Fix AD replication first.',
            'A multi-DC DFSR SYSVOL authoritative workflow depends on reliable AD replication of the DFSR Subscription attributes.'
        )
    }

    Write-Ok 'Structured AD replication checks report zero current inbound replication failures on every DC.'
}

function Test-BackupRoot {
    Write-Section 'Backup root check' Cyan
    $root = Get-BackupRoot
    $Script:Context['BackupRoot'] = $root
    Write-Info ('Backup root: {0}' -f $root)

    if (Test-Path -LiteralPath $root -PathType Leaf) { Stop-WithError ('Backup root points to a file: {0}' -f $root) }

    if ($Script:Mode -eq 'Check') {
        if (Test-Path -LiteralPath $root -PathType Container) {
            try {
                [void](Get-Acl -LiteralPath $root -ErrorAction Stop)
                Write-Ok 'Backup root exists and ACLs are readable.'
            }
            catch {
                Write-WarnMsg ('Backup root exists but ACLs could not be read: {0}' -f $_.Exception.Message)
            }
            Write-Info 'No write-probe file was created because --check is read-only apart from the transcript/log.'
        }
        else {
            Write-WarnMsg 'Backup root does not exist. In --fix mode it will be created if possible.'
            Write-Info 'No backup root directory was created because --check is read-only apart from the transcript/log.'
        }
        return
    }

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null
        Write-Ok 'Backup root created.'
    }

    $probe = Join-Path $root ('.write_test_{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
    try {
        Set-Content -LiteralPath $probe -Value 'test' -Encoding ASCII -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        Write-Ok 'Backup root is writable.'
    }
    catch {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        Stop-WithError ('Backup root is not writable: {0}. Error: {1}' -f $root,$_.Exception.Message)
    }
}

function Get-SysvolDomainInventory {
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [Parameter(Mandatory=$true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        Stop-WithError ("Inventory failed for {0}. Path does not exist: {1}" -f $Label,$Root)
    }

    $base = (Get-Item -LiteralPath $Root -ErrorAction Stop).FullName.TrimEnd('\')
    $items = New-Object System.Collections.Generic.List[string]
    $children = @(Get-ChildItem -LiteralPath $base -Force -Recurse -ErrorAction Stop)

    foreach ($item in $children) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $rel = $item.FullName.Substring($base.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($rel)) { continue }
        if ($rel -eq 'DfsrPrivate' -or $rel -like 'DfsrPrivate\*') { continue }

        if ($item.PSIsContainer) {
            $items.Add(('D|{0}' -f $rel.ToLowerInvariant())) | Out-Null
        }
        else {
            $items.Add(('F|{0}|{1}' -f $rel.ToLowerInvariant(),$item.Length)) | Out-Null
        }
    }

    return @($items | Sort-Object -Unique)
}

function Test-SysvolDomainBackupConsistency {
    param(
        [Parameter(Mandatory=$true)][string]$SourceDomain,
        [Parameter(Mandatory=$true)][string]$BackupDomain,
        [Parameter(Mandatory=$true)][string]$DcName
    )

    $requiredSourceFolders = @(
        (Join-Path $SourceDomain 'Policies'),
        (Join-Path $SourceDomain 'scripts')
    )
    foreach ($folder in $requiredSourceFolders) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            Stop-WithError ("{0}: source SYSVOL domain backup prerequisite failed. Missing folder: {1}" -f $DcName,$folder)
        }
    }

    $requiredBackupFolders = @(
        (Join-Path $BackupDomain 'Policies'),
        (Join-Path $BackupDomain 'scripts')
    )
    foreach ($folder in $requiredBackupFolders) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            Stop-WithError ("{0}: backup verification failed. Missing folder: {1}" -f $DcName,$folder) @('No DFSR/AD recovery changes have been made after this backup failure.')
        }
    }

    $sourceInventory = @(Get-SysvolDomainInventory -Root $SourceDomain -Label ("{0} source" -f $DcName))
    $backupInventory = @(Get-SysvolDomainInventory -Root $BackupDomain -Label ("{0} backup" -f $DcName))
    $diff = @(Compare-Object -ReferenceObject $sourceInventory -DifferenceObject $backupInventory)

    if ($diff.Count -gt 0) {
        Write-Blank
        Write-Host ("{0}: first backup inventory differences:" -f $DcName) -ForegroundColor Red
        $diff | Select-Object -First 30 | Format-Table InputObject,SideIndicator -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Red }
        Stop-WithError ("{0}: backup verification failed. Source and backup inventories do not match." -f $DcName) @(
            'No DFSR/AD recovery changes have been made after this backup failure.',
            'Review the backup destination, permissions, antivirus/file locks, and robocopy output, then rerun --fix.'
        )
    }

    $gptIni = @(Get-ChildItem -LiteralPath (Join-Path $BackupDomain 'Policies') -Filter 'gpt.ini' -Recurse -Force -ErrorAction SilentlyContinue)
    if ($gptIni.Count -lt 1) {
        Stop-WithError ("{0}: backup verification failed. No gpt.ini files were found in the backed up Policies tree." -f $DcName) @('No DFSR/AD recovery changes have been made after this backup failure.')
    }

    Write-Ok ("{0}: backup verified. Inventory items={1}; gpt.ini files={2}." -f $DcName,$backupInventory.Count,$gptIni.Count)
}

function Invoke-SysvolBackups {
    Write-Section 'SYSVOL domain backup on every DC' Cyan
    $root = Get-BackupRoot
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baseBackupRoot = Join-Path $root ('SYSVOL_MultiDC_Domain_Backup_{0}' -f $stamp)
    $backupRoot = $baseBackupRoot
    $suffix = 0
    while (Test-Path -LiteralPath $backupRoot) {
        $suffix++
        $backupRoot = ('{0}_{1}' -f $baseBackupRoot,$suffix)
    }

    New-Item -ItemType Directory -Path $backupRoot -ErrorAction Stop | Out-Null
    $Script:Context['BackupSetPath'] = $backupRoot
    Write-Info ('Backup set: {0}' -f $backupRoot)
    Write-Info 'Every DC backup source is the local path C:\Windows\SYSVOL\domain, accessed through the administrative share.'
    Write-Info 'Backup robocopy options: /E /XJ /R:1 /W:1 /COPY:DAT /DCOPY:DAT /XD DfsrPrivate /NP'
    Write-Info 'Backup uses /E, not /MIR, so the backup destination is not purged if a folder already exists.'

    $robocopy = Get-Command robocopy.exe -ErrorAction SilentlyContinue
    if (-not $robocopy) { Stop-WithError 'robocopy.exe was not found.' }

    foreach ($dc in $Script:Context['DCs']) {
        $hostName = [string]$dc.HostName
        $source = Get-SysvolDomainPathRemote -ComputerName $hostName
        $dest = Join-Path $backupRoot $dc.Name
        Write-SubSection ('Backup {0}' -f $hostName)
        Write-Info ('Source: {0}' -f $source)
        Write-Info ('Destination: {0}' -f $dest)

        if (-not (Test-Path -LiteralPath $source -PathType Container)) {
            Stop-WithError ('Cannot back up SYSVOL domain because source path is missing: {0}' -f $source)
        }

        New-Item -ItemType Directory -Path $dest -ErrorAction Stop | Out-Null
        & $robocopy.Source $source $dest /E /XJ /R:1 /W:1 /COPY:DAT /DCOPY:DAT /XD DfsrPrivate /NP
        $rc = $LASTEXITCODE
        Write-Info ('Robocopy exit code: {0}' -f $rc)
        if ($rc -gt 7) {
            Stop-WithError ('Robocopy backup failed for {0} with exit code {1}.' -f $hostName,$rc) @('No DFSR/AD recovery changes have been made after this backup failure.')
        }

        Test-SysvolDomainBackupConsistency -SourceDomain $source -BackupDomain $dest -DcName $hostName
        Add-Action ('Backed up and verified C:\Windows\SYSVOL\domain from {0} to {1}' -f $hostName,$dest)
    }
    Write-Ok 'SYSVOL domain backup completed and verified for every DC.'
}


function Get-DfsrWin32ServiceRemote {
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    return Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Filter "Name='DFSR'" -ErrorAction Stop
}

function Wait-DfsrServiceStateRemote {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][ValidateSet('Running','Stopped')][string]$DesiredState,
        [int]$TimeoutSeconds = 120
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $svc = Get-DfsrWin32ServiceRemote -ComputerName $ComputerName
        if ([string]$svc.State -eq $DesiredState) {
            Write-Ok ('{0}: DFSR service state is {1}.' -f $ComputerName,$DesiredState)
            return $true
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    $last = '<unavailable>'
    try { $last = [string](Get-DfsrWin32ServiceRemote -ComputerName $ComputerName).State } catch {}
    Stop-WithError ('{0}: DFSR service did not reach state {1} within {2}s. Last observed state: {3}' -f $ComputerName,$DesiredState,$TimeoutSeconds,$last)
}

function Set-DfsrStartupMode {
    param([string]$ComputerName, [ValidateSet('Manual','Automatic')][string]$Mode)
    Write-Info ('PowerShell/WMI: setting DFSR startup mode on {0} to {1}.' -f $ComputerName,$Mode)
    $svc = Get-DfsrWin32ServiceRemote -ComputerName $ComputerName
    $result = $svc.ChangeStartMode($Mode)
    $rc = [int]$result.ReturnValue
    Write-Info ('Win32_Service.ChangeStartMode return code on {0}: {1}' -f $ComputerName,$rc)
    if ($rc -ne 0) {
        Stop-WithError ('Failed to set DFSR startup mode on {0} to {1}. Win32_Service return code: {2}' -f $ComputerName,$Mode,$rc)
    }
    Write-Ok ('{0}: DFSR startup mode set to {1}.' -f $ComputerName,$Mode)
}

function Stop-DfsrServiceRemote {
    param([string]$ComputerName)
    Write-Info ('PowerShell/WMI: stopping DFSR on {0}.' -f $ComputerName)
    $svc = Get-DfsrWin32ServiceRemote -ComputerName $ComputerName
    if ([string]$svc.State -eq 'Stopped') {
        Write-Ok ('{0}: DFSR service is already stopped.' -f $ComputerName)
        return
    }
    $result = $svc.StopService()
    $rc = [int]$result.ReturnValue
    Write-Info ('Win32_Service.StopService return code on {0}: {1}' -f $ComputerName,$rc)
    if ($rc -notin @(0,10)) {
        Stop-WithError ('Failed to request DFSR stop on {0}. Win32_Service return code: {1}' -f $ComputerName,$rc)
    }
    [void](Wait-DfsrServiceStateRemote -ComputerName $ComputerName -DesiredState Stopped -TimeoutSeconds 120)
}

function Start-DfsrServiceRemote {
    param([string]$ComputerName)
    Write-Info ('PowerShell/WMI: starting DFSR on {0}.' -f $ComputerName)
    $svc = Get-DfsrWin32ServiceRemote -ComputerName $ComputerName
    if ([string]$svc.State -eq 'Running') {
        Write-Ok ('{0}: DFSR service is already running.' -f $ComputerName)
        return
    }
    $result = $svc.StartService()
    $rc = [int]$result.ReturnValue
    Write-Info ('Win32_Service.StartService return code on {0}: {1}' -f $ComputerName,$rc)
    if ($rc -notin @(0,10)) {
        Stop-WithError ('Failed to request DFSR start on {0}. Win32_Service return code: {1}' -f $ComputerName,$rc)
    }
    [void](Wait-DfsrServiceStateRemote -ComputerName $ComputerName -DesiredState Running -TimeoutSeconds 120)
}

function Invoke-RepadminSyncAll {
    Write-Section 'Force AD replication' Cyan
    $repadmin = Get-Command repadmin.exe -ErrorAction SilentlyContinue
    if (-not $repadmin) { Stop-WithError 'repadmin.exe was not found.' }

    $rc = Invoke-External -FilePath $repadmin.Source -Arguments @('/syncall','/AdeP','/Q') -AllowFailure
    $summary = Get-Win32ExitCodeSummary -Code $rc

    if ($rc -eq 0) {
        Write-Ok ('repadmin /syncall completed with exit code {0}.' -f $summary)
    }
    elseif ($rc -eq 234) {
        Write-WarnMsg ('repadmin /syncall returned {0}. This commonly maps to ERROR_MORE_DATA. The script will not treat this as the safety verdict; it will validate convergence with structured AD cmdlets.' -f $summary)
    }
    else {
        Write-WarnMsg ('repadmin /syncall returned non-zero exit code {0}. The script will validate the actual AD replication state with structured AD cmdlets before continuing.' -f $summary)
    }

    Start-Sleep -Seconds 5
    Test-ADReplicationHealth
    Add-Action 'Triggered AD replication with repadmin /syncall and validated convergence with structured AD cmdlets.'
}


function Invoke-DfsrPollAdRemote {
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    Write-Info ('Polling DFSR AD configuration on {0}.' -f $ComputerName)

    $attemptErrors = New-Object System.Collections.Generic.List[string]
    $shortName = Get-NetbiosFromFqdn $ComputerName
    $domainNb = $null
    if (Test-ContextKey 'DomainNetBIOS') { $domainNb = [string]$Script:Context['DomainNetBIOS'] }

    $localCandidates = @($env:COMPUTERNAME, ([System.Net.Dns]::GetHostName()))
    if (Test-ContextKey 'LocalDC') {
        $localCandidates += [string]$Script:Context['LocalDC'].HostName
        $localCandidates += [string]$Script:Context['LocalDC'].Name
    }
    $isLocal = $false
    foreach ($candidate in $localCandidates) {
        if ((Normalize-ComputerName $candidate) -eq (Normalize-ComputerName $ComputerName) -or
            (Normalize-ComputerName (Get-NetbiosFromFqdn $candidate)) -eq (Normalize-ComputerName $shortName)) {
            $isLocal = $true
        }
    }

    # Primary path for the local DC: exactly what an operator would type.
    if ($isLocal) {
        try {
            $dfsrdiag = Get-Command dfsrdiag.exe -ErrorAction Stop
            Write-Info ('Trying local dfsrdiag.exe pollad on {0}.' -f $ComputerName)
            $rc = Invoke-External -FilePath $dfsrdiag.Source -Arguments @('pollad') -AllowFailure
            $summary = Get-Win32ExitCodeSummary -Code $rc
            if ($rc -eq 0) {
                Write-Ok ('{0}: local dfsrdiag pollad completed. ExitCode={1}' -f $ComputerName,$summary)
                return $true
            }
            $attemptErrors.Add(('local dfsrdiag pollad returned {0}' -f $summary)) | Out-Null
        }
        catch {
            $attemptErrors.Add(('local dfsrdiag pollad failed: {0}' -f $_.Exception.Message)) | Out-Null
        }
    }

    # Primary path for remote DCs: execute dfsrdiag pollad on the target DC through PowerShell remoting.
    # This matches the reliable manual action: open an elevated shell on that DC and run dfsrdiag pollad.
    if (-not $isLocal) {
        try {
            Write-Info ('Trying remote PowerShell: Invoke-Command -ComputerName {0} { dfsrdiag.exe pollad }' -f $ComputerName)
            $remote = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $cmd = Get-Command dfsrdiag.exe -ErrorAction Stop
                & $cmd.Source pollad 2>&1 | ForEach-Object { [string]$_ }
                return $LASTEXITCODE
            } -ErrorAction Stop
            $remoteLines = @($remote)
            $rc = 0
            if ($remoteLines.Count -gt 0) {
                $last = $remoteLines[-1]
                if ($last -match '^-?\d+$') {
                    $rc = [int]$last
                    $remoteLines = @($remoteLines | Select-Object -First ([Math]::Max(0,$remoteLines.Count - 1)))
                }
            }
            foreach ($line in $remoteLines) { if ($line) { Write-Host $line } }
            $summary = Get-Win32ExitCodeSummary -Code $rc
            if ($rc -eq 0) {
                Write-Ok ('{0}: remote dfsrdiag pollad completed through PowerShell remoting. ExitCode={1}' -f $ComputerName,$summary)
                return $true
            }
            $attemptErrors.Add(('remote Invoke-Command dfsrdiag pollad returned {0}' -f $summary)) | Out-Null
        }
        catch {
            $attemptErrors.Add(('remote Invoke-Command dfsrdiag pollad failed: {0}' -f $_.Exception.Message)) | Out-Null
        }
    }

    # Fallback from the current host: dfsrdiag PollAD /Member:<domain\server>.
    # Do not parse localized output; only numeric exit code is used.
    try {
        $dfsrdiag = Get-Command dfsrdiag.exe -ErrorAction Stop
        $memberValues = New-Object System.Collections.Generic.List[string]
        if ($domainNb) { $memberValues.Add(('{0}\{1}' -f $domainNb,$shortName)) | Out-Null }
        $memberValues.Add($shortName) | Out-Null
        $memberValues.Add($ComputerName) | Out-Null
        $memberValues = @($memberValues | Select-Object -Unique)

        foreach ($member in $memberValues) {
            Write-Info ('Trying dfsrdiag.exe PollAD /Member:{0} from the current host.' -f $member)
            $rc = Invoke-External -FilePath $dfsrdiag.Source -Arguments @('PollAD',('/Member:{0}' -f $member)) -AllowFailure
            $summary = Get-Win32ExitCodeSummary -Code $rc
            if ($rc -eq 0) {
                Write-Ok ('{0}: dfsrdiag PollAD completed through /Member:{1}. ExitCode={2}' -f $ComputerName,$member,$summary)
                return $true
            }
            $attemptErrors.Add(('dfsrdiag PollAD /Member:{0} returned {1}' -f $member,$summary)) | Out-Null
        }
    }
    catch {
        $attemptErrors.Add(('dfsrdiag PollAD /Member fallback failed: {0}' -f $_.Exception.Message)) | Out-Null
    }

    Write-WarnMsg ('DFSR AD polling could not be confirmed programmatically on {0}.' -f $ComputerName)
    foreach ($attemptError in $attemptErrors) { Write-WarnMsg ('  {0}' -f $attemptError) }
    Write-WarnMsg ('Manual fallback on {0}: run dfsrdiag pollad from an elevated prompt on that DC.' -f $ComputerName)
    return $false
}

function Wait-EventRemote {
    param(
        [string]$ComputerName,
        [int[]]$Ids,
        [int]$TimeoutSeconds = 120,
        [string]$Description = 'event'
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $events = @(Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{ LogName='DFS Replication'; Id=$Ids; StartTime=$Script:RunStart } -MaxEvents 5 -ErrorAction Stop)
            if ($events.Count -gt 0) {
                Write-Ok ('{0}: detected {1} ({2}).' -f $ComputerName,$Description,($events[0].Id))
                return $true
            }
        }
        catch {
            Write-WarnMsg ('{0}: unable to query DFS Replication event log: {1}' -f $ComputerName,$_.Exception.Message)
            return $false
        }
        Start-Sleep -Seconds 5
    }
    Write-WarnMsg ('{0}: timed out waiting for {1}.' -f $ComputerName,$Description)
    return $false
}

function Wait-AllDfsrNormal {
    param(
        [int]$TimeoutSeconds = 300,
        [int]$CheckIntervalSeconds = 15,
        [int]$PollRetryAfterSeconds = 60,
        [int]$AuthoritativeNormalExtensionSeconds = 300
    )

    Write-Section 'Wait for DFSR SYSVOL State 4 / Normal on every DC' Cyan

    $authHost = [string]$Script:Context['LocalDC'].HostName
    $startTime = Get-Date
    $deadline = $startTime.AddSeconds($TimeoutSeconds)
    $pollRetried = $false
    $extendedAfterAuthoritativeNormal = $false
    $phase = 'initial'
    $lastRows = @()

    Write-Info ('Timeout: {0}s. Check interval: {1}s. PollAD retry after: {2}s. One-time extension after authoritative DC State 4: {3}s.' -f $TimeoutSeconds,$CheckIntervalSeconds,$PollRetryAfterSeconds,$AuthoritativeNormalExtensionSeconds)

    do {
        $now = Get-Date
        $elapsed = [int][Math]::Floor(($now - $startTime).TotalSeconds)
        $remaining = [int][Math]::Max(0,[Math]::Ceiling(($deadline - $now).TotalSeconds))

        Write-Blank
        Write-Host ('[WAIT] Phase: {0}' -f $phase) -ForegroundColor Gray
        Write-Host ('[WAIT] Elapsed: {0}s' -f $elapsed) -ForegroundColor Gray
        Write-Host ('[WAIT] Remaining: {0}s' -f $remaining) -ForegroundColor Gray
        Write-Host ('[WAIT] Next check in: {0}s' -f $CheckIntervalSeconds) -ForegroundColor Gray

        $rows = @()
        $allOk = $true
        $authoritativeNormal = $false

        foreach ($dc in $Script:Context['DCs']) {
            $hostName = [string]$dc.HostName
            $info = Get-DfsrSysvolInfoRemote -ComputerName $hostName
            $state = $null
            $err = $null
            $msg = $null
            if ($info) {
                $state = [int]$info.State
                $err = [int]$info.LastErrorCode
                $msg = [int]$info.LastErrorMessageId
            }

            if ($state -ne 4) { $allOk = $false }
            if ((Test-DcNameEqual $hostName $authHost) -and $state -eq 4) { $authoritativeNormal = $true }

            $role = 'Non-authoritative'
            if (Test-DcNameEqual $hostName $authHost) { $role = 'Authoritative' }
            $rows += [pscustomobject]@{
                DC = $hostName
                Role = $role
                State = (Convert-DfsrState $state)
                LastErrorCode = $err
                LastErrorMessageId = $msg
            }
        }

        $lastRows = $rows
        $Script:Context['DfsrStateRows'] = @($rows | ForEach-Object { [pscustomobject]@{ DC=$_.DC; State=$_.State; LastErrorCode=$_.LastErrorCode; LastErrorMessageId=$_.LastErrorMessageId } })
        $rows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }

        if ($allOk) {
            Write-Ok 'Every DC reports DFSR SYSVOL State 4 / Normal.'
            Add-Action 'Validated DFSR SYSVOL State 4 / Normal on every DC.'
            return $true
        }

        if (-not $pollRetried -and $elapsed -ge $PollRetryAfterSeconds) {
            Write-Info ('{0} seconds elapsed and DFSR SYSVOL is not State 4 / Normal on every DC.' -f $elapsed)
            Write-Info 'Running dfsrdiag pollad on every involved DC.'
            foreach ($dc in $Script:Context['DCs']) {
                [void](Invoke-DfsrPollAdRemote -ComputerName ([string]$dc.HostName))
            }
            $pollRetried = $true
        }

        if ($authoritativeNormal -and -not $allOk -and -not $extendedAfterAuthoritativeNormal) {
            $deadline = (Get-Date).AddSeconds($AuthoritativeNormalExtensionSeconds)
            $extendedAfterAuthoritativeNormal = $true
            $phase = 'authoritative-normal-extension'
            Write-Ok ('Authoritative DC {0} reached State 4 / Normal.' -f $authHost)
            Write-Info ('Extending wait once by {0} seconds for non-authoritative DCs to complete initial sync.' -f $AuthoritativeNormalExtensionSeconds)
            Write-Info 'If non-authoritative DCs remain stuck after this extension, reboot only the affected non-authoritative DCs and run dfsrdiag pollad again.'
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
    } while ((Get-Date) -lt $deadline)

    $nonNormalRows = @(Get-NonNormalDfsrStateRows -Rows $lastRows)
    $authRow = Get-DfsrStateRowForDc -Rows $lastRows -ComputerName $authHost
    $authNormalAtTimeout = ($null -ne $authRow -and (Test-DfsrStateTextNormal $authRow.State))
    $stuckNonAuthRows = @(Get-NonAuthoritativeNonNormalRows -Rows $lastRows -AuthoritativeComputerName $authHost)

    if ($authNormalAtTimeout -and $stuckNonAuthRows.Count -gt 0) {
        $stuckNames = @($stuckNonAuthRows | ForEach-Object { [string]$_.DC })
        $Script:Context['WaitPartialRecovery'] = $true
        $Script:Context['WaitStuckNonAuthoritativeDcs'] = $stuckNames
        Stop-WithError ('Authoritative DC reached State 4 / Normal, but one or more non-authoritative DCs did not finish initial sync before timeout: {0}.' -f ($stuckNames -join ', ')) @(
            'Do not rerun the multi-DC authoritative recovery while the authoritative DC is already State 4 / Normal.',
            ('On the affected DC(s) only ({0}), run: dfsrdiag pollad' -f ($stuckNames -join ', ')),
            "If a DC remains State 2, restart only that DC's DFSR service and run dfsrdiag pollad again.",
            'If it is still stuck in State 2, reboot only the affected non-authoritative DC and run dfsrdiag pollad after startup.',
            'Then validate State 4 / Normal, SYSVOL and NETLOGON shares, and DFSR backlog.'
        )
    }

    Stop-WithError 'Not all DCs reached DFSR SYSVOL State 4 / Normal before timeout.' @(
        ('Final non-normal DFSR states: {0}' -f (Format-DcStateList $nonNormalRows)),
        'Review DFS Replication event logs on the DCs that are not State 4.',
        'If a DC still returns No data, run dfsrdiag pollad directly on that DC and verify that the DFSR service is running.',
        'Check Event IDs 4114, 4602, 4614, 4604, 5002, 5008, 4012, and 2213.'
    )
}

function Test-FinalSharesAndDcdiag {
    Write-Section 'Final SYSVOL/NETLOGON and dcdiag checks' Cyan
    foreach ($dc in $Script:Context['DCs']) {
        $hostName = [string]$dc.HostName
        Write-SubSection $hostName
        $netView = & net.exe view ('\\{0}' -f $hostName) 2>&1
        $netView | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
        $hasSysvol = ($netView -match '\bSYSVOL\b')
        $hasNetlogon = ($netView -match '\bNETLOGON\b')
        if (-not $hasSysvol -or -not $hasNetlogon) {
            Stop-WithError ('{0}: SYSVOL and/or NETLOGON share is missing.' -f $hostName)
        }
        Write-Ok 'SYSVOL and NETLOGON are visible via net view.'

        $dcdiag = Get-Command dcdiag.exe -ErrorAction SilentlyContinue
        if ($dcdiag) {
            $rc = Invoke-External -FilePath $dcdiag.Source -Arguments @('/s:{0}' -f $hostName, '/test:sysvolcheck', '/test:advertising') -AllowFailure
            if ($rc -ne 0) { Stop-WithError ('dcdiag reported a failure for {0}.' -f $hostName) }
            Write-Ok 'dcdiag sysvolcheck/advertising passed.'
        }
        else {
            Write-WarnMsg 'dcdiag.exe was not found. Skipping dcdiag validation.'
        }
    }
    Add-Action 'Validated SYSVOL/NETLOGON shares and dcdiag checks.'
}


function Show-CheckNextActions {
    Write-Section 'Suggested next actions after --check' Cyan

    $scriptName = Get-ScriptDisplayName
    $auth = [string]$Script:Context['LocalDC'].HostName
    $authShort = [string]$Script:Context['LocalDC'].Name
    $backupRoot = [string]$Script:Context['BackupRoot']
    if ([string]::IsNullOrWhiteSpace($backupRoot)) { $backupRoot = Get-BackupRoot }
    $nonAuth = @($Script:Context['DCs'] | Where-Object { -not (Test-DcNameEqual ([string]$_.HostName) $auth) } | ForEach-Object { [string]$_.HostName })
    $stateRows = @($Script:Context['DfsrStateRows'])
    $states = @($stateRows | ForEach-Object { [string]$_.State })
    $allNormal = ($stateRows.Count -gt 0 -and @(Get-NonNormalDfsrStateRows -Rows $stateRows).Count -eq 0)
    $allInitial = ($stateRows.Count -gt 0 -and @($stateRows | Where-Object { -not (Test-DfsrStateTextInitial $_.State) }).Count -eq 0)
    $authRow = Get-DfsrStateRowForDc -Rows $stateRows -ComputerName $auth
    $authNormal = ($null -ne $authRow -and (Test-DfsrStateTextNormal $authRow.State))
    $nonAuthNonNormalRows = @(Get-NonAuthoritativeNonNormalRows -Rows $stateRows -AuthoritativeComputerName $auth)
    $comparisonRan = [bool]$Script:Context['RobocopyPreviewRan']
    $comparisonHadDifferences = [bool]$Script:Context['RobocopyPreviewHadDifferences']

    Write-Host 'Current assessment:' -ForegroundColor White
    if ($allInitial) {
        Write-Host ('  - Safety gates: PASSED. --fix is eligible from this DC, subject to your final SYSVOL source-of-truth confirmation.') -ForegroundColor Green
    }
    elseif ($allNormal) {
        Write-Host '  - Safety gates: PASSED. Every DC is already State 4 / Normal.' -ForegroundColor Green
    }
    elseif ($authNormal -and $nonAuthNonNormalRows.Count -gt 0) {
        Write-Host '  - Safety gates: PASSED. The authoritative DC is already State 4 / Normal; do not rerun global authoritative recovery for this state.' -ForegroundColor DarkYellow
    }
    else {
        Write-Host '  - Safety gates: PASSED, but the DFSR SYSVOL state is mixed. Review before choosing a recovery action.' -ForegroundColor DarkYellow
    }
    Write-Host ('  - Intended authoritative source: {0}' -f $auth) -ForegroundColor Gray
    if ($nonAuth.Count -gt 0) {
        Write-Host ('  - DCs that --fix will make non-authoritative: {0}' -f ($nonAuth -join ', ')) -ForegroundColor Gray
    }
    if ($states.Count -gt 0) {
        Write-Host ('  - Current DFSR SYSVOL states: {0}' -f (($stateRows | ForEach-Object { '{0}={1}' -f $_.DC,$_.State }) -join '; ')) -ForegroundColor Gray
    }
    if ($allInitial) {
        Write-Host '  - Decision: ELIGIBLE_FOR_AUTHORITATIVE_RECOVERY_AFTER_SOURCE_CONFIRMATION' -ForegroundColor DarkYellow
    }
    elseif ($allNormal) {
        Write-Host '  - Decision: NO_AUTHORITATIVE_RECOVERY_NEEDED_BY_DFSR_STATE' -ForegroundColor Green
    }
    elseif ($authNormal -and $nonAuthNonNormalRows.Count -gt 0) {
        Write-Host '  - Decision: TARGET_NON_AUTHORITATIVE_DC_RECOVERY_OR_REBOOT' -ForegroundColor DarkYellow
    }
    else {
        Write-Host '  - Decision: REVIEW_MIXED_OR_NON_NORMAL_DFSR_STATE_BEFORE_FIX' -ForegroundColor DarkYellow
    }
    if ($comparisonRan -and -not $comparisonHadDifferences) {
        Write-Host '  - Robocopy preview reported no SYSVOL payload differences from the authoritative DC to the other DCs.' -ForegroundColor Gray
    }
    elseif ($comparisonRan -and $comparisonHadDifferences) {
        Write-Host '  - Robocopy preview reported SYSVOL payload differences. Review carefully before using --fix because the local DC will still be the source of truth.' -ForegroundColor DarkYellow
    }

    Write-Blank
    Write-Host 'Backup plan used by --fix:' -ForegroundColor White
    $backupRows = @()
    foreach ($dc in $Script:Context['DCs']) {
        $source = '<unresolved>'
        try { $source = Get-SysvolDomainPathRemote -ComputerName ([string]$dc.HostName) } catch { $source = ('<unresolved: {0}>' -f $_.Exception.Message) }
        $backupRows += [pscustomobject]@{
            DC = [string]$dc.HostName
            Source = $source
            BackupSubfolder = (Join-Path '<timestamped-backup-set>' $dc.Name)
        }
    }
    $backupRows | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Gray }
    Write-Host ('  - Backup root for --fix: {0}' -f $backupRoot) -ForegroundColor Gray
    Write-Host '  - --fix backs up and verifies C:\Windows\SYSVOL\domain from every DC before any DFSR/AD recovery change.' -ForegroundColor Gray

    Write-Blank
    Write-Host 'Notes:' -ForegroundColor White
    if ($allNormal) {
        Write-Host '  - Every DC is already State 4 / Normal. Do not run --fix unless SYSVOL is still broken for another confirmed reason.' -ForegroundColor Green
        Write-Host ('  - Re-check later with: .\{0} --check' -f $scriptName) -ForegroundColor Gray
        return
    }

    if ($allInitial) {
        Write-Host '  - Every DC is State 2 / Initial Sync and every safety gate passed.' -ForegroundColor DarkYellow
        Write-Host '  - This matches the stuck-all-DCs multi-DC authoritative recovery scenario.' -ForegroundColor DarkYellow
        Write-Host ('  - Recommended next recovery step: run --fix from {0}, after confirming its SYSVOL content is the source of truth.' -f $auth) -ForegroundColor DarkYellow
        Write-Host ('  - {0} will be the only authoritative DC; every other DC will be made non-authoritative.' -f $auth) -ForegroundColor DarkYellow
        Write-Host '  - Wait only if this is a fresh/temporary initial sync and you have objective evidence that DFSR is actively progressing toward State 4.' -ForegroundColor Gray
    }
    elseif ($authNormal -and $nonAuthNonNormalRows.Count -gt 0) {
        Write-Host ('  - {0} is already State 4 / Normal.' -f $auth) -ForegroundColor Green
        Write-Host ('  - These non-authoritative DCs are still not State 4 / Normal: {0}.' -f (Format-DcStateList $nonAuthNonNormalRows)) -ForegroundColor DarkYellow
        Write-Host '  - Do not rerun multi-DC authoritative recovery. Work only on the non-authoritative DCs that remain stuck.' -ForegroundColor DarkYellow
    }
    else {
        Write-Host '  - At least one DC is not State 4 / Normal. Review DFSR states and event logs before using any recovery action.' -ForegroundColor DarkYellow
    }

    Write-Blank
    Write-Host 'Suggested actions:' -ForegroundColor White
    if ($allNormal) {
        Write-Host '  - No direct recovery action required.' -ForegroundColor Green
    }
    elseif ($allInitial) {
        Write-Host ('  - Run the recovery only from {0}: .\{1} --fix --backup-path "{2}"' -f $authShort,$scriptName,$backupRoot) -ForegroundColor DarkYellow
    }
    elseif ($authNormal -and $nonAuthNonNormalRows.Count -gt 0) {
        $stuck = ((@($nonAuthNonNormalRows) | ForEach-Object { [string]$_.DC }) -join ', ')
        Write-Host ('  - On {0}: run dfsrdiag pollad; if it remains State 2, restart DFSR; if still stuck, reboot only the affected DC and run dfsrdiag pollad again.' -f $stuck) -ForegroundColor DarkYellow
    }
    else {
        Write-Host '  - Review the DFSR states and event logs first. Do not run --fix unless all DCs are stuck and the local SYSVOL is confirmed as the source of truth.' -ForegroundColor DarkYellow
    }

    Write-Blank
    Write-Host 'What --fix will do:' -ForegroundColor White
    Write-Host '  - Create a timestamped backup set and back up C:\Windows\SYSVOL\domain from every DC involved.' -ForegroundColor Gray
    Write-Host '  - Verify each backup inventory before changing DFSR services or AD DFSR Subscription attributes.' -ForegroundColor Gray
    Write-Host ('  - Stop DFSR on every DC, then set only {0} as authoritative by using msDFSR-Options=1.' -f $auth) -ForegroundColor Gray
    if ($nonAuth.Count -gt 0) {
        Write-Host ('  - Set {0} as non-authoritative and force them to resync from the authoritative DFSR source.' -f ($nonAuth -join ', ')) -ForegroundColor Gray
    }
    Write-Host '  - Force AD replication, poll DFSR AD configuration, restore DFSR startup mode, then wait until every DC reports State 4 / Normal.' -ForegroundColor Gray
    Write-Host ('  - Require interactive confirmation: you must type {0} before backup/recovery actions run.' -f $authShort) -ForegroundColor Gray
    Write-Host '  - Post-fix validation is expected to confirm State 4 / Normal and SYSVOL/NETLOGON on every DC.' -ForegroundColor Gray

    Write-Blank
    Write-Host 'Safety note:' -ForegroundColor White
    Write-Host '  - Do not run --fix from another DC unless you intentionally want that other DC to become the authoritative SYSVOL source.' -ForegroundColor Gray
    Write-Host '  - --check does not modify SYSVOL, DFSR registry values, AD DFSR Subscription attributes, DFSR service state, or backup folders. It only writes the transcript/log file.' -ForegroundColor Gray
}

function Invoke-Preflight {
    Initialize-TopologyContext
    Test-FsmoOwnership
    Test-SitesAndServicesObjects
    Test-DcReachability
    Test-ADReplicationHealth
    Test-DfsrStatesAndSubscriptions
    Test-LocalSourcePayload
    Test-SysvolComparisonPreview
    Test-ParentComputerRegistry
    Test-BackupRoot
    Write-Section 'Preflight result' Green
    Write-Ok 'All safety gates passed.'
    if ($Script:Mode -eq 'Check') {
        Write-Info 'No changes were made. Use --fix only after reviewing this output and confirming the local SYSVOL is the desired source of truth.'
        Show-CheckNextActions
    }
}

function Confirm-FixIntent {
    Write-Section 'Explicit confirmation required' Red
    $auth = [string]$Script:Context['LocalDC'].HostName
    Write-Host ('You are about to make this DC authoritative for DFSR SYSVOL: {0}' -f $auth) -ForegroundColor White
    Write-Host 'Every other DC in the domain will be made non-authoritative and will resync SYSVOL from this source.' -ForegroundColor Yellow
    Write-Host 'This operation stops/starts DFSR on every DC and changes DFSR SYSVOL Subscription attributes in AD.' -ForegroundColor Yellow
    Write-Blank
    $answer = Read-Host ('Type the exact local DC name to continue [{0}]' -f $Script:Context['LocalDC'].Name)
    if ((Normalize-ComputerName $answer) -ne (Normalize-ComputerName $Script:Context['LocalDC'].Name)) {
        Stop-WithError 'Confirmation did not match the local DC name. No changes were made.'
    }
    Write-Ok 'Confirmation accepted.'
}

function Invoke-Fix {
    Invoke-Preflight
    Confirm-FixIntent
    Invoke-SysvolBackups

    $dcs = $Script:Context['DCs']
    $authDc = $Script:Context['LocalDC']
    $nonAuthDcs = @($dcs | Where-Object { $_.HostName -ne $authDc.HostName })

    Write-Section 'Step 1 - Stop DFSR on every DC and set startup to Manual' Cyan
    foreach ($dc in $dcs) {
        Set-DfsrStartupMode -ComputerName ([string]$dc.HostName) -Mode Manual
        Stop-DfsrServiceRemote -ComputerName ([string]$dc.HostName)
        Add-Action ('Stopped DFSR and set startup Manual on {0}' -f $dc.HostName)
    }

    Write-Section 'Step 2 - Disable SYSVOL subscriptions and set authoritative flag only on local DC' Cyan
    foreach ($dc in $dcs) {
        $subDn = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,{0}' -f $dc.ComputerObjectDN
        if ($dc.HostName -eq $authDc.HostName) {
            Set-ADObject -Identity $subDn -Replace @{ 'msDFSR-Enabled' = $false; 'msDFSR-Options' = 1 } -ErrorAction Stop
            Write-Ok ('{0}: set msDFSR-Enabled=FALSE; msDFSR-Options=1' -f $dc.HostName)
        }
        else {
            Set-ADObject -Identity $subDn -Replace @{ 'msDFSR-Enabled' = $false; 'msDFSR-Options' = 0 } -ErrorAction Stop
            Write-Ok ('{0}: set msDFSR-Enabled=FALSE; msDFSR-Options=0' -f $dc.HostName)
        }
    }
    Add-Action 'Disabled all SYSVOL subscriptions and left exactly one authoritative DFSR flag.'
    Invoke-RepadminSyncAll

    Write-Section 'Step 3 - Start and re-enable authoritative DC first' Cyan
    Start-DfsrServiceRemote -ComputerName ([string]$authDc.HostName)
    [void](Wait-EventRemote -ComputerName ([string]$authDc.HostName) -Ids @(4114) -TimeoutSeconds 120 -Description 'Event ID 4114 after disabled membership')

    $authSubDn = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,{0}' -f $authDc.ComputerObjectDN
    Set-ADObject -Identity $authSubDn -Replace @{ 'msDFSR-Enabled' = $true; 'msDFSR-Options' = 1 } -ErrorAction Stop
    Write-Ok ('{0}: set msDFSR-Enabled=TRUE; msDFSR-Options=1' -f $authDc.HostName)
    Invoke-RepadminSyncAll
    [void](Invoke-DfsrPollAdRemote -ComputerName ([string]$authDc.HostName))
    [void](Wait-EventRemote -ComputerName ([string]$authDc.HostName) -Ids @(4602) -TimeoutSeconds 180 -Description 'Event ID 4602 authoritative initialization')
    Add-Action ('Authoritative DC re-enabled: {0}' -f $authDc.HostName)

    Write-Section 'Step 4 - Start and re-enable every non-authoritative DC' Cyan
    foreach ($dc in $nonAuthDcs) {
        Start-DfsrServiceRemote -ComputerName ([string]$dc.HostName)
    }
    Start-Sleep -Seconds 5

    foreach ($dc in $nonAuthDcs) {
        [void](Wait-EventRemote -ComputerName ([string]$dc.HostName) -Ids @(4114) -TimeoutSeconds 120 -Description 'Event ID 4114 after disabled membership')
        $subDn = 'CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,{0}' -f $dc.ComputerObjectDN
        Set-ADObject -Identity $subDn -Replace @{ 'msDFSR-Enabled' = $true; 'msDFSR-Options' = 0 } -ErrorAction Stop
        Write-Ok ('{0}: set msDFSR-Enabled=TRUE; msDFSR-Options=0' -f $dc.HostName)
    }
    Invoke-RepadminSyncAll

    foreach ($dc in $nonAuthDcs) {
        [void](Invoke-DfsrPollAdRemote -ComputerName ([string]$dc.HostName))
        [void](Wait-EventRemote -ComputerName ([string]$dc.HostName) -Ids @(4614,4604) -TimeoutSeconds 240 -Description 'Event ID 4614/4604 non-authoritative initialization')
        Add-Action ('Non-authoritative DC re-enabled: {0}' -f $dc.HostName)
    }

    Write-Section 'Step 5 - Restore DFSR startup type to Automatic' Cyan
    foreach ($dc in $dcs) {
        Set-DfsrStartupMode -ComputerName ([string]$dc.HostName) -Mode Automatic
        Add-Action ('Restored DFSR startup Automatic on {0}' -f $dc.HostName)
    }

    Write-Section 'Step 6 - Final DFSR AD poll on every DC before convergence wait' Cyan
    foreach ($dc in $dcs) {
        [void](Invoke-DfsrPollAdRemote -ComputerName ([string]$dc.HostName))
    }

    Wait-AllDfsrNormal -TimeoutSeconds 300 -CheckIntervalSeconds 15 -PollRetryAfterSeconds 60 -AuthoritativeNormalExtensionSeconds 300
    Test-FinalSharesAndDcdiag
    Show-Summary -Result 'SUCCESS'
    Stop-TranscriptSafe
    exit 0
}

Parse-Arguments -RawArgs $args
Start-TranscriptSafe

try {
    if ($Script:Mode -eq 'Check') {
        Invoke-Preflight
        Show-Summary -Result 'CHECK PASSED'
        Stop-TranscriptSafe
        exit 0
    }
    elseif ($Script:Mode -eq 'Fix') {
        Invoke-Fix
    }
    else {
        Show-Help
        Stop-WithError 'Internal error: no valid mode selected.'
    }
}
catch {
    Stop-WithError ('Unhandled error: {0}' -f $_.Exception.Message) @('Review the log and rerun --check after correcting the blocker.')
}
