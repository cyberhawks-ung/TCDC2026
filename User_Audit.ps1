# ============================================================================
# CCDC User Audit & Password Reset - v3 (Hardened Edition)
# ============================================================================
#
# Run from a Domain Controller as Domain Admin for full domain + remote-server
# coverage, OR run with -Local on any single Windows box to handle only that
# machine's local accounts (no AD module, no WinRM required).
#
# RECOMMENDED LAUNCH (bypasses profile scripts where hijacks are persisted):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\User_Audit.ps1
#
# ============================================================================

#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enforce authorized users/groups and reset passwords, with verification and
    protection against a tampered PowerShell environment.

.DESCRIPTION
    PHASE 0  ENVIRONMENT SANITIZATION (runs before anything else)
             Last competition the Red Team aliased the password-reset cmdlet to
             a no-op, so the "reset" silently did nothing. This phase:
               - Nulls PreCommandLookupAction / PostCommandLookupAction /
                 CommandNotFoundAction hooks
               - Clears $PSDefaultParameterValues (e.g. ':WhatIf'=$true traps)
               - Removes EVERY alias or function that shadows a real command
               - Quarantines PowerShell profile scripts (where aliases persist)
               - Resets PSModulePath and imports ActiveDirectory /
                 LocalAccounts from the System32 path only
               - Removes Image-File-Execution-Options "Debugger" hijacks and
                 cmd.exe AutoRun hijacks for net.exe/powershell.exe/etc.
               - Resolves every critical cmdlet to a verified CommandInfo
                 object; all mutating calls go through these objects (& $Cmd.X)
                 so an alias/function can never intercept them again.
               - Verifies language mode, native binary paths & signatures

    PHASE 1  Domain group membership enforcement (privileged groups)
    PHASE 2  Domain password resets / disables, each reset VERIFIED and with
             a 3-step fallback chain (AD module -> LDAP ADSI -> net.exe)
    PHASE 3  AD hygiene: PasswordNotRequired, DoesNotRequirePreAuth,
             reversible encryption, SIDHistory, PrimaryGroupID, delegation,
             SPNs on users, recently created accounts (fix or report)
    PHASE 4  Remote servers (one WinRM round trip per server): local group
             enforcement + local user resets/disables with the same
             verification/fallback logic, plus profile/IFEO sanitization.

    All output is terminal-only unless -ExportPasswords is given.

.PARAMETER ConfigFile        Path to user_config.txt (default .\user_config.txt)
.PARAMETER PasswordLength    12-32, default 16
.PARAMETER Local             Only process THIS machine's local users/groups.
.PARAMETER TargetServers     Limit Phase 4 to these hosts (name or FQDN).
.PARAMETER SkipGroupAudit    Skip group enforcement (Phase 1 / part of 4)
.PARAMETER SkipPasswordReset Skip resets/disables (Phase 2 / part of 4)
.PARAMETER SkipRemoteServers Skip Phase 4 entirely
.PARAMETER SkipHygiene       Skip Phase 3
.PARAMETER BootstrapWinRM    For domain hosts that do not answer WinRM, use CIM/
                             WMI over DCOM (the DC's own Kerberos context) to run
                             Enable-PSRemoting + open the firewall, then retry.
                             Lets the sweep reach workstations that have remoting
                             turned off. Off by default (it changes remote config).
.PARAMETER KeepProfiles      Report profile scripts but do not quarantine them
.PARAMETER ResetKrbtgt       Reset the krbtgt password ONCE (invalidates
                             golden tickets; safe once, do NOT run twice within
                             10 hours or valid Kerberos tickets break).
.PARAMETER ExportPasswords   Optional CSV path to write passwords to. Default is
                             terminal only. Protect/delete the file afterwards.
.PARAMETER DryRun            Show what would change without changing anything.

.NOTES
    Passwords use A-Z a-z 0-9 and the shell-safe subset  )(.,@=:-!  of the
    competition-allowed specials, and always start with a letter (so they can
    never be mis-parsed as a /switch by net.exe).
#>

[CmdletBinding()]
param(
    [string]$ConfigFile = ".\user_config.txt",
    [ValidateRange(12, 32)][int]$PasswordLength = 16,
    [switch]$Local,
    [string[]]$TargetServers,
    [switch]$SkipGroupAudit,
    [switch]$SkipPasswordReset,
    [switch]$SkipRemoteServers,
    [switch]$SkipHygiene,
    [switch]$BootstrapWinRM,
    [switch]$KeepProfiles,
    [switch]$ResetKrbtgt,
    [string]$ExportPasswords,
    [switch]$DryRun
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# ============================================================================
# PHASE 0 - ENVIRONMENT SANITIZATION
# ============================================================================
# NOTE: Until this phase finishes we deliberately use only Microsoft.PowerShell
# module-qualified names and .NET calls, because even Write-Host may be hijacked.

$script:SanitizeFindings = [System.Collections.ArrayList]::new()
function _note([string]$m, [string]$lvl = 'INFO') {
    [void]$script:SanitizeFindings.Add([PSCustomObject]@{ Level = $lvl; Message = $m })
    $c = switch ($lvl) { 'FIX' { 'Magenta' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } 'OK' { 'Green' } default { 'Gray' } }
    Microsoft.PowerShell.Utility\Write-Host ("  [{0,-4}] {1}" -f $lvl, $m) -ForegroundColor $c
}

[Console]::ForegroundColor = 'Cyan'
[Console]::WriteLine("")
[Console]::WriteLine(("=" * 80))
[Console]::WriteLine("  PHASE 0: POWERSHELL ENVIRONMENT SANITIZATION")
[Console]::WriteLine(("=" * 80))
[Console]::ResetColor()

# --- 0.1 Command lookup hooks ------------------------------------------------
$ic = $ExecutionContext.SessionState.InvokeCommand
foreach ($hook in 'PreCommandLookupAction', 'PostCommandLookupAction', 'CommandNotFoundAction') {
    if ($null -ne $ic.$hook) {
        _note "Command lookup hook '$hook' was SET - cleared" 'FIX'
        $ic.$hook = $null
    }
}
_note "Command lookup hooks clean" 'OK'

# --- 0.2 Default parameter traps ---------------------------------------------
if ($PSDefaultParameterValues -and $PSDefaultParameterValues.Count -gt 0) {
    _note ("PSDefaultParameterValues had {0} entries: {1} - cleared" -f $PSDefaultParameterValues.Count, (($PSDefaultParameterValues.Keys) -join ', ')) 'FIX'
    $PSDefaultParameterValues.Clear()
}
$global:PSDefaultParameterValues = @{}

# --- 0.3 Language mode --------------------------------------------------------
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    _note "Language mode is $($ExecutionContext.SessionState.LanguageMode) - script requires FullLanguage. Check __PSLockdownPolicy env var / WDAC." 'FAIL'
    exit 2
}

# --- 0.4 PSModulePath reset (module hijack) ----------------------------------
$defaultModulePath = @(
    (Microsoft.PowerShell.Management\Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'),
    (Microsoft.PowerShell.Management\Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'),
    (Microsoft.PowerShell.Management\Join-Path $PSHOME 'Modules')
)
$currentPaths = $env:PSModulePath -split ';' | Microsoft.PowerShell.Core\Where-Object { $_ }
$foreignPaths = $currentPaths | Microsoft.PowerShell.Core\Where-Object { $p = $_.TrimEnd('\'); -not ($defaultModulePath | Microsoft.PowerShell.Core\Where-Object { $_.TrimEnd('\') -ieq $p }) }
if ($foreignPaths) {
    _note "Non-default PSModulePath entries: $($foreignPaths -join '; ')" 'WARN'
}
# Session-only reset; system paths first so System32 modules always win
$env:PSModulePath = ($defaultModulePath[2], $defaultModulePath[1], $defaultModulePath[0]) -join ';'
_note "PSModulePath reset for this session (System32 first)" 'OK'

# --- 0.5 Critical command list -----------------------------------------------
$script:CriticalCmdlets = @{
    # name = expected module
    'Get-ADUser' = 'ActiveDirectory'; 'Set-ADUser' = 'ActiveDirectory'; 'Set-ADAccountPassword' = 'ActiveDirectory'
    'Enable-ADAccount' = 'ActiveDirectory'; 'Disable-ADAccount' = 'ActiveDirectory'; 'Unlock-ADAccount' = 'ActiveDirectory'
    'Get-ADGroup' = 'ActiveDirectory'; 'Get-ADGroupMember' = 'ActiveDirectory'; 'Add-ADGroupMember' = 'ActiveDirectory'
    'Remove-ADGroupMember' = 'ActiveDirectory'; 'Get-ADComputer' = 'ActiveDirectory'; 'Get-ADDomain' = 'ActiveDirectory'
    'Get-ADObject' = 'ActiveDirectory'; 'Set-ADObject' = 'ActiveDirectory'; 'Get-ADAccountAuthorizationGroup' = 'ActiveDirectory'
    'Set-ADAccountControl' = 'ActiveDirectory'
    'Get-LocalUser' = 'Microsoft.PowerShell.LocalAccounts'; 'Set-LocalUser' = 'Microsoft.PowerShell.LocalAccounts'
    'Enable-LocalUser' = 'Microsoft.PowerShell.LocalAccounts'; 'Disable-LocalUser' = 'Microsoft.PowerShell.LocalAccounts'
    'Get-LocalGroupMember' = 'Microsoft.PowerShell.LocalAccounts'; 'Add-LocalGroupMember' = 'Microsoft.PowerShell.LocalAccounts'
    'Remove-LocalGroupMember' = 'Microsoft.PowerShell.LocalAccounts'
    'Invoke-Command' = 'Microsoft.PowerShell.Core'; 'Test-WSMan' = 'Microsoft.WSMan.Management'
    'Get-Command' = 'Microsoft.PowerShell.Core'; 'Import-Module' = 'Microsoft.PowerShell.Core'; 'Get-Module' = 'Microsoft.PowerShell.Core'
    'Where-Object' = 'Microsoft.PowerShell.Core'; 'ForEach-Object' = 'Microsoft.PowerShell.Core'
    'ConvertTo-SecureString' = 'Microsoft.PowerShell.Security'; 'Get-AuthenticodeSignature' = 'Microsoft.PowerShell.Security'
    'Write-Host' = 'Microsoft.PowerShell.Utility'; 'Write-Output' = 'Microsoft.PowerShell.Utility'; 'Select-Object' = 'Microsoft.PowerShell.Utility'
    'Sort-Object' = 'Microsoft.PowerShell.Utility'; 'Get-Random' = 'Microsoft.PowerShell.Utility'; 'Get-Date' = 'Microsoft.PowerShell.Utility'
    'Out-File' = 'Microsoft.PowerShell.Utility'; 'Export-Csv' = 'Microsoft.PowerShell.Utility'; 'ConvertTo-Json' = 'Microsoft.PowerShell.Utility'
    'ConvertFrom-Json' = 'Microsoft.PowerShell.Utility'; 'New-Object' = 'Microsoft.PowerShell.Utility'; 'Measure-Object' = 'Microsoft.PowerShell.Utility'
    'Format-Table' = 'Microsoft.PowerShell.Utility'; 'Out-String' = 'Microsoft.PowerShell.Utility'
    'Get-Content' = 'Microsoft.PowerShell.Management'; 'Test-Path' = 'Microsoft.PowerShell.Management'; 'Get-Item' = 'Microsoft.PowerShell.Management'
    'Get-ChildItem' = 'Microsoft.PowerShell.Management'; 'Remove-Item' = 'Microsoft.PowerShell.Management'; 'Rename-Item' = 'Microsoft.PowerShell.Management'
    'Get-ItemProperty' = 'Microsoft.PowerShell.Management'; 'Remove-ItemProperty' = 'Microsoft.PowerShell.Management'; 'Get-Service' = 'Microsoft.PowerShell.Management'
    'Join-Path' = 'Microsoft.PowerShell.Management'; 'Split-Path' = 'Microsoft.PowerShell.Management'; 'Copy-Item' = 'Microsoft.PowerShell.Management'
}
$script:CriticalNatives = @('net.exe', 'net1.exe', 'powershell.exe', 'cmd.exe', 'sc.exe', 'netsh.exe', 'secedit.exe', 'auditpol.exe', 'wevtutil.exe', 'reg.exe', 'whoami.exe', 'dsquery.exe', 'ntdsutil.exe')

# --- 0.6 Remove shadowing aliases --------------------------------------------
# Any alias whose name equals a real cmdlet/function/application name is a shadow
# by definition; any alias naming a critical command is removed regardless.
$removedAliases = @()
$allAliases = @(Microsoft.PowerShell.Utility\Get-Alias -ErrorAction SilentlyContinue)
$realCommandNames = @{}
foreach ($c in (Microsoft.PowerShell.Core\Get-Command -CommandType Cmdlet, Function, Application -ErrorAction SilentlyContinue)) { $realCommandNames[$c.Name.ToLower()] = $true }
foreach ($a in $allAliases) {
    $n = $a.Name.ToLower()
    $isShadow = $realCommandNames.ContainsKey($n) -or $script:CriticalCmdlets.ContainsKey($a.Name) -or ($script:CriticalNatives -contains $n) -or ($script:CriticalNatives -contains ($n + '.exe'))
    if ($isShadow) {
        try {
            Microsoft.PowerShell.Management\Remove-Item -Path ("Alias:\" + $a.Name) -Force -ErrorAction Stop
            $removedAliases += "$($a.Name)->$($a.Definition)"
        } catch {
            # Constant aliases cannot be removed; harmless because every critical call below
            # goes through a bound CommandInfo object, which aliases cannot intercept.
            _note "Could not remove alias $($a.Name) -> $($a.Definition) (Constant?) - bypassed via bound cmdlets" 'WARN'
        }
    }
}
if ($removedAliases.Count -gt 0) { _note "Removed $($removedAliases.Count) SHADOWING ALIAS(ES): $($removedAliases -join ', ')" 'FIX' } else { _note "No shadowing aliases found" 'OK' }

# --- 0.7 Remove shadowing functions ------------------------------------------
$removedFunctions = @()
$cmdletNames = @{}
foreach ($c in (Microsoft.PowerShell.Core\Get-Command -CommandType Cmdlet -ErrorAction SilentlyContinue)) { $cmdletNames[$c.Name.ToLower()] = $true }
foreach ($f in @(Microsoft.PowerShell.Management\Get-ChildItem Function:\ -ErrorAction SilentlyContinue)) {
    $n = $f.Name.ToLower()
    if ($n -eq '_note') { continue }
    # Functions shipped by the OS (module lives under $PSHOME, e.g. Get-FileHash in PS 5.1) are trusted
    if ($f.Module -and $f.Module.ModuleBase -and ($f.Module.ModuleBase -like "$PSHOME*")) { continue }
    $isShadow = $cmdletNames.ContainsKey($n) -or $script:CriticalCmdlets.ContainsKey($f.Name) -or ($script:CriticalNatives -contains $n) -or ($script:CriticalNatives -contains ($n + '.exe')) -or ($n -match '^(net|sc|netsh|secedit|auditpol|reg|whoami)$')
    if ($isShadow) {
        $def = ($f.Definition -replace '\s+', ' ')
        if ($def.Length -gt 80) { $def = $def.Substring(0, 80) + '...' }
        try { Microsoft.PowerShell.Management\Remove-Item -Path ("Function:\" + $f.Name) -Force -ErrorAction Stop; $removedFunctions += "$($f.Name) {$def}" } catch { _note "Could not remove function $($f.Name)" 'FAIL' }
    }
}
if ($removedFunctions.Count -gt 0) { _note "Removed $($removedFunctions.Count) SHADOWING FUNCTION(S): $($removedFunctions -join ' | ')" 'FIX' } else { _note "No shadowing functions found" 'OK' }

# --- 0.8 Quarantine profile scripts ------------------------------------------
$profilePaths = @(
    (Microsoft.PowerShell.Management\Join-Path $PSHOME 'profile.ps1'),
    (Microsoft.PowerShell.Management\Join-Path $PSHOME 'Microsoft.PowerShell_profile.ps1'),
    (Microsoft.PowerShell.Management\Join-Path $PSHOME 'Microsoft.PowerShellISE_profile.ps1')
)
foreach ($u in @(Microsoft.PowerShell.Management\Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
    foreach ($sub in 'Documents\WindowsPowerShell', 'Documents\PowerShell', 'OneDrive\Documents\WindowsPowerShell') {
        $dir = Microsoft.PowerShell.Management\Join-Path $u.FullName $sub
        if (Microsoft.PowerShell.Management\Test-Path $dir) {
            foreach ($p in @(Microsoft.PowerShell.Management\Get-ChildItem $dir -Filter '*profile*.ps1' -File -ErrorAction SilentlyContinue)) { $profilePaths += $p.FullName }
        }
    }
}
$stamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')
$foundProfiles = 0
foreach ($pp in ($profilePaths | Microsoft.PowerShell.Utility\Select-Object -Unique)) {
    if (Microsoft.PowerShell.Management\Test-Path $pp -PathType Leaf) {
        $foundProfiles++
        $head = (Microsoft.PowerShell.Management\Get-Content $pp -TotalCount 15 -ErrorAction SilentlyContinue) -join "`n      "
        _note "PROFILE SCRIPT FOUND: $pp" 'WARN'
        Microsoft.PowerShell.Utility\Write-Host "      $head" -ForegroundColor DarkYellow
        if (-not $KeepProfiles -and -not $DryRun) {
            try {
                Microsoft.PowerShell.Management\Rename-Item -Path $pp -NewName ((Microsoft.PowerShell.Management\Split-Path $pp -Leaf) + ".ccdc-quarantined-$stamp") -Force -ErrorAction Stop
                _note "Quarantined -> $pp.ccdc-quarantined-$stamp" 'FIX'
            } catch { _note "Failed to quarantine ${pp}: $_" 'FAIL' }
        }
    }
}
if ($foundProfiles -eq 0) { _note "No profile scripts present" 'OK' }

# --- 0.9 IFEO debugger hijacks & cmd AutoRun ---------------------------------
$ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($bin in $script:CriticalNatives) {
    $k = Microsoft.PowerShell.Management\Join-Path $ifeoRoot $bin
    if (Microsoft.PowerShell.Management\Test-Path $k) {
        $dbg = (Microsoft.PowerShell.Management\Get-ItemProperty $k -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            _note "IFEO DEBUGGER HIJACK on ${bin}: '$dbg'" 'WARN'
            if (-not $DryRun) { try { Microsoft.PowerShell.Management\Remove-ItemProperty $k -Name Debugger -Force -ErrorAction Stop; _note "Removed IFEO Debugger for $bin" 'FIX' } catch { _note "Failed removing IFEO for ${bin}: $_" 'FAIL' } }
        }
    }
}
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Command Processor', 'HKCU:\SOFTWARE\Microsoft\Command Processor') {
    $ar = (Microsoft.PowerShell.Management\Get-ItemProperty $k -Name AutoRun -ErrorAction SilentlyContinue).AutoRun
    if ($ar) {
        _note "cmd.exe AutoRun HIJACK at ${k}: '$ar'" 'WARN'
        if (-not $DryRun) { try { Microsoft.PowerShell.Management\Remove-ItemProperty $k -Name AutoRun -Force -ErrorAction Stop; _note "Removed AutoRun at $k" 'FIX' } catch { _note "Failed removing AutoRun: $_" 'FAIL' } }
    }
}
_note "IFEO / AutoRun checks done" 'OK'

# --- 0.10 Native binaries ---------------------------------------------------
$script:Native = @{}
foreach ($bin in 'net.exe', 'net1.exe', 'secedit.exe', 'auditpol.exe') {
    $p = Microsoft.PowerShell.Management\Join-Path $env:SystemRoot "System32\$bin"
    if (-not (Microsoft.PowerShell.Management\Test-Path $p)) { _note "MISSING native binary $p" 'FAIL'; continue }
    $script:Native[$bin] = $p
    try {
        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop
        $osb = $false; try { $osb = [bool]$sig.IsOSBinary } catch {}
        if ($sig.Status -ne 'Valid' -and -not $osb) { _note "$bin signature status: $($sig.Status) (IsOSBinary=$osb) - binary may be tampered" 'WARN' }
    } catch {}
}
# Also make sure nothing earlier in PATH shadows them
foreach ($bin in 'net.exe', 'net1.exe') {
    $first = @(Microsoft.PowerShell.Core\Get-Command $bin -CommandType Application -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1)
    if ($first -and $first[0].Source -and ($first[0].Source -ine $script:Native[$bin])) { _note "PATH shadow: '$bin' resolves to $($first[0].Source) instead of System32 - script uses full path" 'WARN' }
}
_note "Native binaries bound to full System32 paths" 'OK'

# --- 0.11 Import trusted modules, resolve critical cmdlets -------------------
$script:Cmd = @{}
$needAD = -not $Local
foreach ($m in @(
        @{ Name = 'Microsoft.PowerShell.LocalAccounts'; Path = (Microsoft.PowerShell.Management\Join-Path $PSHOME 'Modules\Microsoft.PowerShell.LocalAccounts'); Required = $true },
        @{ Name = 'ActiveDirectory'; Path = (Microsoft.PowerShell.Management\Join-Path $PSHOME 'Modules\ActiveDirectory'); Required = $needAD },
        @{ Name = 'Microsoft.WSMan.Management'; Path = (Microsoft.PowerShell.Management\Join-Path $PSHOME 'Modules\Microsoft.WSMan.Management'); Required = $false }
    )) {
    try {
        Microsoft.PowerShell.Core\Get-Module $m.Name -ErrorAction SilentlyContinue | Microsoft.PowerShell.Core\Remove-Module -Force -ErrorAction SilentlyContinue
        if (Microsoft.PowerShell.Management\Test-Path $m.Path) {
            Microsoft.PowerShell.Core\Import-Module $m.Path -Force -ErrorAction Stop -DisableNameChecking
        } else {
            Microsoft.PowerShell.Core\Import-Module $m.Name -Force -ErrorAction Stop -DisableNameChecking
        }
        $loaded = Microsoft.PowerShell.Core\Get-Module $m.Name
        $mp = $loaded.ModuleBase
        if ($mp -and -not ($mp -like "$env:SystemRoot*") -and -not ($mp -like "$env:ProgramFiles\WindowsPowerShell\Modules*")) { _note "Module $($m.Name) loaded from UNEXPECTED path: $mp" 'WARN' }
    } catch {
        if ($m.Required) { _note "Cannot import required module $($m.Name): $_" 'FAIL'; if ($m.Name -eq 'ActiveDirectory') { _note "Run with -Local on a non-DC, or install RSAT-AD-PowerShell" 'FAIL' }; exit 3 }
    }
}

$unresolved = @()
foreach ($name in $script:CriticalCmdlets.Keys) {
    $expected = $script:CriticalCmdlets[$name]
    if (-not $needAD -and $expected -eq 'ActiveDirectory') { continue }
    $ci = $null
    try { $ci = Microsoft.PowerShell.Core\Get-Command -Name $name -CommandType Cmdlet -Module $expected -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 1 } catch {}
    if (-not $ci) { $unresolved += "$name ($expected)"; continue }
    # Detect a second definition of the same name (rogue module) - we still bind the trusted one
    $all = @(Microsoft.PowerShell.Core\Get-Command -Name $name -All -ErrorAction SilentlyContinue)
    if ($all.Count -gt 1) { _note "Multiple definitions of '$name': $(($all | Microsoft.PowerShell.Core\ForEach-Object { "$($_.CommandType):$($_.ModuleName)" }) -join ', ') - bound to $expected cmdlet" 'WARN' }
    $script:Cmd[($name -replace '-', '')] = $ci
}
if ($unresolved.Count -gt 0) {
    _note "Could not resolve critical cmdlets: $($unresolved -join ', ')" 'FAIL'
    if ($unresolved | Microsoft.PowerShell.Core\Where-Object { $_ -match 'ActiveDirectory|LocalAccounts' }) { exit 3 }
}
_note "$($script:Cmd.Count) critical cmdlets bound to verified CommandInfo objects" 'OK'

# Final self-test: the bound object must be a genuine Cmdlet from the expected module
$selfTest = $script:Cmd['SetLocalUser']
if ($selfTest.CommandType -ne 'Cmdlet' -or $selfTest.ModuleName -ne 'Microsoft.PowerShell.LocalAccounts') { _note "Self-test failed: Set-LocalUser binding is $($selfTest.CommandType)/$($selfTest.ModuleName)" 'FAIL'; exit 3 }
if ($needAD) {
    $selfTest = $script:Cmd['SetADAccountPassword']
    if ($selfTest.CommandType -ne 'Cmdlet' -or $selfTest.ModuleName -ne 'ActiveDirectory') { _note "Self-test failed: Set-ADAccountPassword binding is $($selfTest.CommandType)/$($selfTest.ModuleName)" 'FAIL'; exit 3 }
}
_note "Environment sanitized. Continuing." 'OK'

# ============================================================================
# From here on the session is clean; plain cmdlet names are safe, and every
# MUTATING call still goes through $Cmd.* for defence in depth.
# ============================================================================

$script:StartTime = Get-Date
$script:ExecutionLog = [System.Collections.ArrayList]::new()
$script:PasswordResets = [System.Collections.ArrayList]::new()
$script:GroupChanges = [System.Collections.ArrayList]::new()
$script:AccountChanges = [System.Collections.ArrayList]::new()
$script:HygieneFindings = [System.Collections.ArrayList]::new()
$script:Errors = [System.Collections.ArrayList]::new()
$script:Warnings = [System.Collections.ArrayList]::new()
$script:Stats = @{
    GroupsProcessed = 0; MembersRemoved = 0; MembersAdded = 0
    PasswordsReset = 0; PasswordsVerified = 0; PasswordsUnverified = 0; PasswordsFailed = 0
    AccountsDisabled = 0; AccountsUnlocked = 0; ServersProcessed = 0; ServersFailed = 0; HygieneFixes = 0
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL', 'PASSWORD', 'CHANGE', 'AUDIT', 'DRYRUN', 'VERIFY')][string]$Level = 'INFO')
    $entry = [PSCustomObject]@{ Timestamp = Get-Date; Level = $Level; Message = $Message }
    [void]$script:ExecutionLog.Add($entry)
    & $script:Cmd.WriteHost ("[{0}] " -f (Get-Date -Format 'HH:mm:ss')) -NoNewline -ForegroundColor DarkGray
    switch ($Level) {
        'INFO' { & $script:Cmd.WriteHost "[INFO]     " -NoNewline -ForegroundColor Cyan }
        'SUCCESS' { & $script:Cmd.WriteHost "[SUCCESS]  " -NoNewline -ForegroundColor Green }
        'WARNING' { & $script:Cmd.WriteHost "[WARNING]  " -NoNewline -ForegroundColor Yellow; [void]$script:Warnings.Add($entry) }
        'ERROR' { & $script:Cmd.WriteHost "[ERROR]    " -NoNewline -ForegroundColor Red; [void]$script:Errors.Add($entry) }
        'CRITICAL' { & $script:Cmd.WriteHost "[CRITICAL] " -NoNewline -ForegroundColor White -BackgroundColor Red; [void]$script:Errors.Add($entry) }
        'PASSWORD' { & $script:Cmd.WriteHost "[PASSWORD] " -NoNewline -ForegroundColor Black -BackgroundColor Green }
        'CHANGE' { & $script:Cmd.WriteHost "[CHANGE]   " -NoNewline -ForegroundColor Magenta }
        'AUDIT' { & $script:Cmd.WriteHost "[AUDIT]    " -NoNewline -ForegroundColor Blue }
        'DRYRUN' { & $script:Cmd.WriteHost "[DRY RUN]  " -NoNewline -ForegroundColor Yellow -BackgroundColor DarkBlue }
        'VERIFY' { & $script:Cmd.WriteHost "[VERIFY]   " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen }
    }
    & $script:Cmd.WriteHost $Message
}
function Write-SectionHeader([string]$Title) { & $script:Cmd.WriteHost "`n$('=' * 80)`n  $Title`n$('=' * 80)" -ForegroundColor Cyan }
function Write-SubSection([string]$Title) { & $script:Cmd.WriteHost "`n  $Title" -ForegroundColor Yellow; & $script:Cmd.WriteHost ("  " + ("-" * 76)) -ForegroundColor DarkGray }

# ============================================================================
# Shared helpers (also embedded verbatim into the remote worker below)
# ============================================================================
$script:HelperSource = @'
function New-CCDCPassword {
    param([int]$Length = 16)
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; $lower = 'abcdefghijklmnopqrstuvwxyz'; $digit = '0123456789'; $special = ')(.,@=:-!'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $pick = { param($set) $b = New-Object byte[] 4; $rng.GetBytes($b); $set[[math]::Abs([BitConverter]::ToInt32($b, 0)) % $set.Length] }
    $chars = New-Object System.Collections.Generic.List[char]
    1..2 | ForEach-Object { $chars.Add((& $pick $upper)); $chars.Add((& $pick $lower)); $chars.Add((& $pick $digit)); $chars.Add((& $pick $special)) }
    $all = $upper + $lower + $digit + $special
    while ($chars.Count -lt $Length) { $chars.Add((& $pick $all)) }
    # Fisher-Yates
    for ($i = $chars.Count - 1; $i -gt 0; $i--) { $b = New-Object byte[] 4; $rng.GetBytes($b); $j = [math]::Abs([BitConverter]::ToInt32($b, 0)) % ($i + 1); $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t }
    # Always start with a letter (never a special char that a shell might treat as a switch)
    if ($chars[0] -notmatch '[A-Za-z]') { $k = 0; for ($i = 1; $i -lt $chars.Count; $i++) { if ($chars[$i] -match '[A-Za-z]') { $k = $i; break } }; $t = $chars[0]; $chars[0] = $chars[$k]; $chars[$k] = $t }
    $rng.Dispose()
    return -join $chars
}
function Test-CCDCPasswordComplexity([string]$p) {
    return ($p -cmatch '[A-Z]') -and ($p -cmatch '[a-z]') -and ($p -match '[0-9]') -and ($p -match '[)(.,@=:\-!]') -and ($p -notmatch '[^A-Za-z0-9)(.,@=:\-!]') -and ($p -match '^[A-Za-z]')
}
'@
Invoke-Expression $script:HelperSource

function Test-DomainCredential([string]$User, [string]$Password) {
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
        $ok = $ctx.ValidateCredentials($User, $Password, [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate)
        $ctx.Dispose()
        return $ok
    } catch { return $null }
}

function Get-LdapPwdLastSet([string]$DistinguishedName) {
    try {
        $de = [ADSI]("LDAP://" + $DistinguishedName)
        $v = $de.Properties['pwdLastSet'].Value
        if ($null -eq $v) { return 0 }
        return [Int64]$de.ConvertLargeIntegerToInt64($v)
    } catch { return -1 }
}

# ============================================================================
# Banner + Config
# ============================================================================
Clear-Host
Write-SectionHeader "CCDC USER AUDIT v3 - HARDENED EDITION"
& $script:Cmd.WriteHost "  Host: $env:COMPUTERNAME   Mode: $(if ($Local) {'LOCAL ONLY'} else {'DOMAIN (run from DC)'})   Time: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
& $script:Cmd.WriteHost "  Config: $ConfigFile   Password length: $PasswordLength   Specials: )(.,@=:-!" -ForegroundColor Gray
if ($DryRun) { & $script:Cmd.WriteHost "  MODE: DRY RUN - no changes will be made" -ForegroundColor Yellow -BackgroundColor DarkBlue }
$fixes = @($script:SanitizeFindings | Where-Object { $_.Level -in 'FIX', 'WARN', 'FAIL' })
if ($fixes.Count -gt 0) {
    & $script:Cmd.WriteHost "`n  ENVIRONMENT TAMPERING INDICATORS ($($fixes.Count)):" -ForegroundColor Red
    $fixes | ForEach-Object { & $script:Cmd.WriteHost "    [$($_.Level)] $($_.Message)" -ForegroundColor $(if ($_.Level -eq 'FIX') { 'Magenta' } elseif ($_.Level -eq 'FAIL') { 'Red' } else { 'Yellow' }) }
}

Write-SectionHeader "CONFIGURATION"
function Parse-ConfigFile([string]$FilePath) {
    if (-not (Test-Path $FilePath)) {
        # tolerate the old filename
        $alt = Join-Path (Split-Path $FilePath -Parent) 'users_config.txt'
        if (Test-Path $alt) { Write-Log "Config '$FilePath' not found, using '$alt'" -Level WARNING; $FilePath = $alt } else { Write-Log "Configuration file not found: $FilePath" -Level CRITICAL; return $null }
    }
    $sections = 'RegularUsers', 'Administrators', 'DomainAdmins', 'EnterpriseAdmins', 'RemoteDesktopUsers', 'RemoteManagementUsers', 'ExcludedUsers'
    $config = @{}; foreach ($s in $sections) { $config[$s] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
    $current = $null; $ln = 0
    foreach ($raw in (Get-Content $FilePath)) {
        $ln++; $line = $raw.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line -match '^\[(.+)\]$') {
            $name = $matches[1]
            if ($config.ContainsKey($name)) { $current = $name } else { Write-Log "Unknown section [$name] line $ln - ignored" -Level WARNING; $current = $null }
            continue
        }
        if ($current) {
            $u = ($line -split '#')[0].Trim().ToLower()
            if ($u -match '^[a-z0-9_\-\.\$]+$') { [void]$config[$current].Add($u) } else { Write-Log "Invalid username '$u' line $ln - ignored" -Level WARNING }
        }
    }
    $result = @{}; foreach ($k in $config.Keys) { $result[$k] = @($config[$k]) }
    # sanity: excluded users must not be elsewhere
    foreach ($ex in $result.ExcludedUsers) { foreach ($s in $sections) { if ($s -ne 'ExcludedUsers' -and $result[$s] -contains $ex) { Write-Log "'$ex' is in [ExcludedUsers] AND [$s] - ExcludedUsers wins, it will be left untouched" -Level WARNING } } }
    return $result
}
$userConfig = Parse-ConfigFile -FilePath $ConfigFile
if ($null -eq $userConfig) { exit 1 }
$allAuthorizedUsers = @(); foreach ($s in 'RegularUsers', 'Administrators', 'DomainAdmins', 'EnterpriseAdmins', 'RemoteDesktopUsers', 'RemoteManagementUsers') { $allAuthorizedUsers += $userConfig[$s] }
$allAuthorizedUsers = @($allAuthorizedUsers | Select-Object -Unique | Where-Object { $_ })
$excluded = $userConfig.ExcludedUsers
foreach ($s in 'RegularUsers', 'Administrators', 'DomainAdmins', 'EnterpriseAdmins', 'RemoteDesktopUsers', 'RemoteManagementUsers', 'ExcludedUsers') {
    & $script:Cmd.WriteHost ("    {0,-24} {1,3}  {2}" -f $s, $userConfig[$s].Count, ($userConfig[$s] -join ', ')) -ForegroundColor $(if ($s -eq 'ExcludedUsers') { 'Cyan' } else { 'Gray' })
}
Write-Log "Total unique authorized users: $($allAuthorizedUsers.Count); excluded (hands-off): $($excluded.Count)" -Level INFO
if ($excluded.Count -eq 0) { Write-Log "No [ExcludedUsers] defined - make sure scoring/judge accounts are not going to be reset!" -Level WARNING }

# RDP / WinRM sets: Domain & Enterprise Admins automatically get both
$rdpUsers = @(@($userConfig.RemoteDesktopUsers) + @($userConfig.DomainAdmins) + @($userConfig.EnterpriseAdmins) | Select-Object -Unique)
$winrmUsers = @(@($userConfig.RemoteManagementUsers) + @($userConfig.DomainAdmins) + @($userConfig.EnterpriseAdmins) | Select-Object -Unique)

# ============================================================================
# REMOTE / LOCAL WORKER  (runs on each member server, or on this box in -Local)
# One round trip per server. Performs: sanitize, local group enforcement,
# local user reset/disable with verification + fallbacks. Returns a report.
# ============================================================================
$script:LocalWorkerSource = @'
param([string]$ConfigJson, [string]$OptionsJson)
$ErrorActionPreference = 'Continue'
$cfg = $ConfigJson | ConvertFrom-Json
$opt = $OptionsJson | ConvertFrom-Json
$dryRun = [bool]$opt.DryRun
$R = @{ Computer = $env:COMPUTERNAME; Sanitize = @(); Groups = @(); Users = @(); Errors = @(); Passwords = @() }

# --- sanitize this host (profiles, IFEO, AutoRun) ---
try {
    $ic = $ExecutionContext.SessionState.InvokeCommand
    foreach ($h in 'PreCommandLookupAction','PostCommandLookupAction','CommandNotFoundAction') { if ($ic.$h) { $ic.$h = $null; $R.Sanitize += "Cleared hook $h" } }
    if ($PSDefaultParameterValues.Count -gt 0) { $R.Sanitize += "Cleared PSDefaultParameterValues ($($PSDefaultParameterValues.Keys -join ','))"; $PSDefaultParameterValues.Clear() }
    foreach ($a in @(Microsoft.PowerShell.Utility\Get-Alias | Microsoft.PowerShell.Core\Where-Object { $_.Name -match '^(Set|Get|Enable|Disable|Add|Remove)-(Local|AD)' -or $_.Name -match '^(net|net1|sc|secedit|auditpol)(\.exe)?$' })) { Microsoft.PowerShell.Management\Remove-Item "Alias:\$($a.Name)" -Force -ErrorAction SilentlyContinue; $R.Sanitize += "Removed alias $($a.Name)->$($a.Definition)" }
    foreach ($f in @(Microsoft.PowerShell.Management\Get-ChildItem Function:\ | Microsoft.PowerShell.Core\Where-Object { $_.Name -match '^(Set|Get|Enable|Disable|Add|Remove)-(Local|AD)' -or $_.Name -match '^(net|net1|sc|secedit|auditpol)$' })) { Microsoft.PowerShell.Management\Remove-Item "Function:\$($f.Name)" -Force -ErrorAction SilentlyContinue; $R.Sanitize += "Removed function $($f.Name)" }
    $profiles = @("$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1", "$PSHOME\Microsoft.PowerShellISE_profile.ps1")
    foreach ($u in @(Microsoft.PowerShell.Management\Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) { foreach ($sub in 'Documents\WindowsPowerShell','Documents\PowerShell') { $d = Join-Path $u.FullName $sub; if (Test-Path $d) { $profiles += @(Microsoft.PowerShell.Management\Get-ChildItem $d -Filter '*profile*.ps1' -File -ErrorAction SilentlyContinue | ForEach-Object FullName) } } }
    foreach ($p in ($profiles | Select-Object -Unique)) {
        if (Test-Path $p -PathType Leaf) {
            $head = ((Get-Content $p -TotalCount 5 -ErrorAction SilentlyContinue) -join ' | ')
            $R.Sanitize += "PROFILE FOUND: $p :: $head"
            if (-not $opt.KeepProfiles -and -not $dryRun) { try { Rename-Item $p ((Split-Path $p -Leaf) + ".ccdc-quarantined-" + (Get-Date -Format yyyyMMdd-HHmmss)) -Force -ErrorAction Stop; $R.Sanitize += "Quarantined $p" } catch { $R.Errors += "Quarantine failed ${p}: $_" } }
        }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($bin in 'net.exe','net1.exe','powershell.exe','cmd.exe','sc.exe','netsh.exe','secedit.exe','auditpol.exe','reg.exe') {
        $k = Join-Path $ifeo $bin
        if (Test-Path $k) { $dbg = (Get-ItemProperty $k -Name Debugger -ErrorAction SilentlyContinue).Debugger; if ($dbg) { $R.Sanitize += "IFEO HIJACK ${bin}: $dbg"; if (-not $dryRun) { Remove-ItemProperty $k -Name Debugger -Force -ErrorAction SilentlyContinue; $R.Sanitize += "Removed IFEO $bin" } } }
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Command Processor','HKCU:\SOFTWARE\Microsoft\Command Processor') { $ar = (Get-ItemProperty $k -Name AutoRun -ErrorAction SilentlyContinue).AutoRun; if ($ar) { $R.Sanitize += "cmd AutoRun HIJACK ${k}: $ar"; if (-not $dryRun) { Remove-ItemProperty $k -Name AutoRun -Force -ErrorAction SilentlyContinue } } }
} catch { $R.Errors += "Sanitize: $_" }

Import-Module "$PSHOME\Modules\Microsoft.PowerShell.LocalAccounts" -Force -ErrorAction SilentlyContinue
$C = @{}
foreach ($n in 'Get-LocalUser','Set-LocalUser','Enable-LocalUser','Disable-LocalUser','Get-LocalGroupMember','Add-LocalGroupMember','Remove-LocalGroupMember','Get-LocalGroup') {
    $C[($n -replace '-','')] = Microsoft.PowerShell.Core\Get-Command $n -CommandType Cmdlet -Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
}
$haveLA = ($null -ne $C.GetLocalUser)
$netExe = Join-Path $env:SystemRoot 'System32\net.exe'

__HELPERS__

function Test-LocalCred([string]$u, [string]$p) {
    try { Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
        $ok = $ctx.ValidateCredentials($u, $p); $ctx.Dispose(); return $ok } catch { return $null }
}
function Get-LocalPwdLastSet([string]$u) {
    try { if ($haveLA) { $x = (& $C.GetLocalUser -Name $u -ErrorAction Stop).PasswordLastSet; if ($x) { return $x } }
          $adsi = [ADSI]"WinNT://./$u,user"; $age = [int]$adsi.PasswordAge.Value; return (Get-Date).AddSeconds(-$age) } catch { return $null }
}

$excluded = @($cfg.ExcludedUsers); $authorized = @($cfg.AllAuthorized); $domain = $opt.Domain

# ---------------- LOCAL GROUPS ----------------
if (-not $opt.SkipGroupAudit) {
    $groupDefs = @(
        @{ Name='Administrators';          Auth=@($cfg.Administrators);       Defaults=@('Administrator','Domain Admins','Enterprise Admins') },
        @{ Name='Remote Desktop Users';    Auth=@($cfg.RdpUsers);              Defaults=@('Domain Admins','Enterprise Admins') },
        @{ Name='Remote Management Users'; Auth=@($cfg.WinrmUsers);            Defaults=@('Domain Admins','Enterprise Admins') },
        @{ Name='Backup Operators';        Auth=@();                           Defaults=@() },
        @{ Name='Power Users';             Auth=@();                           Defaults=@() },
        @{ Name='Hyper-V Administrators';  Auth=@();                           Defaults=@() },
        @{ Name='Distributed COM Users';   Auth=@();                           Defaults=@() },
        @{ Name='Event Log Readers';       Auth=@();                           Defaults=@() },
        @{ Name='Network Configuration Operators'; Auth=@();                   Defaults=@() }
    )
    if (-not $haveLA) { $R.Errors += "Microsoft.PowerShell.LocalAccounts unavailable - using ADSI/net.exe fallbacks" }
    foreach ($g in $groupDefs) {
        $exists = $false
        try { if ($haveLA) { $null = & $C.GetLocalGroup -Name $g.Name -ErrorAction Stop; $exists = $true } else { $exists = [ADSI]::Exists("WinNT://./$($g.Name),group") } } catch {}
        if (-not $exists) { continue }
        $members = @()
        try { $members = @(& $C.GetLocalGroupMember -Group $g.Name -ErrorAction Stop) } catch {
            # Fallback: WinNT ADSI (Get-LocalGroupMember dies on orphaned SIDs)
            try { $ga = [ADSI]"WinNT://./$($g.Name),group"; $members = @($ga.Invoke('Members') | ForEach-Object { $path = $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$_,$null); [PSCustomObject]@{ Name = ($path -replace '^WinNT://','' -replace '/','\'); SID = $null; ObjectClass='Unknown' } }) } catch { $R.Errors += "Cannot read group $($g.Name): $_" ; continue }
        }
        $names = @()
        foreach ($m in $members) {
            $full = [string]$m.Name; $short = ($full -replace '.*\\','')
            $names += $short.ToLower()
            $sidStr = ''; try { $sidStr = [string]$m.SID.Value } catch {}
            $isRid500 = $sidStr -match '-500$'
            if ($excluded -contains $short.ToLower()) { $R.Groups += [PSCustomObject]@{ Group=$g.Name; Member=$full; Action='Excluded' }; continue }
            $isDefault = $false; foreach ($d in $g.Defaults) { if ($short -ieq $d) { $isDefault = $true } }
            if ($isRid500 -and $g.Name -eq 'Administrators') { $isDefault = $true }   # built-in admin even if renamed
            $isAuth = $isDefault -or ($g.Auth -contains $short.ToLower())
            if ($isAuth) { $R.Groups += [PSCustomObject]@{ Group=$g.Name; Member=$full; Action='OK' }; continue }
            # Orphaned SID (deleted account) - remove too
            if ($dryRun) { $R.Groups += [PSCustomObject]@{ Group=$g.Name; Member=$full; Action='WouldRemove' }; continue }
            $removed = $false
            try { & $C.RemoveLocalGroupMember -Group $g.Name -Member $full -ErrorAction Stop; $removed = $true } catch {
                try { if ($sidStr) { & $C.RemoveLocalGroupMember -Group $g.Name -SID $sidStr -ErrorAction Stop; $removed = $true } } catch {}
                if (-not $removed) { $out = & $netExe localgroup "$($g.Name)" "$full" /delete 2>&1; $removed = ($LASTEXITCODE -eq 0) }
            }
            $R.Groups += [PSCustomObject]@{ Group=$g.Name; Member=$full; Action=$(if ($removed) {'Removed'} else {'RemoveFAILED'}) }
        }
        foreach ($a in $g.Auth) {
            if (-not $a -or ($excluded -contains $a) -or ($names -contains $a)) { continue }
            $target = if ($domain) { "$domain\$a" } else { $a }
            if ($dryRun) { $R.Groups += [PSCustomObject]@{ Group=$g.Name; Member=$target; Action='WouldAdd' }; continue }
            $added = $false
            try { & $C.AddLocalGroupMember -Group $g.Name -Member $target -ErrorAction Stop; $added = $true } catch { $out = & $netExe localgroup "$($g.Name)" "$target" /add 2>&1; $added = ($LASTEXITCODE -eq 0) }
            if (-not $added -and $domain) { try { & $C.AddLocalGroupMember -Group $g.Name -Member $a -ErrorAction Stop; $added = $true; $target = $a } catch {} }
            $R.Groups += [PSCustomObject]@{ Group=$g.Name; Member=$target; Action=$(if ($added) {'Added'} else {'AddFAILED'}) }
        }
    }
}

# ---------------- LOCAL USERS ----------------
if (-not $opt.SkipPasswordReset) {
    $users = @()
    try { $users = @(& $C.GetLocalUser -ErrorAction Stop | Select-Object Name, Enabled, SID, PasswordLastSet) } catch {
        try { $users = @(([ADSI]"WinNT://.").Children | Where-Object { $_.SchemaClassName -eq 'User' } | ForEach-Object { [PSCustomObject]@{ Name=$_.Name.Value; Enabled = -not ([int]$_.UserFlags.Value -band 2); SID=$null; PasswordLastSet=$null } }) } catch { $R.Errors += "Cannot enumerate local users: $_" }
    }
    foreach ($u in $users) {
        $name = [string]$u.Name; $lname = $name.ToLower()
        $sidStr = ''; try { $sidStr = [string]$u.SID.Value } catch {}
        $isRid500 = $sidStr -match '-500$'; $isRid501 = $sidStr -match '-501$'
        if ($isRid501 -or $lname -in 'defaultaccount','wdagutilityaccount') {
            if ($u.Enabled) { if (-not $dryRun) { try { & $C.DisableLocalUser -Name $name -ErrorAction Stop } catch { & $netExe user "$name" /active:no | Out-Null } }; $R.Users += [PSCustomObject]@{ User=$name; Action=$(if ($dryRun) {'WouldDisable(system)'} else {'Disabled(system)'}); Verified=$null } }
            continue
        }
        if ($excluded -contains $lname) { $R.Users += [PSCustomObject]@{ User=$name; Action='Excluded'; Verified=$null }; continue }
        # RID-500 counts as "administrator" in config even if renamed
        $isAuth = ($authorized -contains $lname) -or ($isRid500 -and ($authorized -contains 'administrator'))
        if ($isAuth) {
            if ($dryRun) { $R.Users += [PSCustomObject]@{ User=$name; Action='WouldReset'; Verified=$null }; continue }
            $pw = New-CCDCPassword -Length ([int]$opt.PasswordLength)
            if (-not (Test-CCDCPasswordComplexity $pw)) { $R.Errors += "Generated password failed complexity for $name"; continue }
            $before = Get-LocalPwdLastSet $name
            $method = ''; $ok = $false
            try { $sec = ConvertTo-SecureString $pw -AsPlainText -Force; & $C.SetLocalUser -Name $name -Password $sec -PasswordNeverExpires $false -UserMayChangePassword $true -ErrorAction Stop; $method='Set-LocalUser'; $ok=$true } catch { $R.Errors += "Set-LocalUser ${name}: $_" }
            if (-not $ok) { try { $adsi = [ADSI]"WinNT://./$name,user"; $adsi.SetPassword($pw); $adsi.SetInfo(); $method='ADSI'; $ok=$true } catch { $R.Errors += "ADSI SetPassword ${name}: $_" } }
            if (-not $ok) { $out = & $netExe user "$name" "$pw" 2>&1; if ($LASTEXITCODE -eq 0) { $method='net.exe'; $ok=$true } else { $R.Errors += "net user ${name}: $out" } }
            try { & $C.EnableLocalUser -Name $name -ErrorAction Stop } catch { & $netExe user "$name" /active:yes | Out-Null }
            # verify
            $after = Get-LocalPwdLastSet $name
            $advanced = ($after -and (-not $before -or $after -gt $before))
            $cred = Test-LocalCred $name $pw
            $verified = if ($cred -eq $true) { 'CredentialOK' } elseif ($advanced) { 'PwdLastSetAdvanced(logon-denied?)' } elseif ($ok) { 'UNVERIFIED' } else { 'FAILED' }
            if ($ok) { $R.Passwords += [PSCustomObject]@{ Computer=$env:COMPUTERNAME; User=$name; Password=$pw; Method=$method; Verified=$verified } }
            $R.Users += [PSCustomObject]@{ User=$name; Action=$(if ($ok) {"Reset($method)"} else {'ResetFAILED'}); Verified=$verified }
        } else {
            if ($u.Enabled) {
                if ($dryRun) { $R.Users += [PSCustomObject]@{ User=$name; Action='WouldDisable'; Verified=$null }; continue }
                $ok = $false
                try { & $C.DisableLocalUser -Name $name -ErrorAction Stop; $ok = $true } catch { $out = & $netExe user "$name" /active:no 2>&1; $ok = ($LASTEXITCODE -eq 0) }
                $still = $true; try { $still = (& $C.GetLocalUser -Name $name -ErrorAction Stop).Enabled } catch {}
                $R.Users += [PSCustomObject]@{ User=$name; Action=$(if ($ok -and -not $still) {'Disabled'} else {'DisableFAILED'}); Verified=$(if (-not $still) {'Confirmed'} else {'StillEnabled'}) }
            } else { $R.Users += [PSCustomObject]@{ User=$name; Action='AlreadyDisabled'; Verified=$null } }
        }
    }
}
return ($R | ConvertTo-Json -Depth 5 -Compress)
'@
$script:LocalWorker = [scriptblock]::Create($script:LocalWorkerSource.Replace('__HELPERS__', $script:HelperSource))

function Show-WorkerReport([string]$Json, [string]$Label) {
    $r = $null
    try { $r = $Json | ConvertFrom-Json } catch { Write-Log "Worker on $Label returned unparseable output: $Json" -Level ERROR; $script:Stats.ServersFailed++; return }
    foreach ($s in @($r.Sanitize)) { Write-Log "[$Label] SANITIZE: $s" -Level $(if ($s -match 'HIJACK|PROFILE FOUND|Removed|Cleared') { 'WARNING' } else { 'INFO' }) }
    foreach ($g in @($r.Groups)) {
        $col = switch -Regex ($g.Action) { 'OK' { 'Green' } 'Excluded' { 'Cyan' } 'Would' { 'Yellow' } 'FAILED' { 'Red' } 'Removed' { 'Yellow' } 'Added' { 'Green' } default { 'Gray' } }
        & $script:Cmd.WriteHost ("      {0,-28} {1,-45} {2}" -f $g.Group, $g.Member, $g.Action) -ForegroundColor $col
        if ($g.Action -in 'Removed', 'Added') { [void]$script:GroupChanges.Add([PSCustomObject]@{ Type = 'Local Group'; Computer = $Label; Group = $g.Group; Member = $g.Member; Action = $g.Action }); if ($g.Action -eq 'Removed') { $script:Stats.MembersRemoved++ } else { $script:Stats.MembersAdded++ } }
        if ($g.Action -like '*FAILED*') { Write-Log "[$Label] $($g.Action) $($g.Member) in $($g.Group)" -Level ERROR }
    }
    foreach ($u in @($r.Users)) {
        $col = switch -Regex ($u.Action) { '^Reset' { 'Green' } 'Excluded' { 'Cyan' } 'Would' { 'Yellow' } 'FAILED' { 'Red' } 'Disabled' { 'Yellow' } default { 'Gray' } }
        & $script:Cmd.WriteHost ("      {0,-28} {1,-28} {2}" -f $u.User, $u.Action, $u.Verified) -ForegroundColor $col
        if ($u.Action -like 'Disabled*') { $script:Stats.AccountsDisabled++; [void]$script:AccountChanges.Add([PSCustomObject]@{ Type = 'Local Account'; Computer = $Label; Account = $u.User; Action = 'Disabled' }) }
        if ($u.Action -like '*FAILED*') { Write-Log "[$Label] $($u.Action) for $($u.User)" -Level ERROR }
    }
    foreach ($p in @($r.Passwords)) {
        [void]$script:PasswordResets.Add([PSCustomObject]@{ Type = 'Local User'; Computer = $Label; Account = $p.User; Password = $p.Password; Method = $p.Method; Verified = $p.Verified })
        $script:Stats.PasswordsReset++
        if ($p.Verified -match 'CredentialOK|Advanced') { $script:Stats.PasswordsVerified++ } else { $script:Stats.PasswordsUnverified++ }
        & $script:Cmd.WriteHost "        $Label\$($p.User): " -NoNewline -ForegroundColor Cyan
        & $script:Cmd.WriteHost $p.Password -NoNewline -ForegroundColor Black -BackgroundColor Green
        & $script:Cmd.WriteHost "  [$($p.Method) / $($p.Verified)]" -ForegroundColor $(if ($p.Verified -match 'CredentialOK') { 'Green' } elseif ($p.Verified -match 'Advanced') { 'Yellow' } else { 'Red' })
    }
    foreach ($e in @($r.Errors)) { Write-Log "[$Label] $e" -Level ERROR }
}

$workerConfig = @{
    Administrators = $userConfig.Administrators; RdpUsers = $rdpUsers; WinrmUsers = $winrmUsers
    ExcludedUsers = $excluded; AllAuthorized = $allAuthorizedUsers
} | ConvertTo-Json -Compress -Depth 3
$workerOptions = @{ DryRun = [bool]$DryRun; KeepProfiles = [bool]$KeepProfiles; SkipGroupAudit = [bool]$SkipGroupAudit; SkipPasswordReset = [bool]$SkipPasswordReset; PasswordLength = $PasswordLength; Domain = $(if ($Local) { $env:USERDOMAIN } else { $env:USERDOMAIN }) } | ConvertTo-Json -Compress

# ============================================================================
# LOCAL MODE - run the worker right here and finish
# ============================================================================
if ($Local) {
    Write-SectionHeader "LOCAL MODE: $env:COMPUTERNAME"
    if ((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole -ge 4) { Write-Log "This machine is a Domain Controller - it has no local SAM users. Run without -Local." -Level CRITICAL; exit 1 }
    $json = & $script:LocalWorker $workerConfig $workerOptions
    Show-WorkerReport -Json $json -Label $env:COMPUTERNAME
    $script:Stats.ServersProcessed = 1
} else {

# ============================================================================
# DOMAIN DISCOVERY
# ============================================================================
Write-SectionHeader "DOMAIN INFRASTRUCTURE DISCOVERY"
try {
    $domain = & $script:Cmd.GetADDomain -ErrorAction Stop
    $domainDns = $domain.DNSRoot; $domainNetbios = $domain.NetBIOSName; $domainSid = $domain.DomainSID.Value
    Write-Log "Domain: $domainDns ($domainNetbios)  PDC: $($domain.PDCEmulator)" -Level INFO
} catch { Write-Log "Cannot query domain: $_ - are you on a DC / do you have RSAT?" -Level CRITICAL; exit 1 }
$workerOptions = @{ DryRun = [bool]$DryRun; KeepProfiles = [bool]$KeepProfiles; SkipGroupAudit = [bool]$SkipGroupAudit; SkipPasswordReset = [bool]$SkipPasswordReset; PasswordLength = $PasswordLength; Domain = $domainNetbios } | ConvertTo-Json -Compress

# --- WinRM bootstrap over DCOM (propagation enabler) ------------------------
# When a domain host does not answer WinRM we can still reach it with WMI/CIM
# over DCOM (RPC 135) using the DC's Kerberos context, and have IT turn WinRM on.
function Invoke-WinRMBootstrap {
    param([string]$Target)
    $cmd = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
    'try { Enable-PSRemoting -Force -SkipNetworkProfileCheck } catch {};' +
    'Set-Service WinRM -StartupType Automatic -ErrorAction SilentlyContinue;' +
    'Start-Service WinRM -ErrorAction SilentlyContinue;' +
    'try { Enable-NetFirewallRule -Group ''@FirewallAPI.dll,-30267'' -ErrorAction SilentlyContinue } catch {};' +
    'netsh advfirewall firewall set rule group=\"Windows Remote Management\" new enable=Yes"'
    $sess = $null
    try {
        $opt = New-CimSessionOption -Protocol Dcom
        $sess = New-CimSession -ComputerName $Target -SessionOption $opt -ErrorAction Stop
        $r = Invoke-CimMethod -CimSession $sess -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
        return ($r.ReturnValue -eq 0)   # 0 = process created
    } catch { return $false }
    finally { if ($sess) { Remove-CimSession $sess -ErrorAction SilentlyContinue } }
}

$windowsComputers = @()
if (-not $SkipRemoteServers) {
    try {
        $allComputers = @(& $script:Cmd.GetADComputer -Filter * -Properties OperatingSystem, DNSHostName, PrimaryGroupID, Enabled -ErrorAction Stop)
        $candidates = $allComputers | Where-Object { $_.Enabled -and $_.OperatingSystem -like '*Windows*' -and $_.PrimaryGroupID -ne 516 -and $_.PrimaryGroupID -ne 521 -and $_.Name -ine $env:COMPUTERNAME }
        if ($TargetServers) { $candidates = $candidates | Where-Object { $c = $_; $TargetServers | Where-Object { $c.Name -ieq $_ -or $c.DNSHostName -ieq $_ } } }
        Write-Log "AD computers: $($allComputers.Count) total, $(@($candidates).Count) Windows non-DC candidates (servers + workstations)" -Level INFO
        if ($BootstrapWinRM) { Write-Log "BootstrapWinRM ON - unreachable hosts will be enabled over DCOM as the sweep proceeds" -Level INFO }
        Write-SubSection "Testing WinRM connectivity"
        foreach ($c in $candidates) {
            $cn = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }
            & $script:Cmd.WriteHost "    $cn ..." -NoNewline -ForegroundColor Gray
            $ok = $false; try { $null = & $script:Cmd.TestWSMan -ComputerName $cn -ErrorAction Stop; $ok = $true } catch {}
            if (-not $ok -and $c.Name -ne $cn) { try { $null = & $script:Cmd.TestWSMan -ComputerName $c.Name -ErrorAction Stop; $cn = $c.Name; $ok = $true } catch {} }
            if (-not $ok -and $BootstrapWinRM) {
                & $script:Cmd.WriteHost " bootstrapping..." -NoNewline -ForegroundColor Yellow
                foreach ($tn in @($cn, $c.Name | Select-Object -Unique)) {
                    if (Invoke-WinRMBootstrap -Target $tn) {
                        Start-Sleep -Seconds 6
                        try { $null = & $script:Cmd.TestWSMan -ComputerName $tn -ErrorAction Stop; $cn = $tn; $ok = $true; break } catch {}
                    }
                }
                if ($ok) { Write-Log "WinRM enabled on $cn via DCOM bootstrap" -Level CHANGE }
            }
            if ($ok) { $windowsComputers += $cn; & $script:Cmd.WriteHost " OK" -ForegroundColor Green } else { & $script:Cmd.WriteHost " UNREACHABLE" -ForegroundColor Red; Write-Log "WinRM unreachable: $cn - run this script with -Local on that box$(if (-not $BootstrapWinRM) { ' (or re-run with -BootstrapWinRM)' })" -Level WARNING }
        }
    } catch { Write-Log "Computer discovery failed: $_" -Level ERROR }
}

# ============================================================================
# PHASE 1: DOMAIN GROUP ENFORCEMENT
# ============================================================================
if (-not $SkipGroupAudit) {
    Write-SectionHeader "PHASE 1: DOMAIN GROUP MEMBERSHIP ENFORCEMENT"
    $groupConfigurations = @(
        @{ Name = 'Enterprise Admins';           Auth = $userConfig.EnterpriseAdmins; Defaults = @('Administrator') },
        @{ Name = 'Domain Admins';               Auth = $userConfig.DomainAdmins;     Defaults = @('Administrator') },
        @{ Name = 'Schema Admins';               Auth = @();                          Defaults = @('Administrator') },
        @{ Name = 'Administrators';              Auth = $userConfig.Administrators;   Defaults = @('Administrator', 'Domain Admins', 'Enterprise Admins') },
        @{ Name = 'Account Operators';           Auth = @(); Defaults = @() },
        @{ Name = 'Backup Operators';            Auth = @(); Defaults = @() },
        @{ Name = 'Server Operators';            Auth = @(); Defaults = @() },
        @{ Name = 'Print Operators';             Auth = @(); Defaults = @() },
        @{ Name = 'DnsAdmins';                   Auth = @(); Defaults = @() },
        @{ Name = 'Group Policy Creator Owners'; Auth = @(); Defaults = @('Administrator') },
        @{ Name = 'Key Admins';                  Auth = @(); Defaults = @() },
        @{ Name = 'Enterprise Key Admins';       Auth = @(); Defaults = @() },
        @{ Name = 'Cryptographic Operators';     Auth = @(); Defaults = @() },
        @{ Name = 'Distributed COM Users';       Auth = @(); Defaults = @() },
        @{ Name = 'Event Log Readers';           Auth = @(); Defaults = @() },
        @{ Name = 'Network Configuration Operators'; Auth = @(); Defaults = @() },
        @{ Name = 'Hyper-V Administrators';      Auth = @(); Defaults = @() },
        @{ Name = 'Pre-Windows 2000 Compatible Access'; Auth = @(); Defaults = @('Authenticated Users') },
        @{ Name = 'Remote Desktop Users';        Auth = $rdpUsers;   Defaults = @() },
        @{ Name = 'Remote Management Users';     Auth = $winrmUsers; Defaults = @() }
    )
    $i = 0
    foreach ($gc in $groupConfigurations) {
        $i++; $gname = $gc.Name
        Write-SubSection "Group: $gname [$i/$($groupConfigurations.Count)]"
        $grp = $null; try { $grp = & $script:Cmd.GetADGroup -Identity $gname -Properties Member -ErrorAction Stop } catch { Write-Log "Group '$gname' not found - skipped" -Level INFO; continue }
        $members = @()
        try { $members = @(& $script:Cmd.GetADGroupMember -Identity $grp -ErrorAction Stop) } catch {
            # Fallback for foreign security principals / large groups
            try { $members = @($grp.Member | ForEach-Object { & $script:Cmd.GetADObject -Identity $_ -Properties SamAccountName, objectSid -ErrorAction SilentlyContinue }) } catch { Write-Log "Cannot enumerate '$gname': $_" -Level ERROR; continue }
        }
        $script:Stats.GroupsProcessed++
        Write-Log "Auditing '$gname' ($($members.Count) members)" -Level AUDIT
        $currentNames = @()
        foreach ($m in $members) {
            $sam = [string]$m.SamAccountName; if (-not $sam) { $sam = [string]$m.Name }
            $lsam = $sam.ToLower(); $currentNames += $lsam
            $sidStr = ''; try { $sidStr = [string]$m.SID.Value } catch {}; if (-not $sidStr) { try { $sidStr = [string]$m.objectSid.Value } catch {} }
            $isRid500 = $sidStr -eq "$domainSid-500"
            if ($excluded -contains $lsam) { & $script:Cmd.WriteHost "      [-] $sam (excluded - untouched)" -ForegroundColor Cyan; continue }
            $isDefault = ($gc.Defaults | Where-Object { $_ -ieq $sam }) -or ($isRid500 -and $gc.Defaults -contains 'Administrator')
            if ($isDefault -or ($gc.Auth -contains $lsam)) { & $script:Cmd.WriteHost "      [+] $sam" -ForegroundColor Green; continue }
            & $script:Cmd.WriteHost "      [x] $sam ($($m.objectClass))" -NoNewline -ForegroundColor Red
            if ($DryRun) { & $script:Cmd.WriteHost " [WOULD REMOVE]" -ForegroundColor Yellow; continue }
            try {
                & $script:Cmd.RemoveADGroupMember -Identity $grp -Members $m -Confirm:$false -ErrorAction Stop
                & $script:Cmd.WriteHost " [REMOVED]" -ForegroundColor Yellow
                Write-Log "Removed '$sam' from '$gname'" -Level CHANGE
                [void]$script:GroupChanges.Add([PSCustomObject]@{ Type = 'Domain Group'; Computer = 'Domain'; Group = $gname; Member = $sam; Action = 'Removed' }); $script:Stats.MembersRemoved++
            } catch {
                # Fallback: net group
                $out = & $script:Native['net.exe'] group "$gname" "$sam" /delete /domain 2>&1
                if ($LASTEXITCODE -eq 0) { & $script:Cmd.WriteHost " [REMOVED via net.exe]" -ForegroundColor Yellow; Write-Log "Removed '$sam' from '$gname' (net.exe fallback)" -Level CHANGE; $script:Stats.MembersRemoved++ }
                else { & $script:Cmd.WriteHost " [FAILED]" -ForegroundColor Red; Write-Log "Failed to remove '$sam' from '${gname}': $_ / $out" -Level ERROR }
            }
        }
        foreach ($a in $gc.Auth) {
            if (($excluded -contains $a) -or ($currentNames -contains $a)) { continue }
            $usr = $null; try { $usr = & $script:Cmd.GetADUser -Identity $a -ErrorAction Stop } catch { Write-Log "Authorized user '$a' for '$gname' does not exist in AD" -Level WARNING; continue }
            if ($DryRun) { & $script:Cmd.WriteHost "      + $a [WOULD ADD]" -ForegroundColor Yellow; continue }
            try { & $script:Cmd.AddADGroupMember -Identity $grp -Members $usr -ErrorAction Stop; & $script:Cmd.WriteHost "      + $a [ADDED]" -ForegroundColor Green; Write-Log "Added '$a' to '$gname'" -Level CHANGE; [void]$script:GroupChanges.Add([PSCustomObject]@{ Type = 'Domain Group'; Computer = 'Domain'; Group = $gname; Member = $a; Action = 'Added' }); $script:Stats.MembersAdded++ }
            catch { Write-Log "Failed to add '$a' to '${gname}': $_" -Level ERROR }
        }
    }
}

# ============================================================================
# PHASE 2: DOMAIN PASSWORD RESETS
# ============================================================================
if (-not $SkipPasswordReset) {
    Write-SectionHeader "PHASE 2: DOMAIN USER PASSWORD MANAGEMENT"
    $domainUsers = @()
    try { $domainUsers = @(& $script:Cmd.GetADUser -Filter * -Properties SamAccountName, Enabled, PasswordLastSet, LockedOut, DistinguishedName -ErrorAction Stop) } catch { Write-Log "Cannot enumerate users: $_" -Level CRITICAL; exit 1 }
    Write-Log "Processing $($domainUsers.Count) domain user objects" -Level INFO
    $skipped = 0
    foreach ($u in $domainUsers) {
        $sam = $u.SamAccountName; $lsam = $sam.ToLower()
        if ($lsam -eq 'krbtgt' -or $sam -like '*$') { $skipped++; continue }
        $uSid = ''; try { $uSid = [string]$u.SID.Value } catch {}
        $isRid500 = $uSid -eq "$domainSid-500"
        $isRid501 = $uSid -eq "$domainSid-501"
        if ($excluded -contains $lsam) {
            & $script:Cmd.WriteHost "    [-] EXCLUDED: $sam (untouched)" -ForegroundColor Cyan; $skipped++; continue
        }
        if ($isRid501) {
            if ($u.Enabled) { if ($DryRun) { Write-Log "Would disable Guest ($sam)" -Level DRYRUN } else { try { & $script:Cmd.DisableADAccount -Identity $u -ErrorAction Stop; Write-Log "Disabled Guest ($sam)" -Level CHANGE; $script:Stats.AccountsDisabled++ } catch { Write-Log "Failed to disable Guest: $_" -Level ERROR } } }
            continue
        }
        $isAuth = ($allAuthorizedUsers -contains $lsam) -or ($isRid500 -and ($allAuthorizedUsers -contains 'administrator'))
        if ($isAuth) {
            if ($DryRun) { & $script:Cmd.WriteHost "    [+] WOULD RESET: $sam" -ForegroundColor Yellow; continue }
            $pw = New-CCDCPassword -Length $PasswordLength
            if (-not (Test-CCDCPasswordComplexity $pw)) { Write-Log "Generated password failed complexity for $sam (should never happen)" -Level ERROR; continue }
            $before = Get-LdapPwdLastSet $u.DistinguishedName
            $method = ''; $ok = $false; $errs = @()
            try {
                $sec = & $script:Cmd.ConvertToSecureString -String $pw -AsPlainText -Force
                & $script:Cmd.SetADAccountPassword -Identity $u -NewPassword $sec -Reset -ErrorAction Stop
                $method = 'Set-ADAccountPassword'; $ok = $true
            } catch { $errs += "AD module: $($_.Exception.Message)" }
            if (-not $ok) { try { $de = [ADSI]("LDAP://" + $u.DistinguishedName); $de.SetPassword($pw); $de.SetInfo(); $method = 'LDAP-ADSI'; $ok = $true } catch { $errs += "ADSI: $($_.Exception.Message)" } }
            if (-not $ok) { $out = & $script:Native['net.exe'] user "$sam" "$pw" /domain 2>&1; if ($LASTEXITCODE -eq 0) { $method = 'net.exe'; $ok = $true } else { $errs += "net.exe: $out" } }
            if (-not $ok) { Write-Log "ALL reset methods FAILED for ${sam}: $($errs -join ' || ')" -Level ERROR; $script:Stats.PasswordsFailed++; continue }
            try { & $script:Cmd.SetADUser -Identity $u -ChangePasswordAtLogon $false -Enabled $true -ErrorAction Stop } catch { Write-Log "Post-reset Set-ADUser for ${sam}: $_" -Level WARNING }
            if ($u.LockedOut) { try { & $script:Cmd.UnlockADAccount -Identity $u -ErrorAction Stop; $script:Stats.AccountsUnlocked++ } catch {} }
            # --- VERIFY ---
            $after = Get-LdapPwdLastSet $u.DistinguishedName
            $advanced = ($after -gt 0 -and $after -gt $before)
            $cred = Test-DomainCredential -User $sam -Password $pw
            $verified = if ($cred -eq $true) { 'CredentialOK' } elseif ($advanced) { 'PwdLastSetAdvanced(bind-denied?)' } else { 'UNVERIFIED' }
            if ($verified -eq 'UNVERIFIED') { $script:Stats.PasswordsUnverified++; Write-Log "Reset of $sam via $method NOT verifiable (pwdLastSet unchanged, bind failed) - retrying with net.exe" -Level WARNING
                $out = & $script:Native['net.exe'] user "$sam" "$pw" /domain 2>&1
                if ($LASTEXITCODE -eq 0) { $method += '+net.exe'; $after2 = Get-LdapPwdLastSet $u.DistinguishedName; if ($after2 -gt $before) { $verified = 'PwdLastSetAdvanced(after net.exe)' } ; if ((Test-DomainCredential -User $sam -Password $pw) -eq $true) { $verified = 'CredentialOK(after net.exe)' } }
                if ($verified -ne 'UNVERIFIED') { $script:Stats.PasswordsUnverified--; $script:Stats.PasswordsVerified++ }
            } else { $script:Stats.PasswordsVerified++ }
            $script:Stats.PasswordsReset++
            [void]$script:PasswordResets.Add([PSCustomObject]@{ Type = 'Domain User'; Computer = $domainNetbios; Account = $sam; Password = $pw; Method = $method; Verified = $verified })
            & $script:Cmd.WriteHost "    [+] RESET: " -NoNewline -ForegroundColor Green
            & $script:Cmd.WriteHost "$domainNetbios\$sam  " -NoNewline -ForegroundColor White
            & $script:Cmd.WriteHost $pw -NoNewline -ForegroundColor Black -BackgroundColor Green
            & $script:Cmd.WriteHost "  [$method / $verified]" -ForegroundColor $(if ($verified -like 'CredentialOK*') { 'Green' } elseif ($verified -like 'PwdLastSet*') { 'Yellow' } else { 'Red' })
        } else {
            if ($u.Enabled) {
                if ($DryRun) { & $script:Cmd.WriteHost "    [x] WOULD DISABLE: $sam" -ForegroundColor Yellow; continue }
                $ok = $false
                try { & $script:Cmd.DisableADAccount -Identity $u -ErrorAction Stop; $ok = $true } catch { $out = & $script:Native['net.exe'] user "$sam" /active:no /domain 2>&1; $ok = ($LASTEXITCODE -eq 0) }
                $still = $true; try { $still = (& $script:Cmd.GetADUser -Identity $u -Properties Enabled -ErrorAction Stop).Enabled } catch {}
                if ($ok -and -not $still) { & $script:Cmd.WriteHost "    [x] DISABLED: $sam (unauthorized) [confirmed]" -ForegroundColor Yellow; Write-Log "Disabled unauthorized $sam" -Level CHANGE; $script:Stats.AccountsDisabled++; [void]$script:AccountChanges.Add([PSCustomObject]@{ Type = 'Domain Account'; Computer = 'Domain'; Account = $sam; Action = 'Disabled' }) }
                else { Write-Log "FAILED to disable $sam (still enabled=$still)" -Level ERROR }
            } else { $skipped++ }
        }
    }
    Write-Log "Domain users: reset=$($script:Stats.PasswordsReset) disabled=$($script:Stats.AccountsDisabled) skipped/already-disabled=$skipped" -Level INFO

    if ($ResetKrbtgt) {
        Write-SubSection "krbtgt reset (single pass)"
        if ($DryRun) { Write-Log "Would reset krbtgt password once" -Level DRYRUN } else {
            try {
                $k = & $script:Cmd.GetADUser -Identity krbtgt -Properties PasswordLastSet -ErrorAction Stop
                if ($k.PasswordLastSet -gt (Get-Date).AddHours(-10)) { Write-Log "krbtgt was already reset at $($k.PasswordLastSet) (<10h ago). Skipping to avoid breaking valid tickets." -Level WARNING }
                else { $sec = & $script:Cmd.ConvertToSecureString -String (New-CCDCPassword -Length 32) -AsPlainText -Force; & $script:Cmd.SetADAccountPassword -Identity $k -NewPassword $sec -Reset -ErrorAction Stop; Write-Log "krbtgt password reset (golden tickets invalidated after replication). Do NOT reset again for 10h." -Level CHANGE }
            } catch { Write-Log "krbtgt reset failed: $_" -Level ERROR }
        }
    }
}

# ============================================================================
# PHASE 3: AD HYGIENE (persistence tricks)
# ============================================================================
if (-not $SkipHygiene) {
    Write-SectionHeader "PHASE 3: AD ACCOUNT HYGIENE"
    try {
        $hu = @(& $script:Cmd.GetADUser -Filter * -Properties SamAccountName, Enabled, PasswordNotRequired, DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, SIDHistory, PrimaryGroupID, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, WhenCreated, AdminCount, MemberOf, UserAccountControl, UseDESKeyOnly, PasswordNeverExpires, LastLogonDate -ErrorAction Stop)
    } catch { $hu = @(); Write-Log "Hygiene enumeration failed: $_" -Level ERROR }
    $fixable = @()
    foreach ($u in $hu) {
        $sam = $u.SamAccountName; $lsam = $sam.ToLower()
        if ($lsam -eq 'krbtgt' -or $sam -like '*$') { continue }
        $isEx = $excluded -contains $lsam
        $uSid = ''; try { $uSid = [string]$u.SID.Value } catch {}
        $isBuiltin = ($uSid -eq "$domainSid-500" -or $uSid -eq "$domainSid-501")
        $issues = @()
        if ($u.PasswordNotRequired) { $issues += 'PasswordNotRequired' }
        if ($u.DoesNotRequirePreAuth) { $issues += 'NoKerbPreAuth(AS-REP roastable)' }
        if ($u.AllowReversiblePasswordEncryption) { $issues += 'ReversibleEncryption' }
        if ($u.SIDHistory -and $u.SIDHistory.Count -gt 0) { $issues += "SIDHistory($($u.SIDHistory -join ','))" }
        if ($u.PrimaryGroupID -ne 513 -and $u.PrimaryGroupID -ne 514 -and -not $isBuiltin) { $issues += "PrimaryGroupID=$($u.PrimaryGroupID)" }
        if ($u.TrustedForDelegation) { $issues += 'TrustedForDelegation' }
        if ($u.TrustedToAuthForDelegation) { $issues += 'TrustedToAuthForDelegation' }
        if ($u.ServicePrincipalNames -and $u.ServicePrincipalNames.Count -gt 0) { $issues += "SPNs($($u.ServicePrincipalNames.Count),kerberoastable)" }
        if ($u.WhenCreated -gt (Get-Date).AddDays(-7)) { $issues += "CreatedRecently($($u.WhenCreated.ToString('MM-dd HH:mm')))" }
        if ($u.AdminCount -eq 1 -and -not $u.MemberOf) { $issues += 'AdminCount=1(orphaned)' }
        if ($u.UseDESKeyOnly) { $issues += 'DESOnlyKerberos(crackable)' }
        if ($u.PasswordNeverExpires -and $u.Enabled) { $issues += 'PasswordNeverExpires' }                       # report only: may be a service account
        if ($u.Enabled -and $u.LastLogonDate -and $u.LastLogonDate -lt (Get-Date).AddDays(-90)) { $issues += "Stale(lastLogon $($u.LastLogonDate.ToString('yyyy-MM-dd')))" }   # report only
        if ($issues.Count -eq 0) { continue }
        [void]$script:HygieneFindings.Add([PSCustomObject]@{ Account = $sam; Enabled = $u.Enabled; Excluded = $isEx; Issues = ($issues -join ', ') })
        & $script:Cmd.WriteHost ("    [{0}] {1,-24} {2}" -f $(if ($isEx) { '-' } else { '!' }), $sam, ($issues -join ', ')) -ForegroundColor $(if ($isEx) { 'Cyan' } else { 'Yellow' })
        if ($isEx) { continue }
        # Fix what is safe to fix
        $set = @{}
        if ($u.PasswordNotRequired) { $set.PasswordNotRequired = $false }
        if ($u.DoesNotRequirePreAuth) { $set.DoesNotRequirePreAuth = $false }
        if ($u.AllowReversiblePasswordEncryption) { $set.AllowReversiblePasswordEncryption = $false }
        if ($u.TrustedForDelegation) { $set.TrustedForDelegation = $false }
        $fixPG = ($u.PrimaryGroupID -ne 513 -and $u.PrimaryGroupID -ne 514 -and -not $isBuiltin)
        $fixSID = ($u.SIDHistory -and $u.SIDHistory.Count -gt 0)
        $fixDES = [bool]$u.UseDESKeyOnly      # DES is dead; nothing modern needs it. AES keys stay, so logons keep working.
        if ($set.Count -eq 0 -and -not $fixPG -and -not $fixSID -and -not $fixDES) { continue }
        if ($DryRun) { Write-Log "Would fix $sam : $($set.Keys -join ',')$(if ($fixPG) {' PrimaryGroupID->513'})$(if ($fixSID) {' clear SIDHistory'})$(if ($fixDES) {' UseDESKeyOnly->false'})" -Level DRYRUN; continue }
        try {
            if ($set.Count -gt 0) { & $script:Cmd.SetADUser -Identity $u @set -ErrorAction Stop }
            if ($fixPG) { & $script:Cmd.SetADObject -Identity $u.DistinguishedName -Replace @{ primaryGroupID = 513 } -ErrorAction Stop }
            if ($fixSID) { & $script:Cmd.SetADObject -Identity $u.DistinguishedName -Clear sIDHistory -ErrorAction Stop }
            if ($fixDES) { & $script:Cmd.SetADAccountControl -Identity $u -UseDESKeyOnly $false -ErrorAction Stop }
            Write-Log "Fixed $sam : $($set.Keys -join ',')$(if ($fixPG) {' PrimaryGroupID->513'})$(if ($fixSID) {' SIDHistory cleared'})$(if ($fixDES) {' DES-only cleared'})" -Level CHANGE; $script:Stats.HygieneFixes++
        } catch { Write-Log "Hygiene fix failed for ${sam}: $_" -Level ERROR }
    }
    if ($script:HygieneFindings.Count -eq 0) { Write-Log "No hygiene issues found" -Level SUCCESS } else { Write-Log "$($script:HygieneFindings.Count) accounts with findings (SPNs / recent-creation / PasswordNeverExpires / Stale are report-only)" -Level AUDIT }

    # Password policy sanity (Red Team likes minpwlen 0 / reversible encryption on the default domain policy)
    try {
        $pol = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        Write-Log "Default domain password policy: MinLen=$($pol.MinPasswordLength) Complexity=$($pol.ComplexityEnabled) Reversible=$($pol.ReversibleEncryptionEnabled) Lockout=$($pol.LockoutThreshold) History=$($pol.PasswordHistoryCount)" -Level AUDIT
        if ($pol.ReversibleEncryptionEnabled -or -not $pol.ComplexityEnabled -or $pol.MinPasswordLength -lt 8) { Write-Log "Default domain password policy is WEAK - Harden.ps1 will set STIG values (or fix via GPMC)" -Level WARNING }
    } catch {}
}

# ============================================================================
# PHASE 4: REMOTE MEMBER SERVERS (one round trip each)
# ============================================================================
if (-not $SkipRemoteServers -and $windowsComputers.Count -gt 0 -and -not ($SkipGroupAudit -and $SkipPasswordReset)) {
    Write-SectionHeader "PHASE 4: MEMBER SERVER LOCAL GROUPS & USERS"
    $n = 0
    foreach ($cn in $windowsComputers) {
        $n++; Write-SubSection "Server: $cn [$n/$($windowsComputers.Count)]"
        try {
            $json = & $script:Cmd.InvokeCommand -ComputerName $cn -ScriptBlock $script:LocalWorker -ArgumentList $workerConfig, $workerOptions -ErrorAction Stop
            Show-WorkerReport -Json $json -Label $cn
            $script:Stats.ServersProcessed++
        } catch { Write-Log "Worker failed on ${cn}: $_  -> copy this script + config to $cn and run:  powershell -NoProfile -File .\User_Audit.ps1 -Local" -Level ERROR; $script:Stats.ServersFailed++ }
    }
}

} # end domain mode

# ============================================================================
# SUMMARY
# ============================================================================
$end = Get-Date
Write-SectionHeader "SUMMARY"
& $script:Cmd.WriteHost ("  Duration: {0:mm}m {0:ss}s   Groups: {1}  Removed: {2}  Added: {3}" -f ($end - $script:StartTime), $script:Stats.GroupsProcessed, $script:Stats.MembersRemoved, $script:Stats.MembersAdded)
& $script:Cmd.WriteHost ("  Passwords reset: {0}  verified: {1}  unverified: {2}  FAILED: {3}" -f $script:Stats.PasswordsReset, $script:Stats.PasswordsVerified, $script:Stats.PasswordsUnverified, $script:Stats.PasswordsFailed) -ForegroundColor $(if ($script:Stats.PasswordsFailed -gt 0 -or $script:Stats.PasswordsUnverified -gt 0) { 'Yellow' } else { 'Green' })
& $script:Cmd.WriteHost ("  Accounts disabled: {0}  unlocked: {1}  hygiene fixes: {2}  servers: {3} ok / {4} failed" -f $script:Stats.AccountsDisabled, $script:Stats.AccountsUnlocked, $script:Stats.HygieneFixes, $script:Stats.ServersProcessed, $script:Stats.ServersFailed)
& $script:Cmd.WriteHost ("  Warnings: {0}  Errors: {1}" -f $script:Warnings.Count, $script:Errors.Count) -ForegroundColor $(if ($script:Errors.Count -gt 0) { 'Red' } else { 'Gray' })
if ($DryRun) { & $script:Cmd.WriteHost "`n  DRY RUN - nothing was changed" -ForegroundColor Yellow -BackgroundColor DarkBlue }

if ($script:PasswordResets.Count -gt 0) {
    Write-SubSection "ALL PASSWORDS - RECORD NOW (terminal only unless -ExportPasswords)"
    foreach ($r in $script:PasswordResets) {
        & $script:Cmd.WriteHost ("      {0}\{1,-22} " -f $r.Computer, $r.Account) -NoNewline -ForegroundColor Cyan
        & $script:Cmd.WriteHost $r.Password -NoNewline -ForegroundColor Black -BackgroundColor Green
        & $script:Cmd.WriteHost ("  {0} / {1}" -f $r.Method, $r.Verified) -ForegroundColor $(if ($r.Verified -like 'CredentialOK*') { 'Green' } elseif ($r.Verified -like 'PwdLastSet*') { 'Yellow' } else { 'Red' })
    }
    if ($ExportPasswords) {
        try { $script:PasswordResets | & $script:Cmd.ExportCsv -Path $ExportPasswords -NoTypeInformation -Force -ErrorAction Stop; Write-Log "Passwords exported to $ExportPasswords - move it off-box and delete it" -Level WARNING } catch { Write-Log "Export failed: $_" -Level ERROR }
    }
    $unv = @($script:PasswordResets | Where-Object { $_.Verified -notlike 'CredentialOK*' -and $_.Verified -notlike 'PwdLastSet*' })
    if ($unv.Count -gt 0) { & $script:Cmd.WriteHost "`n  !! $($unv.Count) reset(s) could NOT be verified - test these logins manually: $(($unv | ForEach-Object { "$($_.Computer)\$($_.Account)" }) -join ', ')" -ForegroundColor Red }
}
if ($script:GroupChanges.Count -gt 0) { Write-SubSection "Group changes"; $script:GroupChanges | Format-Table Type, Computer, Group, Member, Action -AutoSize | Out-String | & $script:Cmd.WriteHost }
if ($script:AccountChanges.Count -gt 0) { Write-SubSection "Account changes"; $script:AccountChanges | Format-Table Type, Computer, Account, Action -AutoSize | Out-String | & $script:Cmd.WriteHost }
if ($script:HygieneFindings.Count -gt 0) { Write-SubSection "Hygiene findings"; $script:HygieneFindings | Format-Table Account, Enabled, Excluded, Issues -AutoSize -Wrap | Out-String | & $script:Cmd.WriteHost }
if ($script:Errors.Count -gt 0) { Write-SubSection "Errors"; $script:Errors | ForEach-Object { & $script:Cmd.WriteHost "      [$($_.Timestamp.ToString('HH:mm:ss'))] $($_.Message)" -ForegroundColor Red } }

Write-SectionHeader "NEXT STEPS"
& $script:Cmd.WriteHost "  [ ] Record passwords; verify one RDP and one WinRM login with new creds" -ForegroundColor White
& $script:Cmd.WriteHost "  [ ] Confirm scoring services still pass (excluded accounts untouched)" -ForegroundColor White
& $script:Cmd.WriteHost "  [ ] Run the C redundancy tool (audit.exe) if any reset shows UNVERIFIED" -ForegroundColor White
& $script:Cmd.WriteHost "  [ ] For UNREACHABLE servers: copy script+config, run  powershell -NoProfile -File User_Audit.ps1 -Local" -ForegroundColor White
& $script:Cmd.WriteHost "  [ ] Then run Harden.ps1 (-Mode Audit first, then -Mode Apply)" -ForegroundColor White
& $script:Cmd.WriteHost "  [ ] Clear-History ; Remove-Item (Get-PSReadlineOption).HistorySavePath" -ForegroundColor Gray
& $script:Cmd.WriteHost ""

# Scrub secrets from memory
$script:PasswordResets.Clear(); [GC]::Collect()
