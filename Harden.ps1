# ============================================================================
# CCDC Windows Hardening - v3 (STIG-driven, HardeningKitty-style)
# ============================================================================
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Audit
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Apply
#   .\Harden.ps1 -Mode Apply -AllDomain            (from a DC: every reachable Windows box)
#   .\Harden.ps1 -Mode Audit -ComputerName WEB01,SQL01 -ReportCsv .\stig.csv
#
# ============================================================================

#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Audit and apply the DISA STIG for Windows Server (member / DC), plus CCDC
    operational hardening, on this machine or across the domain.

.DESCRIPTION
    Modeled on scipag/HardeningKitty: a finding list (ID, method, path, item,
    recommended value, severity) is evaluated in Audit mode and enforced in
    Apply mode.  IDs are the V-numbers from the DoD Windows Server 2019 STIG
    (HardeningKitty finding_list_dod_microsoft_windows_server_2019_*_stig).
    Items whose STIG value would break a CCDC environment are still AUDITED
    but marked CCDC-SKIP with the reason, so nothing deviates silently.

    Methods implemented natively (no external binaries besides secedit/auditpol
    /wevtutil from System32):
      Registry, AccountPolicy, SecOption, UserRight (secedit), AuditPol,
      Service, Feature, FirewallProfile, MpPref, AsrRule, EventLog

    CCDC operational modules (Apply mode, switch-able):
      role detection + role-based firewall allow-list (safety net keeps every
      currently-listening port and REPORTS ports not explained by a role),
      unnecessary service disable, LOLBin outbound block, Defender enable and
      signature update, PowerShell v2 / SMBv1 removal, IIS hardening (never
      touches anonymous auth - scoring engines browse anonymously), SQL audit
      (read-only), scheduled-task audit, service-persistence watchdog,
      optional PII scan, DC service verification.

.PARAMETER Mode           Audit (default) or Apply
.PARAMETER ComputerName   Remote targets (WinRM). Default: this machine only.
.PARAMETER AllDomain      From a DC: discover and target all Windows computers.
.PARAMETER Role           Auto (default) | DC | Member  - which STIG list to use
.PARAMETER LockoutThreshold  STIG says 3. Red Team can lock out your accounts
                          with bad logons; 0 disables lockout. Default 3.
.PARAMETER SkipFirewall / SkipServices / SkipPersistence / SkipDefender / SkipIIS
.PARAMETER SkipBanner     Do not set the logon legal notice
.PARAMETER RenameBuiltins Rename Administrator/Guest (STIG). Off by default:
                          may break scoring that logs in as 'Administrator'.
.PARAMETER IncludeRisky   Also APPLY the CCDC-SKIP items (LDAP signing required,
                          FIPS, Credential Guard/VBS, deny DA network logon...)
.PARAMETER PIIScan        Scan user folders / inetpub for SSN-like content (slow)
.PARAMETER BootstrapWinRM During -AllDomain / -ComputerName fan-out, enable WinRM
                          on targets that do not answer, via CIM/WMI over DCOM
                          (the DC's Kerberos context), so workstations with
                          remoting off still get hardened. Off by default.
.PARAMETER EnableSSH      Install/enable OpenSSH Server as a REDUNDANT admin
                          channel (tcp/22) so blue team keeps access if WinRM is
                          tampered with. Adds the PowerShell-over-SSH subsystem
                          (needs pwsh for PS remoting; interactive shell works
                          either way) and is kept alive by the watchdog.
.PARAMETER SSHKeyOnly     With -EnableSSH, disable SSH password auth (key only).
.PARAMETER SSHPublicKey   With -EnableSSH, an OpenSSH public key line to install
                          for administrators (administrators_authorized_keys).
.PARAMETER AsrAuditMode   Apply Defender ASR rules / PUA / Network Protection in
                          AUDIT mode (log only, never block) instead of Block.
                          Use first if you are worried about breaking apps; review
                          Defender events 1121/1122, then re-run without it.
                          Rules already in Block are left in Block.
.PARAMETER LogDir         Where the transcript, auditpol/secedit backups and the
                          old->new change CSV are written (default C:\HardeningLogs).
                          Everything needed to roll back lives here.
.PARAMETER ReportCsv      Write the per-finding results to a CSV
.PARAMETER RemoteOptions  (internal) options hashtable when invoked over WinRM

.NOTES
    Reboot-required items are flagged in the report (EnableLUA, SMB1/PSv2
    feature removal, VBS, FIPS).  Nothing reboots automatically.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)][hashtable]$RemoteOptions,
    [ValidateSet('Audit', 'Apply')][string]$Mode = 'Audit',
    [string[]]$ComputerName,
    [switch]$AllDomain,
    [ValidateSet('Auto', 'DC', 'Member')][string]$Role = 'Auto',
    [ValidateRange(0, 50)][int]$LockoutThreshold = 3,
    [switch]$SkipFirewall, [switch]$SkipServices, [switch]$SkipPersistence, [switch]$SkipDefender, [switch]$SkipIIS,
    [switch]$SkipBanner, [switch]$RenameBuiltins, [switch]$IncludeRisky, [switch]$PIIScan,
    [switch]$BootstrapWinRM,
    [switch]$EnableSSH, [switch]$SSHKeyOnly, [string]$SSHPublicKey,
    [switch]$AsrAuditMode,
    [string]$LogDir = 'C:\HardeningLogs',
    [string]$ReportCsv
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# When invoked remotely via Invoke-Command -FilePath, the options arrive as a hashtable
if ($RemoteOptions) {
    foreach ($k in $RemoteOptions.Keys) { Set-Variable -Name $k -Value $RemoteOptions[$k] -Scope Script -Force }
    $ComputerName = $null; $AllDomain = $false
    $script:IsRemoteRun = $true
} else { $script:IsRemoteRun = $false }

# ============================================================================
# 0. Environment sanitization (compact version of User_Audit.ps1 Phase 0)
# ============================================================================
$ic = $ExecutionContext.SessionState.InvokeCommand
foreach ($h in 'PreCommandLookupAction', 'PostCommandLookupAction', 'CommandNotFoundAction') { if ($ic.$h) { $ic.$h = $null; Microsoft.PowerShell.Utility\Write-Host "  [FIX] cleared command hook $h" -ForegroundColor Magenta } }
if ($PSDefaultParameterValues.Count -gt 0) { Microsoft.PowerShell.Utility\Write-Host "  [FIX] cleared PSDefaultParameterValues: $($PSDefaultParameterValues.Keys -join ',')" -ForegroundColor Magenta; $PSDefaultParameterValues.Clear() }
$env:PSModulePath = (Microsoft.PowerShell.Management\Join-Path $PSHOME 'Modules') + ';' + (Microsoft.PowerShell.Management\Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
$cmdletNames = @{}; foreach ($c in (Microsoft.PowerShell.Core\Get-Command -CommandType Cmdlet -ErrorAction SilentlyContinue)) { $cmdletNames[$c.Name.ToLower()] = $true }
$natives = 'secedit', 'auditpol', 'wevtutil', 'net', 'net1', 'sc', 'netsh', 'reg', 'dism'
foreach ($a in @(Microsoft.PowerShell.Utility\Get-Alias -ErrorAction SilentlyContinue)) {
    $n = $a.Name.ToLower()
    if ($cmdletNames.ContainsKey($n) -or ($natives -contains $n) -or ($n -like '*-*')) { try { Microsoft.PowerShell.Management\Remove-Item "Alias:\$($a.Name)" -Force -ErrorAction Stop; Microsoft.PowerShell.Utility\Write-Host "  [FIX] removed shadowing alias $($a.Name) -> $($a.Definition)" -ForegroundColor Magenta } catch {} }
}
foreach ($f in @(Microsoft.PowerShell.Management\Get-ChildItem Function:\ -ErrorAction SilentlyContinue)) {
    $n = $f.Name.ToLower()
    if ($f.Module -and $f.Module.ModuleBase -like "$PSHOME*") { continue }
    if ($cmdletNames.ContainsKey($n) -or ($natives -contains $n)) { try { Microsoft.PowerShell.Management\Remove-Item "Function:\$($f.Name)" -Force -ErrorAction Stop; Microsoft.PowerShell.Utility\Write-Host "  [FIX] removed shadowing function $($f.Name)" -ForegroundColor Magenta } catch {} }
}
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($bin in 'secedit.exe', 'auditpol.exe', 'wevtutil.exe', 'net.exe', 'net1.exe', 'powershell.exe', 'cmd.exe', 'netsh.exe', 'sc.exe', 'reg.exe') {
    $k = "$ifeo\$bin"; if (Test-Path $k) { $d = (Get-ItemProperty $k -Name Debugger -ErrorAction SilentlyContinue).Debugger; if ($d) { if ($Mode -eq 'Apply') { Remove-ItemProperty $k -Name Debugger -Force -ErrorAction SilentlyContinue; Write-Host "  [FIX] IFEO debugger hijack on $bin ('$d') removed" -ForegroundColor Magenta } else { Write-Host "  [WARN] IFEO debugger hijack on $bin ('$d') - Apply mode removes it" -ForegroundColor Yellow } } }
}
$Bin = @{}; foreach ($b in 'secedit.exe', 'auditpol.exe', 'wevtutil.exe', 'net.exe', 'sc.exe', 'netsh.exe') { $Bin[$b] = Join-Path $env:SystemRoot "System32\$b" }

# ============================================================================
# Logging
# ============================================================================
$script:Results = [System.Collections.ArrayList]::new()
$script:Log = [System.Collections.ArrayList]::new()
$script:RebootNeeded = [System.Collections.ArrayList]::new()
$script:Suspicious = [System.Collections.ArrayList]::new()
$script:Changes = [System.Collections.ArrayList]::new()     # old -> new records for rollback
$script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:AuditPolBackedUp = $false
try { New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction Stop | Out-Null } catch { $LogDir = Join-Path $env:TEMP 'HardeningLogs'; New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction SilentlyContinue | Out-Null }
$script:TranscriptOn = $false
try { Start-Transcript -Path (Join-Path $LogDir "harden-$env:COMPUTERNAME-$script:Stamp.txt") -Force -ErrorAction Stop | Out-Null; $script:TranscriptOn = $true } catch {}
function Add-Change([string]$Item, $Old, $New, [string]$Why) {
    [void]$script:Changes.Add([PSCustomObject]@{ Time = (Get-Date -Format s); Computer = $env:COMPUTERNAME; Item = $Item; Old = [string]$Old; New = [string]$New; Why = $Why })
}
function Write-Log([string]$Message, [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'CHANGE', 'AUDIT')][string]$Level = 'INFO') {
    [void]$script:Log.Add([PSCustomObject]@{ T = Get-Date; L = $Level; M = $Message })
    $c = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'CHANGE' { 'Magenta' } 'AUDIT' { 'Cyan' } default { 'Gray' } }
    Write-Host ("[{0}] [{1,-6}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $c
}
function Write-Section([string]$t) { Write-Host "`n$('=' * 80)`n  $t`n$('=' * 80)" -ForegroundColor Cyan }
function Write-Sub([string]$t) { Write-Host "`n  $t" -ForegroundColor Yellow; Write-Host ("  " + '-' * 76) -ForegroundColor DarkGray }

# ============================================================================
# Machine facts
# ============================================================================
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$script:IsDC = ($cs.DomainRole -ge 4)
if ($Role -eq 'Auto') { $Role = if ($script:IsDC) { 'DC' } else { 'Member' } }
$script:IsDomainJoined = $cs.PartOfDomain
$script:HasADModule = $false
if ($script:IsDC) { try { Import-Module (Join-Path $PSHOME 'Modules\ActiveDirectory') -ErrorAction Stop -DisableNameChecking; $script:HasADModule = $true } catch {} }

Write-Section "CCDC HARDENING v3 - $($env:COMPUTERNAME)  [$Mode]  STIG profile: $Role"
Write-Host "  $($os.Caption) build $($os.BuildNumber)   Domain: $($cs.Domain)   DomainRole: $($cs.DomainRole)   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
# platform posture (report only)
$sb = try { if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'on' } else { 'OFF' } } catch { 'n/a' }
$hvci = try { if ((Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop).SecurityServicesRunning -contains 2) { 'running' } else { 'off' } } catch { 'n/a' }
$hf = try { (Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1); } catch { $null }
Write-Host "  SecureBoot: $sb   HVCI: $hvci   Last hotfix: $(if ($hf) { "$($hf.HotFixID) $($hf.InstalledOn.ToString('yyyy-MM-dd'))" } else { 'unknown' })   Log dir: $LogDir" -ForegroundColor Gray

# ============================================================================
# Fan-out to remote computers (then exit)
# ============================================================================
if (-not $script:IsRemoteRun -and ($ComputerName -or $AllDomain)) {
    $targets = @()
    if ($AllDomain) {
        if (-not $script:HasADModule) { try { Import-Module ActiveDirectory -ErrorAction Stop; $script:HasADModule = $true } catch { Write-Log "ActiveDirectory module required for -AllDomain" 'ERROR'; exit 1 } }
        $targets = @(Get-ADComputer -Filter { OperatingSystem -like '*Windows*' -and Enabled -eq $true } -Properties DNSHostName | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    }
    if ($ComputerName) { $targets += $ComputerName }
    $targets = @($targets | Select-Object -Unique)
    $opts = @{ Mode = $Mode; Role = 'Auto'; LockoutThreshold = $LockoutThreshold; SkipFirewall = [bool]$SkipFirewall; SkipServices = [bool]$SkipServices; SkipPersistence = [bool]$SkipPersistence; SkipDefender = [bool]$SkipDefender; SkipIIS = [bool]$SkipIIS; SkipBanner = [bool]$SkipBanner; RenameBuiltins = [bool]$RenameBuiltins; IncludeRisky = [bool]$IncludeRisky; PIIScan = [bool]$PIIScan; EnableSSH = [bool]$EnableSSH; SSHKeyOnly = [bool]$SSHKeyOnly; SSHPublicKey = $SSHPublicKey; AsrAuditMode = [bool]$AsrAuditMode; LogDir = $LogDir }

    # WinRM bootstrap over DCOM: turn remoting on for hosts that do not answer
    function Invoke-WinRMBootstrap([string]$Target) {
        $cmd = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
        'try { Enable-PSRemoting -Force -SkipNetworkProfileCheck } catch {};' +
        'Set-Service WinRM -StartupType Automatic -ErrorAction SilentlyContinue;' +
        'Start-Service WinRM -ErrorAction SilentlyContinue;' +
        'netsh advfirewall firewall set rule group=\"Windows Remote Management\" new enable=Yes"'
        $sess = $null
        try {
            $sess = New-CimSession -ComputerName $Target -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop
            $r = Invoke-CimMethod -CimSession $sess -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
            return ($r.ReturnValue -eq 0)
        } catch { return $false }
        finally { if ($sess) { Remove-CimSession $sess -ErrorAction SilentlyContinue } }
    }

    $all = @()
    foreach ($t in $targets) {
        Write-Section "REMOTE: $t"
        try {
            $r = Invoke-Command -ComputerName $t -FilePath $PSCommandPath -ArgumentList $opts -ErrorAction Stop
            $all += @($r | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Id'] })
        } catch {
            if ($BootstrapWinRM) {
                Write-Log "$t unreachable - attempting WinRM bootstrap over DCOM" 'WARN'
                if (Invoke-WinRMBootstrap $t) {
                    Start-Sleep -Seconds 6
                    try {
                        $r = Invoke-Command -ComputerName $t -FilePath $PSCommandPath -ArgumentList $opts -ErrorAction Stop
                        $all += @($r | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Id'] })
                        Write-Log "$t hardened after bootstrap" 'OK'
                        continue
                    } catch {}
                }
            }
            Write-Log "$t failed: $_   -> copy Harden.ps1 to it and run locally$(if (-not $BootstrapWinRM) { ' (or re-run with -BootstrapWinRM)' })" 'ERROR'
        }
    }
    # include this DC itself when -AllDomain
    if ($AllDomain -and -not ($targets | Where-Object { $_ -ieq $env:COMPUTERNAME -or $_ -ilike "$env:COMPUTERNAME.*" })) {
        Write-Section "LOCAL: $env:COMPUTERNAME"
        $all += @(& $PSCommandPath $opts | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Id'] })
    }
    if ($ReportCsv) { $all | Export-Csv -Path $ReportCsv -NoTypeInformation -Force; Write-Log "Report written: $ReportCsv ($($all.Count) rows)" 'OK' }
    Write-Section "DOMAIN SUMMARY"
    $all | Group-Object Computer | ForEach-Object { $p = @($_.Group | Where-Object Status -in 'Pass', 'Fixed').Count; $f = @($_.Group | Where-Object Status -in 'Fail', 'FixFailed').Count; $s = @($_.Group | Where-Object Status -like 'CCDC-SKIP*').Count; Write-Host ("  {0,-30} pass/fixed {1,3}   fail {2,3}   ccdc-skip {3,3}" -f $_.Name, $p, $f, $s) -ForegroundColor $(if ($f -gt 0) { 'Yellow' } else { 'Green' }) }
    Write-Host "  Per-host rollback material (transcript, auditpol/secedit backups, changes CSV) is in $LogDir on EACH target." -ForegroundColor Gray
    if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch {} }
    exit 0
}

# ============================================================================
# secedit cache (one export, one configure)
# ============================================================================
$script:SecTemp = Join-Path $env:TEMP ("ccdc-sec-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:SecTemp -Force | Out-Null
$script:SecExport = Join-Path $script:SecTemp 'export.inf'
$script:SecPolicy = @{}       # section -> @{ key = value }
$script:SecPending = @{ 'System Access' = @{}; 'Privilege Rights' = @{} }
$script:SecLoaded = $false
function Load-SecPolicy {
    & $Bin['secedit.exe'] /export /cfg $script:SecExport /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    if (-not (Test-Path $script:SecExport)) { Write-Log "secedit export failed - UserRight/SecOption findings will NOT be evaluated or applied" 'ERROR'; return }
    # keep a rollback copy of the pre-change policy:  secedit /configure /db x.sdb /cfg <this file> /areas SECURITYPOLICY USER_RIGHTS
    if ($Mode -eq 'Apply') { try { Copy-Item $script:SecExport (Join-Path $LogDir "secedit-before-$script:Stamp.inf") -Force -ErrorAction Stop } catch {} }
    $sec = ''
    foreach ($line in (Get-Content $script:SecExport -Encoding Unicode)) {
        if ($line -match '^\[(.+)\]$') { $sec = $matches[1]; if (-not $script:SecPolicy.ContainsKey($sec)) { $script:SecPolicy[$sec] = @{} }; continue }
        if ($sec -and $line -match '^\s*([^=]+?)\s*=\s*(.*)$') { $script:SecPolicy[$sec][$matches[1]] = $matches[2].Trim() }
    }
    $script:SecLoaded = ($script:SecPolicy.ContainsKey('Privilege Rights') -and $script:SecPolicy['Privilege Rights'].Count -gt 0)
    if (-not $script:SecLoaded) { Write-Log "secedit export contained no [Privilege Rights] - UserRight/SecOption findings will NOT be evaluated or applied" 'ERROR' }
}
function Get-SecValue([string]$Section, [string]$Key) { if ($script:SecPolicy[$Section] -and $script:SecPolicy[$Section].ContainsKey($Key)) { return $script:SecPolicy[$Section][$Key] }; return $null }
function Flush-SecPolicy {
    $sa = $script:SecPending['System Access']; $pr = $script:SecPending['Privilege Rights']
    if ($sa.Count -eq 0 -and $pr.Count -eq 0) { return $true }
    $inf = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    if ($sa.Count -gt 0) { $inf += '[System Access]'; foreach ($k in $sa.Keys) { $inf += "$k = $($sa[$k])" } }
    if ($pr.Count -gt 0) { $inf += '[Privilege Rights]'; foreach ($k in $pr.Keys) { $inf += "$k = $($pr[$k])" } }
    $cfg = Join-Path $script:SecTemp 'apply.inf'; $db = Join-Path $script:SecTemp 'apply.sdb'
    $inf | Out-File -FilePath $cfg -Encoding Unicode -Force
    $areas = @(); if ($sa.Count) { $areas += 'SECURITYPOLICY' }; if ($pr.Count) { $areas += 'USER_RIGHTS' }
    $secArgs = @('/configure', '/db', $db, '/cfg', $cfg, '/areas') + $areas + @('/quiet')
    $out = & $Bin['secedit.exe'] @secArgs 2>&1
    $ok = ($LASTEXITCODE -eq 0)
    if ($ok) { Write-Log "secedit applied $($sa.Count) System Access + $($pr.Count) User Rights changes" 'CHANGE' } else { Write-Log "secedit configure failed ($LASTEXITCODE): $out  see $env:windir\security\logs\scesrv.log" 'ERROR' }
    # re-load for verification
    $script:SecPolicy = @{}; Load-SecPolicy
    return $ok
}
Load-SecPolicy

# well-known SIDs used in user-rights recommendations
$S = @{
    Admins = '*S-1-5-32-544'; Users = '*S-1-5-32-545'; Guests = '*S-1-5-32-546'; BackupOps = '*S-1-5-32-551'; RDPUsers = '*S-1-5-32-555'
    RMUsers = '*S-1-5-32-580'; IIS = '*S-1-5-32-568'; AuthUsers = '*S-1-5-11'; Service = '*S-1-5-6'; LocalSvc = '*S-1-5-19'; NetSvc = '*S-1-5-20'
    LocalAccount = '*S-1-5-113'; EDC = '*S-1-5-9'; WinMgr = '*S-1-5-90-0'; VMs = '*S-1-5-83-0'; Everyone = '*S-1-1-0'; Network = '*S-1-5-2'
}

# ============================================================================
# FINDING LIST  (IDs: DoD Windows Server 2019 STIG v2r1 via HardeningKitty;
#                CCDC-* = CCDC operational extras)
#   F Id Method Name A B Rec [Type] [Op] [Sev] [Scope] [Note] [Skip]
#   Registry: A=Path B=Item     AuditPol: A=GUID           UserRight: A=Privilege Rec=@(SIDs) Op=Exact|MaxSet|MinSet
#   AccountPolicy/SecOption: A=secedit key                  Service/Feature: A=name  FirewallProfile: A=profile B=prop
#   MpPref: B=property   AsrRule: A=GUID   EventLog: A=log Rec=KB
# ============================================================================
function F { param($Id, $Method, $Name, $A, $B, $Rec, $Type = 'DWord', $Op = '=', $Sev = 'Medium', $Scope = 'All', $Note = '', $Skip = '')
    [PSCustomObject]@{ Id = $Id; Method = $Method; Name = $Name; A = $A; B = $B; Rec = $Rec; Type = $Type; Op = $Op; Sev = $Sev; Scope = $Scope; Note = $Note; Skip = $Skip } }

$LSA = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $POLSYS = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$NETLOGON = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; $WKS = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; $SRV = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$TS = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; $WINRM = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM'; $PS = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$banner = "This system is for authorized use only. All activity is monitored and logged. Unauthorized access is prohibited and will be prosecuted."

$Findings = @(
    # ---------------- Account Policies ----------------
    F 'V-93479' 'AccountPolicy' 'Password history 24' 'PasswordHistorySize' $null 24 'Int' '>='
    F 'V-93477' 'AccountPolicy' 'Maximum password age <= 60 days' 'MaximumPasswordAge' $null 60 'Int' '<='
    F 'V-93471' 'AccountPolicy' 'Minimum password age >= 1 day' 'MinimumPasswordAge' $null 1 'Int' '>='
    F 'V-93463' 'AccountPolicy' 'Minimum password length >= 14' 'MinimumPasswordLength' $null 14 'Int' '>='
    F 'V-93459' 'SecOption' 'Password complexity enabled' 'PasswordComplexity' $null 1
    F 'V-93465' 'SecOption' 'Reversible encryption disabled' 'ClearTextPassword' $null 0 'DWord' '=' 'High'
    F 'V-93141' 'AccountPolicy' "Account lockout threshold ($LockoutThreshold)" 'LockoutBadCount' $null $LockoutThreshold 'Int' 'Lockout' 'Medium' 'All' 'Red Team can lock accounts via bad logons; tune with -LockoutThreshold (0=off)'
    F 'V-93145' 'AccountPolicy' 'Lockout duration >= 15 min' 'LockoutDuration' $null 15 'Int' '>='
    F 'V-93143' 'AccountPolicy' 'Lockout counter reset >= 15 min' 'ResetLockoutCount' $null 15 'Int' '>='
    F 'V-93497' 'SecOption' 'Guest account disabled' 'EnableGuestAccount' $null 0
    F 'V-93281' 'SecOption' 'Rename built-in Administrator (-> CCDC_Admin)' 'NewAdministratorName' $null '"Administrator"' 'String' '!=' 'Medium' 'All' 'Enable with -RenameBuiltins' $(if (-not $RenameBuiltins) { 'May break scoring/judges that log in as Administrator' })
    F 'V-93283' 'SecOption' 'Rename built-in Guest (-> CCDC_Visitor)' 'NewGuestName' $null '"Guest"' 'String' '!=' 'Low' 'All' 'Enable with -RenameBuiltins' $(if (-not $RenameBuiltins) { 'Cosmetic; Guest is disabled anyway' })
    F 'V-93289' 'SecOption' 'No anonymous SID/Name translation' 'LSAAnonymousNameLookup' $null 0 'DWord' '=' 'High'
    # ---------------- Security Options (registry) ----------------
    F 'V-93279' 'Registry' 'Limit blank passwords to console' $LSA 'LimitBlankPasswordUse' 1 'DWord' '=' 'High'
    F 'V-93151' 'Registry' 'Force audit policy subcategory settings' $LSA 'SCENoApplyLegacyAuditPolicy' 1
    F 'V-93547' 'Registry' 'Netlogon: require sign or seal' $NETLOGON 'RequireSignOrSeal' 1
    F 'V-93549' 'Registry' 'Netlogon: seal secure channel' $NETLOGON 'SealSecureChannel' 1
    F 'V-93551' 'Registry' 'Netlogon: sign secure channel' $NETLOGON 'SignSecureChannel' 1
    F 'V-93455' 'Registry' 'Machine account password changes enabled' $NETLOGON 'DisablePasswordChange' 0
    F 'V-93285' 'Registry' 'Machine account max password age 30' $NETLOGON 'MaximumPasswordAge' 30 'DWord' '<='
    F 'V-93553' 'Registry' 'Netlogon: require strong key' $NETLOGON 'RequireStrongKey' 1
    F 'V-92961' 'Registry' 'Machine inactivity limit 900s' $POLSYS 'InactivityTimeoutSecs' 900 'DWord' '='
    F 'V-93147' 'Registry' 'Logon banner text' $POLSYS 'LegalNoticeText' $banner 'String' 'NotEmpty' 'Medium' 'All' '' $(if ($SkipBanner) { '-SkipBanner given' })
    F 'V-93149' 'Registry' 'Logon banner caption' $POLSYS 'LegalNoticeCaption' 'NOTICE' 'String' 'NotEmpty' 'Medium' 'All' '' $(if ($SkipBanner) { '-SkipBanner given' })
    F 'V-93287' 'Registry' 'Smart card removal: lock' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScRemoveOption' '1' 'String'
    F 'V-93555' 'Registry' 'SMB client: require signing' $WKS 'RequireSecuritySignature' 1
    F 'V-93557' 'Registry' 'SMB client: enable signing' $WKS 'EnableSecuritySignature' 1
    F 'V-93469' 'Registry' 'SMB client: no plaintext password' $WKS 'EnablePlainTextPassword' 0
    F 'V-93559' 'Registry' 'SMB server: require signing' $SRV 'RequireSecuritySignature' 1
    F 'V-93561' 'Registry' 'SMB server: enable signing' $SRV 'EnableSecuritySignature' 1
    F 'V-93291' 'Registry' 'No anonymous SAM enumeration' $LSA 'RestrictAnonymousSAM' 1 'DWord' '=' 'High'
    F 'V-93537' 'Registry' 'No anonymous SAM/share enumeration' $LSA 'RestrictAnonymous' 1 'DWord' '=' 'High'
    F 'V-93293' 'Registry' 'Everyone excludes Anonymous' $LSA 'EveryoneIncludesAnonymous' 0
    F 'V-93539' 'Registry' 'Restrict null session access' $SRV 'RestrictNullSessAccess' 1 'DWord' '=' 'High'
    F 'V-93045' 'Registry' 'Restrict remote SAM calls to Admins' $LSA 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' 'String'
    F 'V-93295' 'Registry' 'Use machine identity for NTLM' $LSA 'UseMachineId' 1
    F 'V-93297' 'Registry' 'No NULL session fallback' "$LSA\MSV1_0" 'allownullsessionfallback' 0
    F 'V-93299' 'Registry' 'No PKU2U online identities' "$LSA\pku2u" 'AllowOnlineID' 0
    F 'V-93495' 'Registry' 'Kerberos: AES only (no RC4/DES)' "$POLSYS\Kerberos\Parameters" 'SupportedEncryptionTypes' 2147483640 'DWord' '=' 'Medium' 'All' 'Breaks RC4-only legacy clients (old Samba/Java) - re-enable RC4 if a scored service fails Kerberos'
    F 'V-93467' 'Registry' 'No LM hash storage' $LSA 'NoLMHash' 1 'DWord' '=' 'High'
    F 'V-93301' 'Registry' 'LM auth level: NTLMv2 only, refuse LM/NTLM' $LSA 'LmCompatibilityLevel' 5 'DWord' '=' 'High'
    F 'V-93303' 'Registry' 'LDAP client signing: negotiate' 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1 'DWord' '>='
    F 'V-93305' 'Registry' 'NTLM min client sec: NTLMv2+128bit' "$LSA\MSV1_0" 'NTLMMinClientSec' 537395200
    F 'V-93307' 'Registry' 'NTLM min server sec: NTLMv2+128bit' "$LSA\MSV1_0" 'NTLMMinServerSec' 537395200
    F 'V-93493' 'Registry' 'Force strong key protection' 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' 'ForceKeyProtection' 1
    F 'V-93511' 'Registry' 'FIPS compliant algorithms' "$LSA\FIPSAlgorithmPolicy" 'Enabled' 1 'DWord' '=' 'Medium' 'All' 'Reboot' $(if (-not $IncludeRisky) { 'FIPS mode breaks apps using MD5/RC4 (.NET, some web apps, MySQL connectors); reboot' })
    F 'V-93309' 'Registry' 'Strengthen default object permissions' 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' 1
    F 'V-93431' 'Registry' 'UAC: Admin Approval Mode for built-in Admin' $POLSYS 'FilterAdministratorToken' 1
    F 'V-93521' 'Registry' 'UAC: no UIAccess desktop toggle' $POLSYS 'EnableUIADesktopToggle' 0
    F 'V-93523' 'Registry' 'UAC: admins prompt for consent on secure desktop' $POLSYS 'ConsentPromptBehaviorAdmin' 2 'DWord' '='
    F 'V-93433' 'Registry' 'UAC: standard users auto-deny elevation' $POLSYS 'ConsentPromptBehaviorUser' 0
    F 'V-93525' 'Registry' 'UAC: detect installers' $POLSYS 'EnableInstallerDetection' 1
    F 'V-93527' 'Registry' 'UAC: UIAccess only from secure paths' $POLSYS 'EnableSecureUIAPaths' 1
    F 'V-93435' 'Registry' 'UAC: enabled (EnableLUA)' $POLSYS 'EnableLUA' 1 'DWord' '=' 'Medium' 'All' 'Reboot'
    F 'V-93529' 'Registry' 'UAC: virtualize file/registry writes' $POLSYS 'EnableVirtualization' 1
    F 'V-93519' 'Registry' 'UAC token filter for local accounts on network' $POLSYS 'LocalAccountTokenFilterPolicy' 0 'DWord' '=' 'Medium' 'Member' 'Blocks remote admin via LOCAL accounts (PtH). Domain admin WinRM unaffected.'
    # ---------------- MSS / Network ----------------
    F 'V-93233' 'Registry' 'IPv6 source routing disabled' 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 2
    F 'V-93235' 'Registry' 'IPv4 source routing disabled' 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2
    F 'V-93237' 'Registry' 'Ignore ICMP redirects' 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0
    F 'V-93541' 'Registry' 'Ignore NetBIOS name release requests' 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' 'NoNameReleaseOnDemand' 1
    F 'V-93239' 'Registry' 'No insecure guest SMB logons' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0
    F 'V-93241a' 'Registry' 'Hardened UNC path: NETLOGON' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\NETLOGON' 'RequireMutualAuthentication=1, RequireIntegrity=1' 'String'
    F 'V-93241b' 'Registry' 'Hardened UNC path: SYSVOL' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\SYSVOL' 'RequireMutualAuthentication=1, RequireIntegrity=1' 'String'
    F 'V-93453' 'Registry' 'RPC: restrict unauthenticated clients' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'RestrictRemoteClients' 1 'DWord' '=' 'Medium' 'Member'
    F 'CCDC-LLMNR' 'Registry' 'LLMNR disabled (Responder defence)' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    F 'CCDC-MDNS' 'Registry' 'mDNS disabled (poisoning/relay surface)' 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0 'DWord' '=' 'Low' 'All' 'Servers resolve via DNS; only matters for AirPrint/Chromecast-style discovery'
    # ---- Authentication AUDIT logging (log only, changes nothing about how clients authenticate) ----
    # These give you the data to decide whether the CCDC-SKIP items (LDAP signing required, NTLM restriction) are safe to enforce.
    F 'CCDC-LDAPLOG' 'Registry' 'Log unsigned LDAP binds (Event 2889) before enforcing signing' 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' '16 LDAP Interface Events' 2 'DWord' '=' 'Medium' 'DC'
    F 'CCDC-NTLMAUDIT' 'Registry' 'Audit incoming NTLM (Event 8004) before restricting NTLM' "$LSA\MSV1_0" 'AuditReceivingNTLMTraffic' 2 'DWord' '=' 'Low'
    F 'CCDC-NTLMAUDIT-DC' 'Registry' 'Audit NTLM authentication in domain' $NETLOGON 'AuditNTLMInDomain' 7 'DWord' '=' 'Low' 'DC'
    F 'V-93401' 'Registry' 'WDigest disabled - no plaintext creds in LSASS' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 'DWord' '=' 'High'
    F 'CCDC-PPL' 'Registry' 'LSA runs as protected process (RunAsPPL)' $LSA 'RunAsPPL' 1 'DWord' '=' 'High' 'All' 'Reboot; blocks mimikatz LSASS access'
    F 'CCDC-CACHE' 'Registry' 'Cached logons <= 4' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' '4' 'String' 'NumLE'
    # ---------------- Credential / Device Guard ----------------
    F 'V-93243' 'Registry' 'Remote host allows delegation of non-exportable creds' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' 'AllowProtectedCreds' 1
    F 'V-93245' 'Registry' 'Virtualization Based Security' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1 'DWord' '=' 'Low' 'All' 'Reboot' $(if (-not $IncludeRisky) { 'Needs UEFI/nested-virt; no effect in most CCDC VMs, may affect boot' })
    F 'V-93277' 'Registry' 'Credential Guard' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags' 1 'DWord' '>=' 'High' 'Member' 'Reboot' $(if (-not $IncludeRisky) { 'Needs VBS hardware support' })
    # ---------------- Administrative Templates ----------------
    F 'V-93251a' 'Registry' 'GP: process even if unchanged' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' 'NoGPOListChanges' 0
    F 'V-93251b' 'Registry' 'GP: background refresh on' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' 'NoBackgroundPolicy' 0
    F 'V-93403a' 'Registry' 'No web PnP driver download' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'DisableWebPnPDownload' 1
    F 'V-93403b' 'Registry' 'No HTTP printing' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'DisableHTTPPrinting' 1
    F 'V-93407' 'Registry' 'No network selection UI at logon' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'DontDisplayNetworkSelectionUI' 1
    F 'V-93419' 'Registry' 'No local user enumeration at logon' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnumerateLocalUsers' 0 'DWord' '=' 'Medium' 'Member'
    F 'V-93253' 'Registry' 'Password on wake (battery)' 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'DCSettingIndex' 1 'DWord' '=' 'Low'
    F 'V-93255' 'Registry' 'Password on wake (AC)' 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' 'ACSettingIndex' 1 'DWord' '=' 'Low'
    F 'V-93409' 'Registry' 'App compat inventory off' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableInventory' 1 'DWord' '=' 'Low'
    F 'V-93373' 'Registry' 'No Autoplay for non-volume devices' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1 'DWord' '=' 'High'
    F 'V-93375' 'Registry' 'AutoRun: do not execute' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1 'DWord' '=' 'High'
    F 'V-93377' 'Registry' 'Autoplay off for all drives' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 'DWord' '=' 'High'
    F 'V-93517' 'Registry' 'No admin enumeration on elevation' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' 'EnumerateAdministrators' 0
    F 'V-93257' 'Registry' 'Telemetry: Basic' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 1 'DWord' '<=' 'Low'
    F 'V-93259' 'Registry' 'Delivery Optimization: LAN only' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode' 2 'DWord' '=' 'Low'
    F 'V-93177' 'EventLog' 'Application log >= 32 MB' 'Application' $null 65536 'Int' '>='
    F 'V-93179' 'EventLog' 'Security log >= 192 MB' 'Security' $null 262144 'Int' '>='
    F 'V-93181' 'EventLog' 'System log >= 32 MB' 'System' $null 65536 'Int' '>='
    F 'CCDC-PSLOG' 'EventLog' 'PowerShell Operational log >= 256 MB' 'Microsoft-Windows-PowerShell/Operational' $null 262144 'Int' '>='
    F 'CCDC-NTLMLOG' 'EventLog' 'NTLM Operational log >= 128 MB (8004 audit events)' 'Microsoft-Windows-NTLM/Operational' $null 131072 'Int' '>=' 'Low'
    F 'CCDC-SECLOG-DC' 'EventLog' 'Security log >= 1 GB on DCs (investigation retention)' 'Security' $null 1048576 'Int' '>=' 'Medium' 'DC'
    F 'V-93425' 'Registry' 'RDP: no password saving' $TS 'DisablePasswordSaving' 1
    F 'V-93533' 'Registry' 'RDP: no drive redirection' $TS 'fDisableCdm' 1
    F 'V-93427' 'Registry' 'RDP: always prompt for password' $TS 'fPromptForPassword' 1
    F 'V-92971' 'Registry' 'RDP: encrypt RPC traffic' $TS 'fEncryptRPCTraffic' 1
    F 'V-92973' 'Registry' 'RDP: high encryption level' $TS 'MinEncryptionLevel' 3
    F 'CCDC-NLA' 'Registry' 'RDP: Network Level Authentication' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 'DWord' '=' 'High'
    F 'CCDC-RDPTLS' 'Registry' 'RDP: TLS security layer' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer' 2
    F 'CCDC-RDPIDLE' 'Registry' 'RDP: disconnect idle sessions 15 min' $TS 'MaxIdleTime' 900000 'DWord' '<='
    F 'V-93265' 'Registry' 'IE feeds: no attachment download' 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' 'DisableEnclosureDownload' 1 'DWord' '=' 'Low'
    F 'V-93415' 'Registry' 'Search: no indexing encrypted items' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowIndexingEncryptedStoresOrItems' 0 'DWord' '=' 'Low'
    F 'V-93411a' 'Registry' 'SmartScreen enabled' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1
    F 'V-93411b' 'Registry' 'SmartScreen: block' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block' 'String'
    F 'V-93199' 'Registry' 'Installer: no user control' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'EnableUserControl' 0
    F 'V-93201' 'Registry' 'Installer: never AlwaysInstallElevated' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 'DWord' '=' 'High'
    F 'V-93269' 'Registry' 'No automatic restart sign-on' $POLSYS 'DisableAutomaticRestartSignOn' 1
    F 'V-93175' 'Registry' 'PowerShell script block logging' "$PS\ScriptBlockLogging" 'EnableScriptBlockLogging' 1
    F 'CCDC-PSMOD' 'Registry' 'PowerShell module logging' "$PS\ModuleLogging" 'EnableModuleLogging' 1
    F 'CCDC-PSMOD2' 'Registry' 'PowerShell module logging: all modules' "$PS\ModuleLogging\ModuleNames" '*' '*' 'String'
    F 'CCDC-PSTX' 'Registry' 'PowerShell transcription' "$PS\Transcription" 'EnableTranscripting' 1
    F 'CCDC-PSTX2' 'Registry' 'PowerShell transcription: invocation header' "$PS\Transcription" 'EnableInvocationHeader' 1
    F 'CCDC-CMDLINE' 'Registry' 'Audit process creation includes command line' "$POLSYS\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1 'DWord' '=' 'Medium' 'All' 'STIG V-93173 says 0; CCDC deviation: 1 gives Event 4688 full command lines for hunting'
    F 'V-93503' 'Registry' 'WinRM client: no Basic auth' "$WINRM\Client" 'AllowBasic' 0 'DWord' '=' 'High'
    F 'V-93499' 'Registry' 'WinRM client: no unencrypted' "$WINRM\Client" 'AllowUnencryptedTraffic' 0
    F 'V-93505' 'Registry' 'WinRM client: no Digest' "$WINRM\Client" 'AllowDigest' 0
    F 'V-93507' 'Registry' 'WinRM service: no Basic auth' "$WINRM\Service" 'AllowBasic' 0 'DWord' '=' 'High'
    F 'V-93501' 'Registry' 'WinRM service: no unencrypted' "$WINRM\Service" 'AllowUnencryptedTraffic' 0
    F 'V-93429' 'Registry' 'WinRM service: no RunAs creds' "$WINRM\Service" 'DisableRunAs' 1
    F 'V-93399' 'Registry' 'No lock screen slideshow' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenSlideshow' 1 'DWord' '=' 'Low'
    # ---------------- SMBv1 ----------------
    F 'V-93393' 'Registry' 'SMBv1 server disabled' $SRV 'SMB1' 0
    F 'V-93395' 'Registry' 'SMBv1 client driver disabled' 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10' 'Start' 4
    F 'CCDC-SMB1F' 'Feature' 'SMBv1 feature removed' 'SMB1Protocol' 'FS-SMB1' 'Disabled' 'String' '=' 'High' 'All' 'Reboot'
    F 'CCDC-PSV2' 'Feature' 'PowerShell v2 engine removed (log bypass)' 'MicrosoftWindowsPowerShellV2Root' 'PowerShell-V2' 'Disabled' 'String' '=' 'Medium' 'All' 'Reboot'
    # ---------------- DC specific ----------------
    F 'V-93545' 'Registry' 'DC: LDAP server signing required' 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity' 2 'DWord' '=' 'Medium' 'DC' '' $(if (-not $IncludeRisky) { 'Breaks plain simple-bind LDAP clients (Linux apps, scoring LDAP checks). Enable with -IncludeRisky' })
    F 'V-93273' 'Registry' 'DC: do not refuse machine pwd changes' $NETLOGON 'RefusePasswordChange' 0 'DWord' '=' 'Medium' 'DC'
    # ---------------- Audit Policy (GUID = subcategory) ----------------
    F 'V-93153' 'AuditPol' 'Credential Validation' '{0CCE923F-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-92985' 'AuditPol' 'Computer Account Management' '{0CCE9236-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-92979' 'AuditPol' 'Security Group Management' '{0CCE9237-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-92981' 'AuditPol' 'User Account Management' '{0CCE9235-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93157' 'AuditPol' 'Plug and Play Events' '{0CCE9248-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-93091' 'AuditPol' 'Process Creation' '{0CCE922B-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-92989' 'AuditPol' 'Account Lockout' '{0CCE9217-69AE-11D9-BED3-505054503030}' $null 'Failure'
    F 'V-93159' 'AuditPol' 'Group Membership' '{0CCE9249-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-93171' 'AuditPol' 'Logoff' '{0CCE9216-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-92967' 'AuditPol' 'Logon' '{0CCE9215-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93161' 'AuditPol' 'Special Logon' '{0CCE921B-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-93163' 'AuditPol' 'Other Object Access Events' '{0CCE9227-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93167' 'AuditPol' 'Removable Storage' '{0CCE9245-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93095' 'AuditPol' 'Audit Policy Change' '{0CCE922F-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93097' 'AuditPol' 'Authentication Policy Change' '{0CCE9230-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-93099' 'AuditPol' 'Authorization Policy Change' '{0CCE9231-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-93101' 'AuditPol' 'Sensitive Privilege Use' '{0CCE9228-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93105' 'AuditPol' 'IPsec Driver' '{0CCE9213-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93109' 'AuditPol' 'Other System Events' '{0CCE9214-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93113' 'AuditPol' 'Security State Change' '{0CCE9210-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-93115' 'AuditPol' 'Security System Extension' '{0CCE9211-69AE-11D9-BED3-505054503030}' $null 'Success'
    F 'V-93117' 'AuditPol' 'System Integrity' '{0CCE9212-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'V-93089' 'AuditPol' 'Other Account Management Events' '{0CCE923A-69AE-11D9-BED3-505054503030}' $null 'Success' 'String' '=' 'Medium' 'DC'
    F 'V-93133' 'AuditPol' 'Directory Service Access' '{0CCE923B-69AE-11D9-BED3-505054503030}' $null 'Success and Failure' 'String' '=' 'Medium' 'DC'
    F 'V-93137' 'AuditPol' 'Directory Service Changes' '{0CCE923C-69AE-11D9-BED3-505054503030}' $null 'Success and Failure' 'String' '=' 'Medium' 'DC'
    F 'CCDC-AUD-KERB' 'AuditPol' 'Kerberos Authentication Service (DC)' '{0CCE9242-69AE-11D9-BED3-505054503030}' $null 'Success and Failure' 'String' '=' 'Medium' 'DC'
    F 'CCDC-AUD-TGT' 'AuditPol' 'Kerberos Service Ticket Operations (DC)' '{0CCE9240-69AE-11D9-BED3-505054503030}' $null 'Success and Failure' 'String' '=' 'Medium' 'DC'
    F 'CCDC-AUD-SHARE' 'AuditPol' 'File Share' '{0CCE9224-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    F 'CCDC-AUD-SCHED' 'AuditPol' 'Other Logon/Logoff Events (RDP reconnects)' '{0CCE921C-69AE-11D9-BED3-505054503030}' $null 'Success and Failure'
    # ---------------- User Rights Assignment ----------------
    F 'V-93049' 'UserRight' 'Access Credential Manager as trusted caller: none' 'SeTrustedCredManAccessPrivilege' $null @() 'Sid' 'Exact'
    F 'V-93007' 'UserRight' 'Access this computer from the network' 'SeNetworkLogonRight' $null $(if ($Role -eq 'DC') { @($S.Admins, $S.AuthUsers, $S.EDC) } else { @($S.Admins, $S.AuthUsers) }) 'Sid' 'Exact' 'Medium' 'All' 'STIG member list omits Authenticated Users in HardeningKitty CSV; real STIG includes it. Kept so SMB/IIS Windows-auth/WinRM keep working.'
    F 'V-93051' 'UserRight' 'Act as part of the OS: none' 'SeTcbPrivilege' $null @() 'Sid' 'Exact' 'High'
    F 'V-93039' 'UserRight' 'Add workstations to domain: Admins' 'SeMachineAccountPrivilege' $null @($S.Admins) 'Sid' 'Exact' 'Medium' 'DC'
    F 'V-93017' 'UserRight' 'Allow log on locally: Admins' 'SeInteractiveLogonRight' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-92997' 'UserRight' 'Allow log on through RDP' 'SeRemoteInteractiveLogonRight' $null @($S.Admins, $S.RDPUsers) 'Sid' 'Exact' 'Medium' 'All' 'STIG DC = Administrators only; CCDC keeps Remote Desktop Users (matches user_config.txt)'
    F 'V-93053' 'UserRight' 'Back up files: Admins' 'SeBackupPrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93055' 'UserRight' 'Create a pagefile: Admins' 'SeCreatePagefilePrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93057' 'UserRight' 'Create a token object: none' 'SeCreateTokenPrivilege' $null @() 'Sid' 'Exact' 'High'
    F 'V-93059' 'UserRight' 'Create global objects' 'SeCreateGlobalPrivilege' $null @($S.Admins, $S.Service, $S.LocalSvc, $S.NetSvc) 'Sid' 'MaxSet'
    F 'V-93061' 'UserRight' 'Create permanent shared objects: none' 'SeCreatePermanentPrivilege' $null @() 'Sid' 'Exact'
    F 'V-93063' 'UserRight' 'Create symbolic links: Admins (+VMs on Hyper-V)' 'SeCreateSymbolicLinkPrivilege' $null @($S.Admins, $S.VMs) 'Sid' 'MaxSet'
    F 'V-93065' 'UserRight' 'Debug programs: Admins' 'SeDebugPrivilege' $null @($S.Admins) 'Sid' 'MaxSet' 'High'
    F 'V-93009' 'UserRight' 'Deny network logon: Guests (+Local account on members)' 'SeDenyNetworkLogonRight' $null $(if ($Role -eq 'DC') { @($S.Guests) } else { @($S.Guests, $S.LocalAccount) }) 'Sid' 'MinSet' 'Medium' 'All' 'STIG also denies Domain/Enterprise Admins on members - CCDC deviation: that would block DA WinRM/SMB management from the DC'
    F 'V-93011' 'UserRight' 'Deny batch logon: Guests' 'SeDenyBatchLogonRight' $null @($S.Guests) 'Sid' 'MinSet' 'Medium' 'All' 'STIG member adds DA/EA - CCDC deviation (scheduled tasks as DA)'
    F 'V-93015' 'UserRight' 'Deny local logon: Guests' 'SeDenyInteractiveLogonRight' $null @($S.Guests) 'Sid' 'MinSet' 'Medium' 'All' 'STIG member adds DA/EA - CCDC deviation (console logon as DA)'
    F 'V-92963' 'UserRight' 'Deny RDP logon: Guests (+Local account on members)' 'SeDenyRemoteInteractiveLogonRight' $null $(if ($Role -eq 'DC') { @($S.Guests) } else { @($S.Guests, $S.LocalAccount) }) 'Sid' 'MinSet' 'Medium' 'All' 'STIG member adds DA/EA - CCDC deviation'
    F 'V-93047' 'UserRight' 'Enable delegation' 'SeEnableDelegationPrivilege' $null $(if ($Role -eq 'DC') { @($S.Admins) } else { @() }) 'Sid' 'Exact'
    F 'V-93067' 'UserRight' 'Force shutdown remotely: Admins' 'SeRemoteShutdownPrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93069' 'UserRight' 'Generate security audits' 'SeAuditPrivilege' $null @($S.LocalSvc, $S.NetSvc, $S.IIS) 'Sid' 'MaxSet'
    F 'V-93071' 'UserRight' 'Impersonate a client (+IIS_IUSRS)' 'SeImpersonatePrivilege' $null @($S.Admins, $S.Service, $S.LocalSvc, $S.NetSvc, $S.IIS) 'Sid' 'MaxSet'
    F 'V-93073' 'UserRight' 'Increase scheduling priority' 'SeIncreaseBasePriorityPrivilege' $null @($S.Admins, $S.WinMgr) 'Sid' 'MaxSet'
    F 'V-93075' 'UserRight' 'Load and unload drivers: Admins' 'SeLoadDriverPrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93077' 'UserRight' 'Lock pages in memory: none' 'SeLockMemoryPrivilege' $null @() 'Sid' 'Exact' 'Medium' 'All' 'SQL Server service accounts legitimately hold this' 'Report-only: removing degrades SQL Server; fix manually if not SQL'
    F 'V-93197' 'UserRight' 'Manage auditing and security log: Admins' 'SeSecurityPrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93079' 'UserRight' 'Modify firmware environment: Admins' 'SeSystemEnvironmentPrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93081' 'UserRight' 'Perform volume maintenance: Admins' 'SeManageVolumePrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93083' 'UserRight' 'Profile single process: Admins' 'SeProfileSingleProcessPrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93085' 'UserRight' 'Restore files: Admins' 'SeRestorePrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    F 'V-93087' 'UserRight' 'Take ownership: Admins' 'SeTakeOwnershipPrivilege' $null @($S.Admins) 'Sid' 'MaxSet'
    # ---------------- Windows Firewall STIG (v1r7) ----------------
    F 'V-17415' 'FirewallProfile' 'Firewall on (Domain)' 'Domain' 'Enabled' 'True' 'String'
    F 'V-17416' 'FirewallProfile' 'Firewall on (Private)' 'Private' 'Enabled' 'True' 'String'
    F 'V-17417' 'FirewallProfile' 'Firewall on (Public)' 'Public' 'Enabled' 'True' 'String'
    F 'V-17418' 'FirewallProfile' 'Inbound default Block (Domain)' 'Domain' 'DefaultInboundAction' 'Block' 'String'
    F 'V-17428' 'FirewallProfile' 'Inbound default Block (Private)' 'Private' 'DefaultInboundAction' 'Block' 'String'
    F 'V-17438' 'FirewallProfile' 'Inbound default Block (Public)' 'Public' 'DefaultInboundAction' 'Block' 'String'
    F 'V-17426' 'FirewallProfile' 'Log dropped (Domain)' 'Domain' 'LogBlocked' 'True' 'String'
    F 'V-17436' 'FirewallProfile' 'Log dropped (Private)' 'Private' 'LogBlocked' 'True' 'String'
    F 'V-17446' 'FirewallProfile' 'Log dropped (Public)' 'Public' 'LogBlocked' 'True' 'String'
    F 'V-17427' 'FirewallProfile' 'Log allowed (Domain)' 'Domain' 'LogAllowed' 'True' 'String'
    F 'V-17437' 'FirewallProfile' 'Log allowed (Private)' 'Private' 'LogAllowed' 'True' 'String'
    F 'V-17447' 'FirewallProfile' 'Log allowed (Public)' 'Public' 'LogAllowed' 'True' 'String'
    F 'V-17425' 'FirewallProfile' 'Log size >= 16 MB (Domain)' 'Domain' 'LogMaxSizeKilobytes' 16384 'Int' '>='
    F 'V-17435' 'FirewallProfile' 'Log size >= 16 MB (Private)' 'Private' 'LogMaxSizeKilobytes' 16384 'Int' '>='
    F 'V-17445' 'FirewallProfile' 'Log size >= 16 MB (Public)' 'Public' 'LogMaxSizeKilobytes' 16384 'Int' '>='
    # ---------------- Defender (Defender STIG v2r1 essentials + ASR) ----------------
    F 'DEF-RT' 'MpPref' 'Real-time protection on' $null 'DisableRealtimeMonitoring' $false 'Bool'
    F 'DEF-BM' 'MpPref' 'Behavior monitoring on' $null 'DisableBehaviorMonitoring' $false 'Bool'
    F 'DEF-IOAV' 'MpPref' 'Scan downloads/attachments' $null 'DisableIOAVProtection' $false 'Bool'
    F 'DEF-SCRIPT' 'MpPref' 'Script scanning on' $null 'DisableScriptScanning' $false 'Bool'
    # -AsrAuditMode: accept Block(1) OR Audit(2) as a pass (>=1) and apply Audit; default demands Block
    $asrOp = $(if ($AsrAuditMode) { '>=' } else { '=' })
    F 'DEF-PUA' 'MpPref' "PUA protection: $(if ($AsrAuditMode) { 'audit' } else { 'block' })" $null 'PUAProtection' 1 'Int' $asrOp
    F 'DEF-MAPS' 'MpPref' 'Cloud protection (MAPS advanced)' $null 'MAPSReporting' 2 'Int'
    F 'DEF-SAMPLES' 'MpPref' 'Sample submission: safe samples' $null 'SubmitSamplesConsent' 1 'Int'
    F 'DEF-ARCH' 'MpPref' 'Scan archives' $null 'DisableArchiveScanning' $false 'Bool'
    F 'DEF-REMOVABLE' 'MpPref' 'Scan removable drives' $null 'DisableRemovableDriveScanning' $false 'Bool'
    F 'DEF-EMAIL' 'MpPref' 'Scan email' $null 'DisableEmailScanning' $false 'Bool'
    F 'DEF-NET' 'MpPref' "Network protection: $(if ($AsrAuditMode) { 'audit' } else { 'block' })" $null 'EnableNetworkProtection' 1 'Int' $asrOp
    F 'DEF-CTRLFOLDER' 'MpPref' 'Controlled folder access (audit)' $null 'EnableControlledFolderAccess' 2 'Int' '=' 'Low' 'All' 'Audit mode only - block mode breaks apps writing to user folders'
    $asrLbl = $(if ($AsrAuditMode) { 'audit' } else { 'block' })
    F 'ASR-1' 'AsrRule' "ASR: $asrLbl credential stealing from LSASS" '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' $null 1 'Int' $asrOp 'High'
    F 'ASR-2' 'AsrRule' "ASR: $asrLbl persistence via WMI subscription" 'e6db77e5-3df2-4cf1-b95a-636979351e5b' $null 1 'Int' $asrOp 'High'
    F 'ASR-3' 'AsrRule' "ASR: $asrLbl obfuscated scripts" '5beb7efe-fd9a-4556-801d-275e5ffc04cc' $null 1 'Int' $asrOp
    F 'ASR-4' 'AsrRule' "ASR: $asrLbl JS/VBS launching downloaded content" 'd3e037e1-3eb8-44c8-a917-57927947596d' $null 1 'Int' $asrOp
    F 'ASR-5' 'AsrRule' "ASR: $asrLbl executable content from email" 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' $null 1 'Int' $asrOp
    F 'ASR-6' 'AsrRule' "ASR: $asrLbl Office child processes" 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' $null 1 'Int' $asrOp
    F 'ASR-7' 'AsrRule' "ASR: $asrLbl Office from injecting code" '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' $null 1 'Int' $asrOp
    F 'ASR-8' 'AsrRule' "ASR: $asrLbl Win32 API calls from macros" '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' $null 1 'Int' $asrOp
    F 'ASR-9' 'AsrRule' "ASR: $asrLbl untrusted USB processes" 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' $null 1 'Int' $asrOp
    F 'ASR-10' 'AsrRule' "ASR: $asrLbl advanced ransomware protection" 'c1db55ab-c21a-4637-bb3f-a12568109d35' $null 1 'Int' $asrOp
    F 'ASR-11' 'AsrRule' "ASR: $asrLbl abuse of vulnerable signed drivers" '56a863a9-875e-4185-98a7-b882c64b5ce5' $null 1 'Int' $asrOp
    F 'ASR-12' 'AsrRule' "ASR: $asrLbl PsExec/WMI process creation" 'd1e49aac-8f56-4280-b9ba-993a6d77406c' $null 1 'Int' $asrOp 'Medium' 'All' '' $(if ($AsrAuditMode) { '' } else { 'Blocks WMI/PsExec-launched processes - can break scoring or admin tooling; -IncludeRisky (or -AsrAuditMode to log only)' })
    # ---------------- Services (CCDC) ----------------
    F 'CCDC-SVC-RR' 'Service' 'Remote Registry disabled' 'RemoteRegistry' $null 'Disabled' 'String'
    F 'CCDC-SVC-SPOOL' 'Service' 'Print Spooler disabled (PrintNightmare)' 'Spooler' $null 'Disabled' 'String' '=' 'High' 'All' 'Skipped automatically when shared printers are detected'
    F 'CCDC-SVC-FAX' 'Service' 'Fax disabled' 'Fax' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-SSDP' 'Service' 'SSDP Discovery disabled' 'SSDPSRV' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-UPNP' 'Service' 'UPnP host disabled' 'upnphost' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-RA' 'Service' 'Routing and Remote Access disabled' 'RemoteAccess' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-ICS' 'Service' 'Internet Connection Sharing disabled' 'SharedAccess' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-BROWSER' 'Service' 'Computer Browser disabled' 'Browser' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-XBOX' 'Service' 'Xbox services disabled' 'XblAuthManager' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-XBOX2' 'Service' 'Xbox services disabled' 'XblGameSave' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-WER' 'Service' 'Windows Error Reporting disabled' 'WerSvc' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-DIAG' 'Service' 'Connected User Experiences (telemetry) disabled' 'DiagTrack' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-MAPS' 'Service' 'Maps broker disabled' 'MapsBroker' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-RETAIL' 'Service' 'Retail demo disabled' 'RetailDemo' $null 'Disabled' 'String' '=' 'Low'
    F 'CCDC-SVC-WMP' 'Service' 'WMP network sharing disabled' 'WMPNetworkSvc' $null 'Disabled' 'String' '=' 'Low'
)

# ============================================================================
# ENGINE
# ============================================================================
function Get-RegValue($Path, $Item) { try { $p = Get-ItemProperty -Path $Path -Name $Item -ErrorAction Stop; return $p.$Item } catch { return $null } }
function Set-RegValue($Path, $Item, $Value, $Type) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $t = switch ($Type) { 'String' { 'String' } 'MultiString' { 'MultiString' } 'QWord' { 'QWord' } default { 'DWord' } }
    New-ItemProperty -Path $Path -Name $Item -Value $Value -PropertyType $t -Force -ErrorAction Stop | Out-Null
}
function Compare-Value($Current, $Rec, $Op, $Type) {
    if ($Op -eq 'NotEmpty') { return ((@($Current) -join ' ') -match '[\p{L}\p{N}]') }   # must contain a real letter/digit (not NUL / zero-width / whitespace)
    if ($null -eq $Current) { return $false }
    if ($Op -eq 'NumLE') { $c = 0; return ([int]::TryParse([string]$Current, [ref]$c) -and $c -le [int]$Rec) }
    if ($Type -eq 'Bool') { return ([bool]$Current -eq [bool]$Rec) }
    if ($Type -in 'DWord', 'Int', 'QWord') {
        $c = 0; $r = 0
        if (-not [long]::TryParse([string]$Current, [ref]$c)) { return $false }; $r = [long]$Rec
        switch ($Op) { '>=' { return $c -ge $r } '<=' { return $c -le $r } '!=' { return $c -ne $r } default { return $c -eq $r } }
    }
    if ($Op -eq '!=') { return ([string]$Current -ne [string]$Rec) }
    return ([string]$Current -eq [string]$Rec)
}

$script:AuditPolCache = $null
function Get-AuditPolSetting([string]$Guid) {
    if (-not $script:AuditPolCache) {
        $script:AuditPolCache = @{}
        $csv = & $Bin['auditpol.exe'] /get /category:* /r 2>$null | Where-Object { $_ -match ',' } | ConvertFrom-Csv
        foreach ($row in $csv) { if ($row.'Subcategory GUID') { $script:AuditPolCache[$row.'Subcategory GUID'.ToUpper()] = $row.'Inclusion Setting' } }
    }
    $v = $script:AuditPolCache[$Guid.ToUpper()]; if ($null -eq $v) { return 'Unknown' }; return $v
}
function Test-AuditPol([string]$Current, [string]$Rec) {
    $needS = $Rec -like '*Success*'; $needF = $Rec -like '*Failure*'
    $hasS = $Current -like '*Success*'; $hasF = $Current -like '*Failure*'
    return ((-not $needS) -or $hasS) -and ((-not $needF) -or $hasF)
}

function Get-UserRight([string]$Priv) {
    $v = Get-SecValue 'Privilege Rights' $Priv
    if ([string]::IsNullOrWhiteSpace($v)) { return @() }
    return @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
function Resolve-ToSid([string]$entry) {
    if ($entry.StartsWith('*')) { return $entry }
    try { $sid = (New-Object System.Security.Principal.NTAccount($entry)).Translate([System.Security.Principal.SecurityIdentifier]).Value; return "*$sid" } catch { return $entry }
}
function Sid-Label([string]$s) {
    try { $sid = New-Object System.Security.Principal.SecurityIdentifier($s.TrimStart('*')); return $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { return $s }
}

$script:DetectedRoles = @()
function Get-CurrentValue($f) {
    switch ($f.Method) {
        'Registry' { return Get-RegValue $f.A $f.B }
        'SecOption' { return Get-SecValue 'System Access' $f.A }
        'AccountPolicy' {
            if ($script:IsDC -and $script:HasADModule) {
                try { $p = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
                    switch ($f.A) { 'PasswordHistorySize' { return $p.PasswordHistoryCount } 'MaximumPasswordAge' { return [int]$p.MaxPasswordAge.TotalDays } 'MinimumPasswordAge' { return [int]$p.MinPasswordAge.TotalDays } 'MinimumPasswordLength' { return $p.MinPasswordLength } 'LockoutBadCount' { return $p.LockoutThreshold } 'LockoutDuration' { return [int]$p.LockoutDuration.TotalMinutes } 'ResetLockoutCount' { return [int]$p.LockoutObservationWindow.TotalMinutes } } } catch {}
            }
            $v = Get-SecValue 'System Access' $f.A; if ($v -eq '-1') { return 99999 }; return $v
        }
        'AuditPol' { return Get-AuditPolSetting $f.A }
        'UserRight' { return , @(@(Get-UserRight $f.A) | Where-Object { $_ } | ForEach-Object { Resolve-ToSid $_ }) }
        'Service' { $s = Get-Service -Name $f.A -ErrorAction SilentlyContinue; if (-not $s) { return 'NotInstalled' }; return [string]$s.StartType }
        'Feature' {
            try { $x = Get-WindowsOptionalFeature -Online -FeatureName $f.A -ErrorAction Stop; if ($x) { return [string]$x.State } } catch {}
            try { $y = Get-WindowsFeature -Name $f.B -ErrorAction Stop; if ($y) { return $(if ($y.Installed) { 'Enabled' } else { 'Disabled' }) } } catch {}
            return 'NotInstalled'
        }
        'FirewallProfile' { try { $p = Get-NetFirewallProfile -Name $f.A -ErrorAction Stop; return [string]$p.($f.B) } catch { return $null } }
        'MpPref' { try { $p = Get-MpPreference -ErrorAction Stop; return $p.($f.B) } catch { return $null } }
        'AsrRule' { try { $p = Get-MpPreference -ErrorAction Stop; $ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions); for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i] -ieq $f.A) { return [int]$acts[$i] } }; return 0 } catch { return $null } }
        'EventLog' { try { $x = & $Bin['wevtutil.exe'] gl "$($f.A)" 2>$null | Where-Object { $_ -match '^\s*maxSize:' } | Select-Object -First 1; if ($x -and ($x -match '(\d+)')) { return [int]([long]$matches[1] / 1024) } } catch {}; return $null }
    }
}
function Test-Finding($f, $cur) {
    switch ($f.Method) {
        'AuditPol' { return Test-AuditPol $cur $f.Rec }
        'UserRight' {
            $curSet = @(@($cur) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToUpper() }); $recSet = @(@($f.Rec) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToUpper() })
            $noExtra = (@($curSet | Where-Object { $recSet -notcontains $_ }).Count -eq 0)
            $noMissing = (@($recSet | Where-Object { $curSet -notcontains $_ }).Count -eq 0)
            switch ($f.Op) {
                'Exact' { return ($noExtra -and $noMissing) }
                'MaxSet' { return $noExtra }
                'MinSet' { return $noMissing }
            }
        }
        'AccountPolicy' {
            if ($f.Op -eq 'Lockout') { if ([int]$f.Rec -eq 0) { return $true }; $c = 0; [void][int]::TryParse([string]$cur, [ref]$c); return (($c -gt 0) -and ($c -le [int]$f.Rec)) }
            if ($f.A -in 'LockoutDuration', 'ResetLockoutCount' -and $LockoutThreshold -eq 0) { return $true }
            return Compare-Value $cur $f.Rec $f.Op 'Int' }
        'Service' { if ($cur -eq 'NotInstalled') { return $true }; return ($cur -eq $f.Rec) }
        'Feature' { return ($cur -in 'Disabled', 'NotInstalled', 'DisablePending', 'Removed') }
        default { return Compare-Value $cur $f.Rec $f.Op $f.Type }
    }
}
function Apply-Finding($f, $cur) {
    switch ($f.Method) {
        'Registry' { Set-RegValue $f.A $f.B $f.Rec $f.Type; return $true }
        'SecOption' {
            $val = $f.Rec
            if ($f.A -eq 'NewAdministratorName') { $val = '"CCDC_Admin"' } elseif ($f.A -eq 'NewGuestName') { $val = '"CCDC_Visitor"' }
            $script:SecPending['System Access'][$f.A] = $val; return 'Pending' }
        'AccountPolicy' {
            $val = $f.Rec
            if ($f.A -eq 'LockoutBadCount' -and [int]$val -eq 0) { $script:SecPending['System Access']['LockoutBadCount'] = 0; return 'Pending' }
            $script:SecPending['System Access'][$f.A] = $val
            if ($f.A -eq 'LockoutBadCount') { $script:SecPending['System Access']['LockoutDuration'] = 15; $script:SecPending['System Access']['ResetLockoutCount'] = 15 }
            if ($script:IsDC -and $script:HasADModule) {
                try {
                    $p = @{}
                    switch ($f.A) { 'PasswordHistorySize' { $p.PasswordHistoryCount = [int]$val } 'MaximumPasswordAge' { $p.MaxPasswordAge = [timespan]::FromDays([int]$val) } 'MinimumPasswordAge' { $p.MinPasswordAge = [timespan]::FromDays([int]$val) } 'MinimumPasswordLength' { $p.MinPasswordLength = [int]$val } 'LockoutBadCount' { $p.LockoutThreshold = [int]$val } 'LockoutDuration' { $p.LockoutDuration = [timespan]::FromMinutes([int]$val) } 'ResetLockoutCount' { $p.LockoutObservationWindow = [timespan]::FromMinutes([int]$val) } }
                    Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN -ComplexityEnabled $true -ReversibleEncryptionEnabled $false @p -ErrorAction Stop
                } catch { Write-Log "Set-ADDefaultDomainPasswordPolicy: $_ (Default Domain Policy GPO may override - fix in GPMC too)" 'WARN' }
            }
            return 'Pending'
        }
        'AuditPol' { $s = if ($f.Rec -like '*Success*') { 'enable' } else { 'disable' }; $fl = if ($f.Rec -like '*Failure*') { 'enable' } else { 'disable' }
            # one-time rollback backup:  auditpol /restore /file:<backup>
            if (-not $script:AuditPolBackedUp) { $bk = Join-Path $LogDir "auditpol-before-$script:Stamp.csv"; & $Bin['auditpol.exe'] /backup /file:"$bk" 2>&1 | Out-Null; $script:AuditPolBackedUp = $true; Write-Log "Audit policy backed up to $bk" 'INFO' }
            # never REDUCE existing auditing
            if ($cur -like '*Success*') { $s = 'enable' }; if ($cur -like '*Failure*') { $fl = 'enable' }
            & $Bin['auditpol.exe'] /set /subcategory:"$($f.A)" /success:$s /failure:$fl 2>&1 | Out-Null; $script:AuditPolCache = $null; return ($LASTEXITCODE -eq 0) }
        'UserRight' {
            $curSet = @(@($cur) | Where-Object { $_ }); $recSet = @(@($f.Rec) | Where-Object { $_ })
            $new = switch ($f.Op) {
                'Exact' { $recSet }
                'MaxSet' { @($curSet | Where-Object { $u = $_.ToUpper(); ($recSet | ForEach-Object { $_.ToUpper() }) -contains $u }) }
                'MinSet' { @($curSet + ($recSet | Where-Object { $r = $_.ToUpper(); -not (($curSet | ForEach-Object { $_.ToUpper() }) -contains $r) })) }
            }
            $script:SecPending['Privilege Rights'][$f.A] = (@($new) -join ','); return 'Pending'
        }
        'Service' { $svc = Get-Service -Name $f.A -ErrorAction SilentlyContinue; if (-not $svc) { return $true }
            if ($f.A -eq 'Spooler' -and $script:DetectedRoles -contains 'PrintServer') { return 'Skip:print server role (shared printers found)' }
            Stop-Service -Name $f.A -Force -ErrorAction SilentlyContinue; Set-Service -Name $f.A -StartupType Disabled -ErrorAction Stop; return $true }
        'Feature' {
            $done = $false
            try { $x = Get-WindowsOptionalFeature -Online -FeatureName $f.A -ErrorAction Stop; if ($x.State -eq 'Enabled') { Disable-WindowsOptionalFeature -Online -FeatureName $f.A -NoRestart -ErrorAction Stop | Out-Null; $done = $true } } catch {}
            if (-not $done) { try { $y = Get-WindowsFeature -Name $f.B -ErrorAction Stop; if ($y.Installed) { Uninstall-WindowsFeature -Name $f.B -ErrorAction Stop | Out-Null; $done = $true } } catch {} }
            if ($f.A -eq 'SMB1Protocol') { try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue } catch {} }
            [void]$script:RebootNeeded.Add($f.Name); return $true
        }
        'FirewallProfile' { $p = @{ Name = $f.A; $($f.B) = $(if ($f.Type -eq 'Int') { [int]$f.Rec } else { $f.Rec }) }; Set-NetFirewallProfile @p -ErrorAction Stop; return $true }
        'MpPref' {
            $val = $(if ($f.Type -eq 'Bool') { [bool]$f.Rec } else { [int]$f.Rec })
            # -AsrAuditMode: PUA / Network Protection go to AuditMode (2) instead of Block (1)
            if ($AsrAuditMode -and $f.B -in 'PUAProtection', 'EnableNetworkProtection' -and $val -eq 1) { $val = 2 }
            $p = @{ $($f.B) = $val }; Set-MpPreference @p -ErrorAction Stop; return $true }
        'AsrRule' {
            $act = [int]$f.Rec
            if ($AsrAuditMode -and $act -eq 1) { $act = 2 }   # AuditMode: log only, never block
            Add-MpPreference -AttackSurfaceReductionRules_Ids $f.A -AttackSurfaceReductionRules_Actions $act -ErrorAction Stop; return $true }
        'EventLog' { & $Bin['wevtutil.exe'] sl "$($f.A)" /ms:$([long]$f.Rec * 1024) 2>&1 | Out-Null; if ($f.A -like '*PowerShell*' -or $f.A -like '*NTLM*') { & $Bin['wevtutil.exe'] sl "$($f.A)" /e:true 2>&1 | Out-Null }; return ($LASTEXITCODE -eq 0) }
    }
    return $false
}
function Format-Cur($f, $cur) {
    if ($f.Method -eq 'UserRight') { return (@($cur | ForEach-Object { Sid-Label $_ }) -join ', ') }
    if ($null -eq $cur) { return '<not set>' }
    return [string]$cur
}
function Format-Rec($f) { if ($f.Method -eq 'UserRight') { return "$($f.Op): " + (@($f.Rec | ForEach-Object { Sid-Label $_ }) -join ', ') }; return [string]$f.Rec }

function Invoke-Findings {
    Write-Section "STIG FINDINGS ($Mode) - $($Findings.Count) checks"
    $i = 0; $stats = @{ Pass = 0; Fail = 0; Fixed = 0; FixFailed = 0; Skip = 0; NA = 0; Error = 0 }
    $pending = @()
    foreach ($f in $Findings) {
        $i++
        if ($f.Scope -ne 'All' -and $f.Scope -ne $Role) { $stats.NA++; continue }
        $r = [PSCustomObject]@{ Computer = $env:COMPUTERNAME; Id = $f.Id; Severity = $f.Sev; Name = $f.Name; Method = $f.Method; Before = ''; Current = ''; Recommended = (Format-Rec $f); Status = ''; Note = $f.Note }
        # SAFETY: never evaluate/apply secedit-backed findings if the export could not be read -
        # an unknown "current" set would otherwise be applied as an EMPTY set for MaxSet rights.
        if (-not $script:SecLoaded -and ($f.Method -in 'UserRight', 'SecOption' -or ($f.Method -eq 'AccountPolicy' -and -not ($script:IsDC -and $script:HasADModule)))) {
            $r.Status = 'Error'; $r.Note = 'secedit export unavailable (not elevated?) - not evaluated'; $stats.Error++
            [void]$script:Results.Add($r); Write-Finding $r; continue
        }
        try {
            $cur = Get-CurrentValue $f
            $r.Current = Format-Cur $f $cur; $r.Before = $r.Current     # Before = pre-change value for the rollback CSV
            $pass = Test-Finding $f $cur
            if ($pass) { $r.Status = 'Pass'; $stats.Pass++ }
            elseif ($f.Skip -and -not ($IncludeRisky -and $f.Skip -notlike 'Report-only*' -and $f.Skip -notlike '-SkipBanner*' -and $f.Skip -notlike 'May break scoring*' -and $f.Skip -notlike 'Cosmetic*')) { $r.Status = "CCDC-SKIP"; $r.Note = $f.Skip; $stats.Skip++ }
            elseif ($Mode -eq 'Audit') { $r.Status = 'Fail'; $stats.Fail++ }
            else {
                $res = Apply-Finding $f $cur
                if ($res -eq 'Pending') { $r.Status = 'Pending'; $pending += @{ R = $r; F = $f } }
                elseif ($res -is [string] -and $res -like 'Skip:*') { $r.Status = 'CCDC-SKIP'; $r.Note = $res.Substring(5); $stats.Skip++ }
                elseif ($res) {
                    $script:AuditPolCache = $null
                    $cur2 = Get-CurrentValue $f; $r.Current = Format-Cur $f $cur2
                    if (Test-Finding $f $cur2) { $r.Status = 'Fixed'; $stats.Fixed++ } else { $r.Status = 'FixFailed'; $stats.FixFailed++ }
                    if ($f.Note -eq 'Reboot' -or $f.Note -like '*Reboot*') { [void]$script:RebootNeeded.Add($f.Name) }
                } else { $r.Status = 'FixFailed'; $stats.FixFailed++ }
            }
        } catch { $r.Status = 'Error'; $r.Note = $_.Exception.Message; $stats.Error++ }
        [void]$script:Results.Add($r)
        if ($r.Status -ne 'Pending') { Write-Finding $r }
    }
    if ($pending.Count -gt 0) {
        Write-Sub "Applying batched secedit changes ($($pending.Count) findings)"
        $ok = Flush-SecPolicy
        foreach ($p in $pending) {
            $cur2 = Get-CurrentValue $p.F; $p.R.Current = Format-Cur $p.F $cur2
            if (Test-Finding $p.F $cur2) { $p.R.Status = 'Fixed'; $stats.Fixed++ } else { $p.R.Status = 'FixFailed'; $stats.FixFailed++; if ($p.F.Method -eq 'AccountPolicy' -and $script:IsDC) { $p.R.Note = 'Default Domain Policy GPO overrides local policy - set in GPMC: Computer Config > Policies > Windows Settings > Security Settings > Account Policies' } }
            Write-Finding $p.R
        }
    }
    Write-Sub "Findings summary"
    Write-Host ("  Pass {0}  Fixed {1}  Fail {2}  FixFailed {3}  CCDC-Skip {4}  Error {5}  N/A(role) {6}" -f $stats.Pass, $stats.Fixed, $stats.Fail, $stats.FixFailed, $stats.Skip, $stats.Error, $stats.NA) -ForegroundColor White
    return $stats
}
function Write-Finding($r) {
    $c = switch ($r.Status) { 'Pass' { 'Green' } 'Fixed' { 'Magenta' } 'Fail' { 'Red' } 'FixFailed' { 'Red' } 'CCDC-SKIP' { 'DarkYellow' } 'Error' { 'Red' } default { 'Gray' } }
    $cur = $r.Current; if ($cur.Length -gt 60) { $cur = $cur.Substring(0, 57) + '...' }
    Write-Host ("  [{0,-9}] {1,-14} {2,-6} {3,-52} cur: {4}" -f $r.Status, $r.Id, $r.Severity, $r.Name, $cur) -ForegroundColor $c
    if ($r.Status -in 'Fail', 'FixFailed', 'CCDC-SKIP', 'Error' -and $r.Note) { Write-Host ("               {0}" -f $r.Note) -ForegroundColor DarkGray }
}

# ============================================================================
# CCDC OPERATIONAL MODULES
# ============================================================================
$RoleSignatures = @{
    DomainController = @{ Services = @('NTDS'); Ports = @(53, 88, 123, 135, 137, 138, 139, 389, 445, 464, 593, 636, 3268, 3269, 9389, '49152-65535'); Critical = @('NTDS', 'DNS', 'Netlogon', 'W32Time', 'kdc', 'DFSR', 'ADWS', 'LanmanServer', 'LanmanWorkstation') }
    MSSQL = @{ Services = @('MSSQLSERVER', 'MSSQL$*'); Ports = @(1433, 1434); Critical = @('MSSQLSERVER') }
    MySQL = @{ Services = @('MySQL*', 'MariaDB*'); Ports = @(3306); Critical = @('MySQL*') }
    IIS = @{ Services = @('W3SVC'); Ports = @(80, 443, 8080); Critical = @('W3SVC', 'WAS') }
    RDP = @{ Services = @('TermService'); Ports = @(3389); Critical = @('TermService') }
    FileServer = @{ Services = @('LanmanServer'); Ports = @(445, 139); Critical = @('LanmanServer') }
    PrintServer = @{ Services = @('Spooler'); Ports = @(); Critical = @() }
    DNS = @{ Services = @('DNS'); Ports = @(53); Critical = @('DNS') }
    DHCP = @{ Services = @('DHCPServer'); Ports = @(67, 68); Critical = @('DHCPServer') }
    WinRM = @{ Services = @('WinRM'); Ports = @(5985, 5986); Critical = @('WinRM') }
    SSH = @{ Services = @('sshd'); Ports = @(22); Critical = @('sshd') }
    FTP = @{ Services = @('FTPSVC'); Ports = @(21); Critical = @('FTPSVC') }
    SMTP = @{ Services = @('SMTPSVC', 'hMailServer', 'MailEnable*'); Ports = @(25, 110, 143, 465, 587, 993, 995); Critical = @() }
    'Hyper-V' = @{ Services = @('vmms'); Ports = @(2179); Critical = @('vmms') }
    CA = @{ Services = @('CertSvc'); Ports = @(135); Critical = @('CertSvc') }
}
function Detect-Roles {
    Write-Sub "Role detection"
    $running = @(Get-Service | Where-Object Status -eq 'Running' | Select-Object -ExpandProperty Name)
    $roles = @()
    foreach ($r in $RoleSignatures.Keys) { foreach ($svc in $RoleSignatures[$r].Services) { if ($running | Where-Object { $_ -like $svc }) { $roles += $r; break } } }
    # FileServer only if there are non-default shares; PrintServer only if printers are shared
    if ($roles -contains 'FileServer') { $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'ADMIN$', 'C$', 'IPC$', 'NETLOGON', 'SYSVOL' -and $_.Name -notlike '*$' }); if ($shares.Count -eq 0) { $roles = @($roles | Where-Object { $_ -ne 'FileServer' }) } else { Write-Log "Shares: $($shares.Name -join ', ')" 'AUDIT' } }
    if ($roles -contains 'PrintServer') { $printers = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object Shared); if ($printers.Count -eq 0) { $roles = @($roles | Where-Object { $_ -ne 'PrintServer' }) } }
    $script:DetectedRoles = @($roles | Select-Object -Unique)
    Write-Log "Roles: $(if ($script:DetectedRoles) { $script:DetectedRoles -join ', ' } else { '(none - generic server)' })" 'AUDIT'
    # listening ports vs roles
    $rolePorts = @(); foreach ($r in $script:DetectedRoles) { $rolePorts += $RoleSignatures[$r].Ports }
    $listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    $unexplained = @()
    foreach ($p in $listening) {
        $explained = $false
        foreach ($rp in $rolePorts) { if ($rp -is [string] -and $rp -match '^(\d+)-(\d+)$') { if ($p -ge [int]$matches[1] -and $p -le [int]$matches[2]) { $explained = $true } } elseif ([int]$rp -eq $p) { $explained = $true } }
        if ($p -in 135, 445, 5985, 5986, 3389, 139) { $explained = $true }
        if ($p -ge 49152) { $explained = $true }
        if (-not $explained) { $proc = (Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess; $pn = (Get-Process -Id $proc -ErrorAction SilentlyContinue).ProcessName; $unexplained += "$p ($pn/$proc)" }
    }
    Write-Log "Listening TCP: $($listening -join ', ')" 'AUDIT'
    if ($unexplained) { Write-Log "PORTS NOT EXPLAINED BY A ROLE (check for backdoors): $($unexplained -join ', ')" 'WARN'; $unexplained | ForEach-Object { [void]$script:Suspicious.Add("Unexplained listener: $_") } }
    return $listening
}

function Configure-Firewall($listening) {
    Write-Sub "Role-based firewall allow-list"
    $ports = @(5985, 5986, 3389)  # never lock ourselves out
    foreach ($r in $script:DetectedRoles) { $ports += $RoleSignatures[$r].Ports }
    # safety net: keep every currently listening port open (reported above if unexplained)
    $ports += $listening
    $ports = @($ports | ForEach-Object { [string]$_ } | Select-Object -Unique)
    $udp = @(53, 67, 68, 88, 123, 137, 138, 389, 464, 500, 636, 4500, 1434)
    if ($Mode -ne 'Apply') { Write-Log "Would allow: $($ports -join ', ')" 'INFO'; return }
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName 'CCDC-*' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'CCDC-Allow-ICMPv4' -Direction Inbound -Protocol ICMPv4 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    $n = 1
    foreach ($p in $ports) {
        if ($p -match '^\d+$') {
            New-NetFirewallRule -DisplayName "CCDC-Allow-TCP-$p" -Direction Inbound -Protocol TCP -LocalPort ([int]$p) -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null; $n++
            if ([int]$p -in $udp) { New-NetFirewallRule -DisplayName "CCDC-Allow-UDP-$p" -Direction Inbound -Protocol UDP -LocalPort ([int]$p) -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null; $n++ }
        } elseif ($p -match '^\d+-\d+$') { New-NetFirewallRule -DisplayName "CCDC-Allow-TCP-$p" -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null; $n++ }
    }
    Write-Log "Firewall: default inbound BLOCK, $n allow rules for: $($ports -join ', ')" 'CHANGE'
    # report foreign inbound allow rules that are enabled (possible Red Team holes)
    $foreign = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -notlike 'CCDC-*' -and $_.Group -eq '' -and $_.DisplayGroup -eq '' })
    if ($foreign) { Write-Log "Non-grouped inbound allow rules (review): $(($foreign | Select-Object -First 15).DisplayName -join '; ')" 'WARN'; $foreign | ForEach-Object { [void]$script:Suspicious.Add("Firewall allow rule: $($_.DisplayName)") } }
    # LOLBins outbound block
    $lol = 'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'cscript.exe', 'wscript.exe', 'hh.exe', 'msiexec.exe', 'pcalua.exe', 'esentutl.exe', 'expand.exe', 'extrac32.exe', 'makecab.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'cmstp.exe', 'forfiles.exe', 'wmic.exe'
    $k = 0
    foreach ($b in $lol) { foreach ($dir in "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64") { $p = Join-Path $dir $b; if (Test-Path $p) { New-NetFirewallRule -DisplayName "CCDC-Block-LOLBin-$($b -replace '\.exe$','')-$(Split-Path $dir -Leaf)" -Direction Outbound -Program $p -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null; $k++ } } }
    foreach ($p in (Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework*\v*\msbuild.exe", "$env:SystemRoot\Microsoft.NET\Framework*\v*\installutil.exe" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "CCDC-Block-LOLBin-$($p.BaseName)-$($p.Directory.Name)" -Direction Outbound -Program $p.FullName -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null; $k++ }
    Write-Log "LOLBin outbound block rules: $k" 'CHANGE'
}

function Configure-Defender {
    Write-Sub "Windows Defender"
    $svc = Get-Service WinDefend -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Log "Defender not present" 'INFO'; return }
    if ($Mode -eq 'Apply') {
        Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service WinDefend -ErrorAction SilentlyContinue
        # Red Team likes to add exclusions - wipe them
        try { $p = Get-MpPreference; foreach ($e in @($p.ExclusionPath)) { Remove-MpPreference -ExclusionPath $e -ErrorAction SilentlyContinue; Write-Log "Removed Defender path exclusion: $e" 'CHANGE' }; foreach ($e in @($p.ExclusionProcess)) { Remove-MpPreference -ExclusionProcess $e -ErrorAction SilentlyContinue; Write-Log "Removed Defender process exclusion: $e" 'CHANGE' }; foreach ($e in @($p.ExclusionExtension)) { Remove-MpPreference -ExclusionExtension $e -ErrorAction SilentlyContinue; Write-Log "Removed Defender extension exclusion: $e" 'CHANGE' } } catch {}
        Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -ErrorAction SilentlyContinue
        Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue
        try { Update-MpSignature -ErrorAction Stop; Write-Log "Signatures updated" 'OK' } catch { Write-Log "Signature update failed (no internet?)" 'WARN' }
    }
    try {
        $s = Get-MpComputerStatus; Write-Log "Defender: AV=$($s.AntivirusEnabled) RT=$($s.RealTimeProtectionEnabled) Tamper=$($s.IsTamperProtected) SigAge=$($s.AntivirusSignatureAge)d" 'AUDIT'
        if (-not $s.IsTamperProtected) { Write-Log "Tamper Protection is OFF - Red Team can disable Defender with one Set-MpPreference. Cannot be set by script; enable via Windows Security > Virus & threat protection > Manage settings (or Intune/MDE)" 'WARN' }
        if ($AsrAuditMode) { Write-Log "ASR/PUA/NetworkProtection applied in AUDIT mode - review Defender Operational events 1121/1122, then re-run without -AsrAuditMode to block" 'INFO' }
    } catch {}
}

function Harden-IIS {
    if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) { return }
    Write-Sub "IIS hardening (anonymous auth is NOT touched - scoring browses anonymously)"
    try { Import-Module WebAdministration -ErrorAction Stop } catch { Write-Log "WebAdministration module missing" 'WARN'; return }
    if ($Mode -ne 'Apply') { Write-Log "Would: app pool identity ApplicationPoolIdentity, directory browsing off, remove server header, request filtering (no double-escaping, 30MB limit), disable WebDAV, custom errors on" 'INFO'; return }
    $n = 0
    foreach ($pool in Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue) { try { $id = (Get-ItemProperty "IIS:\AppPools\$($pool.Name)" -Name processModel.identityType).ToString(); if ($id -in 'LocalSystem', 'SpecificUser') { Set-ItemProperty "IIS:\AppPools\$($pool.Name)" -Name processModel.identityType -Value 4; Write-Log "AppPool $($pool.Name): identity $id -> ApplicationPoolIdentity" 'CHANGE'; $n++ } } catch {} }
    foreach ($site in Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue) {
        $p = "IIS:\Sites\$($site.Name)"
        try { Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $p -Value $false -ErrorAction Stop; $n++ } catch {}
        try { Set-WebConfigurationProperty -Filter /system.webServer/httpErrors -Name errorMode -PSPath $p -Value 'DetailedLocalOnly' -ErrorAction Stop } catch {}
    }
    try { Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name allowDoubleEscaping -Value $false -PSPath 'IIS:\' -ErrorAction Stop; Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering/requestLimits -Name maxAllowedContentLength -Value 31457280 -PSPath 'IIS:\' -ErrorAction Stop } catch {}
    try {
        $haveTrace = Get-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering/verbs/add[@verb="TRACE"]' -Name allowed -PSPath 'IIS:\' -ErrorAction SilentlyContinue
        if ($null -eq $haveTrace) { Add-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering/verbs -Name . -Value @{verb = 'TRACE'; allowed = $false } -PSPath 'IIS:\' -ErrorAction SilentlyContinue }
    } catch {}
    try { Set-WebConfigurationProperty -Filter /system.webServer/handlers -Name accessPolicy -Value 'Read,Script' -PSPath 'IIS:\' -ErrorAction SilentlyContinue } catch {}
    try { if (Get-WebGlobalModule WebDAVModule -ErrorAction SilentlyContinue) { Set-WebConfigurationProperty -Filter /system.webServer/webdav/authoring -Name enabled -Value $false -PSPath 'IIS:\' -ErrorAction SilentlyContinue } } catch {}
    try { Set-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering -Name removeServerHeader -Value $true -PSPath 'IIS:\' -ErrorAction SilentlyContinue } catch {}
    Write-Log "IIS: $n site/pool changes applied" 'CHANGE'
    # web.config / recently modified web files (webshell hunt)
    $recent = @(Get-ChildItem C:\inetpub -Recurse -File -Include *.aspx, *.asp, *.php, *.ashx, *.asmx, *.config -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-2) } | Select-Object -First 20)
    if ($recent) { Write-Log "Web files modified in last 48h (webshell check): $(($recent | ForEach-Object { $_.FullName }) -join '; ')" 'WARN'; $recent | ForEach-Object { [void]$script:Suspicious.Add("Recent web file: $($_.FullName)") } }
}

function Audit-SQL {
    if (-not (Get-Service | Where-Object { $_.Name -like 'MSSQL*' -and $_.Status -eq 'Running' })) { return }
    Write-Sub "SQL Server audit (read-only)"
    $q = { param($sql) try { if (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue) { (Invoke-Sqlcmd -Query $sql -ServerInstance localhost -ErrorAction Stop -QueryTimeout 10 | Select-Object -First 1).v } else { $o = & sqlcmd -S localhost -Q "SET NOCOUNT ON; $sql" -h -1 -W 2>&1; ($o | Where-Object { $_ -match '\S' } | Select-Object -First 1).Trim() } } catch { 'n/a' } }
    foreach ($chk in @(@{ N = 'xp_cmdshell'; Q = "SELECT CONVERT(INT,value_in_use) v FROM sys.configurations WHERE name='xp_cmdshell'" }, @{ N = 'clr enabled'; Q = "SELECT CONVERT(INT,value_in_use) v FROM sys.configurations WHERE name='clr enabled'" }, @{ N = 'Ad Hoc Distributed Queries'; Q = "SELECT CONVERT(INT,value_in_use) v FROM sys.configurations WHERE name='Ad Hoc Distributed Queries'" }, @{ N = 'sa enabled'; Q = "SELECT CASE is_disabled WHEN 1 THEN 0 ELSE 1 END v FROM sys.server_principals WHERE name='sa'" })) {
        $v = & $q $chk.Q
        if ("$v" -eq '1') { Write-Log "SQL: $($chk.N) = ENABLED  (disable if scoring does not need it)" 'WARN' } else { Write-Log "SQL: $($chk.N) = $v" 'AUDIT' }
    }
    $sysadmins = & { param($sql) try { if (Get-Command Invoke-Sqlcmd -ErrorAction SilentlyContinue) { (Invoke-Sqlcmd -Query $sql -ServerInstance localhost -ErrorAction Stop).name -join ', ' } else { (& sqlcmd -S localhost -Q "SET NOCOUNT ON; $sql" -h -1 -W 2>&1 | Where-Object { $_ -match '\S' }) -join ', ' } } catch { 'n/a' } } "SELECT p.name FROM sys.server_role_members m JOIN sys.server_principals r ON m.role_principal_id=r.principal_id JOIN sys.server_principals p ON m.member_principal_id=p.principal_id WHERE r.name='sysadmin'"
    Write-Log "SQL sysadmin logins: $sysadmins" 'AUDIT'
}

# ACEs granting write-type rights to Everyone / Users / Authenticated Users / INTERACTIVE
function Get-WeakAces([string]$Path) {
    if (-not $Path -or $Path.Length -le 3) { return }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $acl) { return }
    $weakSids = 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4'
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = try { $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
        if ($weakSids -notcontains $sid) { continue }
        if ($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl|CreateFiles|CreateDirectories|AppendData|ChangePermissions|TakeOwnership') {
            [PSCustomObject]@{ Path = $Path; Who = $ace.IdentityReference.Value; Rights = $ace.FileSystemRights }
        }
    }
}

# DC-only exposure checks adopted from the Harden-DC baseline. Report-only except two
# functionally-neutral fixes: MachineAccountQuota -> 0 and zone transfers -> NS-only.
function Audit-DomainExposure {
    if (-not $script:IsDC -or -not $script:HasADModule) { return }
    Write-Sub "Domain exposure (DCSync rights, MAQ, SYSVOL secrets, krbtgt, delegation, DNS)"
    try { $dom = Get-ADDomain -ErrorAction Stop } catch { Write-Log "Get-ADDomain failed: $_" 'WARN'; return }

    # DCSync: who holds replication rights on the domain root
    try {
        $guids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'
        $rep = @((Get-Acl "AD:$($dom.DistinguishedName)" -ErrorAction Stop).Access | Where-Object { $_.AccessControlType -eq 'Allow' -and ($guids -contains $_.ObjectType.ToString()) } | Select-Object -ExpandProperty IdentityReference -Unique | ForEach-Object { $_.Value })
        $expected = '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|.*\\Domain Controllers|.*\\Enterprise Domain Controllers|.*\\Enterprise Read-only Domain Controllers|.*\\Domain Admins|.*\\Enterprise Admins|.*\\MSOL_.*|.*\\AAD_.*)$'
        foreach ($p in $rep) { if ($p -notmatch $expected) { Write-Log "DCSync-capable principal NOT in expected set: $p" 'WARN'; [void]$script:Suspicious.Add("DCSync rights: $p") } }
        Write-Log "Replication rights on domain root: $($rep -join ', ')" 'AUDIT'
    } catch { Write-Log "Replication ACL check failed: $_" 'WARN' }

    # ms-DS-MachineAccountQuota: any user can add 10 machine accounts by default (RBCD / noPac style abuse). 0 is safe - admins can still join PCs.
    try {
        $maq = (Get-ADObject $dom.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota'
        if ($maq -gt 0) {
            if ($Mode -eq 'Apply') { Set-ADDomain -Identity $dom.DistinguishedName -Replace @{ 'ms-DS-MachineAccountQuota' = 0 } -ErrorAction Stop; Add-Change 'ms-DS-MachineAccountQuota' $maq 0 'non-admins could join machines'; Write-Log "MachineAccountQuota $maq -> 0" 'CHANGE' }
            else { Write-Log "ms-DS-MachineAccountQuota = $maq (Apply sets 0)" 'WARN' }
        } else { Write-Log "MachineAccountQuota = 0" 'OK' }
    } catch { Write-Log "MachineAccountQuota check failed: $_" 'WARN' }

    # SYSVOL: GPP cpassword / plaintext passwords in scripts
    try {
        $sv = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)"
        $hits = @(Get-ChildItem $sv -Recurse -File -Include *.xml, *.bat, *.cmd, *.ps1, *.vbs -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword|password\s*=' -List -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -Unique)
        if ($hits.Count) { Write-Log "SYSVOL files containing cpassword/password= ($($hits.Count)): $($hits -join '; ')  -> remove GPP passwords, rotate exposed creds" 'WARN'; $hits | ForEach-Object { [void]$script:Suspicious.Add("SYSVOL secret: $_") } } else { Write-Log "No cpassword/password= in SYSVOL" 'OK' }
    } catch {}

    # krbtgt age (User_Audit.ps1 -ResetKrbtgt performs the rotation)
    try { $k = Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction Stop; $age = [int]((Get-Date) - $k.PasswordLastSet).TotalDays; if ($age -gt 180) { Write-Log "krbtgt password is $age days old - rotate with User_Audit.ps1 -ResetKrbtgt (once; again after 10h+)" 'WARN' } else { Write-Log "krbtgt password age: $age days" 'OK' } } catch {}

    # non-DC computers with unconstrained delegation (TGT harvesting)
    try { $uc = @(Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties PrimaryGroupID -ErrorAction Stop | Where-Object PrimaryGroupID -ne 516); foreach ($c in $uc) { Write-Log "Non-DC computer with UNCONSTRAINED delegation: $($c.Name)" 'WARN'; [void]$script:Suspicious.Add("Unconstrained delegation: $($c.Name)") } } catch {}

    # DNS: zone transfers to anyone -> restrict to NS-listed servers (functionally neutral); insecure dynamic updates -> report only
    if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
        foreach ($z in @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })) {
            if ($z.SecureSecondaries -eq 'TransferAnyServer') {
                if ($Mode -eq 'Apply') { try { Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries TransferToZoneNameServer -ErrorAction Stop; Add-Change "DNS zone $($z.ZoneName) SecureSecondaries" 'TransferAnyServer' 'TransferToZoneNameServer' 'zone transfer to anyone'; Write-Log "DNS zone $($z.ZoneName): transfers restricted to NS servers" 'CHANGE' } catch { Write-Log "DNS zone $($z.ZoneName) transfer fix failed: $_" 'WARN' } }
                else { Write-Log "DNS zone $($z.ZoneName) allows zone transfer to ANY server (Apply restricts to NS)" 'WARN' }
            }
            if ($z.DynamicUpdate -eq 'NonsecureAndSecure') { Write-Log "DNS zone $($z.ZoneName) accepts NON-SECURE dynamic updates (report only - switching to Secure can break non-domain clients' DNS registration)" 'WARN' }
        }
    }
    try { $src = (& w32tm /query /source 2>$null) -join ''; if ($src) { Write-Log "Time source: $src" 'AUDIT' } } catch {}
}

function Audit-Persistence {
    Write-Sub "Persistence audit (scheduled tasks, run keys, WMI subscriptions, services)"
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskName -notlike 'CCDC-*' })
    foreach ($t in $tasks) { $a = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '; Write-Log "Task: $($t.TaskPath)$($t.TaskName) [$($t.State)] as $($t.Principal.UserId) -> $a" 'AUDIT'; [void]$script:Suspicious.Add("Scheduled task: $($t.TaskName) -> $a") }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; if ($p) { foreach ($n in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) { Write-Log "Run key: $k\$($n.Name) = $($n.Value)" 'AUDIT'; [void]$script:Suspicious.Add("Run key: $($n.Name) = $($n.Value)") } }
    }
    $wmi = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
    foreach ($w in $wmi) { Write-Log "WMI event consumer: $($w.Name) ($($w.CimClass.CimClassName)) $($w.CommandLineTemplate)$($w.ScriptText)" 'WARN'; [void]$script:Suspicious.Add("WMI consumer: $($w.Name)") }
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and $_.PathName -notlike '*\Windows\*' -and $_.PathName -notlike '"*\Windows\*' -and $_.PathName -notlike '*Program Files*' })
    foreach ($s in $svcs) { Write-Log "Service outside Windows/Program Files: $($s.Name) [$($s.State)/$($s.StartMode)] -> $($s.PathName)" 'WARN'; [void]$script:Suspicious.Add("Service: $($s.Name) -> $($s.PathName)") }

    # --- Service privilege-escalation surface: unquoted paths (fixed) and binaries writable by non-admins (reported) ---
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object PathName)) {
        if ($s.PathName -notmatch '^"?(.+?\.exe)') { continue }
        $exe = [Environment]::ExpandEnvironmentVariables($Matches[1])
        if ($exe -like "$env:windir\*") { continue }
        # unquoted path with spaces: Windows tries C:\Program.exe, C:\Program Files\App.exe ... -> quoting is a no-op functionally
        if ($s.PathName -notmatch '^"' -and $exe -match '\s') {
            $rest = $s.PathName.Substring($exe.Length)
            $fixed = '"' + $exe + '"' + $rest
            if ($Mode -eq 'Apply') {
                & $Bin['sc.exe'] config $s.Name binPath= "$fixed" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { Add-Change "Service $($s.Name) ImagePath" $s.PathName $fixed 'quoted unquoted service path (priv-esc)'; Write-Log "Quoted service path: $($s.Name) -> $fixed" 'CHANGE' }
                else { Write-Log "Could not quote path for $($s.Name): sc.exe exit $LASTEXITCODE" 'WARN' }
            } else { Write-Log "Unquoted service path with spaces: $($s.Name) -> $($s.PathName)" 'WARN'; [void]$script:Suspicious.Add("Unquoted service path: $($s.Name)") }
        }
        # binary or its folder writable by Everyone / Users / Authenticated Users / INTERACTIVE  (report only - fixing ACLs can break apps)
        $weak = @(Get-WeakAces (Split-Path $exe -Parent)) + @(Get-WeakAces $exe)
        if ($weak.Count) { $who = ($weak.Who | Sort-Object -Unique) -join ','; Write-Log "Service binary/folder writable by non-admins: $($s.Name) ($exe) by $who" 'WARN'; [void]$script:Suspicious.Add("Writable service binary: $($s.Name) by $who") }
    }
    $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($winlogon.Userinit -and $winlogon.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Write-Log "Winlogon Userinit tampered: $($winlogon.Userinit)" 'WARN'; [void]$script:Suspicious.Add("Userinit: $($winlogon.Userinit)") }
    if ($winlogon.Shell -and $winlogon.Shell -ne 'explorer.exe') { Write-Log "Winlogon Shell tampered: $($winlogon.Shell)" 'WARN'; [void]$script:Suspicious.Add("Shell: $($winlogon.Shell)") }
    $sticky = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | Where-Object { (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger }
    foreach ($s in $sticky) { $d = (Get-ItemProperty $s.PSPath -Name Debugger).Debugger; Write-Log "IFEO debugger: $($s.PSChildName) -> $d" 'WARN'; [void]$script:Suspicious.Add("IFEO: $($s.PSChildName) -> $d"); if ($Mode -eq 'Apply' -and $s.PSChildName -in 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe') { Remove-ItemProperty $s.PSPath -Name Debugger -Force; Write-Log "Removed accessibility backdoor IFEO on $($s.PSChildName)" 'CHANGE' } }
    if ($Mode -eq 'Apply') {
        # Accessibility-feature backdoors (sethc/utilman replaced by cmd.exe)
        foreach ($f in 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe') { $p = "$env:SystemRoot\System32\$f"; $sig = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue; $isOs = $false; try { $isOs = [bool]$sig.IsOSBinary } catch {}; if ($sig -and $sig.Status -ne 'Valid' -and -not $isOs) { Write-Log "$f is NOT a signed OS binary - possible backdoor (sfc /scannow to restore)" 'WARN'; [void]$script:Suspicious.Add("Replaced binary: $p") } }
    }
}

function Enable-SSHServer {
    Write-Sub "SSH server - redundant admin channel (survives WinRM tampering)"
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    if ($Mode -ne 'Apply') {
        Write-Log "Would install/enable OpenSSH Server on tcp/22 (key auth$(if ($SSHKeyOnly) { ', password OFF' } else { ', password ON' }), PS-over-SSH subsystem, watchdog-maintained)" 'INFO'
        return
    }
    if (-not $svc) {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cap -and $cap.State -ne 'Installed') {
            try { Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop; Write-Log "Installed $($cap.Name)" 'CHANGE' } catch { Write-Log "OpenSSH.Server capability install failed: $_" 'WARN' }
        }
        $svc = Get-Service sshd -ErrorAction SilentlyContinue
        if (-not $svc) { Write-Log "OpenSSH Server unavailable on this OS (pre-2019?) - install Win32-OpenSSH manually offline, then re-run -EnableSSH" 'WARN'; return }
    }

    Set-Service sshd -StartupType Automatic -ErrorAction SilentlyContinue
    Set-Service 'ssh-agent' -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service 'ssh-agent' -ErrorAction SilentlyContinue

    # firewall: allow tcp/22 inbound (our own named rule + re-enable the installer's if present)
    if (-not (Get-NetFirewallRule -Name 'CCDC-SSH-In' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'CCDC-SSH-In' -DisplayName 'CCDC OpenSSH Server (sshd) tcp/22' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any -ErrorAction SilentlyContinue | Out-Null
    } else { Enable-NetFirewallRule -Name 'CCDC-SSH-In' -ErrorAction SilentlyContinue }
    Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue

    # sshd_config (idempotent: manage a fenced block, strip prior copies of our directives)
    $cfgDir = Join-Path $env:ProgramData 'ssh'
    if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }
    $cfg = Join-Path $cfgDir 'sshd_config'
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    $shellExe = if ($pwsh) { $pwsh.Source } else { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
    try { New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value $shellExe -ErrorAction SilentlyContinue } catch {}

    $existingCfg = @(); if (Test-Path $cfg) { $existingCfg = @(Get-Content $cfg -ErrorAction SilentlyContinue) }
    $managed = '^\s*(PubkeyAuthentication|PasswordAuthentication|PermitRootLogin|Subsystem\s+powershell|Subsystem\s+sftp)\b'
    $clean = @(); $inBlk = $false
    foreach ($ln in $existingCfg) {
        if ($ln -match '^\s*#\s*CCDC-MANAGED-BEGIN') { $inBlk = $true; continue }
        if ($ln -match '^\s*#\s*CCDC-MANAGED-END') { $inBlk = $false; continue }
        if ($inBlk -or ($ln -match $managed)) { continue }
        $clean += $ln
    }
    $block = @('# CCDC-MANAGED-BEGIN', 'PubkeyAuthentication yes',
        ('PasswordAuthentication ' + $(if ($SSHKeyOnly) { 'no' } else { 'yes' })),
        'PermitRootLogin no', 'Subsystem sftp sftp-server.exe')
    if ($pwsh) { $block += ('Subsystem powershell "' + $shellExe + '" -sshs -NoLogo -NoProfile') }
    $block += @('Match Group administrators',
        '       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys',
        '# CCDC-MANAGED-END')
    ($clean + $block) | Set-Content -Path $cfg -Encoding ASCII -Force

    if ($SSHPublicKey) {
        $ak = Join-Path $cfgDir 'administrators_authorized_keys'
        $keys = @(); if (Test-Path $ak) { $keys = @(Get-Content $ak -ErrorAction SilentlyContinue) }
        if ($keys -notcontains $SSHPublicKey) { ($keys + $SSHPublicKey) | Set-Content -Path $ak -Encoding ASCII -Force; Write-Log "Installed admin SSH public key" 'CHANGE' }
        & icacls $ak /inheritance:r /grant 'SYSTEM:F' 'BUILTIN\Administrators:F' 2>&1 | Out-Null
    } elseif (-not $SSHKeyOnly) {
        Write-Log "No -SSHPublicKey given: relying on password auth. Provide a key and use -SSHKeyOnly for a stronger fallback." 'WARN'
    }

    & $Bin['sc.exe'] failure sshd reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    Restart-Service sshd -ErrorAction SilentlyContinue
    $running = (Get-Service sshd -ErrorAction SilentlyContinue).Status
    Write-Log "SSH redundant channel: sshd $running on tcp/22, password $(if ($SSHKeyOnly) { 'OFF' } else { 'ON' }), PS-over-SSH $(if ($pwsh) { 'ready' } else { 'needs pwsh on target' }) - watchdog will keep it alive" 'OK'
}

function Create-Persistence {
    Write-Sub "Service persistence watchdog"
    $crit = @('WinRM', 'TermService', 'EventLog', 'WinDefend', 'MpsSvc', 'BFE')
    if (Get-Service sshd -ErrorAction SilentlyContinue) { $crit += @('sshd', 'ssh-agent') }
    foreach ($r in $script:DetectedRoles) { $crit += $RoleSignatures[$r].Critical }
    $crit = @($crit | Where-Object { $_ -notlike '*`**' } | Select-Object -Unique | Where-Object { Get-Service $_ -ErrorAction SilentlyContinue })
    if ($Mode -ne 'Apply') { Write-Log "Would watch: $($crit -join ', ')" 'INFO'; return }
    $watch = @"
# CCDC watchdog - restarts critical services, re-enables firewall/Defender, logs to Application/CCDC-Watchdog
`$services = @('$($crit -join "','")')
foreach (`$s in `$services) { try { `$svc = Get-Service `$s -ErrorAction Stop; if (`$svc.StartType -eq 'Disabled') { Set-Service `$s -StartupType Automatic }; if (`$svc.Status -ne 'Running') { Start-Service `$s -ErrorAction SilentlyContinue; Write-EventLog -LogName Application -Source CCDC-Watchdog -EventId 1001 -EntryType Warning -Message "Restarted `$s" -ErrorAction SilentlyContinue } } catch {} }
try { if ((Get-NetFirewallProfile | Where-Object Enabled -eq `$false)) { Set-NetFirewallProfile -All -Enabled True; Write-EventLog -LogName Application -Source CCDC-Watchdog -EventId 1002 -EntryType Warning -Message 'Firewall re-enabled' -ErrorAction SilentlyContinue } } catch {}
try { if ((Get-MpPreference).DisableRealtimeMonitoring) { Set-MpPreference -DisableRealtimeMonitoring `$false; Write-EventLog -LogName Application -Source CCDC-Watchdog -EventId 1003 -EntryType Warning -Message 'Defender RT re-enabled' -ErrorAction SilentlyContinue } } catch {}
try { if (Get-Service sshd -ErrorAction SilentlyContinue) { foreach (`$rn in 'CCDC-SSH-In','OpenSSH-Server-In-TCP') { `$fr = Get-NetFirewallRule -Name `$rn -ErrorAction SilentlyContinue; if (`$fr -and `$fr.Enabled -ne 'True') { Enable-NetFirewallRule -Name `$rn -ErrorAction SilentlyContinue; Write-EventLog -LogName Application -Source CCDC-Watchdog -EventId 1004 -EntryType Warning -Message "Re-enabled firewall rule `$rn" -ErrorAction SilentlyContinue } } } } catch {}
"@
    $path = "$env:SystemRoot\System32\CCDC-Watchdog.ps1"
    $watch | Out-File $path -Encoding ASCII -Force
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('CCDC-Watchdog')) { New-EventLog -LogName Application -Source 'CCDC-Watchdog' } } catch {}
    Unregister-ScheduledTask -TaskName 'CCDC-Watchdog' -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$path`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'CCDC-Watchdog' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'CCDC service/firewall/defender watchdog' -ErrorAction Stop | Out-Null
    foreach ($s in $crit) { & $Bin['sc.exe'] failure $s reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null }
    Write-Log "Watchdog every 2 min for: $($crit -join ', ')" 'CHANGE'
}

function Scan-PII {
    Write-Sub "PII scan (SSN / card-number patterns)"
    $pat = '\b\d{3}-\d{2}-\d{4}\b|\b(?:\d[ -]*?){13,16}\b'
    $hits = @(Get-ChildItem 'C:\Users\*\Desktop', 'C:\Users\*\Documents', 'C:\Users\*\Downloads', 'C:\inetpub', 'C:\Shares', 'C:\Data' -Recurse -File -Include *.txt, *.csv, *.docx, *.xlsx, *.pdf, *.xml, *.json, *.sql, *.log, *.html, *.htm -ErrorAction SilentlyContinue | Where-Object Length -lt 20MB | Select-String -Pattern $pat -List -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -Unique)
    if ($hits) { Write-Log "Possible PII in $($hits.Count) files: $($hits -join '; ')" 'WARN' } else { Write-Log "No PII patterns found" 'OK' }
}

function Verify-DCServices {
    if (-not $script:IsDC) { return }
    Write-Sub "DC core services check"
    foreach ($s in 'NSI', 'Bowser', 'MRxSmb20', 'SamSs', 'Srv2', 'LanmanWorkstation', 'LanmanServer', 'Netlogon', 'NTDS', 'DNS', 'kdc', 'W32Time', 'DFSR', 'ADWS') {
        $svc = Get-Service $s -ErrorAction SilentlyContinue; if (-not $svc) { continue }
        if ($svc.Status -ne 'Running') { if ($Mode -eq 'Apply') { Set-Service $s -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service $s -ErrorAction SilentlyContinue; Write-Log "Started $s" 'CHANGE' } else { Write-Log "$s is $($svc.Status)" 'WARN' } }
    }
    try { $t = & dcdiag /test:services /q 2>&1; if ($t) { Write-Log "dcdiag services: $($t -join ' ')" 'WARN' } else { Write-Log "dcdiag /test:services passed" 'OK' } } catch {}
}

# ============================================================================
# MAIN
# ============================================================================
$listening = Detect-Roles
$stats = Invoke-Findings
Write-Section "CCDC OPERATIONAL MODULES ($Mode)"
if (-not $SkipFirewall) { Configure-Firewall $listening }
if (-not $SkipDefender) { Configure-Defender }
if (-not $SkipIIS) { Harden-IIS }
Audit-SQL
Audit-Persistence
if ($PIIScan) { Scan-PII }
if ($EnableSSH) { Enable-SSHServer }
if (-not $SkipPersistence) { Create-Persistence }
Verify-DCServices
Audit-DomainExposure

# ---- summary ----
Write-Section "SUMMARY - $env:COMPUTERNAME"
Write-Host ("  Findings: Pass {0}  Fixed {1}  Fail {2}  FixFailed {3}  CCDC-Skip {4}  Error {5}" -f $stats.Pass, $stats.Fixed, $stats.Fail, $stats.FixFailed, $stats.Skip, $stats.Error) -ForegroundColor White
$fails = @($script:Results | Where-Object { $_.Status -in 'Fail', 'FixFailed', 'Error' })
if ($fails) { Write-Sub "Open findings"; $fails | Sort-Object Severity | ForEach-Object { Write-Host ("  {0,-10} {1,-6} {2,-14} {3}" -f $_.Status, $_.Severity, $_.Id, $_.Name) -ForegroundColor Red } }
$skips = @($script:Results | Where-Object Status -eq 'CCDC-SKIP')
if ($skips) { Write-Sub "Deliberately skipped (CCDC deviations - apply manually or with -IncludeRisky if safe)"; $skips | ForEach-Object { Write-Host ("  {0,-14} {1,-50} {2}" -f $_.Id, $_.Name, $_.Note) -ForegroundColor DarkYellow } }
if ($script:Suspicious.Count) { Write-Sub "REVIEW LIST (possible Red Team artifacts)"; $script:Suspicious | Select-Object -Unique | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Yellow } }
if ($script:RebootNeeded.Count) { Write-Sub "Reboot required to complete"; $script:RebootNeeded | Select-Object -Unique | ForEach-Object { Write-Host "  * $_" -ForegroundColor Yellow } }
if ($ReportCsv -and -not $script:IsRemoteRun) { $script:Results | Export-Csv -Path $ReportCsv -NoTypeInformation -Force; Write-Log "Report: $ReportCsv" 'OK' }

# ---- rollback record: every old -> new change made this run ----
if ($Mode -eq 'Apply') {
    foreach ($r in @($script:Results | Where-Object { $_.Status -in 'Fixed', 'FixFailed' })) { Add-Change "$($r.Id) $($r.Name)" $r.Before $r.Current "STIG/CCDC finding ($($r.Status)); recommended: $($r.Recommended)" }
    if ($script:Changes.Count) {
        $chg = Join-Path $LogDir "changes-$env:COMPUTERNAME-$script:Stamp.csv"
        try { $script:Changes | Export-Csv -Path $chg -NoTypeInformation -Force; Write-Log "$($script:Changes.Count) change(s) recorded (old -> new) in $chg" 'OK' } catch { Write-Log "Could not write change log: $_" 'WARN' }
    }
    Write-Host "`n  Rollback material in ${LogDir}: transcript, secedit-before-*.inf (secedit /configure), auditpol-before-*.csv (auditpol /restore), changes-*.csv" -ForegroundColor Gray
}
if ($Mode -eq 'Audit') { Write-Host "`n  Audit only. Re-run with -Mode Apply to enforce." -ForegroundColor Cyan }
Remove-Item $script:SecTemp -Recurse -Force -ErrorAction SilentlyContinue
if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch {} }

# hand results back to the fan-out caller
if ($script:IsRemoteRun) { $script:Results }
