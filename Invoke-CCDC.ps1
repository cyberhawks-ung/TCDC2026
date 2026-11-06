<#
================================================================================
  Invoke-CCDC.ps1  -  cross-platform launcher for the CCDC Windows tooling
================================================================================

  WHAT IT IS
    A thin ORCHESTRATOR that you can run from Linux, macOS or Windows. It does
    NOT harden anything by itself - it connects to a Windows "entry host"
    (normally a Domain Controller), copies User_Audit.ps1 / Harden.ps1 /
    user_config.txt onto it, and runs them THERE. Because they run on the DC,
    their own domain fan-out ( -AllDomain / AD computer discovery ) reaches
    every Windows server and workstation in the domain, using the DC's own
    Kerberos context - so there is no WinRM "double hop" from the Linux box.

    Linux/macOS only needs PowerShell 7  ( the 'pwsh' binary ).
    The heavy Windows-only cmdlets (secedit, AD, LocalAccounts, NetFirewall...)
    only ever execute on Windows targets, never on the Linux control node.

  TWO WAYS TO REACH THE ENTRY HOST
    -Transport WinRM  (default)  TCP 5985/5986. From Linux use -Authentication
                                 Negotiate (NTLM) or Kerberos. -UseSSL for 5986.
    -Transport SSH               Windows OpenSSH Server with the PowerShell
                                 subsystem enabled. Often the easiest from Linux.

  QUICK START (from Linux)
    # install PowerShell 7 if needed, then:
    pwsh -File ./Invoke-CCDC.ps1 -EntryHost dc01.range.local -Username RANGE\Administrator
    # audit-only dry run of everything, domain-wide:
    pwsh -File ./Invoke-CCDC.ps1 -EntryHost 10.0.0.10 -Username Administrator -Task Both -Mode Audit -DryRun
    # actually apply hardening + reset users across the whole domain:
    pwsh -File ./Invoke-CCDC.ps1 -EntryHost dc01 -Username RANGE\Administrator -Task Both -Mode Apply -BootstrapWinRM
    # over SSH instead of WinRM:
    pwsh -File ./Invoke-CCDC.ps1 -EntryHost dc01 -Username Administrator -Transport SSH

  QUICK START (from Windows)
    .\Invoke-CCDC.ps1 -EntryHost dc01 -Task Both -Mode Apply         # uses current creds

  NOTES
    * Passwords the tools generate are printed to the live terminal only. Use
      User_Audit's own -ExportPasswords (via -AuditArgs) if you must have a CSV.
    * -AllDomain (default) makes the tools sweep the whole domain from the DC.
      Point -EntryHost at each standalone/workgroup box instead if it is not
      domain-joined (the tools then run in their -Local single-box mode).
================================================================================
#>

[CmdletBinding(DefaultParameterSetName = 'Cred')]
param(
    [Parameter(Mandatory)][string[]]$EntryHost,

    [Parameter(ParameterSetName = 'Cred')][pscredential]$Credential,
    [Parameter(ParameterSetName = 'User')][string]$Username,

    [ValidateSet('WinRM', 'SSH')][string]$Transport = 'WinRM',
    [ValidateSet('Default', 'Negotiate', 'Kerberos', 'Basic', 'CredSSP')][string]$Authentication = 'Negotiate',
    [switch]$UseSSL,
    [int]$Port,
    [string]$KeyFilePath,                                     # SSH private key (optional, -Transport SSH)

    [ValidateSet('Audit', 'Harden', 'Both')][string]$Task = 'Both',
    [ValidateSet('Audit', 'Apply')][string]$Mode = 'Audit',   # Harden.ps1 mode
    [switch]$DryRun,                                          # User_Audit.ps1 dry run + forces Harden Audit
    [switch]$Local,                                           # run tools in single-box mode (no domain sweep)
    [switch]$BootstrapWinRM,                                  # let the tools enable WinRM on unreachable domain hosts
    [switch]$EnableSSH,                                       # install OpenSSH Server on targets as a redundant channel
    [switch]$SSHKeyOnly,                                      # with -EnableSSH: disable SSH password auth
    [string]$SSHPublicKey,                                    # with -EnableSSH: admin public key line to install

    [string]$ScriptSource = $PSScriptRoot,                    # local folder holding the .ps1 + user_config.txt
    [string]$RemoteDir = 'C:\CCDC',                           # where they are copied on the target
    [switch]$KeepRemote,                                      # do not delete the remote copy afterwards

    [string[]]$AuditArgs,                                     # extra args passed through to User_Audit.ps1
    [string[]]$HardenArgs                                     # extra args passed through to Harden.ps1
)

$ErrorActionPreference = 'Stop'
$isWin = if ($null -ne $IsWindows) { $IsWindows } else { $true }   # $IsWindows is undefined on 5.1 (=> Windows)

# allow comma-separated hosts (so `pwsh -File ... -EntryHost a,b` and deploy.sh both work)
$EntryHost = @($EntryHost | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red }

# --- preflight --------------------------------------------------------------
Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host "  CCDC ORCHESTRATOR   task=$Task  mode=$Mode  transport=$Transport  $(if($DryRun){'DRY-RUN'})" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan
Info "Control node: $([System.Environment]::OSVersion.VersionString)  PSVersion $($PSVersionTable.PSVersion)  Edition $($PSVersionTable.PSEdition)"

if (-not $isWin -and $PSVersionTable.PSEdition -ne 'Core') {
    Fail "On Linux/macOS you must run this with PowerShell 7 (pwsh). Install: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux"
    exit 2
}

# resolve the three payload files
$payload = @{}
foreach ($f in 'User_Audit.ps1', 'Harden.ps1', 'user_config.txt') {
    $p = Join-Path $ScriptSource $f
    if (Test-Path $p) { $payload[$f] = (Resolve-Path $p).Path }
    elseif ($f -eq 'user_config.txt') { Warn "user_config.txt not found in $ScriptSource - User_Audit will need one on the target" }
    else { Fail "Required file not found: $p  (use -ScriptSource to point at the folder)"; exit 2 }
}
Info ("Payload: " + (($payload.Keys) -join ', '))

# credentials
if (-not $Credential) {
    if ($Username) {
        $Credential = Get-Credential -UserName $Username -Message "Password for $Username on $($EntryHost -join ', ')"
    } elseif (-not $isWin) {
        # Linux control node cannot use implicit Windows creds - must supply them
        $u = Read-Host "Windows username (e.g. DOMAIN\Administrator)"
        $Credential = Get-Credential -UserName $u -Message "Password for $u"
    } else {
        Info "No -Credential given; using the current Windows identity ($env:USERDOMAIN\$env:USERNAME)"
    }
}

# --- session factory --------------------------------------------------------
function New-EntrySession {
    param([string]$ComputerNameOrHost)

    if ($Transport -eq 'SSH') {
        $sshUser = if ($Credential) { $Credential.UserName } else { $env:USERNAME }
        $p = @{ HostName = $ComputerNameOrHost; UserName = $sshUser }
        if ($Port) { $p.Port = $Port }
        if ($KeyFilePath) { $p.KeyFilePath = $KeyFilePath }
        return New-PSSession @p
    }

    # WinRM
    $so = New-PSSessionOption -OperationTimeout 0 -IdleTimeout 7200000 -OpenTimeout 60000
    $p = @{
        ComputerName   = $ComputerNameOrHost
        Authentication = $Authentication
        SessionOption  = $so
        ErrorAction    = 'Stop'
    }
    if ($Credential) { $p.Credential = $Credential }
    if ($UseSSL) { $p.UseSSL = $true }
    if ($Port) { $p.Port = $Port } elseif ($UseSSL) { $p.Port = 5986 } else { $p.Port = 5985 }
    return New-PSSession @p
}

# scriptblock that runs ON the target: creates $RemoteDir, then runs the tools there
$runner = {
    param($RemoteDir, $DoAudit, $DoHarden, $HardenMode, $DryRun, $Local, $Bootstrap, $EnableSSH, $SSHKeyOnly, $SSHPublicKey, $AuditExtra, $HardenExtra)

    $ErrorActionPreference = 'Continue'
    if (-not (Test-Path $RemoteDir)) { New-Item -ItemType Directory -Path $RemoteDir -Force | Out-Null }
    Set-Location $RemoteDir
    Write-Host "`n########## RUNNING ON $env:COMPUTERNAME  ($RemoteDir) ##########`n" -ForegroundColor Magenta

    $auditPs = Join-Path $RemoteDir 'User_Audit.ps1'
    $hardenPs = Join-Path $RemoteDir 'Harden.ps1'

    if ($DoAudit -and (Test-Path $auditPs)) {
        Write-Host "`n===== User_Audit.ps1 =====" -ForegroundColor Cyan
        $a = @()
        if ($DryRun) { $a += '-DryRun' }
        if ($Local) { $a += '-Local' }
        if ($Bootstrap -and -not $Local) { $a += '-BootstrapWinRM' }
        if ($AuditExtra) { $a += $AuditExtra }
        & $auditPs @a
    }

    if ($DoHarden -and (Test-Path $hardenPs)) {
        Write-Host "`n===== Harden.ps1 =====" -ForegroundColor Cyan
        $h = @('-Mode', $(if ($DryRun) { 'Audit' } else { $HardenMode }))
        if (-not $Local) { $h += '-AllDomain' }
        if ($Bootstrap) { $h += '-BootstrapWinRM' }
        if ($EnableSSH) { $h += '-EnableSSH' }
        if ($SSHKeyOnly) { $h += '-SSHKeyOnly' }
        if ($SSHPublicKey) { $h += @('-SSHPublicKey', $SSHPublicKey) }
        if ($HardenExtra) { $h += $HardenExtra }
        & $hardenPs @h
    }
}

$doAudit = ($Task -in 'Audit', 'Both')
$doHarden = ($Task -in 'Harden', 'Both')

foreach ($h in $EntryHost) {
    Write-Host ("`n" + ("-" * 78)) -ForegroundColor DarkCyan
    Info "Connecting to entry host: $h  ($Transport)"
    $sess = $null
    try {
        $sess = New-EntrySession -ComputerNameOrHost $h
        Ok "Session open to $h"

        # push the payload
        Info "Copying tooling to ${h}:$RemoteDir"
        Invoke-Command -Session $sess -ScriptBlock { param($d) if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } } -ArgumentList $RemoteDir
        foreach ($name in $payload.Keys) {
            Copy-Item -Path $payload[$name] -Destination (Join-Path $RemoteDir $name) -ToSession $sess -Force
        }
        Ok "Payload copied"

        # run
        Invoke-Command -Session $sess -ScriptBlock $runner -ArgumentList `
            $RemoteDir, $doAudit, $doHarden, $Mode, [bool]$DryRun, [bool]$Local, [bool]$BootstrapWinRM, `
            [bool]$EnableSSH, [bool]$SSHKeyOnly, $SSHPublicKey, $AuditArgs, $HardenArgs

        # cleanup
        if (-not $KeepRemote) {
            Invoke-Command -Session $sess -ScriptBlock { param($d) Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue } -ArgumentList $RemoteDir
            Info "Removed remote copy ($RemoteDir). Use -KeepRemote to leave it in place."
        } else {
            Warn "Left tooling on ${h}:$RemoteDir  (-KeepRemote)"
        }
        Ok "Finished $h"
    } catch {
        Fail "$h : $($_.Exception.Message)"
        if ($Transport -eq 'WinRM') {
            Warn "WinRM tips from Linux: target must have WinRM listening; try -Authentication Negotiate (NTLM) or Kerberos, add -UseSSL for 5986. Verify with:  Test-NetConnection $h -Port 5985"
        } else {
            Warn "SSH tips: target needs OpenSSH Server + the PowerShell subsystem line in sshd_config:  Subsystem powershell pwsh.exe -sshs -NoLogo"
        }
    } finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }
}

Write-Host ("`n" + ("=" * 78)) -ForegroundColor Cyan
Ok "All entry hosts processed."
Write-Host "  Record any generated passwords now (they were printed above, not saved)." -ForegroundColor Gray
