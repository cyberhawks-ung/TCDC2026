#!/usr/bin/env bash
# =============================================================================
#  deploy.sh - run the CCDC Windows tooling from Linux / macOS
# =============================================================================
#  Thin wrapper around Invoke-CCDC.ps1. It only needs PowerShell 7 (pwsh);
#  the actual Windows hardening runs on the target(s) over WinRM or SSH.
#
#  USAGE
#    ./deploy.sh -H dc01.range.local -u 'RANGE\Administrator'                # audit dry-run, whole domain
#    ./deploy.sh -H 10.0.0.10 -u Administrator -t Both -m Apply -b           # apply + reset, bootstrap WinRM
#    ./deploy.sh -H dc01 -u Administrator -S                                 # over SSH instead of WinRM
#    ./deploy.sh -H web01 -u Administrator -L                                # single non-domain box (-Local)
#
#  FLAGS
#    -H HOST      entry host (Domain Controller recommended). Repeatable: -H a -H b
#    -u USER      Windows username (e.g. 'DOMAIN\Administrator'). Prompts for password.
#    -t TASK      Audit | Harden | Both            (default Both)
#    -m MODE      Audit | Apply   (Harden mode)    (default Audit)
#    -n           dry run (audit-only, changes nothing)
#    -b           bootstrap WinRM on unreachable domain hosts (enables propagation)
#    -L           -Local: run the tools in single-box mode (no domain sweep)
#    -S           use SSH transport instead of WinRM
#    -s           use SSL/HTTPS for WinRM (port 5986)
#    -A AUTH      WinRM auth: Negotiate | Kerberos | Basic | CredSSP  (default Negotiate)
#    -d DIR       local folder containing the .ps1 + user_config.txt (default: this script's dir)
#    -x           install OpenSSH Server on the targets as a redundant admin channel
#    -y           with -x: disable SSH password auth (key only)
#    -P FILE      with -x: OpenSSH public key file to install for administrators
#    -h           help
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS=(); USER_NAME=""; TASK="Both"; MODE="Audit"; AUTH="Negotiate"
DRYRUN=0; BOOT=0; LOCAL=0; SSH=0; SSL=0; SRC="$HERE"; ENSSH=0; KEYONLY=0; PUBKEYFILE=""

usage() { sed -n '2,33p' "$0"; exit "${1:-0}"; }

while getopts ":H:u:t:m:A:d:P:nbLSsxyh" opt; do
  case "$opt" in
    H) HOSTS+=("$OPTARG") ;;
    u) USER_NAME="$OPTARG" ;;
    t) TASK="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    A) AUTH="$OPTARG" ;;
    d) SRC="$OPTARG" ;;
    P) PUBKEYFILE="$OPTARG" ;;
    n) DRYRUN=1 ;;
    b) BOOT=1 ;;
    L) LOCAL=1 ;;
    S) SSH=1 ;;
    s) SSL=1 ;;
    x) ENSSH=1 ;;
    y) KEYONLY=1 ;;
    h) usage 0 ;;
    \?) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
    :) echo "Option -$OPTARG needs a value" >&2; usage 1 ;;
  esac
done

if ! command -v pwsh >/dev/null 2>&1; then
  echo "ERROR: PowerShell 7 (pwsh) is not installed." >&2
  echo "  Debian/Ubuntu:  sudo apt-get install -y powershell   (after adding the MS repo)" >&2
  echo "  Fedora/RHEL:    sudo dnf install -y powershell" >&2
  echo "  or see https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux" >&2
  exit 2
fi

if [ "${#HOSTS[@]}" -eq 0 ]; then echo "ERROR: at least one -H HOST is required." >&2; usage 1; fi
if [ -z "$USER_NAME" ]; then echo "ERROR: -u USER is required." >&2; usage 1; fi

# build pwsh argument list
ARGS=( -NoProfile -File "$HERE/Invoke-CCDC.ps1"
       -EntryHost "$(IFS=,; echo "${HOSTS[*]}")"
       -Username "$USER_NAME"
       -Task "$TASK" -Mode "$MODE" -Authentication "$AUTH"
       -ScriptSource "$SRC" )

[ "$DRYRUN" -eq 1 ] && ARGS+=( -DryRun )
[ "$BOOT"   -eq 1 ] && ARGS+=( -BootstrapWinRM )
[ "$LOCAL"  -eq 1 ] && ARGS+=( -Local )
[ "$SSH"    -eq 1 ] && ARGS+=( -Transport SSH )
[ "$SSL"    -eq 1 ] && ARGS+=( -UseSSL )
[ "$ENSSH"  -eq 1 ] && ARGS+=( -EnableSSH )
[ "$KEYONLY" -eq 1 ] && ARGS+=( -SSHKeyOnly )
if [ -n "$PUBKEYFILE" ]; then
  if [ ! -f "$PUBKEYFILE" ]; then echo "ERROR: public key file not found: $PUBKEYFILE" >&2; exit 2; fi
  ARGS+=( -SSHPublicKey "$(tr -d '\r\n' < "$PUBKEYFILE")" )
fi

echo "[*] pwsh ${ARGS[*]}"
exec pwsh "${ARGS[@]}"
