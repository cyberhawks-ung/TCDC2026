#!/usr/bin/env bash
# Local read-only audit, except creation of a private report directory.
# Run on the listed Ubuntu hosts, or a confirmed Linux jumpbox. No configuration changes.
set -u
umask 077
machine=''
base='.'
usage() { printf 'Usage: bash audit-linux.sh --machine NAME [--output-parent EXISTING_DIRECTORY]\nNames: ns1 ftp-archive artifactorium ssh-workstation ipcam jumpbox\n'; }
while (($#)); do
  case "$1" in
    --machine) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; machine=$2; shift 2 ;;
    --output-parent) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; base=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
case "$machine" in
  ns1) expected='10.106.10.53' ;;
  ftp-archive) expected='10.106.10.21' ;;
  artifactorium) expected='10.106.10.80' ;;
  ssh-workstation) expected='10.106.10.22' ;;
  ipcam) expected='10.150.0.6' ;;
  jumpbox) expected='10.106.40.22 10.99.6.2' ;;
  *) usage >&2; exit 2 ;;
esac
command -v ip >/dev/null 2>&1 || { echo 'ip command required to check local scope.' >&2; exit 2; }
local_ips=$(ip -o -4 address show | awk '{split($4,a,"/"); print a[1]}')
matched=0
for address in $expected; do
  if printf '%s\n' "$local_ips" | grep -Fqx "$address"; then matched=1; fi
done
[[ $matched == 1 ]] || { echo 'Refusing: the named Team 6 address is not assigned locally. No report created.' >&2; exit 2; }
[[ -d "$base" && ! -L "$base" ]] || { echo 'Output parent must be an existing real directory.' >&2; exit 2; }
out=$(mktemp -d "$base/linux-audit-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || exit 1
exec 3>&1
exec >"$out/report.txt" 2>&1
run() {
  printf '\n###'; printf ' %q' "$@"; printf '\n'
  if command -v "$1" >/dev/null 2>&1; then
    timeout 30 "$@"; rc=$?; printf '\n[exit=%s]\n' "$rc"
  else printf '[unavailable]\n'; fi
}
printf 'Team 6 machine: %s; local audit UTC: %s; uid=%s\n' "$machine" "$(date -u +%FT%TZ)" "$EUID"
printf 'Evidence may contain sensitive usernames, paths and log messages. Protect it.\n'
run hostnamectl
run cat /etc/os-release
run uname -a
run ip -brief address
run ip route
run ip -6 route
run ss -lntup
run systemctl --no-pager --failed
run systemctl --no-pager list-units --type=service --state=running
run systemctl --no-pager list-timers --all
run getent passwd
run getent group sudo
run getent group adm
run getent group docker
run awk -F: '$3 == 0 {print $1 ": uid 0"}' /etc/passwd
run /usr/sbin/sshd -T
run visudo -c
run last -n 30
run journalctl --no-pager --since '-2 hours' -n 400 -u ssh -u sshd
run journalctl --no-pager --since '-2 hours' -n 400 -p warning
run nft list ruleset
run ufw status verbose
run aa-status
run sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
run dpkg-query -W '-f=${binary:Package}\t${Version}\n'
run apt-cache policy openssh-server bind9 vsftpd proftpd-core nginx apache2
run apt-get -s upgrade
run df -h
run timedatectl status
run find /etc/cron.d /etc/cron.daily /etc/systemd/system -xdev -maxdepth 2 -type f -printf '%m %u %g %p\n'
run find /root/.ssh /home -xdev -maxdepth 4 -type f -name authorized_keys -printf '%m %u %g %p\n'
printf '\nNo secret files, private keys, password hashes or environment blocks intentionally collected.\n'
printf 'Use sshd -T -C user=...,host=...,addr=... separately for each Match context.\n'
printf '\nReport directory: %s\n' "$out"
printf 'Report directory: %s\n' "$out" >&3
