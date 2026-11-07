#!/usr/bin/env bash
# detect-change.sh — TCDC SMC 2026 · host compromise detector.
#
#   First run takes a BASELINE of what this box looks like.
#   Every run after that DIFFS against the baseline and reports only changes.
#
# Detection only. It never changes an account, a file, a service or a firewall
# rule on this box. For every finding it prints the exact command to
# investigate and the exact command to fix, and a human decides. The only
# things it writes are its own baseline and its own log.
#
# RUNS LOCALLY ON EACH BOX. scp it over like rotate-creds.sh and run it in a
# terminal:
#
#     scp detect-change.sh root@<box>:/root/
#     ssh root@<box>
#     /root/detect-change.sh --baseline      # once, as early in the round as possible
#     /root/detect-change.sh --watch 60      # leave this in a terminal
#
# Run it inside tmux. If the terminal dies the detector dies with it and
# NOTHING TELLS YOU — that is the cost of having no daemon and no timer.
#
# ---------------------------------------------------------------------------
# DESIGN
#
#   * ONE FLAT FACT STREAM. Every check, whatever it looks at, emits
#     "section<TAB>key<TAB>value". The baseline is that stream, sorted. A
#     cycle is a diff of old against new, which yields ADDED / REMOVED /
#     CHANGED (old -> new) uniformly for every check. Adding a check is one
#     function; the diff engine never changes.
#
#   * TWO CLASSES OF FINDING. A pure baseline diff has a fatal blind spot: if
#     Red Team is already in when the baseline is taken, their backdoor is
#     recorded as normal and never reported. So alongside the DIFF findings
#     there are ALWAYS findings - things that are wrong regardless of the
#     baseline (a second UID 0, /etc/ld.so.preload existing, a service user
#     running an interactive shell, a listener on an implant port). Those fire
#     on the very first run.
#
#   * NO PERSISTENCE OF ITS OWN. No systemd unit, no cron entry, no installed
#     agent. It runs in a terminal. That means it has no artifact of its own
#     to allow-list and no artifact for Red Team to find and edit.
#
#   * CHEAP AND HEAVY TIERS. The cheap checks (accounts, sudoers, keys, cron,
#     units, processes, ports, sessions, /tmp) run every cycle. The expensive
#     ones (dpkg --verify, the SUID sweep, hashing the web roots) are read-only
#     but still cost real disk I/O on a box whose uptime is being scored, so
#     they run every heavy_interval seconds (default 600), niced, and never
#     twice in one cycle.
#
#   * THE SHADOW FILE IS NEVER COPIED. The baseline stores a truncated sha256
#     OF each hash, never the hash. Enough to see a password change; useless to
#     anyone who steals the baseline. (R23 hygiene — the jumpbox and this state
#     directory must not become a second copy of every credential on the box.)
#
#   * STATE LIVES ON THE BOX IT WATCHES, which is the one real weakness of
#     running locally: root can edit the baseline so a backdoor reads as
#     normal. Mitigations: the baseline's sha256 is printed on creation and on
#     every startup so you can compare it against a copy you keep off-box, and
#     an unexplained change to the baseline file is itself a CRIT finding.
#     Copy $STATE/baseline.facts off this box once, right after --baseline.
#
# Rules compliance (TCDC SMC packet):
#   R7/R8  — reports on every account including blackteam/whiteteam and root,
#            but modifies none of them, and logged-in sessions for blackteam
#            and whiteteam are excluded from findings by default.
#   R11-R13— nothing is deleted, moved, quarantined or disabled. Ever.
#   R20    — no credentials, no hostnames, no team-specific data in this file.
#            Safe to commit. Keep detect.conf out of the repo.
#
set -uo pipefail

PROG=${0##*/}
VERSION=1.0

# ---------------------------------------------------------------- defaults ---
MODE=""                       # baseline | once | watch | status | accept | resolve
INTERVAL=60
PREFIX=""                     # test hook: treat DIR as /
STATE=""                      # default /var/lib/tcdc/detect  (or PREFIX-relative)
LOGDIR=""                     # default /var/log/tcdc/detect
CONFIG=""                     # default /etc/tcdc/detect.conf
HEAVY_INTERVAL=600
DO_HEAVY=1
DO_LIVE=1                     # process / socket / session checks
FORCE=0
ASSUME_YES=0
QUIET=0
BELL=1
ACCEPT_SPEC=""
RESOLVE_ID=""
APPEND_ONLY=0                 # chattr +a the alert log
MAX_EVIDENCE_KB=64
MAX_WEB_FILES=4000
MAX_TMP_FILES=2000

# Where dropped web content lives. Overridable with 'webroot' in the config.
WEBROOTS=(/var/www /srv/www /usr/share/nginx/html /var/www/html)
TMPDIRS=(/tmp /var/tmp /dev/shm)

# Ports that are an implant until proven otherwise. ALWAYS findings.
IMPLANT_PORTS='^(4444|4445|1337|31337|6666|6667|5555|8888|9001|9002|12345|54321|2222)$'

# Service accounts that have no business running an interactive shell.
SERVICE_USERS='^(www-data|bind|named|ftp|vsftpd|proftpd|tftp|mosquitto|mysql|postgres|redis|memcache|nginx|apache|apache2|clamav|postfix|dovecot|snmp|lp|mail|news|irc|gnats|list|uucp|proxy|backup|sync|games|man|nobody|daemon|bin|sys|_apt|syslog|messagebus|sshd|tss|uuidd|tcpdump|chrony|polkitd|lxd|dnsmasq|systemd-.*)$'

# Interpreters and network tools that are how a shell comes back.
INTERPRETERS='^(sh|bash|dash|ksh|zsh|csh|tcsh|ash|busybox|python|python2|python3|python3\.[0-9]+|perl|ruby|php|php[0-9.]*|lua[0-9.]*|node|nc|nc\.openbsd|nc\.traditional|ncat|netcat|socat|telnet|awk|gawk|mawk|xterm|script)$'

# Out-of-scope humans. Their sessions are noise, not findings (R8).
OUT_OF_SCOPE_SESSIONS='^(blackteam|whiteteam)$'

# Privileged groups worth tracking membership of.
PRIV_GROUPS=(root sudo admin wheel adm shadow disk docker lxd systemd-journal)

# Baked-in noise suppression. Every one of these is something that changes on
# a healthy Ubuntu box and would otherwise cry wolf every 60 seconds.
DEFAULT_IGNORES=(
  'tmpfile:.*/systemd-private-[0-9a-f]+'          # systemd PrivateTmp dirs
  'tmpfile:.*/snap\.[^/]+'                        # snapd
  'tmpfile:.*/\.X11-unix'
  'tmpfile:.*/\.XIM-unix'
  'tmpfile:.*/\.font-unix'
  'tmpfile:.*/\.ICE-unix'
  'tmpfile:.*/ssh-[A-Za-z0-9]+'                   # agent sockets
  'tmpfile:.*/tmux-[0-9]+'
  'tmpfile:.*/vmware-.*'
  'tmpfile:.*/pulse-.*'
  'tmpfile:.*/clamav-[0-9a-f]+'                   # scan-host.sh's own scratch
  'tmpfile:.*/tcdc-.*'                            # our own tooling
  'listen:udp:[^ ]*:(3[2-9][0-9]{3}|[4-6][0-9]{4}) .*exe=(/usr/sbin/named|named)'
  'conn:.*exe=(/usr/lib/apt/methods/|/usr/bin/apt|/usr/bin/dpkg|/usr/bin/freshclam|/usr/bin/curl /etc/apt)'
  'proc:shell:www-data:(sh|bash):.*(php-fpm|/usr/sbin/apache2|logrotate)'
  'session:.*:(tmux|screen)'
)

# ------------------------------------------------------------------ output ---
if [ -t 2 ]; then C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_C=$'\033[36m'; C_M=$'\033[35m'; C_B=$'\033[1m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else C_R=; C_G=; C_Y=; C_C=; C_M=; C_B=; C_D=; C_0=; fi
TTY=0; [ -t 2 ] && TTY=1

info() { [ "$QUIET" = 1 ] || printf '%s\n' "$*" >&2; }
ok()   { [ "$QUIET" = 1 ] || printf '%s[ ok ]%s %s\n' "$C_G" "$C_0" "$*" >&2; }
warn() { printf '%s[warn]%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
err()  { printf '%s[FAIL]%s %s\n' "$C_R" "$C_0" "$*" >&2; }
crit() { printf '%s[CRIT]%s %s\n' "$C_R" "$C_0" "$*" >&2; }
act()  { printf '%s[ACT ]%s %s\n' "$C_C" "$C_0" "$*" >&2; }
say()  { printf '%s\n' "$*" >&2; }
die()  { err "$*"; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }
hr()   { [ "$QUIET" = 1 ] || printf '%s%s%s\n' "$C_D" "--------------------------------------------------------------------------" "$C_0" >&2; }

usage() {
  cat >&2 <<__HELP__
$PROG v$VERSION — baseline this box, then report everything that changes

  Detection only. Nothing on this box is ever modified, deleted or disabled.
  Every finding comes with the command to investigate it and the command to
  fix it, for a human to run.

ACTIONS
  --baseline              record what this box looks like now (do this FIRST,
                          as early in the round as you can)
  --once                  one comparison against the baseline, then exit
  --watch [SECONDS]       compare every SECONDS (default $INTERVAL) until ctrl-C
  --status                list the findings that are still open
  --accept SPEC           fold current reality into the baseline: "that was me"
                            --accept shadow              (after a rotation)
                            --accept file:/etc/sudoers
                            --accept all                 (needs --yes)
  --resolve ID            close one open finding by its id
  --help, --version

OPTIONS
  --interval N            seconds between cycles in --watch       (default $INTERVAL)
  --heavy-interval N      seconds between the expensive checks     (default $HEAVY_INTERVAL)
  --no-heavy              never run dpkg --verify, the SUID sweep or web hashing
  --no-live               skip process / socket / session checks
  --config FILE           allowlist and settings        (default /etc/tcdc/detect.conf)
  --state DIR             baseline and state           (default /var/lib/tcdc/detect)
  --log-dir DIR           alert log                    (default /var/log/tcdc/detect)
  --append-only           chattr +a the alert log so alerts cannot be trimmed
                          (note: this also stops logrotate; -a to undo)
  --no-bell               do not ring the terminal bell on a CRIT finding
  --force                 allow --baseline to overwrite an existing baseline
  --yes                   do not prompt for confirmation
  --quiet                 findings and the verdict only
  --prefix DIR            treat DIR as / (test hook — used by the test suite)

WHAT IT WATCHES
  accounts   new users, UID 0, shell changes, sudo/adm/docker/lxd membership,
             /etc/sudoers + sudoers.d, /etc/shadow hash changes
  ssh        authorized_keys for every user, sshd_config
  persist    crontabs (users + /etc/cron*), systemd units and timers,
             /etc/ld.so.preload, /etc/profile.d, user dotfiles, rc.local, PAM
  binaries   new SUID/SGID files, dpkg --verify drift, deleted-exe processes
  processes  shells and interpreters owned by or parented to a service user
  network    new listening ports, outbound connections to never-before-seen IPs
  files      new files in /tmp, /dev/shm, /var/tmp and the web roots
  sessions   who is logged in (blackteam and whiteteam excluded)

EXIT CODES
  0  nothing changed and nothing outstanding
  1  new findings, or findings still open from an earlier cycle
  2  usage or preflight error
  3  baseline missing, unreadable or tampered with

TYPICAL ROUND
  $PROG --baseline                  # then copy \$STATE/baseline.facts off-box
  $PROG --watch 60                  # leave it running in tmux
  # after you rotate passwords yourself:
  $PROG --accept shadow
__HELP__
}

# ------------------------------------------------------------ arg parsing ---
want_mode() { [ -z "$MODE" ] || die "pick one action, not both --$MODE and --$1"; MODE=$1; }

while [ $# -gt 0 ]; do
  case $1 in
    --baseline)  want_mode baseline;;
    --once)      want_mode once;;
    --watch)     want_mode watch
                 if [ $# -gt 1 ] && [[ ${2:-} =~ ^[0-9]+$ ]]; then INTERVAL=$2; shift; fi;;
    --status)    want_mode status;;
    --accept)    want_mode accept; ACCEPT_SPEC=${2:?--accept needs a SPEC}; shift;;
    --resolve)   want_mode resolve; RESOLVE_ID=${2:?--resolve needs an ID}; shift;;
    --interval)  INTERVAL=${2:?}; shift;;
    --heavy-interval) HEAVY_INTERVAL=${2:?}; shift;;
    --no-heavy)  DO_HEAVY=0;;
    --no-live)   DO_LIVE=0;;
    --config)    CONFIG=${2:?}; shift;;
    --state)     STATE=${2:?}; shift;;
    --log-dir)   LOGDIR=${2:?}; shift;;
    --append-only) APPEND_ONLY=1;;
    --no-bell)   BELL=0;;
    --force)     FORCE=1;;
    --yes|-y)    ASSUME_YES=1;;
    --quiet|-q)  QUIET=1;;
    --prefix)    PREFIX=${2:?}; shift;;
    --help|-h)   usage; exit 0;;
    --version)   printf '%s %s\n' "$PROG" "$VERSION"; exit 0;;
    --) shift; break;;
    *) err "unknown argument: $1"; usage; exit 2;;
  esac
  shift
done

[ -n "$MODE" ] || { usage; exit 2; }
[[ $INTERVAL =~ ^[0-9]+$ ]] || die "--interval must be a whole number of seconds"
[ "$INTERVAL" -ge 5 ] || die "--interval below 5s will cost more in load than it buys in detection"
[[ $HEAVY_INTERVAL =~ ^[0-9]+$ ]] || die "--heavy-interval must be a whole number of seconds"

if [ -n "$PREFIX" ]; then
  PREFIX=${PREFIX%/}
  [ -d "$PREFIX" ] || die "--prefix $PREFIX is not a directory"
  [ -r "$PREFIX/etc/passwd" ] || die "--prefix $PREFIX has no etc/passwd — wrong directory?"
fi

# Paths. p() is the only way this script names a file: with --prefix set every
# path lands inside the fake root, which is what makes the suite able to test
# a tool that normally reads /etc/shadow.
p() { printf '%s%s' "$PREFIX" "$1"; }

: "${STATE:=$(p /var/lib/tcdc/detect)}"
: "${LOGDIR:=$(p /var/log/tcdc/detect)}"
: "${CONFIG:=$(p /etc/tcdc/detect.conf)}"

BASELINE="$STATE/baseline.facts"
META="$STATE/baseline.meta"
EVIDENCE="$STATE/evidence"
SEEN_IPS="$STATE/seen-ips"
FINDINGS="$STATE/open-findings"
HEAVY_STAMP="$STATE/last-heavy"
HEAVY_CACHE="$STATE/heavy.facts"
ALERTLOG="$LOGDIR/alerts.log"
LOCKFILE="$STATE/.lock"

HOSTN=$(hostname 2>/dev/null || echo unknown)

# ------------------------------------------------------------------ config ---
IGNORES=("${DEFAULT_IGNORES[@]}")
SCORING_IPS=()

load_config() {
  [ -r "$CONFIG" ] || return 0
  local line key val n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n+1))
    line=${line%%#*}
    line=$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -n "$line" ] || continue
    key=${line%% *}; val=${line#* }
    [ "$key" = "$line" ] && val=""
    case $key in
      ignore)          [ -n "$val" ] && IGNORES+=("$val");;
      webroot)         [ -n "$val" ] && WEBROOTS+=("$val");;
      tmpdir)          [ -n "$val" ] && TMPDIRS+=("$val");;
      scoring_ip)      [ -n "$val" ] && SCORING_IPS+=("$val");;
      heavy_interval)  [[ $val =~ ^[0-9]+$ ]] && HEAVY_INTERVAL=$val;;
      interval)        [[ $val =~ ^[0-9]+$ ]] && INTERVAL=$val;;
      max_evidence_kb) [[ $val =~ ^[0-9]+$ ]] && MAX_EVIDENCE_KB=$val;;
      max_web_files)   [[ $val =~ ^[0-9]+$ ]] && MAX_WEB_FILES=$val;;
      implant_ports)   IMPLANT_PORTS="^($(printf '%s' "$val" | tr -s ' ,' '|'))\$";;
      *) warn "$CONFIG:$n: unknown directive '$key' (ignored)";;
    esac
  done < "$CONFIG"
  # A scoring engine's IP is expected outbound traffic, not a finding.
  local ip
  for ip in "${SCORING_IPS[@]}"; do
    IGNORES+=("conn:$(printf '%s' "$ip" | sed 's/\./\\./g'):")
  done
}
load_config

# ignored <section> <key> <value> — true if a baked-in or configured regex
# matches. Matched against "section:key value", extended regex, case sensitive.
ignored() {
  local subject="$1:$2 $3" re
  for re in "${IGNORES[@]}"; do
    printf '%s' "$subject" | grep -qE -- "$re" && return 0
  done
  return 1
}

# ============================================================== COLLECTORS ===
#
# Every collector prints zero or more lines of
#     section<TAB>key<TAB>value
# on stdout and nothing else. No collector writes to the box. Keys must be
# STABLE between cycles or everything looks changed every minute, which is why
# nothing is keyed on a pid, an ephemeral port or a line number.

# fact <section> <key> <value>  — tabs and newlines are squeezed out so one
# fact is always exactly one line.
fact() {
  local s=$1 k=$2 v=$3
  k=${k//$'\t'/ }; k=${k//$'\n'/ }
  v=${v//$'\t'/ }; v=${v//$'\n'/ }
  printf '%s\t%s\t%s\n' "$s" "$k" "$v"
}

# truncated sha256 — long enough that a collision is not a practical concern,
# short enough that a fact line stays readable in a terminal.
h12()  { [ -r "$1" ] && sha256sum -- "$1" 2>/dev/null | cut -c1-12 || printf 'unreadable'; }
hs()   { printf '%s' "$1" | sha256sum | cut -c1-12; }
fmeta() { stat -c 'mode=%a owner=%u:%g size=%s' -- "$1" 2>/dev/null || printf 'mode=? owner=? size=?'; }

# Resolved tool paths are recorded as facts: a PATH shim is how the test suite
# feeds this fake `ss` output, and a /usr/local/bin/ss shadowing the real one
# is exactly the kind of change worth catching.
SS_CMD=$(command -v ss || true)
PS_CMD=$(command -v ps || true)
WHO_CMD=$(command -v who || true)
DPKG_CMD=$(command -v dpkg || true)
NICE=""
have nice && NICE="nice -n 19"
have ionice && NICE="$NICE ionice -c3"

collect_tools() {
  local t
  for t in ss ps who dpkg sha256sum find stat; do
    fact tool "$t" "path=$(command -v "$t" 2>/dev/null || echo MISSING)"
  done
}

# --------------------------------------------------------------- accounts ---
collect_users() {
  local pw; pw=$(p /etc/passwd); [ -r "$pw" ] || return 0
  awk -F: 'NF>=7 {printf "%s\t%s\t%s\t%s\t%s\n", $1,$3,$4,$6,$7}' "$pw" |
  while IFS=$'\t' read -r name uid gid home shell; do
    fact user "$name" "uid=$uid gid=$gid shell=$shell home=$home"
  done
}

collect_groups() {
  local gf; gf=$(p /etc/group); [ -r "$gf" ] || return 0
  local g members
  for g in "${PRIV_GROUPS[@]}"; do
    members=$(awk -F: -v g="$g" '$1==g{print $4}' "$gf" |
              tr ',' '\n' | grep -v '^$' | LC_ALL=C sort | paste -sd, -)
    # A privileged group that exists but is empty is still a fact worth
    # holding: somebody being ADDED to it is the finding.
    awk -F: -v g="$g" '$1==g{f=1} END{exit !f}' "$gf" || continue
    fact group "$g" "members=${members:-none}"
  done
}

# The hash itself is NEVER stored. h= is a truncated sha256 OF the hash, which
# detects a change without the baseline becoming a crackable credential dump.
collect_shadow() {
  local sf; sf=$(p /etc/shadow); [ -r "$sf" ] || return 0
  local name hash state lastchg
  while IFS=: read -r name hash lastchg _; do
    [ -n "$name" ] || continue
    case $hash in
      '')        state=EMPTY;;
      '!'*|'*')  state=locked;;
      '*'*)      state=nologin;;
      '$'*)      state=active;;
      *)         state=other;;
    esac
    fact shadow "$name" "state=$state h=$(hs "$hash") lastchg=$lastchg"
  done < "$sf"
}

# ------------------------------------------------------------------ files ---
# Text files whose CONTENT matters: a copy is kept (capped) so an alert can
# show the line that was added rather than only "the hash changed".
EVIDENCE_WORTHY='^(/etc/sudoers|/etc/sudoers\.d/|/etc/ld\.so\.preload|/etc/profile$|/etc/profile\.d/|/etc/bash\.bashrc|/etc/rc\.local|/etc/pam\.d/|/etc/crontab|/etc/cron\.|/var/spool/cron/crontabs/|/etc/ssh/sshd_config|.*/\.ssh/authorized_keys|.*/\.(bashrc|profile|bash_profile|bash_login|bash_logout)$|/etc/systemd/system/)'

ev_path() { printf '%s/%s' "$EVIDENCE" "$(printf '%s' "$1" | sed 's|/|%|g')"; }

# save_evidence <real-path> <logical-path>
save_evidence() {
  local real=$1 logical=$2 dest
  printf '%s' "$logical" | grep -qE -- "$EVIDENCE_WORTHY" || return 0
  [ -f "$real" ] && [ -r "$real" ] || return 0
  [ "$(stat -c %s -- "$real" 2>/dev/null || echo 999999)" -le $((MAX_EVIDENCE_KB*1024)) ] || return 0
  dest=$(ev_path "$logical")
  mkdir -p "$EVIDENCE" 2>/dev/null
  cp -- "$real" "$dest" 2>/dev/null && chmod 600 "$dest" 2>/dev/null
}

# file_fact <real-path>  — emits one fact keyed on the path as it appears on a
# real box (the --prefix is stripped) so a baseline is portable and readable.
file_fact() {
  local real=$1 logical=${1#$PREFIX}
  [ -e "$real" ] || return 0
  if [ -L "$real" ]; then
    fact file "$logical" "symlink-> $(readlink -- "$real" 2>/dev/null) $(fmeta "$real")"
    return 0
  fi
  [ -f "$real" ] || return 0
  fact file "$logical" "sha256=$(h12 "$real") $(fmeta "$real")"
}

# The fixed list of files whose change is always interesting, plus the
# directories where a NEW file is itself the finding.
collect_files() {
  local f d

  for f in /etc/sudoers /etc/ld.so.preload /etc/rc.local /etc/crontab \
           /etc/profile /etc/bash.bashrc /etc/login.defs /etc/nsswitch.conf \
           /etc/ssh/sshd_config /etc/hosts /etc/resolv.conf /etc/passwd \
           /etc/group /etc/gshadow /etc/shells /etc/sudoers.d /etc/systemd/system; do
    [ -e "$(p "$f")" ] || continue
    if [ -d "$(p "$f")" ]; then
      fact dirmode "$f" "$(fmeta "$(p "$f")")"
    else
      file_fact "$(p "$f")"
    fi
  done

  # Directories where every file is tracked individually.
  for d in /etc/sudoers.d /etc/profile.d /etc/pam.d /etc/cron.d \
           /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
           /etc/ssh/sshd_config.d /var/spool/cron/crontabs /etc/ld.so.conf.d; do
    [ -d "$(p "$d")" ] || continue
    while IFS= read -r f; do file_fact "$f"; done < <(
      find "$(p "$d")" -maxdepth 1 -mindepth 1 \( -type f -o -type l \) 2>/dev/null | LC_ALL=C sort)
  done

  # systemd units: anything under /etc/systemd/system and /run/systemd/system,
  # at any depth, plus new files appearing in the vendor directories.
  for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [ -d "$(p "$d")" ] || continue
    while IFS= read -r f; do file_fact "$f"; done < <(
      find "$(p "$d")" -mindepth 1 \( -type f -o -type l \) \
           \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) \
           2>/dev/null | LC_ALL=C sort)
  done
}

# Per-user files: authorized_keys (one fact per KEY, so you see which key
# appeared) and the login scripts that are the cheapest persistence there is.
collect_user_files() {
  local pw; pw=$(p /etc/passwd); [ -r "$pw" ] || return 0
  local name home real f
  while IFS=: read -r name _ _ _ _ home _; do
    [ -n "$name" ] && [ -n "$home" ] || continue
    case $home in /|/nonexistent|/dev/null|'') continue;; esac
    real=$(p "$home")
    [ -d "$real" ] || continue

    for f in .bashrc .profile .bash_profile .bash_login .bash_logout .bash_aliases \
             .ssh/rc .ssh/config .ssh/environment .selected_editor; do
      [ -e "$real/$f" ] && file_fact "$real/$f"
    done

    # .ssh directory mode matters as much as its contents.
    [ -d "$real/.ssh" ] && fact dirmode "$home/.ssh" "$(fmeta "$real/.ssh")"

    for f in authorized_keys authorized_keys2; do
      [ -r "$real/.ssh/$f" ] || continue
      fact file "$home/.ssh/$f" "sha256=$(h12 "$real/.ssh/$f") $(fmeta "$real/.ssh/$f")"
      # One fact per key, keyed on the key material so reordering the file is
      # not a change but adding a key is.
      local ktype kdata kcomment
      while read -r ktype kdata kcomment; do
        [ -n "$kdata" ] || continue
        case $ktype in '#'*|'') continue;; esac
        # options-prefixed lines: shift along until a key type shows up
        case $ktype in
          ssh-*|ecdsa-*|sk-*) :;;
          *) continue;;
        esac
        fact akey "$name:$f:$(hs "$kdata")" "type=$ktype comment=${kcomment:-none}"
      done < "$real/.ssh/$f"
    done
  done < "$pw"
}

# ------------------------------------------------------------------- live ---
# Processes, sockets and sessions. These cannot be faked with a directory of
# files, so they go through $SS_CMD / $PS_CMD / $WHO_CMD, which the test suite
# shims on PATH.

collect_proc() {
  [ "$DO_LIVE" = 1 ] || return 0
  local procdir; procdir=$(p /proc)
  [ -d "$procdir" ] || return 0

  # 1. Processes whose executable has been deleted from disk. A normal daemon
  #    shows this after an apt upgrade until it is restarted, so it is a
  #    finding and not a crisis — but a memory-resident implant that unlinked
  #    itself looks exactly like this and nothing else does.
  local pid exe owner comm
  while IFS= read -r pid; do
    exe=$(readlink -- "$procdir/$pid/exe" 2>/dev/null) || continue
    [ -n "$exe" ] || continue
    case $exe in
      *' (deleted)')
        owner=$(stat -c %U -- "$procdir/$pid" 2>/dev/null || echo '?')
        comm=$(tr -d '\0' < "$procdir/$pid/comm" 2>/dev/null | head -1)
        # keyed on exe+owner, not pid: a respawning implant stays ONE finding
        fact proc "deleted:${exe% (deleted)}:$owner" "comm=$comm"
        ;;
    esac
  done < <(find "$procdir" -maxdepth 1 -mindepth 1 -regextype posix-extended \
                -regex '.*/[0-9]+' -printf '%f\n' 2>/dev/null | LC_ALL=C sort -n)

  # 2. Shells and interpreters belonging to, or parented by, a service user.
  #    www-data running bash is not a bug in Apache; it is a webshell.
  [ -n "$PS_CMD" ] || return 0
  local -A powner=() pcomm=()
  local u pp cm args
  while read -r u pid pp cm args; do
    [ -n "$pid" ] || continue
    powner[$pid]=$u; pcomm[$pid]=$cm
  done < <("$PS_CMD" -eo user=,pid=,ppid=,comm=,args= 2>/dev/null)

  while read -r u pid pp cm args; do
    [ -n "$pid" ] || continue
    printf '%s' "$cm" | grep -qE -- "$INTERPRETERS" || continue
    local puser=${powner[$pp]:-?} pparent=${pcomm[$pp]:-?}
    # Interesting if the process OR its parent belongs to a service account.
    if printf '%s' "$u" | grep -qE -- "$SERVICE_USERS" ||
       printf '%s' "$puser" | grep -qE -- "$SERVICE_USERS"; then
      fact proc "shell:$u:$cm:$(hs "$args")" "ppid_user=$puser parent=$pparent args=${args:0:160}"
    fi
  done < <("$PS_CMD" -eo user=,pid=,ppid=,comm=,args= 2>/dev/null)
}

# ss output, parsed defensively: the process column is users:(("name",pid=N,fd=N)).
_ss_exe() { printf '%s' "$1" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p'; }
_ss_pid() { printf '%s' "$1" | sed -n 's/.*pid=\([0-9]*\).*/\1/p'; }

collect_listen() {
  [ "$DO_LIVE" = 1 ] || return 0
  [ -n "$SS_CMD" ] || return 0
  local netid state rq sq local_a peer rest exe pid port
  while read -r netid state rq sq local_a peer rest; do
    [ -n "$local_a" ] || continue
    case $netid in tcp|udp) :;; *) continue;; esac
    exe=$(_ss_exe "$rest"); pid=$(_ss_pid "$rest")
    port=${local_a##*:}
    fact listen "$netid:$local_a" "exe=${exe:-unknown} pid=${pid:-?}"
  done < <("$SS_CMD" -lntupH 2>/dev/null)
}

# Outbound connections are the noisiest check on the box, so this is keyed on
# the REMOTE IP and compared against a cumulative list of every IP ever seen.
# Each new IP is reported once, ever — not once per cycle, and not once per
# ephemeral source port.
collect_conn() {
  [ "$DO_LIVE" = 1 ] || return 0
  [ -n "$SS_CMD" ] || return 0
  local rq sq local_a peer rest exe rip
  while read -r rq sq local_a peer rest; do
    [ -n "$peer" ] || continue
    rip=${peer%:*}; rip=${rip#[}; rip=${rip%]}
    [ -n "$rip" ] || continue
    case $rip in 127.0.0.1|::1|'*'|0.0.0.0) continue;; esac
    exe=$(_ss_exe "$rest")
    fact conn "$rip" "port=${peer##*:} exe=${exe:-unknown}"
  done < <("$SS_CMD" -tnpH state established 2>/dev/null)
}

collect_sessions() {
  [ "$DO_LIVE" = 1 ] || return 0
  [ -n "$WHO_CMD" ] || return 0
  local u line rest host
  while read -r u line rest; do
    [ -n "$u" ] || continue
    printf '%s' "$u" | grep -qE -- "$OUT_OF_SCOPE_SESSIONS" && continue
    host=$(printf '%s' "$rest" | sed -n 's/.*(\(.*\)).*/\1/p')
    fact session "$u:$line:${host:-local}" "since=$(printf '%s' "$rest" | sed 's/ *(.*)//')"
  done < <("$WHO_CMD" 2>/dev/null)
}

# -------------------------------------------------------------- tmp + web ---
# These two scan whole directory trees, so they are where a naive
# implementation costs you uptime. The first version forked stat + sha256sum +
# head PER FILE and scanned /var/www and /var/www/html separately because both
# are in the default root list: 460 files took 20 seconds. Measured, not
# guessed. Now metadata comes from one find, hashes from one batched
# sha256sum, and overlapping roots are collapsed.

# dedup_roots <paths...> — drop anything nested inside another path, so a file
# under /var/www/html is never hashed twice.
dedup_roots() {
  local -a out=()
  local a b keep
  while IFS= read -r a; do
    keep=1
    for b in ${out[@]+"${out[@]}"}; do
      case "$a/" in "$b"/*) keep=0; break;; esac
    done
    [ "$keep" = 1 ] && out+=("$a")
  done < <(printf '%s\n' "$@" | LC_ALL=C sort -u)
  printf '%s\n' ${out[@]+"${out[@]}"}
}

# Extensions that cannot execute. Classified as inert so the magic sniff below
# never has to open them.
# Doubled backslash on purpose: awk processes escape sequences in a -v
# assignment, so a single \. arrives as a plain . and matches ANY character.
INERT_EXT='\\.(txt|log|json|xml|csv|dat|conf|cfg|ini|yml|yaml|md|rst|gz|bz2|xz|zip|tar|7z|png|jpe?g|gif|svg|ico|webp|bmp|css|js|map|woff2?|ttf|eot|otf|html?|pdf|mo|po|sql|lock|pid|sock)$'

# scan_tree <section> <root> <max> <want_hash 0|1>
# One find, one sort, one batched sha256sum, one awk. No per-file forks.
scan_tree() {
  local section=$1 root=$2 max=$3 want=$4
  local SCAN_META="$STATE/.scan.$$.meta"
  local SCAN_HASH="$STATE/.scan.$$.hash"
  find "$root" -xdev -type f -printf '%p\t%m\t%U\t%G\t%s\n' 2>/dev/null |
    LC_ALL=C sort | head -n "$max" > "$SCAN_META" 2>/dev/null
  : > "$SCAN_HASH"
  if [ "$want" = 1 ] && [ -s "$SCAN_META" ]; then
    # one sha256sum process per xargs batch, not per file
    cut -f1 "$SCAN_META" | tr '\n' '\0' | xargs -0 -r $NICE sha256sum 2>/dev/null > "$SCAN_HASH"
  fi
  # NOT `NR==FNR`: when want=0 the hash file is EMPTY, and NR/FNR then stay
  # equal for every line of the metadata file, so all of it would be parsed as
  # hash output and nothing would be emitted at all. Key off FILENAME.
  awk -F'\t' -v sec="$section" -v pfx="$PREFIX" -v want="$want" \
      -v inert="$INERT_EXT" -v hashfile="$SCAN_HASH" '
    FILENAME == hashfile {
      if (substr($0,1,1) == "\\") next          # escaped path, left unhashed
      h[substr($0,67)] = substr($0,1,12)
      next
    }
    {
      path=$1; mode=$2; uid=$3; gid=$4; size=$5
      lp = path; if (pfx != "") sub("^" pfx, "", lp)
      low = tolower(path)
      m3  = (length(mode) >= 3) ? substr(mode, length(mode)-2) : mode
      if      (low ~ /\.(php|phtml|php[3-8])$/)                 t="PHP"
      else if (low ~ /\.(sh|bash|zsh|ksh)$/)                    t="SHELL"
      else if (low ~ /\.(pl|py|rb|lua|jsp|asp|aspx|cgi|jar)$/)  t="SCRIPT"
      else if (low ~ inert)                                     t="data"
      else if (m3 ~ /[1357]/)                                   t="EXEC"
      else                                                      t="file"
      v = "type=" t " mode=" mode " owner=" uid ":" gid " size=" size
      if (want == 1) v = v " sha256=" ((path in h) ? h[path] : "unreadable")
      printf "%s\t%s\t%s\n", sec, lp, v
    }
  ' "$SCAN_HASH" "$SCAN_META"
  rm -f "$SCAN_META" "$SCAN_HASH"
}

# A dropped ELF with no extension and no execute bit would read as type=file,
# so the tmp directories (small, and where droppers land) still get a real
# magic sniff. Web roots do not: they hold thousands of files with telling
# extensions, and opening every one of them is what cost 20 seconds. Capped so
# a /tmp full of junk cannot stall a cycle.
SNIFF_CAP=200
sniff_types() {
  local sec k v n=0 real magic
  while IFS=$'\t' read -r sec k v; do
    case $v in
      *'type=file'*|*'type=EXEC'*)
        if [ "$n" -lt "$SNIFF_CAP" ]; then
          n=$((n+1)); real=$(p "$k")
          magic=$(head -c 4 -- "$real" 2>/dev/null | tr -d '\0')
          case $magic in
            $'\177ELF'*) v=${v/type=file/type=ELF};    v=${v/type=EXEC/type=ELF};;
            '#!'*)       v=${v/type=file/type=SCRIPT}; v=${v/type=EXEC/type=SCRIPT};;
          esac
        fi;;
    esac
    printf '%s\t%s\t%s\n' "$sec" "$k" "$v"
  done
}

collect_tmp() {
  local d reals=() r
  for d in "${TMPDIRS[@]}"; do r=$(p "$d"); [ -d "$r" ] && reals+=("$r"); done
  [ ${#reals[@]} -gt 0 ] || return 0
  while IFS= read -r d; do
    [ -n "$d" ] && scan_tree tmpfile "$d" "$MAX_TMP_FILES" 0
  done < <(dedup_roots "${reals[@]}") | sniff_types
}

# Web roots are CONTENT-hashed, not just listed: a defacement replaces
# index.html, it does not add a file.
collect_web() {
  local d reals=() r
  for d in "${WEBROOTS[@]}"; do r=$(p "$d"); [ -d "$r" ] && reals+=("$r"); done
  [ ${#reals[@]} -gt 0 ] || return 0
  while IFS= read -r d; do
    [ -n "$d" ] && scan_tree webfile "$d" "$MAX_WEB_FILES" 1
  done < <(dedup_roots "${reals[@]}")
}

# ------------------------------------------------------------------ heavy ---
collect_suid() {
  local f
  while IFS= read -r f; do
    fact suid "${f#$PREFIX}" "sha256=$(h12 "$f") $(fmeta "$f")"
  done < <(find "$(p /)" -xdev \( -path "$(p /proc)" -o -path "$(p /sys)" -o -path "$(p /run)" \
                 -o -path "$(p /snap)" -o -path "$(p /var/lib/lxcfs)" -o -path "$STATE" \) -prune -o \
                 -type f -perm /6000 -print 2>/dev/null | LC_ALL=C sort)
}

collect_dpkg() {
  [ -n "$DPKG_CMD" ] || return 0
  [ -z "$PREFIX" ] || return 0        # no meaningful dpkg database under a fake root
  local flags path
  while read -r flags path _; do
    [ -n "$path" ] || continue
    fact dpkg "$path" "verify=$flags"
  done < <($NICE "$DPKG_CMD" --verify 2>/dev/null | awk '{print $1, $NF}')
}

# ------------------------------------------------------------ assemble all ---
# The heavy facts are CACHED between cycles and replayed into every fact
# stream. If they were simply omitted on a cheap cycle, every SUID binary on
# the box would look REMOVED one minute and ADDED the next.
heavy_due() {
  [ "$DO_HEAVY" = 1 ] || return 1
  [ -f "$HEAVY_STAMP" ] || return 0
  local last now; last=$(cat "$HEAVY_STAMP" 2>/dev/null || echo 0); now=$(date +%s)
  [ $((now - last)) -ge "$HEAVY_INTERVAL" ]
}

collect_cheap() {
  collect_tools; collect_users; collect_groups; collect_shadow
  collect_files; collect_user_files; collect_proc; collect_listen
  collect_conn; collect_sessions; collect_tmp
}

collect_heavy_now() {
  collect_suid; collect_dpkg; collect_web
}

# collect_all <outfile>
collect_all() {
  local out=$1
  local tmp="$out.part"
  : > "$tmp"
  collect_cheap >> "$tmp" 2>/dev/null
  if heavy_due; then
    info "running the heavy checks (dpkg --verify, SUID sweep, web roots)"
    collect_heavy_now > "$HEAVY_CACHE.part" 2>/dev/null
    mv -f "$HEAVY_CACHE.part" "$HEAVY_CACHE"
    date +%s > "$HEAVY_STAMP"
  fi
  [ -f "$HEAVY_CACHE" ] && cat "$HEAVY_CACHE" >> "$tmp"
  LC_ALL=C sort -u "$tmp" -o "$tmp"
  mv -f "$tmp" "$out"
}

# ======================================================= BASELINE-FREE CHECKS =
# Findings that are true regardless of the baseline, so a compromise that was
# already in place when the baseline was taken is still reported. Emits
# sev<TAB>section<TAB>change<TAB>key<TAB>new<TAB>old.
emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-}" "${6:-}"; }

always_checks() {
  local pw sf f

  # A second UID 0 account. Reported, never touched: deleting an account
  # mid-round can break a scored service and may itself be the trap.
  pw=$(p /etc/passwd)
  if [ -r "$pw" ]; then
    awk -F: '$3==0 && $1!="root" {print $1}' "$pw" | while read -r u; do
      emit CRIT uid0 PRESENT "$u" "a second account with UID 0"
    done
    awk -F: '$3>=1000 && $3!=65534 && $7 ~ /(bash|sh|zsh|ksh|csh|fish)$/ {print $1}' "$pw" >/dev/null
  fi

  # The loader preload file. On a stock Ubuntu box this file DOES NOT EXIST.
  # Its mere presence is one of the highest-signal findings available.
  if [ -s "$(p /etc/ld.so.preload)" ]; then
    emit CRIT preload PRESENT /etc/ld.so.preload "$(tr '\n' ' ' < "$(p /etc/ld.so.preload)" 2>/dev/null)"
  fi

  # A real user with no password at all.
  sf=$(p /etc/shadow)
  if [ -r "$sf" ]; then
    awk -F: '$2=="" {print $1}' "$sf" | while read -r u; do
      emit CRIT shadow EMPTY "$u" "empty password field — this account authenticates with no password"
    done
  fi

  # World-writable SUID, and SUID binaries where they have no business being.
  if [ -f "$HEAVY_CACHE" ]; then
    awk -F'\t' '$1=="suid"' "$HEAVY_CACHE" | while IFS=$'\t' read -r _ k v; do
      printf '%s' "$v" | grep -qE 'mode=[0-9]*[2367][0-9]?$' &&
        emit CRIT suid WRITABLE "$k" "SUID binary is group- or world-writable: $v"
      case $k in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/var/www/*|/srv/*)
          emit CRIT suid LOCATION "$k" "SUID binary in a writable directory: $v";;
      esac
    done
  fi

  # An executable in /dev/shm is not a cache file.
  for f in $(find "$(p /dev/shm)" -xdev -type f -perm /0111 2>/dev/null); do
    emit CRIT tmpfile EXEC "${f#$PREFIX}" "executable file in /dev/shm"
  done

  # A listener on a port that is an implant by convention.
  if [ "$DO_LIVE" = 1 ] && [ -n "$SS_CMD" ]; then
    collect_listen | while IFS=$'\t' read -r _ k v; do
      local port=${k##*:}
      printf '%s' "$port" | grep -qE -- "$IMPLANT_PORTS" &&
        emit CRIT listen IMPLANT "$k" "listener on a well-known implant port: $v"
    done
  fi

  # A service account with a login shell it does not need.
  if [ -r "$pw" ]; then
    awk -F: -v svc="$SERVICE_USERS" '$1 ~ svc && $7 ~ /(bash|\/sh|zsh|ksh|csh|fish)$/ {print $1 "\t" $7}' "$pw" |
    while IFS=$'\t' read -r u sh; do
      emit CRIT user SHELL "$u" "service account has an interactive shell: $sh"
    done
  fi

  # authorized_keys that someone other than the owner can write.
  if [ -r "$pw" ]; then
    while IFS=: read -r name _ uid _ _ home _; do
      local ak; ak=$(p "$home")/.ssh/authorized_keys
      [ -f "$ak" ] || continue
      local m o; m=$(stat -c %a -- "$ak" 2>/dev/null); o=$(stat -c %u -- "$ak" 2>/dev/null)
      printf '%s' "$m" | grep -qE '[0-9]?[2367][2367]$|[0-9]?[0-9][2367]$' &&
        emit CRIT akey PERMS "$name:authorized_keys" "mode $m — writable by someone other than the owner"
      # Skipped under --prefix: in a fake root every file is owned by whoever
      # ran the suite, so this would fire on every box and prove nothing.
      [ -z "$PREFIX" ] && [ -n "$o" ] && [ "$o" != "$uid" ] && [ "$o" != 0 ] &&
        emit CRIT akey OWNER "$name:authorized_keys" "owned by uid $o, not by $name (uid $uid)"
    done < "$pw"
  fi
}

# ==================================================== SEVERITY AND COMMANDS ==
# severity_of <section> <change> <key> <new>
severity_of() {
  local s=$1 c=$2 k=$3 v=$4
  case "$s" in
    tool)     printf CRIT;;
    akey)     [ "$c" = REMOVED ] && printf warn || printf CRIT;;
    suid)     [ "$c" = REMOVED ] && printf warn || printf CRIT;;
    preload|uid0) printf CRIT;;
    webfile)  [ "$c" = REMOVED ] && printf warn || printf CRIT;;
    user)     case "$c:$v" in
                ADDED:*)   printf CRIT;;
                *uid=0*)   printf CRIT;;
                CHANGED:*) printf CRIT;;
                *)         printf warn;;
              esac;;
    group)    printf CRIT;;
    shadow)   [ "$c" = CHANGED ] && printf warn || printf CRIT;;
    file)     case "$k" in
                /etc/sudoers*|/etc/ld.so.preload|/etc/pam.d/*|*/authorized_keys*|\
                /etc/cron*|/var/spool/cron/*|/etc/systemd/system/*|/etc/profile*|\
                /etc/rc.local|/etc/ssh/sshd_config*|*/.bashrc|*/.profile|*/.bash_profile)
                  printf CRIT;;
                *) printf warn;;
              esac;;
    dirmode)  printf warn;;
    proc)     case "$k" in shell:*) printf CRIT;; *) printf warn;; esac;;
    listen)   printf "$(printf '%s' "${k##*:}" | grep -qE -- "$IMPLANT_PORTS" && printf CRIT || printf warn)";;
    conn)     printf warn;;
    tmpfile)  case "$v" in *type=PHP*|*type=ELF*|*type=SHELL*|*type=SCRIPT*|*type=EXEC*) printf CRIT;; *) printf info;; esac;;
    session)  printf warn;;
    dpkg)     printf warn;;
    *)        printf warn;;
  esac
}

# commands_for <section> <change> <key> <new> <old>
# Prints "investigate" and "fix" command lines. These are PRINTED ONLY. The
# tool never runs them: a human reads the evidence and decides.
commands_for() {
  local s=$1 c=$2 k=$3 v=$4 o=$5
  local user port pid ip ev real
  printf '  %sinvestigate:%s\n' "$C_D" "$C_0"
  case "$s" in
    user)
      printf '    getent passwd %s; id %s; last -n 20 %s\n' "$k" "$k" "$k"
      printf '    grep -a "%s" /var/log/auth.log | tail -40\n' "$k"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      case "$v" in
        *uid=0*) printf '    # a second UID 0 account. DO NOT delete it mid-round.\n'
                 printf '    usermod -L %s && usermod -s /usr/sbin/nologin %s\n' "$k" "$k";;
        *)       printf '    usermod -L %s                      # lock, reversible with usermod -U\n' "$k"
                 printf '    usermod -s /usr/sbin/nologin %s    # remove the shell\n' "$k";;
      esac;;
    group)
      printf '    getent group %s\n' "$k"
      printf '    grep -n "^%s:" /etc/group\n' "$k"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    cp -a /etc/group /var/backups/tcdc/group.$(date +%%s)\n'
      printf '    gpasswd -d <USER> %s             # one user at a time, then re-check\n' "$k";;
    shadow)
      printf '    chage -l %s; passwd -S %s\n' "$k" "$k"
      printf '    grep -a "password changed for %s" /var/log/auth.log | tail\n' "$k"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    # if this was your own rotation:   %s --accept shadow\n' "$PROG"
      printf '    # if it was not:  rotate it back under your control\n'
      printf '    bin/rotate-creds.sh --round <N> --vault <vault> --commit\n';;
    file|dirmode)
      real=$(p "$k"); ev=$(ev_path "$k")
      printf '    ls -l %s; stat %s\n' "$real" "$real"
      [ -f "$ev" ] && printf '    diff -u %s %s\n' "$ev" "$real"
      case "$k" in
        /etc/sudoers*) printf '    visudo -c                          # confirm it still parses\n';;
        */authorized_keys*) printf '    cat -n %s\n' "$real";;
        /etc/systemd/system/*) printf '    systemctl cat %s 2>/dev/null; systemctl status %s\n' "${k##*/}" "${k##*/}";;
        /var/spool/cron/crontabs/*) printf '    crontab -l -u %s\n' "${k##*/}";;
      esac
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    cp -a %s /var/backups/tcdc/            # keep the evidence first\n' "$real"
      if [ -f "$ev" ]; then
        printf '    cp -a %s %s   # restore the baseline copy\n' "$ev" "$real"
      else
        printf '    # no baseline copy of this file — edit it by hand after reading the diff\n'
      fi
      case "$k" in
        /etc/sudoers*) printf '    visudo -c   # MUST pass before you walk away, or every admin loses root\n';;
        /etc/systemd/system/*) printf '    systemctl daemon-reload\n';;
      esac;;
    akey)
      user=${k%%:*}
      printf '    cat -n /home/%s/.ssh/authorized_keys 2>/dev/null || cat -n ~%s/.ssh/authorized_keys\n' "$user" "$user"
      printf '    grep -a "Accepted publickey for %s" /var/log/auth.log | tail -20\n' "$user"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    cp -a ~%s/.ssh/authorized_keys /var/backups/tcdc/\n' "$user"
      printf '    # delete the offending line, then confirm you can still log in BEFORE closing this session\n'
      printf '    sed -i "/<the key text>/d" ~%s/.ssh/authorized_keys\n' "$user";;
    listen)
      port=${k##*:}
      printf '    ss -lntup | grep -w %s\n' "$port"
      printf '    pid=$(ss -lntupH | grep -w %s | sed -n "s/.*pid=\\([0-9]*\\).*/\\1/p" | head -1); ps -fp $pid; ls -l /proc/$pid/exe /proc/$pid/cwd\n' "$port"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    # identify the service FIRST — killing a scored listener costs uptime\n'
      printf '    kill -STOP $pid        # freeze it for analysis, reversible with kill -CONT\n';;
    conn)
      ip=$k
      printf '    ss -tnp | grep -w %s\n' "$ip"
      printf '    ps -fp $(ss -tnpH | grep -w %s | sed -n "s/.*pid=\\([0-9]*\\).*/\\1/p" | head -1)\n' "$ip"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    # if this is an implant beacon, block it and keep the process for analysis:\n'
      printf '    iptables -I OUTPUT -d %s -j DROP      # remove with -D when done\n' "$ip";;
    proc)
      case "$k" in
        shell:*) user=$(printf '%s' "$k" | cut -d: -f2)
                 printf '    ps -ef --forest | grep -A2 -B2 -w %s\n' "$user"
                 printf '    for p in $(pgrep -u %s); do echo "== $p"; ls -l /proc/$p/exe /proc/$p/cwd; tr "\\0" " " < /proc/$p/cmdline; echo; done\n' "$user"
                 printf '  %sfix:%s\n' "$C_D" "$C_0"
                 printf '    # a service user running a shell is a webshell until proven otherwise.\n'
                 printf '    # freeze, do not kill — you want the process for the incident report:\n'
                 printf '    kill -STOP <PID>\n'
                 printf '    # then find how it got in:\n'
                 printf '    grep -rE "(eval|base64_decode|system|passthru|shell_exec)" /var/www --include="*.php" | head -40\n';;
        deleted:*) printf '    ls -l /proc/*/exe 2>/dev/null | grep deleted\n'
                 printf '    # recover the binary from memory for analysis:\n'
                 printf '    cp /proc/<PID>/exe /root/recovered-<PID>.bin\n'
                 printf '  %sfix:%s\n' "$C_D" "$C_0"
                 printf '    # if the package was just upgraded this is benign; restart the service:\n'
                 printf '    systemctl restart <unit>\n'
                 printf '    # if nothing was upgraded, treat as an implant: kill -STOP <PID> and preserve\n';;
      esac;;
    suid)
      printf '    ls -l %s; dpkg -S %s 2>/dev/null || echo "NOT OWNED BY ANY PACKAGE"\n' "$k" "$k"
      printf '    sha256sum %s\n' "$k"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    cp -a %s /var/backups/tcdc/\n' "$k"
      printf '    chmod -s %s                      # drop setuid, reversible with chmod u+s\n' "$k";;
    tmpfile|webfile)
      real=$(p "$k")
      printf '    ls -l %s; file %s; sha256sum %s\n' "$real" "$real" "$real"
      printf '    head -c 400 %s | strings | head -20\n' "$real"
      printf '    stat -c "%%y modified, uid %%u" %s\n' "$real"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    mkdir -p /root/tcdc-quarantine && mv %s /root/tcdc-quarantine/\n' "$real"
      [ "$s" = webfile ] && {
        printf '    # if this is a defacement, restore from your own copy, not from the box:\n'
        printf '    # and check the access log for how it was written:\n'
        printf '    grep -a "%s" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null | tail -20\n' "${k##*/}"; };;
    session)
      user=${k%%:*}
      printf '    who; w; last -n 30 %s\n' "$user"
      printf '    grep -a "Accepted .* for %s" /var/log/auth.log | tail -20\n' "$user"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    # confirm it is not a teammate or a scoring check before you do this:\n'
      printf '    pkill -9 -u %s -t %s\n' "$user" "$(printf '%s' "$k" | cut -d: -f2)";;
    dpkg)
      printf '    dpkg -S %s; sha256sum %s\n' "$k" "$k"
      printf '    dpkg --verify | grep -w %s\n' "$k"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    cp -a %s /var/backups/tcdc/\n' "$k"
      printf '    apt-get install --reinstall -y $(dpkg -S %s | cut -d: -f1)\n' "$k";;
    uid0)
      printf '    getent passwd %s; id %s; last -n 20 %s\n' "$k" "$k" "$k"
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    # DO NOT userdel mid-round. Lock it and keep it for the report:\n'
      printf '    usermod -L %s && usermod -s /usr/sbin/nologin %s\n' "$k" "$k";;
    preload)
      printf '    cat /etc/ld.so.preload; ls -l $(cat /etc/ld.so.preload)\n'
      printf '  %sfix:%s\n' "$C_D" "$C_0"
      printf '    cp -a /etc/ld.so.preload /var/backups/tcdc/\n'
      printf '    : > /etc/ld.so.preload     # empty it; every new process is affected immediately\n';;
    *)
      printf '    # no canned command for section "%s" — inspect by hand\n' "$s";;
  esac
}

# ============================================================== FINDINGS ======
# One line per open finding:
#   fp  first_seen  sev  section  change  key  new  old
fp_of() { hs "$1|$2|$3|$4|$5" | cut -c1-10; }

is_open()  { [ -f "$FINDINGS" ] && cut -f1 "$FINDINGS" 2>/dev/null | grep -qxF -- "$1"; }
add_open() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$3" "$4" "$5" "$6" "$7" "$8" >> "$FINDINGS"; }

sev_colour() { case $1 in CRIT) printf '%s' "$C_R";; warn) printf '%s' "$C_Y";; info) printf '%s' "$C_D";; *) printf '%s' "$C_0";; esac; }

# report_finding <sev> <section> <change> <key> <new> <old> <fp>
report_finding() {
  local sev=$1 s=$2 c=$3 k=$4 v=$5 o=$6 fp=$7 col
  col=$(sev_colour "$sev")
  {
    printf '%s[%s]%s %-9s %-8s %s%s%s  %s(id %s)%s\n' \
      "$col" "$sev" "$C_0" "$s" "$c" "$C_B" "$k" "$C_0" "$C_D" "$fp" "$C_0"
    [ -n "$o" ] && [ "$c" = CHANGED ] && printf '       old: %s\n       new: %s\n' "$o" "$v"
    [ -n "$o" ] && [ "$c" = REMOVED ] && printf '       was: %s\n' "$o"
    [ -n "$v" ] && [ "$c" != CHANGED ] && printf '       %s\n' "$v"
    # The real content diff, when a copy of the file was kept.
    if [ "$s" = file ] && [ "$c" = CHANGED ] && [ -f "$(ev_path "$k")" ] && [ -f "$(p "$k")" ]; then
      printf '%s' "$C_M"
      diff -u --label baseline --label current "$(ev_path "$k")" "$(p "$k")" 2>/dev/null |
        sed -e '1,2d' -e 's/^/       /' | head -30
      printf '%s' "$C_0"
    fi
    commands_for "$s" "$c" "$k" "$v" "$o"
    printf '\n'
  } >&2
  # The log is plain text with no escape codes: it is an inject attachment.
  {
    printf '%s  %s  %s  %s  %s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HOSTN" "$sev" "$s" "$c" "$k"
    [ -n "$o" ] && printf '    old: %s\n' "$o"
    [ -n "$v" ] && printf '    new: %s\n' "$v"
  } >> "$ALERTLOG" 2>/dev/null
  [ "$sev" = CRIT ] && [ "$BELL" = 1 ] && [ "$TTY" = 1 ] && printf '\a' >&2
  return 0
}

# ================================================================ PREFLIGHT ==
need_root() {
  [ -n "$PREFIX" ] && return 0
  [ "$(id -u)" = 0 ] && return 0
  die "must run as root: /etc/shadow, other users' authorized_keys, ss -p and /proc/*/exe are all root-only. Without them the baseline would be silently incomplete."
}

setup_dirs() {
  mkdir -p "$STATE" "$EVIDENCE" "$LOGDIR" 2>/dev/null || die "cannot create $STATE / $LOGDIR"
  chmod 700 "$STATE" "$LOGDIR" 2>/dev/null
  chmod 700 "$EVIDENCE" 2>/dev/null
  touch "$ALERTLOG" 2>/dev/null && chmod 600 "$ALERTLOG" 2>/dev/null
  if [ "$APPEND_ONLY" = 1 ] && have chattr; then
    chattr +a "$ALERTLOG" 2>/dev/null && act "alert log is now append-only (undo with: chattr -a $ALERTLOG)" \
      || warn "could not set append-only on $ALERTLOG (needs root and a filesystem that supports it)"
  fi
}

# The baseline's own integrity. State lives on the box being watched, so an
# attacker with root can edit it. This cannot be prevented locally — it can
# only be made loud.
write_meta() {
  { printf 'host %s\n' "$HOSTN"
    printf 'created %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'facts %s\n' "$(wc -l < "$BASELINE")"
    printf 'sha256 %s\n' "$(sha256sum < "$BASELINE" | cut -d' ' -f1)"
  } > "$META"
  chmod 600 "$META" 2>/dev/null
}

# Said once, not once a minute. A tampered baseline printing its seven-line
# block every cycle for eight hours is how the operator learns to scroll past
# it, which defeats the point of noticing at all.
META_WARNED=0
check_meta() {
  [ -f "$BASELINE" ] || { err "no baseline at $BASELINE — run: $PROG --baseline"; return 3; }
  [ -r "$BASELINE" ] || { err "baseline at $BASELINE is not readable"; return 3; }
  [ -f "$META" ] || { warn "no $META — cannot verify the baseline has not been edited"; return 0; }
  local want got
  want=$(awk '$1=="sha256"{print $2}' "$META")
  got=$(sha256sum < "$BASELINE" | cut -d' ' -f1)
  if [ -n "$want" ] && [ "$want" != "$got" ]; then
    if [ "$META_WARNED" = 1 ]; then return 3; fi
    META_WARNED=1
    crit "BASELINE HAS BEEN MODIFIED outside this tool"
    say  "       expected sha256 $want"
    say  "       found    sha256 $got"
    say  "       Someone with root may have edited the baseline so a change reads as normal."
    say  "       Compare against the copy you took off-box:"
    say  "         diff <(sort $BASELINE) <(sort /path/to/offbox/baseline.facts)"
    say  "       To accept the current file as the baseline:  $PROG --accept all --yes"
    return 3
  fi
  return 0
}

# ============================================================ DIFF ENGINE ====
# Sections where a fact DISAPPEARING is normal churn rather than a finding.
# A process exits, a user logs out, a /tmp file is cleaned up — reporting
# those would bury the real alerts within the hour. A listener disappearing is
# NOT in this list: a scored service that stopped listening is worth knowing.
REMOVED_IS_NOISE='^(conn|proc|session|tmpfile|dpkg)$'

diff_facts() {
  awk -F'\t' -v OFS='\t' '
    NR==FNR { if ($1=="conn") next; old[$1 FS $2]=$3; seen[$1 FS $2]=1; next }
    { if ($1=="conn") next
      k = $1 FS $2
      if (!(k in seen)) { print "ADDED", $1, $2, $3, "" }
      else { if (old[k] != $3) print "CHANGED", $1, $2, $3, old[k]; delete seen[k] }
    }
    END { for (k in seen) { split(k, a, FS); print "REMOVED", a[1], a[2], "", old[k] } }
  ' "$1" "$2"
}

# Outbound connections are deliberately NOT handled by the diff engine. An IP
# that was connected at baseline time, disconnects, and reconnects would
# otherwise alert forever. Instead every IP ever seen is kept in a cumulative
# list and each new one is reported exactly once.
conn_check() {
  local new=$1 ip v first=0
  touch "$SEEN_IPS" 2>/dev/null
  while IFS=$'\t' read -r _ ip v; do
    [ -n "$ip" ] || continue
    grep -qxF -- "$ip" "$SEEN_IPS" 2>/dev/null && continue
    printf '%s\n' "$ip" >> "$SEEN_IPS"
    ignored conn "$ip" "$v" && continue
    local fp; fp=$(fp_of ADDED conn NEW-IP "$ip" "$v")
    is_open "$fp" && continue
    add_open "$fp" '' warn conn NEW-IP "$ip" "$v" ''
    report_finding warn conn NEW-IP "$ip" "$v" '' "$fp"
    first=$((first+1))
  done < <(awk -F'\t' '$1=="conn"' "$new")
  printf '%s' "$first"
}

# run_cycle — one comparison. Prints findings, returns the number of NEW ones.
CYCLE_NEW=0
CYCLE_SUPPRESSED=0
run_cycle() {
  local new="$STATE/current.facts"
  CYCLE_NEW=0; CYCLE_SUPPRESSED=0
  collect_all "$new"

  local change section key newv oldv sev fp
  while IFS=$'\t' read -r change section key newv oldv; do
    [ -n "$section" ] || continue
    if [ "$change" = REMOVED ] && printf '%s' "$section" | grep -qE -- "$REMOVED_IS_NOISE"; then
      continue
    fi
    if ignored "$section" "$key" "${newv:-$oldv}"; then
      CYCLE_SUPPRESSED=$((CYCLE_SUPPRESSED+1)); continue
    fi
    sev=$(severity_of "$section" "$change" "$key" "$newv")
    fp=$(fp_of "$change" "$section" "$key" "$newv" "$oldv")
    # Already-reported findings stay OPEN but are not re-printed every cycle.
    # Re-alerting identical findings once a minute is how a detector gets
    # ignored by hour two; --status lists everything still outstanding.
    is_open "$fp" && continue
    add_open "$fp" '' "$sev" "$section" "$change" "$key" "$newv" "$oldv"
    report_finding "$sev" "$section" "$change" "$key" "$newv" "$oldv" "$fp"
    CYCLE_NEW=$((CYCLE_NEW+1))
  done < <(diff_facts "$BASELINE" "$new")

  local nip; nip=$(conn_check "$new")
  CYCLE_NEW=$((CYCLE_NEW + nip))

  # Baseline-independent findings, every cycle, including the very first.
  while IFS=$'\t' read -r sev section change key newv oldv; do
    [ -n "$section" ] || continue
    ignored "$section" "$key" "$newv" && { CYCLE_SUPPRESSED=$((CYCLE_SUPPRESSED+1)); continue; }
    fp=$(fp_of "$change" "$section" "$key" "$newv" "$oldv")
    is_open "$fp" && continue
    add_open "$fp" '' "$sev" "$section" "$change" "$key" "$newv" "$oldv"
    report_finding "$sev" "$section" "$change" "$key" "$newv" "$oldv" "$fp"
    CYCLE_NEW=$((CYCLE_NEW+1))
  done < <(always_checks)

  return 0
}

open_count() { [ -f "$FINDINGS" ] && wc -l < "$FINDINGS" | tr -d ' ' || printf 0; }

# =================================================================== MODES ===
save_all_evidence() {
  local s k v
  while IFS=$'\t' read -r s k v; do
    [ "$s" = file ] || continue
    save_evidence "$(p "$k")" "$k"
  done < "$BASELINE"
}

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || die "$1 (re-run with --yes to confirm non-interactively)"
  printf '%s [type yes to continue] ' "$1" >&2
  local a; read -r a
  [ "$a" = yes ]
}

do_baseline() {
  need_root; setup_dirs
  if [ -f "$BASELINE" ] && [ "$FORCE" != 1 ]; then
    err "a baseline already exists: $BASELINE"
    say "       Created: $(awk '$1=="created"{print $2}' "$META" 2>/dev/null || echo unknown)"
    say "       Taking a new one DISCARDS everything the old one would have caught."
    say "       If a change was yours, accept just that:   $PROG --accept shadow"
    say "       To replace the baseline anyway:            $PROG --baseline --force"
    exit 2
  fi
  if [ -f "$BASELINE" ]; then
    confirm "Replace the existing baseline? Anything Red Team has already changed becomes the new 'normal'." \
      || die "aborted — baseline left alone"
  fi
  rm -f "$HEAVY_STAMP"                     # a baseline always includes the heavy facts
  info "collecting baseline on $HOSTN ..."
  collect_all "$BASELINE"
  : > "$FINDINGS"
  awk -F'\t' '$1=="conn"{print $2}' "$BASELINE" | LC_ALL=C sort -u > "$SEEN_IPS"
  save_all_evidence
  write_meta
  chmod 600 "$BASELINE" "$SEEN_IPS" "$FINDINGS" 2>/dev/null
  hr
  ok "baseline: $(wc -l < "$BASELINE") facts  ·  $(awk -F'\t' '{print $1}' "$BASELINE" | LC_ALL=C sort -u | tr '\n' ' ')"
  say ""
  say "  ${C_B}sha256 $(awk '$1=="sha256"{print $2}' "$META")${C_0}"
  say ""
  say "  Copy the baseline off this box NOW, so you can tell later whether it was edited:"
  say "    scp $BASELINE <you>@<jumpbox>:baseline-$HOSTN.facts"
  say ""
  say "  Then leave the detector running:"
  say "    $0 --watch $INTERVAL"
  hr
  # A baseline is not a clean bill of health: report what is wrong right now.
  info "checking for things that are wrong regardless of the baseline ..."
  local sev section change key newv oldv fp n=0
  while IFS=$'\t' read -r sev section change key newv oldv; do
    [ -n "$section" ] || continue
    ignored "$section" "$key" "$newv" && continue
    fp=$(fp_of "$change" "$section" "$key" "$newv" "$oldv")
    add_open "$fp" '' "$sev" "$section" "$change" "$key" "$newv" "$oldv"
    report_finding "$sev" "$section" "$change" "$key" "$newv" "$oldv" "$fp"
    n=$((n+1))
  done < <(always_checks)
  if [ "$n" = 0 ]; then ok "nothing obviously wrong at baseline time"
  else crit "$n finding(s) present AT BASELINE TIME — this box may already be compromised"
       say  "       These are NOT in the baseline as 'normal'. They stay open until you resolve them."
       return 1
  fi
  return 0
}

do_accept() {
  need_root; setup_dirs
  check_meta || [ "$ASSUME_YES" = 1 ] || die "refusing to accept into a baseline that failed its integrity check (--yes to override)"
  local new="$STATE/accept.facts"
  collect_all "$new"
  local spec=$ACCEPT_SPEC sect keyre n_before n_after
  n_before=$(wc -l < "$BASELINE")

  if [ "$spec" = all ]; then
    confirm "Accept EVERYTHING on this box as the new baseline? Any live compromise becomes 'normal'." \
      || die "aborted"
    cp -f "$new" "$BASELINE"
  else
    sect=${spec%%:*}
    keyre=""
    [ "$spec" != "$sect" ] && keyre=${spec#*:}
    awk -F'\t' -v s="$sect" '$1!=s' "$BASELINE" > "$BASELINE.t"
    if [ -n "$keyre" ]; then
      # put back the facts of that section that do NOT match the key pattern
      awk -F'\t' -v s="$sect" -v re="$keyre" '$1==s && $2 !~ re' "$BASELINE" >> "$BASELINE.t"
      awk -F'\t' -v s="$sect" -v re="$keyre" '$1==s && $2 ~ re' "$new"      >> "$BASELINE.t"
    else
      awk -F'\t' -v s="$sect" '$1==s' "$new" >> "$BASELINE.t"
    fi
    LC_ALL=C sort -u "$BASELINE.t" -o "$BASELINE.t"
    mv -f "$BASELINE.t" "$BASELINE"
  fi

  save_all_evidence
  write_meta
  n_after=$(wc -l < "$BASELINE")
  # Close any open finding in the accepted section.
  if [ -f "$FINDINGS" ]; then
    if [ "$spec" = all ]; then : > "$FINDINGS"
    else awk -F'\t' -v s="${spec%%:*}" '$4!=s' "$FINDINGS" > "$FINDINGS.t" && mv -f "$FINDINGS.t" "$FINDINGS"; fi
  fi
  {
    printf '%s  %s  ACCEPT  %s  (facts %s -> %s)\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HOSTN" "$spec" "$n_before" "$n_after"
  } >> "$ALERTLOG" 2>/dev/null
  act "accepted '$spec' into the baseline ($n_before -> $n_after facts)"
  say "  new sha256 $(awk '$1=="sha256"{print $2}' "$META")  — update your off-box copy"
  return 0
}

do_status() {
  local n; n=$(open_count)
  if [ "$n" = 0 ]; then ok "no open findings on $HOSTN"; return 0; fi
  say ""
  printf '%s%-11s %-6s %-9s %-8s %s%s\n' "$C_B" "ID" "SEV" "SECTION" "CHANGE" "KEY" "$C_0" >&2
  local fp seen sev s c k v o
  while IFS=$'\t' read -r fp seen sev s c k v o; do
    printf '%s%-11s %-6s%s %-9s %-8s %s\n' "$(sev_colour "$sev")" "$fp" "$sev" "$C_0" "$s" "$c" "$k" >&2
    [ -n "$seen" ] && printf '            %sfirst seen %s%s\n' "$C_D" "$seen" "$C_0" >&2
  done < "$FINDINGS"
  say ""
  say "  $n open finding(s) on $HOSTN. Close one with: $PROG --resolve <ID>"
  say "  Full history with commands: $ALERTLOG"
  return 1
}

do_resolve() {
  [ -f "$FINDINGS" ] || die "no findings file at $FINDINGS"
  grep -qF -- "$RESOLVE_ID" "$FINDINGS" || die "no open finding with id '$RESOLVE_ID' (see: $PROG --status)"
  local line; line=$(grep -F -- "$RESOLVE_ID" "$FINDINGS" | head -1)
  grep -vF -- "$RESOLVE_ID" "$FINDINGS" > "$FINDINGS.t" && mv -f "$FINDINGS.t" "$FINDINGS"
  act "resolved $RESOLVE_ID"
  printf '%s  %s  RESOLVE  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HOSTN" "$line" >> "$ALERTLOG" 2>/dev/null
  say "  NOTE: this only closes the alert. It does not undo anything on the box."
  say "  If the change is still present it will NOT be reported again — it is now"
  say "  tracked only in $ALERTLOG. Fix the box, or re-run --baseline when clean."
  return 0
}

# Only one instance may hold the state directory, or two cycles interleave and
# write each other's current.facts.
take_lock() {
  # NOT `exec 9>"$LOCKFILE" 2>/dev/null`: with no command, exec applies its
  # redirections to THIS shell permanently, so the 2>/dev/null would silently
  # discard every warning and every finding for the rest of the run. Cost an
  # afternoon once; worth the comment.
  have flock || return 0
  exec 9>"$LOCKFILE"
  flock -n 9 || die "another $PROG is already running against $STATE (lock: $LOCKFILE)"
}

heartbeat() {
  local cyc=$1 t=$2 n=$3
  local nxt='--' last
  if [ "$DO_HEAVY" = 1 ]; then
    last=$(cat "$HEAVY_STAMP" 2>/dev/null || echo 0)
    nxt=$(( HEAVY_INTERVAL - ( $(date +%s) - last ) )); [ "$nxt" -lt 0 ] && nxt=0
    nxt="${nxt}s"
  fi
  local msg
  msg=$(printf '%s[%s]%s cycle %-5s  open %-4s  took %-4s  heavy in %-6s %s' \
        "$C_D" "$(date +%H:%M:%S)" "$C_0" "$cyc" "$n" "${t}s" "$nxt" "$C_D·$C_0")
  if [ "$TTY" = 1 ] && [ "$QUIET" != 1 ]; then
    printf '\r\033[K%s' "$msg" >&2
  elif [ "$QUIET" != 1 ]; then
    printf '%s\n' "$msg" >&2
  fi
}

do_once() {
  need_root; setup_dirs; take_lock
  check_meta || exit 3
  run_cycle
  local n; n=$(open_count)
  if [ "$CYCLE_NEW" = 0 ]; then
    ok "no change on $HOSTN${C_D}$([ "$CYCLE_SUPPRESSED" -gt 0 ] && printf ' (%s suppressed by allowlist)' "$CYCLE_SUPPRESSED")${C_0}"
    # Nothing NEW is not the same as nothing WRONG. Exiting 0 with an
    # unresolved compromise outstanding would let a wrapper script call this
    # box clean, so anything still open is a non-zero exit.
    if [ "$n" -gt 0 ]; then
      say "  ${C_Y}$n finding(s) still open${C_0} — $PROG --status"
      return 1
    fi
    return 0
  fi
  hr
  say "  ${C_B}$CYCLE_NEW new finding(s) on $HOSTN${C_0}  ·  $n open in total  ·  $PROG --status"
  return 1
}

do_watch() {
  need_root; setup_dirs; take_lock
  check_meta || exit 3
  local cyc=0 t0 t1 rc=0
  trap 'printf "\n" >&2; info "stopped after $cyc cycles — $(open_count) finding(s) open"; exit 0' INT TERM
  hr
  ok "watching $HOSTN every ${INTERVAL}s  ·  baseline $(wc -l < "$BASELINE") facts  ·  ctrl-C to stop"
  say "  ${C_D}state $STATE   log $ALERTLOG${C_0}"
  say "  ${C_D}baseline sha256 $(awk '$1=="sha256"{print $2}' "$META" 2>/dev/null)${C_0}"
  hr
  while :; do
    cyc=$((cyc+1))
    t0=$(date +%s)
    # A baseline edited underneath us is itself a finding. Checked every cycle,
    # but check_meta only speaks the first time.
    if ! check_meta; then rc=3; fi
    run_cycle
    t1=$(date +%s)
    [ "$CYCLE_NEW" -gt 0 ] && rc=1
    heartbeat "$cyc" "$((t1-t0))" "$(open_count)"
    sleep "$INTERVAL"
  done
}

# ==================================================================== MAIN ===
case $MODE in
  baseline) do_baseline;;
  once)     do_once;;
  watch)    do_watch;;
  status)   do_status;;
  accept)   do_accept;;
  resolve)  do_resolve;;
  *)        usage; exit 2;;
esac
