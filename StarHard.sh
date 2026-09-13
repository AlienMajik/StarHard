#!/usr/bin/env bash
#===============================================================================
# StarHard.sh  v1.2
# Universal Linux hardening script (Debian/Ubuntu/Parrot/Kali, RHEL/Fedora/
# Rocky/Alma, openSUSE, Arch, Alpine).
#
# v1.2 changes:
#   * rkhunter/chkrootkit replaced by Lynis, ClamAV (+freshclam), unhide,
#     debsums/rpm -V, all wired into a weekly starhard-scan timer
#   * --audit mode: report PASS/FAIL against expected state, change nothing
#   * --sections / --exclude: run only chosen sections
#   * Rollback now removes files this script created and restores prior
#     file modes, service states and firewall state
#   * SSH: refuses to disable password auth unless authorized_keys exists,
#     always allows SSH through the firewall when run over SSH, ensures the
#     sshd_config.d Include line exists, sets Banner, drops "Protocol 2";
#     TcpForwarding/AgentForwarding/MaxAuthTries only tightened on server
#   * shadow/gshadow only ever tightened (chmod o-rwx), never loosened
#   * ENCRYPT_METHOD YESCRYPT where libcrypt supports it, sane SHA512 rounds
#   * pam_faillock account lockout (authselect on RHEL, common-auth on Debian)
#   * fail2ban recidive jail fixed (backend=auto)
#   * auditd: immutable-mode detection, b32 rules on x86_64
#   * AIDE daily check timer; sshd Banner; sudo use_pty + logfile
#   * ctrl-alt-del masked; persistent journald with size cap
#   * /dev/shm nodev,nosuid,noexec; /tmp and /var/tmp tightened on server
#   * Extra sysctl: io_uring_disabled, unprivileged_userfaultfd
#   * Module blacklist: "blacklist" lines added, loaded modules unloaded
#   * AppArmor: profiles set to enforce (server auto, desktop prompted)
#   * unattended-upgrades configured (origins, unused deps); zypper timer
#   * Server profile: avahi/cups/bluetooth masked, usbguard enabled
#   * GRUB password works on RHEL/Fedora (grub2-setpassword)
#   * --ids crowdsec|fail2ban (section 8): CrowdSec + firewall bouncer from
#     the official repo, default on server; fail2ban is stopped/disabled so
#     the two never fight over bans. Desktop default stays fail2ban.
#   * Section 18: installs/verifies Lynis, runs a full audit, summarises
#     warnings + suggestions, maps each to the StarHard section that covers
#     it, and tracks the hardening index across runs (no blind auto-fixing)
#===============================================================================

set -u
umask 077

VERSION="1.2"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/starhard/$TS"
LOG_DIR="/var/log/starhard"
LOG_FILE="$LOG_DIR/starhard-$TS.log"
ROLLBACK="$BACKUP_DIR/rollback.sh"

DRY_RUN=0
AUDIT=0
PROFILE="desktop"
ASSUME_YES=0
SECTIONS=""
EXCLUDE=""
IDS=""
NEW_PKGS=()
ARCH="$(uname -m)"
SSH_ACTIVE=0
[[ -n "${SSH_CONNECTION:-}" ]] && SSH_ACTIVE=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

#---------------------------------------------------------------- helpers -----
log()  { echo -e "${GREEN}[+]${NC} $1"; _tolog "[+] $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; _tolog "[!] $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; _tolog "[-] $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; _tolog "[i] $1"; }
_tolog(){ [[ $DRY_RUN -eq 0 && $AUDIT -eq 0 && -d "$LOG_DIR" ]] && { echo "$(date '+%F %T') $1" >> "$LOG_FILE"; } 2>/dev/null; return 0; }

run() {
    # run <description> <command...>
    local desc="$1"; shift
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would run: $*"
        return 0
    fi
    if "$@" >> "$LOG_FILE" 2>&1; then
        log "$desc"
    else
        warn "$desc failed (see $LOG_FILE) — continuing"
        return 1
    fi
}

rb() {
    # append a line to the rollback script
    [[ $DRY_RUN -eq 0 ]] && echo "$1" >> "$ROLLBACK"
    return 0
}

backup_file() {
    # backs up an existing file once per run and records its restore
    local f="$1"
    [[ -e "$f" ]] || return 0
    [[ $DRY_RUN -eq 1 ]] && { info "DRY-RUN: would back up $f"; return 0; }
    local dest="$BACKUP_DIR${f}"
    [[ -e "$dest" ]] && return 0
    mkdir -p "$(dirname "$dest")"
    cp -a "$f" "$dest"
    rb "cp -a '$dest' '$f'"
}

record_rm() {
    # file created by this run -> rollback removes it
    rb "rm -f '$1'"
}

record_mode() {
    # record current mode so rollback can restore it
    local f="$1"
    [[ -e "$f" && $DRY_RUN -eq 0 ]] || return 0
    rb "chmod $(stat -c '%a' "$f") '$f'"
}

write_file() {
    # write_file <path> <mode> ; content on stdin
    local f="$1" mode="${2:-644}"
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would write $f"
        cat > /dev/null
        return 0
    fi
    if [[ -e "$f" ]]; then backup_file "$f"; else record_rm "$f"; fi
    mkdir -p "$(dirname "$f")"
    cat > "$f"
    chmod "$mode" "$f"
    log "Wrote $f"
}

tighten() {
    # tighten <file> <mode>  (mode may be symbolic, e.g. o-rwx)
    [[ -e "$1" ]] || return 0
    record_mode "$1"
    run "chmod $2 $1" chmod "$2" "$1"
}

ask() {
    # ask "question" -> 0 yes / 1 no ; auto-yes with -y, auto-no in dry-run
    [[ $DRY_RUN -eq 1 ]] && { info "DRY-RUN: would ask: $1 (assuming no)"; return 1; }
    [[ $ASSUME_YES -eq 1 ]] && return 0
    local reply
    read -r -p "$(echo -e "${YELLOW}[?]${NC} $1 (y/N): ")" reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

has_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }

unit_exists() { systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"; }

svc_enable() {
    local s="$1"
    if has_systemd; then
        if [[ $DRY_RUN -eq 0 ]] && ! systemctl is-enabled -q "$s" 2>/dev/null; then
            rb "systemctl disable --now '$s' 2>/dev/null || true"
        fi
        run "enable service $s" systemctl enable --now "$s"
    elif command -v rc-update >/dev/null 2>&1; then
        rb "rc-update del '$s' default 2>/dev/null; rc-service '$s' stop 2>/dev/null || true"
        run "enable service $s" rc-update add "$s" default
        run "start service $s" rc-service "$s" start
    fi
}

svc_mask() {
    local s="$1"
    has_systemd || return 0
    unit_exists "$s" || return 0
    if [[ $DRY_RUN -eq 0 ]] && ! systemctl is-enabled "$s" 2>/dev/null | grep -q masked; then
        rb "systemctl unmask '$s' 2>/dev/null || true"
    fi
    run "mask $s" systemctl mask --now "$s"
}

write_timer() {
    # write_timer <name> <description> <OnCalendar> <ExecStart>
    has_systemd || { info "No systemd — skipping timer $1"; return 0; }
    local n="$1" d="$2" cal="$3" ex="$4"
    write_file "/etc/systemd/system/$n.service" 644 <<EOF
[Unit]
Description=$d

[Service]
Type=oneshot
ExecStart=$ex
Nice=19
IOSchedulingClass=idle
EOF
    write_file "/etc/systemd/system/$n.timer" 644 <<EOF
[Unit]
Description=$d (timer)

[Timer]
OnCalendar=$cal
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
    [[ $DRY_RUN -eq 0 ]] && systemctl daemon-reload
    svc_enable "$n.timer"
}

should_run() {
    local n="$1"
    if [[ -n "$SECTIONS" ]]; then
        [[ ",$SECTIONS," == *",$n,"* ]] || return 1
    fi
    [[ ",$EXCLUDE," == *",$n,"* ]] && return 1
    return 0
}

section() {
    # section <number> <name> <function>
    local n="$1" name="$2" fn="$3"
    if ! should_run "$n"; then
        info "Section $n ($name) skipped by --sections/--exclude"
        return 0
    fi
    echo
    log "Section $n: $name"
    "$fn"
}

sshd_opt() { sshd -T 2>/dev/null | awk -v k="$1" 'tolower($1)==k {print $2; exit}'; }

#------------------------------------------------------------ arg parsing -----
usage() {
    cat <<EOF
Usage: sudo $0 [options]
  --dry-run             Show what would be done without changing anything
  --audit               Report PASS/FAIL against the hardened state, change nothing
  --profile <p>         desktop (default) or server (stricter SSH/firewall/mounts/services)
  --sections a,b,c      Run only these section numbers (see --help list below)
  --exclude a,b,c       Skip these section numbers
  --ids <i>             crowdsec or fail2ban for section 8 (default: crowdsec on server, fail2ban on desktop)
  -y, --yes             Assume "yes" to optional prompts (non-interactive)
  -h, --help            This help

Sections:
   1 packages            7 firewall             13 banners/perms/sudo
   2 sysctl              8 IPS (crowdsec/fail2ban) 14 AppArmor/SELinux
   3 kernel modules      9 auditd + acct        15 services/mounts/journald
   4 auth policy        10 AIDE + timer         16 cleanup
   5 core dumps         11 malware/rootkit scan 17 GRUB password (interactive)
   6 SSH                12 automatic updates    18 Lynis audit + report analysis
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)  DRY_RUN=1 ;;
        --audit)    AUDIT=1 ;;
        --profile)  PROFILE="${2:-desktop}"; shift ;;
        --sections) SECTIONS="${2:-}"; shift ;;
        --exclude)  EXCLUDE="${2:-}"; shift ;;
        --ids)      IDS="${2:-}"; shift ;;
        -y|--yes)   ASSUME_YES=1 ;;
        -h|--help)  usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
    shift
done

[[ "$PROFILE" =~ ^(desktop|server)$ ]] || { err "Profile must be desktop or server"; exit 1; }
if [[ -z "$IDS" ]]; then
    [[ "$PROFILE" == "server" ]] && IDS="crowdsec" || IDS="fail2ban"
fi
[[ "$IDS" =~ ^(crowdsec|fail2ban)$ ]] || { err "--ids must be crowdsec or fail2ban"; exit 1; }
[[ -z "$SECTIONS" || "$SECTIONS" =~ ^[0-9,]+$ ]] || { err "--sections takes a comma list of numbers"; exit 1; }
[[ -z "$EXCLUDE"  || "$EXCLUDE"  =~ ^[0-9,]+$ ]] || { err "--exclude takes a comma list of numbers"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    err "Run as root: sudo $0"
    exit 1
fi

if [[ $DRY_RUN -eq 0 && $AUDIT -eq 0 ]]; then
    mkdir -p "$BACKUP_DIR" "$LOG_DIR"
    {
        echo "#!/usr/bin/env bash"
        echo "# Rollback for StarHard run $TS."
        echo "# Restores backed-up files, removes files StarHard created, restores"
        echo "# file modes, service and firewall state. Review before running. Reboot afterwards."
        echo "set -x"
    } > "$ROLLBACK"
    chmod 700 "$ROLLBACK"
fi

#-------------------------------------------------------- distro detection ----
OS_ID="unknown"; OS_LIKE=""; PKG=""
if [[ -r /etc/os-release ]]; then
    # sourced in a subshell so os-release's VERSION/ID don't clobber ours
    OS_ID="$(. /etc/os-release; echo "${ID:-unknown}")"
    OS_LIKE="$(. /etc/os-release; echo "${ID_LIKE:-}")"
fi

is_family() { [[ "$OS_ID" == "$1" || " $OS_LIKE " == *" $1 "* ]]; }

if command -v apt-get >/dev/null 2>&1 && (is_family debian || is_family ubuntu); then
    PKG="apt"
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG="yum"
elif command -v zypper >/dev/null 2>&1; then
    PKG="zypper"
elif command -v pacman >/dev/null 2>&1; then
    PKG="pacman"
elif command -v apk >/dev/null 2>&1; then
    PKG="apk"
else
    err "No supported package manager found (apt/dnf/yum/zypper/pacman/apk)."
    exit 1
fi

pkg_installed() {
    case "$PKG" in
        apt)            dpkg -s "$1" >/dev/null 2>&1 ;;
        dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
        pacman)         pacman -Qi "$1" >/dev/null 2>&1 ;;
        apk)            apk info -e "$1" >/dev/null 2>&1 ;;
    esac
}

pkg_update() {
    case "$PKG" in
        apt)    run "apt update" env DEBIAN_FRONTEND=noninteractive apt-get update -qq ;;
        dnf)    run "dnf metadata refresh" dnf -q makecache ;;
        yum)    run "yum metadata refresh" yum -q makecache ;;
        zypper) run "zypper refresh" zypper -q refresh ;;
        pacman) run "pacman -Sy" pacman -Sy --noconfirm ;;
        apk)    run "apk update" apk update -q ;;
    esac
}

pkg_install() {
    # installs each package individually so one missing package doesn't kill the rest;
    # tracks newly installed packages for the rollback script
    local p was
    for p in "$@"; do
        was=1; pkg_installed "$p" && was=0
        case "$PKG" in
            apt)    run "install $p" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$p" ;;
            dnf)    run "install $p" dnf install -y -q "$p" ;;
            yum)    run "install $p" yum install -y -q "$p" ;;
            zypper) run "install $p" zypper -q install -y "$p" ;;
            pacman) run "install $p" pacman -S --noconfirm --needed "$p" ;;
            apk)    run "install $p" apk add -q "$p" ;;
        esac
        [[ $was -eq 1 && $DRY_RUN -eq 0 ]] && pkg_installed "$p" && NEW_PKGS+=("$p")
    done
    return 0
}

pkg_remove() {
    local p
    for p in "$@"; do
        pkg_installed "$p" || continue
        case "$PKG" in
            apt)    run "purge $p" env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$p" ;;
            dnf)    run "remove $p" dnf remove -y -q "$p" ;;
            yum)    run "remove $p" yum remove -y -q "$p" ;;
            zypper) run "remove $p" zypper -q remove -y "$p" ;;
            pacman) run "remove $p" pacman -R --noconfirm "$p" ;;
            apk)    run "remove $p" apk del -q "$p" ;;
        esac
    done
    return 0
}

#===============================================================================
# AUDIT MODE
#===============================================================================
A_PASS=0; A_FAIL=0

chk() {
    # chk <section> <description> <command...>
    local n="$1" d="$2"; shift 2
    should_run "$n" || return 0
    if "$@" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC} [$n] $d"; A_PASS=$((A_PASS+1))
    else
        echo -e "${RED}FAIL${NC} [$n] $d"; A_FAIL=$((A_FAIL+1))
    fi
}

sysctl_is() { [[ "$(sysctl -n "$1" 2>/dev/null)" == "$2" ]]; }
not_other_readable() { [[ ! -e "$1" ]] || [[ "$(stat -c '%a' "$1")" =~ [0-7][0-7]0$ ]]; }
fw_active() {
    if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null | grep -q 'Status: active'
    elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state 2>/dev/null | grep -q running
    elif command -v nft >/dev/null 2>&1; then [[ -n "$(nft list ruleset 2>/dev/null)" ]]
    else return 1; fi
}
svc_active() { has_systemd && systemctl is-active -q "$1" 2>/dev/null; }
mac_active() {
    if command -v aa-status >/dev/null 2>&1; then aa-status --enabled 2>/dev/null
    elif command -v getenforce >/dev/null 2>&1; then [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]
    else return 1; fi
}
scanner_present() { command -v lynis >/dev/null 2>&1 && command -v clamscan >/dev/null 2>&1; }
clam_db() { ls /var/lib/clamav/main.c[lv]d /var/lib/clamav/daily.c[lv]d >/dev/null 2>&1; }
mount_has_opt() { findmnt -no OPTIONS "$1" 2>/dev/null | grep -qw "$2"; }
autoupd_cfg() {
    case "$PKG" in
        apt) grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null ;;
        dnf) svc_active dnf-automatic.timer ;;
        zypper) svc_active starhard-zypper-patch.timer ;;
        *) return 1 ;;
    esac
}
audit_rules_loaded() { [[ "$(auditctl -l 2>/dev/null | grep -c .)" -ge 10 ]]; }
aide_scheduled() { [[ -f /etc/cron.daily/dailyaidecheck ]] || svc_active starhard-aide-check.timer; }

do_audit() {
    echo "==============================================================="
    echo "  StarHard v$VERSION — AUDIT (profile: $PROFILE). Nothing will change."
    echo "==============================================================="
    chk 2  "sysctl hardening file present"            test -f /etc/sysctl.d/99-hardening.conf
    chk 2  "kernel.kptr_restrict = 2"                 sysctl_is kernel.kptr_restrict 2
    chk 2  "net.ipv4.tcp_syncookies = 1"              sysctl_is net.ipv4.tcp_syncookies 1
    chk 2  "net.ipv4.conf.all.accept_redirects = 0"   sysctl_is net.ipv4.conf.all.accept_redirects 0
    chk 3  "module blacklist present"                 test -f /etc/modprobe.d/hardening-blacklist.conf
    chk 3  "dccp module not loaded"                   bash -c '! lsmod | grep -q "^dccp "'
    chk 4  "login.defs UMASK 027"                     grep -Eq '^UMASK\s+027' /etc/login.defs
    chk 4  "pwquality policy present"                 test -f /etc/security/pwquality.conf.d/50-hardening.conf
    chk 4  "faillock policy present"                  test -f /etc/security/faillock.conf
    chk 4  "cron.allow restricts to root"             grep -qx root /etc/cron.allow
    chk 5  "core dumps disabled (limits)"             test -f /etc/security/limits.d/50-nocoredump.conf
    chk 5  "fs.suid_dumpable = 0"                     sysctl_is fs.suid_dumpable 0
    if command -v sshd >/dev/null 2>&1; then
        chk 6 "sshd PermitRootLogin no"               bash -c "[[ \"$(sshd_opt permitrootlogin)\" == no ]]"
        chk 6 "sshd MaxAuthTries <= 6"                bash -c "[[ \"$(sshd_opt maxauthtries)\" -le 6 ]]"
        chk 6 "sshd Banner set"                       bash -c "[[ \"$(sshd_opt banner)\" != none ]]"
        chk 6 "sshd X11Forwarding no"                 bash -c "[[ \"$(sshd_opt x11forwarding)\" == no ]]"
        if [[ "$PROFILE" == "server" ]]; then
            chk 6 "sshd PasswordAuthentication no (server)" bash -c "[[ \"$(sshd_opt passwordauthentication)\" == no ]]"
            chk 6 "sshd AllowTcpForwarding no (server)"     bash -c "[[ \"$(sshd_opt allowtcpforwarding)\" == no ]]"
        fi
    fi
    chk 7  "firewall active"                          fw_active
    if [[ "$IDS" == "crowdsec" ]]; then
        chk 8 "crowdsec running"                      svc_active crowdsec
        chk 8 "crowdsec firewall bouncer running"     svc_active crowdsec-firewall-bouncer
        chk 8 "bouncer registered with LAPI"          bash -c 'cscli bouncers list -o raw 2>/dev/null | grep -qi firewall'
        chk 8 "fail2ban not running alongside crowdsec" bash -c '! systemctl is-active -q fail2ban 2>/dev/null'
    else
        chk 8 "fail2ban running"                      svc_active fail2ban
        chk 8 "fail2ban recidive uses backend=auto"   bash -c "grep -A4 '^\[recidive\]' /etc/fail2ban/jail.local 2>/dev/null | grep -q 'backend *= *auto'"
    fi
    chk 9  "auditd running"                           svc_active auditd
    chk 9  "audit rules loaded (>=10)"                audit_rules_loaded
    chk 10 "AIDE database exists"                     bash -c 'ls /var/lib/aide/aide.db /var/lib/aide/aide.db.gz >/dev/null 2>&1'
    chk 10 "AIDE check scheduled"                     aide_scheduled
    chk 11 "lynis + clamav installed"                 scanner_present
    chk 11 "ClamAV signature database present"        clam_db
    chk 11 "weekly starhard-scan timer active"        svc_active starhard-scan.timer
    chk 12 "automatic security updates configured"    autoupd_cfg
    chk 13 "/etc/shadow not other-readable"           not_other_readable /etc/shadow
    chk 13 "/etc/gshadow not other-readable"          not_other_readable /etc/gshadow
    chk 13 "login banner present"                     grep -q 'AUTHORIZED USE ONLY' /etc/issue
    chk 13 "sudo hardening present"                   test -f /etc/sudoers.d/50-starhard
    chk 14 "MAC (AppArmor/SELinux) enforcing"         mac_active
    chk 15 "ctrl-alt-del masked"                      bash -c 'systemctl is-enabled ctrl-alt-del.target 2>/dev/null | grep -q masked'
    chk 15 "/dev/shm mounted noexec"                  mount_has_opt /dev/shm noexec
    chk 15 "journald persistent"                      grep -rqs '^Storage=persistent' /etc/systemd/journald.conf.d/ /etc/systemd/journald.conf
    if [[ "$PROFILE" == "server" ]]; then
        chk 15 "/tmp mounted noexec (server)"         mount_has_opt /tmp noexec
        chk 15 "avahi not running (server)"           bash -c '! systemctl is-active -q avahi-daemon 2>/dev/null'
    fi
    echo "==============================================================="
    echo "  PASS: $A_PASS   FAIL: $A_FAIL"
    echo "==============================================================="
    [[ $A_FAIL -eq 0 ]]
}


echo "==============================================================="
echo "  StarHard v$VERSION"
echo "  OS: $OS_ID   Package manager: $PKG   Profile: $PROFILE   Arch: $ARCH   IPS: $IDS"
[[ $DRY_RUN -eq 1 ]] && echo "  MODE: DRY RUN — no changes will be made"
[[ $SSH_ACTIVE -eq 1 ]] && echo "  Running over SSH — SSH access will be preserved in firewall rules"
echo "  Backups: $BACKUP_DIR"
echo "==============================================================="

#===============================================================================
# 1. Packages
#===============================================================================
sec_packages() {
    pkg_update
    local server_pkgs=() f2b=()
    [[ "$IDS" == "fail2ban" ]] && f2b=(fail2ban)
    [[ "$PKG" == "apt" && "$IDS" == "fail2ban" ]] && f2b+=(python3-systemd)
    case "$PKG" in
        apt)
            [[ "$PROFILE" == "server" ]] && server_pkgs=(usbguard)
            pkg_install aide "${f2b[@]}" libpam-tmpdir needrestart \
                apt-listchanges libpam-pwquality libpam-modules auditd audispd-plugins \
                acct debsums unattended-upgrades apparmor apparmor-utils ufw \
                lynis clamav clamav-freshclam unhide sudo "${server_pkgs[@]}"
            ;;
        dnf|yum)
            if [[ "$OS_ID" != "fedora" ]] && is_family rhel; then
                pkg_installed epel-release || pkg_install epel-release
                pkg_update
            fi
            [[ "$PROFILE" == "server" ]] && server_pkgs=(usbguard)
            pkg_install aide "${f2b[@]}" audit psacct libpwquality firewalld \
                dnf-automatic policycoreutils lynis clamav clamav-update unhide sudo \
                "${server_pkgs[@]}"
            ;;
        zypper)
            [[ "$PROFILE" == "server" ]] && server_pkgs=(usbguard)
            pkg_install aide "${f2b[@]}" audit acct pam_pwquality firewalld lynis clamav unhide sudo \
                "${server_pkgs[@]}"
            ;;
        pacman)
            [[ "$PROFILE" == "server" ]] && server_pkgs=(usbguard)
            pkg_install aide "${f2b[@]}" audit acct libpwquality ufw lynis clamav unhide sudo \
                "${server_pkgs[@]}"
            ;;
        apk)
            pkg_install aide "${f2b[@]}" audit lynis clamav sudo
            ;;
    esac
    info "Not installed automatically (external repos): Wazuh agent (FIM/rootkit/log analysis) and Falco/Tetragon (eBPF runtime detection) are recommended on servers."
}

#===============================================================================
# 2. Kernel / sysctl hardening
#===============================================================================
sec_sysctl() {
    write_file /etc/sysctl.d/99-hardening.conf 644 <<'EOF'
# === Kernel ===
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.kexec_load_disabled = 1
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
kernel.io_uring_disabled = 2
vm.unprivileged_userfaultfd = 0
net.core.bpf_jit_harden = 2

# === IPv4 ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === IPv6 ===
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
    # -e: keys unknown to this kernel are ignored instead of failing the whole run
    run "Apply sysctl settings" sysctl -e --system
}

#===============================================================================
# 3. Blacklist rarely-used kernel modules
#===============================================================================
sec_modules() {
    local mods=(dccp sctp rds tipc cramfs freevxfs jffs2 hfs hfsplus udf firewire-core)
    [[ "$PROFILE" == "server" ]] && mods+=(bluetooth btusb)
    {
        echo "# StarHard — 'install' blocks explicit loading, 'blacklist' blocks autoloading"
        local m
        for m in "${mods[@]}"; do
            printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m"
        done
    } | write_file /etc/modprobe.d/hardening-blacklist.conf 644

    # Unload anything already loaded (fails harmlessly if in use)
    local m
    for m in "${mods[@]}"; do
        if lsmod 2>/dev/null | grep -q "^${m//-/_} "; then
            run "unload module $m" modprobe -r "$m" || warn "$m is in use — will be blocked after reboot"
        fi
    done
}

#===============================================================================
# 4. Password policy, umask, hashing, account lockout, cron
#===============================================================================
sec_auth() {
    if [[ -f /etc/login.defs ]]; then
        # Prefer yescrypt when libcrypt supports it (Debian 11+, Fedora, Arch, openSUSE TW)
        local hash_block
        local ys
        ys="$(perl -e 'print crypt("x","\$y\$j9T\$abcdefghijklmnopq\$")' 2>/dev/null || true)"
        if [[ "$ys" == '$y$'* ]]; then
            hash_block=$'ENCRYPT_METHOD  YESCRYPT\nYESCRYPT_COST_FACTOR 7'
            info "yescrypt supported — using ENCRYPT_METHOD YESCRYPT"
        else
            hash_block=$'ENCRYPT_METHOD  SHA512\nSHA_CRYPT_MIN_ROUNDS 100000\nSHA_CRYPT_MAX_ROUNDS 100000'
            info "yescrypt not available — using SHA512 with 100000 rounds"
        fi
        backup_file /etc/login.defs
        if [[ $DRY_RUN -eq 0 ]]; then
            sed -i -E '/^#?\s*(UMASK|SHA_CRYPT_MIN_ROUNDS|SHA_CRYPT_MAX_ROUNDS|YESCRYPT_COST_FACTOR|ENCRYPT_METHOD|PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)\b/d' /etc/login.defs
            sed -i '/^# === StarHard ===$/d' /etc/login.defs
            {
                echo
                echo "# === StarHard ==="
                echo "UMASK           027"
                echo "$hash_block"
                echo "PASS_MAX_DAYS   365"
                echo "PASS_MIN_DAYS   1"
                echo "PASS_WARN_AGE   14"
            } >> /etc/login.defs
            log "login.defs updated"
        else
            info "DRY-RUN: would update /etc/login.defs"
        fi
    fi

    write_file /etc/profile.d/50-umask-hardening.sh 644 <<'EOF'
umask 027
EOF

    if [[ -d /etc/security ]]; then
        write_file /etc/security/pwquality.conf.d/50-hardening.conf 644 <<'EOF'
minlen = 14
minclass = 3
maxrepeat = 3
difok = 3
enforce_for_root
EOF
        write_file /etc/security/faillock.conf 644 <<'EOF'
# StarHard: lock account after 5 failures within 15 min, unlock after 15 min
deny = 5
fail_interval = 900
unlock_time = 900
audit
even_deny_root
root_unlock_time = 60
EOF
    fi

    # Debian family PAM wiring (RHEL uses authselect below; Arch ships faillock enabled)
    if [[ -f /etc/pam.d/common-password ]] && ! grep -q pam_pwquality /etc/pam.d/common-password; then
        backup_file /etc/pam.d/common-password
        if [[ $DRY_RUN -eq 0 ]]; then
            sed -i '/pam_unix.so/i password\trequisite\t\t\tpam_pwquality.so retry=3' /etc/pam.d/common-password
            log "pam_pwquality enabled"
        fi
    fi

    if command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1; then
        run "authselect: enable faillock" authselect enable-feature with-faillock
        run "authselect: apply" authselect apply-changes
    elif [[ -f /etc/pam.d/common-auth ]] && ! grep -q pam_faillock /etc/pam.d/common-auth; then
        if ls /lib/security/pam_faillock.so /lib/*/security/pam_faillock.so /usr/lib/*/security/pam_faillock.so /usr/lib/security/pam_faillock.so >/dev/null 2>&1; then
            backup_file /etc/pam.d/common-auth
            backup_file /etc/pam.d/common-account
            if [[ $DRY_RUN -eq 0 ]]; then
                # Order (per pam_faillock(8)): preauth, pam_unix, authfail, authsucc.
                # pam_unix's [success=1] skips authfail on success and lands on authsucc.
                sed -i '0,/pam_unix.so/s//pam_unix.so/;/pam_unix.so/i auth\trequired\t\t\tpam_faillock.so preauth' /etc/pam.d/common-auth
                sed -i '/pam_unix.so/a auth\t[default=die]\t\t\tpam_faillock.so authfail\nauth\tsufficient\t\t\tpam_faillock.so authsucc' /etc/pam.d/common-auth
                if [[ -f /etc/pam.d/common-account ]] && ! grep -q pam_faillock /etc/pam.d/common-account; then
                    sed -i '/pam_unix.so/i account\trequired\t\t\tpam_faillock.so' /etc/pam.d/common-account
                fi
                log "pam_faillock enabled (note: pam-auth-update may rewrite common-auth; re-run StarHard after PAM upgrades)"
            else
                info "DRY-RUN: would wire pam_faillock into common-auth/common-account"
            fi
        else
            warn "pam_faillock.so not found — account lockout not configured"
        fi
    fi

    local f
    for f in /etc/cron.allow /etc/at.allow; do
        write_file "$f" 600 <<'EOF'
root
EOF
    done
    if [[ $DRY_RUN -eq 0 ]]; then
        for f in /etc/cron.deny /etc/at.deny; do
            [[ -e "$f" ]] && { backup_file "$f"; rm -f "$f"; }
        done
    fi
    return 0
}

#===============================================================================
# 5. Core dumps off
#===============================================================================
sec_coredump() {
    write_file /etc/security/limits.d/50-nocoredump.conf 644 <<'EOF'
* hard core 0
* soft core 0
EOF
    if [[ -d /etc/systemd ]]; then
        write_file /etc/systemd/coredump.conf.d/50-hardening.conf 644 <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    fi
}

#===============================================================================
# 6. SSH hardening (with lockout protection)
#===============================================================================
has_authorized_keys() {
    local d
    for d in /root /home/*; do
        [[ -s "$d/.ssh/authorized_keys" ]] && return 0
    done
    return 1
}

sec_ssh() {
    if [[ ! -d /etc/ssh ]]; then info "No /etc/ssh — skipping"; return 0; fi
    local cfg=/etc/ssh/sshd_config dropin=/etc/ssh/sshd_config.d/50-hardening.conf
    local changed_main=0

    # sshd only reads sshd_config.d if the main config includes it
    if [[ -f "$cfg" ]] && ! grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$cfg"; then
        backup_file "$cfg"
        if [[ $DRY_RUN -eq 0 ]]; then
            sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$cfg"
            changed_main=1
            log "Added Include /etc/ssh/sshd_config.d/*.conf to sshd_config"
        else
            info "DRY-RUN: would add Include line to $cfg"
        fi
    fi

    local pw_line="" profile_lines
    if [[ "$PROFILE" == "server" ]]; then
        if has_authorized_keys; then
            warn "Server profile: SSH password login will be DISABLED. Ensure your key works first!"
            if ask "Confirm disabling SSH password authentication?"; then
                pw_line="PasswordAuthentication no"
            else
                warn "Keeping password authentication enabled"
            fi
        else
            warn "No authorized_keys found for any user — REFUSING to disable password authentication"
        fi
        profile_lines=$'MaxAuthTries 4\nMaxSessions 4\nAllowTcpForwarding no\nAllowAgentForwarding no'
    else
        profile_lines=$'MaxAuthTries 6\nMaxSessions 10'
    fi

    [[ $DRY_RUN -eq 0 ]] && mkdir -p /etc/ssh/sshd_config.d
    write_file "$dropin" 600 <<EOF
# StarHard v$VERSION ($PROFILE profile)
PermitRootLogin no
LoginGraceTime 30
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UsePAM yes
Banner /etc/issue.net
$profile_lines
$pw_line
EOF

    if [[ $DRY_RUN -eq 0 ]] && command -v sshd >/dev/null 2>&1; then
        if sshd -t 2>>"$LOG_FILE"; then
            if has_systemd; then
                systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            elif command -v rc-service >/dev/null 2>&1; then
                rc-service sshd reload 2>/dev/null || true
            fi
            log "sshd config validated and reloaded"
        else
            err "sshd rejected new config — reverting SSH hardening"
            rm -f "$dropin"
            [[ $changed_main -eq 1 ]] && cp -a "$BACKUP_DIR$cfg" "$cfg"
        fi
    fi
}

#===============================================================================
# 7. Firewall
#===============================================================================
sec_firewall() {
    local ssh_port
    ssh_port="$(sshd_opt port)"; ssh_port="${ssh_port:-22}"
    local need_ssh=0
    [[ "$PROFILE" == "server" || $SSH_ACTIVE -eq 1 ]] && need_ssh=1

    if command -v ufw >/dev/null 2>&1; then
        local was_active=0
        ufw status 2>/dev/null | grep -q 'Status: active' && was_active=1
        run "ufw default deny incoming" ufw default deny incoming
        run "ufw default allow outgoing" ufw default allow outgoing
        if [[ $need_ssh -eq 1 ]]; then
            run "ufw allow ssh port $ssh_port (rate-limited)" ufw limit "$ssh_port/tcp"
        fi
        if [[ $DRY_RUN -eq 0 ]]; then
            [[ $was_active -eq 0 ]] && rb "ufw disable"
            ufw --force enable >> "$LOG_FILE" 2>&1 && log "ufw enabled"
        else
            info "DRY-RUN: would enable ufw"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        svc_enable firewalld
        run "firewalld default zone public" firewall-cmd --set-default-zone=public
        if [[ $need_ssh -eq 1 ]]; then
            run "allow ssh" firewall-cmd --permanent --add-service=ssh
            [[ "$ssh_port" != "22" ]] && run "allow ssh port $ssh_port" firewall-cmd --permanent --add-port="$ssh_port/tcp"
        fi
        run "reload firewalld" firewall-cmd --reload
    elif command -v nft >/dev/null 2>&1; then
        warn "Only nftables found — writing an example ruleset to /etc/nftables.conf.starhard-example (NOT activated)"
        write_file /etc/nftables.conf.starhard-example 600 <<EOF
#!/usr/sbin/nft -f
# StarHard example — review, copy to /etc/nftables.conf, then: nft -f /etc/nftables.conf
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        tcp dport $ssh_port ct state new limit rate 6/minute accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output priority 0; policy accept; }
}
EOF
    else
        warn "No firewall tool found — install ufw or firewalld"
    fi
}

#===============================================================================
# 8. fail2ban
#===============================================================================
sec_fail2ban() {
    command -v fail2ban-server >/dev/null 2>&1 || { info "fail2ban not installed — skipping"; return 0; }
    local backend="systemd"
    has_systemd || backend="auto"
    write_file /etc/fail2ban/jail.local 644 <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = $backend
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
maxretry = 4
bantime  = 2h

[recidive]
# recidive reads fail2ban's own log file, so it must not use the systemd backend
enabled  = true
backend  = auto
logpath  = /var/log/fail2ban.log
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
    svc_enable fail2ban
}

#===============================================================================
# 8b. CrowdSec (alternative to fail2ban) — official repo + firewall bouncer
#===============================================================================
crowdsec_add_repo() {
    # packagecloud repo for deb/rpm families; distro repos elsewhere
    local script=""
    case "$PKG" in
        apt)         script="https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh" ;;
        dnf|yum)     script="https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh" ;;
        pacman)      info "Arch: using distro 'crowdsec' package; the bouncer is AUR-only (crowdsec-firewall-bouncer)"; return 0 ;;
        zypper|apk)  info "$PKG: attempting distro packages (no official CrowdSec repo)"; return 0 ;;
    esac
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would add CrowdSec repository via $script"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || pkg_install curl
    if curl -fsSL "$script" | bash >> "$LOG_FILE" 2>&1; then
        log "CrowdSec repository added"
        case "$PKG" in
            apt)     rb "rm -f /etc/apt/sources.list.d/crowdsec_crowdsec.list /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg /etc/apt/trusted.gpg.d/crowdsec_crowdsec.gpg" ;;
            dnf|yum) rb "rm -f /etc/yum.repos.d/crowdsec_crowdsec.repo" ;;
        esac
        return 0
    fi
    err "Failed to add CrowdSec repository (see $LOG_FILE)"
    return 1
}

sec_crowdsec() {
    if ! has_systemd; then
        warn "CrowdSec setup here requires systemd — falling back to fail2ban"
        pkg_install fail2ban; sec_fail2ban; return 0
    fi

    if ! pkg_installed crowdsec; then
        crowdsec_add_repo || { warn "Falling back to fail2ban"; pkg_install fail2ban; sec_fail2ban; return 0; }
        pkg_install crowdsec
    fi
    if [[ $DRY_RUN -eq 0 ]] && ! command -v cscli >/dev/null 2>&1; then
        warn "crowdsec not installed — falling back to fail2ban"
        pkg_install fail2ban; sec_fail2ban; return 0
    fi

    # Firewall bouncer: nftables where available, else iptables. Works alongside ufw/firewalld.
    local bouncer="crowdsec-firewall-bouncer-iptables"
    command -v nft >/dev/null 2>&1 && bouncer="crowdsec-firewall-bouncer-nftables"
    [[ "$PKG" == "pacman" ]] && bouncer="crowdsec-firewall-bouncer"
    pkg_installed "$bouncer" || pkg_install "$bouncer"

    # Stop fail2ban so both don't ban/unban the same IPs
    if pkg_installed fail2ban || unit_exists fail2ban.service; then
        if [[ $DRY_RUN -eq 0 ]]; then
            if systemctl is-enabled -q fail2ban 2>/dev/null || systemctl is-active -q fail2ban 2>/dev/null; then
                rb "systemctl enable --now fail2ban 2>/dev/null || true"
                systemctl disable --now fail2ban >> "$LOG_FILE" 2>&1 && log "fail2ban stopped and disabled (CrowdSec takes over)"
                systemctl mask fail2ban >> "$LOG_FILE" 2>&1 && rb "systemctl unmask fail2ban 2>/dev/null || true"
            fi
        else
            info "DRY-RUN: would disable and mask fail2ban"
        fi
    fi

    if [[ $DRY_RUN -eq 0 ]]; then
        cscli hub update >> "$LOG_FILE" 2>&1 || true
        # Base collections: parsers + scenarios for the OS and sshd (idempotent)
        cscli collections install crowdsecurity/linux crowdsecurity/sshd >> "$LOG_FILE" 2>&1 \
            && log "CrowdSec collections: linux, sshd" \
            || warn "cscli collections install reported errors (see log)"
        # Acquisition: make sure sshd logs are read from the journal when no auth.log exists
        if [[ ! -f /var/log/auth.log && ! -f /var/log/secure ]]; then
            write_file /etc/crowdsec/acquis.d/starhard-sshd-journal.yaml 644 <<'EOF'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
EOF
        fi
        # Never ban ourselves
        write_file /etc/crowdsec/parsers/s02-enrich/starhard-whitelist.yaml 644 <<'EOF'
name: starhard/whitelists
description: "Never ban loopback"
whitelist:
  reason: "loopback"
  ip:
    - "127.0.0.1"
    - "::1"
EOF
    fi

    svc_enable crowdsec
    svc_enable crowdsec-firewall-bouncer

    if [[ $DRY_RUN -eq 0 ]]; then
        sleep 2
        if cscli bouncers list -o raw 2>/dev/null | grep -qi firewall; then
            log "Firewall bouncer registered with the local API"
        else
            warn "Bouncer not registered — run: cscli bouncers add starhard-fw && put the key in /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        fi
        info "Optional: enrol in the free console for a dashboard — cscli console enroll <key>  (https://app.crowdsec.net)"
        info "Check activity: cscli metrics | cscli decisions list | cscli alerts list"
    fi
    return 0
}

sec_ips() {
    if [[ "$IDS" == "crowdsec" ]]; then sec_crowdsec; else sec_fail2ban; fi
}

#===============================================================================
# 9. auditd
#===============================================================================
sec_auditd() {
    command -v auditctl >/dev/null 2>&1 || { info "auditd not installed — skipping"; return 0; }
    local arches="b64"
    [[ "$ARCH" == "x86_64" ]] && arches="b64 b32"
    {
        cat <<'EOF'
-D
-b 8192
-f 1

# Identity files
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Privilege escalation
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /bin/su -p x -k privileged
-w /usr/bin/sudo -p x -k privileged
-w /var/log/sudo.log -p wa -k sudo_log

# System configuration
-w /etc/systemd/ -p wa -k systemd
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k pam
-w /etc/apparmor/ -p wa -k mac
-w /etc/apparmor.d/ -p wa -k mac
-w /etc/selinux/ -p wa -k mac
EOF
        local a
        for a in $arches; do
            cat <<EOF

# Syscall rules ($a)
-a always,exit -F arch=$a -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k priv_esc
-a always,exit -F arch=$a -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=$a -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=$a -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=$a -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=$a -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
EOF
        done
        cat <<'EOF'

# Uncomment to log every command run by a real user (very noisy; useful on servers with a log shipper)
#-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec

# Make configuration immutable (requires reboot to change rules)
-e 2
EOF
    } | write_file /etc/audit/rules.d/50-hardening.rules 640

    if [[ $DRY_RUN -eq 0 ]]; then
        if auditctl -s 2>/dev/null | grep -q '^enabled 2'; then
            warn "audit is in immutable mode (-e 2) — new rules load on next reboot"
        else
            if augenrules --load >> "$LOG_FILE" 2>&1; then
                log "audit rules loaded"
            else
                warn "augenrules --load reported errors (see log)"
            fi
        fi
    fi
    svc_enable auditd

    # Process accounting
    if command -v accton >/dev/null 2>&1; then
        if has_systemd; then
            unit_exists acct.service && svc_enable acct
            unit_exists psacct.service && svc_enable psacct
        fi
    fi
    return 0
}

#===============================================================================
# 10. AIDE file-integrity baseline + daily check
#===============================================================================
sec_aide() {
    command -v aide >/dev/null 2>&1 || { info "AIDE not installed — skipping"; return 0; }
    if [[ $DRY_RUN -eq 0 && ! -f /var/lib/aide/aide.db && ! -f /var/lib/aide/aide.db.gz ]]; then
        info "Building AIDE baseline (can take several minutes)"
        if command -v aideinit >/dev/null 2>&1; then
            aideinit --yes --force >> "$LOG_FILE" 2>&1 || aide --init >> "$LOG_FILE" 2>&1 || true
        elif [[ -f /etc/aide/aide.conf ]]; then
            aide --init -c /etc/aide/aide.conf >> "$LOG_FILE" 2>&1 || true
        else
            aide --init >> "$LOG_FILE" 2>&1 || true
        fi
        local ext
        for ext in "" ".gz"; do
            [[ -f "/var/lib/aide/aide.db.new$ext" ]] && mv "/var/lib/aide/aide.db.new$ext" "/var/lib/aide/aide.db$ext"
        done
        log "AIDE baseline created"
    else
        info "AIDE database already exists or dry-run — skipping init"
    fi

    write_file /usr/local/sbin/starhard-aide-check 755 <<'EOF'
#!/bin/sh
# StarHard: daily AIDE integrity check. Findings go to /var/log/starhard/aide-<date>.log
mkdir -p /var/log/starhard
LOG="/var/log/starhard/aide-$(date +%F).log"
if command -v aide.wrapper >/dev/null 2>&1; then
    aide.wrapper --check > "$LOG" 2>&1
elif [ -f /etc/aide/aide.conf ]; then
    aide --check -c /etc/aide/aide.conf > "$LOG" 2>&1
else
    aide --check > "$LOG" 2>&1
fi
rc=$?
[ $rc -ne 0 ] && logger -t starhard-aide "AIDE detected changes (rc=$rc) — see $LOG"
exit 0
EOF
    if [[ -f /etc/cron.daily/dailyaidecheck ]]; then
        info "Distro already schedules a daily AIDE check (/etc/cron.daily/dailyaidecheck)"
    else
        write_timer starhard-aide-check "StarHard daily AIDE integrity check" daily /usr/local/sbin/starhard-aide-check
    fi
}

#===============================================================================
# 11. Malware / rootkit scanning (replaces rkhunter + chkrootkit)
#===============================================================================
sec_scanners() {
    # ClamAV signature updates
    if command -v freshclam >/dev/null 2>&1; then
        local u found=0
        if has_systemd; then
            for u in clamav-freshclam freshclam; do
                if unit_exists "$u.service"; then svc_enable "$u"; found=1; break; fi
            done
        elif command -v rc-update >/dev/null 2>&1 && [[ -f /etc/init.d/freshclam ]]; then
            svc_enable freshclam; found=1
        fi
        [[ $found -eq 0 ]] && warn "No freshclam service unit found — schedule 'freshclam' manually"
        if [[ $DRY_RUN -eq 0 ]] && ! clam_db; then
            info "Downloading ClamAV signatures (first run, may take a few minutes)"
            freshclam >> "$LOG_FILE" 2>&1 || warn "freshclam initial download failed (see log); the service will retry"
        fi
    else
        warn "clamav not installed — skipping signature setup"
    fi

    # Weekly scan: ClamAV + unhide + package integrity + Lynis
    write_file /usr/local/sbin/starhard-scan 755 <<'EOF'
#!/bin/sh
# StarHard weekly scan. Output: /var/log/starhard/scan-<date>.log
mkdir -p /var/log/starhard
LOG="/var/log/starhard/scan-$(date +%F).log"
{
    echo "== starhard-scan $(date) =="

    if command -v clamscan >/dev/null 2>&1; then
        echo; echo "-- clamscan --"
        DIRS=""
        for d in /etc /home /root /tmp /var/tmp /usr/local /opt /srv /var/www; do
            [ -d "$d" ] && DIRS="$DIRS $d"
        done
        # shellcheck disable=SC2086
        clamscan -r -i --exclude-dir='^/(proc|sys|dev|run)' $DIRS
    fi

    if command -v unhide >/dev/null 2>&1; then
        echo; echo "-- unhide (hidden processes) --"
        unhide proc
        unhide sys
    fi

    echo; echo "-- package integrity --"
    if command -v debsums >/dev/null 2>&1; then
        debsums -s
    elif command -v rpm >/dev/null 2>&1; then
        rpm -Va 2>/dev/null | grep '^..5' | grep -v '^.*c /etc/'
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Qkk 2>/dev/null | grep -v ' 0 altered files'
    fi

    if command -v lynis >/dev/null 2>&1; then
        echo; echo "-- lynis --"
        lynis audit system --cronjob --quiet
        echo "Full report: /var/log/lynis-report.dat"
    fi
} > "$LOG" 2>&1
logger -t starhard-scan "weekly scan complete — see $LOG"
exit 0
EOF
    write_timer starhard-scan "StarHard weekly malware/rootkit/integrity scan" weekly /usr/local/sbin/starhard-scan

    # Retire rkhunter/chkrootkit if a previous version installed them
    if pkg_installed rkhunter || pkg_installed chkrootkit; then
        if ask "Remove legacy rkhunter/chkrootkit (unmaintained; replaced by ClamAV+unhide+Lynis)?"; then
            pkg_remove rkhunter chkrootkit
        fi
    fi
    return 0
}

#===============================================================================
# 12. Automatic security updates
#===============================================================================
sec_autoupdate() {
    case "$PKG" in
        apt)
            write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
            write_file /etc/apt/apt.conf.d/52starhard-unattended-upgrades 644 <<'EOF'
// StarHard: security updates only, clean up afterwards, never auto-reboot.
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
EOF
            has_systemd && unit_exists unattended-upgrades.service && svc_enable unattended-upgrades
            case "$OS_ID" in kali|parrot) warn "Rolling distro: '${OS_ID}' has no -security pocket; unattended-upgrades will do nothing. Update manually." ;; esac
            ;;
        dnf)
            if [[ -f /etc/dnf/automatic.conf ]]; then
                backup_file /etc/dnf/automatic.conf
                [[ $DRY_RUN -eq 0 ]] && sed -i -e 's/^upgrade_type.*/upgrade_type = security/' -e 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
                svc_enable dnf-automatic.timer
            fi
            ;;
        zypper)
            write_timer starhard-zypper-patch "StarHard daily security patches (zypper)" daily "/usr/bin/zypper --non-interactive patch --category security"
            ;;
        pacman) info "Arch: unattended upgrades are not recommended on a rolling release — run 'pacman -Syu' regularly" ;;
        apk)    info "Alpine: schedule 'apk upgrade --available' via cron if desired" ;;
        *)      info "Automatic updates: configure manually for $PKG" ;;
    esac
}

#===============================================================================
# 13. Legal banners, file permissions, sudo
#===============================================================================
sec_perms() {
    write_file /etc/issue 644 <<'EOF'
***********************************************************************
*  AUTHORIZED USE ONLY                                                *
*  All activity on this system is monitored and logged.               *
*  Unauthorized access is prohibited.                                 *
***********************************************************************
EOF
    if [[ $DRY_RUN -eq 0 ]]; then
        if [[ -e /etc/issue.net ]]; then backup_file /etc/issue.net; else record_rm /etc/issue.net; fi
        cp /etc/issue /etc/issue.net
    fi

    # Only ever tighten — never loosen (RHEL ships shadow as 0000)
    tighten /etc/shadow o-rwx
    tighten /etc/gshadow o-rwx
    tighten /etc/crontab 0600
    tighten /etc/ssh/sshd_config 0600
    tighten /boot/grub/grub.cfg 0600
    tighten /boot/grub2/grub.cfg 0600
    local d
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "$d" ]] && tighten "$d" 700
    done
    [[ -d /etc/sudoers.d ]] && tighten /etc/sudoers.d 750

    # Home directories: 750 (CIS) — no other-access
    for d in /home/*; do
        [[ -d "$d" ]] || continue
        tighten "$d" o-rwx
    done

    # sudo hardening
    if command -v visudo >/dev/null 2>&1; then
        write_file /etc/sudoers.d/50-starhard 440 <<'EOF'
# StarHard
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults log_input
Defaults passwd_timeout=1
EOF
        if [[ $DRY_RUN -eq 0 ]] && ! visudo -cf /etc/sudoers.d/50-starhard >> "$LOG_FILE" 2>&1; then
            err "visudo rejected /etc/sudoers.d/50-starhard — removing"
            rm -f /etc/sudoers.d/50-starhard
        fi
    fi
    return 0
}

#===============================================================================
# 14. Mandatory Access Control (AppArmor / SELinux)
#===============================================================================
sec_mac() {
    if command -v aa-status >/dev/null 2>&1; then
        svc_enable apparmor
        if aa-status --enabled 2>/dev/null; then
            log "AppArmor active"
            local do_enforce=0
            if [[ "$PROFILE" == "server" ]]; then
                do_enforce=1
            elif ask "Set all AppArmor profiles to enforce mode? (may break apps whose profiles are in complain mode)"; then
                do_enforce=1
            fi
            if [[ $do_enforce -eq 1 && $DRY_RUN -eq 0 ]] && command -v aa-enforce >/dev/null 2>&1; then
                local p n count=0
                for p in /etc/apparmor.d/*; do
                    [[ -f "$p" ]] || continue
                    n="$(basename "$p")"
                    [[ -e "/etc/apparmor.d/disable/$n" || -e "/etc/apparmor.d/force-complain/$n" ]] && continue
                    aa-enforce "$p" >> "$LOG_FILE" 2>&1 && count=$((count+1))
                done
                log "AppArmor: $count profiles set to enforce"
            fi
        else
            warn "AppArmor installed but not active (may need kernel cmdline: apparmor=1 security=apparmor)"
        fi
    elif command -v getenforce >/dev/null 2>&1; then
        local state
        state="$(getenforce 2>/dev/null || echo unknown)"
        if [[ "$state" == "Enforcing" ]]; then
            log "SELinux enforcing"
        else
            warn "SELinux is '$state'. Set SELINUX=enforcing in /etc/selinux/config after testing in permissive mode."
        fi
    else
        info "No AppArmor or SELinux tooling found"
    fi
    return 0
}

#===============================================================================
# 15. Services, mounts, journald
#===============================================================================
remount_with() {
    # remount_with <mountpoint> <opts>  — only if it is actually a mount
    findmnt -n "$1" >/dev/null 2>&1 || return 1
    run "remount $1 with $2" mount -o "remount,$2" "$1"
}

sec_services() {
    if has_systemd; then
        svc_mask ctrl-alt-del.target

        write_file /etc/systemd/journald.conf.d/50-hardening.conf 644 <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
ForwardToSyslog=yes
EOF
        if [[ $DRY_RUN -eq 0 ]]; then
            mkdir -p /var/log/journal
            systemctl restart systemd-journald >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    # /dev/shm: nodev,nosuid,noexec (safe on desktop and server)
    if [[ -f /etc/fstab ]] && ! grep -Eq '^\S+\s+/dev/shm\s' /etc/fstab; then
        backup_file /etc/fstab
        if [[ $DRY_RUN -eq 0 ]]; then
            echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
            log "Added hardened /dev/shm entry to fstab"
        else
            info "DRY-RUN: would add /dev/shm entry to fstab"
        fi
    fi
    remount_with /dev/shm nodev,nosuid,noexec || true

    if [[ "$PROFILE" == "server" ]]; then
        # /tmp: noexec via tmp.mount drop-in where tmp.mount is in use, else live remount if separate
        if has_systemd && unit_exists tmp.mount && systemctl is-enabled -q tmp.mount 2>/dev/null; then
            write_file /etc/systemd/system/tmp.mount.d/50-hardening.conf 644 <<'EOF'
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,noexec
EOF
            [[ $DRY_RUN -eq 0 ]] && systemctl daemon-reload
        fi
        remount_with /tmp nosuid,nodev,noexec || info "/tmp is not a separate mount — consider 'systemctl enable tmp.mount' or an fstab entry"
        remount_with /var/tmp nosuid,nodev,noexec || info "/var/tmp is not a separate mount — skipped"

        # Unneeded network services
        local s
        for s in avahi-daemon.socket avahi-daemon.service cups.socket cups.service cups-browsed.service bluetooth.service; do
            svc_mask "$s"
        done

        # USBGuard: allow currently attached devices, block new ones
        if command -v usbguard >/dev/null 2>&1; then
            if [[ ! -s /etc/usbguard/rules.conf ]]; then
                if [[ $DRY_RUN -eq 0 ]]; then
                    mkdir -p /etc/usbguard
                    record_rm /etc/usbguard/rules.conf
                    usbguard generate-policy > /etc/usbguard/rules.conf 2>>"$LOG_FILE" && chmod 600 /etc/usbguard/rules.conf
                    log "USBGuard policy generated from currently attached devices"
                else
                    info "DRY-RUN: would generate USBGuard policy"
                fi
            fi
            svc_enable usbguard
            warn "USBGuard active: new USB devices are blocked until allowed with 'usbguard allow-device <id>'"
        fi
    fi
    return 0
}

#===============================================================================
# 16. Cleanup: insecure legacy packages, residuals, old kernels, docker
#===============================================================================
sec_cleanup() {
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would remove (if installed): rsh-client rsh-redone-client tftp atftpd tftpd-hpa talk telnetd"
    else
        pkg_remove rsh-client rsh-redone-client tftp atftpd tftpd-hpa talk telnetd
    fi

    if [[ "$PKG" == "apt" ]]; then
        local residual
        residual="$(dpkg -l 2>/dev/null | awk '/^rc/ {print $2}')"
        if [[ -n "$residual" && $DRY_RUN -eq 0 ]]; then
            # shellcheck disable=SC2086
            apt-get purge -y $residual >> "$LOG_FILE" 2>&1 && log "Residual package configs purged"
        else
            info "No residual packages (or dry-run)"
        fi
        run "autoremove old kernels + orphaned packages" env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y
    elif [[ "$PKG" == "dnf" ]]; then
        run "autoremove orphaned packages" dnf autoremove -y
    fi

    # Docker: prune stopped containers (INTERACTIVE ONLY — deletes container filesystems)
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        local stopped
        stopped="$(docker ps -aq -f status=exited 2>/dev/null | wc -l)"
        if [[ "$stopped" -gt 0 ]]; then
            if [[ $DRY_RUN -eq 1 || $ASSUME_YES -eq 1 ]]; then
                warn "Docker: $stopped stopped container(s). Skipped (interactive-only) — run 'docker container prune' manually."
            else
                warn "Docker: $stopped stopped container(s). Pruning DELETES their filesystems and any data inside."
                if ask "Prune stopped Docker containers?"; then
                    run "docker container prune" docker container prune -f
                else
                    info "Skipped Docker prune"
                fi
            fi
        fi
    fi
    return 0
}

#===============================================================================
# 17. Optional GRUB password (interactive only)
#===============================================================================
grub_regen() {
    if command -v update-grub >/dev/null 2>&1; then
        update-grub
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        local out=/boot/grub2/grub.cfg
        [[ -f "$out" ]] || out="$(ls /boot/efi/EFI/*/grub.cfg 2>/dev/null | head -1)"
        [[ -n "$out" ]] && grub2-mkconfig -o "$out"
    elif command -v grub-mkconfig >/dev/null 2>&1; then
        grub-mkconfig -o /boot/grub/grub.cfg
    fi
}

sec_grub() {
    if [[ $ASSUME_YES -eq 1 || $DRY_RUN -eq 1 ]]; then
        info "GRUB password is interactive-only — skipped"
        return 0
    fi
    if command -v grub2-setpassword >/dev/null 2>&1; then
        # RHEL/Fedora: handles superuser + unrestricted boot entries correctly (incl. BLS)
        if ask "Set a GRUB password (protects boot parameters; normal boot stays password-free)?"; then
            [[ -f /boot/grub2/user.cfg ]] && backup_file /boot/grub2/user.cfg
            if grub2-setpassword; then
                grub_regen >> "$LOG_FILE" 2>&1 || true
                log "GRUB password set via grub2-setpassword"
            else
                err "grub2-setpassword failed"
            fi
        fi
        return 0
    fi
    local mkpw=""
    for mkpw in grub-mkpasswd-pbkdf2 grub2-mkpasswd-pbkdf2; do
        command -v "$mkpw" >/dev/null 2>&1 && break
        mkpw=""
    done
    [[ -n "$mkpw" ]] || { info "GRUB not found — skipped"; return 0; }
    if ask "Set a GRUB password (protects boot parameters; normal boot stays password-free)?"; then
        local hash
        hash="$("$mkpw" | grep -o 'grub\.pbkdf2\.sha512\..*' || true)"
        if [[ -n "$hash" ]]; then
            if [[ -e /etc/grub.d/40_custom ]]; then backup_file /etc/grub.d/40_custom; else record_rm /etc/grub.d/40_custom; fi
            cat > /etc/grub.d/40_custom <<EOF
#!/bin/sh
exec tail -n +3 \$0
set superusers="root"
password_pbkdf2 root $hash
EOF
            chmod +x /etc/grub.d/40_custom
            if [[ -f /etc/grub.d/10_linux ]] && ! grep -q -- '--unrestricted' /etc/grub.d/10_linux; then
                backup_file /etc/grub.d/10_linux
                sed -i 's/CLASS="--class gnu-linux/CLASS="--unrestricted --class gnu-linux/' /etc/grub.d/10_linux || true
            fi
            grub_regen >> "$LOG_FILE" 2>&1 || true
            log "GRUB password set (normal boot remains unrestricted)"
        else
            err "Failed to generate GRUB hash"
        fi
    fi
    return 0
}

#===============================================================================
# 18. Lynis audit + report analysis
#===============================================================================
STATE_DIR="/var/lib/starhard"

# Lynis test-ID prefix/ID -> StarHard section that addresses it
lynis_section_for() {
    case "$1" in
        KRNL-5820|KRNL-6000|KRNL-5830) echo 2 ;;
        USB-1000|STRG-1840|STRG-1846|NETW-3200|FILE-6430) echo 3 ;;
        AUTH-9228|AUTH-9229|AUTH-9230|AUTH-9262|AUTH-9282|AUTH-9286|AUTH-9328|AUTH-9408|SCHD-7704) echo 4 ;;
        SSH-*) echo 6 ;;
        FIRE-*) echo 7 ;;
        ACCT-*|LOGG-2190) echo 9 ;;
        FINT-*) echo 10 ;;
        MALW-*|TOOL-5002) echo 11 ;;
        PKGS-7390|PKGS-7398|PKGS-7420|DEB-0810|DEB-0880) echo 12 ;;
        BANN-*|FILE-7524) echo 13 ;;
        MACF-*) echo 14 ;;
        FILE-6310|FILE-6336|FILE-6344|LOGG-2138|LOGG-2154) echo 15 ;;
        PKGS-7346|PKGS-7382) echo 16 ;;
        BOOT-*) echo 17 ;;
        *) echo "" ;;
    esac
}

lynis_summary() {
    # lynis_summary <report.dat>
    local rep="$1"
    [[ -r "$rep" ]] || { warn "Lynis report not found: $rep"; return 1; }
    local idx warnings suggestions
    idx="$(grep -m1 '^hardening_index=' "$rep" | cut -d= -f2)"
    warnings="$(grep -c '^warning\[\]=' "$rep")"
    suggestions="$(grep -c '^suggestion\[\]=' "$rep")"

    echo
    echo "---------------- Lynis results ----------------"
    echo "Hardening index: ${idx:-?}/100   Warnings: $warnings   Suggestions: $suggestions"

    # Track index across runs
    if [[ $DRY_RUN -eq 0 && -n "$idx" ]]; then
        mkdir -p "$STATE_DIR"
        local prev=""
        [[ -f "$STATE_DIR/lynis-index" ]] && prev="$(tail -n1 "$STATE_DIR/lynis-index" | cut -d' ' -f2)"
        echo "$TS $idx" >> "$STATE_DIR/lynis-index"
        [[ -n "$prev" ]] && echo "Previous run: $prev  ->  now: $idx  (change: $((idx - prev)))"
    fi

    local line id desc detail sec
    if [[ "$warnings" -gt 0 ]]; then
        echo
        echo "WARNINGS (fix these first):"
        while IFS= read -r line; do
            IFS='|' read -r id desc detail _ <<< "${line#warning[]=}"
            sec="$(lynis_section_for "$id")"
            printf '  %-10s %s' "$id" "$desc"
            [[ -n "$detail" && "$detail" != "-" ]] && printf ' [%s]' "$detail"
            [[ -n "$sec" ]] && printf '  -> StarHard section %s' "$sec"
            echo
        done < <(grep '^warning\[\]=' "$rep")
    fi

    if [[ "$suggestions" -gt 0 ]]; then
        echo
        echo "SUGGESTIONS:"
        local covered=0 manual=0
        while IFS= read -r line; do
            IFS='|' read -r id desc detail _ <<< "${line#suggestion[]=}"
            sec="$(lynis_section_for "$id")"
            printf '  %-10s %s' "$id" "$desc"
            [[ -n "$detail" && "$detail" != "-" ]] && printf ' [%s]' "$detail"
            if [[ -n "$sec" ]]; then
                printf '  -> section %s' "$sec"; covered=$((covered+1))
            else
                printf '  -> manual'; manual=$((manual+1))
            fi
            echo
        done < <(grep '^suggestion\[\]=' "$rep")
        echo
        echo "  $covered suggestion(s) map to a StarHard section (re-run with --sections N if still flagged),"
        echo "  $manual need a manual decision. Details on any test: lynis show details <TEST-ID>"
    fi
    echo "Full report: $rep"
    echo "-----------------------------------------------"
    return 0
}

ensure_lynis() {
    command -v lynis >/dev/null 2>&1 && return 0
    info "Lynis not installed — installing"
    if [[ "$PKG" =~ ^(dnf|yum)$ && "$OS_ID" != "fedora" ]] && is_family rhel; then
        pkg_installed epel-release || pkg_install epel-release
    fi
    pkg_install lynis
    command -v lynis >/dev/null 2>&1
}

run_lynis() {
    # run_lynis <tag>  -> writes /var/log/starhard/lynis-<tag>-$TS.dat, prints summary
    local tag="$1"
    local rep="$LOG_DIR/lynis-report-$tag-$TS.dat" lg="$LOG_DIR/lynis-$tag-$TS.log"
    mkdir -p "$LOG_DIR"
    info "Running Lynis audit ($tag) — usually 1-3 minutes"
    lynis audit system --quick --quiet --no-colors --report-file "$rep" --log-file "$lg" >/dev/null 2>&1 \
        || warn "Lynis exited non-zero (normal when warnings are found)"
    lynis_summary "$rep"
}

sec_lynis() {
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would run 'lynis audit system' and summarise the report"
        return 0
    fi
    ensure_lynis || { warn "Lynis unavailable — skipping audit"; return 0; }
    run_lynis post
}

#===============================================================================
# Audit mode dispatch (all functions are defined by this point)
#===============================================================================
if [[ $AUDIT -eq 1 ]]; then
    do_audit; rc=$?
    if should_run 18 && command -v lynis >/dev/null 2>&1; then
        info "Lynis report will be written under $LOG_DIR (no system changes)"
        run_lynis audit
    fi
    exit $rc
fi

#===============================================================================
# Run sections
#===============================================================================
section 1  "packages"                          sec_packages
section 2  "sysctl hardening"                  sec_sysctl
section 3  "kernel module blacklist"           sec_modules
section 4  "authentication policy"             sec_auth
section 5  "disable core dumps"                sec_coredump
section 6  "SSH hardening"                     sec_ssh
section 7  "firewall"                          sec_firewall
section 8  "intrusion prevention ($IDS)"      sec_ips
section 9  "auditd + process accounting"       sec_auditd
section 10 "AIDE integrity baseline + timer"   sec_aide
section 11 "malware/rootkit scanning"          sec_scanners
section 12 "automatic security updates"        sec_autoupdate
section 13 "banners, permissions, sudo"        sec_perms
section 14 "mandatory access control"          sec_mac
section 15 "services, mounts, journald"        sec_services
section 16 "cleanup"                           sec_cleanup
section 17 "GRUB password"                     sec_grub
section 18 "Lynis audit + report analysis"     sec_lynis

#===============================================================================
# Finish rollback script
#===============================================================================
if [[ $DRY_RUN -eq 0 ]]; then
    {
        echo
        if [[ ${#NEW_PKGS[@]} -gt 0 ]]; then
            echo "# Packages installed by this run (not removed automatically; uncomment to remove):"
            echo "# ${NEW_PKGS[*]}"
        fi
        echo "systemctl daemon-reload 2>/dev/null || true"
        echo "sysctl -e --system >/dev/null 2>&1 || true"
        echo "echo 'Rollback complete — reboot now. Audit rules in immutable mode reset on reboot.'"
    } >> "$ROLLBACK"
fi

#===============================================================================
# Summary
#===============================================================================
echo
echo "==============================================================="
log "Hardening complete ($([[ $DRY_RUN -eq 1 ]] && echo 'DRY RUN — nothing changed' || echo 'applied'))"
echo
echo "Sections:"
echo "  1  Security packages ($PKG) — Lynis, ClamAV, unhide, AIDE, auditd"
echo "  2  Kernel/sysctl hardening (incl. IPv6, io_uring, userfaultfd)"
echo "  3  Kernel module blacklist (loaded modules unloaded)"
echo "  4  Password policy, yescrypt/SHA512, umask 027, pwquality, faillock, cron lockdown"
echo "  5  Core dumps disabled"
echo "  6  SSH hardening (validated; Banner; profile-aware forwarding rules)"
echo "  7  Firewall (ufw/firewalld; SSH preserved when run over SSH)"
echo "  8  Intrusion prevention: $IDS$( [[ "$IDS" == "crowdsec" ]] && echo ' + firewall bouncer (fail2ban disabled)')"
echo "  9  auditd rules + process accounting"
echo "  10 AIDE baseline + daily check timer"
echo "  11 Weekly starhard-scan: ClamAV, unhide, package integrity, Lynis"
echo "  12 Automatic security updates"
echo "  13 Banners, permissions (tighten-only), sudo use_pty/logfile"
echo "  14 AppArmor enforce / SELinux status"
echo "  15 ctrl-alt-del masked, persistent journald, /dev/shm noexec$( [[ "$PROFILE" == "server" ]] && echo ', /tmp noexec, avahi/cups/bt masked, usbguard')"
echo "  16 Cleanup: legacy packages, residuals, old kernels, docker (opt-in)"
echo "  17 GRUB password (interactive)"
echo "  18 Lynis audit run, warnings/suggestions mapped to sections, index tracked in $STATE_DIR/lynis-index"
echo
echo "Backups + rollback script: $BACKUP_DIR"
echo "Log: $LOG_FILE"
echo
echo "Next steps:"
echo "  1. Reboot"
echo "  2. Verify:  sudo $0 --audit --profile $PROFILE --ids $IDS"
echo "  3. Scan:    sudo /usr/local/sbin/starhard-scan   (also runs weekly)"
echo "  4. Lynis:   see section 18 output above; 'lynis show details <TEST-ID>' for any item"
echo "  5. Undo:    sudo bash $ROLLBACK  (then reboot)"
echo "==============================================================="
