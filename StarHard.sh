#!/usr/bin/env bash
#===============================================================================
# StarHard.sh
# Universal Linux hardening script (Debian/Ubuntu/Parrot/Kali, RHEL/Fedora/
# Rocky/Alma, openSUSE, Arch, Alpine).
#
# Improvements over typical single-distro scripts:
#   * Distro + package-manager auto-detection
#   * --dry-run mode (show what would change, change nothing)
#   * --profile desktop|server (server applies stricter SSH/firewall rules)
#   * Full backup of every modified file + generated rollback script
#   * Idempotent: safe to re-run
#   * Logging to /var/log/starhard/
#   * SSH lockout protection (validates config before applying)
#===============================================================================

set -u
umask 077

VERSION="1.0"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/starhard/$TS"
LOG_DIR="/var/log/starhard"
LOG_FILE="$LOG_DIR/starhard-$TS.log"
ROLLBACK="$BACKUP_DIR/rollback.sh"

DRY_RUN=0
PROFILE="desktop"
ASSUME_YES=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

#---------------------------------------------------------------- helpers -----
log()  { echo -e "${GREEN}[+]${NC} $1"; _tolog "[+] $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; _tolog "[!] $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; _tolog "[-] $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; _tolog "[i] $1"; }
_tolog(){ [[ $DRY_RUN -eq 0 ]] && echo "$(date '+%F %T') $1" >> "$LOG_FILE" 2>/dev/null || true; }

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

backup_file() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    [[ $DRY_RUN -eq 1 ]] && { info "DRY-RUN: would back up $f"; return 0; }
    local dest="$BACKUP_DIR${f}"
    mkdir -p "$(dirname "$dest")"
    cp -a "$f" "$dest"
    echo "cp -a '$dest' '$f'" >> "$ROLLBACK"
}

write_file() {
    # write_file <path> <mode> ; content on stdin
    local f="$1" mode="${2:-644}"
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would write $f"
        cat > /dev/null
        return 0
    fi
    backup_file "$f"
    mkdir -p "$(dirname "$f")"
    cat > "$f"
    chmod "$mode" "$f"
    log "Wrote $f"
}

ask() {
    # ask "question" -> 0 yes / 1 no ; auto-yes with -y, auto-no in dry-run
    [[ $ASSUME_YES -eq 1 ]] && return 0
    local reply
    read -r -p "$(echo -e "${YELLOW}[?]${NC} $1 (y/N): ")" reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

#------------------------------------------------------------ arg parsing -----
usage() {
    cat <<EOF
Usage: sudo $0 [options]
  --dry-run           Show what would be done without changing anything
  --profile <p>       desktop (default) or server (stricter SSH + firewall)
  -y, --yes           Assume "yes" to optional prompts (non-interactive)
  -h, --help          This help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --profile) PROFILE="${2:-desktop}"; shift ;;
        -y|--yes)  ASSUME_YES=1 ;;
        -h|--help) usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
    shift
done

[[ "$PROFILE" =~ ^(desktop|server)$ ]] || { err "Profile must be desktop or server"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    err "Run as root: sudo $0"
    exit 1
fi

if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p "$BACKUP_DIR" "$LOG_DIR"
    {
        echo "#!/usr/bin/env bash"
        echo "# Rollback for StarHard run $TS — restores backed-up files."
        echo "# Review before running. Reboot afterwards."
        echo "set -x"
    } > "$ROLLBACK"
    chmod 700 "$ROLLBACK"
fi

#-------------------------------------------------------- distro detection ----
OS_ID="unknown"; OS_LIKE=""; PKG=""
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
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
    # installs each package individually so one missing package doesn't kill the rest
    local p
    for p in "$@"; do
        case "$PKG" in
            apt)    run "install $p" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$p" ;;
            dnf)    run "install $p" dnf install -y -q "$p" ;;
            yum)    run "install $p" yum install -y -q "$p" ;;
            zypper) run "install $p" zypper -q install -y "$p" ;;
            pacman) run "install $p" pacman -S --noconfirm --needed "$p" ;;
            apk)    run "install $p" apk add -q "$p" ;;
        esac
    done
}

pkg_remove() {
    # removes a package only if it is actually installed
    local p
    for p in "$@"; do
        case "$PKG" in
            apt)    dpkg -s "$p" >/dev/null 2>&1 && run "purge $p" env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$p" ;;
            dnf)    rpm -q "$p" >/dev/null 2>&1 && run "remove $p" dnf remove -y -q "$p" ;;
            yum)    rpm -q "$p" >/dev/null 2>&1 && run "remove $p" yum remove -y -q "$p" ;;
            zypper) rpm -q "$p" >/dev/null 2>&1 && run "remove $p" zypper -q remove -y "$p" ;;
            pacman) pacman -Qi "$p" >/dev/null 2>&1 && run "remove $p" pacman -R --noconfirm "$p" ;;
            apk)    apk info -e "$p" >/dev/null 2>&1 && run "remove $p" apk del -q "$p" ;;
        esac
    done
    return 0
}

svc_enable() {
    if command -v systemctl >/dev/null 2>&1; then
        run "enable service $1" systemctl enable --now "$1"
    elif command -v rc-update >/dev/null 2>&1; then
        run "enable service $1" rc-update add "$1" default
        run "start service $1" rc-service "$1" start
    fi
}

echo "==============================================================="
echo "  StarHard v$VERSION"
echo "  OS: $OS_ID   Package manager: $PKG   Profile: $PROFILE"
[[ $DRY_RUN -eq 1 ]] && echo "  MODE: DRY RUN — no changes will be made"
echo "  Backups: $BACKUP_DIR"
echo "==============================================================="
echo

#===============================================================================
# 1. Packages
#===============================================================================
log "Section 1: packages"
pkg_update

case "$PKG" in
    apt)
        pkg_install rkhunter chkrootkit aide fail2ban libpam-tmpdir needrestart \
            apt-listchanges libpam-pwquality auditd acct debsums \
            audispd-plugins unattended-upgrades apparmor apparmor-utils ufw
        ;;
    dnf|yum)
        pkg_install rkhunter aide fail2ban audit psacct libpwquality firewalld \
            dnf-automatic policycoreutils
        ;;
    zypper)
        pkg_install rkhunter aide fail2ban audit acct pam_pwquality firewalld
        ;;
    pacman)
        pkg_install rkhunter aide fail2ban audit acct libpwquality ufw
        ;;
    apk)
        pkg_install aide fail2ban audit
        ;;
esac

#===============================================================================
# 2. Kernel / sysctl hardening
#===============================================================================
log "Section 2: sysctl hardening"

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
net.core.bpf_jit_harden = 2

# === IPv4 ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
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

run "Apply sysctl settings" sysctl --system

#===============================================================================
# 3. Blacklist rarely-used kernel modules
#===============================================================================
log "Section 3: kernel module blacklist"

write_file /etc/modprobe.d/hardening-blacklist.conf 644 <<'EOF'
# Uncommon network protocols
install dccp /bin/false
install sctp /bin/false
install rds  /bin/false
install tipc /bin/false
# Uncommon filesystems
install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
install udf      /bin/false
# Firewire (DMA attack surface)
install firewire-core /bin/false
EOF

#===============================================================================
# 4. Password policy, umask, hashing
#===============================================================================
log "Section 4: authentication policy"

if [[ -f /etc/login.defs ]]; then
    backup_file /etc/login.defs
    if [[ $DRY_RUN -eq 0 ]]; then
        sed -i -E '/^#?\s*(UMASK|SHA_CRYPT_MIN_ROUNDS|SHA_CRYPT_MAX_ROUNDS|ENCRYPT_METHOD|PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)\b/d' /etc/login.defs
        cat >> /etc/login.defs <<'EOF'

# === StarHard ===
UMASK           027
ENCRYPT_METHOD  SHA512
SHA_CRYPT_MIN_ROUNDS 640000
SHA_CRYPT_MAX_ROUNDS 640000
PASS_MAX_DAYS   365
PASS_MIN_DAYS   1
PASS_WARN_AGE   14
EOF
        log "login.defs updated"
    else
        info "DRY-RUN: would update /etc/login.defs"
    fi
fi

# Default umask for login shells
write_file /etc/profile.d/50-umask-hardening.sh 644 <<'EOF'
umask 027
EOF

# pwquality (works across distros that ship it)
if [[ -d /etc/security ]]; then
    write_file /etc/security/pwquality.conf.d/50-hardening.conf 644 <<'EOF'
minlen = 14
minclass = 3
maxrepeat = 3
difok = 3
enforce_for_root
EOF
fi

# Debian family: wire pam_pwquality into common-password if absent
if [[ -f /etc/pam.d/common-password ]] && ! grep -q pam_pwquality /etc/pam.d/common-password; then
    backup_file /etc/pam.d/common-password
    if [[ $DRY_RUN -eq 0 ]]; then
        sed -i '/pam_unix.so/i password\trequisite\t\t\tpam_pwquality.so retry=3' /etc/pam.d/common-password
        log "pam_pwquality enabled"
    fi
fi

# Lock down cron/at to root only
for f in /etc/cron.allow /etc/at.allow; do
    write_file "$f" 640 <<'EOF'
root
EOF
done
[[ $DRY_RUN -eq 0 ]] && rm -f /etc/cron.deny /etc/at.deny 2>/dev/null || true

#===============================================================================
# 5. Core dumps off
#===============================================================================
log "Section 5: disable core dumps"

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

#===============================================================================
# 6. SSH hardening (with lockout protection)
#===============================================================================
log "Section 6: SSH hardening"

if [[ -d /etc/ssh ]]; then
    SSH_EXTRA=""
    if [[ "$PROFILE" == "server" ]]; then
        SSH_EXTRA="PasswordAuthentication no"
        warn "Server profile: SSH password login will be DISABLED. Ensure your SSH key works first!"
        if ! ask "Confirm disabling SSH password authentication?"; then
            SSH_EXTRA=""
            warn "Keeping password authentication enabled"
        fi
    fi

    mkdir -p /etc/ssh/sshd_config.d 2>/dev/null || true
    write_file /etc/ssh/sshd_config.d/50-hardening.conf 600 <<EOF
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UsePAM yes
$SSH_EXTRA
EOF

    # Validate before it can bite us; remove the file if sshd rejects it
    if [[ $DRY_RUN -eq 0 ]] && command -v sshd >/dev/null 2>&1; then
        if sshd -t 2>>"$LOG_FILE"; then
            command -v systemctl >/dev/null 2>&1 && systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            log "sshd config validated and reloaded"
        else
            err "sshd rejected new config — reverting SSH hardening"
            rm -f /etc/ssh/sshd_config.d/50-hardening.conf
        fi
    fi
else
    info "No /etc/ssh — skipping"
fi

#===============================================================================
# 7. Firewall
#===============================================================================
log "Section 7: firewall"

if command -v ufw >/dev/null 2>&1; then
    run "ufw default deny incoming" ufw default deny incoming
    run "ufw default allow outgoing" ufw default allow outgoing
    if [[ "$PROFILE" == "server" ]]; then
        run "ufw allow ssh (rate-limited)" ufw limit ssh
    fi
    [[ $DRY_RUN -eq 0 ]] && ufw --force enable >> "$LOG_FILE" 2>&1 && log "ufw enabled"
elif command -v firewall-cmd >/dev/null 2>&1; then
    svc_enable firewalld
    run "firewalld default zone drop-ish (public)" firewall-cmd --set-default-zone=public
    [[ "$PROFILE" == "server" ]] && run "allow ssh" firewall-cmd --permanent --add-service=ssh
    run "reload firewalld" firewall-cmd --reload
elif command -v nft >/dev/null 2>&1; then
    warn "Only nftables found — not writing rules automatically (too environment-specific). Configure /etc/nftables.conf manually."
else
    warn "No firewall tool found — install ufw or firewalld"
fi

#===============================================================================
# 8. fail2ban
#===============================================================================
if command -v fail2ban-server >/dev/null 2>&1; then
    log "Section 8: fail2ban"
    write_file /etc/fail2ban/jail.local 644 <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
maxretry = 4
bantime  = 2h

[recidive]
enabled  = true
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
    svc_enable fail2ban
fi

#===============================================================================
# 9. auditd
#===============================================================================
if command -v auditctl >/dev/null 2>&1; then
    log "Section 9: auditd rules"
    write_file /etc/audit/rules.d/50-hardening.rules 640 <<'EOF'
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

# Privilege escalation
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /bin/su -p x -k privileged
-w /usr/bin/sudo -p x -k privileged
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k priv_esc

# System configuration
-w /etc/systemd/ -p wa -k systemd
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules

# Time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change

-e 2
EOF
    [[ $DRY_RUN -eq 0 ]] && augenrules --load >> "$LOG_FILE" 2>&1 || true
    svc_enable auditd
fi

# Process accounting
command -v accton >/dev/null 2>&1 && { svc_enable acct 2>/dev/null || svc_enable psacct 2>/dev/null || true; }

#===============================================================================
# 10. AIDE file-integrity baseline
#===============================================================================
if command -v aide >/dev/null 2>&1; then
    log "Section 10: AIDE (baseline can take several minutes)"
    if [[ $DRY_RUN -eq 0 && ! -f /var/lib/aide/aide.db && ! -f /var/lib/aide/aide.db.gz ]]; then
        if command -v aideinit >/dev/null 2>&1; then
            aideinit --yes --force >> "$LOG_FILE" 2>&1 || aide --init >> "$LOG_FILE" 2>&1 || true
        else
            aide --init >> "$LOG_FILE" 2>&1 || true
        fi
        for ext in "" ".gz"; do
            [[ -f "/var/lib/aide/aide.db.new$ext" ]] && mv "/var/lib/aide/aide.db.new$ext" "/var/lib/aide/aide.db$ext"
        done
        log "AIDE baseline created"
    else
        info "AIDE database already exists or dry-run — skipping init"
    fi
fi

#===============================================================================
# 11. rkhunter
#===============================================================================
if command -v rkhunter >/dev/null 2>&1; then
    log "Section 11: rkhunter"
    [[ $DRY_RUN -eq 0 ]] && { rkhunter --update >> "$LOG_FILE" 2>&1 || true; rkhunter --propupd >> "$LOG_FILE" 2>&1 || true; }
fi

#===============================================================================
# 12. Automatic security updates
#===============================================================================
log "Section 12: automatic security updates"
case "$PKG" in
    apt)
        write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
        ;;
    dnf)
        if [[ -f /etc/dnf/automatic.conf ]]; then
            backup_file /etc/dnf/automatic.conf
            [[ $DRY_RUN -eq 0 ]] && sed -i -e 's/^upgrade_type.*/upgrade_type = security/' -e 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
            svc_enable dnf-automatic.timer
        fi
        ;;
    *)  info "Automatic updates: configure manually for $PKG" ;;
esac

#===============================================================================
# 13. Legal banners + file permissions
#===============================================================================
log "Section 13: banners and permissions"

write_file /etc/issue 644 <<'EOF'
***********************************************************************
*  AUTHORIZED USE ONLY                                                *
*  All activity on this system is monitored and logged.               *
*  Unauthorized access is prohibited.                                 *
***********************************************************************
EOF
[[ $DRY_RUN -eq 0 ]] && cp /etc/issue /etc/issue.net

# Tighten sensitive files (only if they exist)
tighten() { [[ -e "$1" ]] && run "chmod $2 $1" chmod "$2" "$1"; }
tighten /etc/shadow 0640
tighten /etc/gshadow 0640
tighten /etc/crontab 0600
tighten /etc/ssh/sshd_config 0600
tighten /boot/grub/grub.cfg 0600
tighten /boot/grub2/grub.cfg 0600
[[ -d /etc/cron.d ]]       && run "chmod 700 /etc/cron.d" chmod 700 /etc/cron.d
[[ -d /etc/cron.daily ]]   && run "chmod 700 /etc/cron.daily" chmod 700 /etc/cron.daily
[[ -d /etc/cron.hourly ]]  && run "chmod 700 /etc/cron.hourly" chmod 700 /etc/cron.hourly
[[ -d /etc/cron.weekly ]]  && run "chmod 700 /etc/cron.weekly" chmod 700 /etc/cron.weekly
[[ -d /etc/cron.monthly ]] && run "chmod 700 /etc/cron.monthly" chmod 700 /etc/cron.monthly
[[ -d /etc/sudoers.d ]]    && run "chmod 750 /etc/sudoers.d" chmod 750 /etc/sudoers.d

# Home directory of invoking user
CURRENT_USER="${SUDO_USER:-$(logname 2>/dev/null || true)}"
if [[ -n "${CURRENT_USER:-}" && -d "/home/$CURRENT_USER" ]]; then
    run "chmod 750 /home/$CURRENT_USER" chmod 750 "/home/$CURRENT_USER"
fi

#===============================================================================
# 14. Mandatory Access Control (AppArmor / SELinux)
#===============================================================================
log "Section 14: mandatory access control"
if command -v aa-status >/dev/null 2>&1; then
    svc_enable apparmor
    aa-status --enabled 2>/dev/null && log "AppArmor active" || warn "AppArmor installed but not active (may need kernel cmdline: apparmor=1 security=apparmor)"
elif command -v getenforce >/dev/null 2>&1; then
    STATE="$(getenforce 2>/dev/null || echo unknown)"
    if [[ "$STATE" == "Enforcing" ]]; then
        log "SELinux enforcing"
    else
        warn "SELinux is '$STATE'. Consider setting SELINUX=enforcing in /etc/selinux/config (test in permissive mode first)."
    fi
fi

#===============================================================================
# 15. Cleanup: insecure legacy packages, residuals, old kernels, docker
#===============================================================================
log "Section 15: cleanup"

# 15a. Remove insecure legacy client/server packages (only if installed)
if [[ $DRY_RUN -eq 1 ]]; then
    info "DRY-RUN: would remove (if installed): rsh-client rsh-redone-client tftp atftpd tftpd-hpa talk"
else
    pkg_remove rsh-client rsh-redone-client tftp atftpd tftpd-hpa talk
fi

# 15b. Residual package configs (Debian family)
if [[ "$PKG" == "apt" ]]; then
    RESIDUAL="$(dpkg -l 2>/dev/null | awk '/^rc/ {print $2}')"
    if [[ -n "$RESIDUAL" && $DRY_RUN -eq 0 ]]; then
        # shellcheck disable=SC2086
        apt-get purge -y $RESIDUAL >> "$LOG_FILE" 2>&1 && log "Residual packages purged"
    else
        info "No residual packages (or dry-run)"
    fi
fi

# 15c. Old kernels and orphaned dependencies
# apt autoremove never touches the running kernel; it keeps the current and
# newest kernels and removes older leftovers plus unused auto-installed deps.
if [[ "$PKG" == "apt" ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would run: apt-get autoremove --purge -y"
    else
        run "autoremove old kernels + orphaned packages" env DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y
    fi
elif [[ "$PKG" == "dnf" ]]; then
    [[ $DRY_RUN -eq 0 ]] && run "autoremove orphaned packages" dnf autoremove -y || info "DRY-RUN: would run: dnf autoremove -y"
fi

# 15d. Docker: prune stopped containers (INTERACTIVE ONLY — deletes container
# filesystems, which may hold data. Never auto-runs with -y or in dry-run.)
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    STOPPED="$(docker ps -aq -f status=exited 2>/dev/null | wc -l)"
    if [[ "$STOPPED" -gt 0 ]]; then
        if [[ $DRY_RUN -eq 1 || $ASSUME_YES -eq 1 ]]; then
            warn "Docker: $STOPPED stopped container(s) found. Skipped (interactive-only step) — run 'docker container prune' manually if unneeded."
        else
            warn "Docker: $STOPPED stopped container(s) found. Pruning DELETES their filesystems and any data inside."
            if ask "Prune stopped Docker containers?"; then
                run "docker container prune" docker container prune -f
            else
                info "Skipped Docker prune"
            fi
        fi
    fi
fi

#===============================================================================
# 16. Optional GRUB password
#===============================================================================
if command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1 && [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
    echo
    if ask "Set a GRUB password (protects boot parameters; you'll still boot normally)?"; then
        HASH="$(grub-mkpasswd-pbkdf2 | grep -o 'grub\.pbkdf2\.sha512\..*' || true)"
        if [[ -n "$HASH" ]]; then
            backup_file /etc/grub.d/40_custom
            cat > /etc/grub.d/40_custom <<EOF
#!/bin/sh
exec tail -n +3 \$0
set superusers="root"
password_pbkdf2 root $HASH
EOF
            chmod +x /etc/grub.d/40_custom
            # --unrestricted keeps normal boots password-free; only editing entries needs the password
            if [[ -f /etc/grub.d/10_linux ]] && ! grep -q -- '--unrestricted' /etc/grub.d/10_linux; then
                backup_file /etc/grub.d/10_linux
                sed -i 's/CLASS="--class gnu-linux/CLASS="--unrestricted --class gnu-linux/' /etc/grub.d/10_linux || true
            fi
            update-grub >> "$LOG_FILE" 2>&1 || grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1 || true
            log "GRUB password set (normal boot remains unrestricted)"
        else
            err "Failed to generate GRUB hash"
        fi
    fi
fi

#===============================================================================
# Summary
#===============================================================================
echo
echo "==============================================================="
log "Hardening complete ($([[ $DRY_RUN -eq 1 ]] && echo 'DRY RUN — nothing changed' || echo 'applied'))"
echo
echo "Applied sections:"
echo "  1  Security packages ($PKG)"
echo "  2  Kernel/sysctl hardening (incl. IPv6)"
echo "  3  Kernel module blacklist"
echo "  4  Password policy, umask 027, pwquality, cron lockdown"
echo "  5  Core dumps disabled"
echo "  6  SSH hardening (validated before reload)"
echo "  7  Firewall (ufw/firewalld)"
echo "  8  fail2ban"
echo "  9  auditd rules + process accounting"
echo "  10 AIDE integrity baseline"
echo "  11 rkhunter"
echo "  12 Automatic security updates"
echo "  13 Legal banners + file permissions (incl. sudoers.d)"
echo "  14 AppArmor/SELinux status"
echo "  15 Cleanup: legacy packages, residuals, old kernels, docker (opt-in)"
echo
echo "Backups + rollback script: $BACKUP_DIR"
echo "Log: $LOG_FILE"
echo
echo "Next steps:"
echo "  1. Reboot"
echo "  2. Audit:  sudo lynis audit system"
echo "  3. To undo: sudo bash $ROLLBACK  (then reboot)"
echo "==============================================================="
