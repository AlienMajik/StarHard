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
#   * Raspberry Pi detection (Pi 5 and earlier): no-GRUB warning + encryption
#     advice, auditd watches on config.txt/cmdline.txt, Raspberry Pi
#     Foundation origin for unattended-upgrades (kernel/firmware/EEPROM),
#     EEPROM bootloader update check, dtoverlay radio disable
#     (--pi-disable-wifi / --pi-disable-bt, bt automatic on server profile),
#     wifi never disabled when the box is reached over wlan, ClamAV scan
#     skipped when free RAM is short (section 19)
#   * Service awareness: Tailscale (tailscale0 trusted, UDP 41641 allowed,
#     rp_filter loose, auto-updates from Tailscale's repo) and Pi-hole (DNS,
#     web UI and DHCP allowed from LAN subnets + tailnet); other listening
#     ports that the firewall would block are listed before enabling it.
#     Pi-hole LAN rules are only added when Pi-hole's own query log shows LAN
#     clients (override: --pihole-lan / --no-lan-dns); stale ufw allow rules
#     for ports with no listener are flagged; existing rules are never removed.
#     accept_ra is left alone when the box has a SLAAC IPv6 address.
#   * starhard-status: /etc/starhard/ignore-units lists failed units to
#     ignore (e.g. unconfigured pentest daemons on Parrot/Kali); the weekly
#     scan holds off idle-suspend with systemd-inhibit so laptops finish it
#   * Section 20 USB: USBGuard on every profile. Desktop = audit mode (log all
#     attaches, block nothing) + two hard rules: new keyboards/HID while the
#     screen is locked and any USB network adapter are blocked. Server = block
#     all unknown devices. starhard-usb-allow <id> authorises a device in one
#     step; starhard-status lists attached devices, flags HID/network devices
#     not in the policy, and shows the week's attach/block events. Weekly
#     ClamAV scan now includes anything mounted under /media or /mnt.
#   * ClamAV exclusions: /etc/starhard/clamav-exclude (one regex per line).
#     Pentest distros (Parrot/Kali) get defaults for directories that contain
#     exploit code or scanner payloads by design — unicornscan, Metasploit,
#     exploitdb, Suricata/Snort rules, wordlists — so the weekly scan stops
#     flagging the tools themselves. Status shows how many paths were skipped.
#   * apt-listbugs aware: serious bugs for a package are shown as info, then
#     the install proceeds (Parrot's listbugs otherwise aborts non-interactive
#     installs). USBGuard rules live in rules.d/ so a buggy postinst that
#     regenerates rules.conf can't erase them; daemon IPC restricted to root.
#   * Keylogger indicators: auditd watches /etc/ld.so.preload and logs
#     user-initiated opens of /dev/input/ (keys preload, input_dev);
#     starhard-status lists processes holding input devices, flags any
#     running from /tmp, /home, /dev/shm or a deleted binary, checks
#     ld.so.preload / LD_PRELOAD and warns when an X11 session is active
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
IS_PI=0; PI_MODEL=""; PI_BOOT=""
PI_DISABLE_WIFI=0; PI_DISABLE_BT=0
PIHOLE_LAN=""   # "" = auto-detect from query log, 1 = force LAN rules, 0 = never
SSH_ACTIVE=0
[[ -n "${SSH_CONNECTION:-}" ]] && SSH_ACTIVE=1
HAS_TAILSCALE=0; HAS_PIHOLE=0
command -v tailscale >/dev/null 2>&1 && HAS_TAILSCALE=1
{ command -v pihole >/dev/null 2>&1 || command -v pihole-FTL >/dev/null 2>&1 || [[ -d /etc/pihole ]]; } && HAS_PIHOLE=1
HAS_SLAAC=0
ip -6 addr show scope global 2>/dev/null | grep -q dynamic && HAS_SLAAC=1

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
        [[ -z "$SECTIONS" ]] && info "Section $n ($name) skipped by --exclude"
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
  --pi-disable-wifi     Raspberry Pi: disable the on-board Wi-Fi radio (dtoverlay=disable-wifi)
  --pi-disable-bt       Raspberry Pi: disable the on-board Bluetooth radio (automatic on server profile)
  --pihole-lan          Pi-hole: always open DNS/web to LAN subnets
  --no-lan-dns          Pi-hole: never open DNS/web to LAN subnets (e.g. Tailscale-only Pi-hole)
                        (default: decided from Pi-hole's query log — LAN rules only if LAN clients query it)
  -y, --yes             Assume "yes" to optional prompts (non-interactive)
  -h, --help            This help

Sections:
   1 packages            7 firewall             13 banners/perms/sudo
   2 sysctl              8 IPS (crowdsec/fail2ban) 14 AppArmor/SELinux
   3 kernel modules      9 auditd + acct        15 services/mounts/journald
   4 auth policy        10 AIDE + timer         16 cleanup
   5 core dumps         11 malware/rootkit scan 17 GRUB password (interactive)
   6 SSH                12 automatic updates    18 Lynis audit + report analysis
                                               19 Raspberry Pi (auto-detected)
                                               20 USB device control (USBGuard)
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
        --pi-disable-wifi) PI_DISABLE_WIFI=1 ;;
        --pi-disable-bt)   PI_DISABLE_BT=1 ;;
        --pihole-lan)      PIHOLE_LAN=1 ;;
        --no-lan-dns)      PIHOLE_LAN=0 ;;
        -y|--yes)   ASSUME_YES=1 ;;
        -h|--help)  usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
    shift
done

[[ "$PROFILE" =~ ^(desktop|server)$ ]] || { err "Profile must be desktop or server"; exit 1; }
if [[ -z "$IDS" ]]; then
    # Prefer whatever is already installed so re-runs and --audit match the box; else profile default.
    if command -v cscli >/dev/null 2>&1; then IDS="crowdsec"
    elif command -v fail2ban-server >/dev/null 2>&1 && [[ "$PROFILE" != "server" ]]; then IDS="fail2ban"
    elif [[ "$PROFILE" == "server" ]]; then IDS="crowdsec"
    else IDS="fail2ban"
    fi
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

# Raspberry Pi detection
if [[ -r /proc/device-tree/model ]]; then
    PI_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)"
    [[ "$PI_MODEL" == *"Raspberry Pi"* ]] && IS_PI=1
fi
if [[ $IS_PI -eq 1 ]]; then
    if [[ -f /boot/firmware/config.txt ]]; then PI_BOOT=/boot/firmware
    elif [[ -f /boot/config.txt ]]; then PI_BOOT=/boot
    fi
    [[ "$PROFILE" == "server" ]] && PI_DISABLE_BT=1
fi

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
            apt)
                if command -v apt-listbugs >/dev/null 2>&1 && [[ $DRY_RUN -eq 0 ]]; then
                    local bugs
                    bugs="$(APT_LISTBUGS_FRONTEND=none apt-listbugs -s serious list "$p" 2>/dev/null | grep -E '^ *b[0-9]+ - #' | sed 's/^ *//' | head -3)"
                    [[ -n "$bugs" ]] && info "apt-listbugs: $p has open serious bug(s) — installing anyway:" && echo "$bugs" | sed 's/^/      /'
                fi
                # A previously aborted install may have left a -30000 pin from apt-listbugs, which makes apt
                # report "no installation candidate". Lift it for this package before trying.
                if [[ $DRY_RUN -eq 0 && -f /etc/apt/preferences.d/apt-listbugs ]] && grep -qx "Package: $p" /etc/apt/preferences.d/apt-listbugs; then
                    backup_file /etc/apt/preferences.d/apt-listbugs
                    # drop the stanza (Explanation..Pin-Priority block) that names this package
                    awk -v pkg="$p" 'BEGIN{RS="";ORS="\n\n"} $0 !~ ("\nPackage: " pkg "\n")' /etc/apt/preferences.d/apt-listbugs > /tmp/.sh-listbugs.$$ \
                        && cat /tmp/.sh-listbugs.$$ > /etc/apt/preferences.d/apt-listbugs; rm -f /tmp/.sh-listbugs.$$
                    info "apt-listbugs had pinned $p as uninstallable (left over from an aborted install) — pin removed"
                fi
                run "install $p" env DEBIAN_FRONTEND=noninteractive APT_LISTBUGS_FRONTEND=none apt-get install -y -qq "$p" ;;
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
    if [[ $HAS_TAILSCALE -eq 1 ]] && command -v ufw >/dev/null 2>&1; then
        chk 7 "tailscale0 allowed through ufw"        bash -c 'ufw status 2>/dev/null | grep -q "on tailscale0"'
    fi
    if [[ $HAS_PIHOLE -eq 1 ]] && command -v ufw >/dev/null 2>&1; then
        if [[ "$PIHOLE_LAN" == "1" ]] || { [[ "$PIHOLE_LAN" != "0" ]] && pihole_has_lan_clients; }; then
            chk 7 "Pi-hole DNS (53) allowed from LAN"  bash -c 'ufw status 2>/dev/null | grep -Eq "^53(/(tcp|udp))? "'
        elif [[ $HAS_TAILSCALE -eq 1 ]]; then
            chk 7 "Pi-hole reachable over tailnet (100.64.0.0/10 or tailscale0 allowed)" bash -c 'ufw status 2>/dev/null | grep -Eq "100\.64\.0\.0/10|on tailscale0"'
            chk 7 "Pi-hole DNS NOT exposed to LAN (tailnet-only setup)" bash -c '! ufw status 2>/dev/null | grep -Eq "^53(/(tcp|udp))? .*(Anywhere|192\.168|10\.|172\.)"'
        fi
    fi
    if [[ $HAS_TAILSCALE -eq 1 ]]; then
        chk 2 "rp_filter loose (2) for Tailscale"     sysctl_is net.ipv4.conf.all.rp_filter 2
    fi
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
    chk 10 "AIDE database exists"                     bash -c '[[ -f /var/lib/aide/aide.db || -f /var/lib/aide/aide.db.gz ]]'
    chk 10 "AIDE check scheduled"                     aide_scheduled
    chk 11 "lynis + clamav installed"                 scanner_present
    chk 11 "ClamAV signature database present"        clam_db
    chk 11 "weekly starhard-scan timer active"        svc_active starhard-scan.timer
    chk 11 "starhard-status installed"                test -x /usr/local/sbin/starhard-status
    chk 12 "automatic security updates configured"    autoupd_cfg
    chk 13 "/etc/shadow not other-readable"           not_other_readable /etc/shadow
    chk 13 "/etc/gshadow not other-readable"          not_other_readable /etc/gshadow
    chk 13 "login banner present"                     grep -q 'AUTHORIZED USE ONLY' /etc/issue
    chk 13 "sudo hardening present"                   test -f /etc/sudoers.d/50-starhard
    chk 14 "MAC (AppArmor/SELinux) enforcing"         mac_active
    chk 15 "ctrl-alt-del masked"                      bash -c 'systemctl is-enabled ctrl-alt-del.target 2>/dev/null | grep -q masked'
    chk 15 "/dev/shm mounted noexec"                  mount_has_opt /dev/shm noexec
    chk 15 "journald persistent"                      grep -rqs '^Storage=persistent' /etc/systemd/journald.conf.d/ /etc/systemd/journald.conf
    if command -v usbguard >/dev/null 2>&1; then
        chk 20 "usbguard running"                     svc_active usbguard
        chk 20 "usbguard StarHard rules in rules.d"   test -s /etc/usbguard/rules.d/50-starhard.conf
        chk 20 "usbguard RuleFolder enabled"          grep -q '^RuleFolder=/etc/usbguard/rules.d' /etc/usbguard/usbguard-daemon.conf
        chk 20 "usbguard IPC restricted to root"      grep -q '^IPCAllowedUsers=root' /etc/usbguard/usbguard-daemon.conf
        chk 20 "usbguard audit → auditd"              grep -q '^AuditBackend=LinuxAudit' /etc/usbguard/usbguard-daemon.conf
        [[ "$PROFILE" != "server" ]] && chk 20 "lock-screen HID block watcher running" svc_active starhard-usb-lock.service
        [[ "$PROFILE" == "server" ]] && chk 20 "usbguard implicit policy = block (server)" grep -q '^ImplicitPolicyTarget=block' /etc/usbguard/usbguard-daemon.conf
    fi
    if [[ "$PROFILE" == "server" ]]; then
        chk 15 "/tmp mounted noexec (server)"         mount_has_opt /tmp noexec
        chk 15 "avahi not running (server)"           bash -c '! systemctl is-active -q avahi-daemon 2>/dev/null'
    fi
    if [[ $IS_PI -eq 1 ]]; then
        chk 19 "Pi: Raspberry Pi origin in unattended-upgrades" test -f /etc/apt/apt.conf.d/53starhard-raspberrypi
        chk 19 "Pi: auditd watching $PI_BOOT/config.txt"       bash -c "grep -q '$PI_BOOT/config.txt' /etc/audit/rules.d/50-hardening.rules"
        command -v rpi-eeprom-update >/dev/null 2>&1 && \
        chk 19 "Pi: EEPROM bootloader up to date"             bash -c "! rpi-eeprom-update 2>/dev/null | grep -q 'UPDATE AVAILABLE'"
        [[ $PI_DISABLE_BT -eq 1 && -n "$PI_BOOT" ]] && \
        chk 19 "Pi: dtoverlay=disable-bt set"                 grep -Eq '^\s*dtoverlay=disable-bt' "$PI_BOOT/config.txt"
        [[ $PI_DISABLE_WIFI -eq 1 && -n "$PI_BOOT" ]] && \
        chk 19 "Pi: dtoverlay=disable-wifi set"               grep -Eq '^\s*dtoverlay=disable-wifi' "$PI_BOOT/config.txt"
        [[ "$PROFILE" == "server" && -n "$PI_BOOT" ]] && \
        chk 19 "Pi: serial console login disabled (server)"   bash -c "! grep -q 'console=serial0' '$PI_BOOT/cmdline.txt'"
    fi
    echo "==============================================================="
    echo "  PASS: $A_PASS   FAIL: $A_FAIL"
    echo "==============================================================="
    [[ $A_FAIL -eq 0 ]]
}


echo "==============================================================="
echo "  StarHard v$VERSION"
echo "  OS: $OS_ID   Package manager: $PKG   Profile: $PROFILE   Arch: $ARCH   IPS: $IDS"
[[ $IS_PI -eq 1 ]] && echo "  Hardware: $PI_MODEL  (boot config: ${PI_BOOT:-not found})"
[[ $HAS_TAILSCALE -eq 1 || $HAS_PIHOLE -eq 1 ]] && echo "  Services detected:$( [[ $HAS_TAILSCALE -eq 1 ]] && echo ' tailscale')$( [[ $HAS_PIHOLE -eq 1 ]] && echo ' pi-hole') — firewall/sysctl adjusted"
[[ $DRY_RUN -eq 1 ]] && echo "  MODE: DRY RUN — no changes will be made"
[[ $SSH_ACTIVE -eq 1 ]] && echo "  Running over SSH — SSH access will be preserved in firewall rules"
[[ $AUDIT -eq 0 ]] && echo "  Backups: $BACKUP_DIR"
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
            server_pkgs=(usbguard)
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
            server_pkgs=(usbguard)
            pkg_install aide "${f2b[@]}" audit psacct libpwquality firewalld \
                dnf-automatic policycoreutils lynis clamav clamav-update unhide sudo \
                "${server_pkgs[@]}"
            ;;
        zypper)
            server_pkgs=(usbguard)
            pkg_install aide "${f2b[@]}" audit acct pam_pwquality firewalld lynis clamav unhide sudo \
                "${server_pkgs[@]}"
            ;;
        pacman)
            server_pkgs=(usbguard)
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
    # rp_filter: strict (1) breaks Tailscale subnet routing/exit nodes; loose (2) keeps the anti-spoof benefit
    local rpf=1 ra_block
    [[ $HAS_TAILSCALE -eq 1 ]] && { rpf=2; info "Tailscale detected — rp_filter set to loose (2)"; }
    if [[ $HAS_SLAAC -eq 1 ]]; then
        ra_block="# accept_ra left at default: this host has a SLAAC IPv6 address and would lose it"
        info "SLAAC IPv6 address present — leaving accept_ra unchanged"
    else
        ra_block=$'net.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0'
    fi
    sed -e "s/__RPF__/$rpf/g" -e "s|__ACCEPT_RA__|${ra_block//$'\n'/\\n}|" <<'EOF' | write_file /etc/sysctl.d/99-hardening.conf 644
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
net.ipv4.conf.all.rp_filter = __RPF__
net.ipv4.conf.default.rp_filter = __RPF__
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === IPv6 ===
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
__ACCEPT_RA__
EOF
    # -e: keys unknown to this kernel are ignored instead of failing the whole run
    run "Apply sysctl settings" sysctl -e --system
}

#===============================================================================
# 3. Blacklist rarely-used kernel modules
#===============================================================================
sec_modules() {
    local mods=(dccp sctp rds tipc cramfs freevxfs jffs2 hfs hfsplus udf)
    # Firewire doesn't exist on a Pi; Bluetooth is cut at the device-tree level in section 19
    [[ $IS_PI -eq 0 ]] && mods+=(firewire-core)
    [[ "$PROFILE" == "server" && $IS_PI -eq 0 ]] && mods+=(bluetooth btusb)
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
        local hash_block ys ys_ok=0
        # Several signals: distro default in login.defs, PAM config, an existing $y$ hash, or a libcrypt probe
        grep -Eq '^\s*ENCRYPT_METHOD\s+YESCRYPT' /etc/login.defs && ys_ok=1
        grep -qs 'yescrypt' /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth && ys_ok=1
        cut -d: -f2 /etc/shadow 2>/dev/null | grep -q '^\$y\$' && ys_ok=1
        ys="$(perl -e 'print crypt("x","\$y\$j9T\$abcdefghijklmnopq\$")' 2>/dev/null || true)"
        [[ "$ys" == '$y$'* ]] && ys_ok=1
        if [[ $ys_ok -eq 1 ]]; then
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
        [[ $HAS_PIHOLE -eq 1 ]] && info "Server profile disables SSH port-forwarding (ssh -L to the Pi-hole UI); reach it via LAN/Tailscale IP instead"
    else
        profile_lines=$'MaxAuthTries 6\nMaxSessions 10'
    fi

    # Crypto + extras, added only where this sshd supports the keyword (sshd -T lists every supported one)
    local sshd_opts crypto_lines=""
    sshd_opts="$(sshd -T 2>/dev/null | awk '{print tolower($1)}')"
    has_opt() { grep -qx "$1" <<< "$sshd_opts"; }
    if has_opt kexalgorithms; then
        crypto_lines+=$'KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\n'
        crypto_lines+=$'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr\n'
        crypto_lines+=$'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n'
        crypto_lines+=$'HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com\n'
    fi
    has_opt requiredrsasize && crypto_lines+=$'RequiredRSASize 3072\n'
    [[ "$PKG" == "apt" ]] && crypto_lines+=$'DebianBanner no\n'
    # Restrict logins to real users who already have keys or a home dir (never lock out the invoking user)
    local allow_users="" u
    if [[ "$PROFILE" == "server" ]]; then
        for u in $(awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd); do
            [[ -s "/home/$u/.ssh/authorized_keys" ]] && allow_users+="$u "
        done
        [[ -n "${SUDO_USER:-}" && "$allow_users" != *"$SUDO_USER "* ]] && allow_users+="$SUDO_USER "
        [[ -n "$allow_users" ]] && crypto_lines+="AllowUsers ${allow_users% }"$'\n' && info "SSH restricted to: ${allow_users% }"
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
$crypto_lines
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
pihole_has_lan_clients() {
    # Looks at Pi-hole's query database for clients in the last 7 days that are NOT
    # tailnet (100.64/10), loopback or the Pi itself. Returns 0 if any found.
    local db=/etc/pihole/pihole-FTL.db sq=""
    [[ -r "$db" ]] || return 1
    if command -v pihole-FTL >/dev/null 2>&1; then sq="pihole-FTL sqlite3"
    elif command -v sqlite3 >/dev/null 2>&1; then sq="sqlite3"
    else return 1; fi
    local clients
    clients="$($sq "$db" "SELECT DISTINCT client FROM queries WHERE timestamp > strftime('%s','now')-604800;" 2>/dev/null)"
    [[ -n "$clients" ]] || return 1
    local my_ips c
    my_ips="$(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
    for c in $clients; do
        case "$c" in
            127.*|::1|100.6[4-9].*|100.[7-9]?.*|100.1[0-1]?.*|100.12[0-7].*|fd7a:115c:a1e0:*) continue ;;
        esac
        [[ " $my_ips " == *" $c "* ]] && continue
        [[ "$c" == *:* ]] && continue   # ignore other IPv6 for this decision
        return 0
    done
    return 1
}

fw_warn_stale_rules() {
    # ufw "ALLOW IN" rules for a numeric port that nothing is listening on
    command -v ufw >/dev/null 2>&1 || return 0
    local listening stale="" rule port proto
    listening="$(ss -tulnH 2>/dev/null | awk '{split($5,a,":"); print $1"/"a[length(a)]}' | sort -u)"
    while read -r rule; do
        port="${rule%%/*}"; proto="${rule#*/}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        case "$proto" in
            tcp|udp) echo "$listening" | grep -qx "$proto/$port" || stale+=" $rule" ;;
            *)       echo "$listening" | grep -Eq "^(tcp|udp)/$port$" || stale+=" $port" ;;
        esac
    done < <(ufw status 2>/dev/null | awk '/ALLOW IN/ && $1 !~ /^Anywhere/ {print $1}' | sed 's/ (v6)//' | sort -u)
    if [[ -n "$stale" ]]; then
        warn "ufw allows these ports but nothing is listening on them (stale? review with 'ufw status numbered'):$stale"
    fi
}

fw_warn_listeners() {
    # fw_warn_listeners <ssh_port> — show non-loopback listeners the default-deny policy will block
    local ssh_port="$1" allowed=" $1 "
    [[ $HAS_PIHOLE -eq 1 ]] && allowed+=" 53 80 443 67 "
    [[ $HAS_TAILSCALE -eq 1 ]] && allowed+=" 41641 "
    local others
    others="$(ss -tulnH 2>/dev/null | awk '{split($5,a,":"); p=a[length(a)]; addr=$5; sub(":"p"$","",addr); if (addr !~ /^(127\.|\[::1\]|::1)/) print $1"/"p}' | sort -u \
        | while read -r l; do p="${l#*/}"; [[ "$allowed" == *" $p "* ]] || echo "$l"; done | tr '\n' ' ')"
    if [[ -n "$others" ]]; then
        warn "Other listening ports that the firewall will now BLOCK from the network: $others"
        warn "If any are needed, allow them: ufw allow <port>/<proto>  (or firewall-cmd --permanent --add-port=<port>/<proto>)"
    fi
}

sec_firewall() {
    local ssh_port
    ssh_port="$(sshd_opt port)"; ssh_port="${ssh_port:-22}"
    local need_ssh=0
    [[ "$PROFILE" == "server" || $SSH_ACTIVE -eq 1 ]] && need_ssh=1

    # LAN subnets (CIDR) of every non-loopback, non-tailscale interface with an IPv4 address
    local lan_nets
    lan_nets="$(ip -o -4 route show scope link 2>/dev/null | awk '$3 !~ /^(lo|tailscale|docker|br-|veth)/ {print $1}' | sort -u)"

    # Pi-hole DHCP enabled?
    local pihole_dhcp=0
    if [[ $HAS_PIHOLE -eq 1 ]]; then
        if command -v pihole-FTL >/dev/null 2>&1 && pihole-FTL --config dhcp.active 2>/dev/null | grep -qi true; then pihole_dhcp=1
        elif grep -qs '^DHCP_ACTIVE=true' /etc/pihole/setupVars.conf; then pihole_dhcp=1
        fi
    fi

    # Pi-hole: open to LAN only if LAN clients actually use it
    local pihole_lan=0
    if [[ $HAS_PIHOLE -eq 1 ]]; then
        if [[ "$PIHOLE_LAN" == "1" ]]; then pihole_lan=1; info "Pi-hole: LAN rules forced on (--pihole-lan)"
        elif [[ "$PIHOLE_LAN" == "0" ]]; then info "Pi-hole: LAN rules skipped (--no-lan-dns)"
        elif pihole_has_lan_clients; then pihole_lan=1; info "Pi-hole: LAN clients seen in the query log — opening DNS/web to LAN subnets"
        elif [[ $HAS_TAILSCALE -eq 1 ]]; then info "Pi-hole: only tailnet/local clients in the query log — NOT opening DNS to the LAN (use --pihole-lan to override)"
        else pihole_lan=1; info "Pi-hole: no query history to judge from — opening DNS/web to LAN subnets (use --no-lan-dns to prevent)"
        fi
    fi

    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -q 'Status: active'; then
            info "ufw already active — existing rules are kept, only defaults + the rules below are added"
        fi
        if [[ $HAS_TAILSCALE -eq 1 ]]; then
            run "ufw: trust tailscale0" ufw allow in on tailscale0
            run "ufw: tailscale direct connections (41641/udp)" ufw allow 41641/udp
        fi
        if [[ $pihole_lan -eq 1 ]]; then
            local n
            for n in $lan_nets; do
                run "ufw: Pi-hole DNS from $n" ufw allow from "$n" to any port 53 proto tcp
                run "ufw: Pi-hole DNS from $n" ufw allow from "$n" to any port 53 proto udp
                run "ufw: Pi-hole web from $n" ufw allow from "$n" to any port 80 proto tcp
                run "ufw: Pi-hole web (TLS) from $n" ufw allow from "$n" to any port 443 proto tcp
                [[ $pihole_dhcp -eq 1 ]] && run "ufw: Pi-hole DHCP from $n" ufw allow from "$n" to any port 67 proto udp
            done
            [[ -z "$lan_nets" ]] && warn "Pi-hole detected but no LAN subnet found — allow port 53 manually: ufw allow 53"
        fi
        local was_active=0
        ufw status 2>/dev/null | grep -q 'Status: active' && was_active=1
        run "ufw default deny incoming" ufw default deny incoming
        run "ufw default allow outgoing" ufw default allow outgoing
        if [[ $need_ssh -eq 1 ]]; then
            run "ufw allow ssh port $ssh_port (rate-limited)" ufw limit "$ssh_port/tcp"
        fi
        fw_warn_listeners "$ssh_port"
        fw_warn_stale_rules
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
        if [[ $HAS_TAILSCALE -eq 1 ]]; then
            run "firewalld: trust tailscale0" firewall-cmd --permanent --zone=trusted --add-interface=tailscale0
            run "firewalld: tailscale 41641/udp" firewall-cmd --permanent --add-port=41641/udp
        fi
        if [[ $pihole_lan -eq 1 ]]; then
            run "firewalld: Pi-hole DNS" firewall-cmd --permanent --add-service=dns
            run "firewalld: Pi-hole web" firewall-cmd --permanent --add-service=http
            run "firewalld: Pi-hole web (TLS)" firewall-cmd --permanent --add-service=https
            [[ $pihole_dhcp -eq 1 ]] && run "firewalld: Pi-hole DHCP" firewall-cmd --permanent --add-service=dhcp
        fi
        fw_warn_listeners "$ssh_port"
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
audit_dedupe() {
    # audit_dedupe <our-file>  — stdin: our rules; stdout: our rules minus any watch path or
    # syscall rule already present in ANOTHER file under /etc/audit/rules.d/. auditctl aborts the
    # whole load on the first duplicate ("Rule exists"), which then fails audit-rules.service and auditd.
    local ours="$1" other
    local -a others=()
    for other in /etc/audit/rules.d/*.rules; do
        [[ -f "$other" && "$other" != "$ours" ]] && others+=("$other")
    done
    if [[ ${#others[@]} -eq 0 ]]; then cat; return 0; fi
    awk -v ourfile="$ours" '
        function norm(l) { gsub(/[ \t]+/, " ", l); sub(/^ /, "", l); sub(/ $/, "", l); return l }
        FILENAME != "-" {
            line = norm($0)
            if (line ~ /^-w /) { split(line, f, " "); paths[f[2]] = FILENAME }
            else if (line ~ /^-a /) { sub(/ -k [^ ]+$/, "", line); rules[line] = FILENAME }
            next
        }
        {
            line = norm($0)
            if (line ~ /^-w /) {
                split(line, f, " ")
                if (f[2] in paths) { print "# skipped (already watched in " paths[f[2]] "): " $0; next }
            } else if (line ~ /^-a /) {
                key = line; sub(/ -k [^ ]+$/, "", key)
                if (key in rules) { print "# skipped (already in " rules[key] "): " $0; next }
            }
            print
        }' "${others[@]}" -
}

sec_auditd() {
    command -v auditctl >/dev/null 2>&1 || { info "auditd not installed — skipping"; return 0; }
    local arches="b64"
    [[ "$ARCH" == "x86_64" ]] && arches="b64 b32"
    # aarch64/riscv64 have no legacy unlink/rename/chmod/chown/lchown syscalls — only the *at variants.
    # auditctl aborts the whole rule load on an unknown syscall name.
    local sc_delete="unlinkat,renameat,renameat2" sc_perm="fchmod,fchmodat,fchown,fchownat" sc_open="openat,openat2"
    if [[ "$ARCH" == "x86_64" ]]; then
        sc_delete="unlink,unlinkat,rename,renameat,renameat2"
        sc_perm="chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown"
        sc_open="open,openat,openat2"
    fi
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

# Library preloading (classic userland keylogger / rootkit hook point)
-w /etc/ld.so.preload -p wa -k preload
-w /etc/ld.so.conf.d/ -p wa -k preload
EOF
        if [[ $IS_PI -eq 1 && -n "$PI_BOOT" ]]; then
            cat <<EOF

# Raspberry Pi boot configuration (FAT partition — permissions can't be tightened, so watch it)
-w $PI_BOOT/config.txt -p wa -k pi_boot
-w $PI_BOOT/cmdline.txt -p wa -k pi_boot
-w /etc/default/rpi-eeprom-update -p wa -k pi_boot
EOF
        fi
        local a
        for a in $arches; do
            cat <<EOF

# Syscall rules ($a)
-a always,exit -F arch=$a -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k priv_esc
-a always,exit -F arch=$a -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=$a -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=$a -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=$a -S $sc_delete -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=$a -S $sc_perm -F auid>=1000 -F auid!=unset -k perm_mod
# Opens of keyboard/mouse devices by a logged-in user (incl. via sudo) — userland keylogger indicator.
# Boot-time daemons (logind, display manager) have auid unset and are excluded.
-a always,exit -F arch=$a -S $sc_open -F dir=/dev/input -F auid>=1000 -F auid!=unset -k input_dev
EOF
        done
        cat <<'EOF'

# Uncomment to log every command run by a real user (very noisy; useful on servers with a log shipper)
#-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec

# Make configuration immutable (requires reboot to change rules)
-e 2
EOF
    } | audit_dedupe /etc/audit/rules.d/50-hardening.rules | write_file /etc/audit/rules.d/50-hardening.rules 640

    if [[ $DRY_RUN -eq 0 ]]; then
        local skipped
        skipped="$(grep -c '^# skipped' /etc/audit/rules.d/50-hardening.rules 2>/dev/null || echo 0)"
        [[ "$skipped" -gt 0 ]] && info "$skipped rule(s) already defined by other files in /etc/audit/rules.d/ — left to those files"
        if auditctl -s 2>/dev/null | grep -q '^enabled 2'; then
            warn "audit is in immutable mode (-e 2) — new rules load on next reboot"
        else
            if augenrules --load >> "$LOG_FILE" 2>&1; then
                log "audit rules loaded"
            else
                warn "augenrules --load reported errors: $(grep -iE 'syscall|error|invalid' "$LOG_FILE" | tail -1)"
            fi
        fi
    fi
    svc_enable auditd

    # sysstat (sar) — Lynis ACCT-9626
    if ! command -v sar >/dev/null 2>&1; then pkg_install sysstat; fi
    if [[ -f /etc/default/sysstat ]]; then
        backup_file /etc/default/sysstat
        [[ $DRY_RUN -eq 0 ]] && sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
    fi
    has_systemd && unit_exists sysstat.service && svc_enable sysstat

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
#!/usr/bin/env bash
# StarHard weekly scan: ClamAV, unhide, package integrity, Lynis.
# Interactive (terminal): live progress bars and stage summaries.
# Timer / non-terminal: silent, log only.   Log: /var/log/starhard/scan-<date>.log
# Options: --quiet (no terminal output)   --clam-only   --no-clam
QUIET=0; CLAM_ONLY=0; NO_CLAM=0
for a in "$@"; do case "$a" in --quiet) QUIET=1;; --clam-only) CLAM_ONLY=1;; --no-clam) NO_CLAM=1;; esac; done
[[ -t 1 ]] || QUIET=1
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo starhard-scan"; exit 1; }

mkdir -p /var/log/starhard
LOG="/var/log/starhard/scan-$(date +%F).log"
TMP="$(mktemp -d /tmp/starhard-scan.XXXXXX)"; trap 'rm -rf "$TMP"' EXIT
T0=$(date +%s)
C=$'\033[0;36m'; G=$'\033[0;32m'; Y=$'\033[1;33m'; R=$'\033[0;31m'; D=$'\033[2m'; N=$'\033[0m'
if [[ "${LANG:-}${LC_ALL:-}" == *[Uu][Tt][Ff]* ]]; then FR=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'); BF='█'; BE='░'; OK='✔'; BAD='✘'
else FR=('|' '/' '-' '\\'); BF='#'; BE='.'; OK='OK'; BAD='XX'; fi

say()   { [[ $QUIET -eq 1 ]] || echo "$@"; }
stage() { [[ $QUIET -eq 1 ]] || { echo; echo -e "${C}━━ $1 ${D}$2${N}"; }; }
fmt_t() { local s=$1; printf '%dm%02ds' $((s/60)) $((s%60)); }
bar() {
    # bar <done> <total> <label>   — one-line progress bar, redrawn in place
    local done=$1 total=$2 label=$3 w=30 pct=0 fill
    [[ $total -gt 0 ]] && pct=$(( done * 100 / total )); [[ $pct -gt 100 ]] && pct=100
    fill=$(( pct * w / 100 ))
    printf '\r  %s%s%s%s %3d%%  %s' "$(printf "$BF%.0s" $(seq 1 $fill))" "$D" "$(printf "$BE%.0s" $(seq 1 $((w-fill))))" "$N" "$pct" "$label"
}
spin() {
    # spin <pid> <label>   — spinner with elapsed time until pid exits
    local pid=$1 label=$2 i=0 s
    s=$(date +%s)
    while kill -0 "$pid" 2>/dev/null; do
        [[ $QUIET -eq 0 ]] && printf '\r  %s %s  %s' "${FR[i % ${#FR[@]}]}" "$label" "$(fmt_t $(( $(date +%s) - s )))"
        i=$((i+1)); sleep 0.2
    done
    [[ $QUIET -eq 0 ]] && printf '\r%*s\r' 70 ''
}
result() { [[ $QUIET -eq 1 ]] || echo -e "  $1"; }

{
    echo "== starhard-scan $(date) =="
} > "$LOG"

say "${C}StarHard scan${N} — $(hostname), $(date '+%a %d %b %H:%M')  ${D}log: $LOG${N}"

#---------------------------------------------------------------- ClamAV -----
if command -v clamscan >/dev/null 2>&1 && [[ $NO_CLAM -eq 0 ]]; then
    { echo; echo "-- clamscan --"; } >> "$LOG"
    AVAIL_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [[ "${AVAIL_KB:-0}" -lt 1500000 ]]; then
        echo "SKIPPED: only $((AVAIL_KB/1024)) MB RAM available (need ~1500 MB). Run clamscan manually when idle." >> "$LOG"
        logger -t starhard-scan "clamscan skipped: low memory"
        stage "1/4 ClamAV malware scan" "skipped — only $((AVAIL_KB/1024)) MB RAM free"
    else
        DIRS=()
        for d in /etc /home /root /tmp /var/tmp /usr/local /opt /srv /var/www; do [[ -d "$d" ]] && DIRS+=("$d"); done
        while read -r m; do [[ -n "$m" ]] && { DIRS+=("$m"); echo "including removable media: $m" >> "$LOG"; }; done \
            < <(findmnt -rn -o TARGET 2>/dev/null | grep -E '^/(media|mnt|run/media)(/|$)')
        EXCL=(); n=0
        if [[ -s /etc/starhard/clamav-exclude ]]; then
            while IFS= read -r pat; do
                case "$pat" in ''|\#*) continue;; esac
                EXCL+=("--exclude-dir=$pat" "--exclude=$pat"); n=$((n+1))
            done < /etc/starhard/clamav-exclude
            echo "exclusions applied: $n pattern(s) from /etc/starhard/clamav-exclude" >> "$LOG"
        fi
        stage "1/4 ClamAV malware scan" "${DIRS[*]}  ($n exclusion pattern(s))"
        SIGS="$(ls /var/lib/clamav/*.c[lv]d 2>/dev/null | wc -l)"
        SIGAGE=$(( ( $(date +%s) - $(stat -c %Y "$(ls -t /var/lib/clamav/daily.c[lv]d 2>/dev/null | head -1)" 2>/dev/null || echo "$T0") ) / 3600 ))
        say "  ${D}signature databases: $SIGS, last updated ${SIGAGE}h ago${N}"

        # Rough file count for the bar (exclusions not applied, so the bar may finish early)
        find "${DIRS[@]}" -xdev -type f 2>/dev/null | wc -l > "$TMP/total" &
        clamscan -r --exclude-dir='^/(proc|sys|dev|run)' "${EXCL[@]}" "${DIRS[@]}" > "$TMP/clam" 2>&1 &
        CPID=$!
        s=$(date +%s); total=0
        while kill -0 "$CPID" 2>/dev/null; do
            [[ $total -eq 0 && -s "$TMP/total" ]] && total=$(< "$TMP/total")
            done=$(wc -l < "$TMP/clam" 2>/dev/null || echo 0)
            inf=$(grep -c ' FOUND$' "$TMP/clam" 2>/dev/null || true)
            if [[ $QUIET -eq 0 ]]; then
                el=$(( $(date +%s) - s ))
                if [[ $done -eq 0 ]]; then
                    printf '\r  loading signatures… %s' "$(fmt_t $el)"
                else
                    rate=$(( el > 0 ? done / el : done ))
                    lbl="$done/${total:-?} files  ${rate}/s  $(fmt_t $el)"
                    [[ ${inf:-0} -gt 0 ]] && lbl="$lbl  ${R}${inf} FOUND${N}"
                    bar "$done" "$total" "$lbl"
                fi
            fi
            sleep 1
        done
        wait "$CPID"; CRC=$?
        [[ $QUIET -eq 0 ]] && printf '\r%*s\r' 100 ''
        # Log: hits + summary only (full per-file list would be hundreds of MB)
        grep ' FOUND$' "$TMP/clam" >> "$LOG"
        sed -n '/SCAN SUMMARY/,$p' "$TMP/clam" >> "$LOG"
        INF=$(grep -m1 '^Infected files:' "$TMP/clam" | awk '{print $3}')
        SCANNED=$(grep -m1 '^Scanned files:' "$TMP/clam" | awk '{print $3}')
        if [[ "${INF:-0}" == "0" ]]; then
            result "${G}${OK}${N} ${SCANNED:-?} files scanned, no malware  ${D}($(fmt_t $(( $(date +%s) - s ))))${N}"
        elif [[ -z "$INF" ]]; then
            result "${Y}!${N} clamscan exited $CRC without a summary — see $LOG"
        else
            result "${R}${BAD} $INF infected file(s):${N}"
            grep ' FOUND$' "$TMP/clam" | sed 's/^/      /' | while read -r l; do say "$l"; done
        fi
    fi
elif [[ $NO_CLAM -eq 0 ]]; then
    stage "1/4 ClamAV" "not installed"
fi
[[ $CLAM_ONLY -eq 1 ]] && { logger -t starhard-scan "clam-only scan complete — see $LOG"; say; say "${D}done in $(fmt_t $(( $(date +%s) - T0 )))${N}"; exit 0; }

#---------------------------------------------------------------- unhide -----
if command -v unhide >/dev/null 2>&1; then
    { echo; echo "-- unhide (hidden processes) --"; } >> "$LOG"
    stage "2/4 Hidden process check (unhide)" "compares /proc, syscalls and brute-forced PIDs"
    { unhide proc; unhide sys; } > "$TMP/unhide" 2>&1 &
    spin $! "scanning PID space"
    cat "$TMP/unhide" >> "$LOG"
    if grep -q 'Found HIDDEN' "$TMP/unhide"; then
        result "${R}${BAD} HIDDEN process reported — see $LOG${N}"
    else
        result "${G}${OK}${N} no hidden processes"
    fi
fi

#------------------------------------------------------- package integrity ---
{ echo; echo "-- package integrity --"; } >> "$LOG"
stage "3/4 Package integrity" "every installed file checked against its package checksum"
if command -v debsums >/dev/null 2>&1; then
    debsums -s > "$TMP/pkg" 2>&1 &
elif command -v rpm >/dev/null 2>&1; then
    { rpm -Va 2>/dev/null | grep '^..5' | grep -v '^.*c /etc/'; } > "$TMP/pkg" 2>&1 &
elif command -v pacman >/dev/null 2>&1; then
    { pacman -Qkk 2>/dev/null | grep -v ' 0 altered files'; } > "$TMP/pkg" 2>&1 &
else
    : > "$TMP/pkg"; true &
fi
spin $! "hashing package files"
cat "$TMP/pkg" >> "$LOG"
CHG=$(grep -c . "$TMP/pkg" || true)
if [[ "${CHG:-0}" -eq 0 ]]; then
    result "${G}${OK}${N} no modified package files"
else
    result "${Y}!${N} $CHG modified file(s) ${D}(edited configs are normal; binaries are not)${N}"
    head -5 "$TMP/pkg" | sed 's/^/      /' | while read -r l; do say "$l"; done
    [[ $CHG -gt 5 ]] && say "      ${D}… $((CHG-5)) more in $LOG${N}"
fi

#----------------------------------------------------------------- Lynis -----
if command -v lynis >/dev/null 2>&1; then
    { echo; echo "-- lynis --"; } >> "$LOG"
    stage "4/4 Lynis configuration audit" "~250 checks, read-only"
    lynis audit system --cronjob --quiet > "$TMP/lynis" 2>&1 &
    spin $! "auditing system configuration"
    cat "$TMP/lynis" >> "$LOG"
    echo "Full report: /var/log/lynis-report.dat" >> "$LOG"
    IDX=$(grep -m1 '^hardening_index=' /var/log/lynis-report.dat 2>/dev/null | cut -d= -f2)
    WN=$(grep -c '^warning\[\]=' /var/log/lynis-report.dat 2>/dev/null || true)
    result "${G}${OK}${N} hardening index ${IDX:-?}/100, ${WN:-0} warning(s)  ${D}(starhard.sh --audit explains them)${N}"
fi

logger -t starhard-scan "weekly scan complete — see $LOG"
say
say "${D}done in $(fmt_t $(( $(date +%s) - T0 )))  •  sudo starhard-status for the digest${N}"
exit 0
EOF
    local scan_exec=/usr/local/sbin/starhard-scan
    if command -v systemd-inhibit >/dev/null 2>&1; then
        # Laptops suspend mid-scan otherwise; this holds idle-suspend while it runs (lid close still wins)
        scan_exec="/usr/bin/systemd-inhibit --what=sleep:idle --who=StarHard --why=weekly-security-scan /usr/local/sbin/starhard-scan"
    fi
    write_timer starhard-scan "StarHard weekly malware/rootkit/integrity scan" weekly "$scan_exec"
    if [[ $DRY_RUN -eq 0 && ! -e /etc/starhard/ignore-units ]]; then
        mkdir -p /etc/starhard
        record_rm /etc/starhard/ignore-units
        printf '# starhard-status: failed units to ignore, one per line (e.g. suricata, hostapd-wpe)\n' > /etc/starhard/ignore-units
    fi
    if [[ $DRY_RUN -eq 0 && -f /etc/starhard/clamav-exclude ]] && grep -qx '/\\.msf4/' /etc/starhard/clamav-exclude; then
        # v1.2 defaults with unbounded patterns: rewrite only the default lines, keep user additions
        backup_file /etc/starhard/clamav-exclude
        sed -i -E -e '\|^/\\\.msf4/$|d' -e '\|^\^/root/\\\.msf$|d' \
            -e 's#^(\^/(etc|usr|var|opt)/[^( ]+)$#\1(/|$)#' /etc/starhard/clamav-exclude
        echo '^/(root|home/[^/]+)/\.msf4(/|$)' >> /etc/starhard/clamav-exclude
        info "ClamAV exclude list: tightened default patterns (anchored, bounded)"
    fi
    if [[ $DRY_RUN -eq 0 && ! -e /etc/starhard/clamav-exclude ]]; then
        mkdir -p /etc/starhard
        record_rm /etc/starhard/clamav-exclude
        {
            echo '# starhard-scan: paths ClamAV should skip, one extended regex per line (matched against the full path).'
            echo '# Add directories that legitimately contain exploit code, scanner payloads or detection rules.'
            case "$OS_ID" in
                kali|parrot|blackarch)
                    echo "# Defaults for $OS_ID — security tooling that ClamAV mistakes for malware:"
                    # Every pattern is anchored at the start and bounded at the end with (/|$), so
                    # ^/usr/share/set(/|$) cannot swallow /usr/share/setuptools and a .msf4 dir only
                    # counts under a real home directory, not /tmp/x/.msf4.
                    printf '%s\n' '^/etc/unicornscan(/|$)' '^/usr/share/unicornscan(/|$)' '^/usr/share/metasploit-framework(/|$)' \
                        '^/usr/share/exploitdb(/|$)' '^/usr/share/set(/|$)' '^/usr/share/beef-xss(/|$)' '^/usr/share/webshells(/|$)' \
                        '^/usr/share/windows-resources(/|$)' '^/usr/share/wordlists(/|$)' '^/usr/share/seclists(/|$)' \
                        '^/usr/share/nmap/scripts(/|$)' '^/usr/share/sqlmap(/|$)' '^/usr/share/responder(/|$)' \
                        '^/etc/suricata/rules(/|$)' '^/var/lib/suricata(/|$)' '^/etc/snort(/|$)' '^/usr/share/doc/suricata(/|$)' \
                        '^/opt/metasploit(/|$)' '^/(root|home/[^/]+)/\.msf4(/|$)' ;;
                *) echo '# (none by default on this distro)' ;;
            esac
        } > /etc/starhard/clamav-exclude
        [[ "$OS_ID" =~ ^(kali|parrot|blackarch)$ ]] && info "ClamAV: pentest-tool directories excluded from the weekly scan (edit /etc/starhard/clamav-exclude)"
    fi


    # One-screen security digest
    write_file /usr/local/sbin/starhard-status 755 <<'EOF'
#!/usr/bin/env bash
# starhard-status — one-screen digest of what the StarHard tooling has found.
# Usage: sudo starhard-status [--days N]   (default 7)
DAYS=7
[[ "${1:-}" == "--days" && -n "${2:-}" ]] && DAYS="$2"
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo starhard-status"; exit 1; }

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
ok()   { echo -e "  ${G}OK  ${N} $1"; }
bad()  { echo -e "  ${R}!!  ${N} $1"; }
note() { echo -e "  ${Y}--  ${N} $1"; }
hdr()  { echo; echo -e "${B}== $1 ==${N}"; }
ISSUES=0

hdr "System"
echo "  $(hostname) — $(uname -r) — up $(uptime -p 2>/dev/null | sed 's/^up //')"
if [[ -f /var/run/reboot-required ]]; then bad "Reboot required (kernel/libc updated)"; ISSUES=$((ISSUES+1)); else ok "No reboot pending"; fi
ignore_re='^$'
if [[ -s /etc/starhard/ignore-units ]]; then
    ignore_re="^($(grep -Ev '^\s*(#|$)' /etc/starhard/ignore-units | sed 's/\.service$//' | paste -sd'|'))(\.service)?$"
fi
failed="$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | grep -Ev "$ignore_re" | tr '\n' ' ')"
if [[ -n "$failed" ]]; then bad "Failed services: $failed"; ISSUES=$((ISSUES+1)); else ok "No failed services"; fi

hdr "Updates"
if command -v apt-get >/dev/null 2>&1; then
    sec="$(apt-get -s upgrade 2>/dev/null | grep -ci '^inst.*securi' || true)"
    all="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || true)"
    if [[ "${sec:-0}" -gt 0 ]]; then bad "$sec security update(s) pending ($all total) — run: apt full-upgrade"; ISSUES=$((ISSUES+1))
    elif [[ "${all:-0}" -gt 0 ]]; then note "$all package update(s) pending (none security)"
    else ok "System up to date"; fi
    last="$(grep -h 'Packages that were upgraded' /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -1 | cut -c1-19)"
    [[ -n "$last" ]] && note "Last unattended-upgrade: $last"
elif command -v dnf >/dev/null 2>&1; then
    n="$(dnf -q updateinfo list --security 2>/dev/null | grep -c . || true)"
    if [[ "${n:-0}" -gt 0 ]]; then bad "$n security update(s) pending"; ISSUES=$((ISSUES+1)); else ok "No security updates pending"; fi
fi
command -v pihole >/dev/null 2>&1 && note "Pi-hole: $(pihole -v 2>/dev/null | head -1 | sed 's/^ *//')  (update with: pihole -up)"

hdr "Malware scan (ClamAV / unhide / integrity) — last $DAYS days"
scanlog="$(ls -t /var/log/starhard/scan-*.log 2>/dev/null | head -1)"
if [[ -z "$scanlog" ]]; then
    note "No scan has run yet — run: starhard-scan   (timer: $(systemctl list-timers starhard-scan.timer --no-legend 2>/dev/null | awk '{print $1" "$2" "$3}'))"
else
    age=$(( ( $(date +%s) - $(stat -c %Y "$scanlog") ) / 86400 ))
    note "Last scan: $(basename "$scanlog" .log | sed 's/scan-//') (${age}d ago)"
    inf="$(grep -m1 '^Infected files:' "$scanlog" | awk '{print $3}')"
    if [[ -z "$inf" ]]; then
        if pgrep -x clamscan >/dev/null 2>&1; then
            secs="$(ps -o etimes= -C clamscan 2>/dev/null | head -1 | xargs)"
            note "ClamAV: scan in progress ($(( ${secs:-0} / 60 )) min elapsed)"
        elif grep -q 'SKIPPED: only' "$scanlog"; then note "ClamAV skipped last run (low memory)"
        else note "ClamAV: no result in log (scan interrupted?)"; fi
    elif [[ "$inf" == "0" ]]; then
        ex="$(grep -m1 -o 'exclusions applied: [0-9]*' "$scanlog" | awk '{print $3}')"
        ok "ClamAV: 0 infected files${ex:+ (${ex} path pattern(s) excluded — /etc/starhard/clamav-exclude)}"
    else bad "ClamAV: $inf infected file(s):"; grep ' FOUND$' "$scanlog" | sed 's/^/        /'; ISSUES=$((ISSUES+1)); fi
    if grep -q 'Found HIDDEN' "$scanlog"; then bad "unhide: HIDDEN process/port reported — see $scanlog"; ISSUES=$((ISSUES+1))
    elif grep -q 'unhide' "$scanlog"; then ok "unhide: no hidden processes"; fi
    chg="$(sed -n '/-- package integrity --/,/-- lynis --/p' "$scanlog" | grep -Ev '^--|^$|^Full report' | grep -c . || true)"
    if [[ "${chg:-0}" -gt 0 ]]; then note "Package integrity: $chg modified file(s) — see $scanlog (config edits are normal)"
    else ok "Package integrity: no modified package files"; fi
fi
db="$(ls -t /var/lib/clamav/daily.c[lv]d 2>/dev/null | head -1)"
if [[ -n "$db" ]]; then
    dage=$(( ( $(date +%s) - $(stat -c %Y "$db") ) / 86400 ))
    if [[ $dage -gt 3 ]]; then bad "ClamAV signatures are ${dage}d old — check: systemctl status clamav-freshclam"; ISSUES=$((ISSUES+1)); else ok "ClamAV signatures current (${dage}d)"; fi
fi

hdr "File integrity (AIDE)"
aidelog="$(ls -t /var/log/starhard/aide-*.log /var/log/aide/aide.log 2>/dev/null | head -1)"
aidedb="$(ls -t /var/lib/aide/aide.db /var/lib/aide/aide.db.gz 2>/dev/null | head -1)"
if [[ -z "$aidelog" ]]; then
    note "No AIDE check log yet (runs daily)"
elif [[ -n "$aidedb" && "$aidedb" -nt "$aidelog" ]]; then
    ok "Baseline rebuilt $(( ( $(date +%s) - $(stat -c %Y "$aidedb") ) / 3600 ))h ago — newer than the last check; next daily check will report against it"
else
    aage=$(( ( $(date +%s) - $(stat -c %Y "$aidelog") ) / 86400 ))
    if grep -q 'found NO differences\|AIDE found no differences' "$aidelog" 2>/dev/null; then
        ok "Last check (${aage}d ago): no changes"
    else
        a="$(grep -m1 -E '^ *Added entries:' "$aidelog" | awk '{print $NF}')"
        r="$(grep -m1 -E '^ *Removed entries:' "$aidelog" | awk '{print $NF}')"
        c="$(grep -m1 -E '^ *Changed entries:' "$aidelog" | awk '{print $NF}')"
        if [[ -n "$a$r$c" ]]; then
            if [[ "${a:-0}" -gt 5000 || "${r:-0}" -gt 5000 ]]; then
                bad "AIDE baseline is stale (added ${a:-0}, removed ${r:-0}) — reports are noise until you rebuild: aideinit --yes --force"; ISSUES=$((ISSUES+1))
            else
                note "Last check (${aage}d ago): added ${a:-0}, removed ${r:-0}, changed ${c:-0} — $aidelog"
            fi
            crit="$(grep -E '^(changed|f[^ ]*):? */(etc/(passwd|shadow|sudoers|ssh)|usr/(s?bin)/|usr/local/s?bin/)' "$aidelog" | head -5)"
            if [[ -n "$crit" ]]; then bad "Changes in sensitive paths:"; echo "$crit" | sed 's/^/        /'; ISSUES=$((ISSUES+1)); fi
            note "After a legitimate upgrade, refresh the baseline: aideinit --yes --force"
        else
            note "Last check (${aage}d ago): see $aidelog"
        fi
    fi
fi

hdr "Audit trail (auditd) — last $DAYS days"
if command -v ausearch >/dev/null 2>&1 && systemctl is-active -q auditd 2>/dev/null; then
    since="$(date -d "$DAYS days ago" '+%m/%d/%Y' 2>/dev/null || echo recent)"
    cnt() { ausearch -k "$1" -ts "$since" 2>/dev/null | grep -c '^type=SYSCALL\|^type=PATH' ; }
    for k in identity scope modules pi_boot sshd sudo_log preload input_dev; do
        n="$(cnt "$k")"
        [[ "${n:-0}" -gt 0 ]] && note "$k: $n event(s)   → ausearch -k $k -ts $since -i | less"
    done
    fl="$(ausearch -m USER_LOGIN -ts "$since" 2>/dev/null | grep -c 'res=failed' || true)"
    if [[ "${fl:-0}" -gt 20 ]]; then bad "$fl failed logins"; ISSUES=$((ISSUES+1)); elif [[ "${fl:-0}" -gt 0 ]]; then note "$fl failed login(s)"; else ok "No failed logins"; fi
    ok "auditd running"
else
    bad "auditd not running"; ISSUES=$((ISSUES+1))
fi

hdr "Keylogger indicators"
# 1. Library preload hooks
if [[ -s /etc/ld.so.preload ]]; then
    bad "/etc/ld.so.preload exists and is not empty — every process loads these libraries:"; sed 's/^/        /' /etc/ld.so.preload; ISSUES=$((ISSUES+1))
else
    ok "No /etc/ld.so.preload"
fi
pre="$(grep -ls 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/zsh/zshenv 2>/dev/null | tr '\n' ' ')"
[[ -n "$pre" ]] && { bad "LD_PRELOAD set system-wide in: $pre"; ISSUES=$((ISSUES+1)); }
# 2. Who holds the input devices right now
known='^(systemd|Xorg|Xwayland|weston|wayfire|labwc|sway|hyprland|kwin_wayland|gnome-shell|mutter|cage|cosmic-comp|river|niri|systemd-logind|upowerd|acpid|thd|triggerhappy|kodi|kodi\.bin|steam|steamwebhelper|gamescope|retroarch|lightdm|sddm|gdm|gdm-wayland-ses|pipewire|wireplumber)$'
holders="$(for fd in /proc/[0-9]*/fd/*; do
    t="$(readlink "$fd" 2>/dev/null)" || continue
    [[ "$t" == /dev/input/* ]] || continue
    pid="${fd#/proc/}"; pid="${pid%%/*}"
    echo "$pid"
done | sort -un)"
if [[ -z "$holders" ]]; then
    ok "No process currently holds an input device"
else
    while read -r pid; do
        comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null || echo '?')"
        usr="$(stat -c %U "/proc/$pid" 2>/dev/null)"
        if [[ "$exe" == *"(deleted)"* ]]; then
            bad "PID $pid ($comm, $usr) holds input devices from a DELETED binary: $exe"; ISSUES=$((ISSUES+1))
        elif [[ "$exe" == /tmp/* || "$exe" == /var/tmp/* || "$exe" == /dev/shm/* || "$exe" == /home/* || "$exe" == /root/* ]]; then
            bad "PID $pid ($comm, $usr) holds input devices, running from $exe"; ISSUES=$((ISSUES+1))
        elif [[ "$comm" =~ $known ]]; then
            ok "$comm (PID $pid, $usr) — expected to read input"
        else
            note "$comm (PID $pid, $usr) reads input devices — $exe   (unfamiliar? ps -fp $pid)"
        fi
    done <<< "$holders"
fi
# 3. Display server: on X11 any process on the display can sniff keys (XRecord), undetectably
xs="$(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}' | while read -r sid; do loginctl show-session "$sid" -p Type --value 2>/dev/null; done | grep -c '^x11$')"
if [[ "${xs:-0}" -gt 0 ]]; then note "X11 session active: any process on the display can read keystrokes — Wayland closes this"
else ok "No X11 session (Wayland/console only)"; fi

hdr "USB devices"
if command -v usbguard >/dev/null 2>&1 && systemctl is-active -q usbguard 2>/dev/null; then
    mode="$(grep -m1 '^ImplicitPolicyTarget=' /etc/usbguard/usbguard-daemon.conf 2>/dev/null | cut -d= -f2)"
    ok "USBGuard running (unknown devices: ${mode:-?})"
    # Current devices; flag HID (03) / network (02, e0) class devices that have no allow rule
    usbguard list-devices 2>/dev/null | while IFS= read -r line; do
        id="${line%%:*}"; state="$(echo "$line" | awk '{print $2}')"
        name="$(echo "$line" | grep -o 'name "[^"]*"' | cut -d'"' -f2)"
        vid="$(echo "$line" | grep -o 'id [0-9a-f:]*' | cut -d' ' -f2)"
        ifs="$(echo "$line" | grep -o 'with-interface {[^}]*}\|with-interface [0-9a-f:]*' | head -1)"
        serial="$(echo "$line" | grep -o 'serial "[^"]*"' | cut -d'"' -f2)"
        # interface codes are cc:ss:pp tokens; classify on the whole token, not a substring
        toks="$(echo "$ifs" | grep -oE '\b[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b')"
        cls=""
        echo "$toks" | grep -q '^03:' && cls="HID"
        echo "$toks" | grep -Eq '^(02:06:|02:00:|e0:01:03|ef:04:01)' && cls="${cls:+$cls+}NET"
        echo "$toks" | grep -q '^e0:01:01' && cls="${cls:+$cls+}BT"
        echo "$toks" | grep -q '^08:' && cls="${cls:+$cls+}STORAGE"
        [[ -z "$name" ]] && name="(no name)"
        if [[ "$state" == "block" || "$state" == "reject" ]]; then
            bad "BLOCKED  [$id] $vid ${name:-?} ${cls:+($cls)} — allow with: starhard-usb-allow $id"; ISSUES=$((ISSUES+1))
        elif [[ "$cls" == *HID* || "$cls" == *NET* ]] && ! grep -q "serial \"$serial\"" /etc/usbguard/rules.conf 2>/dev/null && ! grep -q "id $vid" /etc/usbguard/rules.conf 2>/dev/null; then
            note "allowed  [$id] $vid ${name:-?} ($cls) — not in the policy file (plugged in since setup)"
        else
            echo "          [$id] $vid ${name:-?}${cls:+ ($cls)}"
        fi
    done
    # Attach / block events this week
    if command -v ausearch >/dev/null 2>&1; then
        since="$(date -d "$DAYS days ago" '+%m/%d/%Y' 2>/dev/null)"
        ev="$(ausearch -m USER_DEVICE -ts "$since" 2>/dev/null | grep -c 'op=insert' || true)"
        bl="$(ausearch -m USER_DEVICE -ts "$since" 2>/dev/null | grep -c 'target=block\|target=reject' || true)"
        if [[ "${bl:-0}" -gt 0 ]]; then note "$ev USB attach event(s), $bl blocked   → ausearch -m USER_DEVICE -ts $since -i | grep -i block"
        elif [[ "${ev:-0}" -gt 0 ]]; then note "$ev USB attach event(s), none blocked   → ausearch -m USER_DEVICE -ts $since -i"
        else ok "No USB attach events in $DAYS days"; fi
    fi
    if systemctl is-enabled -q starhard-usb-lock.service 2>/dev/null && ! systemctl is-active -q starhard-usb-lock.service 2>/dev/null; then
        bad "lock-screen USB watcher not running"; ISSUES=$((ISSUES+1))
    fi
elif command -v usbguard >/dev/null 2>&1; then
    bad "USBGuard installed but not running"; ISSUES=$((ISSUES+1))
else
    note "USBGuard not installed — run StarHard section 20"
fi

hdr "Intrusion prevention"
if command -v cscli >/dev/null 2>&1 && systemctl is-active -q crowdsec 2>/dev/null; then
    n="$(cscli decisions list -o raw 2>/dev/null | tail -n +2 | grep -c . || true)"
    ok "CrowdSec running — $n active ban(s)   → cscli alerts list"
    if ! cscli bouncers list -o raw 2>/dev/null | grep -qi firewall; then bad "CrowdSec has NO firewall bouncer registered — it detects but does not block"; ISSUES=$((ISSUES+1)); fi
    if systemctl is-active -q fail2ban 2>/dev/null; then bad "fail2ban is ALSO running — two ban engines conflict; run: StarHard.sh --sections 8 --ids crowdsec"; ISSUES=$((ISSUES+1)); fi
elif command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active -q fail2ban 2>/dev/null; then
    b="$(fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $NF}')"
    t="$(fail2ban-client status sshd 2>/dev/null | grep 'Total banned' | awk '{print $NF}')"
    ok "fail2ban running — sshd: ${b:-0} banned now, ${t:-0} total"
else
    bad "No intrusion prevention service running"; ISSUES=$((ISSUES+1))
fi
if command -v ufw >/dev/null 2>&1; then
    ufw status 2>/dev/null | grep -q 'Status: active' && ok "ufw active" || { bad "ufw INACTIVE"; ISSUES=$((ISSUES+1)); }
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --state 2>/dev/null | grep -q running && ok "firewalld running" || { bad "firewalld not running"; ISSUES=$((ISSUES+1)); }
fi

hdr "Lynis"
if [[ -f /var/lib/starhard/lynis-index ]]; then
    read -r ts idx < <(tail -n1 /var/lib/starhard/lynis-index)
    note "Hardening index $idx/100 (run $ts)   → starhard.sh --audit for a fresh one"
fi

echo
if [[ $ISSUES -eq 0 ]]; then echo -e "${G}Nothing needs attention.${N}"; else echo -e "${R}$ISSUES item(s) need attention.${N}"; fi
EOF

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
            if [[ $IS_PI -eq 1 ]] || ls /etc/apt/sources.list.d/raspi.list >/dev/null 2>&1; then
                # Kernel, firmware, EEPROM and Pi-specific packages come from archive.raspberrypi.com,
                # which is NOT a -security pocket — without this the Pi never gets kernel updates.
                write_file /etc/apt/apt.conf.d/53starhard-raspberrypi 644 <<'EOF'
// StarHard: include Raspberry Pi Foundation repos in unattended upgrades
Unattended-Upgrade::Origins-Pattern {
    "origin=Raspberry Pi Foundation,codename=${distro_codename}";
    "origin=Raspbian,codename=${distro_codename},label=Raspbian";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
};
EOF
                [[ $DRY_RUN -eq 0 ]] && log "unattended-upgrades: Raspberry Pi Foundation origin added"
            fi
            if [[ $HAS_TAILSCALE -eq 1 ]]; then
                write_file /etc/apt/apt.conf.d/54starhard-tailscale 644 <<'EOF'
// StarHard: keep the Tailscale client current (it's on your network edge)
Unattended-Upgrade::Origins-Pattern { "origin=Tailscale"; };
EOF
            fi
            [[ $HAS_PIHOLE -eq 1 ]] && info "Pi-hole updates itself with 'pihole -up' (not apt) — run it regularly or cron it"
            has_systemd && unit_exists unattended-upgrades.service && svc_enable unattended-upgrades
            case "$OS_ID" in
                kali|parrot)
                    warn "Rolling distro: '${OS_ID}' has no -security pocket; unattended-upgrades will do nothing. Update manually."
                    if [[ $DRY_RUN -eq 0 && -f /etc/starhard/ignore-units ]] && ! grep -q '^suricata' /etc/starhard/ignore-units; then
                        printf '# Pentest daemons that ship unconfigured on %s and fail at every boot\nhostapd-wpe\nisc-dhcp-server\nlighttpd-maint\nsslh\nsuricata\n' "$OS_ID" >> /etc/starhard/ignore-units
                        info "starhard-status: ignoring unconfigured pentest daemons (edit /etc/starhard/ignore-units)"
                    fi
                    ;;
            esac
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
    if [[ $IS_PI -eq 0 ]]; then
        tighten /boot/grub/grub.cfg 0600
        tighten /boot/grub2/grub.cfg 0600
    fi
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
    if [[ $IS_PI -eq 1 ]]; then
        info "Raspberry Pi has no GRUB — bootloader handled in section 19"
        return 0
    fi
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
        local hash pw1 pw2
        while :; do
            read -r -s -p "  GRUB password: " pw1; echo
            read -r -s -p "  Confirm:       " pw2; echo
            [[ -z "$pw1" ]] && { err "Empty password — aborting GRUB step"; return 0; }
            [[ "$pw1" == "$pw2" ]] && break
            warn "Passwords do not match — try again"
        done
        hash="$(printf '%s\n%s\n' "$pw1" "$pw1" | "$mkpw" 2>/dev/null | grep -o 'grub\.pbkdf2\.sha512\..*' || true)"
        unset pw1 pw2
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
        STRG-1840|STRG-1846|NETW-3200|FILE-6430) echo 3 ;;
        AUTH-9228|AUTH-9229|AUTH-9230|AUTH-9262|AUTH-9286|AUTH-9328|AUTH-9408|SCHD-7704) echo 4 ;;
        SSH-*) echo 6 ;;
        FIRE-4508|FIRE-4512|FIRE-4534) echo 7 ;;
        ACCT-*) echo 9 ;;
        FINT-*) echo 10 ;;
        MALW-*) echo 11 ;;
        PKGS-7390|PKGS-7398|PKGS-7420|DEB-0810|DEB-0880) echo 12 ;;
        BANN-*|FILE-7524) echo 13 ;;
        MACF-*) echo 14 ;;
        FILE-6336|FILE-6344|LOGG-2138) echo 15 ;;
        PKGS-7346|PKGS-7382) echo 16 ;;
        BOOT-5122) echo 17 ;;
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
            if [[ "$id" == "NETW-3015" && "$desc$detail" =~ (tailscale|wg[0-9]|tun[0-9]|zt[a-z0-9]+|nebula) ]]; then
                printf '  -> n/a (VPN tunnel interface; expected)'
            elif [[ "$id" == "NETW-3015" ]]; then
                printf '  -> check: bridge link; ss -0lp  (bridge member or packet sniffer?)'
            elif [[ -n "$sec" ]]; then
                printf '  -> StarHard section %s' "$sec"
            fi
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
            if [[ "$id" == "AUTH-9230" ]] && grep -Eq '^\s*ENCRYPT_METHOD\s+YESCRYPT' /etc/login.defs 2>/dev/null; then
                printf '  %-10s %s  -> n/a (yescrypt in use; SHA rounds do not apply)\n' "$id" "$desc"
                continue
            fi
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
# 19. Raspberry Pi (runs only when a Pi is detected)
#===============================================================================
pi_default_iface() { ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}'; }

pi_add_overlay() {
    # pi_add_overlay <overlay>  — appends dtoverlay=<overlay> under an [all] section, idempotent
    local ov="$1" cfg="$PI_BOOT/config.txt"
    if grep -Eq "^\s*dtoverlay=$ov\b" "$cfg"; then
        info "dtoverlay=$ov already present"
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would add dtoverlay=$ov to $cfg"; return 0; fi
    backup_file "$cfg"
    {
        echo
        echo "[all]"
        echo "# StarHard"
        echo "dtoverlay=$ov"
    } >> "$cfg"
    log "Added dtoverlay=$ov to $cfg (takes effect after reboot)"
}

sec_pi() {
    if [[ $IS_PI -eq 0 ]]; then
        info "Not a Raspberry Pi — skipped"
        return 0
    fi
    log "Detected: $PI_MODEL"
    if [[ -z "$PI_BOOT" ]]; then
        warn "config.txt not found under /boot/firmware or /boot — skipping boot-config changes"
    fi

    # --- Bootloader reality check
    warn "No bootloader password exists on a Raspberry Pi. Anyone with the SD card / NVMe has full access."
    if ! lsblk -o TYPE 2>/dev/null | grep -q crypt; then
        warn "Root filesystem is not encrypted. For data at rest use LUKS on a data partition (cryptsetup), or"
        warn "an encrypted root via 'rpi-image-gen' / 'raspi-config > Advanced > Encrypt' where your OS release offers it."
    else
        log "Encrypted block device detected"
    fi

    # --- EEPROM bootloader firmware (Pi 4/5/CM4/CM5)
    if command -v rpi-eeprom-update >/dev/null 2>&1; then
        local ee
        ee="$(rpi-eeprom-update 2>/dev/null || true)"
        echo "$ee" | grep -E 'CURRENT|LATEST|RELEASE|BOOTLOADER' | sed 's/^/    /'
        if echo "$ee" | grep -q 'UPDATE AVAILABLE'; then
            if [[ $DRY_RUN -eq 1 ]]; then
                info "DRY-RUN: would stage EEPROM bootloader update (rpi-eeprom-update -a)"
            elif [[ $ASSUME_YES -eq 1 ]] || ask "EEPROM bootloader update available — stage it for next reboot?"; then
                run "stage EEPROM update" rpi-eeprom-update -a
            fi
        else
            log "EEPROM bootloader is up to date"
        fi
        has_systemd && unit_exists rpi-eeprom-update.service && svc_enable rpi-eeprom-update.service
    else
        info "rpi-eeprom-update not installed (only relevant for Pi 4/5 family) — apt install rpi-eeprom"
    fi

    # --- Radios via device-tree overlays (cuts power to the chip; cleaner than module blacklists)
    if [[ -n "$PI_BOOT" ]]; then
        if [[ $PI_DISABLE_BT -eq 1 ]]; then
            pi_add_overlay disable-bt
            has_systemd && unit_exists hciuart.service && svc_mask hciuart.service
            has_systemd && unit_exists bluetooth.service && svc_mask bluetooth.service
        fi
        if [[ $PI_DISABLE_WIFI -eq 1 ]]; then
            local dif
            dif="$(pi_default_iface)"
            if [[ "$dif" == wl* ]]; then
                err "Default route is via $dif (Wi-Fi) — REFUSING to disable Wi-Fi, you would lose the box"
            elif [[ $SSH_ACTIVE -eq 1 && "$(ip -o addr show 2>/dev/null | awk -v ip="$(echo "$SSH_CONNECTION" | awk '{print $3}')" '$4 ~ "^"ip"/" {print $2; exit}')" == wl* ]]; then
                err "This SSH session arrived over Wi-Fi — REFUSING to disable Wi-Fi"
            else
                pi_add_overlay disable-wifi
                [[ $DRY_RUN -eq 0 ]] && command -v rfkill >/dev/null 2>&1 && rfkill block wlan 2>/dev/null || true
            fi
        fi
    fi

    # --- Memory note for the weekly scan
    local mem_mb
    mem_mb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
    if [[ $mem_mb -lt 3000 ]]; then
        warn "${mem_mb} MB RAM: the weekly ClamAV scan auto-skips when <1.5 GB is free. Run it manually at idle: sudo starhard-scan"
    fi

    # --- Serial console: a physical UART login bypasses everything above
    if [[ -n "$PI_BOOT" && -f "$PI_BOOT/cmdline.txt" ]] && grep -q 'console=serial0' "$PI_BOOT/cmdline.txt"; then
        if [[ "$PROFILE" == "server" ]]; then
            if [[ $DRY_RUN -eq 0 ]]; then
                backup_file "$PI_BOOT/cmdline.txt"
                sed -i 's/console=serial0,[0-9]* //' "$PI_BOOT/cmdline.txt"
                log "Serial console login removed from cmdline.txt (server profile)"
            else
                info "DRY-RUN: would remove console=serial0 from cmdline.txt"
            fi
        else
            info "Serial console login is enabled in cmdline.txt (fine for a desktop; server profile removes it)"
        fi
    fi
    return 0
}

#===============================================================================
# 20. USB device control (USBGuard) — every profile
#===============================================================================
sec_usb() {
    if ! has_systemd; then info "USBGuard setup requires systemd — skipping"; return 0; fi
    if ! command -v usbguard >/dev/null 2>&1; then
        if [[ "$PKG" == "apk" ]]; then info "usbguard is not packaged for Alpine — skipping"; return 0; fi
        info "usbguard not installed — installing"
        pkg_install usbguard
        if [[ $DRY_RUN -eq 0 ]] && ! command -v usbguard >/dev/null 2>&1; then
            warn "usbguard failed to install (see $LOG_FILE) — skipping USB device control"
            return 0
        fi
        # Fresh install: the package may auto-start with an empty policy. Stop it until our policy is in place.
        [[ $DRY_RUN -eq 0 ]] && systemctl stop usbguard >/dev/null 2>&1 || true
    fi

    local rules=/etc/usbguard/rules.conf conf=/etc/usbguard/usbguard-daemon.conf
    local rulesd=/etc/usbguard/rules.d sh_rules=/etc/usbguard/rules.d/50-starhard.conf

    # Base policy: everything attached right now is allowed. Never regenerate an existing policy.
    if [[ ! -s "$rules" ]]; then
        if [[ $DRY_RUN -eq 0 ]]; then
            mkdir -p /etc/usbguard
            record_rm "$rules"
            usbguard generate-policy > "$rules" 2>>"$LOG_FILE" && chmod 600 "$rules"
            log "USBGuard: $(grep -c '^allow' "$rules") currently attached device(s) allowed"
        else
            info "DRY-RUN: would snapshot attached devices into $rules"
        fi
    else
        info "USBGuard policy already exists ($(grep -c '^allow' "$rules" 2>/dev/null || echo '?') allow rules) — keeping it"
    fi

    # StarHard rules live in rules.d/ (usbguard RuleFolder), read AFTER rules.conf so the device
    # allow-list always wins. Kept separate because usbguard <1.1.4's postinst regenerates rules.conf
    # on upgrade (Debian #1134796) and would otherwise erase these.
    [[ -d "$rulesd" ]] || { [[ $DRY_RUN -eq 0 ]] && mkdir -p "$rulesd" && chmod 700 "$rulesd"; }
    # Migrate rules a previous StarHard run appended to rules.conf
    if [[ $DRY_RUN -eq 0 && -f "$rules" ]] && grep -q '# StarHard' "$rules"; then
        backup_file "$rules"
        sed -i '/^# StarHard/,$d' "$rules"
        info "USBGuard: moved StarHard rules out of rules.conf into $sh_rules"
    fi
    if [[ "$PROFILE" == "server" ]]; then
        write_file "$sh_rules" 600 <<'EOF'
# StarHard (server): anything not in rules.conf is blocked. Authorise with: starhard-usb-allow <id>
block
EOF
    else
        write_file "$sh_rules" 600 <<'EOF'
# StarHard (desktop): known devices are allowed by rules.conf. Two hard blocks regardless of lock state:
#  - a device that presents as a network adapter (PoisonTap / rogue USB-Ethernet)
#  - a hub that also carries a HID interface (common in keystroke-injector cables)
block with-interface one-of { 02:06:00 02:00:00 e0:01:03 ef:04:01 }
block with-interface all-of { 09:00:00 03:00:00 }
# New keyboards/HID while the screen is locked are handled by starhard-usb-lock.service
EOF
    fi

    # Daemon config: desktop audits new devices (apply-policy but implicit target allow), server blocks.
    if [[ -f "$conf" ]]; then
        backup_file "$conf"
        if [[ $DRY_RUN -eq 0 ]]; then
            local implicit="allow"; [[ "$PROFILE" == "server" ]] && implicit="block"
            sed -i -E "s/^ImplicitPolicyTarget=.*/ImplicitPolicyTarget=$implicit/" "$conf"
            sed -i -E 's/^PresentDevicePolicy=.*/PresentDevicePolicy=apply-policy/' "$conf"
            sed -i -E 's/^PresentControllerPolicy=.*/PresentControllerPolicy=keep/' "$conf"
            sed -i -E 's/^InsertedDevicePolicy=.*/InsertedDevicePolicy=apply-policy/' "$conf"
            sed -i -E 's/^AuditBackend=.*/AuditBackend=LinuxAudit/' "$conf"
            grep -q '^AuditBackend=' "$conf" || echo 'AuditBackend=LinuxAudit' >> "$conf"
            # Read our rules from rules.d/
            if grep -q '^#*\s*RuleFolder=' "$conf"; then sed -i -E "s|^#*\s*RuleFolder=.*|RuleFolder=$rulesd/|" "$conf"; else echo "RuleFolder=$rulesd/" >> "$conf"; fi
            # IPC: root only (Debian #1134751 — plugdev granted full control). starhard-usb-allow runs as root anyway.
            sed -i -E 's/^IPCAllowedUsers=.*/IPCAllowedUsers=root/' "$conf"
            grep -q '^IPCAllowedUsers=' "$conf" || echo 'IPCAllowedUsers=root' >> "$conf"
            sed -i -E 's/^IPCAllowedGroups=.*/IPCAllowedGroups=/' "$conf"
            log "USBGuard daemon: implicit target '$implicit', rules.d enabled, IPC root-only, audit via auditd"
        fi
    fi

    # Desktop: block NEW HID (keyboards/mice/injectors) while the screen is locked.
    # Implemented as a logind hook that swaps the implicit policy, so nothing is lost on unlock.
    if [[ "$PROFILE" != "server" ]]; then
        write_file /usr/local/sbin/starhard-usb-lockhook 755 <<'EOF'
#!/bin/sh
# Called by starhard-usb-lock.service on screen lock/unlock. lock = block new HID; unlock = allow again.
case "$1" in
    lock)   usbguard set-parameter ImplicitPolicyTarget block >/dev/null 2>&1 ;;
    unlock) usbguard set-parameter ImplicitPolicyTarget allow >/dev/null 2>&1 ;;
esac
EOF
        # A tiny watcher on the session Lock/Unlock signals (works for GNOME, KDE, labwc/swaylock via logind)
        write_file /usr/local/sbin/starhard-usb-lockwatch 755 <<'EOF'
#!/bin/sh
# Follows logind LockedHint across all sessions; toggles USBGuard's implicit policy.
state=""
while :; do
    locked=0
    for sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
        [ "$(loginctl show-session "$sid" -p LockedHint --value 2>/dev/null)" = "yes" ] && locked=1
    done
    if [ "$locked" = "1" ] && [ "$state" != "locked" ]; then /usr/local/sbin/starhard-usb-lockhook lock; state=locked; fi
    if [ "$locked" = "0" ] && [ "$state" != "unlocked" ]; then /usr/local/sbin/starhard-usb-lockhook unlock; state=unlocked; fi
    sleep 3
done
EOF
        write_file /etc/systemd/system/starhard-usb-lock.service 644 <<'EOF'
[Unit]
Description=StarHard: block new USB devices while the screen is locked
After=usbguard.service
Requires=usbguard.service

[Service]
ExecStart=/usr/local/sbin/starhard-usb-lockwatch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        [[ $DRY_RUN -eq 0 ]] && systemctl daemon-reload
    fi

    # One-command authorise helper
    write_file /usr/local/sbin/starhard-usb-allow 755 <<'EOF'
#!/usr/bin/env bash
# starhard-usb-allow [id]   — permanently allow a USB device. No id: list blocked devices.
[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
if [[ -z "${1:-}" ]]; then
    echo "Blocked / rejected devices:"; usbguard list-devices -b 2>/dev/null || echo "  (none)"
    echo; echo "All devices:"; usbguard list-devices 2>/dev/null
    echo; echo "Usage: starhard-usb-allow <id>"; exit 0
fi
usbguard allow-device -p "$1" && echo "Device $1 allowed permanently (rule appended to /etc/usbguard/rules.conf)"
EOF

    svc_enable usbguard
    [[ "$PROFILE" != "server" ]] && svc_enable starhard-usb-lock.service

    if [[ "$PROFILE" == "server" ]]; then
        warn "USBGuard BLOCKS every USB device not attached right now. Authorise new ones: starhard-usb-allow <id>"
    else
        info "USBGuard: logging all attaches; USB network adapters and HID-hubs blocked; new HID blocked while screen is locked"
    fi
    return 0
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
[[ $IS_PI -eq 1 ]] && section 19 "Raspberry Pi" sec_pi
section 20 "USB device control"                sec_usb
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
echo "  15 ctrl-alt-del masked, persistent journald, /dev/shm noexec$( [[ "$PROFILE" == "server" ]] && echo ', /tmp noexec, avahi/cups/bt masked')"
echo "  16 Cleanup: legacy packages, residuals, old kernels, docker (opt-in)"
echo "  17 GRUB password (interactive)"
echo "  18 Lynis audit run, warnings/suggestions mapped to sections, index tracked in $STATE_DIR/lynis-index"
echo "  20 USBGuard: $( [[ "$PROFILE" == "server" ]] && echo 'block unknown devices' || echo 'audit mode + block USB-network/HID-hub + block new HID while locked' ) — authorise: starhard-usb-allow <id>"
[[ $IS_PI -eq 1 ]] && echo "  19 Raspberry Pi: EEPROM, boot-config auditing, Pi update origin, radios$( [[ "$PROFILE" == "server" ]] && echo ', serial console')"
echo
echo "Backups + rollback script: $BACKUP_DIR"
echo "Log: $LOG_FILE"
echo
echo "Next steps:"
echo "  1. Reboot"
echo "  2. Verify:  sudo $0 --audit --profile $PROFILE --ids $IDS"
echo "  3. Status:  sudo starhard-status   (one-screen digest: scans, AIDE, audit, bans, updates)"
echo "  4. Scan:    sudo /usr/local/sbin/starhard-scan   (also runs weekly)"
echo "  5. Lynis:   see section 18 output above; 'lynis show details <TEST-ID>' for any item"
echo "  6. Undo:    sudo bash $ROLLBACK  (then reboot)"
echo "==============================================================="
