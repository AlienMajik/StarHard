#!/usr/bin/env bash
#===============================================================================
# StarHard.sh  v1.3
# Universal Linux hardening script (Debian/Ubuntu/Parrot/Kali, RHEL/Fedora/
# Rocky/Alma, openSUSE, Arch, Alpine).
#
# v1.3 changes:
#   * SSH drop-in renamed 00-starhard.conf so it is read before cloud-init's
#     (sshd keeps the FIRST value it sees); effective config verified with sshd -T
#   * CrowdSec repository added from a repo file + signing key pinned by
#     fingerprint (no more "curl | bash" as root)
#   * sudo log_input removed (it wrote typed passwords to disk)
#   * Firewall: Docker-published ports are called out as bypassing ufw/firewalld;
#     firewalld gets Pi-hole rules scoped to LAN subnets; hosts with only nftables
#     (Alpine) get a real default-deny table instead of an inert example file;
#     every added rule and the previous defaults are recorded for rollback
#   * pam_faillock wired through pam-auth-update profiles (survives PAM upgrades)
#   * cron/at restricted to root on the server profile only
#   * starhard-status: exit code, --json, --quiet; starhard-notify + daily timer
#     with hooks in /etc/starhard/notify.d (mail, ntfy, webhook, desktop, MOTD);
#     repeated low-memory ClamAV skips escalate to an issue
#   * --audit verifies every sysctl, module, sshd option and audit-rule key that
#     the apply pass writes (shared tables); options persist in /etc/starhard/config
#   * --rollback original|latest|<timestamp>: the first-ever state of every file,
#     mode, service and firewall setting is kept in /var/backups/starhard/original
#   * auditd: delete/perm_mod rules narrowed on desktop, log retention raised;
#     AIDE baseline refreshed automatically after package transactions;
#     USB lock watcher is event-driven and fails closed
#   * Opt-in sections: 21 kernel boot parameters (--boot-params), 22 systemd
#     sandboxing for network daemons (--sandbox-services), 23 Docker daemon
#     (--docker-harden), 24 DNS-over-TLS / NTS time (--secure-dns, --secure-time)
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

VERSION="1.3"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/starhard/$TS"
LOG_DIR="/var/log/starhard"
LOG_FILE="$LOG_DIR/starhard-$TS.log"
ROLLBACK="$BACKUP_DIR/rollback.sh"
ORIG_DIR="/var/backups/starhard/original"   # first-ever state of everything StarHard touched
CONF_FILE="/etc/starhard/config"            # options from the last run (defaults for the next)
STATE_DIR="/var/lib/starhard"

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
# Opt-in sections (21-24)
BOOT_PARAMS=0; BOOT_LOCKDOWN=0; SANDBOX=0; DOCKER_HARDEN=0; SECURE_DNS=""; SECURE_TIME=0
ROLLBACK_TARGET=""; CONF_LOADED=0
# CrowdSec packagecloud signing key (primary key fingerprint). The key is downloaded, its
# fingerprint compared with this value, and only then trusted — for this one repository.
CROWDSEC_KEY_FPR="6A89E3C2303A901A889971D3376ED5326E93CD0C"
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

# Rollback bookkeeping. Two levels:
#   per run   $BACKUP_DIR/rollback.sh          undoes THIS run (back to the state just before it)
#   original  $ORIG_DIR/{files,created,commands} the state before StarHard first touched each thing;
#             only the FIRST record for a file / mode / service / firewall setting is kept, so
#             re-running StarHard never overwrites it with already-hardened state.
_rb() {
    # append a line to this run's rollback script only
    [[ $DRY_RUN -eq 0 ]] && echo "$1" >> "$ROLLBACK"
    return 0
}

orig_key() {
    # orig_key <command> -> the thing the command restores (one original record per key)
    local c="${1//\'/}" w
    read -r -a w <<< "$c"
    case "$c" in
        "chmod "*)                     echo "mode:${w[2]:-}" ;;
        "systemctl disable --now "*|"systemctl enable --now "*) echo "svc:${w[3]:-}" ;;
        "systemctl unmask "*)          echo "mask:${w[2]:-}" ;;
        "rc-update "*)                 echo "svc:${w[2]:-}" ;;
        "ufw default "*)               echo "ufwdefault:${w[3]:-}" ;;
        "firewall-cmd --set-default-zone="*) echo "firewalld-default-zone" ;;
        *)                             echo "cmd:$c" ;;
    esac
}

orig_seen() {
    # orig_seen <key> -> 0 if the original state for this key is already on record
    grep -qxF -- "$1" "$ORIG_DIR/keys" 2>/dev/null
}

orig_mark() {
    # the thing was already in its target state when StarHard first met it: nothing to undo, ever
    [[ $DRY_RUN -eq 0 && -d "$ORIG_DIR" ]] || return 0
    orig_seen "$1" || echo "$1" >> "$ORIG_DIR/keys"
    return 0
}

orig_cmd() {
    [[ $DRY_RUN -eq 0 && -d "$ORIG_DIR" ]] || return 0
    local key; key="$(orig_key "$1")"
    orig_seen "$key" && return 0
    echo "$key" >> "$ORIG_DIR/keys"
    echo "$1" >> "$ORIG_DIR/commands"
}

rb() {
    # append a line to the rollback script (and keep the first such record as the original state)
    [[ $DRY_RUN -eq 0 ]] || return 0
    echo "$1" >> "$ROLLBACK"
    orig_cmd "$1"
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
    _rb "cp -a '$dest' '$f'"
    # first time StarHard touches this file, and StarHard did not create it: this IS the original
    if [[ -d "$ORIG_DIR" && ! -e "$ORIG_DIR/files$f" ]] && ! grep -qxF -- "$f" "$ORIG_DIR/created" 2>/dev/null; then
        mkdir -p "$(dirname "$ORIG_DIR/files$f")"
        cp -a "$f" "$ORIG_DIR/files$f"
    fi
    return 0
}

record_rm() {
    # file created by this run -> rollback removes it
    _rb "rm -f '$1'"
    [[ $DRY_RUN -eq 0 && -d "$ORIG_DIR" ]] || return 0
    if [[ ! -e "$ORIG_DIR/files$1" ]] && ! grep -qxF -- "$1" "$ORIG_DIR/created" 2>/dev/null; then
        echo "$1" >> "$ORIG_DIR/created"
    fi
    return 0
}

seed_original() {
    # First 1.3 run on a box that earlier versions already hardened: rebuild the original state
    # from the per-run backups, oldest first (the oldest copy of a file is the pristine one).
    [[ -d "$ORIG_DIR" ]] && return 0
    mkdir -p "$ORIG_DIR/files"
    : > "$ORIG_DIR/created"; : > "$ORIG_DIR/commands"; : > "$ORIG_DIR/keys"
    chmod 700 "$ORIG_DIR"
    local d f rel line seeded=0
    while IFS= read -r d; do
        d="${d%/}"
        [[ "$d" == "$BACKUP_DIR" || ! -d "$d" ]] && continue
        seeded=$((seeded+1))
        while IFS= read -r -d '' f; do
            rel="${f#"$d"}"
            [[ "$rel" == "/rollback.sh" || -e "$ORIG_DIR/files$rel" ]] && continue
            grep -qxF -- "$rel" "$ORIG_DIR/created" && continue
            mkdir -p "$(dirname "$ORIG_DIR/files$rel")"
            cp -a "$f" "$ORIG_DIR/files$rel"
        done < <(find "$d" \( -type f -o -type l \) -print0 2>/dev/null)
        [[ -r "$d/rollback.sh" ]] || continue
        while IFS= read -r line; do
            case "$line" in
                "rm -f '"*"'")
                    rel="${line#rm -f \'}"; rel="${rel%\'}"
                    if [[ "$rel" != *"'"* ]]; then
                        [[ -e "$ORIG_DIR/files$rel" ]] || grep -qxF -- "$rel" "$ORIG_DIR/created" || echo "$rel" >> "$ORIG_DIR/created"
                    else
                        orig_cmd "$line"
                    fi ;;
                "cp -a "*|"#"*|"set -x"|""|"echo "*|"systemctl daemon-reload"*|"sysctl -e --system"*) ;;
                *) orig_cmd "$line" ;;
            esac
        done < "$d/rollback.sh"
    done < <(ls -d /var/backups/starhard/[0-9]*-[0-9]*/ 2>/dev/null | sort)
    if [[ $seeded -gt 0 ]]; then
        info "Original-state record created in $ORIG_DIR (rebuilt from $seeded earlier run(s))"
    fi
    return 0
}

write_original_rollback() {
    # (re)generate $ORIG_DIR/rollback.sh from the original-state record
    [[ -d "$ORIG_DIR" ]] || return 1
    local out="$ORIG_DIR/rollback.sh" f rel
    {
        echo "#!/usr/bin/env bash"
        echo "# StarHard: return to the state before StarHard FIRST ran on this machine."
        echo "# Generated $(date '+%F %T') — regenerated on every run. Review before running. Reboot afterwards."
        echo "set -x"
        echo "# --- services, file modes, firewall rules"
        cat "$ORIG_DIR/commands" 2>/dev/null
        echo "# --- files as they were"
        while IFS= read -r -d '' f; do
            rel="${f#"$ORIG_DIR/files"}"
            echo "cp -a '$f' '$rel'"
        done < <(find "$ORIG_DIR/files" \( -type f -o -type l \) -print0 2>/dev/null | sort -z)
        echo "# --- files StarHard created"
        while IFS= read -r rel; do
            [[ -n "$rel" ]] && echo "rm -f '$rel'"
        done < "$ORIG_DIR/created"
        echo "command -v pam-auth-update >/dev/null 2>&1 && pam-auth-update --package 2>/dev/null || true"
        echo "systemctl daemon-reload 2>/dev/null || true"
        echo "sysctl -e --system >/dev/null 2>&1 || true"
        echo "command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --reload 2>/dev/null || true"
        echo "echo 'Rollback to the original state complete — reboot now. Installed packages are left in place.'"
    } > "$out"
    chmod 700 "$out"
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
        if [[ $DRY_RUN -eq 0 ]]; then
            if systemctl is-enabled -q "$s" 2>/dev/null; then orig_mark "svc:$s"
            else rb "systemctl disable --now '$s' 2>/dev/null || true"; fi
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
    if [[ $DRY_RUN -eq 0 ]]; then
        if systemctl is-enabled "$s" 2>/dev/null | grep -q masked; then orig_mark "mask:$s"
        else rb "systemctl unmask '$s' 2>/dev/null || true"; fi
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
  --rollback <what>     Undo: 'original' (state before StarHard first ran), 'latest' (the last run),
                        or a run timestamp from /var/backups/starhard/
  -y, --yes             Assume "yes" to optional prompts (non-interactive)
  -V, --version         Print the version
  -h, --help            This help

Opt-in hardening (off unless asked for; remembered for later runs once used):
  --boot-params         Section 21: kernel boot parameters (init_on_alloc, slab_nomerge, ...). Needs a reboot
  --boot-lockdown       Section 21: also add lockdown=integrity (blocks unsigned modules: breaks
                        VirtualBox / NVIDIA DKMS without module signing, and hibernation)
  --sandbox-services    Section 22: systemd sandboxing drop-ins for network-facing daemons; each unit is
                        restarted and the drop-in is removed again if the service does not come back
  --docker-harden       Section 23: Docker daemon.json (no-new-privileges, icc off, log limits, live-restore)
  --secure-dns <p>      Section 24: DNS-over-TLS through systemd-resolved; provider quad9 or cloudflare
  --secure-time         Section 24: authenticated time (NTS) through chrony

Options from the last run are stored in $CONF_FILE and used as defaults; flags override them.
Each opt-in has a --no-<name> form (e.g. --no-boot-lockdown) that stops applying and auditing it.

Sections:
   1 packages            7 firewall             13 banners/perms/sudo
   2 sysctl              8 IPS (crowdsec/fail2ban) 14 AppArmor/SELinux
   3 kernel modules      9 auditd + acct        15 services/mounts/journald
   4 auth policy        10 AIDE + timer         16 cleanup
   5 core dumps         11 malware/rootkit scan 17 GRUB password (interactive)
   6 SSH                12 automatic updates    18 Lynis audit + report analysis
                                               19 Raspberry Pi (auto-detected)
                                               20 USB device control (USBGuard)
  Opt-in: 21 boot parameters   22 service sandboxing   23 Docker daemon   24 secure DNS/time
EOF
    exit 0
}

load_config() {
    # Parsed, never sourced: only known keys with known-good values are accepted.
    [[ -r "$CONF_FILE" ]] || return 0
    local k v
    while IFS='=' read -r k v; do
        case "$k" in
            PROFILE)    [[ "$v" =~ ^(desktop|server)$ ]] && PROFILE="$v" ;;
            IDS)        [[ "$v" =~ ^(crowdsec|fail2ban)$ ]] && IDS="$v" ;;
            PIHOLE_LAN) [[ "$v" =~ ^[01]?$ ]] && PIHOLE_LAN="$v" ;;
            SECURE_DNS) [[ "$v" =~ ^(quad9|cloudflare)?$ ]] && SECURE_DNS="$v" ;;
            PI_DISABLE_WIFI|PI_DISABLE_BT|BOOT_PARAMS|BOOT_LOCKDOWN|SANDBOX|DOCKER_HARDEN|SECURE_TIME)
                        [[ "$v" =~ ^[01]$ ]] && printf -v "$k" '%s' "$v" ;;
        esac
    done < "$CONF_FILE"
    CONF_LOADED=1
    return 0
}
load_config

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
        --boot-params)      BOOT_PARAMS=1 ;;
        --boot-lockdown)    BOOT_PARAMS=1; BOOT_LOCKDOWN=1 ;;
        --sandbox-services) SANDBOX=1 ;;
        --docker-harden)    DOCKER_HARDEN=1 ;;
        --secure-dns)       SECURE_DNS="${2:-}"; shift ;;
        --secure-time)      SECURE_TIME=1 ;;
        # stop applying/auditing a remembered opt-in (does not undo it — use --rollback for that)
        --no-boot-params)      BOOT_PARAMS=0; BOOT_LOCKDOWN=0 ;;
        --no-boot-lockdown)    BOOT_LOCKDOWN=0 ;;
        --no-sandbox-services) SANDBOX=0 ;;
        --no-docker-harden)    DOCKER_HARDEN=0 ;;
        --no-secure-dns)       SECURE_DNS="" ;;
        --no-secure-time)      SECURE_TIME=0 ;;
        --rollback)         ROLLBACK_TARGET="${2:-}"; [[ -n "$ROLLBACK_TARGET" ]] || { err "--rollback needs: original, latest or a run timestamp"; exit 1; }; shift ;;
        -y|--yes)   ASSUME_YES=1 ;;
        -V|--version) echo "StarHard $VERSION"; exit 0 ;;
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
[[ "$SECURE_DNS" =~ ^(quad9|cloudflare)?$ ]] || { err "--secure-dns takes quad9 or cloudflare"; exit 1; }
# Naming an opt-in section in --sections is asking for it
[[ ",$SECTIONS," == *",21,"* ]] && BOOT_PARAMS=1
[[ ",$SECTIONS," == *",22,"* ]] && SANDBOX=1
[[ ",$SECTIONS," == *",23,"* ]] && DOCKER_HARDEN=1
if [[ ",$SECTIONS," == *",24,"* && -z "$SECURE_DNS" && $SECURE_TIME -eq 0 ]]; then
    err "Section 24 needs --secure-dns <quad9|cloudflare> and/or --secure-time"; exit 1
fi

if [[ $EUID -ne 0 ]]; then
    err "Run as root: sudo $0"
    exit 1
fi

do_rollback() {
    local t="$ROLLBACK_TARGET" script=""
    case "$t" in
        original)
            [[ -d "$ORIG_DIR" ]] || { err "No original-state record in $ORIG_DIR (StarHard 1.3+ creates it on its first run)"; exit 1; }
            [[ $DRY_RUN -eq 0 ]] && write_original_rollback
            script="$ORIG_DIR/rollback.sh" ;;
        latest)
            script="$(ls -d /var/backups/starhard/[0-9]*-[0-9]*/ 2>/dev/null | sort | tail -1)rollback.sh" ;;
        *)
            [[ "$t" =~ ^[0-9]{8}-[0-9]{6}$ ]] || { err "--rollback takes original, latest or a timestamp like 20260101-120000"; exit 1; }
            script="/var/backups/starhard/$t/rollback.sh" ;;
    esac
    [[ -r "$script" ]] || { err "Rollback script not found: $script"; ls -d /var/backups/starhard/*/ 2>/dev/null | sed 's/^/    /'; exit 1; }
    echo "Rollback: $t"
    echo "  script:           $script"
    echo "  files restored:   $(grep -c '^cp -a ' "$script")"
    echo "  files removed:    $(grep -c '^rm -f ' "$script")"
    echo "  other steps:      $(grep -vcE '^(cp -a |rm -f |#|set -x|echo |$)' "$script")  (services, modes, firewall)"
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would run the script above. Read it first: less $script"
        exit 0
    fi
    warn "This undoes StarHard's hardening. If you are connected over SSH, the SSH and firewall settings revert too."
    ask "Run the rollback now?" || { info "Nothing changed"; exit 0; }
    bash "$script"; local rc=$?
    info "Rollback script finished (exit $rc). Reboot to finish (kernel modules, audit rules, boot parameters)."
    exit $rc
}
[[ -n "$ROLLBACK_TARGET" ]] && do_rollback

if [[ $DRY_RUN -eq 0 && $AUDIT -eq 0 ]]; then
    mkdir -p "$BACKUP_DIR" "$LOG_DIR"
    seed_original
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
                    local lb_tmp
                    lb_tmp="$(mktemp)" || lb_tmp=""
                    if [[ -n "$lb_tmp" ]]; then
                        awk -v pkg="$p" 'BEGIN{RS="";ORS="\n\n"} $0 !~ ("\nPackage: " pkg "\n")' /etc/apt/preferences.d/apt-listbugs > "$lb_tmp" \
                            && cat "$lb_tmp" > /etc/apt/preferences.d/apt-listbugs
                        rm -f "$lb_tmp"
                    fi
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
A_PASS=0; A_FAIL=0; G_PASS=0; G_FAIL=0; G_NA=0

#---------------------------------------------------------------- shared tables
# Single source of truth: the apply pass writes these, --audit verifies every line of them.
sysctl_table() {
    # rp_filter: strict (1) breaks Tailscale subnet routing/exit nodes; loose (2) keeps the anti-spoof benefit
    local rpf=1
    [[ $HAS_TAILSCALE -eq 1 ]] && rpf=2
    cat <<EOF
# === Kernel ===
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
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
net.ipv4.conf.all.rp_filter = $rpf
net.ipv4.conf.default.rp_filter = $rpf
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === IPv6 ===
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
    if [[ $HAS_SLAAC -eq 1 ]]; then
        echo "# accept_ra left at default: this host has a SLAAC IPv6 address and would lose it"
    else
        echo "net.ipv6.conf.all.accept_ra = 0"
        echo "net.ipv6.conf.default.accept_ra = 0"
    fi
}

module_list() {
    local mods=(dccp sctp rds tipc cramfs freevxfs jffs2 hfs hfsplus udf)
    # Firewire doesn't exist on a Pi; Bluetooth is cut at the device-tree level in section 19
    [[ $IS_PI -eq 0 ]] && mods+=(firewire-core)
    [[ "$PROFILE" == "server" && $IS_PI -eq 0 ]] && mods+=(bluetooth btusb)
    echo "${mods[@]}"
}

ssh_table() {
    # "Keyword value" lines for the sshd drop-in (crypto lists and AllowUsers are added separately)
    cat <<'EOF'
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
EOF
    if [[ "$PROFILE" == "server" ]]; then
        printf '%s\n' 'MaxAuthTries 4' 'MaxSessions 4' 'AllowTcpForwarding no' 'AllowAgentForwarding no'
    else
        printf '%s\n' 'MaxAuthTries 6' 'MaxSessions 10'
    fi
}

SSHD_EFFECTIVE=""
ssh_effective_is() {
    # ssh_effective_is <Keyword> <value> — compares with what sshd actually resolved (sshd -T)
    [[ -n "$SSHD_EFFECTIVE" ]] || SSHD_EFFECTIVE="$(sshd -T 2>/dev/null)"
    local have
    have="$(awk -v k="${1,,}" 'tolower($1)==k {$1=""; sub(/^ /,""); print; exit}' <<< "$SSHD_EFFECTIVE")"
    [[ "${have,,}" == "${2,,}" ]]
}

boot_param_list() {
    # kernel command-line parameters for the opt-in section 21
    local p="init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on"
    [[ "$ARCH" == "x86_64" ]] && p+=" vsyscall=none"
    [[ $BOOT_LOCKDOWN -eq 1 ]] && p+=" lockdown=integrity"
    echo "$p"
}

chkq() {
    # chkq <section> <description> <command...> — like chk, but a PASS is only counted, not printed.
    # Close a run of chkq calls with grp_end to print one summary line.
    local n="$1" d="$2"; shift 2
    should_run "$n" || return 0
    if "$@" >/dev/null 2>&1; then
        G_PASS=$((G_PASS+1)); A_PASS=$((A_PASS+1))
    else
        echo -e "${RED}FAIL${NC} [$n] $d"; G_FAIL=$((G_FAIL+1)); A_FAIL=$((A_FAIL+1))
    fi
}

grp_end() {
    # grp_end <section> <what was checked>
    should_run "$1" || { G_PASS=0; G_FAIL=0; G_NA=0; return 0; }
    local extra=""
    [[ $G_NA -gt 0 ]] && extra=" ($G_NA not available on this kernel/system, skipped)"
    if [[ $G_FAIL -eq 0 ]]; then
        echo -e "${GREEN}PASS${NC} [$1] all $G_PASS $2 match$extra"
    else
        echo -e "${YELLOW}    ${NC} [$1] $2: $G_PASS match, $G_FAIL differ (listed above)$extra"
    fi
    G_PASS=0; G_FAIL=0; G_NA=0
}

AUDIT_LOADED=""
auditd_num_logs_ok() {
    local n
    n="$(awk -F= '/^[[:space:]]*num_logs/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/audit/auditd.conf 2>/dev/null)"
    [[ "$n" =~ ^[0-9]+$ && "$n" -ge 10 ]]
}
audit_key_loaded() { grep -Eq -- "(-k |key=)$1( |\$)" <<< "$AUDIT_LOADED"; }
boot_param_active() { [[ " $(cat /proc/cmdline 2>/dev/null) " == *" $1 "* ]]; }
pam_module_present() {
    # (a plain "ls a b c" fails when any ONE path is missing, which hid the module on Debian)
    local f
    for f in /lib/security/"$1" /lib/*/security/"$1" /usr/lib/*/security/"$1" /usr/lib/security/"$1" /usr/lib64/security/"$1" /lib64/security/"$1"; do
        [[ -e "$f" ]] && return 0
    done
    return 1
}
pam_faillock_wired() { grep -qs 'pam_faillock' /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; }

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
    elif command -v nft >/dev/null 2>&1; then nft list table inet starhard 2>/dev/null | grep -q 'policy drop'
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
    local k v _eq
    while read -r k _eq v; do
        [[ -z "$k" || "$k" == \#* ]] && continue
        if ! sysctl -n "$k" >/dev/null 2>&1; then G_NA=$((G_NA+1)); continue; fi
        chkq 2 "sysctl $k is '$(sysctl -n "$k" 2>/dev/null)', expected $v" sysctl_is "$k" "$v"
    done < <(sysctl_table)
    grp_end 2 "sysctl settings"
    chk 3  "module blacklist present"                 test -f /etc/modprobe.d/hardening-blacklist.conf
    local m
    for m in $(module_list); do
        chkq 3 "module $m not blocked in hardening-blacklist.conf" grep -qx "install $m /bin/false" /etc/modprobe.d/hardening-blacklist.conf
        chkq 3 "module $m is still loaded (reboot, or it is in use)" bash -c "! lsmod | grep -q '^${m//-/_} '"
    done
    grp_end 3 "module blacklist checks"
    chk 4  "login.defs UMASK 027"                     grep -Eq '^UMASK\s+027' /etc/login.defs
    chk 4  "login.defs password hashing set (yescrypt/SHA512)" grep -Eq '^ENCRYPT_METHOD\s+(YESCRYPT|SHA512)' /etc/login.defs
    chk 4  "login.defs PASS_MAX_DAYS 365"             grep -Eq '^PASS_MAX_DAYS\s+365' /etc/login.defs
    chk 4  "pwquality policy present (minlen 14)"     grep -Eq '^minlen\s*=\s*14' /etc/security/pwquality.conf.d/50-hardening.conf
    chk 4  "faillock policy present"                  test -f /etc/security/faillock.conf
    chk 4  "pam_faillock active in the PAM stack"     pam_faillock_wired
    if [[ "$PROFILE" == "server" ]]; then
        chk 4 "cron.allow restricts to root (server)" grep -qx root /etc/cron.allow
    fi
    chk 5  "core dumps disabled (limits)"             test -f /etc/security/limits.d/50-nocoredump.conf
    [[ -d /etc/systemd ]] && \
    chk 5  "core dumps disabled (systemd-coredump)"   grep -qs '^Storage=none' /etc/systemd/coredump.conf.d/50-hardening.conf
    chk 5  "fs.suid_dumpable = 0"                     sysctl_is fs.suid_dumpable 0
    if command -v sshd >/dev/null 2>&1; then
        chk 6 "sshd drop-in is 00-starhard.conf (read first)" test -f /etc/ssh/sshd_config.d/00-starhard.conf
        chk 6 "old 50-hardening.conf drop-in is gone" test ! -e /etc/ssh/sshd_config.d/50-hardening.conf
        local kw val
        while read -r kw val; do
            [[ -n "$kw" ]] || continue
            chkq 6 "sshd effective $kw is not '$val' (another config file wins — check: sshd -T | grep -i $kw)" ssh_effective_is "$kw" "$val"
        done < <(ssh_table)
        grp_end 6 "effective sshd settings (sshd -T)"
        if [[ "$PROFILE" == "server" ]]; then
            chk 6 "sshd PasswordAuthentication no (server)" ssh_effective_is PasswordAuthentication no
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
    if [[ -r /etc/audit/rules.d/50-hardening.rules ]] && should_run 9; then
        AUDIT_LOADED="$(auditctl -l 2>/dev/null)"
        local key
        for key in $(grep -v '^#' /etc/audit/rules.d/50-hardening.rules | grep -oE -- '-k [A-Za-z0-9_-]+' | awk '{print $2}' | sort -u); do
            chkq 9 "audit rules with key '$key' are not loaded (reboot if audit is immutable, else: augenrules --load)" audit_key_loaded "$key"
        done
        grp_end 9 "audit rule keys loaded in the kernel"
    fi
    if [[ -f /etc/audit/auditd.conf ]]; then
        chk 9 "auditd keeps >= 10 rotated logs"       auditd_num_logs_ok
    fi
    chk 10 "AIDE database exists"                     bash -c '[[ -f /var/lib/aide/aide.db || -f /var/lib/aide/aide.db.gz ]]'
    chk 10 "AIDE check scheduled"                     aide_scheduled
    if has_systemd && [[ "$PKG" =~ ^(apt|dnf|pacman)$ ]]; then
        chk 10 "AIDE baseline auto-refresh after package changes" svc_active starhard-aide-refresh.path
    fi
    chk 11 "lynis + clamav installed"                 scanner_present
    chk 11 "ClamAV signature database present"        clam_db
    chk 11 "weekly starhard-scan timer active"        svc_active starhard-scan.timer
    chk 11 "starhard-status installed"                test -x /usr/local/sbin/starhard-status
    chk 11 "starhard-notify installed"                test -x /usr/local/sbin/starhard-notify
    has_systemd && \
    chk 11 "daily starhard-notify timer active"       svc_active starhard-notify.timer
    chk 12 "automatic security updates configured"    autoupd_cfg
    chk 13 "/etc/shadow not other-readable"           not_other_readable /etc/shadow
    chk 13 "/etc/gshadow not other-readable"          not_other_readable /etc/gshadow
    chk 13 "login banner present"                     grep -q 'AUTHORIZED USE ONLY' /etc/issue
    chk 13 "sudo hardening present (use_pty)"         grep -qs '^Defaults use_pty' /etc/sudoers.d/50-starhard
    chk 13 "sudo does not record typed input (log_input)" bash -c '! grep -rqsE "^Defaults.*\blog_input\b" /etc/sudoers.d/50-starhard'
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
    # --- opt-in sections: checked only when they were asked for (now or on an earlier run)
    if [[ $BOOT_PARAMS -eq 1 ]]; then
        local bp
        for bp in $(boot_param_list); do
            chkq 21 "boot parameter $bp not on the running kernel's command line (reboot?)" boot_param_active "$bp"
        done
        grp_end 21 "kernel boot parameters"
    fi
    if [[ $SANDBOX -eq 1 ]] && has_systemd; then
        local dropin unit
        for dropin in /etc/systemd/system/*.d/50-starhard-sandbox.conf; do
            [[ -f "$dropin" ]] || continue
            unit="$(basename "$(dirname "$dropin")" .d)"
            chk 22 "sandboxed unit $unit is running"   svc_active "$unit"
        done
    fi
    if [[ $DOCKER_HARDEN -eq 1 ]] && command -v docker >/dev/null 2>&1; then
        chk 23 "Docker: no-new-privileges set in daemon.json" grep -Eqs '"no-new-privileges"\s*:\s*true' /etc/docker/daemon.json
        chk 23 "Docker: inter-container traffic off (icc=false)" grep -Eqs '"icc"\s*:\s*false' /etc/docker/daemon.json
    fi
    if [[ -n "$SECURE_DNS" ]]; then
        chk 24 "systemd-resolved DNS-over-TLS configured" grep -Eqs '^DNSOverTLS=(yes|opportunistic)' /etc/systemd/resolved.conf.d/50-starhard.conf
    fi
    if [[ $SECURE_TIME -eq 1 ]]; then
        chk 24 "chrony has NTS time sources"          bash -c 'grep -rqsE "^(server|pool) .* nts" /etc/chrony /etc/chrony.conf /etc/chrony.d'
    fi
    echo "==============================================================="
    echo "  PASS: $A_PASS   FAIL: $A_FAIL"
    echo "==============================================================="
    [[ $A_FAIL -eq 0 ]]
}


echo "==============================================================="
echo "  StarHard v$VERSION"
echo "  OS: $OS_ID   Package manager: $PKG   Profile: $PROFILE   Arch: $ARCH   IPS: $IDS"
[[ $CONF_LOADED -eq 1 ]] && echo "  Options remembered from the last run: $CONF_FILE (flags override)"
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
            pkg_install aide "${f2b[@]}" audit lynis clamav sudo nftables
            ;;
    esac
    info "Not installed automatically (external repos): Wazuh agent (FIM/rootkit/log analysis) and Falco/Tetragon (eBPF runtime detection) are recommended on servers."
}

#===============================================================================
# 2. Kernel / sysctl hardening
#===============================================================================
sec_sysctl() {
    [[ $HAS_TAILSCALE -eq 1 ]] && info "Tailscale detected — rp_filter set to loose (2)"
    [[ $HAS_SLAAC -eq 1 ]] && info "SLAAC IPv6 address present — leaving accept_ra unchanged"
    sysctl_table | write_file /etc/sysctl.d/99-hardening.conf 644
    # -e: keys unknown to this kernel are ignored instead of failing the whole run
    run "Apply sysctl settings" sysctl -e --system
}

#===============================================================================
# 3. Blacklist rarely-used kernel modules
#===============================================================================
sec_modules() {
    local -a mods
    read -r -a mods <<< "$(module_list)"
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
            # drop trailing blank lines, or every run would leave one more behind
            sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' /etc/login.defs
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
    elif command -v pam-auth-update >/dev/null 2>&1 && [[ -d /usr/share/pam-configs ]]; then
        # Debian family: declare faillock as pam-auth-update profiles instead of editing common-auth.
        # pam-auth-update owns common-*; it computes the jump counts for whatever else is in the stack
        # (sssd, systemd-homed, fprintd ...) and re-applies the profiles after every PAM upgrade.
        if ! pam_module_present pam_faillock.so; then
            warn "pam_faillock.so not found — account lockout not configured"
        elif grep -ls 'pam_faillock' /usr/share/pam-configs/* 2>/dev/null | grep -qv '/starhard-faillock'; then
            info "This distro already ships a pam_faillock profile — leaving PAM wiring to it (policy: /etc/security/faillock.conf)"
        else
            # Earlier StarHard versions inserted the lines with sed. Take them out again, so the files
            # match what pam-auth-update generated and it agrees to manage them.
            if [[ ! -f /usr/share/pam-configs/starhard-faillock ]] && grep -qs 'pam_faillock' /etc/pam.d/common-auth /etc/pam.d/common-account; then
                if [[ $DRY_RUN -eq 0 ]]; then
                    backup_file /etc/pam.d/common-auth
                    backup_file /etc/pam.d/common-account
                    sed -i '/pam_faillock\.so/d' /etc/pam.d/common-auth /etc/pam.d/common-account
                    info "Removed the hand-inserted pam_faillock lines (replaced by pam-auth-update profiles)"
                else
                    info "DRY-RUN: would replace the hand-inserted pam_faillock lines with pam-auth-update profiles"
                fi
            fi
            write_file /usr/share/pam-configs/starhard-faillock 644 <<'EOF'
Name: StarHard: count failed logins and lock the account (pam_faillock)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
EOF
            write_file /usr/share/pam-configs/starhard-faillock-notify 644 <<'EOF'
Name: StarHard: refuse locked accounts before authenticating, reset the count on success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
EOF
            if [[ $DRY_RUN -eq 0 ]]; then
                backup_file /etc/pam.d/common-auth
                backup_file /etc/pam.d/common-account
                DEBIAN_FRONTEND=noninteractive pam-auth-update --package >> "$LOG_FILE" 2>&1 || true
                rb "command -v pam-auth-update >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive pam-auth-update --package 2>/dev/null || true"
                if ! grep -q 'pam_unix.so' /etc/pam.d/common-auth 2>/dev/null; then
                    err "common-auth lost pam_unix after pam-auth-update — restoring the previous PAM files"
                    cp -a "$BACKUP_DIR/etc/pam.d/common-auth" /etc/pam.d/common-auth
                    [[ -e "$BACKUP_DIR/etc/pam.d/common-account" ]] && cp -a "$BACKUP_DIR/etc/pam.d/common-account" /etc/pam.d/common-account
                    rm -f /usr/share/pam-configs/starhard-faillock /usr/share/pam-configs/starhard-faillock-notify
                elif grep -q 'pam_faillock' /etc/pam.d/common-auth; then
                    log "pam_faillock enabled through pam-auth-update profiles"
                else
                    warn "pam-auth-update did not apply the faillock profiles — /etc/pam.d/common-* carry local changes it will not overwrite."
                    warn "Review them, then run: pam-auth-update   (tick the two StarHard entries; --force discards the local changes)"
                fi
            else
                info "DRY-RUN: would run pam-auth-update to enable the faillock profiles"
            fi
        fi
    elif [[ -f /etc/pam.d/common-auth || -f /etc/pam.d/system-auth ]] && ! pam_faillock_wired; then
        warn "No authselect or pam-auth-update here — pam_faillock policy written to /etc/security/faillock.conf but not wired into PAM"
    fi

    # cron/at: root-only on servers. Desktops keep user crontabs.
    local f
    if [[ "$PROFILE" == "server" ]]; then
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
    else
        # Undo the root-only restriction StarHard <= 1.2 applied on every profile
        local deny
        for f in /etc/cron.allow /etc/at.allow; do
            [[ -f "$f" && "$(cat "$f" 2>/dev/null)" == "root" ]] || continue
            if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would remove the root-only $f (desktop profile)"; continue; fi
            backup_file "$f"; rm -f "$f"
            deny="${f%.allow}.deny"
            if [[ ! -e "$deny" ]]; then record_rm "$deny"; : > "$deny"; chmod 644 "$deny"; fi
            info "Desktop profile: removed the root-only $f — users can use $(basename "$f" .allow) again (server profile restricts it)"
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
    # sshd keeps the FIRST value it reads for each keyword and reads sshd_config.d in name order.
    # "50-hardening.conf" lost to cloud-init's "50-cloud-init.conf" (PasswordAuthentication); "00-" wins.
    local cfg=/etc/ssh/sshd_config dropin=/etc/ssh/sshd_config.d/00-starhard.conf
    local old_dropin=/etc/ssh/sshd_config.d/50-hardening.conf
    local changed_main=0 removed_old=0

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

    local pw_line=""
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
        [[ $HAS_PIHOLE -eq 1 ]] && info "Server profile disables SSH port-forwarding (ssh -L to the Pi-hole UI); reach it via LAN/Tailscale IP instead"
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
        # the person running this: sudo user, else the login user behind a su/root shell
        local inv="${SUDO_USER:-$(logname 2>/dev/null || true)}"
        [[ -n "$inv" && "$inv" != "root" && " $allow_users" != *" $inv "* ]] && allow_users+="$inv "
        [[ -n "$allow_users" ]] && crypto_lines+="AllowUsers ${allow_users% }"$'\n' && info "SSH restricted to: ${allow_users% }"
    fi

    [[ $DRY_RUN -eq 0 ]] && mkdir -p /etc/ssh/sshd_config.d
    {
        echo "# StarHard v$VERSION ($PROFILE profile). Named 00- on purpose: sshd uses the first value it reads."
        ssh_table
        [[ -n "$pw_line" ]] && echo "$pw_line"
        printf '%s' "$crypto_lines"
    } | write_file "$dropin" 600
    if [[ -e "$old_dropin" ]]; then
        if [[ $DRY_RUN -eq 0 ]]; then
            backup_file "$old_dropin"; rm -f "$old_dropin"; removed_old=1
            info "Replaced the old drop-in 50-hardening.conf with 00-starhard.conf"
        else
            info "DRY-RUN: would remove the old drop-in $old_dropin"
        fi
    fi

    if [[ $DRY_RUN -eq 0 ]] && command -v sshd >/dev/null 2>&1; then
        if sshd -t 2>>"$LOG_FILE"; then
            if has_systemd; then
                systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
            elif command -v rc-service >/dev/null 2>&1; then
                rc-service sshd reload 2>/dev/null || true
            fi
            log "sshd config validated and reloaded"
            # Did our values actually win? Ask sshd what it resolved.
            SSHD_EFFECTIVE=""
            local kw val lost=""
            while read -r kw val; do
                [[ -n "$kw" ]] || continue
                ssh_effective_is "$kw" "$val" || lost+=" $kw"
            done < <(ssh_table)
            if [[ -n "$pw_line" ]] && ! ssh_effective_is PasswordAuthentication no; then lost+=" PasswordAuthentication"; fi
            if [[ -n "$lost" ]]; then
                warn "sshd is NOT using StarHard's value for:$lost"
                warn "Another file sets it earlier (or sshd_config sets it above its Include line). Find it:"
                local lost_re="${lost# }"
                warn "  grep -rniE '^\s*(${lost_re// /|})\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/"
            else
                log "Effective sshd configuration verified with sshd -T"
            fi
        else
            err "sshd rejected new config — reverting SSH hardening"
            rm -f "$dropin"
            [[ $removed_old -eq 1 ]] && cp -a "$BACKUP_DIR$old_dropin" "$old_dropin"
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

docker_published_ports() {
    # proto/port for every port Docker publishes on all interfaces (not the ones bound to 127.0.0.1)
    command -v docker >/dev/null 2>&1 || return 0
    docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | sed 's/^ *//' \
        | grep -E '^(0\.0\.0\.0|\[?::\]?):[0-9-]+->' \
        | sed -E 's/^.*:([0-9-]+)->[0-9-]+\/([a-z]+).*/\2\/\1/' | sort -u
}

fw_warn_listeners() {
    # fw_warn_listeners <ssh_port> — show non-loopback listeners the default-deny policy will block,
    # and separately the Docker-published ports it will NOT block.
    local ssh_port="$1" allowed=" $1 "
    [[ $HAS_PIHOLE -eq 1 ]] && allowed+=" 53 80 443 67 "
    [[ $HAS_TAILSCALE -eq 1 ]] && allowed+=" 41641 "
    local docker_ports others
    docker_ports="$(docker_published_ports | tr '\n' ' ')"
    others="$(ss -tulnH 2>/dev/null | awk '{split($5,a,":"); p=a[length(a)]; addr=$5; sub(":"p"$","",addr); if (addr !~ /^(127\.|\[::1\]|::1)/) print $1"/"p}' | sort -u \
        | while read -r l; do p="${l#*/}"; [[ "$allowed" == *" $p "* || " $docker_ports" == *" $l "* ]] || echo "$l"; done | tr '\n' ' ')"
    if [[ -n "$others" ]]; then
        warn "Other listening ports that the firewall will now BLOCK from the network: $others"
        warn "If any are needed, allow them: ufw allow <port>/<proto>  (or firewall-cmd --permanent --add-port=<port>/<proto>)"
    fi
    if [[ -n "$docker_ports" ]]; then
        warn "Docker publishes these ports on every interface and this firewall does NOT block them: $docker_ports"
        warn "Docker's own NAT/forward rules are evaluated before the host's input rules. To close one, publish it on"
        warn "localhost only (-p 127.0.0.1:PORT:PORT) or filter it in the DOCKER-USER chain. Section 23 (--docker-harden) helps further."
    elif command -v docker >/dev/null 2>&1; then
        info "Docker is installed: ports published with -p bypass this firewall unless bound to 127.0.0.1"
    fi
}

ufw_add() {
    # ufw_add <description> <ufw args...> — add a rule; its removal is recorded only if it was really new
    local desc="$1" out; shift
    if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would run: ufw $*"; return 0; fi
    if out="$(ufw "$@" 2>&1)"; then
        echo "$out" >> "$LOG_FILE"
        log "$desc"
        grep -qi 'skipping' <<< "$out" || rb "ufw delete $* 2>/dev/null || true"
    else
        echo "$out" >> "$LOG_FILE"
        warn "$desc failed (see $LOG_FILE) — continuing"
        return 1
    fi
}

fwd_add() {
    # fwd_add <description> <firewall-cmd --permanent args...> — same idea for firewalld
    local desc="$1" out a undo=""; shift
    if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would run: firewall-cmd --permanent $*"; return 0; fi
    if out="$(firewall-cmd --permanent "$@" 2>&1)"; then
        echo "$out" >> "$LOG_FILE"
        log "$desc"
        if ! grep -q 'ALREADY_ENABLED' <<< "$out"; then
            for a in "$@"; do undo+=" $(printf '%q' "${a/--add-/--remove-}")"; done
            rb "firewall-cmd --permanent$undo 2>/dev/null || true"
        fi
    else
        echo "$out" >> "$LOG_FILE"
        warn "$desc failed (see $LOG_FILE) — continuing"
        return 1
    fi
}

fw_nftables() {
    # fw_nftables <ssh_port> <need_ssh> <pihole_lan> <pihole_dhcp> <lan_nets>
    # Hosts with nft but neither ufw nor firewalld (Alpine, minimal installs). StarHard loads its own
    # table and never flushes the ruleset: tables that Docker, libvirt or Tailscale manage are untouched,
    # and a drop in this table is final whatever the others accept.
    local ssh_port="$1" need_ssh="$2" pihole_lan="$3" pihole_dhcp="$4" lan_nets="$5"
    local f=/etc/starhard/firewall.nft nft_bin n
    nft_bin="$(command -v nft)"
    {
        cat <<EOF
#!$nft_bin -f
# StarHard default-deny inbound firewall (generated — re-run StarHard section 7 to change it).
# Reload by hand: nft -f $f        Remove: nft delete table inet starhard
table inet starhard
delete table inet starhard
table inet starhard {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        meta l4proto icmp accept
        meta l4proto ipv6-icmp accept
        udp sport 67 udp dport 68 accept
        ip6 saddr fe80::/10 udp dport 546 accept
EOF
        [[ "$need_ssh" == "1" ]] && echo "        tcp dport $ssh_port accept"
        if [[ $HAS_TAILSCALE -eq 1 ]]; then
            echo '        iifname "tailscale0" accept'
            echo '        udp dport 41641 accept'
        fi
        if [[ "$pihole_lan" == "1" ]]; then
            for n in $lan_nets; do
                echo "        ip saddr $n tcp dport { 53, 80, 443 } accept"
                echo "        ip saddr $n udp dport 53 accept"
            done
            [[ "$pihole_dhcp" == "1" ]] && echo "        udp dport 67 accept"
        fi
        echo "    }"
        echo "}"
    } | write_file "$f" 600
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would load the nftables table 'inet starhard' (default-deny inbound) and enable it at boot"
        return 0
    fi
    if ! nft -c -f "$f" >> "$LOG_FILE" 2>&1; then
        err "nft rejected $f (see $LOG_FILE) — firewall NOT changed"
        return 1
    fi
    if nft list table inet starhard >/dev/null 2>&1; then orig_mark "cmd:nft delete table inet starhard 2>/dev/null || true"
    else rb "nft delete table inet starhard 2>/dev/null || true"; fi
    if nft -f "$f" >> "$LOG_FILE" 2>&1; then
        log "nftables: default-deny inbound table loaded (inet starhard)"
    else
        err "Loading $f failed (see $LOG_FILE)"; return 1
    fi
    # Load it at every boot
    if has_systemd; then
        write_file /etc/systemd/system/starhard-firewall.service 644 <<EOF
[Unit]
Description=StarHard default-deny firewall (nftables)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nft_bin -f $f

[Install]
WantedBy=sysinit.target
EOF
        systemctl daemon-reload
        svc_enable starhard-firewall.service
    elif command -v rc-update >/dev/null 2>&1; then
        write_file /etc/local.d/starhard-firewall.start 755 <<EOF
#!/bin/sh
# StarHard: load the default-deny firewall at boot
$nft_bin -f $f
EOF
        if rc-update show default 2>/dev/null | grep -qw local; then orig_mark "svc:local"
        else rb "rc-update del local default 2>/dev/null || true"; fi
        run "enable OpenRC 'local' service (loads the firewall at boot)" rc-update add local default
    else
        warn "No systemd or OpenRC: load the firewall at boot yourself: $nft_bin -f $f"
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
            ufw_add "ufw: trust tailscale0" allow in on tailscale0
            ufw_add "ufw: tailscale direct connections (41641/udp)" allow 41641/udp
        fi
        if [[ $pihole_lan -eq 1 ]]; then
            local n
            for n in $lan_nets; do
                ufw_add "ufw: Pi-hole DNS (tcp) from $n" allow from "$n" to any port 53 proto tcp
                ufw_add "ufw: Pi-hole DNS (udp) from $n" allow from "$n" to any port 53 proto udp
                ufw_add "ufw: Pi-hole web from $n" allow from "$n" to any port 80 proto tcp
                ufw_add "ufw: Pi-hole web (TLS) from $n" allow from "$n" to any port 443 proto tcp
            done
            # DHCP requests come from 0.0.0.0 (the client has no address yet), so no source filter
            [[ $pihole_dhcp -eq 1 ]] && ufw_add "ufw: Pi-hole DHCP server (67/udp)" allow 67/udp
            [[ -z "$lan_nets" ]] && warn "Pi-hole detected but no LAN subnet found — allow port 53 manually: ufw allow 53"
        fi
        local was_active=0
        ufw status 2>/dev/null | grep -q 'Status: active' && was_active=1
        # Remember the defaults we are about to change
        if [[ $DRY_RUN -eq 0 && -r /etc/default/ufw ]]; then
            local dir pol
            for dir in INPUT:incoming OUTPUT:outgoing; do
                pol="$(sed -n "s/^DEFAULT_${dir%%:*}_POLICY=\"\(.*\)\"/\1/p" /etc/default/ufw | head -1)"
                case "$pol" in
                    DROP)   rb "ufw default deny ${dir##*:}" ;;
                    REJECT) rb "ufw default reject ${dir##*:}" ;;
                    ACCEPT) rb "ufw default allow ${dir##*:}" ;;
                esac
            done
        fi
        run "ufw default deny incoming" ufw default deny incoming
        run "ufw default allow outgoing" ufw default allow outgoing
        if [[ $need_ssh -eq 1 ]]; then
            ufw_add "ufw allow ssh port $ssh_port (rate-limited)" limit "$ssh_port/tcp"
        fi
        fw_warn_listeners "$ssh_port"
        fw_warn_stale_rules
        if [[ $DRY_RUN -eq 0 ]]; then
            if [[ $was_active -eq 0 ]]; then rb "ufw disable"; else orig_mark "cmd:ufw disable"; fi
            ufw --force enable >> "$LOG_FILE" 2>&1 && log "ufw enabled"
        else
            info "DRY-RUN: would enable ufw"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        svc_enable firewalld
        if [[ $DRY_RUN -eq 0 ]]; then
            local old_zone
            old_zone="$(firewall-cmd --get-default-zone 2>/dev/null)"
            if [[ -n "$old_zone" && "$old_zone" != "public" ]]; then rb "firewall-cmd --set-default-zone=$old_zone"
            else orig_mark "firewalld-default-zone"; fi
        fi
        run "firewalld default zone public" firewall-cmd --set-default-zone=public
        if [[ $need_ssh -eq 1 ]]; then
            fwd_add "firewalld: allow ssh" --add-service=ssh
            [[ "$ssh_port" != "22" ]] && fwd_add "firewalld: allow ssh port $ssh_port" --add-port="$ssh_port/tcp"
        fi
        if [[ $HAS_TAILSCALE -eq 1 ]]; then
            fwd_add "firewalld: trust tailscale0" --zone=trusted --add-interface=tailscale0
            fwd_add "firewalld: tailscale 41641/udp" --add-port=41641/udp
        fi
        if [[ $pihole_lan -eq 1 ]]; then
            # Same scope as the ufw rules: LAN subnets only, never "any source"
            local n spec
            for n in $lan_nets; do
                for spec in 53/tcp 53/udp 80/tcp 443/tcp; do
                    fwd_add "firewalld: Pi-hole $spec from $n" \
                        --add-rich-rule="rule family=\"ipv4\" source address=\"$n\" port port=\"${spec%/*}\" protocol=\"${spec#*/}\" accept"
                done
            done
            [[ $pihole_dhcp -eq 1 ]] && fwd_add "firewalld: Pi-hole DHCP server" --add-service=dhcp
            [[ -z "$lan_nets" ]] && warn "Pi-hole detected but no LAN subnet found — allow DNS manually: firewall-cmd --permanent --add-service=dns"
            # StarHard <= 1.2 opened these to every source; say so rather than silently closing them
            local svc open_all=""
            for svc in dns http https; do
                firewall-cmd --permanent --query-service="$svc" >/dev/null 2>&1 && open_all+=" $svc"
            done
            if [[ -n "$open_all" && -n "$lan_nets" ]]; then
                warn "firewalld still allows these services from ANY source:$open_all (StarHard <= 1.2 added them for Pi-hole)."
                warn "The LAN-only rules above replace them. Close the wide ones: firewall-cmd --permanent$(printf ' --remove-service=%s' $open_all) && firewall-cmd --reload"
            fi
        fi
        fw_warn_listeners "$ssh_port"
        run "reload firewalld" firewall-cmd --reload
    elif command -v nft >/dev/null 2>&1; then
        fw_warn_listeners "$ssh_port"
        fw_nftables "$ssh_port" "$need_ssh" "$pihole_lan" "$pihole_dhcp" "$lan_nets"
    else
        warn "No firewall tool found — install ufw, firewalld or nftables"
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
fetch_pinned_key() {
    # fetch_pinned_key <url> <expected primary-key fingerprint> <output file>
    # Downloads an OpenPGP key over HTTPS and accepts it only if it is exactly one key with the
    # expected fingerprint. Nothing is imported into any keyring here.
    local url="$1" want="$2" out="$3" gh fpr npub
    gh="$(mktemp -d)" || return 1
    chmod 700 "$gh"
    if ! curl -fsSL --proto '=https' --tlsv1.2 -m 60 "$url" -o "$gh/key.asc" 2>>"$LOG_FILE"; then
        rm -rf "$gh"; err "Download failed: $url"; return 1
    fi
    npub="$(GNUPGHOME="$gh" gpg --batch --show-keys --with-colons "$gh/key.asc" 2>/dev/null | grep -c '^pub:')"
    fpr="$(GNUPGHOME="$gh" gpg --batch --show-keys --with-colons "$gh/key.asc" 2>/dev/null | awk -F: '$1=="fpr" {print $10; exit}')"
    if [[ "$npub" != "1" || "${fpr^^}" != "${want^^}" ]]; then
        rm -rf "$gh"
        err "Signing key from $url does NOT match the pinned fingerprint — refusing it"
        err "  expected $want"
        err "  got      ${fpr:-nothing} ($npub key(s) in the file)"
        return 1
    fi
    cp "$gh/key.asc" "$out"
    rm -rf "$gh"
}

crowdsec_add_repo() {
    # Adds CrowdSec's packagecloud repository the way its install script does, minus the script:
    # a repo file plus signing keys that are checked against pinned fingerprints, trusted for this
    # repository only. (Previously: curl <script> | bash, as root.)
    local base="https://packagecloud.io/crowdsec/crowdsec"
    case "$PKG" in
        apt|dnf|yum) ;;
        pacman)      info "Arch: using distro 'crowdsec' package; the bouncer is AUR-only (crowdsec-firewall-bouncer)"; return 0 ;;
        zypper|apk)  info "$PKG: attempting distro packages (no official CrowdSec repo)"; return 0 ;;
    esac
    if ls /etc/apt/sources.list.d/crowdsec*.list /etc/yum.repos.d/crowdsec*.repo >/dev/null 2>&1; then
        info "CrowdSec repository already configured"
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would add the CrowdSec repository (repo file + signing key checked against fingerprint $CROWDSEC_KEY_FPR)"
        return 0
    fi
    command -v curl >/dev/null 2>&1 || pkg_install curl
    if ! command -v gpg >/dev/null 2>&1; then
        if [[ "$PKG" == "apt" ]]; then pkg_install gnupg; else pkg_install gnupg2; fi
    fi
    if ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
        err "curl and gpg are needed to verify the CrowdSec signing key"; return 1
    fi
    local tmp
    tmp="$(mktemp -d)" || return 1
    if ! fetch_pinned_key "$base/gpgkey" "$CROWDSEC_KEY_FPR" "$tmp/repo.asc"; then rm -rf "$tmp"; return 1; fi

    if [[ "$PKG" == "apt" ]]; then
        # packagecloud path: <os>/ <codename>. Derivatives and releases it has no pocket for
        # (Kali, Parrot, a brand-new Debian) use its distribution-independent "any/any".
        local os="debian" dist=""
        if [[ "$OS_ID" == "ubuntu" || " $OS_LIKE " == *" ubuntu "* ]]; then
            os="ubuntu"; dist="$(. /etc/os-release; echo "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}")"
        elif [[ "$OS_ID" == "raspbian" ]]; then
            os="raspbian"; dist="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
        elif [[ "$OS_ID" == "debian" ]]; then
            dist="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
        else
            dist="$(. /etc/os-release; echo "${DEBIAN_CODENAME:-}")"
        fi
        if [[ -z "$dist" ]] || ! curl -fsSL --proto '=https' -m 30 -o /dev/null "$base/$os/dists/$dist/InRelease" 2>/dev/null; then
            [[ -n "$dist" ]] && info "CrowdSec has no '$os/$dist' pocket — using its distribution-independent repository"
            os="any"; dist="any"
        fi
        mkdir -p /etc/apt/keyrings
        record_rm /etc/apt/keyrings/crowdsec.gpg
        if ! gpg --batch --dearmor < "$tmp/repo.asc" > /etc/apt/keyrings/crowdsec.gpg 2>>"$LOG_FILE"; then
            rm -rf "$tmp" /etc/apt/keyrings/crowdsec.gpg; err "Could not convert the CrowdSec key"; return 1
        fi
        chmod 644 /etc/apt/keyrings/crowdsec.gpg
        write_file /etc/apt/sources.list.d/crowdsec.list 644 <<EOF
# CrowdSec (added by StarHard; key pinned to $CROWDSEC_KEY_FPR)
deb [signed-by=/etc/apt/keyrings/crowdsec.gpg] $base/$os/ $dist main
EOF
    else
        # RPM: repository metadata is signed by the repo key, packages by two CrowdSec keys
        local os="el" ver k i=0
        if [[ "$OS_ID" == "fedora" ]]; then os="fedora"; ver="$(rpm -E '%{fedora}' 2>/dev/null)"
        else ver="$(rpm -E '%{rhel}' 2>/dev/null)"; fi
        if [[ ! "$ver" =~ ^[0-9]+$ ]]; then rm -rf "$tmp"; err "Could not determine the release number for the CrowdSec repository"; return 1; fi
        local -a pkgkeys=(
            "crowdsec-crowdsec-C822EDD6B39954A1.pub.gpg:79B8CC3F94472AC862A8AD8DB06F1981145CE2F2"
            "crowdsec-crowdsec-FED78314A2468CCF.pub.gpg:9082D8CACBBEB0DAB218BAB04C3D386C3CDF0DB4"
        )
        mkdir -p /etc/pki/rpm-gpg
        local keylist="file:///etc/pki/rpm-gpg/RPM-GPG-KEY-crowdsec-repo"
        for k in "${pkgkeys[@]}"; do
            i=$((i+1))
            if ! fetch_pinned_key "$base/gpgkey/${k%%:*}" "${k##*:}" "$tmp/pkg$i.asc"; then rm -rf "$tmp"; return 1; fi
            keylist+=$'\n       '"file:///etc/pki/rpm-gpg/RPM-GPG-KEY-crowdsec-pkg$i"
        done
        write_file /etc/pki/rpm-gpg/RPM-GPG-KEY-crowdsec-repo 644 < "$tmp/repo.asc"
        i=0
        for k in "${pkgkeys[@]}"; do
            i=$((i+1))
            write_file "/etc/pki/rpm-gpg/RPM-GPG-KEY-crowdsec-pkg$i" 644 < "$tmp/pkg$i.asc"
        done
        write_file /etc/yum.repos.d/crowdsec.repo 644 <<EOF
# CrowdSec (added by StarHard; signing keys pinned by fingerprint)
[crowdsec_crowdsec]
name=CrowdSec
baseurl=$base/$os/$ver/\$basearch
repo_gpgcheck=1
gpgcheck=1
enabled=1
gpgkey=$keylist
sslverify=1
metadata_expire=300
EOF
    fi
    rm -rf "$tmp"
    log "CrowdSec repository added (signing key fingerprint verified)"
    if [[ "$PKG" == "apt" ]]; then
        pkg_update
    else
        # -y: accept the keys we just verified and wrote, for this repository only
        run "CrowdSec repository: import keys, load metadata" "$PKG" -y -q makecache --disablerepo='*' --enablerepo=crowdsec_crowdsec
    fi
    return 0
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

audit_conf_raise() {
    # audit_conf_raise <key> <minimum> — set a numeric auditd.conf value unless it is already higher
    local f=/etc/audit/auditd.conf cur
    cur="$(awk -F= -v k="$1" '{key=$1; gsub(/[[:space:]]/,"",key)} key==k {v=$2; gsub(/[[:space:]]/,"",v); print v; exit}' "$f")"
    if [[ "$cur" =~ ^[0-9]+$ ]]; then
        [[ "$cur" -ge "$2" ]] && return 0
        sed -i -E "s/^[[:space:]]*$1[[:space:]]*=.*/$1 = $2/" "$f"
    else
        echo "$1 = $2" >> "$f"
    fi
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
EOF
            if [[ "$PROFILE" == "server" ]]; then
                cat <<EOF
# Every deletion and permission change by a logged-in user (server: few interactive users)
-a always,exit -F arch=$a -S $sc_delete -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=$a -S $sc_perm -F auid>=1000 -F auid!=unset -k perm_mod
EOF
            else
                # On a desktop the two rules above fire for every cache file a browser deletes and
                # rotate the audit log away within hours. Watch only the places where it means something.
                cat <<EOF
# Deletions under /var/log by a logged-in user (covering tracks) and under /etc
-a always,exit -F arch=$a -S $sc_delete -F dir=/var/log -F auid>=1000 -F auid!=unset -k log_tamper
-a always,exit -F arch=$a -S $sc_delete -F dir=/etc -F auid>=1000 -F auid!=unset -k delete
# Permission / ownership changes on system paths
-a always,exit -F arch=$a -S $sc_perm -F dir=/etc -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=$a -S $sc_perm -F dir=/usr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=$a -S $sc_perm -F dir=/boot -F auid>=1000 -F auid!=unset -k perm_mod
EOF
            fi
            cat <<EOF
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
        skipped="$(grep -c '^# skipped' /etc/audit/rules.d/50-hardening.rules 2>/dev/null || true)"
        [[ "${skipped:-0}" -gt 0 ]] && info "$skipped rule(s) already defined by other files in /etc/audit/rules.d/ — left to those files"
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
    # Retention: the stock 5 x 8 MB is gone in hours on a busy box, and starhard-status looks back a week.
    # Values are only ever raised, never lowered.
    if [[ -f /etc/audit/auditd.conf ]]; then
        backup_file /etc/audit/auditd.conf
        if [[ $DRY_RUN -eq 0 ]]; then
            audit_conf_raise max_log_file 50
            audit_conf_raise num_logs 10
            pkill -HUP -x auditd 2>/dev/null || true
            log "auditd retention: at least 10 logs of 50 MB"
        else
            info "DRY-RUN: would raise auditd log retention (num_logs >= 10, max_log_file >= 50)"
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

    # Baseline refresh after package transactions. Without it every upgrade turns the daily report
    # into thousands of "changed" lines and the report stops being read.
    write_file /usr/local/sbin/starhard-aide-refresh 755 <<'EOF'
#!/bin/sh
# StarHard: refresh the AIDE baseline (runs by itself a few minutes after packages change).
# `aide --update` first REPORTS every difference against the old baseline, then writes the new one,
# so nothing is absorbed silently: each report is kept as /var/log/starhard/aideupd-<timestamp>.log
FLAG=/var/lib/starhard/aide-refresh-needed
mkdir -p /var/log/starhard /var/lib/starhard
# started by the package-manager hook: let the transaction and its triggers finish first
[ "$1" = "--settle" ] && sleep 300
rm -f "$FLAG"
LOG="/var/log/starhard/aideupd-$(date +%Y%m%d-%H%M%S).log"
if command -v aide.wrapper >/dev/null 2>&1; then
    aide.wrapper --update > "$LOG" 2>&1
elif [ -f /etc/aide/aide.conf ]; then
    aide --update -c /etc/aide/aide.conf > "$LOG" 2>&1
else
    aide --update > "$LOG" 2>&1
fi
rc=$?
# 0-7: finished (bits say added/removed/changed). 14 and up: error — keep the old baseline.
if [ $rc -ge 14 ]; then
    logger -t starhard-aide "baseline refresh FAILED (rc=$rc) — see $LOG"
    exit 1
fi
moved=0
for ext in "" ".gz"; do
    if [ -f "/var/lib/aide/aide.db.new$ext" ]; then
        mv -f "/var/lib/aide/aide.db.new$ext" "/var/lib/aide/aide.db$ext" && moved=1
    fi
done
[ $moved -eq 1 ] && logger -t starhard-aide "baseline refreshed — the differences it absorbed are listed in $LOG"
# keep the last 20 refresh reports
ls -t /var/log/starhard/aideupd-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
exit 0
EOF
    if has_systemd; then
        [[ $DRY_RUN -eq 0 ]] && mkdir -p "$STATE_DIR"
        write_file /etc/systemd/system/starhard-aide-refresh.service 644 <<'EOF'
[Unit]
Description=StarHard: refresh the AIDE baseline after package changes

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/starhard-aide-refresh --settle
Nice=19
IOSchedulingClass=idle
EOF
        write_file /etc/systemd/system/starhard-aide-refresh.path 644 <<'EOF'
[Unit]
Description=StarHard: package changes flagged for an AIDE baseline refresh

[Path]
PathExists=/var/lib/starhard/aide-refresh-needed
Unit=starhard-aide-refresh.service

[Install]
WantedBy=paths.target
EOF
        [[ $DRY_RUN -eq 0 ]] && systemctl daemon-reload
        svc_enable starhard-aide-refresh.path
        # The package manager only drops a flag file; the path unit above does the work, once, afterwards.
        case "$PKG" in
            apt)
                write_file /etc/apt/apt.conf.d/99starhard-aide 644 <<'EOF'
// StarHard: flag the AIDE baseline for a refresh after packages change
DPkg::Post-Invoke { "if [ -d /var/lib/starhard ]; then touch /var/lib/starhard/aide-refresh-needed; fi"; };
EOF
                ;;
            pacman)
                write_file /etc/pacman.d/hooks/zz-starhard-aide.hook 644 <<'EOF'
[Trigger]
Operation = Install
Operation = Upgrade
Operation = Remove
Type = Package
Target = *

[Action]
Description = StarHard: flagging the AIDE baseline for a refresh
When = PostTransaction
Exec = /usr/bin/touch /var/lib/starhard/aide-refresh-needed
EOF
                ;;
            dnf)
                if dnf --version 2>/dev/null | head -1 | grep -qi 'dnf5'; then
                    info "dnf5: no transaction hook installed — after upgrades run: starhard-aide-refresh"
                else
                    pkg_installed python3-dnf-plugin-post-transaction-actions || pkg_install python3-dnf-plugin-post-transaction-actions
                    if [[ -d /etc/dnf/plugins/post-transaction-actions.d || $DRY_RUN -eq 1 ]]; then
                        write_file /etc/dnf/plugins/post-transaction-actions.d/starhard-aide.action 644 <<'EOF'
# StarHard: flag the AIDE baseline for a refresh after any transaction
*:any:/usr/bin/touch /var/lib/starhard/aide-refresh-needed
EOF
                    else
                        info "dnf post-transaction plugin unavailable — after upgrades run: starhard-aide-refresh"
                    fi
                fi
                ;;
            *)  info "$PKG: no transaction hook — after upgrades run: starhard-aide-refresh" ;;
        esac
    else
        info "No systemd: the AIDE baseline is not refreshed automatically — after upgrades run: starhard-aide-refresh"
    fi
}

#===============================================================================
# 11. Malware / rootkit scanning (replaces rkhunter + chkrootkit)
#===============================================================================
install_notify_hooks() {
    # Example hooks for starhard-notify. They are inert until copied without ".example" and made
    # executable; the examples themselves are rewritten on every run, enabled copies never are.
    local d=/etc/starhard/notify.d
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p "$d" "$STATE_DIR"; chmod 700 "$d"
    fi
    if [[ ! -e /etc/starhard/notify.conf ]]; then
        write_file /etc/starhard/notify.conf 600 <<'EOF'
# Settings for the example hooks in /etc/starhard/notify.d/ (shell syntax; root-only, may hold tokens).
# Enable a hook:  cd /etc/starhard/notify.d && cp 20-ntfy.example 20-ntfy && chmod 700 20-ntfy
# Try it:         sudo starhard-notify --test

# 10-mail: needs a working `mail` command (bsd-mailx / s-nail with an MTA or msmtp)
MAIL_TO=""

# 20-ntfy: push to a phone. Anyone who knows a topic name on a public server can read it —
# use your own server, or a long random topic.  e.g. https://ntfy.example.org/3f9c0a...
NTFY_URL=""
NTFY_TOKEN=""

# 30-webhook: Slack / Mattermost / Discord compatible incoming-webhook URL
WEBHOOK_URL=""
EOF
    fi
    write_file "$d/10-mail.example" 600 <<'EOF'
#!/bin/sh
# Mail the digest (stdin) to MAIL_TO from /etc/starhard/notify.conf.
. /etc/starhard/notify.conf 2>/dev/null
[ -n "$MAIL_TO" ] || exit 0
exec mail -s "[StarHard] $STARHARD_SUMMARY" "$MAIL_TO"
EOF
    write_file "$d/20-ntfy.example" 600 <<'EOF'
#!/bin/sh
# Push to an ntfy topic (NTFY_URL, optional NTFY_TOKEN in /etc/starhard/notify.conf).
# Only the "!!" lines are sent, not the whole digest.
. /etc/starhard/notify.conf 2>/dev/null
[ -n "$NTFY_URL" ] || exit 0
prio=high; tag=warning
[ "$STARHARD_STATE" = "resolved" ] && { prio=default; tag=white_check_mark; }
[ "$STARHARD_STATE" = "test" ] && { prio=low; tag=test_tube; }
if [ -n "$NTFY_TOKEN" ]; then
    exec curl -fsS -m 30 -H "Authorization: Bearer $NTFY_TOKEN" -H "Title: $STARHARD_SUMMARY" \
        -H "Priority: $prio" -H "Tags: $tag" -d "${STARHARD_ITEMS:-Nothing needs attention.}" "$NTFY_URL"
fi
exec curl -fsS -m 30 -H "Title: $STARHARD_SUMMARY" -H "Priority: $prio" -H "Tags: $tag" \
    -d "${STARHARD_ITEMS:-Nothing needs attention.}" "$NTFY_URL"
EOF
    write_file "$d/30-webhook.example" 600 <<'EOF'
#!/bin/sh
# POST to an incoming webhook (WEBHOOK_URL in /etc/starhard/notify.conf).
# Sends both "text" (Slack, Mattermost) and "content" (Discord).
. /etc/starhard/notify.conf 2>/dev/null
[ -n "$WEBHOOK_URL" ] || exit 0
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | awk 'BEGIN{ORS="\\n"} {print}'; }
msg="$(esc "$STARHARD_SUMMARY
$STARHARD_ITEMS")"
exec curl -fsS -m 30 -H 'Content-Type: application/json' \
    -d "{\"text\":\"$msg\",\"content\":\"$msg\"}" "$WEBHOOK_URL"
EOF
    write_file "$d/40-desktop.example" 600 <<'EOF'
#!/bin/sh
# Desktop notification (notify-send) in every graphical session on this machine.
command -v notify-send >/dev/null 2>&1 || exit 0
urgency=critical; [ "$STARHARD_STATE" = "resolved" ] && urgency=normal
for sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
    [ "$(loginctl show-session "$sid" -p Type --value 2>/dev/null)" = "tty" ] && continue
    uid="$(loginctl show-session "$sid" -p User --value 2>/dev/null)"
    [ -n "$uid" ] && [ -S "/run/user/$uid/bus" ] || continue
    runuser -u "$(id -un "$uid")" -- env DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        notify-send -u "$urgency" -a StarHard "$STARHARD_SUMMARY" "${STARHARD_ITEMS:-Nothing needs attention.}"
done
exit 0
EOF
    # Login banner line (Debian/Ubuntu dynamic MOTD); starhard-notify keeps the text current
    if [[ -d /etc/update-motd.d ]]; then
        write_file /etc/update-motd.d/60-starhard 755 <<'EOF'
#!/bin/sh
[ -r /var/lib/starhard/last-status ] && printf '\nStarHard (%s)\n' "$(cat /var/lib/starhard/last-status)"
exit 0
EOF
    fi
    info "Notifications: enable a hook in $d (see /etc/starhard/notify.conf), then test with: starhard-notify --test"
}

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
    write_file /usr/local/sbin/starhard-scan 755 <<'__STARHARD_SCAN__'
#!/usr/bin/env bash
# StarHard weekly scan: ClamAV, unhide, package integrity, Lynis.
# Interactive (terminal): live progress bars and stage summaries.
# Timer / non-terminal: silent, log only.   Log: /var/log/starhard/scan-<date>.log
# Options: --quiet (no terminal output)   --clam-only   --no-clam
QUIET=0; CLAM_ONLY=0; NO_CLAM=0
for a in "$@"; do case "$a" in --quiet) QUIET=1;; --clam-only) CLAM_ONLY=1;; --no-clam) NO_CLAM=1;; esac; done
[[ -t 1 ]] || QUIET=1
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo starhard-scan"; exit 1; }

mkdir -p /var/log/starhard /var/lib/starhard
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

say "${C}StarHard scan${N} — $(uname -n), $(date '+%a %d %b %H:%M')  ${D}log: $LOG${N}"

#---------------------------------------------------------------- ClamAV -----
if command -v clamscan >/dev/null 2>&1 && [[ $NO_CLAM -eq 0 ]]; then
    { echo; echo "-- clamscan --"; } >> "$LOG"
    AVAIL_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [[ "${AVAIL_KB:-0}" -lt 1500000 ]]; then
        echo "SKIPPED: only $((AVAIL_KB/1024)) MB RAM available (need ~1500 MB). Run clamscan manually when idle." >> "$LOG"
        logger -t starhard-scan "clamscan skipped: low memory"
        # Count consecutive skips so starhard-status can escalate a scan that never runs (small Pis)
        SK="$(cat /var/lib/starhard/clam-skips 2>/dev/null || echo 0)"; [[ "$SK" =~ ^[0-9]+$ ]] || SK=0
        echo $((SK+1)) > /var/lib/starhard/clam-skips
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
        echo 0 > /var/lib/starhard/clam-skips
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
__STARHARD_SCAN__
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
    write_file /usr/local/sbin/starhard-status 755 <<'__STARHARD_STATUS__'
#!/usr/bin/env bash
# starhard-status — one-screen digest of what the StarHard tooling has found.
# Usage: sudo starhard-status [--days N] [--json] [--quiet]
#   --days N   look back N days (default 7)
#   --json     machine-readable output (one JSON object) instead of the digest
#   --quiet    print nothing; use the exit code only
# Exit code: 0 = nothing needs attention, 1 = at least one "!!" item, 2 = usage error.
DAYS=7; JSON=0; QUIET=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days)  DAYS="${2:-}"; shift ;;
        --json)  JSON=1 ;;
        --quiet) QUIET=1 ;;
        -h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done
[[ "$DAYS" =~ ^[0-9]+$ && "$DAYS" -ge 1 ]] || { echo "--days needs a positive whole number" >&2; exit 2; }
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo starhard-status" >&2; exit 2; }

if [[ -t 1 && $JSON -eq 0 ]]; then
    R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[1;33m'; B=$'\033[0;34m'; N=$'\033[0m'
else
    R=''; G=''; Y=''; B=''; N=''
fi
ISSUES=0; SECTION=""
REC_L=(); REC_S=(); REC_M=()
rec()    { REC_L+=("$1"); REC_S+=("$SECTION"); REC_M+=("$2"); }
out()    { [[ $JSON -eq 1 || $QUIET -eq 1 ]] || printf '%s\n' "$1"; }
ok()     { rec ok "$1";     out "  ${G}OK  ${N} $1"; }
bad()    { rec bad "$1";    ISSUES=$((ISSUES+1)); out "  ${R}!!  ${N} $1"; }
note()   { rec note "$1";   out "  ${Y}--  ${N} $1"; }
detail() { rec detail "$1"; out "        $1"; }
hdr()    { SECTION="$1"; out ""; out "${B}== $1 ==${N}"; }
json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\n'/\\n}"
    s="${s//[[:cntrl:]]/}"
    printf '%s' "$s"
}

hdr "System"
detail "$(uname -n) — $(uname -r) — up $(uptime -p 2>/dev/null | sed 's/^up //')"
if [[ -f /var/run/reboot-required ]]; then bad "Reboot required (kernel/libc updated)"
elif command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; then bad "Reboot required (needs-restarting -r)"
else ok "No reboot pending"; fi
ignore_re='^$'
if [[ -s /etc/starhard/ignore-units ]]; then
    ignore_re="^($(grep -Ev '^\s*(#|$)' /etc/starhard/ignore-units | sed 's/\.service$//' | paste -sd'|'))(\.service)?$"
fi
failed="$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | grep -Ev "$ignore_re" | tr '\n' ' ')"
if [[ -n "$failed" ]]; then bad "Failed services: $failed"; else ok "No failed services"; fi

hdr "Updates"
if command -v apt-get >/dev/null 2>&1; then
    sim="$(apt-get -s upgrade 2>/dev/null)"
    sec="$(grep -ci '^inst.*securi' <<< "$sim" || true)"
    all="$(grep -c '^Inst' <<< "$sim" || true)"
    if [[ "${sec:-0}" -gt 0 ]]; then bad "$sec security update(s) pending ($all total) — run: apt full-upgrade"
    elif [[ "${all:-0}" -gt 0 ]]; then note "$all package update(s) pending (none security)"
    else ok "System up to date"; fi
    last="$(grep -h 'Packages that were upgraded' /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -1 | cut -c1-19)"
    [[ -n "$last" ]] && note "Last unattended-upgrade: $last"
elif command -v dnf >/dev/null 2>&1; then
    n="$(dnf -q updateinfo list --security 2>/dev/null | grep -c . || true)"
    if [[ "${n:-0}" -gt 0 ]]; then bad "$n security update(s) pending"; else ok "No security updates pending"; fi
fi
command -v pihole >/dev/null 2>&1 && note "Pi-hole: $(pihole -v 2>/dev/null | head -1 | sed 's/^ *//')  (update with: pihole -up)"

hdr "Malware scan (ClamAV / unhide / integrity) — last $DAYS days"
scanlog="$(ls -t /var/log/starhard/scan-*.log 2>/dev/null | head -1)"
if [[ -z "$scanlog" ]]; then
    note "No scan has run yet — run: starhard-scan   (timer: $(systemctl list-timers starhard-scan.timer --no-legend 2>/dev/null | awk '{print $1" "$2" "$3}'))"
else
    age=$(( ( $(date +%s) - $(stat -c %Y "$scanlog") ) / 86400 ))
    if [[ $age -gt 15 ]]; then bad "Last scan was ${age}d ago — the weekly timer is not running: systemctl status starhard-scan.timer"
    else note "Last scan: $(basename "$scanlog" .log | sed 's/scan-//') (${age}d ago)"; fi
    inf="$(grep -m1 '^Infected files:' "$scanlog" | awk '{print $3}')"
    if [[ -z "$inf" ]]; then
        if pgrep -x clamscan >/dev/null 2>&1; then
            secs="$(ps -o etimes= -C clamscan 2>/dev/null | head -1 | xargs)"
            note "ClamAV: scan in progress ($(( ${secs:-0} / 60 )) min elapsed)"
        elif grep -q 'SKIPPED: only' "$scanlog"; then
            skips="$(cat /var/lib/starhard/clam-skips 2>/dev/null || echo 1)"
            [[ "$skips" =~ ^[0-9]+$ ]] || skips=1
            if [[ $skips -ge 2 ]]; then
                bad "ClamAV skipped $skips scans in a row (low memory) — no malware scan is happening. Run at idle: starhard-scan --clam-only"
            else
                note "ClamAV skipped last run (low memory)"
            fi
        elif grep -q -- '-- clamscan --' "$scanlog"; then note "ClamAV: no result in log (scan interrupted?)"
        fi
    elif [[ "$inf" == "0" ]]; then
        ex="$(grep -m1 -o 'exclusions applied: [0-9]*' "$scanlog" | awk '{print $3}')"
        ok "ClamAV: 0 infected files${ex:+ (${ex} path pattern(s) excluded — /etc/starhard/clamav-exclude)}"
    else
        bad "ClamAV: $inf infected file(s):"
        while IFS= read -r l; do detail "$l"; done < <(grep ' FOUND$' "$scanlog")
    fi
    if grep -q 'Found HIDDEN' "$scanlog"; then bad "unhide: HIDDEN process/port reported — see $scanlog"
    elif grep -q 'unhide' "$scanlog"; then ok "unhide: no hidden processes"; fi
    chg="$(sed -n '/-- package integrity --/,/-- lynis --/p' "$scanlog" | grep -Ev '^--|^$|^Full report' | grep -c . || true)"
    if [[ "${chg:-0}" -gt 0 ]]; then note "Package integrity: $chg modified file(s) — see $scanlog (config edits are normal)"
    else ok "Package integrity: no modified package files"; fi
fi
db="$(ls -t /var/lib/clamav/daily.c[lv]d 2>/dev/null | head -1)"
if [[ -n "$db" ]]; then
    dage=$(( ( $(date +%s) - $(stat -c %Y "$db") ) / 86400 ))
    if [[ $dage -gt 3 ]]; then bad "ClamAV signatures are ${dage}d old — check: systemctl status clamav-freshclam"; else ok "ClamAV signatures current (${dage}d)"; fi
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
                bad "AIDE baseline is stale (added ${a:-0}, removed ${r:-0}) — reports are noise until you rebuild: aideinit --yes --force"
            else
                note "Last check (${aage}d ago): added ${a:-0}, removed ${r:-0}, changed ${c:-0} — $aidelog"
            fi
            crit="$(grep -E '^(changed|f[^ ]*):? */(etc/(passwd|shadow|sudoers|ssh)|usr/(s?bin)/|usr/local/s?bin/)' "$aidelog" | head -5)"
            if [[ -n "$crit" ]]; then
                bad "Changes in sensitive paths:"
                while IFS= read -r l; do detail "$l"; done <<< "$crit"
            fi
            note "After a legitimate upgrade, refresh the baseline: starhard-aide-refresh  (automatic after package transactions)"
        else
            note "Last check (${aage}d ago): see $aidelog"
        fi
    fi
fi
upd="$(find /var/log/starhard -maxdepth 1 -name 'aideupd-*.log' -mtime "-$DAYS" 2>/dev/null | wc -l)"
[[ "${upd:-0}" -gt 0 ]] && note "Baseline auto-refreshed $upd time(s) after package changes — what each refresh absorbed: /var/log/starhard/aideupd-*.log"
[[ -e /var/lib/starhard/aide-refresh-needed ]] && note "Baseline refresh pending (packages changed; runs within minutes)"

hdr "Audit trail (auditd) — last $DAYS days"
if command -v ausearch >/dev/null 2>&1 && systemctl is-active -q auditd 2>/dev/null; then
    # ausearch parses -ts with the locale's own date format (%x), so produce it the same way
    since="$(date -d "$DAYS days ago" '+%x' 2>/dev/null || echo week-ago)"
    cnt() { ausearch -k "$1" -ts "$since" 2>/dev/null | grep -c '^type=SYSCALL\|^type=PATH' ; }
    for k in identity scope modules pi_boot sshd sudo_log preload input_dev log_tamper; do
        n="$(cnt "$k")"
        [[ "${n:-0}" -gt 0 ]] && note "$k: $n event(s)   → ausearch -k $k -ts $since -i | less"
    done
    fl="$(ausearch -m USER_LOGIN -ts "$since" 2>/dev/null | grep -c 'res=failed' || true)"
    if [[ "${fl:-0}" -gt 20 ]]; then bad "$fl failed logins"; elif [[ "${fl:-0}" -gt 0 ]]; then note "$fl failed login(s)"; else ok "No failed logins"; fi
    # How far back does the audit log actually reach? Noisy rules can rotate a week away in hours.
    oldest="$(ls -tr /var/log/audit/audit.log* 2>/dev/null | head -1)"
    if [[ -n "$oldest" ]]; then
        first="$(head -1 "$oldest" 2>/dev/null | sed -n 's/.*msg=audit(\([0-9]*\)\..*/\1/p')"
        if [[ "$first" =~ ^[0-9]+$ ]]; then
            reach=$(( ( $(date +%s) - first ) / 86400 ))
            nlogs="$(ls /var/log/audit/audit.log* 2>/dev/null | wc -l)"
            if [[ $reach -lt $DAYS && $nlogs -gt 2 ]]; then
                bad "Audit log only reaches back ${reach}d (asked for ${DAYS}d) — events are being rotated away; raise num_logs/max_log_file in /etc/audit/auditd.conf"
            fi
        fi
    fi
    ok "auditd running"
else
    bad "auditd not running"
fi

hdr "Keylogger indicators"
# 1. Library preload hooks
if [[ -s /etc/ld.so.preload ]]; then
    bad "/etc/ld.so.preload exists and is not empty — every process loads these libraries:"
    while IFS= read -r l; do detail "$l"; done < /etc/ld.so.preload
else
    ok "No /etc/ld.so.preload"
fi
pre="$(grep -ls 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/zsh/zshenv 2>/dev/null | tr '\n' ' ')"
[[ -n "$pre" ]] && bad "LD_PRELOAD set system-wide in: $pre"
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
            bad "PID $pid ($comm, $usr) holds input devices from a DELETED binary: $exe"
        elif [[ "$exe" == /tmp/* || "$exe" == /var/tmp/* || "$exe" == /dev/shm/* || "$exe" == /home/* || "$exe" == /root/* ]]; then
            bad "PID $pid ($comm, $usr) holds input devices, running from $exe"
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
    mode="$(usbguard get-parameter ImplicitPolicyTarget 2>/dev/null)"
    [[ -n "$mode" ]] || mode="$(grep -m1 '^ImplicitPolicyTarget=' /etc/usbguard/usbguard-daemon.conf 2>/dev/null | cut -d= -f2)"
    ok "USBGuard running (unknown devices right now: ${mode:-?})"
    # Read through process substitution, not a pipe: the loop must run in this shell so the
    # issue counter and the JSON records survive it.
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        id="${line%%:*}"; state="$(echo "$line" | awk '{print $2}')"
        name="$(echo "$line" | grep -o 'name "[^"]*"' | cut -d'"' -f2)"
        vid="$(echo "$line" | grep -o 'id [0-9a-f]\{4\}:[0-9a-f]\{4\}' | cut -d' ' -f2)"
        ifs="$(echo "$line" | grep -o 'with-interface {[^}]*}\|with-interface [0-9a-f:]*' | head -1)"
        toks="$(echo "$ifs" | grep -oE '\b[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b')"
        cls=""; kbd=0
        echo "$toks" | grep -q '^03:' && cls="HID"
        echo "$toks" | grep -q '^03:01:01' && kbd=1          # HID boot keyboard — the BadUSB signature
        echo "$toks" | grep -Eq '^(02:06:|02:00:|e0:01:03|ef:04:01)' && cls="${cls:+$cls+}NET"
        echo "$toks" | grep -q '^e0:01:01' && cls="${cls:+$cls+}BT"
        echo "$toks" | grep -q '^08:' && cls="${cls:+$cls+}STORAGE"
        [[ -z "$name" ]] && name="(no name)"
        # "In policy" = an explicit allow rule for this VID:PID exists. Serial is NOT used: a device
        # with an empty serial would otherwise match every other empty-serial allow line. Note that a
        # device spoofing a VID:PID already in the allow-list (common BadUSB trick) will read as in-policy.
        in_policy=0
        [[ -n "$vid" ]] && grep -Eq "^allow .*id $vid( |$)" /etc/usbguard/rules.conf 2>/dev/null && in_policy=1
        if [[ "$state" == "block" || "$state" == "reject" ]]; then
            bad "BLOCKED  [$id] $vid ${name} ${cls:+($cls)} — allow with: starhard-usb-allow $id"
        elif [[ $kbd -eq 1 && $in_policy -eq 0 ]]; then
            bad "KEYBOARD [$id] $vid ${name} — a HID keyboard not in your policy (keystroke injector / BadUSB looks exactly like this). If you did not just plug in a keyboard, unplug it."
        elif [[ "$cls" == *HID* || "$cls" == *NET* ]] && [[ $in_policy -eq 0 ]]; then
            note "allowed  [$id] $vid ${name} ($cls) — not in the policy file (plugged in since setup)"
        else
            detail "[$id] $vid ${name}${cls:+ ($cls)}"
        fi
    done < <(usbguard list-devices 2>/dev/null)
    # Attach / block events — USBGuard logs presence changes to the journal regardless of audit backend
    since_j="$DAYS days ago"
    if command -v journalctl >/dev/null 2>&1; then
        jlog="$(journalctl -u usbguard --since "$since_j" --no-pager 2>/dev/null)"
        ins="$(echo "$jlog" | grep -c 'event=Insert' || true)"
        [[ "${ins:-0}" -eq 0 ]] && ins="$(echo "$jlog" | grep -ci 'presence change.*insert' || true)"
        blk="$(echo "$jlog" | grep -E 'event=Insert' | grep -c 'target=block' || true)"
        if [[ "${blk:-0}" -gt 0 ]]; then note "$ins USB device insertion(s), $blk blocked   → journalctl -u usbguard --since '$since_j'"
        elif [[ "${ins:-0}" -gt 0 ]]; then note "$ins USB device insertion(s), none blocked (audit mode logs, does not block)   → journalctl -u usbguard --since '$since_j'"
        else ok "No USB insertions logged in $DAYS days"; fi
    fi
    if systemctl is-enabled -q starhard-usb-lock.service 2>/dev/null && ! systemctl is-active -q starhard-usb-lock.service 2>/dev/null; then
        bad "lock-screen USB watcher not running — new USB devices stay blocked until it is back: systemctl restart starhard-usb-lock"
    fi
elif command -v usbguard >/dev/null 2>&1; then
    bad "USBGuard installed but not running"
else
    note "USBGuard not installed — run StarHard section 20"
fi

hdr "Intrusion prevention"
if command -v cscli >/dev/null 2>&1 && systemctl is-active -q crowdsec 2>/dev/null; then
    n="$(cscli decisions list -o raw 2>/dev/null | tail -n +2 | grep -c . || true)"
    ok "CrowdSec running — $n active ban(s)   → cscli alerts list"
    if ! cscli bouncers list -o raw 2>/dev/null | grep -qi firewall; then bad "CrowdSec has NO firewall bouncer registered — it detects but does not block"; fi
    if systemctl is-active -q fail2ban 2>/dev/null; then bad "fail2ban is ALSO running — two ban engines conflict; run: StarHard.sh --sections 8 --ids crowdsec"; fi
elif command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active -q fail2ban 2>/dev/null; then
    b="$(fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $NF}')"
    t="$(fail2ban-client status sshd 2>/dev/null | grep 'Total banned' | awk '{print $NF}')"
    ok "fail2ban running — sshd: ${b:-0} banned now, ${t:-0} total"
else
    bad "No intrusion prevention service running"
fi
if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q 'Status: active'; then ok "ufw active"; else bad "ufw INACTIVE"; fi
elif command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state 2>/dev/null | grep -q running; then ok "firewalld running"; else bad "firewalld not running"; fi
elif command -v nft >/dev/null 2>&1 && [[ -f /etc/starhard/firewall.nft ]]; then
    if nft list table inet starhard >/dev/null 2>&1; then ok "nftables: StarHard default-deny table loaded"; else bad "nftables: StarHard table NOT loaded — run: nft -f /etc/starhard/firewall.nft"; fi
fi
# Docker publishes ports with its own NAT rules, which are evaluated before ufw/firewalld's input chains
if command -v docker >/dev/null 2>&1; then
    dports="$(docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | sed 's/^ *//' \
        | grep -E '^(0\.0\.0\.0|\[?::\]?):[0-9]+->' | sed -E 's/^.*:([0-9]+)->[0-9]+\/([a-z]+).*/\1\/\2/' | sort -u | tr '\n' ' ')"
    [[ -n "$dports" ]] && note "Docker publishes ${dports}to every interface — these bypass the host firewall (bind with -p 127.0.0.1:PORT:PORT, or filter in the DOCKER-USER chain)"
fi

hdr "Lynis"
if [[ -f /var/lib/starhard/lynis-index ]]; then
    read -r ts idx < <(tail -n1 /var/lib/starhard/lynis-index)
    note "Hardening index $idx/100 (run $ts)   → StarHard.sh --audit for a fresh one"
fi

if [[ $JSON -eq 1 ]]; then
    printf '{"host":"%s","generated":"%s","days":%d,"issues":%d,"items":[' \
        "$(json_esc "$(uname -n)")" "$(date -u +%FT%TZ)" "$DAYS" "$ISSUES"
    for i in "${!REC_L[@]}"; do
        [[ $i -gt 0 ]] && printf ','
        printf '{"level":"%s","section":"%s","message":"%s"}' \
            "${REC_L[$i]}" "$(json_esc "${REC_S[$i]}")" "$(json_esc "${REC_M[$i]}")"
    done
    printf ']}\n'
else
    out ""
    if [[ $ISSUES -eq 0 ]]; then out "${G}Nothing needs attention.${N}"; else out "${R}$ISSUES item(s) need attention.${N}"; fi
fi
[[ $ISSUES -eq 0 ]]
__STARHARD_STATUS__

    # Daily check that pushes a notification only when the picture changes
    write_file /usr/local/sbin/starhard-notify 755 <<'__STARHARD_NOTIFY__'
#!/usr/bin/env bash
# starhard-notify — run starhard-status and push the result, but only when it CHANGES.
# Runs daily from starhard-notify.timer. Nothing is sent while the set of "!!" items stays the same,
# so a hook can be as loud as you like (mail, phone push) without becoming noise.
#
# Usage: sudo starhard-notify [--force] [--test]
#   --force   notify even if nothing changed since the last run
#   --test    send a test message through every enabled hook and exit
#
# Hooks: every executable file in /etc/starhard/notify.d/ (root-owned, not group/world-writable,
# name not ending in .example) is run with the plain-text digest on stdin and these variables:
#   STARHARD_HOST      hostname
#   STARHARD_ISSUES    number of "!!" items now
#   STARHARD_PREVIOUS  number at the last notification
#   STARHARD_STATE     new-issues | changed | resolved | test
#   STARHARD_SUMMARY   one line, e.g. "myhost: 2 item(s) need attention"
#   STARHARD_ITEMS     the "!!" lines, one per line
# Settings shared by the shipped examples live in /etc/starhard/notify.conf.
FORCE=0; TEST=0
for a in "$@"; do
    case "$a" in
        --force) FORCE=1 ;;
        --test)  TEST=1 ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $a" >&2; exit 2 ;;
    esac
done
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo starhard-notify" >&2; exit 2; }

STATE_DIR=/var/lib/starhard
HOOK_DIR=/etc/starhard/notify.d
STATUS="$(command -v starhard-status || echo /usr/local/sbin/starhard-status)"
mkdir -p "$STATE_DIR"
HOST="$(uname -n)"

run_hooks() {
    # run_hooks <digest-file>
    local digest="$1" h ran=0 mode owner
    [[ -d "$HOOK_DIR" ]] || return 0
    for h in "$HOOK_DIR"/*; do
        [[ -f "$h" && -x "$h" && "$h" != *.example ]] || continue
        # A hook runs as root: refuse anything a non-root user could have edited.
        owner="$(stat -c %u "$h")"; mode="$(stat -c %a "$h")"
        if [[ "$owner" != "0" || $(( 8#$mode & 8#022 )) -ne 0 ]]; then
            logger -t starhard-notify "skipping $h: must be owned by root and not group/world-writable"
            continue
        fi
        if timeout 60 "$h" < "$digest" >/dev/null 2>&1; then ran=$((ran+1))
        else logger -t starhard-notify "hook $h failed (exit $?)"; fi
    done
    echo "$ran"
}

TMP="$(mktemp -d /tmp/starhard-notify.XXXXXX)"; trap 'rm -rf "$TMP"' EXIT

if [[ $TEST -eq 1 ]]; then
    printf 'This is a test notification from starhard-notify on %s.\n' "$HOST" > "$TMP/digest"
    export STARHARD_HOST="$HOST" STARHARD_ISSUES=0 STARHARD_PREVIOUS=0 STARHARD_STATE=test
    export STARHARD_SUMMARY="$HOST: StarHard test notification" STARHARD_ITEMS=""
    n="$(run_hooks "$TMP/digest")"
    echo "Test sent through ${n:-0} hook(s) in $HOOK_DIR"
    [[ "${n:-0}" -gt 0 ]] || echo "No enabled hooks. Copy an example: cp $HOOK_DIR/20-ntfy.example $HOOK_DIR/20-ntfy && chmod 700 $HOOK_DIR/20-ntfy"
    exit 0
fi

"$STATUS" > "$TMP/digest" 2>&1; rc=$?
if [[ $rc -ge 2 ]]; then
    logger -t starhard-notify "starhard-status failed (exit $rc)"
    exit 1
fi
# The "!!" lines are the alert content. Numbers are masked for the comparison so that
# "23 failed logins" -> "31 failed logins" does not count as a new problem every day.
ITEMS="$(grep -E '^  !!' "$TMP/digest" | sed -E 's/^  !! +//')"
ISSUES="$(grep -cE '^  !!' "$TMP/digest" || true)"
FP="$(printf '%s\n' "$ITEMS" | sed -E 's/[0-9]+/#/g' | sort | sha256sum | cut -d' ' -f1)"
PREV_FP=""; PREV_N=0
if [[ -r "$STATE_DIR/notify-state" ]]; then
    read -r PREV_FP PREV_N < "$STATE_DIR/notify-state"
    [[ "$PREV_N" =~ ^[0-9]+$ ]] || PREV_N=0
fi

# Login banner: always current, even when no hook is configured
if [[ $ISSUES -gt 0 ]]; then SUMMARY="$HOST: $ISSUES item(s) need attention — sudo starhard-status"
else SUMMARY="$HOST: nothing needs attention"; fi
printf '%s %s\n' "$(date '+%F %H:%M')" "$SUMMARY" > "$STATE_DIR/last-status"
chmod 644 "$STATE_DIR/last-status"

if [[ "$FP" == "$PREV_FP" && $FORCE -eq 0 ]]; then
    exit 0
fi
if   [[ $ISSUES -eq 0 && $PREV_N -eq 0 && $FORCE -eq 0 ]]; then
    # first run on a clean system: record the state, say nothing
    printf '%s %s\n' "$FP" "$ISSUES" > "$STATE_DIR/notify-state"; exit 0
elif [[ $ISSUES -eq 0 ]];   then STATE=resolved
elif [[ $PREV_N -eq 0 ]];   then STATE=new-issues
else                             STATE=changed
fi

export STARHARD_HOST="$HOST" STARHARD_ISSUES="$ISSUES" STARHARD_PREVIOUS="$PREV_N" STARHARD_STATE="$STATE"
export STARHARD_SUMMARY="$SUMMARY" STARHARD_ITEMS="$ITEMS"
n="$(run_hooks "$TMP/digest")"
logger -t starhard-notify "$SUMMARY (state: $STATE, ${n:-0} hook(s) notified)"
printf '%s %s\n' "$FP" "$ISSUES" > "$STATE_DIR/notify-state"
exit 0
__STARHARD_NOTIFY__
    write_timer starhard-notify "StarHard daily status check (notifies on change)" daily /usr/local/sbin/starhard-notify
    install_notify_hooks

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

    # sudo hardening. No log_input: it records everything typed inside a sudo session, including
    # passwords given to the programs run that way, in clear text under /var/log/sudo-io.
    if command -v visudo >/dev/null 2>&1; then
        write_file /etc/sudoers.d/50-starhard 440 <<'EOF'
# StarHard
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
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
        info "USBGuard policy already exists ($(grep -c '^allow' "$rules" 2>/dev/null || true) allow rules) — keeping it"
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
# Every new device plugged in while the screen is locked is blocked by starhard-usb-lock.service
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

    # Desktop: block every NEW device (keyboards, injectors, storage ...) while the screen is locked.
    # Implemented as a logind hook that swaps the implicit policy, so nothing is lost on unlock.
    if [[ "$PROFILE" != "server" ]]; then
        write_file /usr/local/sbin/starhard-usb-lockhook 755 <<'EOF'
#!/bin/sh
# Called by starhard-usb-lock.service. lock = block every new USB device; unlock = allow again.
case "$1" in
    lock)   usbguard set-parameter ImplicitPolicyTarget block >/dev/null 2>&1 ;;
    unlock) usbguard set-parameter ImplicitPolicyTarget allow >/dev/null 2>&1 ;;
esac
EOF
        # Watcher on logind's lock state (GNOME, KDE, labwc/swaylock ... anything that sets LockedHint)
        write_file /usr/local/sbin/starhard-usb-lockwatch 755 <<'EOF'
#!/usr/bin/env bash
# Follows logind's LockedHint across all sessions and switches USBGuard's implicit policy:
# any session locked -> new devices blocked; none locked -> allowed again.
# Event-driven: reacts to logind's D-Bus signals as they happen, so there is no polling window in
# which a device plugged in right after locking is still accepted. A slow re-check runs as a safety net.
hook=/usr/local/sbin/starhard-usb-lockhook
state=""
apply() {
    local locked=0 sid
    for sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
        if [[ "$(loginctl show-session "$sid" -p LockedHint --value 2>/dev/null)" == "yes" ]]; then locked=1; break; fi
    done
    if [[ $locked -eq 1 && "$state" != "locked" ]]; then "$hook" lock && state=locked
    elif [[ $locked -eq 0 && "$state" != "unlocked" ]]; then "$hook" unlock && state=unlocked
    fi
}
apply
if ! command -v busctl >/dev/null 2>&1; then
    while :; do sleep 2; apply; done
fi
mon=(busctl monitor --system --match "type='signal',sender='org.freedesktop.login1'")
command -v stdbuf >/dev/null 2>&1 && mon=(stdbuf -oL "${mon[@]}")
while :; do
    IFS= read -r -t 10 line; rc=$?
    if [[ $rc -gt 128 ]]; then apply; continue; fi   # quiet for 10 s: safety-net re-check
    [[ $rc -ne 0 ]] && exit 1                        # monitor ended: exit, systemd restarts us
    case "$line" in
        *LockedHint*|*Member=Lock*|*Member=Unlock*|*Member=SessionNew*|*Member=SessionRemoved*) apply ;;
    esac
done < <("${mon[@]}" 2>/dev/null)
EOF
        write_file /etc/systemd/system/starhard-usb-lock.service 644 <<'EOF'
[Unit]
Description=StarHard: block new USB devices while the screen is locked
After=usbguard.service systemd-logind.service
Requires=usbguard.service
PartOf=usbguard.service

[Service]
ExecStart=/usr/local/sbin/starhard-usb-lockwatch
# Fail closed: whenever the watcher is not running, new devices are blocked
ExecStopPost=-/usr/local/sbin/starhard-usb-lockhook lock
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
        [[ $DRY_RUN -eq 0 ]] && systemctl daemon-reload
    elif [[ $DRY_RUN -eq 0 ]] && unit_exists starhard-usb-lock.service; then
        # switched from desktop to server: the watcher would re-allow devices on unlock
        systemctl disable --now starhard-usb-lock.service >> "$LOG_FILE" 2>&1 || true
        info "Server profile: lock-screen watcher from an earlier desktop run disabled (everything unknown is blocked anyway)"
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
    if [[ "$PROFILE" != "server" ]]; then
        svc_enable starhard-usb-lock.service
        # the watcher's stop action leaves "block" behind; an undo must put "allow" back
        rb "usbguard set-parameter ImplicitPolicyTarget allow 2>/dev/null || true"
        [[ $DRY_RUN -eq 0 ]] && systemctl try-restart starhard-usb-lock.service >> "$LOG_FILE" 2>&1
    fi

    if [[ "$PROFILE" == "server" ]]; then
        warn "USBGuard BLOCKS every USB device not attached right now. Authorise new ones: starhard-usb-allow <id>"
    else
        info "USBGuard: logging all attaches; USB network adapters and HID-hubs blocked; every new device blocked while the screen is locked"
    fi
    return 0
}

#===============================================================================
# 21. Kernel boot parameters (opt-in: --boot-params / --boot-lockdown)
#===============================================================================
bp_missing() {
    # bp_missing <current command line> -> the parameters from boot_param_list not on it.
    # A parameter the admin already set to another value (init_on_free=0) is left alone.
    local cur=" $1 " p key out=""
    for p in $(boot_param_list); do
        key="${p%%=*}"
        [[ "$cur" == *" $key "* || "$cur" == *" $key="* ]] || out+=" $p"
    done
    echo "${out# }"
}

sec_bootparams() {
    local params missing
    params="$(boot_param_list)"
    info "Parameters: $params"
    if [[ $IS_PI -eq 1 ]]; then
        local cl="$PI_BOOT/cmdline.txt"
        if [[ -z "$PI_BOOT" || ! -f "$cl" ]]; then warn "cmdline.txt not found — boot parameters skipped"; return 0; fi
        missing="$(bp_missing "$(head -1 "$cl")")"
        if [[ -z "$missing" ]]; then info "Already present in $cl"; return 0; fi
        if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would append to $cl: $missing"; return 0; fi
        backup_file "$cl"
        sed -i "1s|[[:space:]]*\$| $missing|" "$cl"
        log "Added to $cl: $missing"
    elif command -v grubby >/dev/null 2>&1; then
        missing="$(bp_missing "$(grubby --info=DEFAULT 2>/dev/null | sed -n 's/^args="\(.*\)"/\1/p')")"
        if [[ -z "$missing" ]]; then info "Already on the kernel command line (grubby)"; return 0; fi
        if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would run: grubby --update-kernel=ALL --args=\"$missing\""; return 0; fi
        rb "grubby --update-kernel=ALL --remove-args='$missing' 2>/dev/null || true"
        run "grubby: add boot parameters" grubby --update-kernel=ALL --args="$missing"
    elif [[ -f /etc/default/grub ]] && command -v update-grub >/dev/null 2>&1; then
        # Debian family: grub-mkconfig reads /etc/default/grub.d/*.cfg after /etc/default/grub
        write_file /etc/default/grub.d/99-starhard.cfg 644 <<EOF
# StarHard section 21: kernel hardening parameters. Delete this file and run update-grub to undo.
GRUB_CMDLINE_LINUX="\$GRUB_CMDLINE_LINUX $params"
EOF
        if [[ $DRY_RUN -eq 0 ]]; then
            if grub_regen >> "$LOG_FILE" 2>&1; then log "GRUB configuration regenerated"; else warn "update-grub failed (see $LOG_FILE)"; fi
        fi
    elif [[ -f /etc/default/grub ]]; then
        # Other GRUB systems: /etc/default/grub is a shell fragment, so a final assignment extends it
        if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would append the parameters to GRUB_CMDLINE_LINUX in /etc/default/grub"; return 0; fi
        backup_file /etc/default/grub
        sed -i '/# StarHard boot parameters$/d' /etc/default/grub
        echo "GRUB_CMDLINE_LINUX=\"\${GRUB_CMDLINE_LINUX:-} $params\"  # StarHard boot parameters" >> /etc/default/grub
        if grub_regen >> "$LOG_FILE" 2>&1; then log "GRUB configuration regenerated"; else warn "grub-mkconfig failed (see $LOG_FILE)"; fi
    elif [[ -f /etc/kernel/cmdline ]]; then
        missing="$(bp_missing "$(cat /etc/kernel/cmdline)")"
        if [[ -z "$missing" ]]; then info "Already present in /etc/kernel/cmdline"; return 0; fi
        if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would append to /etc/kernel/cmdline: $missing"; return 0; fi
        backup_file /etc/kernel/cmdline
        sed -i "1s|[[:space:]]*\$| $missing|" /etc/kernel/cmdline
        log "Added to /etc/kernel/cmdline: $missing"
        warn "systemd-boot / UKI: regenerate the boot entries for this to apply (kernel-install add-all, or reinstall the kernel package)"
    else
        warn "No supported bootloader configuration found — add these to the kernel command line yourself: $params"
        return 0
    fi
    warn "Boot parameters apply after a reboot. If the machine fails to boot, edit the kernel line in the boot menu and remove them."
    [[ $BOOT_LOCKDOWN -eq 1 ]] && warn "lockdown=integrity: unsigned kernel modules (VirtualBox, NVIDIA DKMS without signing) and hibernation will stop working."
    return 0
}

#===============================================================================
# 22. systemd sandboxing for network-facing daemons (opt-in: --sandbox-services)
#===============================================================================
# Units left alone: they need kernel/device/namespace access, manage the network or clock, or are
# the way you log in. Everything else that listens on the network is offered the baseline below.
SANDBOX_SKIP_RE='^(ssh|sshd|ssh@.*|systemd-.*|user@.*|dbus.*|NetworkManager.*|wpa_supplicant.*|iwd|docker|containerd|podman.*|libvirtd|virt.*|tailscaled|wg-quick@.*|openvpn.*|strongswan.*|crowdsec.*|fail2ban|usbguard|auditd|rsyslog|pihole-FTL|cups.*|avahi-daemon|gdm.*|sddm|lightdm|display-manager|getty@.*|polkit|snapd.*|k3s.*|kubelet|lxd.*|incus.*|chrony|chronyd|ntp.*|rpcbind|nfs-.*|firewalld|ufw|nftables|iptables.*)\.service$'

sandbox_exposure() { systemd-analyze security "$1" 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+ [A-Z]+' | head -1; }

sec_sandbox() {
    if ! has_systemd; then info "Service sandboxing needs systemd — skipped"; return 0; fi
    # systemd units that own a listening socket on a non-loopback address
    local pid cg u units=""
    for pid in $(ss -H -tulnp 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\]|::1)/' | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -un); do
        cg="$(awk -F: '$1=="0" {print $3; exit}' "/proc/$pid/cgroup" 2>/dev/null)"
        [[ "$cg" == /system.slice/* ]] || continue
        u="${cg##*/}"
        [[ "$u" == *.service && " $units " != *" $u "* ]] && units+=" $u"
    done
    if [[ -z "${units// /}" ]]; then info "No systemd service is listening on the network — nothing to sandbox"; return 0; fi

    local dropin before after skipped="" done_n=0
    for u in $units; do
        if [[ "$u" =~ $SANDBOX_SKIP_RE ]]; then skipped+=" ${u%.service}"; continue; fi
        dropin="/etc/systemd/system/$u.d/50-starhard-sandbox.conf"
        before="$(sandbox_exposure "$u")"
        if [[ -f "$dropin" ]]; then info "$u already sandboxed (exposure ${before:-?})"; continue; fi
        if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would sandbox $u (exposure now ${before:-?}) and restart it"; continue; fi
        ask "Sandbox $u (exposure now ${before:-?})? The service is restarted; the change is undone if it does not come back." || continue
        write_file "$dropin" 644 <<'EOF'
# StarHard section 22: baseline sandbox. None of these take anything a network daemon normally needs.
# Remove this file, then: systemctl daemon-reload && systemctl restart <unit>
[Service]
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF
        systemctl daemon-reload
        if systemctl restart "$u" >> "$LOG_FILE" 2>&1 && sleep 3 && systemctl is-active -q "$u"; then
            after="$(sandbox_exposure "$u")"
            log "$u sandboxed and running — exposure ${before:-?} -> ${after:-?}"
            done_n=$((done_n+1))
        else
            err "$u did not come back with the sandbox — removing the drop-in and restarting it as before"
            rm -f "$dropin"; rmdir "/etc/systemd/system/$u.d" 2>/dev/null
            systemctl daemon-reload
            systemctl restart "$u" >> "$LOG_FILE" 2>&1 || err "$u is still failing — check: journalctl -u $u -e"
        fi
    done
    [[ -n "$skipped" ]] && info "Left alone (need kernel, device or namespace access, or are your way in):$skipped"
    [[ $done_n -gt 0 ]] && info "A restart only proves the service starts. Use it for a day; to go further: systemd-analyze security <unit>"
    return 0
}

#===============================================================================
# 23. Docker daemon (opt-in: --docker-harden)
#===============================================================================
sec_docker() {
    if ! command -v docker >/dev/null 2>&1; then info "Docker not installed — skipped"; return 0; fi
    local f=/etc/docker/daemon.json lr=true new=""
    # live-restore keeps containers running across daemon restarts, but the daemon refuses to start with it in swarm mode
    [[ "$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)" == "active" ]] && lr=false
    if [[ -s "$f" ]]; then
        if command -v jq >/dev/null 2>&1; then
            new="$(jq --argjson lr "$lr" '. + {"no-new-privileges": true, "icc": false}
                    + (if $lr then {"live-restore": true} else {} end)
                    + (if has("log-driver") then {} else {"log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "3"}} end)' "$f" 2>>"${LOG_FILE:-/dev/null}")"
        elif command -v python3 >/dev/null 2>&1; then
            new="$(LR="$lr" python3 - "$f" <<'PY' 2>>"${LOG_FILE:-/dev/null}"
import json, os, sys
with open(sys.argv[1]) as fh:
    cfg = json.load(fh)
cfg["no-new-privileges"] = True
cfg["icc"] = False
if os.environ.get("LR") == "true":
    cfg["live-restore"] = True
if "log-driver" not in cfg:
    cfg["log-driver"] = "json-file"
    cfg["log-opts"] = {"max-size": "10m", "max-file": "3"}
print(json.dumps(cfg, indent=2))
PY
)"
        else
            warn "Neither jq nor python3 is available to merge $f — add by hand: \"no-new-privileges\": true, \"icc\": false, \"live-restore\": true"
            return 0
        fi
        if [[ -z "$new" ]]; then err "$f is not valid JSON — left untouched"; return 0; fi
    else
        new='{
  "no-new-privileges": true,
  "icc": false,'
        [[ "$lr" == "true" ]] && new+='
  "live-restore": true,'
        new+='
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}'
    fi
    printf '%s\n' "$new" | write_file "$f" 644
    info "Docker: no-new-privileges (setuid binaries inside containers cannot escalate), icc=false (containers on the"
    info "default bridge cannot reach each other; user-defined/compose networks are unaffected), log size capped$( [[ "$lr" == "true" ]] && echo ', live-restore')"
    info "Not applied: userns-remap (changes the ownership of existing volumes — enable it deliberately)"

    if [[ $DRY_RUN -eq 0 ]]; then
        if command -v dockerd >/dev/null 2>&1 && dockerd --help 2>&1 | grep -q -- '--validate'; then
            if ! dockerd --validate --config-file "$f" >> "$LOG_FILE" 2>&1; then
                err "dockerd rejected the new daemon.json — restoring the previous one"
                if [[ -e "$BACKUP_DIR$f" ]]; then cp -a "$BACKUP_DIR$f" "$f"; else rm -f "$f"; fi
                return 0
            fi
        fi
        # Containers that already hold the keys to the host
        local risky
        risky="$(docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} {{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null \
            | awk '/privileged=true/ {print "    " $1 "  (--privileged)"} /docker\.sock/ {print "    " $1 "  (mounts docker.sock = root on the host)"}')"
        [[ -n "$risky" ]] && { warn "Containers with host-level access (review whether each needs it):"; echo "$risky"; }
        if [[ $ASSUME_YES -eq 1 ]]; then
            warn "Docker NOT restarted (-y). The settings apply on the next daemon restart: systemctl restart docker"
        elif ask "Restart Docker now to apply? Running containers stop and come back per their restart policy."; then
            if systemctl restart docker >> "$LOG_FILE" 2>&1 && docker info >/dev/null 2>&1; then
                log "Docker restarted with the hardened configuration"
            else
                err "Docker did not start — restoring the previous daemon.json"
                if [[ -e "$BACKUP_DIR$f" ]]; then cp -a "$BACKUP_DIR$f" "$f"; else rm -f "$f"; fi
                systemctl restart docker >> "$LOG_FILE" 2>&1 || err "Docker still failing — check: journalctl -u docker -e"
            fi
        else
            info "Apply later with: systemctl restart docker"
        fi
    fi
    return 0
}

#===============================================================================
# 24. Encrypted DNS and authenticated time (opt-in: --secure-dns <provider>, --secure-time)
#===============================================================================
sec_secure_dns() {
    if [[ $HAS_PIHOLE -eq 1 ]]; then
        info "Pi-hole is this machine's resolver — encrypt its upstream there (unbound or cloudflared); DNS-over-TLS skipped"
        return 0
    fi
    if ! has_systemd || ! systemctl is-active -q systemd-resolved 2>/dev/null; then
        info "systemd-resolved is not running — DNS-over-TLS not configured (set it up in your resolver: NetworkManager, unbound ...)"
        return 0
    fi
    local servers mode="opportunistic"
    case "$SECURE_DNS" in
        quad9)      servers="9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net" ;;
        cloudflare) servers="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com 2606:4700:4700::1001#cloudflare-dns.com" ;;
    esac
    # Strict mode fails closed, which is right for a server; a laptop has to get through captive portals
    [[ "$PROFILE" == "server" ]] && mode="yes"
    write_file /etc/systemd/resolved.conf.d/50-starhard.conf 644 <<EOF
# StarHard section 24: DNS-over-TLS via $SECURE_DNS. Delete this file and restart systemd-resolved to undo.
[Resolve]
DNS=$servers
DNSOverTLS=$mode
Domains=~.
EOF
    [[ $DRY_RUN -eq 1 ]] && return 0
    systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1
    sleep 2
    if timeout 15 resolvectl query example.com >/dev/null 2>&1 || timeout 15 getent hosts example.com >/dev/null 2>&1; then
        log "DNS-over-TLS active ($SECURE_DNS, mode: $mode) — name resolution verified"
        info "All lookups now go to $SECURE_DNS. Names that only your router's DNS knows (printer.lan) may stop resolving."
        [[ $HAS_TAILSCALE -eq 1 ]] && info "Tailscale MagicDNS names keep working (resolved routes *.ts.net to the tailscale0 link)."
    else
        err "Name resolution failed with DNS-over-TLS — removing the configuration"
        rm -f /etc/systemd/resolved.conf.d/50-starhard.conf
        systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1
    fi
    return 0
}

sec_secure_time() {
    if ! command -v chronyd >/dev/null 2>&1; then
        info "Installing chrony (on Debian/Ubuntu it replaces systemd-timesyncd)"
        pkg_install chrony
        if [[ $DRY_RUN -eq 1 ]]; then info "DRY-RUN: would add NTS time sources to chrony"; return 0; fi
        command -v chronyd >/dev/null 2>&1 || { warn "chrony could not be installed — authenticated time skipped"; return 0; }
    fi
    if ! chronyd --version 2>/dev/null | grep -q '+NTS'; then
        warn "This chrony build has no NTS support (needs chrony 4.0+) — authenticated time skipped"
        return 0
    fi
    local conf="" dir=""
    for conf in /etc/chrony/chrony.conf /etc/chrony.conf ""; do [[ -n "$conf" && -f "$conf" ]] && break; done
    if [[ -z "$conf" ]]; then warn "chrony.conf not found — authenticated time skipped"; return 0; fi
    dir="$(awk '$1=="confdir" {print $2; exit}' "$conf")"
    local body
    body='# StarHard section 24: authenticated time (NTS). With "prefer", plain NTP sources are only used
# when no authenticated source is reachable.
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
server ntppool1.time.nl iburst nts
authselectmode prefer'
    if [[ -n "$dir" ]]; then
        printf '%s\n' "$body" | write_file "$dir/starhard-nts.conf" 644
    elif [[ $DRY_RUN -eq 1 ]]; then
        info "DRY-RUN: would append NTS sources to $conf"; return 0
    else
        backup_file "$conf"
        sed -i '/^# >>> StarHard NTS$/,/^# <<< StarHard NTS$/d' "$conf"
        printf '# >>> StarHard NTS\n%s\n# <<< StarHard NTS\n' "$body" >> "$conf"
        log "NTS sources added to $conf"
    fi
    [[ $DRY_RUN -eq 1 ]] && return 0
    local unit=""
    for unit in chrony.service chronyd.service ""; do [[ -n "$unit" ]] && unit_exists "$unit" && break; done
    if [[ -n "$unit" ]]; then
        svc_enable "$unit"
        systemctl restart "$unit" >> "$LOG_FILE" 2>&1
        sleep 6
        if chronyc -N authdata 2>/dev/null | awk '$2=="NTS" && $4>0 {ok=1} END {exit !ok}'; then
            log "chrony: NTS key exchange succeeded — time is authenticated"
        else
            warn "chrony restarted, but no NTS session yet (outbound TCP 4460 blocked?). Check in a minute: chronyc -N authdata"
        fi
    else
        warn "No chrony service unit found — start chronyd yourself"
    fi
    return 0
}

sec_secure_net() {
    [[ -n "$SECURE_DNS" ]] && sec_secure_dns
    [[ $SECURE_TIME -eq 1 ]] && sec_secure_time
    return 0
}

save_config() {
    # Remember the options for re-runs, --audit and the helpers
    [[ $DRY_RUN -eq 0 ]] || return 0
    mkdir -p "$(dirname "$CONF_FILE")"
    [[ -e "$CONF_FILE" ]] || record_rm "$CONF_FILE"
    cat > "$CONF_FILE" <<EOF
# StarHard: options used on the last run ($TS, v$VERSION). Later runs and --audit default to
# these; command-line flags override them. One KEY=value per line; unknown lines are ignored.
PROFILE=$PROFILE
IDS=$IDS
PIHOLE_LAN=$PIHOLE_LAN
PI_DISABLE_WIFI=$PI_DISABLE_WIFI
PI_DISABLE_BT=$PI_DISABLE_BT
BOOT_PARAMS=$BOOT_PARAMS
BOOT_LOCKDOWN=$BOOT_LOCKDOWN
SANDBOX=$SANDBOX
DOCKER_HARDEN=$DOCKER_HARDEN
SECURE_DNS=$SECURE_DNS
SECURE_TIME=$SECURE_TIME
EOF
    chmod 644 "$CONF_FILE"
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
# Opt-in sections
[[ $BOOT_PARAMS -eq 1 ]]   && section 21 "kernel boot parameters (opt-in)"     sec_bootparams
[[ $SANDBOX -eq 1 ]]       && section 22 "service sandboxing (opt-in)"         sec_sandbox
[[ $DOCKER_HARDEN -eq 1 ]] && section 23 "Docker daemon (opt-in)"              sec_docker
[[ -n "$SECURE_DNS" || $SECURE_TIME -eq 1 ]] && section 24 "encrypted DNS / authenticated time (opt-in)" sec_secure_net
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
        echo "command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --reload 2>/dev/null || true"
        echo "echo 'Rollback of run $TS complete — reboot now. Audit rules in immutable mode reset on reboot.'"
    } >> "$ROLLBACK"
    save_config
    write_original_rollback
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
echo "  9  auditd rules + retention + process accounting"
echo "  10 AIDE baseline + daily check timer + refresh after package changes"
echo "  11 Weekly starhard-scan: ClamAV, unhide, package integrity, Lynis; daily starhard-notify"
echo "  12 Automatic security updates"
echo "  13 Banners, permissions (tighten-only), sudo use_pty/logfile"
echo "  14 AppArmor enforce / SELinux status"
echo "  15 ctrl-alt-del masked, persistent journald, /dev/shm noexec$( [[ "$PROFILE" == "server" ]] && echo ', /tmp noexec, avahi/cups/bt masked')"
echo "  16 Cleanup: legacy packages, residuals, old kernels, docker (opt-in)"
echo "  17 GRUB password (interactive)"
echo "  18 Lynis audit run, warnings/suggestions mapped to sections, index tracked in $STATE_DIR/lynis-index"
echo "  20 USBGuard: $( [[ "$PROFILE" == "server" ]] && echo 'block unknown devices' || echo 'audit mode + block USB-network/HID-hub + block every new device while locked' ) — authorise: starhard-usb-allow <id>"
[[ $IS_PI -eq 1 ]] && echo "  19 Raspberry Pi: EEPROM, boot-config auditing, Pi update origin, radios$( [[ "$PROFILE" == "server" ]] && echo ', serial console')"
[[ $BOOT_PARAMS -eq 1 ]]   && echo "  21 Kernel boot parameters: $(boot_param_list)"
[[ $SANDBOX -eq 1 ]]       && echo "  22 systemd sandbox drop-ins for network-facing services"
[[ $DOCKER_HARDEN -eq 1 ]] && echo "  23 Docker daemon.json hardening"
[[ -n "$SECURE_DNS" || $SECURE_TIME -eq 1 ]] && echo "  24$( [[ -n "$SECURE_DNS" ]] && echo " DNS-over-TLS ($SECURE_DNS)")$( [[ $SECURE_TIME -eq 1 ]] && echo ' NTS time (chrony)')"
[[ $BOOT_PARAMS -eq 0 || $SANDBOX -eq 0 || $DOCKER_HARDEN -eq 0 ]] && echo "  Opt-in extras not used: see --help (--boot-params, --sandbox-services, --docker-harden, --secure-dns, --secure-time)"
echo
echo "Backups + rollback script: $BACKUP_DIR"
echo "Log: $LOG_FILE"
echo
echo "Next steps:"
echo "  1. Reboot"
echo "  2. Verify:  sudo $0 --audit        (profile and options are remembered in $CONF_FILE)"
echo "  3. Status:  sudo starhard-status   (one-screen digest: scans, AIDE, audit, bans, updates)"
echo "  4. Scan:    sudo /usr/local/sbin/starhard-scan   (also runs weekly)"
echo "  5. Lynis:   see section 18 output above; 'lynis show details <TEST-ID>' for any item"
echo "  6. Alerts:  enable a hook in /etc/starhard/notify.d/ and test it: sudo starhard-notify --test"
echo "  7. Undo:    sudo $0 --rollback latest     (this run)"
echo "              sudo $0 --rollback original   (everything StarHard ever changed)   then reboot"
echo "==============================================================="
