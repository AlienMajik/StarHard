# StarHard

A universal Linux hardening script. One command applies a broad set of security best practices — kernel hardening, authentication policy, firewall, intrusion prevention, malware and rootkit scanning, file-integrity monitoring, USB device control, audit logging and system cleanup — on any major Linux distribution, then installs a one-command status digest so you can see at a glance whether anything is wrong. Designed to raise your [Lynis](https://cisofy.com/lynis/) hardening score significantly while staying safe for daily-use systems, Raspberry Pis and home servers.

**Current version: 1.2**

---

## Supported systems

| Family | Distros | Package manager |
|---|---|---|
| Debian | Debian, Ubuntu, Raspberry Pi OS, Parrot OS, Kali, Mint | `apt` |
| Red Hat | Fedora, RHEL, Rocky, AlmaLinux, CentOS Stream | `dnf` / `yum` |
| SUSE | openSUSE Leap / Tumbleweed, SLES | `zypper` |
| Arch | Arch, Manjaro, EndeavourOS | `pacman` |
| Alpine | Alpine Linux | `apk` |

Architectures: x86_64 and aarch64 (Raspberry Pi 4/5, other ARM boards). StarHard auto-detects the distro from `/etc/os-release`, the hardware from the device tree, and the services it needs to work around (Tailscale, Pi-hole) from what's installed — no configuration needed.

**Requirements:** root (`sudo`), bash, an internet connection for package installs, and systemd (Alpine's OpenRC is supported with reduced functionality: no timers, no CrowdSec, no USBGuard).

---

## Installation

1. Download `StarHard.sh` (and optionally `starhard-status`, which the script also installs for you).
2. Make it executable:

   ```bash
   chmod +x StarHard.sh
   ```

3. Skim it before running. Never run a root script you haven't at least glanced at.

StarHard is a single self-contained file. Everything it installs onto the system (`starhard-scan`, `starhard-status`, `starhard-aide-check`, `starhard-usb-allow`) is written by the script itself into `/usr/local/sbin/`.

---

## Recommended workflow

```bash
# 1. Preview — nothing is modified in this mode
sudo ./StarHard.sh --dry-run

# 2. Apply (desktop profile)                  or on a headless box / server:
sudo ./StarHard.sh                             sudo ./StarHard.sh --profile server

# 3. Reboot — module blacklists, audit rules (immutable mode), PAM and boot-config changes need it
sudo reboot

# 4. Verify: PASS/FAIL checklist of everything StarHard set, then a fresh Lynis audit
sudo ./StarHard.sh --audit

# 5. From then on, once a week:
sudo starhard-status
```

A stock desktop typically starts in the 60s and lands in the low-to-mid 80s. Don't chase 100 — past ~85 the remaining Lynis points cost real functionality. Section 18 explains which suggestions StarHard covers and which are judgment calls.

> **Dry-run caveat:** dry-run inspects the system *as it is now*, before packages are installed. Sections that depend on tools from Section 1 (CrowdSec, AIDE, USBGuard, Lynis) may appear skipped in the preview but run on the real pass.

---

## Usage and options

```
sudo ./StarHard.sh [options]

  --dry-run             Show every change that would be made, without making any
  --audit               Report PASS/FAIL against the hardened state and run Lynis; change nothing
  --profile <p>         desktop (default) or server
  --sections a,b,c      Run only these section numbers
  --exclude a,b,c       Skip these section numbers
  --ids <i>             crowdsec or fail2ban for section 8 (default: crowdsec on server, fail2ban on desktop)
  --pihole-lan          Pi-hole: always open DNS/web to LAN subnets
  --no-lan-dns          Pi-hole: never open DNS/web to LAN (e.g. a Tailscale-only Pi-hole)
  --pi-disable-wifi     Raspberry Pi: disable the on-board Wi-Fi radio (refused if you're connected over it)
  --pi-disable-bt       Raspberry Pi: disable the on-board Bluetooth radio (automatic on server profile)
  -y, --yes             Assume "yes" to optional prompts (unattended runs)
  -h, --help            Help
```

### Desktop vs. server profile

| | `--profile desktop` (default) | `--profile server` |
|---|---|---|
| SSH password login | kept | **disabled** — only if an `authorized_keys` file exists, and only after confirmation |
| SSH forwarding / MaxAuthTries | TCP + agent forwarding allowed, 6 tries | forwarding off, 4 tries, `AllowUsers` restricted to users with keys (+ you) |
| Firewall SSH rule | added only when you're running over SSH | always, rate-limited |
| Intrusion prevention | fail2ban | CrowdSec + firewall bouncer |
| `/tmp`, `/var/tmp` | untouched | `nodev,nosuid,noexec` |
| Services | untouched | avahi, cups, bluetooth masked |
| USBGuard | audit mode + targeted blocks (see §20) | blocks every device not present at setup |
| AppArmor | asks before enforcing | enforces all profiles |
| Raspberry Pi | — | Bluetooth off, serial console login removed |

> **Server profile and SSH:** StarHard refuses to disable password authentication if no user has an `authorized_keys` file, always allows SSH through the firewall when it detects it's being run over SSH, validates the config with `sshd -t` and reverts on failure. It still cannot know whether *your* key works — test it in a second terminal first.

### Examples

```bash
sudo ./StarHard.sh                                  # interactive desktop hardening
sudo ./StarHard.sh --dry-run --profile server       # preview the server profile
sudo ./StarHard.sh --profile server -y              # unattended server hardening
sudo ./StarHard.sh --sections 2,6,9                 # re-apply only sysctl, SSH and auditd
sudo ./StarHard.sh --exclude 7,16                   # everything except firewall and cleanup
sudo ./StarHard.sh --ids crowdsec                   # CrowdSec on a desktop
sudo ./StarHard.sh --audit                          # compliance check, no changes
```

---

## What StarHard does

| # | Section | Details |
|---|---|---|
| 1 | Security packages | AIDE, auditd, Lynis, ClamAV + freshclam, unhide, debsums, sysstat, pwquality, firewall, USBGuard, auto-update tooling; fail2ban or CrowdSec per `--ids` (names adapted per distro) |
| 2 | Kernel / sysctl | ~40 settings: ptrace scope, kptr/dmesg restriction, BPF hardening, kexec off, `io_uring` disabled, unprivileged userfaultfd off, SYN cookies, redirect/source-route blocking, martian logging, IPv6 hardening. `rp_filter` goes loose (2) when Tailscale is present; `accept_ra` is left alone if the host has a SLAAC address |
| 3 | Module blacklist | dccp, sctp, rds, tipc, cramfs, freevxfs, jffs2, hfs, hfsplus, udf, firewire — both `install /bin/false` and `blacklist`; already-loaded modules are unloaded. Not firewire on a Pi |
| 4 | Authentication | umask 027, **yescrypt** where supported (SHA512/100k rounds otherwise), password aging, pwquality (minlen 14, 3 classes), **pam_faillock** lockout (5 failures / 15 min) via authselect or common-auth, cron/at restricted to root |
| 5 | Core dumps | Disabled via limits.d and systemd-coredump |
| 6 | SSH | Root login off, banner, idle timeout, verbose logging, modern KEX/cipher/MAC/host-key lists, `RequiredRSASize 3072`, `DebianBanner no` — each only when this sshd supports the keyword. Profile-aware forwarding/MaxAuthTries. Ensures `sshd_config.d` is actually included. Validated with `sshd -t` before reload |
| 7 | Firewall | ufw or firewalld, default-deny inbound. **Service-aware:** trusts `tailscale0` + UDP 41641; opens Pi-hole DNS/web to LAN subnets *only if Pi-hole's query log shows LAN clients*; lists every other listening port the policy will block; flags stale `ufw allow` rules for ports nothing listens on. Existing rules are never removed |
| 8 | Intrusion prevention | **CrowdSec** (official repo, nftables/iptables bouncer, linux+sshd collections, journal acquisition, loopback whitelist; fail2ban stopped and masked so the two never fight) or **fail2ban** (sshd + recidive jail, recidive fixed to `backend=auto`) |
| 9 | auditd | Identity files, sudoers, cron, SSH/PAM/MAC config, module loading, time changes, privilege escalation, mounts, deletions, permission changes, `/etc/ld.so.preload`, opens of `/dev/input/` by users (keylogger indicator), Pi boot config. Correct syscall names on aarch64. **De-duplicates against rules other tools already placed in `rules.d/`**, detects immutable mode. Process accounting + sysstat enabled |
| 10 | AIDE | Baseline database on first run; daily check timer (or defers to the distro's own daily job) |
| 11 | Scanning | Weekly `starhard-scan` timer: **ClamAV** (incl. mounted removable media; skips when < 1.5 GB RAM is free; honours an exclusion list at `/etc/starhard/clamav-exclude`, pre-filled on Parrot/Kali with the tool directories that contain exploit code by design), **unhide**, package integrity (debsums / `rpm -V` / `pacman -Qkk`), **Lynis**. Holds idle-suspend while running so laptops finish. Installs **`starhard-status`**. Offers to remove legacy rkhunter/chkrootkit |
| 12 | Auto-updates | unattended-upgrades (security origin, unused-dep removal, no auto-reboot; **+ Raspberry Pi Foundation and Tailscale origins** when detected), dnf-automatic, or a zypper patch timer. Warns on rolling distros (Parrot/Kali) where there's no security pocket |
| 13 | Banners, permissions, sudo | Legal banners (`/etc/issue`, `issue.net`, sshd `Banner`); **tighten-only** permissions (`chmod o-rwx` — never loosens RHEL's 0000 shadow); cron dirs, sudoers.d, grub.cfg, home directories; sudo `use_pty`, `logfile`, `log_input` |
| 14 | MAC | AppArmor enabled; profiles set to enforce (server: automatic, desktop: prompted — see FAQ). SELinux status reported |
| 15 | Services, mounts, journald | ctrl-alt-del masked; persistent journald with 500 MB cap; `/dev/shm` `nodev,nosuid,noexec`. Server: `/tmp` + `/var/tmp` hardened, avahi/cups/bluetooth masked |
| 16 | Cleanup | Legacy plaintext clients (rsh, tftp, talk, telnetd) purged if present; residual configs; `autoremove`; **opt-in** Docker prune (never with `-y`) |
| 17 | GRUB password | Optional, interactive. Password read silently; normal boots stay unrestricted. Uses `grub2-setpassword` on RHEL/Fedora. Skipped on Raspberry Pi |
| 18 | Lynis | Installs Lynis if missing, runs a full audit **last**, prints warnings and suggestions with each mapped to the StarHard section that addresses it (`-> section N`) or `-> manual`, annotates known false positives, tracks the hardening index across runs in `/var/lib/starhard/lynis-index` |
| 19 | Raspberry Pi | *Auto-detected.* No-bootloader-password / encryption warning, EEPROM update check and staging, `dtoverlay=disable-bt` / `disable-wifi` (Wi-Fi refused if that's how you're connected), auditd watches on `config.txt` / `cmdline.txt`, serial console removed on server, low-RAM note for ClamAV |
| 20 | USB device control | **USBGuard on every profile** (installs it if missing). Devices attached at setup are allowed. *Desktop:* audit mode (all attaches logged to auditd) plus hard blocks on USB network adapters (PoisonTap class) and HID-carrying hubs (injector cables), and **new HID blocked while the screen is locked**. *Server:* everything unknown blocked. StarHard's rules live in `/etc/usbguard/rules.d/` so a package upgrade can't erase them; daemon IPC is restricted to root (closes Debian bugs #1134751/#1135310). `starhard-usb-allow <id>` authorises a device |

Sections run in numeric order except 18 (Lynis), which runs last so it audits the finished state, and 19/20 which run just before it.

### `starhard-status` — the weekly check

```bash
sudo starhard-status            # last 7 days
sudo starhard-status --days 30
```

One screen, `OK` / `--` / `!!` per line, ending in *Nothing needs attention* or a count:

- **System** — reboot required, failed services (ignore list: `/etc/starhard/ignore-units`)
- **Updates** — pending security updates, last unattended-upgrade, Pi-hole version
- **Malware scan** — last `starhard-scan`: ClamAV hits (with file + signature), unhide results, package-integrity changes, signature age; "scan in progress" / "skipped (low memory)" when applicable
- **File integrity (AIDE)** — last check summary, changes in sensitive paths (`/etc/passwd`, `/etc/ssh`, `/usr/bin`…), stale-baseline detection with the rebuild command
- **Audit trail** — event counts per key (identity, sudoers, modules, boot config, preload, input devices…) with the exact `ausearch` command to drill in; failed logins
- **Keylogger indicators** — `/etc/ld.so.preload` and system-wide `LD_PRELOAD`; every process holding `/dev/input/*` (expected compositors `OK`, unknown `--`, anything from `/tmp`, `/home`, `/dev/shm` or a deleted binary `!!`); X11-session warning
- **USB devices** — attached devices with vendor:product and HID / NET / BT / STORAGE tags, blocked devices with the allow command, HID/NET devices allowed but not in the original policy, the week's attach/block events
- **Intrusion prevention** — CrowdSec/fail2ban state, active bans, bouncer registered, warns if both are running; firewall state
- **Lynis** — last hardening index

Everything else runs on its own: ClamAV signatures every few hours, AIDE nightly, the full scan weekly, security updates daily.

### What it deliberately does NOT do

- **Repartitioning** (`/home`, `/var` separate) — can't be done safely after install
- **Removing compilers/dev tools** — you likely need them, especially on Parrot/Kali
- **Blindly enforcing every AppArmor profile** — Debian's `apparmor-profiles` extras ship in complain mode because they're unmaintained; the desktop prompt exists so you can say no (see FAQ)
- **Auto-remediating Lynis suggestions** — most are context-dependent; StarHard shows them, maps them, and leaves the decision to you
- **`kernel.modules_disabled = 1`** — breaks VPNs, VirtualBox, Wi-Fi driver reloads until reboot
- **BIOS/UEFI settings**, Secure Boot, firmware passwords
- **Disk encryption** — it tells you when the root filesystem isn't encrypted (Pi), but can't do it for you
- **A full system upgrade** — run it yourself first

---

## Safety features

- **Dry-run** and **audit** modes — see everything before committing; verify afterwards
- **Automatic backups** of every modified file to `/var/backups/starhard/<timestamp>/`
- **Generated rollback script** that restores backed-up files, **removes files StarHard created**, restores prior file modes, service states and firewall state
- **SSH lockout protection** — password auth never disabled without an `authorized_keys` file; SSH always allowed through the firewall when run over SSH; config validated and auto-reverted
- **Tighten-only permissions** — never loosens a distro's stricter default
- **Service awareness** — Tailscale and Pi-hole detected and accommodated instead of broken
- **Destructive steps are opt-in** — Docker prune always asks, even with `-y`
- **Idempotent** — safe to re-run; `--sections` lets you re-apply one piece
- **Fault-tolerant** — a failed package or step is logged and skipped
- **Full logging** in `/var/log/starhard/`

### Rolling back

```bash
ls /var/backups/starhard/
sudo bash /var/backups/starhard/<timestamp>/rollback.sh
sudo reboot
```

Rollback does not reverse package installs/removals (listed as a comment at the end of the script for you to act on). Audit rules in immutable mode reset on reboot.

### Command reference

Installed by StarHard into `/usr/local/sbin/` (all need `sudo`):

| Command | Purpose |
|---|---|
| `starhard-status [--days N]` | One-screen digest of everything (default 7 days) |
| `starhard-scan` | Run the full ClamAV + unhide + integrity + Lynis scan now |
| `starhard-aide-check` | Run an AIDE integrity check now |
| `starhard-usb-allow [id]` | List blocked USB devices / permanently allow one |

Configuration files StarHard creates for you to edit:

| File | Purpose |
|---|---|
| `/etc/starhard/ignore-units` | Failed systemd units `starhard-status` should not report |
| `/etc/starhard/clamav-exclude` | Paths (regex, one per line) the weekly ClamAV scan skips |
| `/etc/usbguard/rules.conf` | USBGuard device allow-list (snapshot + `starhard-usb-allow` additions) |
| `/etc/usbguard/rules.d/50-starhard.conf` | StarHard's USB policy rules |
| `/var/lib/starhard/lynis-index` | Hardening-index history, one line per run |

Logs: `/var/log/starhard/` (`starhard-<ts>.log` per run, `scan-<date>.log`, `aide-<date>.log`, `lynis-report-*.dat`). Backups and rollback scripts: `/var/backups/starhard/<ts>/`.

---

## Troubleshooting

**Locked out of SSH after server profile** — physical/VPS console: delete `/etc/ssh/sshd_config.d/50-hardening.conf` or run the rollback script, then `systemctl restart sshd`.

**auditd fails to start / "There was an error in line N of audit.rules"** — another tool left rules in `/etc/audit/rules.d/` that duplicate StarHard's. v1.2 de-duplicates automatically; re-run `--sections 9`. If it persists, the log line names the offending rule.

**`starhard-status` says "AIDE baseline is stale"** — a large upgrade rewrote thousands of files. Rebuild: `sudo aideinit --yes --force` (10–20 min). On rolling distros expect this after every big upgrade.

**ClamAV flagged a file** — read the signature name. Windows-malware names (`Win.Trojan.*`, `Win.Dropper.*`) on a text/JSON/rules file are usually detection data containing malware strings, not malware; on pentest distros, scanner payload files (e.g. `/etc/unicornscan/payloads.conf`) and rule sets trip signatures too. Confirm with `dpkg -S <file>` and `debsums -c <package>` (no output = unmodified package file), then add the path to `/etc/starhard/clamav-exclude` so the weekly scan skips it. Unrecognisable binary with no package owner: `sudo mv` it to a root-only directory and investigate.

**USBGuard blocked something I plugged in** — `sudo starhard-usb-allow` lists blocked devices; `sudo starhard-usb-allow <id>` allows one permanently.

**"Package X has no installation candidate" on Parrot/Debian** — `apt-listbugs` refuses packages with open serious bugs and, when it aborts, writes a `-30000` pin into `/etc/apt/preferences.d/apt-listbugs` that makes the package invisible to later installs. StarHard shows the bugs as info, lifts a leftover pin for the package it's installing (backed up for rollback), and proceeds. To do it by hand: delete the package's stanza from that file, then `apt-get update`.

**logrotate.service failed** — usually one bad `postrotate` script in `/etc/logrotate.d/`. `journalctl -u logrotate -b` names it. A common one on Parrot is Suricata's `kill -HUP $(cat /var/run/suricata.pid)` with an empty pid file; make the kill conditional on the pid file being non-empty.

**Pi-hole stopped answering LAN clients** — StarHard only opens port 53 to the LAN if the Pi-hole query log shows LAN clients. Force it: `sudo ./StarHard.sh --sections 7 --pihole-lan`.

**Both fail2ban and CrowdSec are running** — a previous run or tool installed one. `sudo ./StarHard.sh --sections 8 --ids crowdsec` hands over cleanly.

**Failed services I don't care about keep showing** (e.g. unconfigured pentest daemons on Parrot) — add them to `/etc/starhard/ignore-units`, one per line, or `systemctl mask` them. Parrot/Kali get a default list.

**AppArmor "installed but not active"** — add `apparmor=1 security=apparmor` to `GRUB_CMDLINE_LINUX`, `update-grub`, reboot.

**Weekly scan never finishes on my laptop** — v1.2 holds idle-suspend during the scan. Lid-close still wins; run `sudo starhard-scan` manually when the lid will stay open.

**Lynis says NETW-3015 promiscuous interface** — not StarHard. Check for a bridge (`bridge link`) or a sniffer holding a raw socket (`sudo ss -0lp`).

---

## FAQ

**Does this replace Lynis?** No. Lynis audits, StarHard hardens, then runs Lynis for you and explains the output.

**Should I answer yes to "Set all AppArmor profiles to enforce mode"?** Check `sudo aa-status | grep -A30 "complain mode"` first. If it lists dozens of profiles (irssi, samba, LibreOffice, Xorg…), those are Debian's unmaintained extras — answer **no**. Enforce individual profiles you care about with `aa-enforce` and watch `journalctl -k | grep DENIED`.

**Is rkhunter / chkrootkit still useful?** No. rkhunter's last release was 2018 and it flags every container as a rootkit; chkrootkit's signatures are similarly dated. StarHard replaces them with ClamAV (real, daily-updated signatures), unhide (hidden processes), AIDE (changed files) and Lynis, and offers to remove the old ones.

**CrowdSec or fail2ban?** CrowdSec: same idea, plus a community blocklist of IPs currently attacking others, faster, actively developed. It's the default on servers. fail2ban stays the desktop default because it has no external dependencies.

**Wazuh?** Only if you already run a Wazuh manager — the agent does nothing on its own. StarHard mentions it and Falco/Tetragon for fleets but doesn't install them.

**Can StarHard detect keyloggers?** Partly. Kernel-module keyloggers: yes (module audit, unhide). `/dev/input` readers and preload hooks: yes (audit rules + the status section). X11 snooping: no — nothing host-based can; use Wayland. See the status section's "Keylogger indicators".

**Will it break my desktop?** It's designed not to: no services disabled, SSH password login kept, firewall only adds rules (and tells you what it'll block), USBGuard in audit mode, Tailscale and Pi-hole accommodated. The noticeable changes are stricter password rules, a 750 home directory, and new USB devices being refused while the screen is locked.

**How do I know if the weekly scan found something?** `sudo starhard-status` reads the latest scan log and turns it into `OK ClamAV: 0 infected files` or `!! ClamAV: N infected file(s)` with path and signature, plus unhide and integrity results. The raw report is `/var/log/starhard/scan-<date>.log`; `sudo grep -E 'FOUND|HIDDEN' /var/log/starhard/scan-*.log` shows every hit ever recorded. Nothing is deleted or quarantined automatically.

**How do I keep it hardened?** `sudo starhard-status` weekly. `sudo ./StarHard.sh --audit` after big upgrades. `sudo aideinit --yes --force` after upgrades that rewrite many files.

---

## Changelog

**1.2**
- Replaced rkhunter/chkrootkit with Lynis + ClamAV + unhide + package integrity, on a weekly timer; `starhard-status` digest
- `--audit`, `--sections`, `--exclude`, `--ids`, Pi and Pi-hole flags
- CrowdSec with firewall bouncer; fail2ban recidive fix
- Rollback now removes created files and restores modes/services/firewall state
- SSH: lockout guards, Include line, Banner, modern crypto, profile-aware forwarding, `AllowUsers` on server; dropped `Protocol 2`
- yescrypt detection; sane SHA rounds; pam_faillock
- auditd: aarch64 syscall names, de-dup against other rule files, immutable-mode detection, preload + input-device + Pi boot watches
- Firewall: Tailscale/Pi-hole awareness, LAN-client detection from Pi-hole's own DB, blocked-port preview, stale-rule warning
- Raspberry Pi: detection, EEPROM, radios, boot-config auditing, Pi/Tailscale update origins, low-RAM scan guard
- USBGuard on every profile with lock-screen HID blocking, network-adapter and injector-cable blocks, `starhard-usb-allow`
- Tighten-only permissions (fixes RHEL shadow regression), sudo logging, journald, `/dev/shm`, ctrl-alt-del, sysstat, extra sysctls, module unloading, AppArmor enforce option, Lynis mapping and index tracking
- GRUB password read silently (1.1 echoed it to the terminal); works on RHEL via `grub2-setpassword`
- Scan holds idle-suspend; failed-unit ignore list; ClamAV exclusion list with pentest-distro defaults
- apt-listbugs aware installs (shows bugs, lifts leftover pins); USBGuard rules in `rules.d/`, IPC root-only; section 20 installs usbguard itself
- `starhard-status`: keylogger indicators, USB device section with HID/NET/BT/STORAGE tags, dual-IPS and missing-bouncer detection, stale-AIDE and scan-in-progress states

**1.1** — initial multi-distro release.

---

## License / disclaimer

Provided as-is, without warranty. Hardening always involves trade-offs; review the dry-run output and understand each change before applying it to production systems. Test on non-critical machines first.
