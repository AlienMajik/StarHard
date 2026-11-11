# StarHard

A universal Linux hardening script. One command applies a broad set of security best practices — kernel hardening, authentication policy, firewall, intrusion prevention, malware and rootkit scanning, file-integrity monitoring, USB device control, audit logging and system cleanup — on any major Linux distribution, then installs a one-command status digest so you can see at a glance whether anything is wrong. Designed to raise your [Lynis](https://cisofy.com/lynis/) hardening score significantly while staying safe for daily-use systems, Raspberry Pis and home servers.

**Current version: 1.3**

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

1. Download `StarHard.sh`.
2. Make it executable:

   ```bash
   chmod +x StarHard.sh
   ```

3. Check the download (releases ship a `SHA256SUMS` file, signed when the maintainer has a signing key set up):

   ```bash
   sha256sum -c SHA256SUMS --ignore-missing
   minisign -Vm SHA256SUMS -P <public key>      # or: gpg --verify SHA256SUMS.asc SHA256SUMS
   ```

4. Skim it before running. Never run a root script you haven't at least glanced at.

**You only need `StarHard.sh`.** It is self-contained and writes the helper commands into `/usr/local/sbin/` itself: section 11 installs `starhard-scan`, `starhard-status` and `starhard-notify`, section 10 installs `starhard-aide-check` and `starhard-aide-refresh`, section 20 installs `starhard-usb-allow`. Re-running those sections updates them.

The repository also ships `starhard-status`, `starhard-scan` and `starhard-notify` as standalone files. They are the source of what the script writes (`tools/embed.sh` copies them in; CI fails if they drift), provided so you can update one helper without re-running a section:

```bash
sudo install -m 755 starhard-status starhard-scan starhard-notify /usr/local/sbin/
```

Either way ends up identical; `sudo ./StarHard.sh --sections 11` is the simpler route.

---

## Recommended workflow

```bash
# 1. Preview — nothing is modified in this mode
sudo ./StarHard.sh --dry-run

# 2. Apply (desktop profile)                  or on a headless box / server:
sudo ./StarHard.sh                             sudo ./StarHard.sh --profile server

# 3. Reboot — module blacklists, audit rules (immutable mode), PAM and boot-config changes need it
sudo reboot

# 4. Verify: PASS/FAIL for every setting StarHard wrote, then a fresh Lynis audit.
#    The profile and options of the last run are remembered — no need to repeat the flags.
sudo ./StarHard.sh --audit

# 5. Get told when something changes (pick a hook: mail, ntfy, webhook, desktop):
sudo cp /etc/starhard/notify.d/20-ntfy.example /etc/starhard/notify.d/20-ntfy
sudo chmod 700 /etc/starhard/notify.d/20-ntfy && sudoedit /etc/starhard/notify.conf
sudo starhard-notify --test

# 6. Whenever you want the whole picture:
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
  --ids <i>             crowdsec or fail2ban for section 8 (default: whichever is already installed,
                        else crowdsec on server / fail2ban on desktop)
  --pihole-lan          Pi-hole: always open DNS/web to LAN subnets
  --no-lan-dns          Pi-hole: never open DNS/web to LAN (e.g. a Tailscale-only Pi-hole)
  --pi-disable-wifi     Raspberry Pi: disable the on-board Wi-Fi radio (refused if you're connected over it)
  --pi-disable-bt       Raspberry Pi: disable the on-board Bluetooth radio (automatic on server profile)
  --rollback <what>     Undo: original (state before StarHard first ran), latest (the last run),
                        or a run timestamp from /var/backups/starhard/
  -y, --yes             Assume "yes" to optional prompts (unattended runs)
  -V, --version         Print the version
  -h, --help            Help

Opt-in hardening (off unless asked for):
  --boot-params         Section 21: kernel boot parameters (needs a reboot)
  --boot-lockdown       Section 21: also lockdown=integrity (breaks unsigned modules and hibernation)
  --sandbox-services    Section 22: systemd sandboxing drop-ins for network-facing daemons
  --docker-harden       Section 23: Docker daemon.json hardening
  --secure-dns <p>      Section 24: DNS-over-TLS via systemd-resolved (quad9 or cloudflare)
  --secure-time         Section 24: authenticated time (NTS) via chrony
```

**Options are remembered.** A real run stores its profile, IPS choice and opt-ins in `/etc/starhard/config`; later runs and `--audit` default to them, and flags override them. Each opt-in has a `--no-…` form (`--no-boot-lockdown`, `--no-sandbox-services`, …) that stops applying and auditing it.

### Desktop vs. server profile

| | `--profile desktop` (default) | `--profile server` |
|---|---|---|
| SSH password login | kept | **disabled** — only if an `authorized_keys` file exists, and only after confirmation |
| SSH forwarding / MaxAuthTries | TCP + agent forwarding allowed, 6 tries | forwarding off, 4 tries, `AllowUsers` restricted to users with keys (+ you) |
| Firewall SSH rule | added only when you're running over SSH | always, rate-limited |
| Intrusion prevention | fail2ban | CrowdSec + firewall bouncer |
| cron / at | users keep their crontabs | root only (`cron.allow`, `at.allow`) |
| auditd file rules | deletions under `/var/log` and `/etc`, permission changes under `/etc`, `/usr`, `/boot` | every deletion and permission change by a logged-in user |
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
sudo ./StarHard.sh --boot-params --docker-harden    # add two opt-in sections (remembered afterwards)
sudo ./StarHard.sh --rollback original --dry-run    # preview a full undo
```

---

## What StarHard does

| # | Section | Details |
|---|---|---|
| 1 | Security packages | AIDE, auditd, Lynis, ClamAV + freshclam, unhide, debsums, sysstat, pwquality, firewall, USBGuard, auto-update tooling; fail2ban or CrowdSec per `--ids` (names adapted per distro) |
| 2 | Kernel / sysctl | ~40 settings: ptrace scope, kptr/dmesg restriction, BPF hardening, kexec off, `io_uring` disabled, unprivileged userfaultfd off, `TIOCSTI` keystroke injection off, SYN cookies, redirect/source-route blocking, martian logging, IPv6 hardening. `rp_filter` goes loose (2) when Tailscale is present; `accept_ra` is left alone if the host has a SLAAC address |
| 3 | Module blacklist | dccp, sctp, rds, tipc, cramfs, freevxfs, jffs2, hfs, hfsplus, udf, firewire — both `install /bin/false` and `blacklist`; already-loaded modules are unloaded. Not firewire on a Pi |
| 4 | Authentication | umask 027, **yescrypt** where supported (SHA512/100k rounds otherwise), password aging, pwquality (minlen 14, 3 classes), **pam_faillock** lockout (5 failures / 15 min) via authselect (RHEL family) or `pam-auth-update` profiles (Debian family — they survive PAM upgrades and coexist with sssd/fprintd), cron/at restricted to root on the server profile |
| 5 | Core dumps | Disabled via limits.d and systemd-coredump |
| 6 | SSH | Root login off, banner, idle timeout, verbose logging, modern KEX/cipher/MAC/host-key lists, `RequiredRSASize 3072`, `DebianBanner no` — each only when this sshd supports the keyword. Profile-aware forwarding/MaxAuthTries. Written as `00-starhard.conf`: sshd keeps the *first* value it reads, so a later-sorting file such as cloud-init's `50-cloud-init.conf` can no longer override it. Ensures `sshd_config.d` is actually included. Validated with `sshd -t` before reload, then the **effective** configuration is checked with `sshd -T` and any setting that another file still wins is named |
| 7 | Firewall | ufw or firewalld, default-deny inbound. **Service-aware:** trusts `tailscale0` + UDP 41641; opens Pi-hole DNS/web to LAN subnets *only if Pi-hole's query log shows LAN clients*; lists every other listening port the policy will block and, separately, the **Docker-published ports it will not block**; flags stale `ufw allow` rules for ports nothing listens on. firewalld gets the same LAN-scoped Pi-hole rules as ufw. Hosts with only `nft` (Alpine, minimal installs) get a real default-deny table (`inet starhard`, loaded at boot) that leaves Docker/libvirt/Tailscale tables alone. Existing rules are never removed; every rule StarHard adds and the previous default policy are recorded for rollback |
| 8 | Intrusion prevention | **CrowdSec** (official repo added as a repo file with its signing keys **pinned by fingerprint** — no `curl \| bash`; nftables/iptables bouncer, linux+sshd collections, journal acquisition, loopback whitelist; fail2ban stopped and masked so the two never fight) or **fail2ban** (sshd + recidive jail, recidive fixed to `backend=auto`) |
| 9 | auditd | Identity files, sudoers, cron, SSH/PAM/MAC config, module loading, time changes, privilege escalation, mounts, deletions, permission changes, `/etc/ld.so.preload`, opens of `/dev/input/` by users (keylogger indicator), Pi boot config. Correct syscall names on aarch64. **De-duplicates against rules other tools already placed in `rules.d/`**, detects immutable mode. Deletion/permission rules are scoped by profile (see table above) so a desktop's browser cache doesn't rotate the log away; retention raised to at least 10 × 50 MB. Process accounting + sysstat enabled |
| 10 | AIDE | Baseline database on first run; daily check timer (or defers to the distro's own daily job). **The baseline refreshes itself a few minutes after package transactions** (apt, dnf 4, pacman hooks → `starhard-aide-refresh`); what each refresh absorbed is kept in `/var/log/starhard/aideupd-*.log` |
| 11 | Scanning | Weekly `starhard-scan` timer: **ClamAV** (incl. mounted removable media; skips when < 1.5 GB RAM is free; honours an exclusion list at `/etc/starhard/clamav-exclude`, pre-filled on Parrot/Kali with the tool directories that contain exploit code by design — every pattern anchored and bounded), **unhide**, package integrity (debsums / `rpm -V` / `pacman -Qkk`), **Lynis**. Run from a terminal it shows a live progress bar and per-stage results; from the timer it's silent. Holds idle-suspend while running so laptops finish. Installs **`starhard-status`** and **`starhard-notify`** (daily timer; pushes through your hooks only when the set of problems changes). Offers to remove legacy rkhunter/chkrootkit |
| 12 | Auto-updates | unattended-upgrades (security origin, unused-dep removal, no auto-reboot; **+ Raspberry Pi Foundation and Tailscale origins** when detected), dnf-automatic, or a zypper patch timer. Warns on rolling distros (Parrot/Kali) where there's no security pocket |
| 13 | Banners, permissions, sudo | Legal banners (`/etc/issue`, `issue.net`, sshd `Banner`); **tighten-only** permissions (`chmod o-rwx` — never loosens RHEL's 0000 shadow); cron dirs, sudoers.d, grub.cfg, home directories; sudo `use_pty`, `logfile` (not `log_input` — it would write passwords typed inside sudo sessions to disk) |
| 14 | MAC | AppArmor enabled; profiles set to enforce (server: automatic, desktop: prompted — see FAQ). SELinux status reported |
| 15 | Services, mounts, journald | ctrl-alt-del masked; persistent journald with 500 MB cap; `/dev/shm` `nodev,nosuid,noexec`. Server: `/tmp` + `/var/tmp` hardened, avahi/cups/bluetooth masked |
| 16 | Cleanup | Legacy plaintext clients (rsh, tftp, talk, telnetd) purged if present; residual configs; `autoremove`; **opt-in** Docker prune (never with `-y`) |
| 17 | GRUB password | Optional, interactive. Password read silently; normal boots stay unrestricted. Uses `grub2-setpassword` on RHEL/Fedora. Skipped on Raspberry Pi |
| 18 | Lynis | Installs Lynis if missing, runs a full audit **last**, prints warnings and suggestions with each mapped to the StarHard section that addresses it (`-> section N`) or `-> manual`, annotates known false positives (yescrypt rounds, promiscuous VPN tunnel interfaces) and prints the diagnostic commands for a real promiscuous interface, tracks the hardening index across runs in `/var/lib/starhard/lynis-index` |
| 19 | Raspberry Pi | *Auto-detected.* No-bootloader-password / encryption warning, EEPROM update check and staging, `dtoverlay=disable-bt` / `disable-wifi` (Wi-Fi refused if that's how you're connected), auditd watches on `config.txt` / `cmdline.txt`, serial console removed on server, low-RAM note for ClamAV |
| 20 | USB device control | **USBGuard on every profile** (installs it if missing). Devices attached at setup are allowed. *Desktop:* audit mode (all attaches logged to auditd) plus hard blocks on USB network adapters (PoisonTap class) and HID-carrying hubs (injector cables), and **every new device blocked while the screen is locked** (event-driven watcher on logind; if the watcher stops, new devices stay blocked). *Server:* everything unknown blocked. StarHard's rules live in `/etc/usbguard/rules.d/` so a package upgrade can't erase them; daemon IPC is restricted to root (closes Debian bugs #1134751/#1135310). `starhard-usb-allow <id>` authorises a device |
| 21 | Boot parameters *(opt-in)* | `--boot-params`: `init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on`, `vsyscall=none` on x86_64; `--boot-lockdown` adds `lockdown=integrity`. Written via `grubby`, `/etc/default/grub.d/`, `/etc/default/grub`, `/etc/kernel/cmdline` or the Pi's `cmdline.txt`. Parameters you already set to another value are left alone. Reboot required |
| 22 | Service sandboxing *(opt-in)* | `--sandbox-services`: finds the systemd services listening on a non-loopback address, shows each one's `systemd-analyze security` exposure and offers a baseline drop-in (`ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `ProtectClock`, `RestrictNamespaces`, `RestrictSUIDSGID`, …). The service is restarted and **the drop-in is removed again if it does not come back**. sshd, container runtimes, VPNs, time and network daemons are left alone |
| 23 | Docker daemon *(opt-in)* | `--docker-harden`: merges `no-new-privileges`, `icc=false`, log size limits and `live-restore` (not in swarm mode) into `daemon.json`, validates it with `dockerd --validate`, lists containers that are `--privileged` or mount `docker.sock`. Docker is restarted only when you say so (never with `-y`). `userns-remap` is deliberately not applied |
| 24 | Encrypted DNS / authenticated time *(opt-in)* | `--secure-dns quad9\|cloudflare`: DNS-over-TLS through systemd-resolved (strict on server, opportunistic on desktop), verified with a real lookup and reverted if it fails; skipped on a Pi-hole. `--secure-time`: NTS sources for chrony with `authselectmode prefer` |

Sections run in numeric order except 18 (Lynis), which runs last so it audits the finished state; 19–24 run just before it. Sections 21–24 only run when asked for.

### `starhard-status` — the weekly check

```bash
sudo starhard-status            # last 7 days
sudo starhard-status --days 30
sudo starhard-status --json     # one JSON object: {"issues": N, "items": [{"level","section","message"}, ...]}
sudo starhard-status --quiet    # no output, exit code only
```

Exit code: `0` nothing needs attention, `1` at least one `!!` item, `2` usage error — so it drops straight into monitoring (`starhard-status --quiet || alert`).

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

Everything else runs on its own: ClamAV signatures every few hours, AIDE nightly, the full scan weekly, security updates daily, `starhard-notify` daily.

It also escalates things that quietly stop working: a ClamAV scan skipped for low memory twice in a row, a weekly scan that hasn't run for 15 days, an audit log that no longer reaches back as far as you asked.

### `starhard-notify` — hear about it without looking

A daily timer runs `starhard-status` and calls your hooks **only when the set of `!!` items changes** (new problem, different problems, all clear). Counts are ignored for the comparison, so "23 failed logins" becoming "31" is not a new alert.

Hooks are executables in `/etc/starhard/notify.d/`. Four examples are installed, inert until you copy them without `.example` and make them executable; their settings live in `/etc/starhard/notify.conf`:

| Example | Sends to |
|---|---|
| `10-mail.example` | `mail` to `MAIL_TO` |
| `20-ntfy.example` | an [ntfy](https://ntfy.sh) topic (`NTFY_URL`, optional `NTFY_TOKEN`) — only the `!!` lines leave the machine |
| `30-webhook.example` | Slack / Mattermost / Discord incoming webhook (`WEBHOOK_URL`) |
| `40-desktop.example` | `notify-send` in every graphical session |

A hook gets the digest on stdin and `STARHARD_HOST`, `STARHARD_ISSUES`, `STARHARD_PREVIOUS`, `STARHARD_STATE` (`new-issues`, `changed`, `resolved`, `test`), `STARHARD_SUMMARY` and `STARHARD_ITEMS` in its environment. Hooks run as root, so files not owned by root or writable by group/others are refused. On Debian/Ubuntu the one-line summary also appears in the login banner.

```bash
sudo starhard-notify --test     # send a test message through every enabled hook
sudo starhard-notify --force    # run now and notify even if nothing changed
```

### `starhard-scan` — running it yourself

```bash
sudo starhard-scan              # full scan, ~10–25 min
sudo starhard-scan --clam-only  # just ClamAV
sudo starhard-scan --no-clam    # unhide + integrity + Lynis (a couple of minutes)
```

From a terminal it narrates each of the four stages:

```
━━ 1/4 ClamAV malware scan /etc /home /root /tmp … (19 exclusion pattern(s))
  signature databases: 3, last updated 2h ago
  ████████████░░░░░░░░░░░░░░░░░░  41%  92,410/225,517 files  310/s  4m58s
  ✔ 225,517 files scanned, no malware  (12m03s)
━━ 2/4 Hidden process check (unhide)
  ✔ no hidden processes
━━ 3/4 Package integrity
  ! 7 modified file(s)  (edited configs are normal; binaries are not)
━━ 4/4 Lynis configuration audit
  ✔ hardening index 84/100, 1 warning(s)
done in 18m22s  •  sudo starhard-status for the digest
```

The ClamAV bar shows files done/total, throughput and elapsed time, and a red `N FOUND` counter appears the moment anything matches. Under the weekly timer (no terminal) it prints nothing and writes the same log `starhard-status` reads. `--quiet` forces that from a terminal.

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
- **Two levels of rollback**: each run can be undone on its own, and the state from before StarHard *first* touched each file, mode, service and firewall setting is kept separately so a re-run can never overwrite it
- Rollback restores backed-up files, **removes files StarHard created**, restores prior file modes and service states, and deletes the firewall rules StarHard added
- **Self-checking changes** — sshd (`sshd -t`, then `sshd -T`), sudoers (`visudo -c`), PAM (reverted if `pam_unix` disappears), nftables (`nft -c`), DNS-over-TLS (a real lookup), sandbox drop-ins and Docker config (service must come back) are verified and reverted on failure
- **SSH lockout protection** — password auth never disabled without an `authorized_keys` file; SSH always allowed through the firewall when run over SSH; config validated and auto-reverted
- **Tighten-only permissions** — never loosens a distro's stricter default
- **Service awareness** — Tailscale and Pi-hole detected and accommodated instead of broken
- **Destructive steps are opt-in** — Docker prune always asks, even with `-y`
- **Idempotent** — safe to re-run; `--sections` lets you re-apply one piece
- **Fault-tolerant** — a failed package or step is logged and skipped
- **Full logging** in `/var/log/starhard/`

### Rolling back

```bash
sudo ./StarHard.sh --rollback original --dry-run   # what a full undo would do
sudo ./StarHard.sh --rollback original             # back to before StarHard first ran
sudo ./StarHard.sh --rollback latest               # undo only the most recent run
sudo ./StarHard.sh --rollback 20260101-120000      # undo one specific run
sudo reboot
```

`latest` returns to the state just before that run — after a re-run that is *still hardened*. `original` is the full undo; its script is regenerated on every run at `/var/backups/starhard/original/rollback.sh` so you can read it at any time. On a machine first hardened with 1.2, the original state is rebuilt from the oldest per-run backups the first time 1.3 runs.

Rollback does not reverse package installs/removals (listed as a comment at the end of the per-run script for you to act on). Audit rules in immutable mode and boot parameters reset on reboot.

### Command reference

Installed by StarHard into `/usr/local/sbin/` (all need `sudo`):

| Command | Purpose |
|---|---|
| `starhard-status [--days N] [--json\|--quiet]` | One-screen digest of everything (default 7 days); exit 1 when something needs attention |
| `starhard-notify [--test\|--force]` | Run the status check and call the notification hooks when it changed |
| `starhard-scan [--clam-only\|--no-clam\|--quiet]` | Run the full ClamAV + unhide + integrity + Lynis scan now, with live progress |
| `starhard-aide-check` | Run an AIDE integrity check now |
| `starhard-aide-refresh` | Accept the current system as the new AIDE baseline (the differences are logged first) |
| `starhard-usb-allow [id]` | List blocked USB devices / permanently allow one |

Configuration files StarHard creates for you to edit:

| File | Purpose |
|---|---|
| `/etc/starhard/config` | Profile and options of the last run (defaults for the next run and for `--audit`) |
| `/etc/starhard/notify.conf`, `/etc/starhard/notify.d/` | Notification settings and hooks |
| `/etc/starhard/firewall.nft` | The default-deny table on nftables-only hosts (generated; re-run section 7 to change) |
| `/etc/starhard/ignore-units` | Failed systemd units `starhard-status` should not report |
| `/etc/starhard/clamav-exclude` | Paths (regex, one per line) the weekly ClamAV scan skips |
| `/etc/usbguard/rules.conf` | USBGuard device allow-list (snapshot + `starhard-usb-allow` additions) |
| `/etc/usbguard/rules.d/50-starhard.conf` | StarHard's USB policy rules |
| `/var/lib/starhard/lynis-index` | Hardening-index history, one line per run |

Logs: `/var/log/starhard/` (`starhard-<ts>.log` per run, `scan-<date>.log`, `aide-<date>.log`, `aideupd-<ts>.log`, `lynis-report-*.dat`). Backups and rollback scripts: `/var/backups/starhard/<ts>/` per run, `/var/backups/starhard/original/` for the first-ever state.

---

## Troubleshooting

**Locked out of SSH after server profile** — physical/VPS console: delete `/etc/ssh/sshd_config.d/00-starhard.conf` (or `sudo ./StarHard.sh --rollback latest`), then `systemctl restart sshd`.

**"sshd is NOT using StarHard's value for: …"** — another file sets that keyword before StarHard's drop-in is read, usually `sshd_config` itself above its `Include` line. The warning prints the `grep` that finds it; remove or comment the earlier line and re-run `--sections 6`.

**"pam-auth-update did not apply the faillock profiles"** — `/etc/pam.d/common-*` were edited by hand, and pam-auth-update will not overwrite local changes. Run `sudo pam-auth-update`, review, and tick the two StarHard entries.

**USB devices stay blocked after unlocking** — the lock watcher is not running (it fails closed). `sudo systemctl restart starhard-usb-lock`; `sudo starhard-status` reports this state.

**A service misbehaves after `--sandbox-services`** — delete `/etc/systemd/system/<unit>.d/50-starhard-sandbox.conf`, then `systemctl daemon-reload && systemctl restart <unit>`.

**Machine does not boot after `--boot-params`** — at the boot menu press `e`, delete the added parameters from the `linux` line, boot, then remove `/etc/default/grub.d/99-starhard.cfg` (or the `# StarHard boot parameters` line in `/etc/default/grub`) and regenerate the GRUB config.

**auditd fails to start / "There was an error in line N of audit.rules"** — another tool left rules in `/etc/audit/rules.d/` that duplicate StarHard's. v1.2 de-duplicates automatically; re-run `--sections 9`. If it persists, the log line names the offending rule.

**`starhard-status` says "AIDE baseline is stale"** — a large upgrade rewrote thousands of files and no package hook refreshed the baseline (zypper, dnf 5, Alpine, or a manual install outside the package manager). Run `sudo starhard-aide-refresh` (10–20 min); it logs what changed before accepting it.

**ClamAV flagged a file** — read the signature name. Windows-malware names (`Win.Trojan.*`, `Win.Dropper.*`) on a text/JSON/rules file are usually detection data containing malware strings, not malware; on pentest distros, scanner payload files (e.g. `/etc/unicornscan/payloads.conf`) and rule sets trip signatures too. Confirm with `dpkg -S <file>` and `debsums -c <package>` (no output = unmodified package file), then add the path to `/etc/starhard/clamav-exclude` so the weekly scan skips it. Unrecognisable binary with no package owner: `sudo mv` it to a root-only directory and investigate.

**USBGuard blocked something I plugged in** — `sudo starhard-usb-allow` lists blocked devices; `sudo starhard-usb-allow <id>` allows one permanently.

**"Package X has no installation candidate" on Parrot/Debian** — `apt-listbugs` refuses packages with open serious bugs and, when it aborts, writes a `-30000` pin into `/etc/apt/preferences.d/apt-listbugs` that makes the package invisible to later installs. StarHard shows the bugs as info, lifts a leftover pin for the package it's installing (backed up for rollback), and proceeds. To do it by hand: delete the package's stanza from that file, then `apt-get update`.

**logrotate.service failed** — usually one bad `postrotate` script in `/etc/logrotate.d/`. `journalctl -u logrotate -b` names it. A common one on Parrot is Suricata's `kill -HUP $(cat /var/run/suricata.pid)` with an empty pid file; make the kill conditional on the pid file being non-empty.

**Pi-hole stopped answering LAN clients** — StarHard only opens port 53 to the LAN if the Pi-hole query log shows LAN clients. Force it: `sudo ./StarHard.sh --sections 7 --pihole-lan`.

**Both fail2ban and CrowdSec are running** — a previous run or tool installed one. `sudo ./StarHard.sh --sections 8 --ids crowdsec` hands over cleanly.

**Failed services I don't care about keep showing** (e.g. unconfigured pentest daemons on Parrot) — add them to `/etc/starhard/ignore-units`, one per line, or `systemctl mask` them. Parrot/Kali get a default list.

**AppArmor "installed but not active"** — add `apparmor=1 security=apparmor` to `GRUB_CMDLINE_LINUX`, `update-grub`, reboot.

**Weekly scan never finishes on my laptop** — v1.2 holds idle-suspend during the scan. Lid-close still wins; run `sudo starhard-scan` manually when the lid will stay open.

**Lynis says NETW-3015 promiscuous interface** — not StarHard. For `tailscale0` / `wg*` / `tun*` it's expected and StarHard marks it n/a. For a physical interface, check for a bridge (`bridge link`) or a sniffer holding a raw socket (`sudo ss -0lp`).

---

## FAQ

**Does this replace Lynis?** No. Lynis audits, StarHard hardens, then runs Lynis for you and explains the output.

**Should I answer yes to "Set all AppArmor profiles to enforce mode"?** Check `sudo aa-status | grep -A30 "complain mode"` first. If it lists dozens of profiles (irssi, samba, LibreOffice, Xorg…), those are Debian's unmaintained extras — answer **no**. Enforce individual profiles you care about with `aa-enforce` and watch `journalctl -k | grep DENIED`.

**Is rkhunter / chkrootkit still useful?** No. rkhunter's last release was 2018 and it flags every container as a rootkit; chkrootkit's signatures are similarly dated. StarHard replaces them with ClamAV (real, daily-updated signatures), unhide (hidden processes), AIDE (changed files) and Lynis, and offers to remove the old ones.

**CrowdSec or fail2ban?** CrowdSec: same idea, plus a community blocklist of IPs currently attacking others, faster, actively developed. It's the default on servers. fail2ban stays the desktop default because it has no external dependencies.

**Wazuh?** Only if you already run a Wazuh manager — the agent does nothing on its own. StarHard mentions it and Falco/Tetragon for fleets but doesn't install them.

**Can StarHard detect keyloggers?** Partly. Kernel-module keyloggers: yes (module audit, unhide). `/dev/input` readers and preload hooks: yes (audit rules + the status section). X11 snooping: no — nothing host-based can; use Wayland. See the status section's "Keylogger indicators".

**Will it break my desktop?** It's designed not to: no services disabled, SSH password login kept, user crontabs kept, firewall only adds rules (and tells you what it'll block), USBGuard in audit mode, Tailscale and Pi-hole accommodated. The noticeable changes are stricter password rules, account lockout after 5 failed logins, a 750 home directory, and new USB devices being refused while the screen is locked. Sections 21–24 can break things and are therefore opt-in.

**Doesn't the automatic AIDE refresh hide an attacker's changes?** It refreshes only after a package transaction, and `aide --update` writes every difference to `/var/log/starhard/aideupd-<ts>.log` *before* accepting it, so nothing is absorbed unrecorded. Package-owned files are independently verified against package checksums by the weekly scan. If you prefer to accept baselines by hand: `sudo systemctl disable --now starhard-aide-refresh.path`.

**How do I know if the weekly scan found something?** Enable a notification hook (see `starhard-notify`) and you are told the next morning. `sudo starhard-status` reads the latest scan log and turns it into `OK ClamAV: 0 infected files` or `!! ClamAV: N infected file(s)` with path and signature, plus unhide and integrity results. The raw report is `/var/log/starhard/scan-<date>.log`; `sudo grep -E 'FOUND|HIDDEN' /var/log/starhard/scan-*.log` shows every hit ever recorded. Nothing is deleted or quarantined automatically.

**How do I keep it hardened?** Enable a `starhard-notify` hook, or run `sudo starhard-status` weekly. `sudo ./StarHard.sh --audit` after big upgrades shows drift in any single setting.

---

## Development

```bash
make lint      # bash -n + ShellCheck
make test      # tests/run-matrix.sh: one container per distro family
make embed     # after editing starhard-scan / -status / -notify: copy them into StarHard.sh
make check     # everything CI runs
make release   # dist/ + SHA256SUMS, signed with MINISIGN_KEY=... or GPG_KEY=...
```

The container tests run a dry-run (must change nothing), an apply, the helpers, `--audit`, a second apply (must change nothing — idempotency), a real pam_faillock lockout on Debian/Ubuntu, and `--rollback original` (must restore the files) on Debian, Ubuntu, Fedora, Rocky, openSUSE, Arch and Alpine. Containers have no systemd or kernel access, so timers, auditd, USBGuard, firewalld and sections 22/24 are exercised only on their skip paths there — test those on a VM before a release.

---

## Changelog

**1.3**
- SSH drop-in renamed `00-starhard.conf` (read first, so cloud-init can't override it); effective config verified with `sshd -T`; `AllowUsers` keeps the login user behind a root shell
- CrowdSec repository via repo file + fingerprint-pinned signing keys instead of `curl | bash`
- sudo `log_input` removed; predictable temp file replaced with `mktemp`
- Firewall: Docker-published ports called out as bypassing the firewall; firewalld Pi-hole rules scoped to LAN subnets; real nftables default-deny table on nft-only hosts (Alpine); DHCP server rule no longer source-filtered (requests come from 0.0.0.0); every added rule recorded for rollback
- pam_faillock through `pam-auth-update` profiles; fixed module detection that silently skipped lockout on Debian/Ubuntu
- cron/at restricted to root on the server profile only (desktop restriction from 1.2 is lifted on the next run)
- `starhard-status`: exit codes, `--json`, `--quiet`; issues found in the USB list now count; escalates repeated ClamAV skips, an overdue scan and a too-short audit log; locale-safe `ausearch` dates
- `starhard-notify` with a daily timer and mail / ntfy / webhook / desktop hook examples; login-banner summary
- `--audit` verifies every sysctl, blacklisted module, effective sshd option and audit-rule key from the same tables the apply pass writes
- Options persist in `/etc/starhard/config`
- `--rollback original|latest|<timestamp>`; original state kept separately and never overwritten by re-runs
- auditd: delete/perm_mod rules scoped on desktop, `log_tamper` key, retention raised; AIDE baseline refresh after package transactions; USB lock watcher event-driven and fail-closed
- Opt-in sections 21 (boot parameters), 22 (service sandboxing), 23 (Docker daemon), 24 (DNS-over-TLS, NTS)
- `dev.tty.legacy_tiocsti = 0`
- Fixed: login.defs gained a blank line per run; auditd skipped-rule count error; helpers no longer need the `hostname` command
- Tests (7 distro containers), ShellCheck, CI workflow, release checksums/signing

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
- `starhard-scan`: live progress bar, spinners and per-stage results in a terminal; `--clam-only` / `--no-clam` / `--quiet`
- `--ids` defaults to the IPS already installed; Lynis promiscuous-interface warnings annotated for VPN tunnels
- ClamAV exclusion defaults anchored and bounded (`^…(/|$)`; `.msf4` only under real home directories), with in-place migration of an existing list

**1.1** — initial multi-distro release.

---

## License / disclaimer

Provided as-is, without warranty. Hardening always involves trade-offs; review the dry-run output and understand each change before applying it to production systems. Test on non-critical machines first.