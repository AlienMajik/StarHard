# StarHard

A universal Linux hardening script. One command applies a broad set of security best practices — kernel hardening, authentication policy, firewall, intrusion detection, file integrity monitoring, and system cleanup — on any major Linux distribution. Designed to raise your [Lynis](https://cisofy.com/lynis/) hardening score significantly while staying safe for daily-use systems.

---

## Supported systems

| Family | Distros | Package manager |
|---|---|---|
| Debian | Debian, Ubuntu, Parrot OS, Kali, Mint | `apt` |
| Red Hat | Fedora, RHEL, Rocky, AlmaLinux, CentOS Stream | `dnf` / `yum` |
| SUSE | openSUSE Leap / Tumbleweed, SLES | `zypper` |
| Arch | Arch, Manjaro, EndeavourOS | `pacman` |
| Alpine | Alpine Linux | `apk` |

StarHard auto-detects your distro from `/etc/os-release` — no configuration needed.

**Requirements:** root access (`sudo`), bash, an internet connection (to install security packages), and systemd on most distros (Alpine's OpenRC is also supported).

---

## Installation

1. Download `StarHard.sh` to your machine (e.g. your home directory).

2. Make it executable:

   ```bash
   chmod +x StarHard.sh
   ```

3. (Recommended) Skim the script before running it. Never run a root script you haven't at least glanced at — that habit is itself part of good security.

That's it. StarHard is a single self-contained file; there is nothing else to install.

---

## Recommended workflow

The full "measure → preview → apply → verify" cycle:

```bash
# 1. Baseline audit (optional but recommended — Lynis only reads, never changes anything)
sudo apt install lynis          # or dnf/zypper/pacman equivalent
sudo lynis audit system         # note your hardening index

# 2. Preview what StarHard would change — nothing is modified in this mode
sudo ./StarHard.sh --dry-run

# 3. Apply
sudo ./StarHard.sh

# 4. Reboot (module blacklists, GRUB, and PAM changes need a fresh boot)
sudo reboot

# 5. Verify the improvement
sudo lynis audit system
```

A stock desktop typically starts in the 60s and lands in the low-to-mid 80s afterwards. Don't chase 100 — past ~85 the remaining points cost real functionality.

> **Note on dry-run:** dry-run inspects the system *as it is now*, before any packages are installed. Sections that depend on tools installed in Section 1 (ufw firewall, fail2ban, AIDE baseline) may look skipped in the preview but WILL run on the real pass.

---

## Usage and options

```
sudo ./StarHard.sh [options]

  --dry-run          Show every change that would be made, without making any
  --profile <p>      desktop (default) or server
  -y, --yes          Assume "yes" to optional prompts (for unattended runs)
  -h, --help         Show help
```

### Desktop vs. server profile

| | `--profile desktop` (default) | `--profile server` |
|---|---|---|
| SSH password login | left enabled | **disabled** (asks for confirmation first) |
| Firewall SSH rule | none added | SSH allowed with rate limiting |
| Everything else | identical | identical |

> **Warning — server profile:** before confirming "disable SSH password authentication," make sure your SSH **key** login already works in a separate terminal. Otherwise you can lock yourself out of a remote machine. StarHard validates the new SSH config with `sshd -t` and auto-reverts it if sshd rejects it, but it cannot know whether your key is set up.

### Examples

```bash
sudo ./StarHard.sh                          # interactive desktop hardening
sudo ./StarHard.sh --dry-run                # preview only
sudo ./StarHard.sh --profile server -y      # unattended server hardening
```

---

## What StarHard does

| # | Section | Details |
|---|---|---|
| 1 | Security packages | Installs AIDE, fail2ban, auditd, rkhunter, pwquality, firewall, auto-update tooling (names adapted per distro) |
| 2 | Kernel / sysctl | ~40 hardened settings: ptrace scope, kptr restriction, BPF hardening, dmesg restriction, kexec disabled, SYN cookies, redirect/source-route blocking, martian logging, full IPv6 hardening |
| 3 | Module blacklist | Disables rarely-used protocols and filesystems (dccp, sctp, rds, tipc, cramfs, hfs, udf, firewire) |
| 4 | Authentication | umask 027, SHA512 with modern hashing rounds, password aging, pwquality rules (minlen 14, 3 character classes), cron/at restricted to root |
| 5 | Core dumps | Disabled via limits.conf and systemd-coredump |
| 6 | SSH | Root login off, max 3 auth tries, no X11/agent/TCP forwarding, idle timeout, verbose logging — validated before reload |
| 7 | Firewall | Enables ufw or firewalld (whichever your distro uses) with default-deny inbound |
| 8 | fail2ban | SSH jail plus a recidive jail for repeat offenders |
| 9 | auditd | Watches identity files, sudoers, cron, SSH config, kernel module loading, privilege escalation, time changes |
| 10 | AIDE | Creates a file-integrity baseline database |
| 11 | rkhunter | Updates signatures and file properties baseline |
| 12 | Auto-updates | unattended-upgrades (Debian) or dnf-automatic (Red Hat), security updates only |
| 13 | Banners & permissions | Legal warning banners; tightens shadow, crontab, grub.cfg, cron directories, `/etc/sudoers.d`, your home directory |
| 14 | MAC | Enables AppArmor if present; reports SELinux status |
| 15 | Cleanup | Removes insecure legacy packages, residual configs, old kernels, and (opt-in) stopped Docker containers — see below |
| 16 | GRUB password | *Optional, interactive.* Protects boot-parameter editing; normal boots stay password-free |

### Section 15 (cleanup) in detail

This section follows one design rule: **reversible restrictions run automatically; irreversible deletions require a human.**

| Step | What | How it runs | Why |
|---|---|---|---|
| 15a | Purge insecure legacy packages: `rsh-client`, `rsh-redone-client`, `tftp`, `atftpd`, `tftpd-hpa`, `talk` | Automatic, only if actually installed | Plaintext legacy protocols with no place on a modern system; SSH/SFTP replace them |
| 15b | Purge residual package configs (`dpkg` "rc" state) | Automatic (Debian family) | Leftover config files, cron jobs, and startup scripts from removed packages |
| 15c | `apt autoremove --purge` / `dnf autoremove` | Automatic | Removes old kernels and orphaned dependencies. Safe: apt's autoremove **never removes the running kernel** — it keeps the current and newest kernels by design |
| 15d | Prune stopped Docker containers | **Interactive prompt only** — never runs with `-y` or in dry-run | Pruning permanently deletes container filesystems, which may hold real data (paused projects, databases, results). A "yes to everything" flag should never silently destroy data; the script counts stopped containers, warns you, and asks. If skipped, run `docker container prune` manually when you're sure |

### What it deliberately does NOT do

These Lynis findings need human judgment, so StarHard leaves them to you:

- **Separate partitions** for `/tmp`, `/var`, `/home` with `nodev,nosuid,noexec` — can't be done safely after install
- **Removing compilers/dev tools** — you likely need them, especially on Parrot/Kali
- **Disabling running services** (Bluetooth, CUPS, Avahi, Docker, ollama…) — breaks functionality if done blindly
- **Blacklisting `usb-storage`** — a server-grade control; most desktop users need USB drives
- **`kernel.modules_disabled = 1`** — irreversibly blocks ALL module loading until reboot; breaks VPNs, VirtualBox, Wi-Fi driver reloads
- **BIOS/UEFI settings** — Secure Boot, firmware passwords
- **A full system upgrade** — run `sudo apt full-upgrade` (or equivalent) yourself once

---

## Safety features

- **Dry-run mode** — see everything before committing
- **Automatic backups** — every file StarHard modifies is copied to `/var/backups/starhard/<timestamp>/` first
- **Generated rollback script** — each run writes a `rollback.sh` into its backup folder
- **SSH lockout protection** — new SSH config is tested with `sshd -t` and removed automatically if invalid
- **Destructive steps are opt-in** — anything that deletes non-recoverable data (Docker prune) always asks, even in `-y` mode
- **Idempotent** — safe to run multiple times; re-runs simply re-assert the same state
- **Fault-tolerant** — a single failed package or step is logged and skipped, not fatal
- **Full logging** — every action recorded in `/var/log/starhard/`

### Rolling back

```bash
# List available restore points
ls /var/backups/starhard/

# Restore all files from a run, then reboot
sudo bash /var/backups/starhard/<timestamp>/rollback.sh
sudo reboot
```

The rollback restores modified **files**. It does not reverse package operations: security packages that were installed stay installed, and packages removed by the cleanup section (legacy clients, old kernels) stay removed — reinstall them with your package manager if you actually needed one.

---

## Troubleshooting

**"This script must be run as root"** — prefix with `sudo`.

**A package failed to install** — non-fatal; the run continues. Check `/var/log/starhard/` for the exact error. Some packages simply don't exist on every distro.

**Locked out of SSH after server profile** — log in at the physical console (or your VPS provider's web console) and either delete `/etc/ssh/sshd_config.d/50-hardening.conf` or run the rollback script, then `systemctl restart sshd`.

**AIDE init takes forever** — normal; it hashes most of the filesystem. On a large disk this can take 10+ minutes. It only runs on the first execution.

**AppArmor "installed but not active"** — some distros need kernel boot parameters. Add `apparmor=1 security=apparmor` to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, run `sudo update-grub`, and reboot.

**Sudo asks for a password more often / new password rules feel strict** — that's the pwquality policy working as intended. Adjust `/etc/security/pwquality.conf.d/50-hardening.conf` if minlen 14 is too aggressive for you.

**I need tftp/rsh back for a lab** — the cleanup section removed it on purpose. Reinstall explicitly (`sudo apt install tftp`) and StarHard won't fight you until its next run.

**My Lynis score didn't hit the 80s** — make sure you rebooted before re-auditing, then read the remaining Lynis suggestions; most will be the judgment-call items listed above.

---

## FAQ

**Does this replace Lynis?**
No — they're complements. Lynis *audits* (read-only), StarHard *hardens* (makes changes). Use Lynis to measure, StarHard to fix, Lynis again to verify.

**Can I run it on a machine that's already hardened?**
Yes. It's idempotent — existing correct settings are re-asserted, not duplicated, and already-removed packages are skipped silently.

**Will it break my desktop?**
It's designed not to: no services are disabled, no partitions touched, SSH password login stays on in desktop mode, and the GRUB password (if you opt in) doesn't affect normal boots. The most noticeable changes are stricter password rules and a 750 home directory.

**Why didn't it prune my Docker containers with `-y`?**
By design. `-y` auto-accepts *configuration* prompts, but never data-destroying ones. Stopped containers may hold data you want; prune manually when you're certain.

**How do I keep the system hardened over time?**
Automatic security updates are enabled by the script. Beyond that, run `sudo lynis audit system` monthly and re-run StarHard after major OS upgrades.

---

## License / disclaimer

Provided as-is, without warranty. Hardening always involves trade-offs; review the dry-run output and understand each change before applying it to production systems. Test on non-critical machines first.
