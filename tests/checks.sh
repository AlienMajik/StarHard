#!/usr/bin/env bash
# StarHard container checks: dry-run changes nothing, apply works, the embedded helpers match the
# standalone files, a second apply changes nothing (idempotent), rollback restores the original state.
#
# Containers have no systemd and no kernel access, so sections that need them (auditd, USBGuard,
# timers, firewall activation) take their "skip" paths here. Sections 1 (packages), 17 (GRUB,
# interactive) and 18 (Lynis) are excluded to keep a run to about a minute per image.
set -u
FAILS=0
ok()   { echo "  ok    $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
step() { echo; echo "=== $*"; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else fail "$d"; fi; }

cp /src/StarHard.sh /root/StarHard.sh
SH="bash /root/StarHard.sh"
EXCL="--exclude 1,17,18"
snapshot() { find /etc /usr/local/sbin /usr/share/pam-configs -type f ! -path /etc/starhard/config ! -name ld.so.cache -exec sha256sum {} + 2>/dev/null | sort -k2; }
mkdir -p /tmp/pre && cp -a /etc/login.defs /tmp/pre/ 2>/dev/null

step "syntax, --help, --version"
check "bash -n StarHard.sh"            bash -n /root/StarHard.sh
check "--help exits 0"                 $SH --help
check "--version prints the version"   bash -c "$SH --version | grep -q '^StarHard [0-9]'"
check "unknown --secure-dns rejected"  bash -c "! $SH --dry-run --secure-dns nope"

step "dry-run changes nothing"
snapshot > /tmp/s0
if $SH --dry-run -y $EXCL > /tmp/dry.log 2>&1; then ok "dry-run exits 0"; else fail "dry-run exit code $?"; tail -20 /tmp/dry.log; fi
snapshot > /tmp/s1
if cmp -s /tmp/s0 /tmp/s1; then ok "no file under /etc or /usr/local/sbin changed"; else fail "dry-run modified files:"; diff /tmp/s0 /tmp/s1 | head; fi
check "dry-run created no backup dir"  bash -c '[ ! -d /var/backups/starhard ]'
check "server-profile dry-run exits 0" $SH --dry-run -y --profile server $EXCL
check "opt-in sections dry-run exits 0" $SH --dry-run -y --boot-params --sandbox-services --docker-harden --secure-dns quad9 --secure-time $EXCL

step "apply (desktop profile)"
if $SH -y $EXCL > /tmp/apply1.log 2>&1; then ok "apply exits 0"; else fail "apply exit code $?"; fi
check "run reached the summary"        grep -q 'Hardening complete' /tmp/apply1.log
if grep -nE 'unbound variable|command not found|syntax error|No such file or directory' /tmp/apply1.log; then fail "shell errors in the apply output (above)"; else ok "no shell errors in the output"; fi
check "sysctl file written"            test -s /etc/sysctl.d/99-hardening.conf
check "sysctl file has no placeholders" bash -c '! grep -q "__" /etc/sysctl.d/99-hardening.conf'
for h in starhard-scan starhard-status starhard-notify; do
    check "$h installed and identical to the repository file" cmp /src/$h /usr/local/sbin/$h
done
check "starhard-aide-refresh would be valid sh" bash -c '[ ! -e /usr/local/sbin/starhard-aide-refresh ] || sh -n /usr/local/sbin/starhard-aide-refresh'
check "options saved (PROFILE=desktop)" grep -qx 'PROFILE=desktop' /etc/starhard/config
check "sudoers drop-in valid"          bash -c '[ ! -e /etc/sudoers.d/50-starhard ] || visudo -cf /etc/sudoers.d/50-starhard'
check "sudo does not log typed input"  bash -c '! grep -qs log_input /etc/sudoers.d/50-starhard'
check "desktop: cron not restricted to root" bash -c '[ "$(cat /etc/cron.allow 2>/dev/null)" != root ]'
if command -v sshd >/dev/null 2>&1; then
    check "sshd drop-in is 00-starhard.conf" test -s /etc/ssh/sshd_config.d/00-starhard.conf
    check "no 50-hardening.conf left"      test ! -e /etc/ssh/sshd_config.d/50-hardening.conf
    check "sshd accepts the configuration" sshd -t
    check "sshd effective PermitRootLogin no" bash -c "sshd -T | grep -qi '^permitrootlogin no'"
fi
check "notify hook examples installed" test -s /etc/starhard/notify.d/20-ntfy.example
check "original-state record exists"   test -s /var/backups/starhard/original/rollback.sh
check "original rollback is valid bash" bash -n /var/backups/starhard/original/rollback.sh
check "per-run rollback is valid bash" bash -c 'bash -n /var/backups/starhard/2*/rollback.sh'

step "helpers"
/usr/local/sbin/starhard-status > /tmp/status.txt 2>&1; rc=$?
if [ $rc -le 1 ]; then ok "starhard-status exit code is 0 or 1 ($rc)"; else fail "starhard-status exit code $rc"; tail -5 /tmp/status.txt; fi
/usr/local/sbin/starhard-status --json > /tmp/status.json 2>/dev/null; rcj=$?
[ $rcj -eq $rc ] && ok "--json has the same exit code" || fail "--json exit $rcj vs $rc"
if command -v python3 >/dev/null 2>&1; then
    check "--json is valid JSON with an issues count" python3 -c 'import json,sys; d=json.load(open("/tmp/status.json")); assert isinstance(d["issues"],int) and d["items"]'
    n_text="$(grep -c '^  !!' /tmp/status.txt)"; n_json="$(python3 -c 'import json; print(json.load(open("/tmp/status.json"))["issues"])')"
    [ "$n_text" = "$n_json" ] && ok "issue count matches between text and JSON ($n_json)" || fail "issue count: text $n_text, json $n_json"
fi
check "--quiet prints nothing"         bash -c '[ -z "$(/usr/local/sbin/starhard-status --quiet 2>&1)" ]'
check "bad --days rejected (exit 2)"   bash -c '/usr/local/sbin/starhard-status --days x; [ $? -eq 2 ]'
# notify: a hook must fire on the first run with issues, and stay silent when nothing changed
cat > /etc/starhard/notify.d/99-test <<'HOOK'
#!/bin/sh
echo "$STARHARD_STATE $STARHARD_ISSUES" >> /tmp/hook.log
cat > /tmp/hook.digest
HOOK
chmod 700 /etc/starhard/notify.d/99-test
rm -f /tmp/hook.log; /usr/local/sbin/starhard-notify; /usr/local/sbin/starhard-notify
if [ "$rc" -eq 1 ]; then
    check "notify: hook ran exactly once for an unchanged state" bash -c '[ "$(wc -l < /tmp/hook.log)" -eq 1 ]'
    check "notify: state was new-issues" grep -q '^new-issues' /tmp/hook.log
else
    check "notify: silent on a clean system" test ! -e /tmp/hook.log
fi
chmod 777 /etc/starhard/notify.d/99-test; rm -f /tmp/hook.log; /usr/local/sbin/starhard-notify --force
check "notify: world-writable hook is refused" test ! -e /tmp/hook.log
rm -f /etc/starhard/notify.d/99-test
check "login summary written"          test -s /var/lib/starhard/last-status

if command -v pam-auth-update >/dev/null 2>&1 && apt-get install -y -qq pamtester >/dev/null 2>&1; then
    step "account lockout (pam_faillock through pam-auth-update)"
    check "faillock wired into common-auth"  grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth
    useradd -m lockme 2>/dev/null; echo 'lockme:Corr3ct-Horse-Battery' | chpasswd
    try() { echo "$1" | pamtester login lockme authenticate acct_mgmt >/dev/null 2>&1; }
    check "correct password is accepted"     try Corr3ct-Horse-Battery
    for i in 1 2 3 4 5; do try "wrong$i"; done
    check "5 failures recorded"              bash -c '[ "$(faillock --user lockme | grep -c " V$")" -eq 5 ]'
    check "correct password refused while locked" bash -c '! echo Corr3ct-Horse-Battery | pamtester login lockme authenticate acct_mgmt'
    faillock --user lockme --reset
    check "accepted again after reset"       try Corr3ct-Horse-Battery
    userdel -r lockme >/dev/null 2>&1
fi

step "audit"
$SH --audit $EXCL > /tmp/audit.log 2>&1; rc=$?
[ $rc -le 1 ] && ok "--audit exit code is 0 or 1 ($rc)" || fail "--audit exit code $rc"
check "--audit used the saved options" grep -q 'Options remembered' /tmp/audit.log
check "--audit prints a PASS/FAIL total" grep -Eq 'PASS: [0-9]+ +FAIL: [0-9]+' /tmp/audit.log
grep -E 'PASS: [0-9]+' /tmp/audit.log | sed 's/^/        /'
if grep -nE 'unbound variable|command not found|syntax error' /tmp/audit.log; then fail "shell errors in the audit output"; else ok "no shell errors in the audit output"; fi

step "second apply is idempotent"
snapshot > /tmp/s2
$SH -y $EXCL > /tmp/apply2.log 2>&1 || fail "second apply exit code $?"
snapshot > /tmp/s3
if cmp -s /tmp/s2 /tmp/s3; then ok "second apply changed no file"; else fail "second apply changed files:"; diff /tmp/s2 /tmp/s3 | head -20; fi

step "rollback to the original state"
if $SH --rollback original -y > /tmp/rollback.log 2>&1; then ok "--rollback original exits 0"; else fail "--rollback original exit code $?"; tail -5 /tmp/rollback.log; fi
check "created sysctl file removed"    test ! -e /etc/sysctl.d/99-hardening.conf
check "installed helpers removed"      test ! -e /usr/local/sbin/starhard-status
check "sshd drop-in removed"           test ! -e /etc/ssh/sshd_config.d/00-starhard.conf
[ -e /tmp/pre/login.defs ] && check "login.defs back to its original content" cmp /tmp/pre/login.defs /etc/login.defs
command -v sshd >/dev/null 2>&1 && check "sshd still accepts its configuration" sshd -t

echo
if [ $FAILS -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $FAILS check(s) FAILED"; fi
exit $(( FAILS > 0 ))
