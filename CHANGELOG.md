# Changelog

## [2.1.0] — 2026-03-23 — AIR-GAP SAFE RELEASE

### Breaking Change — Lynis removed as external dependency
- Lynis binary is no longer downloaded. The built-in hardening scanner (below)
  replaces it entirely with equivalent checks that run on any air-gapped host.

### New: Built-in Hardening Scanner (run_hardening_scan)
Covers all major Lynis test categories — 100% embedded, zero external calls:

| Category | Checks |
|---|---|
| AUTH | PAM pwquality, nullok, sudoers NOPASSWD, pam_wheel su restriction, password history, SHA512 rounds |
| BOOT | Single-user auth, default systemd target, interactive boot |
| CRYP | SSL/TLS cert expiry in /etc/pki, OpenSSL version, GnuTLS install |
| INSE | telnet/ftp/rsh clients, LDAP cleartext URIs |
| KRNL | kernel.sysrq, kernel.core_uses_pid, kexec_load_disabled |
| LOGG | Remote syslog forwarding, auditd disk_full_action + admin_space_left_action, logrotate |
| MALW | rkhunter/chkrootkit/aide/tripwire/samhain, SELinux AVC denial count |
| PKGS | Installed package count, compilers/debug tools on production |
| SCHD | World-writable cron files, at.allow |
| SHLL | TMOUT set, dangerous PATH entries (. or ::), HISTSIZE info |
| STRG | USB storage module load+blacklist status, autofs |
| TIME | NTP server count (≥2 for redundancy), chronyc sync status |
| TOOL | aide, rkhunter, auditd, firewalld, fail2ban, clamav, openscap, sssd |
| USERS | Interactive account count, shadow password expiry, home dir permissions |
| HRDN | NX/ExecShield, compiler restrictions, process accounting |

### Air-Gap Safety
- **Zero external dependencies**: no curl, no wget, no python3, no bc, no jq
- Pure bash + awk + sed + standard RHEL tools (guaranteed on every RHEL 5+ install)
- JSON field extraction replaced with pure bash `json_field()` function
- Throttle math replaced with pure bash integer arithmetic
- `check_deps()` function verifies required tools and warns about optional ones at startup
- Score colour logic replaced with awk integer truncation + bash comparison

## [2.0.0] — 2026-03-23
- Multi-version RHEL support (5, 6, 7, 8, 9, 10)
- Non-root mode with graceful SKIP for privileged checks
- CIS + DISA STIG + posture checks

## [1.0.0] — 2026-03-23
- Initial release — RHEL 8 only
