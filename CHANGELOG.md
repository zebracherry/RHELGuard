# Changelog

## [2.2.0] — 2026-09-22 — AIR-GAP HARDENED RELEASE

### Fixed — scans that silently died
- **`-q` quiet mode aborted immediately with no report.** Log helpers returned 1
  under `set -e`. Removed `set -e`/`pipefail` for the whole script — an audit
  must finish and report, not stop at the first benign non-zero status.
- **Non-root scans aborted at "File System Integrity"** (`find` hits a
  permission-denied directory → non-zero → exit). Same root cause.
- **RHEL 5/6 could not start**: `systemctl` was a *required* dependency. Now
  optional; `findmnt`, `sha256sum`, `tar` also optional.
- `timeout` does not exist on RHEL 5; `rpm -Va` / `aureport` checks silently
  reported "0" (false PASS). New `run_to` wrapper degrades gracefully.
- `grep -c … || echo 0` produced `"0\n0"` and broke integer tests (6 places).
- **Invalid JSON** whenever a value contained a newline, tab or control char.
- **HTML injection in the report**: category/ID were not escaped and `&`/quotes
  never were. Values are now fully escaped; the report ships a CSP that blocks
  all network loads.
- `CIS-PKG-4` reported "up to date" on hosts with **no repo metadata cache**
  (normal when air-gapped) and counted metadata banner lines as updates.
- Duplicate check IDs (`CIS-MOD`, `STIG-PKG`, `STIG-REQPKG` reused per item).
  IDs are now unique (item-suffixed, with automatic `.N` de-duplication).
- Leftover Lynis flag `-l/--lynis-tar` and messages removed.

### New
- **Air-gap isolation module** (`-m airgap`, included in `all`): 18+ checks for
  egress/bridging, radios, DMA ports, phone-home services, public repos, patch
  age, reboot-pending kernel, NTP/syslog destinations, SSH tunnelling.
- `--baseline FILE` — drift report (NEW / REGRESSED / FIXED / CHANGED) in
  console, HTML and JSON. Pure awk, no jq.
- `--waivers FILE` — documented deviations become `WAIVED` with the reason.
- `--bundle` — tar.gz with reports, MANIFEST.txt and SHA256SUMS; prints bundle
  hash for the media transfer log.
- `--strict` — exit 2 when FAILs remain. `--max-patch-age DAYS`.
- CSV output (with spreadsheet formula-injection guard).
- Script SHA-256 recorded in every report (chain of custody).
- Reports written with `umask 077`.

### Changed
- Compliance score is now `pass / (pass + fail + warn)`. INFO, SKIP and WAIVED
  no longer drag the score down (non-root scans were heavily penalised).
- Report rendering is done once per result at record time (removed the
  char-by-char bash JSON parser) — noticeably faster report generation.

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
