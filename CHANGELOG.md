# Changelog

## [2.3.0] — 2026-09-30 — PYTHON ENGINE + FALSE-POSITIVE FIXES

### New
- **`rhelguard.py` — a native Python engine.** Many hardened hosts will not run
  `.sh` files (local policy, change control, or a transfer gateway that rejects
  the extension). `rhelguard.py` is a full re-implementation, not a wrapper: it
  does not shell out to `rhelguard.sh` or embed it. Python 3.6+, standard
  library only, no pip, no network.
  - Same check IDs, categories, findings and remediation text as the shell
    engine, so a baseline captured with one can be diffed with the other
    (`-b` accepts either engine's JSON).
  - Verified on RHEL 9 (Python 3.9) and RHEL 8 (Python 3.6): both engines
    produce identical results in every mode — `all`, `cis`, `stig`, `posture`,
    `airgap` — as root and non-root.
- Every report now records `engine` (`bash` or `python3`) in the JSON and in the
  bundle `MANIFEST.txt`, so it is clear which produced a given result.
- `.gitattributes` forces LF checkout. A Windows clone with the default
  `core.autocrlf=true` rewrote the scripts to CRLF, and the shebang then failed
  with `env: 'bash
': No such file or directory`.

### Fixed — false FAILs on correctly hardened hosts
- **Duplicate config keys reported the wrong value.** `grep KEY file` returned
  every match, newline-joined (e.g. `PASS_MAX_DAYS = "99999
60"`), which then
  failed every numeric test. Hardening scripts routinely *append* overrides, so
  this hit ordinary hardened hosts: `PASS_WARN_AGE 7` twice reported FAIL.
  Both engines now take the **last** definition, which is what shadow-utils,
  libpwquality, pam_faillock, useradd defaults, systemd and dnf actually
  honour (verified empirically). `sshd_config` keeps first-wins, per OpenSSH.
  Affected `CIS-PW-1..5`, `CIS-PW-PQ`, `CIS-PW-FL1/2`, `CIS-ACC-5`,
  `CIS-KERN-11`, `CIS-AUD-2/3`, `HRDN-LOGG-2/3`, `HRDN-AUTH-6`,
  `STIG-PW-AGE`, `STIG-PW-LEN`.
- **`/etc/shadow` mode 0000 always FAILed.** `stat -Lc %a` prints mode 0000 as
  `0`, and the check compared it against the string `000` — so a correctly
  locked RHEL 9 shadow file was reported non-compliant. Modes are now
  normalised before comparison (`CIS-FILE-3`, `-4`, `-7`).
- **Every kernel/network sysctl FAILed when `sysctl` was absent.** `sysctl`
  ships in procps-ng, which minimal RHEL installs and UBI images omit; the old
  code recorded `N/A` for all of them. Both engines now read `/proc/sys`
  directly and fall back to the binary (`CIS-KERN-1..10`, `CIS-NET-1..22`,
  `HRDN-KRNL-1..3`).
- **Phantom "certificate expiring within 30 days".** `openssl … | cut || continue`
  never continued (cut exits 0 on empty input) and `date -d ""` returns *now*
  rather than failing, so an unreadable cert — or simply no `openssl` installed
  — scored 0 days left and was counted as expiring (`HRDN-CRYP-2`).
- **`POS-AUTH-1` silently passed as non-root.** It shelled out to `chage`, which
  needs root to read `/etc/shadow`; every account then looked compliant. Now
  gated with the root guard and reported as `SKIP (root required)`.

### Fixed — checks that could not fire
- **`hostname` was treated as a required tool and aborted the scan.** It is not
  installed on RHEL minimal installs or UBI containers, so the script exited 1
  with "Missing required tools" before running anything. It is now optional,
  with a `uname -n` → `/proc/sys/kernel/hostname` → `$HOSTNAME` fallback chain.
- `HRDN-BOOT-3` could never match `/proc/cmdline`: `\|` inside a `grep -E`
  pattern is a *literal* pipe, so it searched for the string
  `systemd.confirm_spawn=0|quiet`.
- `STIG-BNR-1` and `CIS-SSH-MAT` never reached their `sshd_config` fallback:
  in `sshd -T | awk … || grep …` the `||` never fires because `awk` exits 0 even
  with no output. `MaxAuthTries` therefore read `N/A` on any host where
  `sshd -T` was unavailable, and `STIG-BNR-1` had a duplicated condition.
- ~35 other `x=$(… || echo "N/A")` assignments had the same dead-fallback bug
  and left the value empty, so findings printed a blank where a value belonged.
- `HRDN-TIME-1` — `grep -c … || echo 0` emitted `"0
0"`, producing a bash
  arithmetic error on stderr during the NTP-source count.

### Changed
- The certificate-expiry sample is now **sorted** before being capped at 30.
  Unsorted, `head -30` examined a different 30 certificates depending on
  filesystem traversal order, so the result was not reproducible between runs
  or between engines.
- `AIR-TIME-1` and `AIR-NET-1` no longer leak awk's newlines and trailing
  spaces into the finding text.
- Version is `2.3.0` for both engines; they are released and tested together.

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
