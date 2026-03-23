# 🛡️ RHELGuard

> **Red Hat Enterprise Linux Security Audit Tool**

A single, self-contained shell script that audits RHEL systems against CIS Benchmarks, DISA STIGs, and a built-in hardening scanner — with **full non-root support**, auto OS detection, and beautiful HTML + JSON reports. **100% air-gap safe — no internet connection required, zero external dependencies.**

---

## ✨ What It Does

| Framework | Coverage |
|---|---|
| **CIS Benchmarks** | RHEL 5, 6, 7, 8, 9, 10 — L1 Server (auto-selected by detected version) |
| **DISA STIG** | RHEL 6, 7, 8, 9 — CAT I (High) + key CAT II (Medium) findings |
| **Posture Checks** | Crypto policy, file integrity, account hygiene, network exposure, SUID audit |
| **Built-in Hardening Scanner** | Embedded Lynis-equivalent covering 15 test categories: AUTH BOOT CRYP INSE KRNL LOGG MALW PKGS SCHD SHLL STRG TIME TOOL USERS HRDN — **no Lynis install needed, fully air-gap safe** |

---

## 🚀 Quick Start

```bash
# Copy to target
scp rhelguard.sh user@server:/tmp/

# Full scan (recommended)
sudo chmod +x /tmp/rhelguard.sh
sudo /tmp/rhelguard.sh

# Non-root partial scan (privileged checks auto-skipped)
chmod +x /tmp/rhelguard.sh
./rhelguard.sh
```

Reports saved to `./rhelguard_reports/` — open the `.html` file in any browser.

---

## 🔍 Non-Root Mode

RHELGuard **does not require root to run** — it will execute everything it can and cleanly skip checks that require elevated privileges, clearly marking them `SKIP (root required)` in the report.

| Check Type | Non-Root | Root |
|---|---|---|
| Kernel modules (lsmod, modprobe.d) | ✅ | ✅ |
| Mount options (findmnt) | ✅ | ✅ |
| SELinux status (getenforce, sestatus) | ✅ | ✅ |
| SSH config (sshd -T) | ✅ | ✅ |
| Sysctl network/kernel params | ✅ | ✅ |
| Service status (systemctl) | ✅ | ✅ |
| File permissions (/etc/passwd etc.) | ✅ | ✅ |
| Account UIDs/GIDs (/etc/passwd) | ✅ | ✅ |
| /etc/shadow — empty passwords | ❌ SKIP | ✅ |
| Audit log file permissions | ❌ SKIP | ✅ |
| RPM package integrity (rpm -Va) | ❌ SKIP | ✅ |
| chage (account expiry per-user) | ❌ SKIP | ✅ |

---

## ⚙️ Usage

```
sudo ./rhelguard.sh [OPTIONS]

OPTIONS:
  -m, --mode       cis | stig | posture | all    (default: all)
  -o, --output     Output directory               (default: ./rhelguard_reports)
  -t, --throttle   ms delay between checks        (default: 50)
  -s, --skip-lynis No-op (kept for compatibility — Lynis is no longer downloaded)
  -q, --quiet      Suppress per-check output
  -h, --help       Show this help
```

### Examples

```bash
# Full scan — all frameworks
sudo ./rhelguard.sh

# CIS only, custom output dir
sudo ./rhelguard.sh -m cis -o /var/log/rhelguard

# STIG only, higher throttle for busy production system
sudo ./rhelguard.sh -m stig -t 200

# Non-root partial scan
./rhelguard.sh

# Quiet mode (no console output, just reports)
sudo ./rhelguard.sh -q

# Air-gapped system — works out of the box, no flags needed
sudo ./rhelguard.sh
```

---

## 🖥️ Supported OS Versions

RHELGuard **auto-detects your RHEL major version** and applies the correct checks:

| Version | CIS Benchmark | DISA STIG | Notes |
|---|---|---|---|
| RHEL 5 | CIS RHEL 5 L1 v2.2.1 | v1r18 | Legacy — basic checks |
| RHEL 6 | CIS RHEL 6 v3.0.0 L1 | v2r2 | EOL — security-critical only |
| RHEL 7 | CIS RHEL 7 v4.0.0 L1 | v3r15 | Full coverage |
| RHEL 8 | CIS RHEL 8 v4.0.0 L1 | v2r6 | Full coverage |
| RHEL 9 | CIS RHEL 9 v2.0.0 L1 | v2r7 | Full coverage + RHEL 9-specific checks |
| RHEL 10 | CIS RHEL 10 v1.0.1 L1 | — | Best-effort (new) |

Also works on compatible derivatives: **CentOS**, **AlmaLinux**, **Rocky Linux**, **Fedora** (best-effort).

---

## 📊 HTML Report Features

The report is a standalone HTML file — no server required, open in any browser.

- **Compliance Score** — percentage circle with colour coding (red/amber/green)
- **Progress bar** — visual compliance fill bar
- **Summary cards** — PASS / FAIL / WARN / INFO / SKIP at a glance
- **Non-root warning** — banner showing how many checks were privilege-skipped
- **Filter buttons** — click to show only failures, warnings, passes etc.
- **Live search** — filter by check ID, category, finding text, remediation command
- **Remediation commands** — every FAIL/WARN shows the exact fix command

---

## 📁 Output Files

```
rhelguard_reports/
├── RHELGuard_<hostname>_<timestamp>.html    ← Human dashboard
└── RHELGuard_<hostname>_<timestamp>.json    ← Machine-readable
```

---

## 🔒 Production Safety

| Feature | Detail |
|---|---|
| ✅ Read-only | Zero system modifications made |
| ✅ No service restarts | Nothing interrupted |
| ✅ Configurable throttle | `--throttle 200` for I/O-sensitive systems |
| ✅ No network probing | All checks are local only |
| ✅ No port scanning | Network checks inspect local sysctl only |
| ✅ Non-root safe | Runs without sudo, skips privileged checks gracefully |
| ✅ No package installs | Zero dependencies beyond base RHEL |

For very busy production systems:

```bash
sudo ./rhelguard.sh -t 500   # 500ms throttle for very busy systems
```

---

## 🔧 Multi-Host Automation

```bash
#!/bin/bash
HOSTS=(web01 db01 app01 bastion01)
for host in "${HOSTS[@]}"; do
    echo "Scanning $host..."
    scp rhelguard.sh root@${host}:/tmp/
    ssh root@${host} "chmod +x /tmp/rhelguard.sh && /tmp/rhelguard.sh -q -s -o /tmp/rg_out"
    mkdir -p collected/${host}
    scp "root@${host}:/tmp/rg_out/*.json" collected/${host}/
    scp "root@${host}:/tmp/rg_out/*.html" collected/${host}/
done
echo "All done. Reports in ./collected/"
```

---

## 📋 JSON Output — jq Queries

```bash
# Show all failures with remediation
jq '.results[] | select(.status=="FAIL") | {id, title, remediation}' RHELGuard_*.json

# Compliance summary
jq '.summary' RHELGuard_*.json

# All CAT I equivalent (FAIL) access control issues
jq '.results[] | select(.status=="FAIL" and .category=="ACCESS CONTROL")' RHELGuard_*.json

# Count skipped due to non-root
jq '.summary.priv_skip' RHELGuard_*.json
```

---

## 📐 Check Coverage Summary

### CIS (version-aware)

| Area | Checks |
|---|---|
| Kernel modules | cramfs, freevxfs, hfs, hfsplus, jffs2, udf, squashfs (8+), firewire, usb-storage, sctp, tipc, atm, can, bluetooth (9+) |
| Mount options | /tmp, /dev/shm, /home, /var, /var/tmp, /var/log, /var/log/audit, /boot (9+) |
| Package management | GPG keys, gpgcheck, localpkg_gpgcheck (9+), pending updates |
| SELinux | Install, bootloader, mode, policy, mcstrans, setroubleshoot |
| Bootloader | Password, config permissions, ownership (9+) |
| Kernel params | ASLR, suid_dump, dmesg_restrict, kptr_restrict, ptrace, hardlinks, symlinks, BPF (8+), user namespaces (9+) |
| Services | 20+ unnecessary service checks, version-conditional |
| Network | 22+ sysctl parameters, firewall |
| Logging | auditd, audit rules (7 keys + extras for 8+), rsyslog, journald |
| SSH | 17 directive checks, version-conditional (GSSAPI, Kerberos, UsePAM) |
| Password policy | login.defs, pwquality, faillock (8+) / pam_tally2 (≤7), TMOUT, umask |
| File permissions | 8 critical /etc files with mode + ownership |
| Account integrity | UID 0 audit, duplicate UIDs/GIDs, empty passwords, inactive lockout |

### DISA STIG

| Severity | Areas |
|---|---|
| CAT I (High) | FIPS mode, disk encryption, shosts files, dangerous packages, Ctrl-Alt-Delete, UID 0 |
| CAT II (Medium) | SSH banners, crypto policy, sudo NOPASSWD, SSH key permissions, USBGuard (9+), required packages (9+), audit log perms, password aging, NTP, wireless, Bluetooth |

### Posture

| Area | Checks |
|---|---|
| File integrity | World-writable /etc files, sticky bit, SUID/SGID inventory, AIDE, RPM verify |
| Accounts | Interactive account expiry, system account shells, cron access |
| Crypto | System crypto policy, Secure Boot, NX/XD bit |
| Network | Listening services, promiscuous mode, IPv6 status |
| Logging | Critical log file presence |
| Built-in Hardening | AUTH, BOOT, CRYP, INSE, KRNL, LOGG, MALW, PKGS, SCHD, SHLL, STRG, TIME, TOOL, USERS, HRDN |

---

## 📜 References

- [CIS Red Hat Enterprise Linux Benchmarks](https://www.cisecurity.org/benchmark/red_hat_linux)
- [DISA STIG for RHEL 8](https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8)
- [DISA STIG for RHEL 9](https://www.stigviewer.com/stigs/red_hat_enterprise_linux_9)
- [Tenable CIS/STIG Audit Files](https://www.tenable.com/audits/search?q=Red+Hat+Enterprise+Linux)
- [CISOfy Lynis](https://github.com/CISOfy/lynis) *(inspiration for hardening categories — not required or downloaded)*
- [NIST 800-53](https://nvd.nist.gov/800-53)

---

## 📜 License

MIT — see [LICENSE](LICENSE)
