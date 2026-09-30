#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  ██████╗ ██╗  ██╗███████╗██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
#  ██╔══██╗██║  ██║██╔════╝██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
#  ██████╔╝███████║█████╗  ██║     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
#  ██╔══██╗██╔══██║██╔══╝  ██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
#  ██║  ██║██║  ██║███████╗███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
#  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
#
#  RHELGuard — Red Hat Enterprise Linux Security Audit Tool (Python edition)
#  Version : 2.3.0
#  Covers  : RHEL 5, 6, 7, 8, 9, 10 (auto-detected)
#  Sources : CIS Benchmarks (L1/L2) + DISA STIG v2 + Lynis-style posture
#  License : MIT
# =============================================================================
# WHY THIS FILE EXISTS
#   Many hardened / STIG'd hosts refuse to execute .sh files (noexec mounts,
#   SELinux policy, or local policy forbidding shell scripts). This is a native
#   Python re-implementation of rhelguard.sh — it does NOT wrap, embed or shell
#   out to the shell script. It emits the same check IDs and the same
#   JSON / CSV / HTML reports, so the two engines are interchangeable and a
#   baseline taken with one can be diffed against the other.
#
# USAGE
#         python3 rhelguard.py [OPTIONS]      # non-root: partial scan
#   sudo  python3 rhelguard.py [OPTIONS]      # full scan (recommended)
#
# REQUIREMENTS
#   Python 3.6+ (RHEL 8 ships 3.6, RHEL 9/10 ship 3.9+). Standard library only
#   — no pip, no venv, no network. Nothing is installed or downloaded.
#
# PRODUCTION SAFE
#   - 100% read-only. Zero system modifications.
#   - Configurable throttle prevents I/O spikes on busy hosts.
#   - Non-root mode: skips privileged checks cleanly, runs everything else.
#   - No network probing, no port scanning, no package installs.
#   - AIR-GAP SAFE: every check reads local state (/proc, /sys, /etc, rpm DB).
#   - Reports are written with umask 077 (they describe your weaknesses).
# =============================================================================

from __future__ import print_function

import argparse
import csv
import errno
import fnmatch
import glob
import grp
import io
import json
import os
import pwd
import re
import shutil
import stat as statmod
import subprocess
import sys
import tarfile
import time
from datetime import datetime

TOOL_NAME = "RHELGuard"
TOOL_VERSION = "2.3.0"
ENGINE = "python3"

if sys.version_info < (3, 6):
    sys.stderr.write("RHELGuard requires Python 3.6 or newer (found %s).\n"
                     % ".".join(str(x) for x in sys.version_info[:3]))
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE
# ─────────────────────────────────────────────────────────────────────────────
_TTY = (sys.stdout.isatty()
        and os.environ.get("TERM", "") not in ("", "dumb")
        and "NO_COLOR" not in os.environ)

RED = "\033[0;31m" if _TTY else ""
GREEN = "\033[0;32m" if _TTY else ""
YELLOW = "\033[1;33m" if _TTY else ""
CYAN = "\033[0;36m" if _TTY else ""
MAGENTA = "\033[0;35m" if _TTY else ""
BOLD = "\033[1m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def _p(msg=""):
    """Print, never dying on a closed pipe or an undecodable console."""
    try:
        print(msg)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "ascii"
        print(msg.encode(enc, "replace").decode(enc, "replace"))
    except (IOError, OSError) as exc:
        if getattr(exc, "errno", None) != errno.EPIPE:
            raise


# ─────────────────────────────────────────────────────────────────────────────
# LOW-LEVEL SYSTEM HELPERS
# All read-only and fail-soft: a missing binary or unreadable file yields an
# empty/None answer, never an exception. This is what lets a single scan run
# to completion on a minimal install, in a container, and as a non-root user.
# ─────────────────────────────────────────────────────────────────────────────
_WHICH_CACHE = {}


def have(binary):
    """True if `binary` is on PATH. Mirrors `command -v`."""
    if binary not in _WHICH_CACHE:
        _WHICH_CACHE[binary] = shutil.which(binary) is not None
    return _WHICH_CACHE[binary]


def run(argv, timeout=None, merge_stderr=False):
    """Run argv, return (returncode, stdout). Never raises.

    rc is 127 when the binary is missing and 124 on timeout, matching the
    shell conventions the original script relied on.
    """
    if not argv:
        return 127, ""
    if not os.path.isabs(argv[0]) and not have(argv[0]):
        return 127, ""
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
            errors="replace",
            env=dict(os.environ, LC_ALL="C", LANG="C"),
        )
    except (OSError, ValueError):
        return 127, ""
    try:
        stdout, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=5)
        except Exception:
            pass
        return 124, ""
    except (OSError, ValueError):
        return 127, ""
    return proc.returncode, stdout or ""


def out(argv, timeout=None):
    """stdout of argv, stripped. Empty string on any failure."""
    return run(argv, timeout=timeout)[1].strip()


def ok(argv, timeout=None):
    """True if argv exits 0. Mirrors `cmd &>/dev/null` used as a condition."""
    return run(argv, timeout=timeout)[0] == 0


def read_text(path):
    """Whole file as str, or None if unreadable. Never raises."""
    try:
        with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (IOError, OSError):
        return None


def read_value(path, default="N/A"):
    """First line of a /proc or /sys file, stripped."""
    txt = read_text(path)
    if txt is None:
        return default
    txt = txt.strip()
    return txt if txt else default


def _expand(paths):
    if isinstance(paths, str):
        paths = [paths]
    expanded = []
    for pat in paths:
        if glob.has_magic(pat):
            expanded.extend(sorted(glob.glob(pat)))
        else:
            expanded.append(pat)
    return expanded


def read_lines(paths, ignore_comments=False):
    """Concatenated lines from a path, list of paths, or globs."""
    lines = []
    for path in _expand(paths):
        txt = read_text(path)
        if txt is None:
            continue
        for line in txt.splitlines():
            if ignore_comments and re.match(r"^\s*(#|$)", line):
                continue
            lines.append(line)
    return lines


def grep_q(paths, pattern, ignorecase=False):
    """True if any line in paths matches pattern. Mirrors `grep -qE`."""
    rx = re.compile(pattern, re.IGNORECASE if ignorecase else 0)
    for line in read_lines(paths):
        if rx.search(line):
            return True
    return False


def grep_lines(paths, pattern, ignorecase=False):
    """Matching lines across paths. Mirrors `grep -hE`."""
    rx = re.compile(pattern, re.IGNORECASE if ignorecase else 0)
    return [l for l in read_lines(paths) if rx.search(l)]


def _walk_all(root, follow_symlinks=False):
    """Every path at or under root. Mirrors find's default no-follow behaviour."""
    try:
        if os.path.islink(root) and not follow_symlinks:
            yield root
            return
        if not os.path.isdir(root):
            yield root
            return
    except OSError:
        return
    yield root
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks,
                                                onerror=lambda e: None):
        for name in dirnames:
            yield os.path.join(dirpath, name)
        for name in filenames:
            yield os.path.join(dirpath, name)


def _regular_files(roots):
    for root in _expand(roots):
        for path in _walk_all(root):
            try:
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
            except OSError:
                continue
            yield path


def grep_rq(roots, pattern, ignorecase=False):
    """Recursive content grep. Mirrors `grep -rqE PATTERN DIR/`."""
    rx = re.compile(pattern, re.IGNORECASE if ignorecase else 0)
    for path in _regular_files(roots):
        txt = read_text(path)
        if txt is None:
            continue
        for line in txt.splitlines():
            if rx.search(line):
                return True
    return False


def grep_r_lines(roots, pattern, ignorecase=False):
    """Recursive grep returning matching lines. Mirrors `grep -rEh`."""
    rx = re.compile(pattern, re.IGNORECASE if ignorecase else 0)
    found = []
    for path in _regular_files(roots):
        txt = read_text(path)
        if txt is None:
            continue
        for line in txt.splitlines():
            if rx.search(line):
                found.append(line)
    return found


# ── find(1) equivalents ─────────────────────────────────────────────────────
def find_paths(roots, name=None, not_name=None, type_=None, maxdepth=None,
               perm_all=None, perm_any=None, perm_exact=None,
               perm_exact_not=None, xdev=False):
    """A focused re-implementation of the `find` calls this tool needs.

    perm_all       -> `-perm -MODE`  (every listed bit set)
    perm_any       -> `-perm /MODE`  (at least one listed bit set)
    perm_exact     -> `-perm MODE`   (permission bits exactly MODE)
    perm_exact_not -> iterable of modes; keep entries matching none of them
    Symlinks are never followed, and a symlinked start point is reported but
    not descended into — both matching find's default behaviour.
    """
    results = []
    for root in _expand(roots):
        try:
            root_st = os.lstat(root)
        except OSError:
            continue
        root_dev = root_st.st_dev
        stack = [(root, 0)]
        while stack:
            path, depth = stack.pop()
            try:
                st = os.lstat(path)
            except OSError:
                continue
            is_link = statmod.S_ISLNK(st.st_mode)
            is_dir = statmod.S_ISDIR(st.st_mode)
            bits = statmod.S_IMODE(st.st_mode)
            base = os.path.basename(path.rstrip("/")) or path
            keep = True
            if name is not None and not _fn_any(base, name):
                keep = False
            if keep and not_name is not None and _fn_any(base, not_name):
                keep = False
            if keep and type_ == "f" and not statmod.S_ISREG(st.st_mode):
                keep = False
            if keep and type_ == "d" and not is_dir:
                keep = False
            if keep and perm_all is not None and (bits & perm_all) != perm_all:
                keep = False
            if keep and perm_any is not None and not (bits & perm_any):
                keep = False
            if keep and perm_exact is not None and bits != perm_exact:
                keep = False
            if keep and perm_exact_not is not None and bits in perm_exact_not:
                keep = False
            if keep:
                results.append(path)
            if is_dir and not is_link and (maxdepth is None or depth < maxdepth):
                if xdev and st.st_dev != root_dev:
                    continue
                try:
                    for entry in os.listdir(path):
                        stack.append((os.path.join(path, entry), depth + 1))
                except OSError:
                    pass
    return results


def _fn_any(base, patterns):
    if isinstance(patterns, str):
        patterns = [patterns]
    return any(fnmatch.fnmatch(base, p) for p in patterns)


# ── stat(1) equivalents (stat -L follows symlinks) ──────────────────────────
def stat_mode(path):
    """Octal permission string like `stat -Lc %a`, or 'N/A'.

    Padded to at least three digits: `stat %a` prints mode 0000 as "0", and
    comparing that against the literal "000" made a correctly locked
    /etc/shadow (mode 0000 on RHEL 9) report as a FAIL.
    """
    try:
        return "%03o" % statmod.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return "N/A"


def stat_owner(path):
    try:
        uid = os.stat(path).st_uid
    except OSError:
        return "N/A"
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def stat_group(path):
    try:
        gid = os.stat(path).st_gid
    except OSError:
        return "N/A"
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def stat_owner_group(path):
    """'owner:group' like `stat -Lc %U:%G`, collapsing to a single 'N/A'."""
    if not os.path.exists(path):
        return "N/A"
    return "%s:%s" % (stat_owner(path), stat_group(path))


# ── sysctl: read /proc/sys directly, fall back to the binary ────────────────
# `sysctl` ships in procps-ng, which is NOT installed on RHEL minimal images
# or UBI containers — reading /proc/sys needs no package at all.
def sysctl(name):
    txt = read_text("/proc/sys/" + name.replace(".", "/"))
    if txt is not None:
        return " ".join(txt.split())
    val = out(["sysctl", "-n", name])
    return val if val else "N/A"


# ── systemd / SysV ─────────────────────────────────────────────────────────
def svc_active(unit):
    """`systemctl is-active unit` exited 0."""
    return ok(["systemctl", "is-active", unit], timeout=20)


def svc_enabled(unit):
    """`systemctl is-enabled unit` exited 0 (also true for static/indirect)."""
    return ok(["systemctl", "is-enabled", unit], timeout=20)


def unit_on(unit):
    """Enabled or active, systemd or SysV. Mirrors the shell `_unit_on`."""
    if have("systemctl"):
        if ok(["systemctl", "is-active", "--quiet", unit], timeout=20):
            return True
        return out(["systemctl", "is-enabled", unit], timeout=20) == "enabled"
    if unit.endswith(".timer") or unit.endswith(".path"):
        return False
    name = unit[:-8] if unit.endswith(".service") else unit
    rc, txt = run(["chkconfig", "--list", name], timeout=20)
    return rc == 0 and ":on" in txt


# ── rpm ────────────────────────────────────────────────────────────────────
def rpm_installed(pkg):
    return ok(["rpm", "-q", pkg], timeout=60)


# ── kernel modules: /proc/modules is lsmod's own source ────────────────────
_MODULES_CACHE = None


def loaded_modules():
    global _MODULES_CACHE
    if _MODULES_CACHE is None:
        mods = set()
        txt = read_text("/proc/modules")
        if txt:
            for line in txt.splitlines():
                parts = line.split()
                if parts:
                    mods.add(parts[0])
        elif have("lsmod"):
            for line in out(["lsmod"]).splitlines()[1:]:
                parts = line.split()
                if parts:
                    mods.add(parts[0])
        _MODULES_CACHE = mods
    return _MODULES_CACHE


def mod_loaded(name):
    return name in loaded_modules()


# ── mounts: /proc/self/mountinfo is findmnt's own source ───────────────────
_MOUNTS_CACHE = None


def _unoctal(text):
    r"""mountinfo escapes space/tab/newline/backslash as \040 etc."""
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), text)


def mounts():
    """{mountpoint: set(options)}, for exact-target lookups like findmnt TARGET."""
    global _MOUNTS_CACHE
    if _MOUNTS_CACHE is None:
        table = {}
        txt = read_text("/proc/self/mountinfo")
        if txt:
            for line in txt.splitlines():
                fields = line.split()
                if len(fields) < 6:
                    continue
                target = _unoctal(fields[4])
                opts = set(fields[5].split(","))
                if "-" in fields:
                    sep = fields.index("-")
                    if len(fields) > sep + 3:
                        opts |= set(fields[sep + 3].split(","))
                table[target] = opts
        else:
            for line in (read_text("/proc/mounts") or "").splitlines():
                fields = line.split()
                if len(fields) >= 4:
                    table[_unoctal(fields[1])] = set(fields[3].split(","))
        _MOUNTS_CACHE = table
    return _MOUNTS_CACHE


def is_mountpoint(path):
    return path in mounts()


def mount_options(path):
    return mounts().get(path, set())


# ── /etc/passwd, /etc/group, /etc/shadow ───────────────────────────────────
def passwd_entries():
    """Parsed from the file (not the pwd module) to match `awk -F:` exactly."""
    rows = []
    for line in read_lines("/etc/passwd"):
        if not line.strip():
            continue
        f = line.split(":")
        if len(f) < 7:
            continue
        rows.append({"user": f[0], "pw": f[1], "uid": f[2], "gid": f[3],
                     "gecos": f[4], "home": f[5], "shell": f[6]})
    return rows


def group_entries():
    rows = []
    for line in read_lines("/etc/group"):
        if not line.strip():
            continue
        f = line.split(":")
        if len(f) < 3:
            continue
        rows.append({"group": f[0], "pw": f[1], "gid": f[2]})
    return rows


def shadow_entries():
    rows = []
    for line in read_lines("/etc/shadow"):
        if not line.strip():
            continue
        f = line.split(":")
        while len(f) < 9:
            f.append("")
        rows.append({"user": f[0], "pw": f[1], "lastchg": f[2], "min": f[3],
                     "max": f[4], "warn": f[5], "inactive": f[6], "expire": f[7]})
    return rows


def as_int(value, default=None):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# ── config-file value extraction ───────────────────────────────────────────
def conf_value(paths, key, sep="=", first=False):
    """Effective value for `key`, or None.

    sep '=' for key=value, None for whitespace-separated.

    Returns the LAST definition by default, because that is what the parsers
    actually honour: shadow-utils (/etc/login.defs), useradd defaults,
    libpwquality, pam_faillock, systemd and dnf all let a later line override
    an earlier one, and hardening scripts routinely append their overrides to
    the end of the shipped file. Taking the first match there would report the
    distro default (e.g. PASS_MAX_DAYS 99999) on a host that is in fact set to
    60, i.e. a false FAIL.

    Pass first=True for sshd_config, which is the documented exception:
    "the first obtained value for each parameter is used".
    """
    if sep == "=":
        rx = re.compile(r"^\s*" + re.escape(key) + r"\s*=\s*(.*?)\s*$", re.IGNORECASE)
    else:
        rx = re.compile(r"^\s*" + re.escape(key) + r"\s+(\S+)", re.IGNORECASE)
    found = None
    for line in read_lines(paths):
        m = rx.match(line)
        if m:
            found = m.group(1).strip()
            if first:
                return found
    return found


_SSHD_T_CACHE = None


def sshd_effective():
    """`sshd -T` as {lowercase_key: value}. Empty if sshd cannot dump its config."""
    global _SSHD_T_CACHE
    if _SSHD_T_CACHE is None:
        conf = {}
        for argv in (["sshd", "-T"], ["/usr/sbin/sshd", "-T"]):
            rc, txt = run(argv, timeout=20)
            if rc == 0 and txt.strip():
                for line in txt.splitlines():
                    parts = line.split(None, 1)
                    if parts:
                        conf[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else ""
                break
        _SSHD_T_CACHE = conf
    return _SSHD_T_CACHE


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER
# Holds run configuration, the result list and the counters. Each check calls
# self.record(...) exactly as the shell version calls record_result.
# ─────────────────────────────────────────────────────────────────────────────
STATUSES = ("PASS", "FAIL", "WARN", "INFO", "SKIP", "WAIVED")


class Scanner(object):

    def __init__(self, args):
        self.args = args
        self.quiet = args.quiet
        self.throttle_s = args.throttle / 1000.0
        self.max_patch_age = args.max_patch_age
        self.output_dir = args.output
        self.scan_mode = args.mode
        self.baseline_file = args.baseline
        self.waiver_file = args.waivers
        self.bundle = args.bundle
        self.strict = args.strict

        self.results = []
        self.counts = dict((s, 0) for s in STATUSES)
        self.total = 0
        self.priv_skip = 0
        self.seen_ids = set()

        self.is_root = (os.geteuid() == 0)
        self.start_ts = time.time()
        self.report_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.hostname = self._hostname()

        self.rhel_major = 0
        self.rhel_full = "Unknown"
        self.os_family = "rhel"

        self.script_path = os.path.abspath(sys.argv[0] if sys.argv[0] else __file__)
        self.script_sha256 = "unavailable"

        self.waivers = []          # list of (id, reason)
        self.drift = []            # list of dicts
        self.drift_new_fail = 0
        self.drift_fixed = 0
        self.drift_changed = 0

    # ── hostname without depending on the `hostname` binary ──────────────────
    @staticmethod
    def _hostname():
        """`hostname` is absent on RHEL minimal installs and UBI containers."""
        name = out(["hostname", "-s"])
        if name:
            return name.split(".")[0]
        for path in ("/proc/sys/kernel/hostname", "/etc/hostname"):
            val = read_value(path, "")
            if val:
                return val.split(".")[0]
        name = os.environ.get("HOSTNAME", "")
        if name:
            return name.split(".")[0]
        try:
            return os.uname()[1].split(".")[0]
        except Exception:
            return "unknown"

    # ── console output ──────────────────────────────────────────────────────
    def log(self, msg):
        if not self.quiet:
            _p("%s[*]%s %s" % (CYAN, RESET, msg))

    def log_warn(self, msg):
        if not self.quiet:
            _p("%s[WARN]%s %s" % (YELLOW, RESET, msg))

    def banner(self, msg):
        if not self.quiet:
            _p("\n%s%s━━━ %s ━━━%s\n" % (BOLD, CYAN, msg, RESET))

    def _echo_result(self, status, cid, title):
        if self.quiet:
            return
        if status == "PASS":
            _p("%s[PASS]%s %s — %s" % (GREEN, RESET, cid, title))
        elif status == "FAIL":
            _p("%s[FAIL]%s %s — %s" % (RED, RESET, cid, title))
        elif status == "WARN":
            _p("%s[WARN]%s %s — %s" % (YELLOW, RESET, cid, title))
        elif status == "INFO":
            _p("%s[INFO]%s %s — %s" % (BOLD, RESET, cid, title))
        elif status == "SKIP":
            _p("      [SKIP] %s — %s" % (cid, title))
        elif status == "WAIVED":
            _p("%s[INFO]%s %s — %s (waived)" % (BOLD, RESET, cid, title))

    # ── version helpers ─────────────────────────────────────────────────────
    def ge(self, n):
        return self.rhel_major >= n

    def le(self, n):
        return self.rhel_major <= n

    def eq(self, n):
        return self.rhel_major == n

    # ── result recording ────────────────────────────────────────────────────
    def record(self, status, cid, title, category, description, remediation=""):
        """Record one finding. Applies ID de-duplication then waivers."""
        base_id = cid
        n = 1
        while cid in self.seen_ids:
            n += 1
            cid = "%s.%d" % (base_id, n)
        self.seen_ids.add(cid)

        if status in ("FAIL", "WARN"):
            for wid, reason in self.waivers:
                if wid and wid in (cid, base_id):
                    description = "WAIVED (was %s): %s — %s" % (status, reason, description)
                    status = "WAIVED"
                    break

        self.total += 1
        self.counts[status] = self.counts.get(status, 0) + 1
        self._echo_result(status, cid, title)

        self.results.append({
            "id": cid,
            "status": status,
            "title": title,
            "category": category,
            "description": description,
            "remediation": remediation if remediation else "N/A",
            "rhel_ver": self.rhel_major,
            "ts": _iso_now(),
        })
        if self.throttle_s > 0:
            time.sleep(self.throttle_s)

    def needs_root(self, cid, title, category):
        """False (and records a SKIP) when not root. Mirrors the shell guard."""
        if not self.is_root:
            self.priv_skip += 1
            self.record("SKIP", cid, title, category,
                        "ROOT REQUIRED — re-run with sudo for full coverage.",
                        "sudo python3 rhelguard.py")
            return False
        return True

    # ── OS detection ────────────────────────────────────────────────────────
    def detect_os(self):
        rel = read_text("/etc/redhat-release")
        osr = _parse_os_release("/etc/os-release")
        if rel and rel.strip():
            self.rhel_full = rel.strip().splitlines()[0]
        elif osr.get("PRETTY_NAME"):
            self.rhel_full = osr["PRETTY_NAME"]

        low = self.rhel_full
        if "Red Hat" in low:
            self.os_family = "rhel"
        elif "CentOS" in low:
            self.os_family = "centos"
        elif "AlmaLinux" in low:
            self.os_family = "alma"
        elif "Rocky" in low:
            self.os_family = "rocky"
        elif "Fedora" in low:
            self.os_family = "fedora"
        else:
            self.os_family = "unknown"

        major = 0
        if osr.get("VERSION_ID"):
            major = as_int(osr["VERSION_ID"].split(".")[0], 0)
        if not major:
            m = re.search(r"release\s+(\d+)", self.rhel_full)
            if m:
                major = as_int(m.group(1), 0)
        self.rhel_major = major or 0

        if self.rhel_major not in (5, 6, 7, 8, 9, 10):
            _p("%s[WARN] Detected major version: %s — best-effort mode "
               "(tool targets 5–10)%s" % (YELLOW, self.rhel_major, RESET))

    # ── dependency check ────────────────────────────────────────────────────
    def check_deps(self):
        """Warn about missing optional tools; only hard-fail on the true basics.

        `hostname`, `sysctl` and friends are deliberately NOT required: they
        live in packages that minimal RHEL installs and UBI images omit, and
        every check that wanted them now has a /proc or /sys fallback.
        """
        required = ["rpm"]
        missing = [t for t in required if not have(t)]
        if missing:
            _p("%s[ERROR] Missing required tools: %s%s" % (RED, " ".join(missing), RESET))
            _p("These are standard on all RHEL systems — check your PATH.")
            sys.exit(1)

        optional = ["hostname", "sysctl", "systemctl", "sshd", "getenforce", "sestatus",
                    "ss", "findmnt", "auditctl", "lsblk", "blkid", "ip", "mokutil",
                    "chage", "tar", "openssl", "chronyc", "aureport",
                    "update-crypto-policies"]
        absent = [t for t in optional if not have(t)]
        if absent:
            self.log_warn("Optional tools not found (checks using them fall back to "
                          "/proc, /sys or are skipped): %s" % " ".join(absent))

        self.log("Air-gap safe: all checks use local system state only.")
        self.log("No outbound network connections are made by any check.")

    # ── preflight ───────────────────────────────────────────────────────────
    def preflight(self):
        self.detect_os()
        self.check_deps()

        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except OSError as exc:
            _p("Cannot create output dir: %s (%s)" % (self.output_dir, exc))
            sys.exit(1)
        if not os.access(self.output_dir, os.W_OK):
            _p("Output dir is not writable: %s" % self.output_dir)
            sys.exit(1)

        self.script_sha256 = _sha256_file(self.script_path)

        if self.waiver_file:
            self.waivers = _load_waivers(self.waiver_file)
            self.log("Waivers  : %d loaded from %s" % (len(self.waivers), self.waiver_file))

        if not self.is_root:
            _p("%s╔══════════════════════════════════════════════════════════════╗" % YELLOW)
            _p("║  ⚠  Running WITHOUT root — privileged checks will be SKIP'd  ║")
            _p("║  Re-run with sudo for complete coverage.                     ║")
            _p("╚══════════════════════════════════════════════════════════════╝%s" % RESET)

        self.log("Tool     : %s v%s (%s engine)" % (TOOL_NAME, TOOL_VERSION, ENGINE))
        self.log("Host     : %s" % self.hostname)
        self.log("OS       : %s (RHEL major: %s, family: %s)"
                 % (self.rhel_full, self.rhel_major, self.os_family))
        self.log("Kernel   : %s" % _kernel_release())
        self.log("Mode     : %s" % self.scan_mode)
        self.log("Throttle : %dms" % self.args.throttle)
        self.log("As root  : %s" % str(self.is_root).lower())
        self.log("Output   : %s" % self.output_dir)
        self.log("SHA-256  : %s" % self.script_sha256)

    # ── scoring ─────────────────────────────────────────────────────────────
    def compliance_pct(self):
        denom = self.counts["PASS"] + self.counts["FAIL"] + self.counts["WARN"]
        if denom <= 0:
            return 0.0
        return round((self.counts["PASS"] / float(denom)) * 100.0, 1)

    # ── drift vs baseline ───────────────────────────────────────────────────
    def compute_drift(self):
        if not self.baseline_file:
            return
        old = _load_baseline_statuses(self.baseline_file)
        if old is None:
            self.log_warn("Baseline could not be parsed: %s" % self.baseline_file)
            return
        for res in self.results:
            cid, new = res["id"], res["status"]
            if cid not in old:
                if new in ("FAIL", "WARN"):
                    self.drift.append({"change": "NEW", "id": cid, "from": "-",
                                       "to": new, "title": res["title"]})
                continue
            prev = old[cid]
            if prev == new:
                continue
            if new in ("FAIL", "WARN") and prev not in ("FAIL", "WARN"):
                change = "REGRESSED"
            elif new == "PASS" and prev in ("FAIL", "WARN"):
                change = "FIXED"
            else:
                change = "CHANGED"
            self.drift.append({"change": change, "id": cid, "from": prev,
                               "to": new, "title": res["title"]})
        self.drift_new_fail = sum(1 for d in self.drift if d["change"] in ("NEW", "REGRESSED"))
        self.drift_fixed = sum(1 for d in self.drift if d["change"] == "FIXED")
        self.drift_changed = len(self.drift)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def _iso_now():
    return datetime.now().replace(microsecond=0).astimezone().isoformat()


def _kernel_release():
    try:
        return os.uname()[2]
    except Exception:
        return read_value("/proc/sys/kernel/osrelease", "unknown")


def _parse_os_release(path):
    data = {}
    for line in read_lines(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        data[key.strip()] = val
    return data


def _sha256_file(path):
    """Chain of custody: which build produced this report."""
    try:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unavailable"


def _load_waivers(path):
    """`CHECK-ID | reason` per line; blanks and # comments ignored."""
    waivers = []
    for line in read_lines(path, ignore_comments=True):
        if "|" in line:
            wid, _, reason = line.partition("|")
            reason = reason.strip() or "(no reason given)"
        else:
            wid, reason = line, "(no reason given)"
        wid = re.sub(r"\s+", "", wid)
        if wid:
            waivers.append((wid, reason))
    return waivers


def _load_baseline_statuses(path):
    """{id: status} from a previous RHELGuard JSON report."""
    txt = read_text(path)
    if txt is None:
        return None
    try:
        data = json.loads(txt)
        results = data.get("results", [])
        return dict((r["id"], r["status"]) for r in results
                    if isinstance(r, dict) and "id" in r and "status" in r)
    except (ValueError, TypeError, KeyError):
        pass
    # Fall back to the line-oriented form (one JSON object per line).
    statuses = {}
    for line in txt.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and "id" in obj and "status" in obj and "change" not in obj:
            statuses[obj["id"]] = obj["status"]
    return statuses or None


# =============================================================================
#  ██████╗██╗███████╗
# ██╔════╝██║██╔════╝
# ██║     ██║███████╗
# ██║     ██║╚════██║
# ╚██████╗██║███████║
#  ╚═════╝╚═╝╚══════╝
#  CIS BENCHMARK CHECKS  (version-aware: RHEL 5–10)
# =============================================================================

def run_cis_checks(s):
    # ── Kernel Modules ───────────────────────────────────────────────────────
    s.banner("CIS — Filesystem Kernel Modules")

    modules = ["cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf"]
    if s.ge(8):
        modules += ["squashfs", "firewire-core", "usb-storage", "sctp", "tipc"]
    if s.ge(9):
        modules += ["atm", "can", "bluetooth"]

    for mod in modules:
        safe = mod.replace("-", "_")
        loaded = mod_loaded(safe)
        blacklisted = grep_rq("/etc/modprobe.d",
                              r"^\s*(blacklist|install)\s+" + re.escape(mod))
        if not loaded and blacklisted:
            s.record("PASS", "CIS-MOD-" + mod,
                     "Kernel module '%s' disabled and blacklisted" % mod,
                     "CONFIGURATION MANAGEMENT",
                     "Module %s is not loaded and is blacklisted." % mod, "")
        elif not loaded:
            s.record("WARN", "CIS-MOD-" + mod,
                     "Module '%s' not loaded but not blacklisted" % mod,
                     "CONFIGURATION MANAGEMENT",
                     "Module %s is absent at runtime but not hardened." % mod,
                     "echo 'install %s /bin/false' >> /etc/modprobe.d/hardening.conf && "
                     "echo 'blacklist %s' >> /etc/modprobe.d/hardening.conf" % (mod, mod))
        else:
            s.record("FAIL", "CIS-MOD-" + mod,
                     "Kernel module '%s' is loaded/available" % mod,
                     "CONFIGURATION MANAGEMENT",
                     "Module %s is currently loaded." % mod,
                     "modprobe -r %s && echo 'install %s /bin/false' >> "
                     "/etc/modprobe.d/hardening.conf" % (mod, mod))

    # ── Mount Options ────────────────────────────────────────────────────────
    s.banner("CIS — Filesystem Mount Options")

    mount_checks = [
        ("/tmp", "nodev", "CIS-MNT-1"),
        ("/tmp", "nosuid", "CIS-MNT-2"),
        ("/tmp", "noexec", "CIS-MNT-3"),
        ("/dev/shm", "nodev", "CIS-MNT-4"),
        ("/dev/shm", "nosuid", "CIS-MNT-5"),
        ("/dev/shm", "noexec", "CIS-MNT-6"),
        ("/home", "nodev", "CIS-MNT-7"),
        ("/home", "nosuid", "CIS-MNT-8"),
        ("/var", "nodev", "CIS-MNT-9"),
        ("/var", "nosuid", "CIS-MNT-10"),
        ("/var/tmp", "nodev", "CIS-MNT-11"),
        ("/var/tmp", "nosuid", "CIS-MNT-12"),
        ("/var/tmp", "noexec", "CIS-MNT-13"),
        ("/var/log", "nodev", "CIS-MNT-14"),
        ("/var/log", "nosuid", "CIS-MNT-15"),
        ("/var/log", "noexec", "CIS-MNT-16"),
        ("/var/log/audit", "nodev", "CIS-MNT-17"),
        ("/var/log/audit", "nosuid", "CIS-MNT-18"),
        ("/var/log/audit", "noexec", "CIS-MNT-19"),
    ]
    if s.ge(9):
        mount_checks += [("/boot", "nodev", "CIS-MNT-20"),
                         ("/boot", "nosuid", "CIS-MNT-21")]

    for mp, opt, cid in mount_checks:
        if is_mountpoint(mp):
            if opt in mount_options(mp):
                s.record("PASS", cid, "%s has %s option" % (mp, opt),
                         "MEDIA PROTECTION", "%s is mounted with %s." % (mp, opt), "")
            else:
                s.record("FAIL", cid, "%s missing '%s' mount option" % (mp, opt),
                         "MEDIA PROTECTION", "%s does not have %s." % (mp, opt),
                         "Add %s to %s in /etc/fstab and remount: mount -o remount %s"
                         % (opt, mp, mp))
        else:
            s.record("WARN", cid, "%s is not a separate partition" % mp,
                     "MEDIA PROTECTION",
                     "%s is not mounted as a separate filesystem." % mp,
                     "Consider creating a dedicated partition for %s" % mp)

    # ── Package / Update Management ──────────────────────────────────────────
    s.banner("CIS — Software & Package Management")

    if rpm_installed("gpg-pubkey"):
        s.record("PASS", "CIS-PKG-1", "GPG keys are configured", "SYSTEM INTEGRITY",
                 "GPG public keys installed via RPM database.", "")
    else:
        s.record("FAIL", "CIS-PKG-1", "No GPG keys found in RPM database",
                 "SYSTEM INTEGRITY", "No gpg-pubkey packages found.",
                 "Import your organisation's GPG key: rpm --import <keyfile>")

    repo_conf = ["/etc/yum.conf", "/etc/dnf/dnf.conf", "/etc/yum.repos.d/*.repo"]
    if grep_q(repo_conf, r"^\s*gpgcheck\s*=\s*0"):
        s.record("FAIL", "CIS-PKG-2", "gpgcheck=0 found in at least one repo config",
                 "SYSTEM INTEGRITY", "One or more repos have gpgcheck disabled.",
                 "Set gpgcheck=1 in all /etc/yum.repos.d/*.repo files and /etc/dnf/dnf.conf")
    else:
        s.record("PASS", "CIS-PKG-2", "gpgcheck is not disabled in any repo config",
                 "SYSTEM INTEGRITY",
                 "gpgcheck=0 was not found in yum/dnf configuration.", "")

    if s.ge(9):
        local_gpg = conf_value("/etc/dnf/dnf.conf", "localpkg_gpgcheck") or "N/A"
        if local_gpg == "1":
            s.record("PASS", "CIS-PKG-3", "localpkg_gpgcheck = 1 (RHEL 9+)",
                     "SYSTEM INTEGRITY", "Local package GPG check is enforced.", "")
        else:
            s.record("FAIL", "CIS-PKG-3", "localpkg_gpgcheck not set to 1 (RHEL 9+)",
                     "SYSTEM INTEGRITY",
                     "Local package installs do not require GPG verification.",
                     "Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf")

    # Pending updates — cache-only (-C), never touches the network.
    # Exit codes: 0 = none, 100 = updates available, anything else = no cache.
    pkg_mgr = "yum" if s.le(7) else "dnf"
    if have(pkg_mgr):
        rc, txt = run([pkg_mgr, "check-update", "-C", "--quiet"], timeout=90)
        pending = len([l for l in txt.splitlines()
                       if re.match(r"^[A-Za-z0-9_.+-]+\.[A-Za-z0-9_]+\s+[0-9]", l)])
        if rc == 100:
            s.record("WARN", "CIS-PKG-4",
                     "%d pending package update(s) in local metadata" % pending,
                     "SYSTEM INTEGRITY",
                     "Local repo metadata lists %d newer package(s). Freshness depends "
                     "on when your internal mirror was last synced." % pending,
                     "Sync the internal mirror/media, then: %s update" % pkg_mgr)
        elif rc == 0:
            s.record("PASS", "CIS-PKG-4", "No pending updates in local repo metadata",
                     "SYSTEM INTEGRITY",
                     "No updates listed in cached metadata. See AIR-PATCH-1 for patch "
                     "age — metadata may itself be stale.", "")
        else:
            s.record("SKIP", "CIS-PKG-4", "No usable local repo metadata cache",
                     "SYSTEM INTEGRITY",
                     "%s has no cached metadata (typical on air-gapped hosts). Patch "
                     "currency is assessed by AIR-PATCH-1 instead." % pkg_mgr,
                     "%s makecache  (against your internal mirror or mounted media)" % pkg_mgr)
    else:
        s.record("SKIP", "CIS-PKG-4", "%s not available" % pkg_mgr,
                 "SYSTEM INTEGRITY", "Package manager not found.", "")

    # ── SELinux ──────────────────────────────────────────────────────────────
    s.banner("CIS — SELinux / Mandatory Access Control")

    if rpm_installed("libselinux"):
        s.record("PASS", "CIS-SEL-1", "SELinux (libselinux) is installed",
                 "ACCESS CONTROL", "libselinux package is present.", "")
    else:
        s.record("FAIL", "CIS-SEL-1", "SELinux is not installed", "ACCESS CONTROL",
                 "libselinux package is missing.", "Install: dnf install libselinux")

    grub_cfg = "/boot/grub2/grub.cfg" if s.ge(7) else "/boot/grub/grub.conf"

    if grep_q([grub_cfg, "/etc/default/grub"], r"selinux=0|enforcing=0"):
        s.record("FAIL", "CIS-SEL-2", "SELinux disabled in bootloader configuration",
                 "ACCESS CONTROL", "selinux=0 or enforcing=0 found in bootloader.",
                 "Remove selinux=0/enforcing=0 from %s and /etc/default/grub, then "
                 "regenerate grub config." % grub_cfg)
    else:
        s.record("PASS", "CIS-SEL-2", "SELinux is not disabled in bootloader",
                 "ACCESS CONTROL", "No selinux=0 or enforcing=0 in grub config.", "")

    semode = out(["getenforce"]) or "Unknown"
    if semode == "Enforcing":
        s.record("PASS", "CIS-SEL-3", "SELinux mode = Enforcing", "ACCESS CONTROL",
                 "SELinux is actively enforcing policy.", "")
    elif semode == "Permissive":
        s.record("WARN", "CIS-SEL-3", "SELinux mode = Permissive (should be Enforcing)",
                 "ACCESS CONTROL", "SELinux is permissive — not blocking violations.",
                 "setenforce 1 && sed -i 's/SELINUX=permissive/SELINUX=enforcing/' "
                 "/etc/selinux/config")
    else:
        s.record("FAIL", "CIS-SEL-3", "SELinux mode = %s" % semode, "ACCESS CONTROL",
                 "SELinux is disabled or status unknown.",
                 "Set SELINUX=enforcing in /etc/selinux/config and reboot.")

    sepol = "N/A"
    for line in out(["sestatus"]).splitlines():
        if "Loaded policy" in line:
            sepol = line.split()[-1]
            break
    if sepol in ("targeted", "mls"):
        s.record("PASS", "CIS-SEL-4", "SELinux policy = %s" % sepol, "ACCESS CONTROL",
                 "SELinux policy type is valid.", "")
    else:
        s.record("FAIL", "CIS-SEL-4",
                 "SELinux policy = %s (expected targeted or mls)" % sepol,
                 "ACCESS CONTROL",
                 "SELinux policy type is not set to a recommended value.",
                 "Set SELINUXTYPE=targeted in /etc/selinux/config")

    if s.ge(7):
        for pkg in ("mcstrans", "setroubleshoot"):
            if rpm_installed(pkg):
                s.record("FAIL", "CIS-SEL-5",
                         "Package '%s' is installed (should not be)" % pkg,
                         "CONFIGURATION MANAGEMENT",
                         "%s is installed on this system." % pkg,
                         "Remove: dnf remove %s" % pkg)
            else:
                s.record("PASS", "CIS-SEL-5", "Package '%s' is not installed" % pkg,
                         "CONFIGURATION MANAGEMENT", "%s is not present." % pkg, "")

    # ── Bootloader ───────────────────────────────────────────────────────────
    s.banner("CIS — Bootloader")

    grub_pass_file = "/boot/grub2/user.cfg" if s.ge(7) else ""
    if grub_pass_file and grep_q([grub_pass_file, grub_cfg],
                                 r"^\s*GRUB2_PASSWORD|^\s*password"):
        s.record("PASS", "CIS-BOOT-1", "Bootloader password is set", "ACCESS CONTROL",
                 "GRUB2 password entry found.", "")
    elif s.le(6) and grep_q("/boot/grub/grub.conf", r"^\s*password"):
        s.record("PASS", "CIS-BOOT-1", "Bootloader password is set (GRUB legacy)",
                 "ACCESS CONTROL", "GRUB password entry found in grub.conf.", "")
    else:
        s.record("FAIL", "CIS-BOOT-1", "Bootloader password is NOT set",
                 "ACCESS CONTROL", "No GRUB password found.",
                 "Set bootloader password: grub2-setpassword  (RHEL 7+) or edit "
                 "/boot/grub/grub.conf (RHEL 5/6)")

    grub_perm = stat_mode(grub_cfg)
    if grub_perm in ("600", "400"):
        s.record("PASS", "CIS-BOOT-2", "Bootloader config permissions = %s" % grub_perm,
                 "ACCESS CONTROL", "%s is appropriately restricted." % grub_cfg, "")
    else:
        s.record("FAIL", "CIS-BOOT-2",
                 "Bootloader config permissions = %s (expected 600)" % grub_perm,
                 "ACCESS CONTROL", "%s permissions are not restrictive." % grub_cfg,
                 "chmod og-rwx %s" % grub_cfg)

    if s.ge(9):
        grub_owner = stat_owner_group(grub_cfg)
        if grub_owner == "root:root":
            s.record("PASS", "CIS-BOOT-3", "grub.cfg owned by root:root",
                     "ACCESS CONTROL", "Bootloader config has correct ownership.", "")
        else:
            s.record("FAIL", "CIS-BOOT-3",
                     "grub.cfg ownership = %s (expected root:root)" % grub_owner,
                     "ACCESS CONTROL", "grub.cfg is not owned by root:root.",
                     "chown root:root %s" % grub_cfg)

    # ── Kernel Hardening Parameters ──────────────────────────────────────────
    s.banner("CIS — Kernel Hardening Parameters")

    sysctl_checks = [
        ("fs.suid_dumpable", "0", "CIS-KERN-1"),
        ("kernel.dmesg_restrict", "1", "CIS-KERN-2"),
        ("kernel.kptr_restrict", "1", "CIS-KERN-3"),
        ("kernel.randomize_va_space", "2", "CIS-KERN-4"),
        ("fs.protected_hardlinks", "1", "CIS-KERN-5"),
        ("fs.protected_symlinks", "1", "CIS-KERN-6"),
        ("kernel.yama.ptrace_scope", "1", "CIS-KERN-7"),
    ]
    if s.ge(8):
        sysctl_checks += [("kernel.perf_event_paranoid", "2", "CIS-KERN-8"),
                          ("net.core.bpf_jit_harden", "2", "CIS-KERN-9")]
    if s.ge(9):
        sysctl_checks += [("user.max_user_namespaces", "0", "CIS-KERN-10")]

    for param, expected, cid in sysctl_checks:
        actual = sysctl(param)
        if actual == expected:
            s.record("PASS", cid, "%s = %s" % (param, actual),
                     "CONFIGURATION MANAGEMENT",
                     "Kernel parameter %s is correctly set." % param, "")
        else:
            s.record("FAIL", cid, "%s = %s (expected: %s)" % (param, actual, expected),
                     "CONFIGURATION MANAGEMENT",
                     "Kernel parameter %s is %s, expected %s." % (param, actual, expected),
                     "echo '%s = %s' >> /etc/sysctl.d/99-hardening.conf && sysctl -w %s=%s"
                     % (param, expected, param, expected))

    core_storage = conf_value("/etc/systemd/coredump.conf", "Storage") or "N/A"
    if core_storage == "none":
        s.record("PASS", "CIS-KERN-11", "systemd-coredump Storage = none",
                 "CONFIGURATION MANAGEMENT", "Core dump storage is disabled.", "")
    else:
        s.record("FAIL", "CIS-KERN-11",
                 "systemd-coredump Storage = %s (should be none)" % core_storage,
                 "CONFIGURATION MANAGEMENT", "Core dumps may be stored.",
                 "Set Storage=none and ProcessSizeMax=0 in /etc/systemd/coredump.conf")

    # ── Services ─────────────────────────────────────────────────────────────
    s.banner("CIS — Unnecessary Services")

    svc_checks = [("telnet", "TELNET"), ("rsh", "RSH"), ("rlogin", "RLOGIN"),
                  ("rexec", "REXEC"), ("ypserv", "NIS-server"), ("tftp", "TFTP"),
                  ("xinetd", "XINETD")]
    if s.ge(7):
        svc_checks += [("avahi-daemon", "AVAHI"), ("cups", "CUPS"),
                       ("dhcpd", "DHCP-server"), ("named", "DNS-server"),
                       ("vsftpd", "FTP-server"), ("httpd", "HTTP-server"),
                       ("dovecot", "IMAP/POP3"), ("smb", "SAMBA"),
                       ("squid", "SQUID-proxy"), ("snmpd", "SNMP"),
                       ("nfs-server", "NFS-server"), ("rpcbind", "RPC-bind"),
                       ("autofs", "AUTOFS"), ("kdump", "KDUMP")]
    if s.ge(9):
        svc_checks += [("gssproxy", "GSSPROXY"), ("iprutils", "IPRUTILS"),
                       ("tuned", "TUNED"), ("quagga", "QUAGGA")]

    for svc, label in svc_checks:
        if svc_enabled(svc):
            s.record("FAIL", "CIS-SVC", "Service %s (%s) is enabled" % (svc, label),
                     "CONFIGURATION MANAGEMENT",
                     "%s is enabled and may be running." % svc,
                     "systemctl --now disable %s" % svc)
        else:
            s.record("PASS", "CIS-SVC", "Service %s (%s) is not enabled" % (svc, label),
                     "CONFIGURATION MANAGEMENT", "%s is not enabled." % svc, "")

    if s.ge(8):
        if svc_enabled("debug-shell"):
            s.record("FAIL", "CIS-SVC-DBG", "debug-shell.service is enabled",
                     "CONFIGURATION MANAGEMENT",
                     "debug-shell provides unauthenticated root access.",
                     "systemctl disable debug-shell.service")
        else:
            s.record("PASS", "CIS-SVC-DBG", "debug-shell.service is not enabled",
                     "CONFIGURATION MANAGEMENT", "Debug shell is disabled.", "")

    # ── Network Hardening ────────────────────────────────────────────────────
    s.banner("CIS — Network Kernel Parameters")

    net_checks = [
        ("net.ipv4.ip_forward", "0", "CIS-NET-1"),
        ("net.ipv4.conf.all.send_redirects", "0", "CIS-NET-2"),
        ("net.ipv4.conf.default.send_redirects", "0", "CIS-NET-3"),
        ("net.ipv4.conf.all.accept_source_route", "0", "CIS-NET-4"),
        ("net.ipv4.conf.default.accept_source_route", "0", "CIS-NET-5"),
        ("net.ipv4.conf.all.accept_redirects", "0", "CIS-NET-6"),
        ("net.ipv4.conf.default.accept_redirects", "0", "CIS-NET-7"),
        ("net.ipv4.conf.all.secure_redirects", "0", "CIS-NET-8"),
        ("net.ipv4.conf.default.secure_redirects", "0", "CIS-NET-9"),
        ("net.ipv4.conf.all.log_martians", "1", "CIS-NET-10"),
        ("net.ipv4.conf.default.log_martians", "1", "CIS-NET-11"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "CIS-NET-12"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "CIS-NET-13"),
        ("net.ipv4.conf.all.rp_filter", "1", "CIS-NET-14"),
        ("net.ipv4.conf.default.rp_filter", "1", "CIS-NET-15"),
        ("net.ipv4.tcp_syncookies", "1", "CIS-NET-16"),
        ("net.ipv6.conf.all.accept_ra", "0", "CIS-NET-17"),
        ("net.ipv6.conf.default.accept_ra", "0", "CIS-NET-18"),
        ("net.ipv6.conf.all.accept_redirects", "0", "CIS-NET-19"),
        ("net.ipv6.conf.all.accept_source_route", "0", "CIS-NET-20"),
    ]
    if s.ge(9):
        net_checks += [("net.core.bpf_jit_harden", "2", "CIS-NET-21"),
                       ("net.ipv4.conf.default.rp_filter", "1", "CIS-NET-22")]

    for param, expected, cid in net_checks:
        actual = sysctl(param)
        if actual == expected:
            s.record("PASS", cid, "%s = %s" % (param, actual),
                     "NETWORK CONFIGURATION",
                     "Network parameter %s is correct." % param, "")
        else:
            s.record("FAIL", cid, "%s = %s (expected: %s)" % (param, actual, expected),
                     "NETWORK CONFIGURATION",
                     "Network parameter %s is %s, expected %s." % (param, actual, expected),
                     "echo '%s = %s' >> /etc/sysctl.d/99-network.conf && sysctl -w %s=%s"
                     % (param, expected, param, expected))

    fw_active = any(svc_active(fw) for fw in ("firewalld", "nftables", "iptables"))
    if fw_active:
        s.record("PASS", "CIS-FW-1", "A firewall service is active",
                 "NETWORK CONFIGURATION", "firewalld/nftables/iptables is running.", "")
    else:
        s.record("FAIL", "CIS-FW-1", "No firewall service is active",
                 "NETWORK CONFIGURATION", "No active firewall detected.",
                 "systemctl --now enable firewalld")

    # ── Logging & Auditing ───────────────────────────────────────────────────
    s.banner("CIS — Logging & Auditing")

    if svc_active("auditd"):
        s.record("PASS", "CIS-AUD-1", "auditd is active", "AUDIT AND ACCOUNTABILITY",
                 "Audit daemon is running.", "")
    else:
        s.record("FAIL", "CIS-AUD-1", "auditd is not active",
                 "AUDIT AND ACCOUNTABILITY", "Audit daemon is not running.",
                 "systemctl --now enable auditd")

    auditd_conf = "/etc/audit/auditd.conf"
    if os.path.isfile(auditd_conf):
        max_action = conf_value(auditd_conf, "max_log_file_action") or ""
        if re.search(r"keep_logs|rotate", max_action, re.IGNORECASE):
            s.record("PASS", "CIS-AUD-2", "max_log_file_action = %s" % max_action,
                     "AUDIT AND ACCOUNTABILITY", "Audit log rotation is configured.", "")
        else:
            s.record("FAIL", "CIS-AUD-2", "max_log_file_action = %s" % max_action,
                     "AUDIT AND ACCOUNTABILITY",
                     "Audit log rotation action is not set correctly.",
                     "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf")

        sla = conf_value(auditd_conf, "space_left_action") or ""
        if re.search(r"email|exec|syslog|rotate", sla, re.IGNORECASE):
            s.record("PASS", "CIS-AUD-3", "space_left_action = %s" % sla,
                     "AUDIT AND ACCOUNTABILITY",
                     "Audit space_left_action notifies administrators.", "")
        else:
            s.record("FAIL", "CIS-AUD-3",
                     "space_left_action = %s (expected: email/syslog)" % sla,
                     "AUDIT AND ACCOUNTABILITY",
                     "space_left_action is not configured to alert.",
                     "Set space_left_action = email in /etc/audit/auditd.conf")

    rules_file = ""
    for cand in ("/etc/audit/rules.d/audit.rules", "/etc/audit/audit.rules"):
        if os.path.isfile(cand):
            rules_file = cand
            break

    if rules_file:
        audit_keys = ["time-change", "identity", "system-locale", "MAC-policy",
                      "logins", "session", "perm_mod"]
        if s.ge(8):
            audit_keys += ["privileged-commands", "module-load"]
        live_rules = out(["auditctl", "-l"]) if have("auditctl") else ""
        for key in audit_keys:
            needle = "-k " + key
            if grep_q(rules_file, re.escape(needle)) or needle in live_rules:
                s.record("PASS", "CIS-AUD-RULE",
                         "Audit rule key '%s' is configured" % key,
                         "AUDIT AND ACCOUNTABILITY",
                         "Audit rule for %s found." % key, "")
            else:
                s.record("FAIL", "CIS-AUD-RULE", "Audit rule key '%s' is missing" % key,
                         "AUDIT AND ACCOUNTABILITY",
                         "No audit rule with key '%s' found." % key,
                         "Add appropriate audit rules with -k %s to %s" % (key, rules_file))
    else:
        s.record("WARN", "CIS-AUD-4", "No audit rules file found",
                 "AUDIT AND ACCOUNTABILITY",
                 "Cannot locate /etc/audit/rules.d/audit.rules.",
                 "Create and configure /etc/audit/rules.d/audit.rules")

    if any(svc_active(x) for x in ("rsyslog", "syslog", "syslog-ng")):
        s.record("PASS", "CIS-LOG-1", "A syslog service is active",
                 "AUDIT AND ACCOUNTABILITY", "Logging daemon is running.", "")
    else:
        s.record("FAIL", "CIS-LOG-1", "No syslog service is active",
                 "AUDIT AND ACCOUNTABILITY", "rsyslog/syslog/syslog-ng is not running.",
                 "systemctl --now enable rsyslog")

    if s.ge(7):
        if svc_active("systemd-journald"):
            s.record("PASS", "CIS-LOG-2", "systemd-journald is active",
                     "AUDIT AND ACCOUNTABILITY", "Journal daemon is running.", "")
        else:
            s.record("FAIL", "CIS-LOG-2", "systemd-journald is not active",
                     "AUDIT AND ACCOUNTABILITY", "systemd journal is not running.",
                     "systemctl --now enable systemd-journald")

    # ── SSH Configuration ────────────────────────────────────────────────────
    s.banner("CIS — SSH Server Configuration")

    ssh_conf = "/etc/ssh/sshd_config"
    if os.path.isfile(ssh_conf):
        max_auth = 4
        ssh_checks = [
            ("PermitRootLogin", "no", "CIS-SSH-1"),
            ("PermitEmptyPasswords", "no", "CIS-SSH-2"),
            ("IgnoreRhosts", "yes", "CIS-SSH-3"),
            ("HostbasedAuthentication", "no", "CIS-SSH-4"),
            ("PermitUserEnvironment", "no", "CIS-SSH-5"),
            ("LogLevel", "INFO", "CIS-SSH-6"),
            ("X11Forwarding", "no", "CIS-SSH-7"),
            ("ClientAliveInterval", "300", "CIS-SSH-8"),
            ("ClientAliveCountMax", "0", "CIS-SSH-9"),
            ("Banner", "/etc/issue.net", "CIS-SSH-10"),
        ]
        if s.ge(8):
            ssh_checks += [("GSSAPIAuthentication", "no", "CIS-SSH-11"),
                           ("KerberosAuthentication", "no", "CIS-SSH-12"),
                           ("StrictModes", "yes", "CIS-SSH-13"),
                           ("Compression", "no", "CIS-SSH-14")]
        if s.ge(9):
            ssh_checks += [("UsePAM", "yes", "CIS-SSH-15"),
                           ("PrintLastLog", "yes", "CIS-SSH-16"),
                           ("X11UseLocalhost", "yes", "CIS-SSH-17")]

        eff = sshd_effective()
        for directive, expected, cid in ssh_checks:
            actual = eff.get(directive.lower(), "")
            if actual:
                actual = actual.split()[0].lower() if actual.split() else ""
            if not actual:
                raw = conf_value(ssh_conf, directive, sep=None, first=True)
                actual = raw.lower() if raw else "N/A"
            exp_lc = expected.lower()
            if actual == exp_lc:
                s.record("PASS", cid, "SSH %s = %s" % (directive, actual),
                         "ACCESS CONTROL",
                         "SSH directive %s is correctly set." % directive, "")
            else:
                s.record("FAIL", cid,
                         "SSH %s = %s (expected: %s)"
                         % (directive, actual if actual else "not set", expected),
                         "ACCESS CONTROL",
                         "SSH directive %s is not set to recommended value." % directive,
                         "Set '%s %s' in %s && systemctl restart sshd"
                         % (directive, expected, ssh_conf))

        mat = eff.get("maxauthtries", "")
        if mat:
            mat = mat.split()[0]
        if not mat:
            mat = conf_value(ssh_conf, "MaxAuthTries", sep=None, first=True) or "N/A"
        mat_int = as_int(mat)
        if mat_int is not None and mat_int <= max_auth:
            s.record("PASS", "CIS-SSH-MAT",
                     "SSH MaxAuthTries = %s (≤%d)" % (mat, max_auth),
                     "ACCESS CONTROL", "MaxAuthTries is within acceptable range.", "")
        else:
            s.record("FAIL", "CIS-SSH-MAT",
                     "SSH MaxAuthTries = %s (expected ≤%d)" % (mat, max_auth),
                     "ACCESS CONTROL", "MaxAuthTries is too high or not set.",
                     "Set 'MaxAuthTries %d' in %s && systemctl restart sshd"
                     % (max_auth, ssh_conf))
    else:
        s.record("SKIP", "CIS-SSH", "sshd_config not found — SSH checks skipped",
                 "ACCESS CONTROL", "/etc/ssh/sshd_config does not exist.", "")

    # ── Password & Account Policies ──────────────────────────────────────────
    s.banner("CIS — Password & Account Policies")

    login_defs = "/etc/login.defs"
    if os.path.isfile(login_defs):
        pass_max_expect = 60 if s.ge(9) else 365
        pw_checks = [
            ("PASS_MAX_DAYS", pass_max_expect, "max", "CIS-PW-1"),
            ("PASS_MIN_DAYS", 1, "min", "CIS-PW-2"),
            ("PASS_MIN_LEN", 14, "min", "CIS-PW-3"),
            ("PASS_WARN_AGE", 7, "min", "CIS-PW-4"),
        ]
        for param, expected, comp, cid in pw_checks:
            raw = conf_value(login_defs, param, sep=None)
            actual = raw if raw else "N/A"
            val = as_int(actual)
            good = False
            if val is not None:
                good = (val <= expected) if comp == "max" else (val >= expected)
            if good:
                s.record("PASS", cid,
                         "%s = %s (meets %s of %s)" % (param, actual, comp, expected),
                         "ACCESS CONTROL", "%s meets the required threshold." % param, "")
            else:
                s.record("FAIL", cid,
                         "%s = %s (expected %s: %s)" % (param, actual, comp, expected),
                         "ACCESS CONTROL",
                         "%s does not meet the required threshold." % param,
                         "Update %s in %s" % (param, login_defs))

        encrypt = conf_value(login_defs, "ENCRYPT_METHOD", sep=None) or "N/A"
        if re.search(r"SHA512|SHA256", encrypt, re.IGNORECASE):
            s.record("PASS", "CIS-PW-5", "ENCRYPT_METHOD = %s" % encrypt,
                     "SYSTEM INTEGRITY", "FIPS-approved password hashing in use.", "")
        else:
            s.record("FAIL", "CIS-PW-5",
                     "ENCRYPT_METHOD = %s (expected SHA512)" % encrypt,
                     "SYSTEM INTEGRITY",
                     "Password hashing algorithm may not be FIPS-approved.",
                     "Set 'ENCRYPT_METHOD SHA512' in %s" % login_defs)

    pwq_conf = "/etc/security/pwquality.conf"
    if s.ge(7) and os.path.isfile(pwq_conf):
        for opt in ("minlen", "dcredit", "ucredit", "lcredit", "ocredit"):
            raw = conf_value(pwq_conf, opt)
            val = raw if raw else "N/A"
            num = as_int(val)
            if opt == "minlen":
                if num is not None and num >= 14:
                    s.record("PASS", "CIS-PW-PQ", "pwquality %s = %s (≥14)" % (opt, val),
                             "ACCESS CONTROL", "Password minimum length is configured.", "")
                else:
                    s.record("FAIL", "CIS-PW-PQ",
                             "pwquality %s = %s (expected ≥14)" % (opt, val),
                             "ACCESS CONTROL", "Password minimum length is insufficient.",
                             "Set 'minlen = 14' in /etc/security/pwquality.conf")
            else:
                if num is not None and num < 0:
                    s.record("PASS", "CIS-PW-PQ",
                             "pwquality %s = %s (complexity enforced)" % (opt, val),
                             "ACCESS CONTROL",
                             "Password complexity for %s is required." % opt, "")
                else:
                    s.record("FAIL", "CIS-PW-PQ",
                             "pwquality %s = %s (expected < 0 e.g. -1)" % (opt, val),
                             "ACCESS CONTROL",
                             "Password complexity %s is not enforced." % opt,
                             "Set '%s = -1' in /etc/security/pwquality.conf" % opt)

    if s.ge(8):
        fconf = "/etc/security/faillock.conf"
        if os.path.isfile(fconf):
            raw = conf_value(fconf, "deny")
            deny = raw if raw else "N/A"
            dnum = as_int(deny)
            if dnum is not None and 0 < dnum <= 3:
                s.record("PASS", "CIS-PW-FL1", "faillock deny = %s (≤3)" % deny,
                         "ACCESS CONTROL", "Account lockout threshold is ≤3.", "")
            else:
                s.record("FAIL", "CIS-PW-FL1",
                         "faillock deny = %s (expected ≤3)" % deny, "ACCESS CONTROL",
                         "Account lockout threshold is not configured correctly.",
                         "Set 'deny = 3' in /etc/security/faillock.conf")

            raw = conf_value(fconf, "unlock_time")
            utime = raw if raw else "N/A"
            unum = as_int(utime)
            if utime == "0" or (unum is not None and unum >= 900):
                s.record("PASS", "CIS-PW-FL2",
                         "faillock unlock_time = %s (0 or ≥900s)" % utime,
                         "ACCESS CONTROL", "Account unlock requires admin or ≥15 min.", "")
            else:
                s.record("FAIL", "CIS-PW-FL2",
                         "faillock unlock_time = %s (expected 0 or ≥900)" % utime,
                         "ACCESS CONTROL", "Account unlock time is too short.",
                         "Set 'unlock_time = 0' in /etc/security/faillock.conf")
        else:
            s.record("FAIL", "CIS-PW-FL1", "faillock.conf not found", "ACCESS CONTROL",
                     "/etc/security/faillock.conf is missing.",
                     "Configure pam_faillock and create /etc/security/faillock.conf")
    elif s.le(7):
        if grep_rq("/etc/pam.d", r"pam_tally2"):
            s.record("PASS", "CIS-PW-FL1", "pam_tally2 is configured (RHEL ≤7)",
                     "ACCESS CONTROL",
                     "Account lockout via pam_tally2 is configured.", "")
        else:
            s.record("FAIL", "CIS-PW-FL1",
                     "pam_tally2 not configured in /etc/pam.d/ (RHEL ≤7)",
                     "ACCESS CONTROL", "No account lockout mechanism found.",
                     "Configure pam_tally2 in /etc/pam.d/system-auth")

    umask_paths = ["/etc/profile", "/etc/bashrc", "/etc/profile.d/*.sh"]
    umask_vals = sorted(set(l.split()[1] for l in grep_lines(umask_paths, r"^\s*umask\s+")
                            if len(l.split()) > 1))
    umask_val = umask_vals[0] if umask_vals else "N/A"
    if umask_val in ("027", "077"):
        s.record("PASS", "CIS-PW-UM", "Default umask = %s" % umask_val,
                 "ACCESS CONTROL", "Default umask is restrictive.", "")
    else:
        s.record("FAIL", "CIS-PW-UM",
                 "Default umask = %s (expected 027 or 077)" % umask_val,
                 "ACCESS CONTROL",
                 "Default umask may allow excessive file permissions.",
                 "Set 'umask 027' in /etc/profile and /etc/bashrc")

    tmout = "N/A"
    for line in grep_lines(umask_paths, r"^\s*(readonly\s+)?TMOUT"):
        nums = re.findall(r"[0-9]+", line)
        if nums:
            tmout = nums[0]
            break
    tnum = as_int(tmout)
    if tnum is not None and tnum <= 600:
        s.record("PASS", "CIS-PW-TO", "TMOUT = %s seconds (≤600)" % tmout,
                 "ACCESS CONTROL", "Idle session timeout is configured.", "")
    else:
        s.record("FAIL", "CIS-PW-TO", "TMOUT = %s (expected ≤600)" % tmout,
                 "ACCESS CONTROL",
                 "Idle session timeout is not configured or too long.",
                 "Add 'readonly TMOUT=600' to /etc/profile.d/tmout.sh")

    # ── System File Permissions ──────────────────────────────────────────────
    s.banner("CIS — Critical File Permissions & Ownership")

    file_checks = [
        ("/etc/passwd", "644", "root", "root", "CIS-FILE-1"),
        ("/etc/group", "644", "root", "root", "CIS-FILE-2"),
        ("/etc/shadow", "000", "root", "root", "CIS-FILE-3"),
        ("/etc/gshadow", "000", "root", "root", "CIS-FILE-4"),
        ("/etc/passwd-", "644", "root", "root", "CIS-FILE-5"),
        ("/etc/group-", "644", "root", "root", "CIS-FILE-6"),
        ("/etc/shadow-", "000", "root", "root", "CIS-FILE-7"),
        ("/etc/crontab", "600", "root", "root", "CIS-FILE-8"),
    ]
    for filepath, perm, owner, group, cid in file_checks:
        if not os.path.isfile(filepath):
            s.record("SKIP", cid, "%s does not exist — skipping" % filepath,
                     "CONFIGURATION MANAGEMENT",
                     "File %s is not present on this system." % filepath, "")
            continue
        actual_perm = stat_mode(filepath)
        actual_owner = stat_owner(filepath)
        actual_group = stat_group(filepath)
        expected_perm = perm
        if "shadow" in filepath and s.le(8):
            expected_perm = "640"
        if (actual_perm == expected_perm and actual_owner == owner
                and actual_group == group):
            s.record("PASS", cid,
                     "%s — perm:%s owner:%s:%s"
                     % (filepath, actual_perm, actual_owner, actual_group),
                     "CONFIGURATION MANAGEMENT",
                     "%s has correct permissions and ownership." % filepath, "")
        else:
            s.record("FAIL", cid,
                     "%s — got %s/%s:%s (expected %s/%s:%s)"
                     % (filepath, actual_perm, actual_owner, actual_group,
                        expected_perm, owner, group),
                     "CONFIGURATION MANAGEMENT",
                     "File %s permissions or ownership is incorrect." % filepath,
                     "chmod %s %s && chown %s:%s %s"
                     % (expected_perm, filepath, owner, group, filepath))

    # ── Account Integrity ────────────────────────────────────────────────────
    s.banner("CIS — Account Integrity")

    pw_rows = passwd_entries()
    uid0_non_root = len([r for r in pw_rows if r["uid"] == "0" and r["user"] != "root"])
    if uid0_non_root == 0:
        s.record("PASS", "CIS-ACC-1", "Only root has UID 0", "ACCESS CONTROL",
                 "No other accounts have UID 0.", "")
    else:
        s.record("FAIL", "CIS-ACC-1",
                 "%d non-root account(s) have UID 0" % uid0_non_root,
                 "ACCESS CONTROL", "Accounts other than root have UID 0.",
                 "Remove or change UID for non-root accounts with UID 0.")

    dup_uid = _count_duplicates([r["uid"] for r in pw_rows])
    if dup_uid == 0:
        s.record("PASS", "CIS-ACC-2", "No duplicate UIDs in /etc/passwd",
                 "ACCESS CONTROL", "All user UIDs are unique.", "")
    else:
        s.record("FAIL", "CIS-ACC-2", "%d duplicate UID(s) found" % dup_uid,
                 "ACCESS CONTROL", "Duplicate UIDs exist in /etc/passwd.",
                 "Investigate and resolve: awk -F: '{print $3}' /etc/passwd | sort | uniq -d")

    dup_gid = _count_duplicates([r["gid"] for r in group_entries()])
    if dup_gid == 0:
        s.record("PASS", "CIS-ACC-3", "No duplicate GIDs in /etc/group",
                 "ACCESS CONTROL", "All group GIDs are unique.", "")
    else:
        s.record("FAIL", "CIS-ACC-3", "%d duplicate GID(s) found" % dup_gid,
                 "ACCESS CONTROL", "Duplicate GIDs exist in /etc/group.",
                 "Investigate and resolve: awk -F: '{print $3}' /etc/group | sort | uniq -d")

    if s.needs_root("CIS-ACC-4", "Check for accounts with empty passwords",
                    "ACCESS CONTROL"):
        empty_pw = len([r for r in shadow_entries() if r["pw"] == ""])
        if empty_pw == 0:
            s.record("PASS", "CIS-ACC-4", "No accounts with empty passwords",
                     "ACCESS CONTROL", "All shadow entries have a password or lock.", "")
        else:
            s.record("FAIL", "CIS-ACC-4",
                     "%d account(s) have empty passwords" % empty_pw,
                     "ACCESS CONTROL", "Empty password fields found in /etc/shadow.",
                     "Lock or set passwords: passwd -l <user>")

    raw = conf_value("/etc/default/useradd", "INACTIVE")
    inactive = raw if raw else "N/A"
    max_inactive = 35
    inum = as_int(inactive)
    if inum is not None and 0 < inum <= max_inactive:
        s.record("PASS", "CIS-ACC-5",
                 "Inactive account lock = %s days (≤%d)" % (inactive, max_inactive),
                 "ACCESS CONTROL", "Inactive account lockout is configured.", "")
    else:
        s.record("FAIL", "CIS-ACC-5",
                 "Inactive account lock = %s (expected 1–%d)" % (inactive, max_inactive),
                 "ACCESS CONTROL",
                 "Inactive account lockout is not properly configured.",
                 "Set 'INACTIVE=%d' in /etc/default/useradd && useradd -D -f %d"
                 % (max_inactive, max_inactive))

    s.banner("CIS — Time Synchronization")
    if any(svc_active(x) for x in ("chronyd", "ntpd", "timesyncd")):
        s.record("PASS", "CIS-TIME-1", "Time synchronization service is active",
                 "AUDIT AND ACCOUNTABILITY", "chronyd/ntpd/timesyncd is running.", "")
    else:
        s.record("FAIL", "CIS-TIME-1", "No time sync service is active",
                 "AUDIT AND ACCOUNTABILITY", "Time synchronization is not running.",
                 "systemctl --now enable chronyd")


def _count_duplicates(values):
    """Number of distinct values appearing more than once. Mirrors `uniq -d | wc -l`."""
    seen = {}
    for v in values:
        seen[v] = seen.get(v, 0) + 1
    return len([v for v, n in seen.items() if n > 1])


# =============================================================================
#  ███████╗████████╗██╗ ██████╗
#  ██╔════╝╚══██╔══╝██║██╔════╝
#  ███████╗   ██║   ██║██║  ███╗
#  ╚════██║   ██║   ██║██║   ██║
#  ███████║   ██║   ██║╚██████╔╝
#  ╚══════╝   ╚═╝   ╚═╝ ╚═════╝
#  DISA STIG CHECKS (RHEL 6–9 version-aware)
# =============================================================================

def run_stig_checks(s):
    s.banner("STIG — High Severity (CAT I) Checks")

    if re.search(r"release (6|7|8|9|10)\.", s.rhel_full):
        s.record("PASS", "STIG-OS-1",
                 "OS is a vendor-supported release: %s" % s.rhel_full,
                 "SYSTEM INTEGRITY", "Detected OS version is supported.", "")
    else:
        s.record("WARN", "STIG-OS-1", "OS support status could not be confirmed",
                 "SYSTEM INTEGRITY",
                 "Verify %s has active vendor support." % s.rhel_full,
                 "Check: https://access.redhat.com/product-life-cycles")

    fips_en = read_value("/proc/sys/crypto/fips_enabled", "0")
    if fips_en == "1":
        s.record("PASS", "STIG-FIPS-1", "FIPS 140-2/3 mode is enabled",
                 "SYSTEM INTEGRITY", "FIPS mode is active (fips_enabled=1).", "")
    else:
        s.record("FAIL", "STIG-FIPS-1",
                 "FIPS mode is NOT enabled (fips_enabled=%s)" % fips_en,
                 "SYSTEM INTEGRITY", "FIPS-validated cryptography is not enforced.",
                 "fips-mode-setup --enable && reboot")

    if s.ge(9):
        cp = out(["update-crypto-policies", "--show"]) or "N/A"
        if cp == "FIPS":
            s.record("PASS", "STIG-CRYPTO-1", "System crypto policy = FIPS",
                     "SYSTEM INTEGRITY", "System-wide crypto policy is set to FIPS.", "")
        else:
            s.record("FAIL", "STIG-CRYPTO-1",
                     "System crypto policy = %s (expected FIPS)" % cp,
                     "SYSTEM INTEGRITY", "Crypto policy is not FIPS.",
                     "update-crypto-policies --set FIPS && reboot")

    luks = False
    if have("lsblk") and "crypt" in out(["lsblk", "-o", "TYPE"]):
        luks = True
    if not luks and have("blkid") and re.search(r"luks", out(["blkid"]), re.IGNORECASE):
        luks = True
    if luks:
        s.record("PASS", "STIG-LUKS-1", "Disk encryption (LUKS) detected",
                 "MEDIA PROTECTION", "At least one LUKS encrypted partition found.", "")
    else:
        s.record("WARN", "STIG-LUKS-1", "No LUKS disk encryption detected",
                 "MEDIA PROTECTION",
                 "No LUKS partitions found — data-at-rest may not be protected.",
                 "Implement LUKS encryption on partitions holding sensitive data.")

    if find_paths("/etc", name="shosts.equiv"):
        s.record("FAIL", "STIG-RHOST-1", "shosts.equiv files found", "ACCESS CONTROL",
                 "Host-based auth files exist on this system.",
                 "find / -name shosts.equiv -delete")
    else:
        s.record("PASS", "STIG-RHOST-1", "No shosts.equiv files found",
                 "ACCESS CONTROL", "No shosts.equiv found.", "")

    if find_paths(["/root", "/home"], name=".shosts"):
        s.record("FAIL", "STIG-RHOST-2", ".shosts files found in home directories",
                 "ACCESS CONTROL", ".shosts files present — host-based auth risk.",
                 "find /root /home -name .shosts -delete")
    else:
        s.record("PASS", "STIG-RHOST-2", "No .shosts files found", "ACCESS CONTROL",
                 "No .shosts files detected.", "")

    dangerous = ["telnet-server", "rsh-server", "tftp-server", "vsftpd", "sendmail"]
    if s.ge(8):
        dangerous += ["abrt", "abrt-cli", "libreport"]
    if s.ge(9):
        dangerous += ["ypserv", "nfs-utils", "gssproxy", "iprutils", "tuned", "quagga"]
    for pkg in dangerous:
        if rpm_installed(pkg):
            s.record("FAIL", "STIG-PKG-" + pkg,
                     "Dangerous package '%s' is installed" % pkg,
                     "CONFIGURATION MANAGEMENT",
                     "%s should not be installed on this system." % pkg,
                     "dnf remove %s" % pkg)
        else:
            s.record("PASS", "STIG-PKG-" + pkg, "Package '%s' is not installed" % pkg,
                     "CONFIGURATION MANAGEMENT", "%s is not present." % pkg, "")

    if s.ge(9):
        required = ["openssl-pkcs11", "gnutls-utils", "nss-tools", "rng-tools",
                    "s-nail", "libreswan", "usbguard"]
        for pkg in required:
            if rpm_installed(pkg):
                s.record("PASS", "STIG-REQPKG-" + pkg,
                         "Required package '%s' is installed" % pkg,
                         "SYSTEM INTEGRITY",
                         "%s is present as required by STIG." % pkg, "")
            else:
                s.record("FAIL", "STIG-REQPKG-" + pkg,
                         "Required package '%s' is NOT installed" % pkg,
                         "SYSTEM INTEGRITY",
                         "%s is required by RHEL 9 STIG but missing." % pkg,
                         "dnf install %s" % pkg)

    cad = out(["systemctl", "status", "ctrl-alt-del.target"], timeout=20)
    if "masked" in cad:
        s.record("PASS", "STIG-CAD-1", "Ctrl-Alt-Delete is masked",
                 "CONFIGURATION MANAGEMENT", "ctrl-alt-del.target is masked.", "")
    else:
        s.record("FAIL", "STIG-CAD-1", "Ctrl-Alt-Delete is NOT masked",
                 "CONFIGURATION MANAGEMENT", "ctrl-alt-del.target is not masked.",
                 "systemctl mask ctrl-alt-del.target")

    s.banner("STIG — Medium Severity (CAT II) Key Checks")

    banner_file = sshd_effective().get("banner", "").strip()
    if banner_file:
        banner_file = banner_file.split()[0]
    if not banner_file:
        banner_file = conf_value("/etc/ssh/sshd_config", "Banner", sep=None,
                                  first=True) or ""
    if not banner_file or banner_file == "none":
        banner_file = "none"

    banner_exists = banner_file != "none" and os.path.isfile(banner_file)
    if banner_exists and grep_q(banner_file,
                                r"authorized|consent|monitored|government",
                                ignorecase=True):
        s.record("PASS", "STIG-BNR-1", "SSH banner configured with consent language",
                 "ACCESS CONTROL",
                 "SSH banner at %s contains required text." % banner_file, "")
    elif banner_exists:
        s.record("WARN", "STIG-BNR-1",
                 "SSH banner exists but may lack required consent text",
                 "ACCESS CONTROL",
                 "Banner at %s may not contain required legal text." % banner_file,
                 "Add mandatory consent/authorized-use text to %s" % banner_file)
    else:
        s.record("FAIL", "STIG-BNR-1", "No SSH banner configured", "ACCESS CONTROL",
                 "No SSH login banner found.",
                 "Create /etc/issue.net with consent text and set "
                 "'Banner /etc/issue.net' in sshd_config")

    if grep_rq(["/etc/sudoers", "/etc/sudoers.d"], r"^\s*[^#].*NOPASSWD"):
        s.record("FAIL", "STIG-SUDO-1", "NOPASSWD found in sudoers configuration",
                 "ACCESS CONTROL",
                 "Some sudo rules allow passwordless privilege escalation.",
                 "Remove NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/")
    else:
        s.record("PASS", "STIG-SUDO-1", "No NOPASSWD entries in sudoers",
                 "ACCESS CONTROL",
                 "All sudo rules require password authentication.", "")

    if s.ge(9):
        if rpm_installed("usbguard") and svc_enabled("usbguard"):
            s.record("PASS", "STIG-USB-1", "USBGuard is installed and enabled",
                     "MEDIA PROTECTION", "USB device authorization policy is active.", "")
        else:
            s.record("FAIL", "STIG-USB-1",
                     "USBGuard is not installed or not enabled", "MEDIA PROTECTION",
                     "USB peripherals are not being controlled by USBGuard.",
                     "dnf install usbguard && systemctl --now enable usbguard")

    bad_pub = len(find_paths("/etc/ssh", name="*.pub", perm_exact_not=(0o644,)))
    if bad_pub == 0:
        s.record("PASS", "STIG-SSH-KEYS-1", "SSH public host keys have mode 0644",
                 "ACCESS CONTROL", "All /etc/ssh/*.pub files are mode 644.", "")
    else:
        s.record("FAIL", "STIG-SSH-KEYS-1",
                 "%d SSH public key file(s) with wrong permissions" % bad_pub,
                 "ACCESS CONTROL", "SSH public key file permissions are not 644.",
                 "chmod 644 /etc/ssh/*.pub")

    bad_priv = len(find_paths("/etc/ssh", name="ssh_host_*_key", not_name="*.pub",
                              perm_exact_not=(0o640, 0o600)))
    if bad_priv == 0:
        s.record("PASS", "STIG-SSH-KEYS-2",
                 "SSH private host keys have mode 640 or 600", "ACCESS CONTROL",
                 "All SSH private host keys have correct permissions.", "")
    else:
        s.record("FAIL", "STIG-SSH-KEYS-2",
                 "%d SSH private key file(s) with wrong permissions" % bad_priv,
                 "ACCESS CONTROL", "SSH private key permissions are too permissive.",
                 "chmod 600 /etc/ssh/ssh_host_*_key")

    if s.ge(9):
        sshd_owner = stat_owner_group("/etc/ssh/sshd_config")
        if sshd_owner == "root:root":
            s.record("PASS", "STIG-SSH-CFG-1", "sshd_config owned by root:root",
                     "ACCESS CONTROL", "SSH server config has correct ownership.", "")
        else:
            s.record("FAIL", "STIG-SSH-CFG-1",
                     "sshd_config ownership = %s (expected root:root)" % sshd_owner,
                     "ACCESS CONTROL", "sshd_config is not owned by root:root.",
                     "chown root:root /etc/ssh/sshd_config && chmod 600 "
                     "/etc/ssh/sshd_config")

    if s.needs_root("STIG-AUD-LOG", "Check audit log file permissions",
                    "AUDIT AND ACCOUNTABILITY"):
        log_file = conf_value("/etc/audit/auditd.conf", "log_file")
        audit_dir = os.path.dirname(log_file) if log_file else "/var/log/audit"
        if os.path.isdir(audit_dir):
            bad_audit = len(find_paths(audit_dir, type_="f", perm_exact_not=(0o600,)))
            if bad_audit == 0:
                s.record("PASS", "STIG-AUD-LOG", "Audit log files have mode 0600",
                         "AUDIT AND ACCOUNTABILITY",
                         "All audit logs in %s are mode 600." % audit_dir, "")
            else:
                s.record("FAIL", "STIG-AUD-LOG",
                         "%d audit log file(s) with incorrect permissions" % bad_audit,
                         "AUDIT AND ACCOUNTABILITY",
                         "Audit logs in %s are not mode 600." % audit_dir,
                         "chmod 600 %s/*.log" % audit_dir)

    if s.ge(8):
        raw = conf_value("/etc/login.defs", "PASS_MAX_DAYS", sep=None)
        pass_max = raw if raw else "N/A"
        pnum = as_int(pass_max)
        if pnum is not None and pnum <= 60:
            s.record("PASS", "STIG-PW-AGE", "PASS_MAX_DAYS = %s (≤60)" % pass_max,
                     "ACCESS CONTROL", "Password max age meets STIG requirement.", "")
        else:
            s.record("FAIL", "STIG-PW-AGE",
                     "PASS_MAX_DAYS = %s (STIG requires ≤60)" % pass_max,
                     "ACCESS CONTROL", "Password maximum age exceeds 60 days.",
                     "Set 'PASS_MAX_DAYS 60' in /etc/login.defs")

        raw = conf_value("/etc/security/pwquality.conf", "minlen")
        minlen = raw if raw else "N/A"
        mnum = as_int(minlen)
        if mnum is not None and mnum >= 15:
            s.record("PASS", "STIG-PW-LEN", "pwquality minlen = %s (≥15)" % minlen,
                     "ACCESS CONTROL",
                     "Password minimum length meets STIG requirement.", "")
        else:
            s.record("FAIL", "STIG-PW-LEN",
                     "pwquality minlen = %s (STIG requires ≥15)" % minlen,
                     "ACCESS CONTROL",
                     "Password minimum length is below 15 characters.",
                     "Set 'minlen = 15' in /etc/security/pwquality.conf")

    if svc_active("chronyd") or svc_active("ntpd"):
        s.record("PASS", "STIG-NTP-1", "Time sync service is active",
                 "AUDIT AND ACCOUNTABILITY", "chronyd or ntpd is running.", "")
    else:
        s.record("FAIL", "STIG-NTP-1", "No time sync service is active",
                 "AUDIT AND ACCOUNTABILITY", "Neither chronyd nor ntpd is running.",
                 "systemctl --now enable chronyd")

    if re.search(r"wlan|wifi|wireless", _ip_link_show(), re.IGNORECASE):
        s.record("WARN", "STIG-WIFI-1", "Wireless network interface(s) detected",
                 "NETWORK CONFIGURATION",
                 "Wireless interfaces found. Disable if not required.",
                 "nmcli radio wifi off  OR  ip link set <wlan_iface> down")
    else:
        s.record("PASS", "STIG-WIFI-1", "No wireless interfaces detected",
                 "NETWORK CONFIGURATION", "No wireless interfaces found.", "")

    if svc_active("bluetooth"):
        s.record("FAIL", "STIG-BT-1", "Bluetooth service is active",
                 "CONFIGURATION MANAGEMENT",
                 "Bluetooth is running and should be disabled.",
                 "systemctl --now disable bluetooth && echo 'install bluetooth "
                 "/bin/false' >> /etc/modprobe.d/hardening.conf")
    else:
        s.record("PASS", "STIG-BT-1", "Bluetooth service is not active",
                 "CONFIGURATION MANAGEMENT", "Bluetooth is disabled.", "")


_IP_LINK_CACHE = None


def _ip_link_show():
    """`ip link show`, with a /sys/class/net fallback when iproute2 is absent."""
    global _IP_LINK_CACHE
    if _IP_LINK_CACHE is None:
        txt = out(["ip", "link", "show"], timeout=20)
        if not txt:
            names = []
            try:
                names = sorted(os.listdir("/sys/class/net"))
            except OSError:
                pass
            parts = []
            for name in names:
                flags = read_value("/sys/class/net/%s/flags" % name, "")
                promisc = ""
                try:
                    if flags and (int(flags, 16) & 0x100):
                        promisc = "PROMISC"
                except ValueError:
                    pass
                wireless = os.path.isdir("/sys/class/net/%s/wireless" % name) \
                    or os.path.exists("/sys/class/net/%s/phy80211" % name)
                extra = " wireless" if wireless else ""
                parts.append("%s: <%s>%s" % (name, promisc, extra))
            txt = "\n".join(parts)
        _IP_LINK_CACHE = txt
    return _IP_LINK_CACHE


# =============================================================================
#  ██████╗  ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███████╗
#  ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
#  ██████╔╝██║   ██║███████╗   ██║   ██║   ██║██████╔╝█████╗
#  ██╔═══╝ ██║   ██║╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝
#  ██║     ╚██████╔╝███████║   ██║   ╚██████╔╝██║  ██║███████╗
#  ╚═╝      ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
#  LYNIS-STYLE POSTURE CHECKS
# =============================================================================

def run_posture_checks(s):
    s.banner("POSTURE — File System Integrity")

    ww_etc = len(find_paths("/etc", maxdepth=2, type_="f", perm_all=0o002))
    if ww_etc == 0:
        s.record("PASS", "POS-FS-1", "No world-writable files in /etc",
                 "FILE INTEGRITY",
                 "No world-writable files found in /etc (depth 2).", "")
    else:
        s.record("FAIL", "POS-FS-1", "%d world-writable file(s) in /etc" % ww_etc,
                 "FILE INTEGRITY", "World-writable files found in /etc.",
                 "find /etc -maxdepth 2 -perm -o+w -type f -exec chmod o-w {} \\;")

    no_sticky = len([p for p in find_paths(["/tmp", "/var", "/home", "/srv", "/opt"],
                                           maxdepth=3, type_="d", perm_all=0o002,
                                           xdev=True)
                     if not _has_sticky(p)])
    if no_sticky == 0:
        s.record("PASS", "POS-FS-2",
                 "All world-writable directories have sticky bit set",
                 "FILE INTEGRITY", "No world-writable dirs missing sticky bit.", "")
    else:
        s.record("FAIL", "POS-FS-2",
                 "%d world-writable dir(s) missing sticky bit" % no_sticky,
                 "FILE INTEGRITY",
                 "Some world-writable directories lack sticky bit.",
                 "find / -xdev -perm -0002 -type d ! -perm -1000 -exec chmod +t {} \\;")

    suid_count = len(find_paths(["/usr/bin", "/usr/sbin", "/bin", "/sbin"],
                                perm_any=0o6000))
    s.record("INFO", "POS-FS-3",
             "%d SUID/SGID files in standard bin dirs" % suid_count,
             "FILE INTEGRITY", "Review SUID/SGID binaries periodically.",
             "find / -perm /6000 -type f 2>/dev/null")

    if rpm_installed("aide") or have("aide"):
        s.record("PASS", "POS-FS-4",
                 "AIDE file integrity monitoring is installed", "FILE INTEGRITY",
                 "AIDE package is present.", "")
    else:
        s.record("WARN", "POS-FS-4", "AIDE is not installed", "FILE INTEGRITY",
                 "No file integrity monitoring tool found.",
                 "dnf install aide && aide --init && mv /var/lib/aide/aide.db.new.gz "
                 "/var/lib/aide/aide.db.gz")

    if s.needs_root("POS-FS-5", "RPM package file integrity check (rpm -Va)",
                    "FILE INTEGRITY"):
        rc, txt = run(["rpm", "-Va", "--nofiledigest"], timeout=30)
        rpm_changed = len([l for l in txt.splitlines()
                           if re.match(r"^\.M\.|^S\.", l)])
        if rpm_changed == 0:
            s.record("PASS", "POS-FS-5", "No modified RPM-owned files detected",
                     "FILE INTEGRITY", "rpm -Va found no modified package files.", "")
        else:
            s.record("WARN", "POS-FS-5",
                     "%d RPM-owned file(s) may be modified" % rpm_changed,
                     "FILE INTEGRITY",
                     "rpm -Va detected %d potentially modified files." % rpm_changed,
                     "Review: rpm -Va | grep -E '^.M|^S'")

    s.banner("POSTURE — Account & Authentication Hygiene")

    # chage needs root to read /etc/shadow; without it every account looks fine,
    # which is a silent false PASS — so gate the whole check on privilege.
    if s.needs_root("POS-AUTH-1", "Interactive account expiry (chage)",
                    "ACCESS CONTROL"):
        no_expiry = 0
        for row in passwd_entries():
            uid = as_int(row["uid"])
            if uid is None or uid < 1000:
                continue
            if row["shell"] in ("/sbin/nologin", "/bin/false"):
                continue
            expiry = ""
            for line in out(["chage", "-l", row["user"]], timeout=20).splitlines():
                if "Account expires" in line:
                    expiry = line.split(":", 1)[1].strip() if ":" in line else ""
                    break
            if expiry == "never":
                no_expiry += 1
        if no_expiry == 0:
            s.record("PASS", "POS-AUTH-1", "All interactive accounts have expiry set",
                     "ACCESS CONTROL",
                     "No interactive accounts with 'never' expiry.", "")
        else:
            s.record("WARN", "POS-AUTH-1",
                     "%d interactive account(s) have no expiry" % no_expiry,
                     "ACCESS CONTROL", "Some interactive accounts never expire.",
                     "chage -E YYYY-MM-DD <username>")

    sys_with_shell = 0
    for row in passwd_entries():
        uid = as_int(row["uid"])
        if uid is None or uid >= 1000 or row["user"] == "root":
            continue
        if re.search(r"nologin|false", row["shell"]):
            continue
        sys_with_shell += 1
    if sys_with_shell == 0:
        s.record("PASS", "POS-AUTH-2", "No system accounts with interactive shells",
                 "ACCESS CONTROL", "All system accounts use nologin/false shells.", "")
    else:
        s.record("WARN", "POS-AUTH-2",
                 "%d system account(s) have interactive shells" % sys_with_shell,
                 "ACCESS CONTROL", "System accounts should not have login shells.",
                 "usermod -s /sbin/nologin <username>")

    if os.path.isfile("/etc/cron.allow"):
        s.record("PASS", "POS-CRON-1",
                 "/etc/cron.allow exists (restricts cron access)", "ACCESS CONTROL",
                 "cron.allow is configured.", "")
    elif os.path.isfile("/etc/cron.deny"):
        s.record("WARN", "POS-CRON-1",
                 "/etc/cron.deny exists but cron.allow is preferred",
                 "ACCESS CONTROL", "cron.deny is less strict than cron.allow.",
                 "Create /etc/cron.allow and list permitted users")
    else:
        s.record("FAIL", "POS-CRON-1",
                 "No cron access control file (/etc/cron.allow or cron.deny)",
                 "ACCESS CONTROL", "No restriction on who can use cron.",
                 "Create /etc/cron.allow with permitted users only")

    s.banner("POSTURE — Crypto & System Posture")

    if s.ge(7):
        cp = out(["update-crypto-policies", "--show"]) or "N/A"
        if cp == "FIPS":
            s.record("PASS", "POS-CRYPTO-1", "System crypto policy = FIPS",
                     "SYSTEM INTEGRITY", "FIPS crypto policy is active.", "")
        elif cp == "DEFAULT":
            s.record("WARN", "POS-CRYPTO-1",
                     "System crypto policy = DEFAULT (recommend FIPS)",
                     "SYSTEM INTEGRITY", "Non-FIPS crypto policy in use.",
                     "update-crypto-policies --set FIPS && reboot")
        else:
            s.record("INFO", "POS-CRYPTO-1", "System crypto policy = %s" % cp,
                     "SYSTEM INTEGRITY", "Crypto policy: %s." % cp, "")

    if have("mokutil") and "enabled" in out(["mokutil", "--sb-state"], timeout=20):
        s.record("PASS", "POS-BOOT-1", "UEFI Secure Boot is enabled",
                 "SYSTEM INTEGRITY", "Secure Boot is active.", "")
    elif os.path.isdir("/sys/firmware/efi"):
        s.record("WARN", "POS-BOOT-1",
                 "UEFI present but Secure Boot status unknown", "SYSTEM INTEGRITY",
                 "UEFI firmware detected — verify Secure Boot in firmware settings.",
                 "mokutil --sb-state")
    else:
        s.record("INFO", "POS-BOOT-1",
                 "System appears to be BIOS/legacy (no UEFI)", "SYSTEM INTEGRITY",
                 "No UEFI detected — Secure Boot not applicable.", "")

    if grep_q("/proc/cpuinfo", r"nx", ignorecase=True):
        s.record("PASS", "POS-HW-1", "CPU NX/XD (No-Execute) bit supported",
                 "SYSTEM INTEGRITY",
                 "Hardware NX support detected in /proc/cpuinfo.", "")
    else:
        s.record("INFO", "POS-HW-1", "NX/XD bit status could not be confirmed",
                 "SYSTEM INTEGRITY", "Could not confirm NX hardware feature.", "")

    s.banner("POSTURE — Network Exposure")

    listen_count = _listening_tcp_count()
    s.record("INFO", "POS-NET-1",
             "%d listening TCP service(s) detected" % listen_count,
             "NETWORK CONFIGURATION",
             "Review all listening ports and disable unneeded services.", "ss -tlnp")

    promisc = len([l for l in _ip_link_show().splitlines() if "PROMISC" in l])
    if promisc == 0:
        s.record("PASS", "POS-NET-2", "No interfaces in promiscuous mode",
                 "NETWORK CONFIGURATION",
                 "No promiscuous mode network interfaces detected.", "")
    else:
        s.record("FAIL", "POS-NET-2",
                 "%d interface(s) in promiscuous mode" % promisc,
                 "NETWORK CONFIGURATION",
                 "Promiscuous mode allows capture of all network traffic.",
                 "ip link set <iface> promisc off")

    ipv6 = read_value("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0")
    if ipv6 == "1":
        s.record("INFO", "POS-NET-3", "IPv6 is disabled system-wide",
                 "NETWORK CONFIGURATION", "IPv6 is disabled.", "")
    else:
        s.record("INFO", "POS-NET-3", "IPv6 is enabled", "NETWORK CONFIGURATION",
                 "IPv6 is enabled — ensure it is properly configured.",
                 "To disable: echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> "
                 "/etc/sysctl.d/99-ipv6.conf")

    s.banner("POSTURE — Log File Health")

    for logfile in ("/var/log/messages", "/var/log/secure", "/var/log/audit/audit.log"):
        if os.path.isfile(logfile):
            s.record("PASS", "POS-LOG-1", "Log file present: %s" % logfile,
                     "AUDIT AND ACCOUNTABILITY", "%s exists." % logfile, "")
        else:
            s.record("WARN", "POS-LOG-1", "Log file missing: %s" % logfile,
                     "AUDIT AND ACCOUNTABILITY", "%s does not exist." % logfile,
                     "Verify rsyslog/auditd is configured to write %s" % logfile)


def _has_sticky(path):
    try:
        return bool(os.lstat(path).st_mode & statmod.S_ISVTX)
    except OSError:
        return False


def _listening_tcp_count():
    """Count listening TCP sockets. Prefers `ss`, falls back to /proc/net/tcp*."""
    if have("ss"):
        txt = out(["ss", "-tlnp"], timeout=30)
        if txt:
            return len([l for l in txt.splitlines() if "LISTEN" in l])
    count = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        txt = read_text(path)
        if not txt:
            continue
        for line in txt.splitlines()[1:]:
            fields = line.split()
            # st == 0A is TCP_LISTEN
            if len(fields) > 3 and fields[3] == "0A":
                count += 1
    return count


# =============================================================================
#  ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗
#  ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝
#  ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
#  ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║
#  ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝
#  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
#
#  BUILT-IN HARDENING SCAN — Lynis-compatible test categories
#  Fully embedded — zero external dependencies — 100% air-gap safe
#  Covers AUTH BOOT CRYP INSE KRNL LOGG MALW PKGS SCHD SHLL STRG TIME TOOL
#  USERS HRDN
# =============================================================================

def run_hardening_scan(s):

    # ── AUTH: Authentication & PAM ───────────────────────────────────────────
    s.banner("HARDENING [AUTH] — Authentication & PAM")

    if grep_rq("/etc/pam.d", r"pam_pwquality|pam_cracklib"):
        s.record("PASS", "HRDN-AUTH-1", "PAM password quality module is configured",
                 "AUTHENTICATION",
                 "pam_pwquality or pam_cracklib found in PAM config.", "")
    else:
        s.record("FAIL", "HRDN-AUTH-1", "PAM password quality module not configured",
                 "AUTHENTICATION", "No pam_pwquality/pam_cracklib in /etc/pam.d/.",
                 "authconfig --enablereqpass --update  OR  configure pam_pwquality "
                 "in /etc/pam.d/system-auth")

    if grep_rq("/etc/pam.d", r"nullok"):
        s.record("FAIL", "HRDN-AUTH-2",
                 "nullok found in PAM config (empty passwords allowed)",
                 "AUTHENTICATION", "PAM nullok option permits passwordless logins.",
                 "Remove 'nullok' from all files in /etc/pam.d/")
    else:
        s.record("PASS", "HRDN-AUTH-2", "PAM nullok is not present",
                 "AUTHENTICATION",
                 "Empty password logins are not permitted via PAM.", "")

    if os.path.isfile("/etc/sudoers"):
        nopasswd_count = len(grep_lines("/etc/sudoers", r"NOPASSWD"))
        if nopasswd_count == 0:
            s.record("PASS", "HRDN-AUTH-3", "No NOPASSWD entries in /etc/sudoers",
                     "AUTHENTICATION", "All sudo rules require password.", "")
        else:
            s.record("FAIL", "HRDN-AUTH-3",
                     "%d NOPASSWD entry/entries in sudoers" % nopasswd_count,
                     "AUTHENTICATION", "Passwordless sudo is configured.",
                     "Remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/*")

    if grep_q("/etc/pam.d/su", r"^\s*auth\s+required\s+pam_wheel"):
        s.record("PASS", "HRDN-AUTH-4",
                 "su access restricted to wheel group via pam_wheel",
                 "AUTHENTICATION", "pam_wheel.so required in /etc/pam.d/su.", "")
    else:
        s.record("FAIL", "HRDN-AUTH-4", "su is not restricted to wheel group",
                 "AUTHENTICATION", "pam_wheel.so not enforced for su.",
                 "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su")

    if grep_rq("/etc/pam.d", r"pam_pwhistory|remember="):
        rem_val = "0"
        for line in grep_r_lines("/etc/pam.d", r"remember=[0-9]+"):
            m = re.search(r"remember=([0-9]+)", line)
            if m:
                rem_val = m.group(1)
                break
        rnum = as_int(rem_val)
        if rnum is not None and rnum >= 5:
            s.record("PASS", "HRDN-AUTH-5",
                     "Password history enforcement: remember=%s (≥5)" % rem_val,
                     "AUTHENTICATION", "Password reuse is restricted.", "")
        else:
            s.record("WARN", "HRDN-AUTH-5",
                     "Password history remember=%s (recommended ≥5)" % rem_val,
                     "AUTHENTICATION",
                     "Password reuse restriction may be insufficient.",
                     "Add 'password required pam_pwhistory.so remember=5' to "
                     "/etc/pam.d/system-auth")
    else:
        s.record("FAIL", "HRDN-AUTH-5",
                 "Password history (pam_pwhistory) not configured",
                 "AUTHENTICATION", "Previous passwords can be immediately reused.",
                 "Add 'password required pam_pwhistory.so remember=5' to "
                 "/etc/pam.d/system-auth")

    raw = conf_value("/etc/login.defs", "SHA_CRYPT_MIN_ROUNDS", sep=None)
    rounds = raw if raw else "0"
    rnum = as_int(rounds)
    if rnum is not None and rnum >= 5000:
        s.record("PASS", "HRDN-AUTH-6",
                 "SHA_CRYPT_MIN_ROUNDS = %s (≥5000)" % rounds, "AUTHENTICATION",
                 "Sufficient password hashing rounds configured.", "")
    else:
        s.record("FAIL", "HRDN-AUTH-6",
                 "SHA_CRYPT_MIN_ROUNDS = %s (expected ≥5000)" % rounds,
                 "AUTHENTICATION", "Insufficient password hashing rounds.",
                 "Set 'SHA_CRYPT_MIN_ROUNDS 5000' in /etc/login.defs")

    # ── BOOT: Bootloader & Init ──────────────────────────────────────────────
    s.banner("HARDENING [BOOT] — Bootloader & Init")

    rescue_units = ["/usr/lib/systemd/system/rescue.service",
                    "/usr/lib/systemd/system/emergency.service"]
    if grep_q(rescue_units, r"ExecStart.*-b|sulogin|sushell"):
        s.record("PASS", "HRDN-BOOT-1",
                 "Rescue/emergency mode requires authentication",
                 "CONFIGURATION MANAGEMENT",
                 "systemd rescue/emergency services use sulogin.", "")
    else:
        s.record("WARN", "HRDN-BOOT-1",
                 "Rescue/emergency mode authentication unclear",
                 "CONFIGURATION MANAGEMENT",
                 "Verify rescue/emergency services require root password.",
                 "Check /usr/lib/systemd/system/rescue.service and emergency.service")

    def_target = out(["systemctl", "get-default"], timeout=20) or "unknown"
    if def_target == "multi-user.target":
        s.record("PASS", "HRDN-BOOT-2",
                 "Default systemd target = multi-user (non-graphical)",
                 "CONFIGURATION MANAGEMENT",
                 "System boots to CLI, not graphical environment.", "")
    elif def_target == "graphical.target":
        s.record("WARN", "HRDN-BOOT-2",
                 "Default target = graphical.target (consider multi-user for servers)",
                 "CONFIGURATION MANAGEMENT",
                 "Graphical environment increases attack surface.",
                 "systemctl set-default multi-user.target")
    else:
        s.record("INFO", "HRDN-BOOT-2", "Default target = %s" % def_target,
                 "CONFIGURATION MANAGEMENT",
                 "Verify this is the intended boot target.", "")

    if (grep_q("/etc/sysconfig/init", r"^\s*PROMPT\s*=\s*no")
            or grep_q("/proc/cmdline", r"systemd\.confirm_spawn=0|quiet")):
        s.record("PASS", "HRDN-BOOT-3", "Interactive boot is disabled",
                 "CONFIGURATION MANAGEMENT",
                 "System does not allow interactive boot prompts.", "")
    else:
        s.record("WARN", "HRDN-BOOT-3",
                 "Interactive boot status could not be confirmed",
                 "CONFIGURATION MANAGEMENT", "Verify interactive boot is disabled.",
                 "Set PROMPT=no in /etc/sysconfig/init  OR add "
                 "'systemd.confirm_spawn=0' to GRUB_CMDLINE_LINUX")

    # ── CRYP: Cryptography ──────────────────────────────────────────────────
    s.banner("HARDENING [CRYP] — Cryptography & Certificates")

    expired_certs = 0
    expiring_soon = 0
    now_epoch = time.time()
    # Bounded, SORTED sample: there are often 150+ trust-store certs and each
    # one costs an openssl fork. Sorting keeps the sample stable across runs and
    # identical to the shell engine's `find ... | sort | head -30`.
    certs = sorted(find_paths(["/etc/pki", "/etc/ssl"], name=["*.pem", "*.crt"]))[:30]
    for certfile in certs:
        enddate = ""
        for line in out(["openssl", "x509", "-noout", "-enddate", "-in", certfile],
                        timeout=3).splitlines():
            if "=" in line:
                enddate = line.split("=", 1)[1].strip()
                break
        if not enddate:
            continue
        exp_epoch = _parse_openssl_date(enddate)
        if exp_epoch is None:
            continue
        days_left = int((exp_epoch - now_epoch) // 86400)
        if days_left < 0:
            expired_certs += 1
        elif days_left < 30:
            expiring_soon += 1

    if expired_certs == 0 and expiring_soon == 0:
        s.record("PASS", "HRDN-CRYP-1",
                 "No expired or soon-expiring certificates found in /etc/pki",
                 "SYSTEM INTEGRITY", "Checked certificates appear valid.", "")
    else:
        if expired_certs > 0:
            s.record("FAIL", "HRDN-CRYP-1",
                     "%d expired certificate(s) in /etc/pki" % expired_certs,
                     "SYSTEM INTEGRITY", "Expired certificates found.",
                     "Renew expired certificates in /etc/pki")
        if expiring_soon > 0:
            s.record("WARN", "HRDN-CRYP-2",
                     "%d certificate(s) expiring within 30 days" % expiring_soon,
                     "SYSTEM INTEGRITY", "Certificates expiring soon.",
                     "Renew certificates expiring within 30 days")

    ossl_ver = "N/A"
    ossl_out = out(["openssl", "version"], timeout=10)
    if ossl_out:
        parts = ossl_out.split()
        if len(parts) > 1:
            ossl_ver = parts[1]
    s.record("INFO", "HRDN-CRYP-3", "OpenSSL version: %s" % ossl_ver,
             "SYSTEM INTEGRITY",
             "Installed OpenSSL: %s. Ensure it is patched." % ossl_ver,
             "dnf update openssl")

    if have("gnutls-cli") or rpm_installed("gnutls"):
        s.record("PASS", "HRDN-CRYP-4", "GnuTLS is installed", "SYSTEM INTEGRITY",
                 "GnuTLS package is present.", "")
    else:
        s.record("WARN", "HRDN-CRYP-4", "GnuTLS not found", "SYSTEM INTEGRITY",
                 "GnuTLS is not installed.", "dnf install gnutls gnutls-utils")

    # ── INSE: Insecure Protocols & Services ─────────────────────────────────
    s.banner("HARDENING [INSE] — Insecure Protocols")

    if rpm_installed("telnet"):
        s.record("WARN", "HRDN-INSE-1", "telnet client is installed",
                 "CONFIGURATION MANAGEMENT",
                 "Telnet transmits credentials in cleartext.", "dnf remove telnet")
    else:
        s.record("PASS", "HRDN-INSE-1", "telnet client is not installed",
                 "CONFIGURATION MANAGEMENT", "Insecure telnet client is absent.", "")

    if rpm_installed("ftp"):
        s.record("WARN", "HRDN-INSE-2", "ftp client is installed",
                 "CONFIGURATION MANAGEMENT",
                 "FTP transmits credentials in cleartext.", "dnf remove ftp")
    else:
        s.record("PASS", "HRDN-INSE-2", "ftp client is not installed",
                 "CONFIGURATION MANAGEMENT", "Insecure FTP client is absent.", "")

    if rpm_installed("rsh"):
        s.record("FAIL", "HRDN-INSE-3", "rsh client is installed",
                 "CONFIGURATION MANAGEMENT",
                 "rsh is an insecure remote shell protocol.", "dnf remove rsh")
    else:
        s.record("PASS", "HRDN-INSE-3", "rsh client is not installed",
                 "CONFIGURATION MANAGEMENT", "rsh client is absent.", "")

    ldap_conf = ["/etc/nslcd.conf", "/etc/sssd/sssd.conf", "/etc/openldap/ldap.conf"]
    if grep_q(ldap_conf, r"^\s*uri\s+ldap://", ignorecase=True):
        s.record("WARN", "HRDN-INSE-4",
                 "LDAP cleartext URI found in config (ldap:// not ldaps://)",
                 "NETWORK CONFIGURATION", "LDAP configured without TLS.",
                 "Change ldap:// to ldaps:// in LDAP client configuration")
    else:
        s.record("PASS", "HRDN-INSE-4", "No cleartext LDAP URIs found",
                 "NETWORK CONFIGURATION",
                 "LDAP is either not configured or uses TLS.", "")

    # ── KRNL: Kernel extras beyond CIS ──────────────────────────────────────
    s.banner("HARDENING [KRNL] — Kernel Extra Checks")

    sysrq = sysctl("kernel.sysrq")
    if sysrq == "0":
        s.record("PASS", "HRDN-KRNL-1", "kernel.sysrq = 0 (disabled)",
                 "CONFIGURATION MANAGEMENT", "Magic SysRq key is disabled.", "")
    else:
        s.record("WARN", "HRDN-KRNL-1",
                 "kernel.sysrq = %s (expected 0)" % sysrq,
                 "CONFIGURATION MANAGEMENT",
                 "SysRq can allow dangerous low-level operations.",
                 "echo 'kernel.sysrq = 0' >> /etc/sysctl.d/99-hardening.conf && "
                 "sysctl -w kernel.sysrq=0")

    core_pid = sysctl("kernel.core_uses_pid")
    if core_pid == "1":
        s.record("PASS", "HRDN-KRNL-2", "kernel.core_uses_pid = 1",
                 "CONFIGURATION MANAGEMENT",
                 "Core dumps include PID in filename.", "")
    else:
        s.record("INFO", "HRDN-KRNL-2", "kernel.core_uses_pid = %s" % core_pid,
                 "CONFIGURATION MANAGEMENT", "Consider enabling core_uses_pid.",
                 "echo 'kernel.core_uses_pid = 1' >> /etc/sysctl.d/99-hardening.conf")

    if s.ge(8):
        kexec = sysctl("kernel.kexec_load_disabled")
        if kexec == "1":
            s.record("PASS", "HRDN-KRNL-3", "kernel.kexec_load_disabled = 1",
                     "CONFIGURATION MANAGEMENT",
                     "Loading a new kernel for execution is disabled.", "")
        else:
            s.record("FAIL", "HRDN-KRNL-3",
                     "kernel.kexec_load_disabled = %s (expected 1)" % kexec,
                     "CONFIGURATION MANAGEMENT",
                     "kexec allows loading alternate kernels.",
                     "echo 'kernel.kexec_load_disabled = 1' >> "
                     "/etc/sysctl.d/99-hardening.conf")

    # ── LOGG: Logging ───────────────────────────────────────────────────────
    s.banner("HARDENING [LOGG] — Logging Configuration")

    rsyslog_paths = ["/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf", "/etc/syslog.conf"]
    if grep_q(rsyslog_paths, r"^\s*\*\.\*\s+@@|^\s*\*\.\*\s+@[^@]|remote_host"):
        s.record("PASS", "HRDN-LOGG-1", "Remote syslog forwarding is configured",
                 "AUDIT AND ACCOUNTABILITY",
                 "Logs are forwarded to a remote server.", "")
    else:
        s.record("WARN", "HRDN-LOGG-1",
                 "Remote syslog forwarding is not configured",
                 "AUDIT AND ACCOUNTABILITY", "Logs are only stored locally.",
                 "Configure remote logging in /etc/rsyslog.conf: *.* @@logserver:514")

    auditd_conf = "/etc/audit/auditd.conf"
    if os.path.isfile(auditd_conf):
        dfa = conf_value(auditd_conf, "disk_full_action") or ""
        if re.search(r"halt|single|syslog", dfa, re.IGNORECASE):
            s.record("PASS", "HRDN-LOGG-2", "auditd disk_full_action = %s" % dfa,
                     "AUDIT AND ACCOUNTABILITY",
                     "System takes action when audit disk is full.", "")
        else:
            s.record("FAIL", "HRDN-LOGG-2",
                     "auditd disk_full_action = %s (expected halt/single/syslog)" % dfa,
                     "AUDIT AND ACCOUNTABILITY",
                     "No action configured when audit disk fills up.",
                     "Set 'disk_full_action = halt' in /etc/audit/auditd.conf")

        asla = conf_value(auditd_conf, "admin_space_left_action") or ""
        if re.search(r"halt|single|email|exec", asla, re.IGNORECASE):
            s.record("PASS", "HRDN-LOGG-3",
                     "auditd admin_space_left_action = %s" % asla,
                     "AUDIT AND ACCOUNTABILITY",
                     "Admin notified when audit space is critically low.", "")
        else:
            s.record("FAIL", "HRDN-LOGG-3",
                     "auditd admin_space_left_action = %s" % asla,
                     "AUDIT AND ACCOUNTABILITY",
                     "No action for critically low audit disk space.",
                     "Set 'admin_space_left_action = halt' in /etc/audit/auditd.conf")

    if os.path.isfile("/etc/logrotate.conf") or os.path.isdir("/etc/logrotate.d"):
        s.record("PASS", "HRDN-LOGG-4", "logrotate is configured",
                 "AUDIT AND ACCOUNTABILITY",
                 "/etc/logrotate.conf or /etc/logrotate.d exists.", "")
    else:
        s.record("WARN", "HRDN-LOGG-4", "logrotate configuration not found",
                 "AUDIT AND ACCOUNTABILITY", "Log rotation may not be configured.",
                 "Install logrotate: dnf install logrotate")

    # ── MALW: Malware & Integrity Tools ─────────────────────────────────────
    s.banner("HARDENING [MALW] — Malware & Integrity Tools")

    malw_found = False
    for tool in ("rkhunter", "chkrootkit", "aide", "tripwire", "samhain"):
        if have(tool) or rpm_installed(tool):
            s.record("PASS", "HRDN-MALW-1",
                     "Malware/integrity scanner '%s' is installed" % tool,
                     "SYSTEM INTEGRITY",
                     "%s is available for periodic scanning." % tool, "")
            malw_found = True
    if not malw_found:
        s.record("WARN", "HRDN-MALW-1",
                 "No malware or rootkit scanner installed", "SYSTEM INTEGRITY",
                 "rkhunter, chkrootkit, aide, tripwire, samhain not found.",
                 "Install rkhunter: dnf install rkhunter  OR  aide: dnf install aide")

    if have("aureport"):
        rc, txt = run(["aureport", "--avc"], timeout=10)
        avc_count = max(0, len(txt.splitlines()) - 6)
        if avc_count == 0:
            s.record("PASS", "HRDN-MALW-2",
                     "No recent SELinux AVC denials in audit log",
                     "SYSTEM INTEGRITY", "aureport --avc shows no recent denials.", "")
        else:
            s.record("INFO", "HRDN-MALW-2",
                     "%d SELinux AVC denial(s) found" % avc_count,
                     "SYSTEM INTEGRITY",
                     "SELinux has logged %d AVC denial(s)." % avc_count,
                     "Review: aureport --avc  and  ausearch -m avc -ts recent")

    # ── PKGS: Package Management ────────────────────────────────────────────
    s.banner("HARDENING [PKGS] — Package Management")

    rc, txt = run(["rpm", "-qa"], timeout=120)
    pkg_count = len([l for l in txt.splitlines() if l.strip()]) if rc == 0 else "N/A"
    s.record("INFO", "HRDN-PKGS-1", "%s RPM packages installed" % pkg_count,
             "CONFIGURATION MANAGEMENT",
             "Minimise installed packages to reduce attack surface.",
             "Review: rpm -qa | sort  and remove unneeded packages")

    dev_pkgs = sum(1 for pkg in ("gcc", "gcc-c++", "make", "gdb", "strace", "ltrace")
                   if rpm_installed(pkg))
    if dev_pkgs == 0:
        s.record("PASS", "HRDN-PKGS-2", "No compiler/debug tools installed",
                 "CONFIGURATION MANAGEMENT",
                 "gcc, make, gdb, strace, ltrace not found.", "")
    else:
        s.record("WARN", "HRDN-PKGS-2",
                 "%d compiler/debug tool(s) installed" % dev_pkgs,
                 "CONFIGURATION MANAGEMENT",
                 "Compilers and debug tools increase attack surface.",
                 "Remove: dnf remove gcc gcc-c++ make gdb strace ltrace")

    # ── SCHD: Scheduled Tasks ───────────────────────────────────────────────
    s.banner("HARDENING [SCHD] — Scheduled Jobs")

    ww_cron = len(find_paths(["/etc/cron*", "/var/spool/cron"], type_="f",
                             perm_all=0o002))
    if ww_cron == 0:
        s.record("PASS", "HRDN-SCHD-1", "No world-writable cron files found",
                 "CONFIGURATION MANAGEMENT",
                 "Cron files have appropriate permissions.", "")
    else:
        s.record("FAIL", "HRDN-SCHD-1",
                 "%d world-writable cron file(s) found" % ww_cron,
                 "CONFIGURATION MANAGEMENT",
                 "World-writable cron files are a security risk.",
                 "find /etc/cron* /var/spool/cron -perm -o+w -exec chmod o-w {} \\;")

    if os.path.isfile("/etc/at.allow"):
        s.record("PASS", "HRDN-SCHD-2",
                 "/etc/at.allow exists (at job access controlled)",
                 "ACCESS CONTROL", "at command access is restricted via at.allow.", "")
    else:
        s.record("WARN", "HRDN-SCHD-2", "/etc/at.allow not found", "ACCESS CONTROL",
                 "at command access is not explicitly restricted.",
                 "Create /etc/at.allow listing only permitted users")

    # ── SHLL: Shell & Environment ───────────────────────────────────────────
    s.banner("HARDENING [SHLL] — Shell Configuration")

    profile_paths = ["/etc/profile", "/etc/profile.d/*.sh", "/etc/bashrc"]
    tmout_set = ""
    for line in grep_lines(profile_paths, r"TMOUT"):
        if not line.startswith("#"):
            tmout_set = line
            break
    if tmout_set:
        s.record("PASS", "HRDN-SHLL-1", "TMOUT is set in shell profile",
                 "ACCESS CONTROL",
                 "Idle session timeout configured: %s" % tmout_set, "")
    else:
        s.record("FAIL", "HRDN-SHLL-1", "TMOUT not set in any shell profile",
                 "ACCESS CONTROL", "Interactive sessions have no idle timeout.",
                 "echo 'readonly TMOUT=600' > /etc/profile.d/tmout.sh && chmod +x "
                 "/etc/profile.d/tmout.sh")

    bad_path = grep_q(profile_paths, r"PATH=.*(\.|::|^:|:$)")
    if not bad_path:
        s.record("PASS", "HRDN-SHLL-2",
                 "No dangerous PATH entries (. or ::) in shell profiles",
                 "ACCESS CONTROL",
                 "Shell profiles do not include current dir in PATH.", "")
    else:
        s.record("FAIL", "HRDN-SHLL-2",
                 "Dangerous PATH entry found in shell profile", "ACCESS CONTROL",
                 "PATH includes '.' or empty entry — allows local binary hijacking.",
                 "Remove '.' and empty entries from PATH in /etc/profile and "
                 "/etc/bashrc")

    hist_nums = []
    for line in grep_lines(profile_paths, r"HISTSIZE"):
        if line.startswith("#"):
            continue
        hist_nums.extend(as_int(n) for n in re.findall(r"[0-9]+", line))
    hist_nums = [n for n in hist_nums if n is not None]
    histsize = str(max(hist_nums)) if hist_nums else "N/A"
    s.record("INFO", "HRDN-SHLL-3", "HISTSIZE = %s" % histsize,
             "AUDIT AND ACCOUNTABILITY", "Shell command history size.",
             "Set HISTSIZE=1000 and HISTFILESIZE=2000 in /etc/profile")

    # ── STRG: Storage & USB ─────────────────────────────────────────────────
    s.banner("HARDENING [STRG] — Storage & USB")

    usb_loaded = mod_loaded("usb_storage")
    usb_bl = grep_rq("/etc/modprobe.d", r"install usb.storage /bin/(false|true)")
    if not usb_loaded and usb_bl:
        s.record("PASS", "HRDN-STRG-1",
                 "USB mass storage is disabled and blacklisted", "MEDIA PROTECTION",
                 "usb-storage module is not loaded and is blacklisted.", "")
    elif not usb_loaded:
        s.record("WARN", "HRDN-STRG-1",
                 "USB storage not loaded but not blacklisted", "MEDIA PROTECTION",
                 "usb-storage is absent but could be loaded.",
                 "echo 'install usb-storage /bin/false' >> "
                 "/etc/modprobe.d/hardening.conf")
    else:
        s.record("FAIL", "HRDN-STRG-1", "USB mass storage module is loaded",
                 "MEDIA PROTECTION",
                 "usb-storage is active — USB drives can be mounted.",
                 "modprobe -r usb-storage && echo 'install usb-storage /bin/false' "
                 ">> /etc/modprobe.d/hardening.conf")

    if svc_active("autofs"):
        s.record("FAIL", "HRDN-STRG-2", "autofs automount service is running",
                 "MEDIA PROTECTION", "Automatic media mounting is active.",
                 "systemctl --now disable autofs")
    else:
        s.record("PASS", "HRDN-STRG-2", "autofs is not running",
                 "MEDIA PROTECTION", "Automatic media mounting is disabled.", "")

    # ── TIME: Time Synchronisation ──────────────────────────────────────────
    s.banner("HARDENING [TIME] — Time Synchronisation")

    ntp_servers = 0
    if os.path.isfile("/etc/chrony.conf"):
        ntp_servers = len(grep_lines("/etc/chrony.conf", r"^\s*(server|pool)"))
    elif os.path.isfile("/etc/ntp.conf"):
        ntp_servers = len(grep_lines("/etc/ntp.conf", r"^\s*server"))
    if ntp_servers >= 2:
        s.record("PASS", "HRDN-TIME-1",
                 "%d NTP server(s) configured (≥2 for redundancy)" % ntp_servers,
                 "AUDIT AND ACCOUNTABILITY", "Multiple time sources configured.", "")
    elif ntp_servers == 1:
        s.record("WARN", "HRDN-TIME-1",
                 "Only 1 NTP server configured (recommend ≥2)",
                 "AUDIT AND ACCOUNTABILITY",
                 "Single NTP source is a single point of failure.",
                 "Add a second server/pool entry to /etc/chrony.conf")
    else:
        s.record("FAIL", "HRDN-TIME-1",
                 "No NTP servers configured in chrony.conf or ntp.conf",
                 "AUDIT AND ACCOUNTABILITY",
                 "Time synchronisation source is not configured.",
                 "Add 'pool pool.ntp.org iburst' to /etc/chrony.conf")

    if have("chronyc"):
        tracking = ""
        for line in out(["chronyc", "tracking"], timeout=5).splitlines():
            if "Leap status" in line:
                tracking = line.split()[-1]
                break
        if tracking == "Normal":
            s.record("PASS", "HRDN-TIME-2",
                     "chronyc reports time is synchronised (Leap status: Normal)",
                     "AUDIT AND ACCOUNTABILITY", "System clock is synced to NTP.", "")
        else:
            s.record("WARN", "HRDN-TIME-2",
                     "chronyc Leap status = %s (expected Normal)" % tracking,
                     "AUDIT AND ACCOUNTABILITY",
                     "System clock may not be properly synchronised.",
                     "systemctl restart chronyd && chronyc tracking")

    # ── TOOL: Security Tools Inventory ──────────────────────────────────────
    s.banner("HARDENING [TOOL] — Security Tools")

    desired_tools = [
        ("aide", "File integrity monitoring"),
        ("rkhunter", "Rootkit scanner"),
        ("auditd", "Audit daemon"),
        ("firewalld", "Host firewall"),
        ("fail2ban", "Brute force protection"),
        ("clamav", "Antivirus scanner"),
        ("openscap", "OpenSCAP compliance scanner"),
        ("oscap", "OpenSCAP CLI tool"),
        ("sssd", "System security services daemon"),
    ]
    unit_list = out(["systemctl", "list-units", "--all"], timeout=30)
    for tool, desc in desired_tools:
        present = have(tool) or rpm_installed(tool) or (tool in unit_list)
        if present:
            s.record("PASS", "HRDN-TOOL",
                     "Security tool '%s' (%s) is present" % (tool, desc),
                     "SYSTEM INTEGRITY", "%s is installed." % tool, "")
        else:
            s.record("INFO", "HRDN-TOOL",
                     "Security tool '%s' (%s) not found" % (tool, desc),
                     "SYSTEM INTEGRITY",
                     "%s is not installed — consider adding it." % tool,
                     "dnf install %s" % tool)

    # ── USERS: Extended User Checks ─────────────────────────────────────────
    s.banner("HARDENING [USERS] — User Account Audit")

    user_count = 0
    for row in passwd_entries():
        uid = as_int(row["uid"])
        if uid is not None and 1000 <= uid < 65534:
            user_count += 1
    s.record("INFO", "HRDN-USERS-1",
             "%d interactive user account(s) (UID ≥1000)" % user_count,
             "ACCESS CONTROL", "Review all interactive accounts periodically.",
             "awk -F: '$3>=1000' /etc/passwd")

    if s.needs_root("HRDN-USERS-2", "Check shadow password expiry fields",
                    "ACCESS CONTROL"):
        no_expiry_shadow = 0
        for row in shadow_entries():
            if row["pw"].startswith("!") or row["pw"] == "*":
                continue
            if row["max"] in ("99999", "", "0"):
                no_expiry_shadow += 1
        if no_expiry_shadow == 0:
            s.record("PASS", "HRDN-USERS-2",
                     "All active accounts have password max-age configured",
                     "ACCESS CONTROL",
                     "No accounts with 99999 or empty max password age.", "")
        else:
            s.record("WARN", "HRDN-USERS-2",
                     "%d account(s) have no password expiry" % no_expiry_shadow,
                     "ACCESS CONTROL",
                     "Accounts with PASS_MAX_DAYS=99999 or unset found.",
                     "chage -M 60 <username>  for each affected user")

    bad_homes = 0
    for row in passwd_entries():
        uid = as_int(row["uid"])
        if uid is None or uid < 1000:
            continue
        if not os.path.isdir(row["home"]):
            continue
        hperm = as_int(stat_mode(row["home"]))
        if hperm is not None and hperm > 750:
            bad_homes += 1
    if bad_homes == 0:
        s.record("PASS", "HRDN-USERS-3",
                 "All home directories have mode 750 or less", "ACCESS CONTROL",
                 "Home directory permissions are appropriately restrictive.", "")
    else:
        s.record("FAIL", "HRDN-USERS-3",
                 "%d home director(ies) are too permissive (>750)" % bad_homes,
                 "ACCESS CONTROL",
                 "Some home directories are world or group-readable.",
                 "chmod 750 <homedir>  for each affected user")

    # ── HRDN: System Hardening Features ─────────────────────────────────────
    s.banner("HARDENING [HRDN] — System Hardening Features")

    if grep_q("/proc/cpuinfo", r" nx", ignorecase=True):
        s.record("PASS", "HRDN-HRDN-1", "CPU NX (No-Execute) bit is supported",
                 "SYSTEM INTEGRITY", "Hardware enforced NX/DEP is available.", "")

    if os.path.isfile("/proc/sys/kernel/exec-shield"):
        es = read_value("/proc/sys/kernel/exec-shield", "")
        if es == "1":
            s.record("PASS", "HRDN-HRDN-2", "ExecShield is enabled",
                     "SYSTEM INTEGRITY", "kernel.exec-shield = 1", "")
        else:
            s.record("FAIL", "HRDN-HRDN-2", "ExecShield is not enabled",
                     "SYSTEM INTEGRITY", "kernel.exec-shield = %s" % es,
                     "echo 'kernel.exec-shield = 1' >> "
                     "/etc/sysctl.d/99-hardening.conf")

    if _is_world_executable("/usr/bin/gcc") or _is_world_executable("/usr/bin/cc"):
        s.record("WARN", "HRDN-HRDN-3",
                 "Compiler (gcc/cc) is executable by all users",
                 "CONFIGURATION MANAGEMENT",
                 "Compilers should be restricted on production servers.",
                 "chmod o-x /usr/bin/gcc /usr/bin/cc 2>/dev/null || dnf remove gcc")
    else:
        s.record("PASS", "HRDN-HRDN-3", "No compilers found on system PATH",
                 "CONFIGURATION MANAGEMENT",
                 "Compiler tools are not installed or not accessible.", "")

    if svc_active("psacct") or svc_active("acct"):
        s.record("PASS", "HRDN-HRDN-4",
                 "Process accounting is active (psacct/acct)",
                 "AUDIT AND ACCOUNTABILITY",
                 "Process accounting records commands run by all users.", "")
    else:
        s.record("WARN", "HRDN-HRDN-4", "Process accounting is not active",
                 "AUDIT AND ACCOUNTABILITY",
                 "User command history is not tracked at OS level.",
                 "systemctl --now enable psacct  OR  dnf install psacct && "
                 "systemctl --now enable psacct")

    if not s.quiet:
        _p("%s[PASS]%s Built-in hardening scan complete." % (GREEN, RESET))


def _is_world_executable(path):
    """The finding claims 'executable by all users', so test the o+x bit."""
    try:
        return bool(statmod.S_IMODE(os.stat(path).st_mode) & 0o001)
    except OSError:
        return False


_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _parse_openssl_date(text):
    """Parse `openssl x509 -enddate` output (e.g. 'Mar  3 12:00:00 2030 GMT')."""
    m = re.match(r"\s*([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})",
                 text)
    if not m:
        return None
    mon = _MONTHS.get(m.group(1))
    if not mon:
        return None
    try:
        import calendar
        return calendar.timegm((int(m.group(6)), mon, int(m.group(2)),
                                int(m.group(3)), int(m.group(4)), int(m.group(5)),
                                0, 0, 0))
    except (ValueError, OverflowError):
        return None


# =============================================================================
#   █████╗ ██╗██████╗      ██████╗  █████╗ ██████╗
#  ██╔══██╗██║██╔══██╗    ██╔════╝ ██╔══██╗██╔══██╗
#  ███████║██║██████╔╝    ██║  ███╗███████║██████╔╝
#  ██╔══██║██║██╔══██╗    ██║   ██║██╔══██║██╔═══╝
#  ██║  ██║██║██║  ██║    ╚██████╔╝██║  ██║██║
#  ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝     ╚═════╝ ╚═╝  ╚═╝╚═╝
#  AIR-GAP / ENCLAVE ISOLATION CHECKS
#  Answers: "Could this host reach, bridge to, or leak into another network —
#  and is it quietly decaying because it can't reach its update sources?"
#  100% local reads: /proc, /sys, /etc, rpm DB. Nothing is resolved or probed.
# =============================================================================

# Hostname suffixes that are definitely outside an enclave. Extend as needed.
AIRGAP_PUBLIC_PATTERNS = """
redhat.com fedoraproject.org centos.org rockylinux.org almalinux.org oracle.com
amazonaws.com cloudfront.net github.com githubusercontent.com ntp.org google.com
googleapis.com cloudflare.com windows.com microsoft.com apple.com nist.gov
quad9.net opendns.com akamaized.net fastly.net
""".split()


def _is_ip_literal(value):
    return bool(re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", value)) or value.count(":") >= 2


def _is_private_ip(ip):
    low = ip.lower()
    if (low.startswith("10.") or low.startswith("192.168.") or low.startswith("127.")
            or low.startswith("169.254.") or low in ("0.0.0.0", "::1", "::")
            or low.startswith("fe80:")):
        return True
    if re.match(r"^f[cd][0-9a-f]*:", low):
        return True
    if low.startswith("172."):
        octet = as_int(low[4:].split(".")[0])
        if octet is not None and 16 <= octet <= 31:
            return True
    if low.startswith("100."):
        octet = as_int(low[4:].split(".")[0])
        if octet is not None and 64 <= octet <= 127:
            return True
    return False


def host_is_public(host):
    """True if host is a public IP literal or a known internet domain."""
    if not host:
        return False
    h = host.strip().lower().lstrip("[").rstrip("]")
    if not h:
        return False
    if _is_ip_literal(h):
        return not _is_private_ip(h)
    for pat in AIRGAP_PUBLIC_PATTERNS:
        if h == pat or h.endswith("." + pat):
            return True
    return False


def url_host(url):
    """Bare host from a URL: scheme, credentials, port and path stripped."""
    u = url
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0]
    if "@" in u:
        u = u.rsplit("@", 1)[1]
    if u.startswith("["):
        u = u[1:].split("]", 1)[0]
    else:
        u = u.split(":", 1)[0]
    return u


def run_airgap_checks(s):
    s.banner("AIR-GAP — Network Egress & Bridging")

    # ── AIR-NET-1: default route, read from /proc (works on RHEL 5–10) ────────
    def4, gw_desc = _default_routes_v4()
    def6 = _default_routes_v6()
    if def4 == 0 and def6 == 0:
        s.record("PASS", "AIR-NET-1", "No default route configured",
                 "NETWORK CONFIGURATION",
                 "Host has no default gateway (IPv4/IPv6) — traffic cannot leave "
                 "the local segments by default.", "")
    else:
        s.record("WARN", "AIR-NET-1",
                 "Default route present (IPv4: %d, IPv6: %d)" % (def4, def6),
                 "NETWORK CONFIGURATION",
                 "Default gateway(s): %s. In an isolated enclave confirm this "
                 "gateway cannot forward beyond the enclave boundary."
                 % (gw_desc if gw_desc else "see ip route"),
                 "Verify: ip route show default; remove if not required "
                 "(nmcli con mod <con> ipv4.never-default yes)")

    # ── AIR-NET-2: multi-homed hosts can bridge enclaves ─────────────────────
    ifaces = _active_interfaces()
    nif = len(ifaces)
    if nif <= 1:
        s.record("PASS", "AIR-NET-2",
                 "Single active network interface (%s)" % " ".join(ifaces),
                 "NETWORK CONFIGURATION", "Host is not multi-homed.", "")
    else:
        s.record("WARN", "AIR-NET-2",
                 "Host is multi-homed: %d active interfaces (%s)"
                 % (nif, " ".join(ifaces)),
                 "NETWORK CONFIGURATION",
                 "A host on several networks can bridge an enclave to another "
                 "zone. Confirm each interface is intended and forwarding is off.",
                 "sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding  "
                 "# both must be 0")

    # ── AIR-NET-3: IP forwarding (the bridge itself) ─────────────────────────
    f4 = read_value("/proc/sys/net/ipv4/ip_forward", "0")
    f6 = read_value("/proc/sys/net/ipv6/conf/all/forwarding", "0")
    if f4 == "0" and f6 == "0":
        s.record("PASS", "AIR-NET-3", "IPv4 and IPv6 forwarding disabled",
                 "NETWORK CONFIGURATION",
                 "Host will not route packets between networks.", "")
    else:
        s.record("FAIL", "AIR-NET-3",
                 "Packet forwarding enabled (ipv4=%s, ipv6=%s)" % (f4, f6),
                 "NETWORK CONFIGURATION",
                 "This host can act as a router between the enclave and other "
                 "networks.",
                 "printf 'net.ipv4.ip_forward=0\\nnet.ipv6.conf.all.forwarding=0\\n' "
                 "> /etc/sysctl.d/99-airgap.conf && sysctl --system")

    # ── AIR-DNS-1: resolvers outside the enclave ─────────────────────────────
    all_ns = []
    pub_ns = []
    for line in read_lines("/etc/resolv.conf"):
        m = re.match(r"^\s*nameserver\s+(\S+)", line)
        if m:
            ns = m.group(1)
            all_ns.append(ns)
            if host_is_public(ns):
                pub_ns.append(ns)
    if pub_ns:
        s.record("FAIL", "AIR-DNS-1",
                 "Public DNS resolver(s) configured: %s" % " ".join(pub_ns),
                 "NETWORK CONFIGURATION",
                 "Queries to public resolvers leak hostnames and are a classic "
                 "DNS-tunnel exfiltration path.",
                 "Point /etc/resolv.conf (or NetworkManager ipv4.dns) at internal "
                 "resolvers only")
    elif not all_ns:
        s.record("INFO", "AIR-DNS-1", "No DNS resolvers configured",
                 "NETWORK CONFIGURATION",
                 "No nameserver entries in /etc/resolv.conf (common and acceptable "
                 "in fully isolated hosts).", "")
    else:
        s.record("PASS", "AIR-DNS-1",
                 "Only internal DNS resolvers configured: %s" % " ".join(all_ns),
                 "NETWORK CONFIGURATION",
                 "All nameservers are private addresses.", "")

    # ── AIR-NET-4: proxies, system-wide or for the package manager ──────────
    proxy_paths = ["/etc/environment", "/etc/profile", "/etc/profile.d/*.sh",
                   "/etc/yum.conf", "/etc/dnf/dnf.conf", "/etc/yum.repos.d/*.repo"]
    proxy_rx = re.compile(
        r"^\s*(export\s+)?(https?|ftp|all)_proxy\s*=|^\s*proxy\s*=", re.IGNORECASE)
    proxies = []
    for line in read_lines(proxy_paths):
        if proxy_rx.match(line):
            masked = re.sub(r"(://)[^@/]*@", r"\1***@", " ".join(line.split()))
            if masked not in proxies:
                proxies.append(masked)
    proxies = proxies[:5]
    if not proxies:
        s.record("PASS", "AIR-NET-4",
                 "No system-wide or package-manager proxy configured",
                 "NETWORK CONFIGURATION", "No *_proxy / proxy= settings found.", "")
    else:
        s.record("WARN", "AIR-NET-4", "Proxy configuration present",
                 "NETWORK CONFIGURATION",
                 "Proxy settings found (credentials masked): %s. Confirm the proxy "
                 "is an internal, enclave-scoped service." % (";".join(proxies) + ";"),
                 "Review /etc/environment, /etc/profile.d/, /etc/yum.conf, "
                 "/etc/dnf/dnf.conf")

    s.banner("AIR-GAP — Radios & Covert Channels")

    # ── AIR-RF-1: Wi-Fi hardware/driver ─────────────────────────────────────
    wifi_if = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            base = "/sys/class/net/" + name
            if os.path.isdir(base + "/wireless") or os.path.exists(base + "/phy80211"):
                wifi_if.append(name)
    except OSError:
        pass
    wifi_drivers = ["iwlwifi", "iwlmvm", "iwldvm", "ath9k", "ath10k_pci", "ath11k_pci",
                    "ath12k", "brcmfmac", "b43", "rt2800pci", "rt2800usb", "rtw88_pci",
                    "rtw89_pci", "mt7921e", "mt76", "cfg80211", "mac80211"]
    wifi_mods = [m for m in wifi_drivers if mod_loaded(m)]
    if not wifi_if and not wifi_mods:
        s.record("PASS", "AIR-RF-1", "No Wi-Fi interfaces or drivers loaded",
                 "MEDIA PROTECTION",
                 "No 802.11 interfaces and no wireless stack modules loaded.", "")
    else:
        s.record("FAIL", "AIR-RF-1", "Wi-Fi capability present", "MEDIA PROTECTION",
                 "Interfaces:%s; modules:%s. A radio defeats the air gap."
                 % (" " + " ".join(wifi_if) if wifi_if else " none",
                    " " + " ".join(wifi_mods) if wifi_mods else " none"),
                 "nmcli radio wifi off; blacklist drivers in "
                 "/etc/modprobe.d/airgap.conf (install <mod> /bin/false); remove "
                 "hardware where possible")

    # ── AIR-RF-2: Bluetooth ─────────────────────────────────────────────────
    bt_mods = [m for m in ("bluetooth", "btusb", "btintel", "btrtl", "hci_uart")
               if mod_loaded(m)]
    bt_controllers = bool(glob.glob("/sys/class/bluetooth/*"))
    if not bt_mods and not bt_controllers:
        s.record("PASS", "AIR-RF-2", "No Bluetooth stack loaded", "MEDIA PROTECTION",
                 "No Bluetooth modules or controllers present.", "")
    else:
        detail = " " + " ".join(bt_mods) if bt_mods else " (controller present)"
        s.record("FAIL", "AIR-RF-2", "Bluetooth stack loaded:%s" % detail,
                 "MEDIA PROTECTION",
                 "Bluetooth provides an out-of-band radio channel across the air gap.",
                 "systemctl mask --now bluetooth; echo 'install bluetooth /bin/false' "
                 ">> /etc/modprobe.d/airgap.conf")

    # ── AIR-RF-3: cellular / WWAN modems ────────────────────────────────────
    wwan = [m for m in ("qmi_wwan", "cdc_mbim", "cdc_wdm", "option", "sierra",
                        "sierra_net", "mhi_wwan_ctrl", "wwan") if mod_loaded(m)]
    wwan_desc = " ".join(wwan)
    if glob.glob("/dev/cdc-wdm*") or glob.glob("/dev/wwan*"):
        wwan_desc += " (device nodes present)"
        wwan.append("devnodes")
    if unit_on("ModemManager.service"):
        wwan_desc += " ModemManager"
        wwan.append("ModemManager")
    if not wwan:
        s.record("PASS", "AIR-RF-3", "No cellular/WWAN modem capability",
                 "MEDIA PROTECTION",
                 "No WWAN drivers, device nodes or ModemManager.", "")
    else:
        s.record("FAIL", "AIR-RF-3",
                 "Cellular/WWAN capability present: %s" % wwan_desc.strip(),
                 "MEDIA PROTECTION",
                 "A cellular modem is a direct, unmonitored path to the internet.",
                 "systemctl mask --now ModemManager; blacklist WWAN drivers; "
                 "physically remove the modem")

    # ── AIR-RF-4: USB network adapters / phone tethering ────────────────────
    usbnet = [m for m in ("cdc_ether", "cdc_ncm", "rndis_host", "r8152",
                          "ax88179_178a", "asix", "usbnet", "ipheth")
              if mod_loaded(m)]
    if not usbnet:
        s.record("PASS", "AIR-RF-4", "No USB network / tethering drivers loaded",
                 "MEDIA PROTECTION",
                 "Plugging in a phone or USB NIC has not created a network path.", "")
    else:
        s.record("WARN", "AIR-RF-4",
                 "USB network/tethering drivers loaded: %s" % " ".join(usbnet),
                 "MEDIA PROTECTION",
                 "A tethered phone or USB NIC can silently add an internet uplink.",
                 'Blacklist: for m in cdc_ether rndis_host ipheth r8152; do echo '
                 '"install $m /bin/false"; done >> /etc/modprobe.d/airgap.conf; '
                 'enforce USBGuard')

    # ── AIR-DMA-1: Thunderbolt / FireWire DMA ───────────────────────────────
    dma = []
    for path in sorted(glob.glob("/sys/bus/thunderbolt/devices/domain*/security")):
        sec = read_value(path, "")
        if sec in ("none", "dponly"):
            dma.append("thunderbolt(security=%s)" % sec)
    dma += [m for m in ("firewire_ohci", "ohci1394") if mod_loaded(m)]
    if not dma:
        s.record("PASS", "AIR-DMA-1",
                 "No unauthenticated DMA ports (Thunderbolt/FireWire)",
                 "MEDIA PROTECTION",
                 "No FireWire drivers loaded and Thunderbolt (if any) requires "
                 "authorization.", "")
    else:
        s.record("WARN", "AIR-DMA-1",
                 "DMA-capable port exposure: %s" % " ".join(dma),
                 "MEDIA PROTECTION",
                 "Physical DMA attacks can read memory or inject code without any "
                 "network.",
                 "Set Thunderbolt security to 'user'/'secure' in firmware; blacklist "
                 "firewire_ohci; enable IOMMU (intel_iommu=on / amd_iommu=on)")

    # ── AIR-USB-1: desktop automount of removable media ─────────────────────
    if unit_on("udisks2.service"):
        s.record("WARN", "AIR-USB-1",
                 "udisks2 is running (removable media automount)",
                 "MEDIA PROTECTION",
                 "Removable media can be mounted by users — the main malware/exfil "
                 "path into an air-gapped network.",
                 "systemctl mask --now udisks2   # and enforce USBGuard allow-list")
    else:
        s.record("PASS", "AIR-USB-1", "udisks2 automount not active",
                 "MEDIA PROTECTION",
                 "Removable media is not auto-mounted for users.", "")

    s.banner("AIR-GAP — Phone-Home & Discovery Services")

    svc_list = [
        ("rhsmcertd.service",
         "Red Hat subscription cert checks — contacts RHSM/Satellite"),
        ("insights-client.timer", "Red Hat Insights uploads system data"),
        ("rhcd.service",
         "Remote host configuration daemon (console.redhat.com)"),
        ("dnf-makecache.timer",
         "Periodic repo metadata refresh — fails noisily or reaches outside"),
        ("dnf-automatic.timer",
         "Automatic updates — unreviewed change in a controlled enclave"),
        ("dnf-automatic-install.timer",
         "Automatic updates install without change control"),
        ("yum-cron.service", "Automatic updates (RHEL 7)"),
        ("packagekit.service", "PackageKit background refresh"),
        ("avahi-daemon.service",
         "mDNS/DNS-SD advertises host and services on the LAN"),
        ("cups-browsed.service",
         "Printer discovery — network listener (CVE-2024-47176 class)"),
        ("cloud-init.service", "Fetches instance metadata/user-data at boot"),
        ("geoclue.service", "Geolocation service (Wi-Fi/network lookups)"),
        ("kdump.service", "__KDUMP__"),
    ]
    found = 0
    for unit, why in svc_list:
        if why == "__KDUMP__":
            # kdump is fine locally; only flag it when it ships dumps over the network
            if not unit_on(unit):
                continue
            if not grep_q("/etc/kdump.conf", r"^\s*(ssh|nfs|net)\s"):
                continue
            why = "kdump sends crash dumps (full memory) over the network"
        elif not unit_on(unit):
            continue
        found += 1
        s.record("WARN", "AIR-SVC-" + unit.split(".")[0],
                 "%s is enabled/active" % unit, "CONFIGURATION MANAGEMENT",
                 "%s." % why,
                 "systemctl disable --now %s   # or mask, if not required in the "
                 "enclave" % unit)
    if found == 0:
        s.record("PASS", "AIR-SVC-0",
                 "No phone-home or LAN discovery services active",
                 "CONFIGURATION MANAGEMENT",
                 "None of the known call-home/discovery services are enabled.", "")

    # ── AIR-RHSM-1: subscription-manager pointed at the public CDN ──────────
    if os.access("/etc/rhsm/rhsm.conf", os.R_OK):
        rhsm_host = _ini_value("/etc/rhsm/rhsm.conf", "server", "hostname")
        if rhsm_host and host_is_public(rhsm_host):
            s.record("WARN", "AIR-RHSM-1",
                     "subscription-manager targets public host: %s" % rhsm_host,
                     "CONFIGURATION MANAGEMENT",
                     "Disconnected hosts should register to an internal Satellite "
                     "or use offline manifests.",
                     "subscription-manager config "
                     "--server.hostname=<internal-satellite>  OR  disable rhsmcertd")
        else:
            s.record("PASS", "AIR-RHSM-1",
                     "subscription-manager server is internal (%s)"
                     % (rhsm_host if rhsm_host else "unset"),
                     "CONFIGURATION MANAGEMENT",
                     "RHSM is not configured to reach the public Red Hat CDN.", "")

    s.banner("AIR-GAP — Update Sources & Patch Currency")

    # ── AIR-REPO-1: enabled repositories that point at the internet ─────────
    repos = _parse_repos("/etc/yum.repos.d/*.repo")
    pub_repos = []
    for name, urls in repos:
        for key, val in urls:
            host = url_host(val)
            if key in ("mirrorlist", "metalink") or host_is_public(host):
                pub_repos.append("%s(%s)" % (name, host if host else key))
                break
    if not repos:
        s.record("INFO", "AIR-REPO-1", "No enabled yum/dnf repositories",
                 "SYSTEM INTEGRITY",
                 "No enabled repos with a baseurl/mirrorlist in /etc/yum.repos.d/.", "")
    elif not pub_repos:
        s.record("PASS", "AIR-REPO-1",
                 "All enabled repositories are internal or local media",
                 "SYSTEM INTEGRITY",
                 "No enabled repo references a public mirror, mirrorlist or metalink.",
                 "")
    else:
        s.record("WARN", "AIR-REPO-1",
                 "Enabled repositories point outside the enclave",
                 "SYSTEM INTEGRITY",
                 "Repos: %s. These cannot be reached and cause timeouts; some tools "
                 "may try to fall back to other sources." % " ".join(pub_repos),
                 "dnf config-manager --set-disabled <repo>  and use an internal "
                 "mirror (baseurl=https://mirror.internal/...) or file:///mnt/media")

    # ── AIR-PATCH-1: patch age — the real risk of a disconnected host ───────
    rc, txt = run(["rpm", "-qa", "--qf", "%{INSTALLTIME}\n"], timeout=120)
    times = sorted(t for t in (as_int(l) for l in txt.splitlines()) if t is not None)
    if times:
        newest = times[-1]
        age_days = int((time.time() - newest) // 86400)
        last_pkg = ""
        rc2, txt2 = run(["rpm", "-qa", "--last"], timeout=120)
        for line in txt2.splitlines():
            if line.strip():
                last_pkg = line.split()[0]
                break
        if age_days <= s.max_patch_age:
            s.record("PASS", "AIR-PATCH-1",
                     "Last package change %d day(s) ago" % age_days,
                     "SYSTEM INTEGRITY",
                     "Most recent install/update: %s. Threshold: %d days."
                     % (last_pkg, s.max_patch_age), "")
        elif age_days <= s.max_patch_age * 2:
            s.record("WARN", "AIR-PATCH-1",
                     "No package updates for %d days (threshold %d)"
                     % (age_days, s.max_patch_age),
                     "SYSTEM INTEGRITY",
                     "Most recent change: %s. Air-gapped hosts silently fall behind "
                     "on security errata." % last_pkg,
                     "Import the latest errata via your internal mirror/transfer "
                     "media, then patch")
        else:
            s.record("FAIL", "AIR-PATCH-1",
                     "No package updates for %d days (>2x %d-day threshold)"
                     % (age_days, s.max_patch_age),
                     "SYSTEM INTEGRITY",
                     "Most recent change: %s. The host is likely missing multiple "
                     "critical errata." % last_pkg,
                     "Schedule an offline patch cycle: sync mirror -> transfer -> "
                     "dnf update")
    else:
        s.record("SKIP", "AIR-PATCH-1", "Could not read package install times",
                 "SYSTEM INTEGRITY", "rpm query failed.", "")

    # ── AIR-PATCH-2: running kernel older than newest installed kernel ─────
    run_k = _kernel_release()
    newest_k = ""
    rc, txt = run(["rpm", "-q", "--last", "kernel", "kernel-core", "kernel-uek"],
                  timeout=60)
    for line in txt.splitlines():
        if not line.strip() or "not installed" in line:
            continue
        newest_k = re.sub(r"^kernel(-core|-uek)?-", "", line.split()[0])
        break
    if not newest_k:
        s.record("SKIP", "AIR-PATCH-2", "Could not determine installed kernels",
                 "SYSTEM INTEGRITY", "No kernel package found in rpm DB.", "")
    elif run_k == newest_k:
        s.record("PASS", "AIR-PATCH-2",
                 "Running the newest installed kernel (%s)" % run_k,
                 "SYSTEM INTEGRITY",
                 "No reboot is pending to activate kernel fixes.", "")
    else:
        s.record("WARN", "AIR-PATCH-2",
                 "Reboot pending: running %s, newest installed %s"
                 % (run_k, newest_k),
                 "SYSTEM INTEGRITY",
                 "Kernel security fixes that were imported are not active until "
                 "reboot.",
                 "Schedule a reboot in the next maintenance window")

    s.banner("AIR-GAP — Time, Logging & Tunnels")

    # ── AIR-TIME-1: time sources unreachable from an enclave ───────────────
    srcs = []
    for tconf in (["/etc/chrony.conf"] + sorted(glob.glob("/etc/chrony.d/*.conf"))
                  + ["/etc/ntp.conf"]):
        if not os.access(tconf, os.R_OK):
            continue
        for line in read_lines(tconf):
            m = re.match(r"^\s*(server|pool|peer)\s+(\S+)", line)
            if m:
                srcs.append(m.group(2))
    pub_t = [h for h in srcs if host_is_public(h)]
    if not srcs:
        s.record("WARN", "AIR-TIME-1", "No NTP time sources configured",
                 "AUDIT AND ACCOUNTABILITY",
                 "Without a shared internal time source, log correlation and "
                 "Kerberos break across the enclave.",
                 "Configure an internal stratum source (GPS/PTP appliance or an "
                 "enclave NTP server) in /etc/chrony.conf")
    elif pub_t:
        s.record("WARN", "AIR-TIME-1",
                 "Public/unreachable NTP sources configured: %s" % " ".join(pub_t),
                 "AUDIT AND ACCOUNTABILITY",
                 "Public time pools are unreachable in an enclave; the clock will "
                 "drift.",
                 "Replace with internal time sources in /etc/chrony.conf")
    else:
        s.record("PASS", "AIR-TIME-1",
                 "Time sources are internal: %s" % " ".join(srcs),
                 "AUDIT AND ACCOUNTABILITY", "No public NTP pools referenced.", "")

    # ── AIR-LOG-1: remote log forwarding to public destinations ────────────
    any_log = []
    pub_log = []
    target_rx = re.compile(r'(?:^|\s)@@?(?:\([^)]*\))?([^\s:;]+)|target="([^"]+)"')
    for line in read_lines(["/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf"]):
        if re.match(r"^\s*#", line):
            continue
        for m in target_rx.finditer(line):
            tgt = m.group(1) or m.group(2)
            if not tgt:
                continue
            any_log.append(tgt)
            if host_is_public(tgt):
                pub_log.append(tgt)
    if pub_log:
        s.record("FAIL", "AIR-LOG-1",
                 "Logs forwarded to public destination(s): %s" % " ".join(pub_log),
                 "AUDIT AND ACCOUNTABILITY",
                 "Log forwarding outside the enclave is both an exfiltration "
                 "channel and unreachable.",
                 "Forward to an internal collector only (rsyslog action target=)")
    else:
        s.record("INFO", "AIR-LOG-1",
                 "Remote log destinations:%s"
                 % (" " + " ".join(any_log) if any_log else " none"),
                 "AUDIT AND ACCOUNTABILITY",
                 "No public log destinations. Local-only logging needs a documented "
                 "offline collection process.", "")

    # ── AIR-SSH-1: SSH tunnelling features that can bridge enclaves ────────
    if have("sshd") or os.access("/etc/ssh/sshd_config", os.R_OK):
        conf = dict(sshd_effective())
        if not conf:
            conf = _sshd_config_with_defaults()
        on_feats = []
        for key in ("allowtcpforwarding", "permittunnel", "gatewayports",
                    "x11forwarding", "allowagentforwarding",
                    "allowstreamlocalforwarding"):
            val = (conf.get(key) or "").split()
            val = val[0].lower() if val else ""
            if val and val != "no":
                on_feats.append("%s=%s" % (key, val))
        if not on_feats:
            s.record("PASS", "AIR-SSH-1", "SSH forwarding/tunnelling disabled",
                     "ACCESS CONTROL",
                     "TCP/agent/stream/X11 forwarding, tunnels and gateway ports "
                     "are off.", "")
        else:
            s.record("WARN", "AIR-SSH-1",
                     "SSH forwarding/tunnelling enabled: %s" % " ".join(on_feats),
                     "ACCESS CONTROL",
                     "SSH port forwarding and tunnels let a single allowed SSH "
                     "session pivot traffic across enclave boundaries.",
                     "In sshd_config: AllowTcpForwarding no, AllowAgentForwarding "
                     "no, AllowStreamLocalForwarding no, PermitTunnel no, "
                     "GatewayPorts no, X11Forwarding no")

    if not s.quiet:
        _p("%s[PASS]%s Air-gap isolation checks complete." % (GREEN, RESET))


# ─────────────────────────────────────────────────────────────────────────────
# AIR-GAP HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _default_routes_v4():
    """(count, 'a.b.c.d (iface) ...') from /proc/net/route — no `ip` needed."""
    txt = read_text("/proc/net/route")
    if txt is None:
        return 0, ""
    count = 0
    gateways = []
    for line in txt.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        if f[1] == "00000000" and f[7] == "00000000":
            count += 1
        if f[1] == "00000000":
            gateways.append("%s (%s)" % (_hex_le_to_ip(f[2]), f[0]))
    return count, " ".join(gateways)


def _hex_le_to_ip(hexstr):
    """/proc/net/route stores addresses little-endian hex."""
    try:
        octets = [int(hexstr[i:i + 2], 16) for i in range(0, 8, 2)]
    except (ValueError, IndexError):
        return "0.0.0.0"
    return "%d.%d.%d.%d" % (octets[3], octets[2], octets[1], octets[0])


def _default_routes_v6():
    txt = read_text("/proc/net/ipv6_route")
    if txt is None:
        return 0
    count = 0
    for line in txt.splitlines():
        f = line.split()
        if len(f) < 10:
            continue
        if f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
            count += 1
    return count


_SKIP_IFACE_RX = re.compile(
    r"^(lo|virbr[0-9]+-nic|docker[0-9]*|podman[0-9]*|cni.*|veth.*)$")


def _active_interfaces():
    names = []
    try:
        entries = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return names
    for name in entries:
        if _SKIP_IFACE_RX.match(name):
            continue
        if read_value("/sys/class/net/%s/operstate" % name, "") == "up":
            names.append(name)
    return names


def _ini_value(path, section, key):
    """First `key` inside [section] of an INI file."""
    in_section = False
    key_rx = re.compile(r"^\s*" + re.escape(key) + r"\s*=(.*)$", re.IGNORECASE)
    for line in read_lines(path):
        m = re.match(r"^\s*\[([^\]]+)\]", line)
        if m:
            in_section = m.group(1).strip().lower() == section.lower()
            continue
        if not in_section:
            continue
        m = key_rx.match(line)
        if m:
            return re.sub(r"\s+", "", m.group(1))
    return ""


def _parse_repos(pattern):
    """[(repo_name, [(key, url), ...]), ...] for ENABLED repos that define a URL."""
    repos = []
    for path in sorted(glob.glob(pattern)):
        section = None
        enabled = True
        urls = []

        def flush():
            if section and enabled and urls:
                repos.append((section, list(urls)))

        for line in read_lines(path):
            m = re.match(r"^\s*\[([^\]]*)\]", line)
            if m:
                flush()
                section = re.sub(r"[\[\]\s]", "", m.group(0))
                enabled = True
                urls = []
                continue
            m = re.match(r"^\s*enabled\s*=\s*(\S*)", line)
            if m:
                enabled = m.group(1).strip() in ("1", "true", "yes")
                continue
            m = re.match(r"^\s*(baseurl|mirrorlist|metalink)\s*=\s*(.*?)\s*$", line)
            if m:
                urls.append((m.group(1), m.group(2)))
        flush()
    return repos


def _sshd_config_with_defaults():
    """Parse sshd_config like sshd does (first match wins), applying OpenSSH defaults."""
    seen = {}
    paths = sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")) + ["/etc/ssh/sshd_config"]
    for line in read_lines(paths):
        if re.match(r"^\s*[Mm]atch\b", line):
            break
        if re.match(r"^\s*#", line):
            continue
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0].lower()
            if key not in seen:
                seen[key] = parts[1].lower()
    defaults = {"allowtcpforwarding": "yes", "permittunnel": "no",
                "gatewayports": "no", "x11forwarding": "no",
                "allowagentforwarding": "yes", "allowstreamlocalforwarding": "yes"}
    for key, val in defaults.items():
        seen.setdefault(key, val)
    return seen


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
def _esc_html(value):
    return (str(value)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _esc_html_br(value):
    return _esc_html(value).replace("\n", "<br>")


def _compact(obj):
    """One-line JSON with no space after ':'.

    The README documents `grep '"status":"FAIL"' RHELGuard_*.json` for enclaves
    with no jq, and json.dumps' default separators insert a space that breaks it.
    This also keeps the two engines' result lines byte-comparable.
    """
    return json.dumps(obj, sort_keys=False, separators=(",", ":"))


def _report_base(s):
    return "%s_%s_%s" % (TOOL_NAME, s.hostname, s.report_ts)


def _open_report(path):
    """Reports describe your weaknesses — create them 0600."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return io.open(fd, "w", encoding="utf-8", newline="\n")


def generate_json_report(s):
    jfile = os.path.join(s.output_dir, _report_base(s) + ".json")
    elapsed = int(time.time() - s.start_ts)

    head = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "engine": ENGINE,
        "script_sha256": s.script_sha256,
        "hostname": s.hostname,
        "scan_date": _iso_now(),
        "os": s.rhel_full,
        "rhel_major": s.rhel_major,
        "os_family": s.os_family,
        "kernel": _kernel_release(),
        "scan_mode": s.scan_mode,
        "run_as_root": s.is_root,
        "duration_seconds": elapsed,
        "baseline": os.path.basename(s.baseline_file) if s.baseline_file else "",
        "waiver_file": os.path.basename(s.waiver_file) if s.waiver_file else "",
        "summary": {
            "total": s.total,
            "pass": s.counts["PASS"],
            "fail": s.counts["FAIL"],
            "warn": s.counts["WARN"],
            "info": s.counts["INFO"],
            "skip": s.counts["SKIP"],
            "waived": s.counts["WAIVED"],
            "priv_skip": s.priv_skip,
            "compliance_pct": s.compliance_pct(),
            "compliance_formula": "pass/(pass+fail+warn)",
            "drift_new_or_regressed": s.drift_new_fail,
            "drift_fixed": s.drift_fixed,
        },
    }

    # One result per line is intentional: grep/awk/baseline friendly, exactly
    # like the shell engine, so `grep '"status":"FAIL"' report.json` still works.
    with _open_report(jfile) as fh:
        fh.write("{\n")
        for key in ("tool", "version", "engine", "script_sha256", "hostname",
                    "scan_date", "os", "rhel_major", "os_family", "kernel",
                    "scan_mode", "run_as_root", "duration_seconds", "baseline",
                    "waiver_file"):
            fh.write('  "%s": %s,\n' % (key, json.dumps(head[key])))
        fh.write('  "summary": {\n')
        summary_keys = list(head["summary"].keys())
        for i, key in enumerate(summary_keys):
            comma = "," if i < len(summary_keys) - 1 else ""
            fh.write('    "%s": %s%s\n' % (key, json.dumps(head["summary"][key]), comma))
        fh.write("  },\n")
        fh.write('  "drift": [\n')
        for i, d in enumerate(s.drift):
            prefix = "    " if i == 0 else "   ,"
            fh.write("%s%s\n" % (prefix, _compact(d)))
        fh.write("  ],\n")
        fh.write('  "results": [\n')
        for i, r in enumerate(s.results):
            prefix = "    " if i == 0 else "   ,"
            fh.write("%s%s\n" % (prefix, _compact(r)))
        fh.write("  ]\n}\n")
    return jfile


def generate_csv_report(s):
    cfile = os.path.join(s.output_dir, _report_base(s) + ".csv")
    with _open_report(cfile) as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(["id", "status", "category", "title", "description",
                         "remediation"])
        for r in s.results:
            writer.writerow([_csv_safe(r["id"]), _csv_safe(r["status"]),
                             _csv_safe(r["category"]), _csv_safe(r["title"]),
                             _csv_safe(r["description"]),
                             _csv_safe(r["remediation"])])
    return cfile


def _csv_safe(value):
    """Collapse newlines and defuse spreadsheet formula injection."""
    text = re.sub(r"[\r\n]+", " ", str(value))
    if text[:1] in ("=", "+", "@", "-"):
        text = "'" + text
    return text


HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Air-gap safe: the report can never load or send anything over the network -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; \
style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; \
base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<style>
:root{--pass:#27ae60;--fail:#e74c3c;--warn:#f39c12;--info:#3498db;--skip:#7f8c8d;
  --bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#1f6feb;--head:#21262d}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:20px;font-size:14px}
a{color:var(--accent);text-decoration:none}
/* ── Header ── */
.header{display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.logo{font-size:2rem;font-weight:900;letter-spacing:-1px;
  background:linear-gradient(135deg,#e94560,#f39c12);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header-meta{font-size:.8rem;color:#8b949e;line-height:1.7}
.header-meta strong{color:var(--text)}
/* ── Score ── */
.score-row{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.score-card{background:var(--head);border:1px solid var(--border);border-radius:12px;
  padding:20px 28px;display:flex;align-items:center;gap:20px;flex:1;min-width:260px}
.score-circle{width:80px;height:80px;border-radius:50%;border:5px solid #e74c3c;
  display:flex;align-items:center;justify-content:center;font-size:1.3rem;font-weight:700;color:#e74c3c;flex-shrink:0}
.score-detail h2{font-size:1rem;font-weight:600;color:var(--text)}
.score-detail p{font-size:.8rem;color:#8b949e;margin-top:4px}
/* ── Summary Cards ── */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--head);border:1px solid var(--border);border-radius:10px;padding:14px;text-align:center}
.card .num{font-size:2rem;font-weight:700}
.card .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:#8b949e;margin-top:2px}
/* ── Version badge ── */
.ver-badge{display:inline-block;background:var(--accent);color:#fff;font-size:.75rem;
  padding:3px 10px;border-radius:20px;font-weight:600;margin-bottom:20px}
/* ── Controls ── */
.controls{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;align-items:center}
.search{flex:1;min-width:200px;padding:8px 12px;border-radius:6px;
  background:var(--head);border:1px solid var(--border);color:var(--text);font-size:.85rem}
.filter-btn{padding:6px 14px;border-radius:20px;border:none;cursor:pointer;
  font-size:.78rem;font-weight:600;transition:opacity .15s;opacity:.7}
.filter-btn:hover,.filter-btn.active{opacity:1}
.fb-all{background:#484f58;color:#fff}
.fb-PASS{background:var(--pass);color:#fff}
.fb-FAIL{background:var(--fail);color:#fff}
.fb-WARN{background:var(--warn);color:#000}
.fb-INFO{background:var(--info);color:#fff}
.fb-SKIP{background:var(--skip);color:#fff}
/* ── Table ── */
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{background:var(--head);border-bottom:1px solid var(--border);padding:10px 12px;text-align:left;font-weight:600;color:#8b949e;text-transform:uppercase;font-size:.72rem;letter-spacing:.5px}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:700;font-size:.7rem;white-space:nowrap}
.b-PASS{background:var(--pass);color:#fff}.b-FAIL{background:var(--fail);color:#fff}
.b-WARN{background:var(--warn);color:#000}.b-INFO{background:var(--info);color:#fff}
.b-SKIP{background:var(--skip);color:#fff}
.id-cell{font-family:monospace;font-size:.78rem;color:#79c0ff;white-space:nowrap}
.rem{font-size:.75rem;color:#f39c12;margin-top:4px;font-family:monospace;background:rgba(243,156,18,.08);
  padding:3px 8px;border-radius:4px;display:inline-block}
/* ── Progress bar ── */
.prog-bar{height:8px;background:var(--border);border-radius:4px;overflow:hidden;margin-bottom:20px}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--fail) 0%,var(--warn) 50%,var(--pass) 100%);
  transition:width 1s ease}
/* ── Priv warning ── */
.priv-warn{background:rgba(243,156,18,.12);border:1px solid var(--warn);border-radius:8px;
  padding:12px 16px;margin-bottom:20px;font-size:.85rem;color:var(--warn)}
footer{margin-top:30px;font-size:.72rem;color:#484f58;text-align:center;padding:10px}
.b-WAIVED{background:#8e44ad;color:#fff}.fb-WAIVED{background:#8e44ad;color:#fff}
.desc{color:#8b949e}
.drift{background:var(--head);border:1px solid var(--border);border-radius:10px;padding:14px 18px;margin-bottom:20px}
.drift h3{font-size:.9rem;margin-bottom:8px}
.drift td{padding:5px 10px}
.d-REGRESSED,.d-NEW{color:var(--fail);font-weight:700}.d-FIXED{color:var(--pass);font-weight:700}.d-CHANGED{color:var(--warn)}
.sha{font-family:monospace;font-size:.72rem;color:#8b949e;word-break:break-all}
@media print{body{background:#fff;color:#000}.controls{display:none}}
</style>
"""

HTML_SCRIPT = """
<script>
var cur='all';
function sf(f){
  cur=f;
  var b=document.querySelectorAll('.filter-btn');
  for(var i=0;i<b.length;i++) b[i].classList.remove('active');
  document.querySelector('.fb-'+f).classList.add('active');
  ft();
}
function ft(){
  var q=document.getElementById('srch').value.toLowerCase();
  var r=document.querySelectorAll('#tb tr');
  for(var i=0;i<r.length;i++){
    var sm=cur==='all'||r[i].getAttribute('data-s')===cur;
    var tm=!q||r[i].textContent.toLowerCase().indexOf(q)>-1;
    r[i].style.display=(sm&&tm)?'':'none';
  }
}
</script>
</body>
</html>
"""


def generate_html_report(s):
    hfile = os.path.join(s.output_dir, _report_base(s) + ".html")
    cpct = s.compliance_pct()
    elapsed = int(time.time() - s.start_ts)
    c = s.counts

    score_color = "#e74c3c"
    if cpct >= 80:
        score_color = "#27ae60"
    elif cpct >= 60:
        score_color = "#f39c12"

    h_host = _esc_html(s.hostname)
    h_os = _esc_html(s.rhel_full)
    h_kernel = _esc_html(_kernel_release())
    h_mode = _esc_html(s.scan_mode)
    h_sha = _esc_html(s.script_sha256)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()

    parts = [HTML_HEAD]
    parts.append("<title>RHELGuard — %s — %s</title>\n</head>\n<body>\n\n"
                 % (h_host, s.report_ts))
    parts.append('<div class="header">\n'
                 '  <div class="logo">RHELGuard</div>\n'
                 '  <div class="header-meta">\n'
                 '    <div>🖥️ <strong>%s</strong> &nbsp;|&nbsp; 📅 <strong>%s</strong></div>\n'
                 '    <div>🐧 <strong>%s</strong> &nbsp;|&nbsp; 🔧 Kernel <strong>%s</strong></div>\n'
                 '    <div>⚙️ Mode: <strong>%s</strong> &nbsp;|&nbsp; 🔑 Root: <strong>%s</strong>'
                 ' &nbsp;|&nbsp; 🐍 Engine: <strong>%s</strong>'
                 ' &nbsp;|&nbsp; ⏱ %ds &nbsp;|&nbsp; v%s</div>\n'
                 '    <div class="sha">script sha256: %s</div>\n'
                 '  </div>\n</div>\n'
                 % (h_host, _esc_html(now_str), h_os, h_kernel, h_mode,
                    str(s.is_root).lower(), ENGINE, elapsed, TOOL_VERSION, h_sha))

    if not s.is_root:
        parts.append('<div class="priv-warn">⚠️ &nbsp;<strong>Non-root scan</strong> — '
                     '%d privileged checks were skipped. Re-run with '
                     '<code>sudo python3 rhelguard.py</code> for full coverage.</div>\n'
                     % s.priv_skip)

    parts.append('<div class="score-row">\n  <div class="score-card">\n'
                 '    <div class="score-circle" style="border-color:%s;color:%s">%s%%</div>\n'
                 '    <div class="score-detail">\n'
                 '      <h2>Compliance Score</h2>\n'
                 '      <p>%d passed · %d failed · %d warnings · %d waived · %d skipped</p>\n'
                 '      <p style="margin-top:8px;color:#8b949e">Score = pass ÷ '
                 '(pass + fail + warn) · %d checks total</p>\n'
                 '    </div>\n  </div>\n</div>\n\n'
                 % (score_color, score_color, cpct, c["PASS"], c["FAIL"], c["WARN"],
                    c["WAIVED"], c["SKIP"], s.total))

    parts.append('<div class="prog-bar"><div class="prog-fill" style="width:%s%%">'
                 '</div></div>\n\n' % cpct)

    parts.append('<div class="cards">\n')
    for label, num, color in (("Pass", c["PASS"], "var(--pass)"),
                              ("Fail", c["FAIL"], "var(--fail)"),
                              ("Warn", c["WARN"], "var(--warn)"),
                              ("Waived", c["WAIVED"], "#8e44ad"),
                              ("Info", c["INFO"], "var(--info)"),
                              ("Skip", c["SKIP"], "var(--skip)")):
        parts.append('  <div class="card"><div class="num" style="color:%s">%d</div>'
                     '<div class="lbl">%s</div></div>\n' % (color, num, label))
    parts.append('  <div class="card"><div class="num">%d</div>'
                 '<div class="lbl">Total</div></div>\n</div>\n' % s.total)

    if s.baseline_file:
        parts.append('<div class="drift"><h3>📈 Drift since baseline <code>%s</code> — '
                     '%d new/regressed · %d fixed · %d changed</h3>'
                     % (_esc_html(os.path.basename(s.baseline_file)),
                        s.drift_new_fail, s.drift_fixed, s.drift_changed))
        if s.drift:
            parts.append('<table><thead><tr><th>Change</th><th>Check ID</th>'
                         '<th>From</th><th>To</th><th>Title</th></tr></thead><tbody>')
            for d in s.drift:
                parts.append('<tr><td class="d-%s">%s</td><td class="id-cell">%s</td>'
                             '<td>%s</td><td>%s</td><td>%s</td></tr>\n'
                             % (_esc_html(d["change"]), _esc_html(d["change"]),
                                _esc_html(d["id"]), _esc_html(d["from"]),
                                _esc_html(d["to"]), _esc_html(d["title"])))
            parts.append("</tbody></table>")
        else:
            parts.append("<p>No changes.</p>")
        parts.append("</div>\n")

    parts.append('<div class="controls">\n'
                 '  <input class="search" type="text" id="srch" '
                 'placeholder="🔍 Search checks..." onkeyup="ft()">\n'
                 '  <button class="filter-btn fb-all active" onclick="sf(\'all\')">All (%d)</button>\n'
                 '  <button class="filter-btn fb-FAIL" onclick="sf(\'FAIL\')">Fail (%d)</button>\n'
                 '  <button class="filter-btn fb-WARN" onclick="sf(\'WARN\')">Warn (%d)</button>\n'
                 '  <button class="filter-btn fb-PASS" onclick="sf(\'PASS\')">Pass (%d)</button>\n'
                 '  <button class="filter-btn fb-WAIVED" onclick="sf(\'WAIVED\')">Waived (%d)</button>\n'
                 '  <button class="filter-btn fb-INFO" onclick="sf(\'INFO\')">Info (%d)</button>\n'
                 '  <button class="filter-btn fb-SKIP" onclick="sf(\'SKIP\')">Skip (%d)</button>\n'
                 '</div>\n\n'
                 % (s.total, c["FAIL"], c["WARN"], c["PASS"], c["WAIVED"],
                    c["INFO"], c["SKIP"]))

    parts.append('<table id="t">\n  <thead><tr>\n'
                 '    <th style="width:70px">Status</th>\n'
                 '    <th style="width:150px">Check ID</th>\n'
                 '    <th style="width:160px">Category</th>\n'
                 '    <th>Finding &amp; Remediation</th>\n'
                 '  </tr></thead>\n  <tbody id="tb">\n')

    for r in s.results:
        rem = ""
        if r["remediation"] and r["remediation"] != "N/A":
            rem = '<div class="rem">&#128295; %s</div>' % _esc_html_br(r["remediation"])
        parts.append('<tr data-s="%s"><td><span class="badge b-%s">%s</span></td>'
                     '<td class="id-cell">%s</td><td>%s</td><td><strong>%s</strong>'
                     '<br><small class="desc">%s</small>%s</td></tr>\n'
                     % (_esc_html(r["status"]), _esc_html(r["status"]),
                        _esc_html(r["status"]), _esc_html(r["id"]),
                        _esc_html(r["category"]), _esc_html_br(r["title"]),
                        _esc_html_br(r["description"]), rem))

    parts.append('  </tbody>\n</table>\n\n<footer>\n  %s v%s (%s engine) &nbsp;·&nbsp;\n'
                 '  CIS RHEL 5–10 + DISA STIG (RHEL 6–9) + Built-in Hardening + '
                 'Air-gap Isolation &nbsp;·&nbsp;\n  Generated %s &nbsp;·&nbsp;\n'
                 '  For authorised security testing only\n</footer>\n'
                 % (TOOL_NAME, TOOL_VERSION, ENGINE, _esc_html(now_str)))
    parts.append(HTML_SCRIPT)

    with _open_report(hfile) as fh:
        fh.write("".join(parts))
    return hfile


# ─────────────────────────────────────────────────────────────────────────────
# TRANSFER BUNDLE — for carrying results across the air gap (sneakernet)
# Produces <name>.tar.gz with the reports + MANIFEST.txt + SHA256SUMS, and
# prints the bundle's own SHA-256 to record in the media transfer log.
# ─────────────────────────────────────────────────────────────────────────────
def generate_bundle(s, files):
    base = _report_base(s)
    stage = os.path.join(s.output_dir, "." + base + "_bundle")
    inner = os.path.join(stage, base)
    try:
        os.makedirs(inner, exist_ok=True)
        for src in files:
            shutil.copy2(src, inner)

        operator = out(["id", "-un"]) or str(os.geteuid())
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            operator += " (sudo from %s)" % sudo_user

        manifest = os.path.join(inner, "MANIFEST.txt")
        with _open_report(manifest) as fh:
            fh.write("tool=%s\n" % TOOL_NAME)
            fh.write("version=%s\n" % TOOL_VERSION)
            fh.write("engine=%s\n" % ENGINE)
            fh.write("script_sha256=%s\n" % s.script_sha256)
            fh.write("hostname=%s\n" % s.hostname)
            fh.write("os=%s\n" % s.rhel_full)
            fh.write("kernel=%s\n" % _kernel_release())
            fh.write("run_as_root=%s\n" % str(s.is_root).lower())
            fh.write("operator=%s\n" % operator)
            fh.write("created=%s\n" % _iso_now())
            fh.write("summary=pass:%d fail:%d warn:%d waived:%d info:%d skip:%d\n"
                     % (s.counts["PASS"], s.counts["FAIL"], s.counts["WARN"],
                        s.counts["WAIVED"], s.counts["INFO"], s.counts["SKIP"]))

        sums = os.path.join(inner, "SHA256SUMS")
        with _open_report(sums) as fh:
            for name in sorted(os.listdir(inner)):
                if name == "SHA256SUMS":
                    continue
                fh.write("%s  %s\n" % (_sha256_file(os.path.join(inner, name)), name))

        tarball = os.path.join(s.output_dir, base + ".tar.gz")
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(inner, arcname=base)
        return tarball
    except (OSError, IOError, tarfile.TarError):
        return None
    finally:
        shutil.rmtree(stage, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
EPILOG = """
examples:
  sudo python3 rhelguard.py                     full scan, all frameworks
  sudo python3 rhelguard.py -m cis -o /var/log/rhelguard
  sudo python3 rhelguard.py -m stig -t 200      higher throttle for busy hosts
  python3 rhelguard.py                          non-root partial scan
  sudo python3 rhelguard.py -m airgap           air-gap isolation checks only
  sudo python3 rhelguard.py -b last.json -w waivers.txt -B --strict

exit codes:
  0  scan completed      1  usage/setup error      2  FAILs present (--strict only)
"""


class _ArgParser(argparse.ArgumentParser):
    """Exit 1 on a usage error.

    argparse's default is 2, which this tool already uses to mean "FAILs are
    present" under --strict. A CI job checking for 2 must not confuse a typo in
    the command line with a failed compliance gate.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("%s: error: %s\n" % (self.prog, message))
        sys.exit(1)


def parse_args(argv):
    parser = _ArgParser(
        prog="rhelguard.py",
        description="%s v%s — RHEL security audit (CIS + DISA STIG + hardening + "
                    "air-gap). Read-only, air-gap safe, standard library only."
                    % (TOOL_NAME, TOOL_VERSION),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-m", "--mode", default="all",
                        choices=["cis", "stig", "posture", "airgap", "all"],
                        help="which framework(s) to run (default: all)")
    parser.add_argument("-o", "--output", default="./rhelguard_reports",
                        metavar="DIR", help="output directory")
    parser.add_argument("-t", "--throttle", type=int, default=50, metavar="MS",
                        help="milliseconds to pause between checks (default: 50)")
    parser.add_argument("-b", "--baseline", default="", metavar="FILE",
                        help="previous RHELGuard JSON — report drift since then")
    parser.add_argument("-w", "--waivers", default="", metavar="FILE",
                        help='accepted deviations, one "CHECK-ID | reason" per line')
    parser.add_argument("-a", "--max-patch-age", type=int, default=90, metavar="DAYS",
                        help="days since last package change before flagging")
    parser.add_argument("-B", "--bundle", action="store_true",
                        help="pack reports + MANIFEST + SHA256SUMS into a .tar.gz")
    parser.add_argument("--strict", action="store_true",
                        help="exit 2 if any FAIL remains (CI / automation)")
    parser.add_argument("-s", "--skip-lynis", action="store_true",
                        help="no-op, kept for backward compatibility")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress per-check output (summary still printed)")
    parser.add_argument("-V", "--version", action="version",
                        version="%s %s (%s engine)" % (TOOL_NAME, TOOL_VERSION, ENGINE))

    args = parser.parse_args(argv)

    if args.throttle < 0:
        parser.error("Invalid --throttle: %s (must be >= 0)" % args.throttle)
    if args.max_patch_age < 0:
        parser.error("Invalid --max-patch-age: %s (must be >= 0)" % args.max_patch_age)
    if args.baseline and not os.access(args.baseline, os.R_OK):
        parser.error("Baseline not readable: %s" % args.baseline)
    if args.waivers and not os.access(args.waivers, os.R_OK):
        parser.error("Waiver file not readable: %s" % args.waivers)
    return args


ASCII_LOGO = r"""
  ██████╗ ██╗  ██╗███████╗██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██╔════╝██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║█████╗  ██║     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔══██╗██╔══██║██╔══╝  ██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║  ██║██║  ██║███████╗███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""


def main(argv=None):
    os.umask(0o077)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    s = Scanner(args)
    s.preflight()

    if not s.quiet:
        _p("\n%s%s%s%s" % (BOLD, CYAN, ASCII_LOGO, RESET))
        _p("  %sv%s%s · RHEL 5–10 · CIS + DISA STIG + Hardening + Air-gap · "
           "%s%s%s (RHEL %s)\n"
           % (BOLD, TOOL_VERSION, RESET, CYAN, s.hostname, RESET, s.rhel_major))

    if args.mode == "cis":
        run_cis_checks(s)
    elif args.mode == "stig":
        run_stig_checks(s)
    elif args.mode == "posture":
        run_posture_checks(s)
        run_hardening_scan(s)
    elif args.mode == "airgap":
        run_airgap_checks(s)
    else:
        run_cis_checks(s)
        run_stig_checks(s)
        run_posture_checks(s)
        run_hardening_scan(s)
        run_airgap_checks(s)

    s.compute_drift()

    # ── Summary (always printed, even with -q) ──────────────────────────────
    cpct = s.compliance_pct()
    elapsed = int(time.time() - s.start_ts)
    c = s.counts

    _p("")
    _p("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s" % (BOLD, CYAN, RESET))
    _p("%s  SCAN COMPLETE  %ds  |  RHEL %s  |  %s%s"
       % (BOLD, elapsed, s.rhel_major, s.hostname, RESET))
    _p("%s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s" % (BOLD, CYAN, RESET))
    _p("  %s%-10s%s%d" % (GREEN, "PASS", RESET, c["PASS"]))
    _p("  %s%-10s%s%d" % (RED, "FAIL", RESET, c["FAIL"]))
    _p("  %s%-10s%s%d" % (YELLOW, "WARN", RESET, c["WARN"]))
    _p("  %s%-10s%s%d" % (MAGENTA, "WAIVED", RESET, c["WAIVED"]))
    _p("  %s%-10s%s%d" % (CYAN, "INFO", RESET, c["INFO"]))
    _p("  %-10s%d" % ("SKIP", c["SKIP"]))
    if not s.is_root:
        _p("  %s%-10s%s%d  (re-run as root for full coverage)"
           % (YELLOW, "PRIV-SKIP", RESET, s.priv_skip))
    _p("  %-10s%d" % ("TOTAL", s.total))
    _p("  %sCompliance Score : %s%%%s  (pass / (pass+fail+warn))" % (BOLD, cpct, RESET))
    if s.baseline_file:
        _p("  %sDrift            : %s%d new/regressed%s%s · %s%d fixed%s"
           % (BOLD, RED, s.drift_new_fail, RESET, BOLD, GREEN, s.drift_fixed, RESET))
        for d in [x for x in s.drift if x["change"] in ("NEW", "REGRESSED")][:15]:
            _p("      %-10s %-28s %s -> %s"
               % (d["change"], d["id"], d["from"], d["to"]))
    _p("")

    s.log("Generating reports...")
    jout = generate_json_report(s)
    hout = generate_html_report(s)
    cout = generate_csv_report(s)

    _p("  📄 JSON   → %s%s%s" % (CYAN, jout, RESET))
    _p("  🌐 HTML   → %s%s%s" % (CYAN, hout, RESET))
    _p("  📊 CSV    → %s%s%s" % (CYAN, cout, RESET))

    if s.bundle:
        bout = generate_bundle(s, [jout, hout, cout])
        if bout:
            _p("  📦 BUNDLE → %s%s%s" % (CYAN, bout, RESET))
            _p("     sha256: %s   <- record this in your media transfer log"
               % _sha256_file(bout))
        else:
            _p("  %sBundle could not be created (write error).%s" % (YELLOW, RESET))
    _p("")
    if not s.quiet:
        _p("  %s%sDone. Open the HTML report for full details.%s\n"
           % (GREEN, BOLD, RESET))

    if s.strict and c["FAIL"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _p("\nInterrupted — no report written.")
        sys.exit(1)
