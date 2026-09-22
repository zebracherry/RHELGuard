#!/usr/bin/env bash
# =============================================================================
#  ██████╗ ██╗  ██╗███████╗██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
#  ██╔══██╗██║  ██║██╔════╝██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
#  ██████╔╝███████║█████╗  ██║     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
#  ██╔══██╗██╔══██║██╔══╝  ██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
#  ██║  ██║██║  ██║███████╗███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
#  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
#
#  RHELGuard — Red Hat Enterprise Linux Security Audit Tool
#  Version : 2.2.0
#  Covers  : RHEL 5, 6, 7, 8, 9, 10 (auto-detected)
#  Sources : CIS Benchmarks (L1/L2) + DISA STIG v2 + Lynis-style posture
#  License : MIT
# =============================================================================
# USAGE:
#         ./rhelguard.sh [OPTIONS]           # non-root: partial scan
#   sudo  ./rhelguard.sh [OPTIONS]           # full scan (recommended)
#
# OPTIONS:
#   -m, --mode       cis | stig | posture | airgap | all  (default: all)
#   -o, --output     Output directory             (default: ./rhelguard_reports)
#   -t, --throttle   ms between checks            (default: 50)
#   -b, --baseline   Previous RHELGuard JSON — report drift since then
#   -w, --waivers    Waiver file: "CHECK-ID | reason" per line
#   -a, --max-patch-age  Days before patch age is flagged     (default: 90)
#   -B, --bundle     Pack reports + SHA256SUMS + manifest into a tar.gz
#       --strict     Exit code 2 if any FAIL remains (for automation)
#   -s, --skip-lynis No-op (kept for backward compatibility)
#   -q, --quiet      Suppress per-check console output
#   -h, --help       Show this help
#
# PRODUCTION SAFE:
#   - 100% read-only. Zero system modifications.
#   - Configurable throttle prevents I/O spikes on busy hosts.
#   - Non-root mode: skips privileged checks cleanly, runs everything else.
#   - No network probing, no port scanning, no package installs.
#   - AIR-GAP SAFE: zero external dependencies — pure bash + standard RHEL tools
#     (awk, sed, grep, find, stat, rpm). No python3, no bc, no curl needed.
#   - Reports are written with umask 077 (they describe your weaknesses).
# =============================================================================

# NOTE: deliberately NOT using `set -e` / `pipefail`. Under those options any
# benign non-zero status (find hitting a permission-denied dir as non-root,
# grep -c matching nothing, [[ ]] false in quiet mode) aborted the whole scan
# with no report. Every check handles its own errors instead.
set +e
umask 077

# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────────────────────
readonly TOOL_NAME="RHELGuard"
readonly TOOL_VERSION="2.2.0"
SCAN_MODE="all"
OUTPUT_DIR="./rhelguard_reports"
THROTTLE_MS=50
QUIET=false
BASELINE_FILE=""      # previous JSON report for drift comparison
WAIVER_FILE=""        # accepted deviations: "ID | reason"
WAIVER_DATA=""        # loaded waiver lines
MAX_PATCH_AGE=90      # days
BUNDLE=false
STRICT=false
SEEN_IDS="|"          # used to guarantee unique check IDs (bash 3.2 safe, no assoc arrays)
SCRIPT_PATH="$0"
SCRIPT_SHA256="unavailable"
DRIFT_NEW_FAIL=0; DRIFT_FIXED=0; DRIFT_CHANGED=0
START_TS=$(date +%s)
REPORT_TS=$(date +"%Y%m%d_%H%M%S")
HOSTNAME_VAL=$(hostname -s 2>/dev/null || echo "unknown")

# Privilege flag — set once, used everywhere
IS_ROOT=false
[[ $EUID -eq 0 ]] && IS_ROOT=true

# Counters
PASS=0; FAIL=0; WARN=0; INFO=0; SKIP=0; WAIVED=0; TOTAL=0; PRIV_SKIP=0

# Results written line-by-line as JSON objects to a temp file
RESULTS_FILE=$(mktemp /tmp/rhelguard_results.XXXXXX)
HTML_ROWS_FILE=$(mktemp /tmp/rhelguard_rows.XXXXXX)
CSV_ROWS_FILE=$(mktemp /tmp/rhelguard_csv.XXXXXX)
DRIFT_FILE=$(mktemp /tmp/rhelguard_drift.XXXXXX)
trap 'rm -f "$RESULTS_FILE" "$HTML_ROWS_FILE" "$CSV_ROWS_FILE" "$DRIFT_FILE"' EXIT

# Detected RHEL version (set in detect_os)
RHEL_MAJOR=0
RHEL_FULL="Unknown"
OS_FAMILY="rhel"   # rhel | centos | alma | rocky | fedora | unknown

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# PORTABLE TIMEOUT — `timeout` is not in RHEL 5 coreutils. Without it the old
# code silently returned "0" (false PASS). Now we run the command unbounded.
# ─────────────────────────────────────────────────────────────────────────────
run_to() {
    local secs="$1"; shift
    if command -v timeout &>/dev/null; then timeout "$secs" "$@"; else "$@"; fi
}

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK — warn about missing optional tools, never hard-fail
# All REQUIRED tools are bash builtins or guaranteed on any RHEL install.
# ─────────────────────────────────────────────────────────────────────────────
check_deps() {
    # These are REQUIRED — present on every RHEL 5+ system
    local required=(awk sed grep find stat rpm uname date hostname)
    local missing=()
    for t in "${required[@]}"; do
        command -v "$t" &>/dev/null || missing+=("$t")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Missing required tools: ${missing[*]}${RESET}"
        echo "These are standard on all RHEL systems — check your PATH."
        exit 1
    fi

    # These are OPTIONAL — degrade gracefully if absent
    local optional=(systemctl sshd getenforce sestatus ss findmnt auditctl lsblk blkid ip mokutil chage sha256sum tar)
    local absent=()
    for t in "${optional[@]}"; do
        command -v "$t" &>/dev/null || absent+=("$t")
    done
    if [[ ${#absent[@]} -gt 0 ]]; then
        log_warn "Optional tools not found (checks using them will be skipped): ${absent[*]}"
    fi

    # Explicitly note that no internet is needed
    log "Air-gap safe: all checks use local system state only."
    log "No outbound network connections are made by any check."
}


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
log()      { [[ "$QUIET" == false ]] && echo -e "${CYAN}[*]${RESET} $*"; return 0; }
log_ok()   { [[ "$QUIET" == false ]] && echo -e "${GREEN}[PASS]${RESET} $*"; return 0; }
log_fail() { [[ "$QUIET" == false ]] && echo -e "${RED}[FAIL]${RESET} $*"; return 0; }
log_warn() { [[ "$QUIET" == false ]] && echo -e "${YELLOW}[WARN]${RESET} $*"; return 0; }
log_info() { [[ "$QUIET" == false ]] && echo -e "${BOLD}[INFO]${RESET} $*"; return 0; }
log_skip() { [[ "$QUIET" == false ]] && echo -e "      [SKIP] $*"; return 0; }
banner()   { [[ "$QUIET" == false ]] && echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}\n"; return 0; }

# ─────────────────────────────────────────────────────────────────────────────
# PRODUCTION THROTTLE
# ─────────────────────────────────────────────────────────────────────────────
throttle() {
    if [[ "$THROTTLE_MS" -gt 0 ]]; then
        local _int=$(( THROTTLE_MS / 1000 ))
        local _frac=$(printf "%03d" $(( THROTTLE_MS % 1000 )))
        sleep "${_int}.${_frac}" 2>/dev/null || true
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# ROOT GUARD — non-root callers skip privileged checks gracefully
# Usage:  needs_root "ID" "Title" "Category" || return
# ─────────────────────────────────────────────────────────────────────────────
needs_root() {
    local id="$1" title="$2" cat="$3"
    if [[ "$IS_ROOT" == false ]]; then
        PRIV_SKIP=$(( PRIV_SKIP + 1 ))
        _write_result "SKIP" "$id" "$title" "$cat" \
            "ROOT REQUIRED — re-run with sudo for full coverage." \
            "sudo ./rhelguard.sh"
        return 1
    fi
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# RECORD RESULT
# ─────────────────────────────────────────────────────────────────────────────
# record_result STATUS ID TITLE CATEGORY DESCRIPTION [REMEDIATION]
record_result() {
    local status="$1" id="$2" title="$3" cat="$4" desc="$5" rem="${6:-N/A}"
    _write_result "$status" "$id" "$title" "$cat" "$desc" "$rem"
}

_write_result() {
    local status="$1" id="$2" title="$3" cat="$4" desc="$5" rem="$6"

    # ── Guarantee unique check IDs (needed for baselines + waivers) ──────────
    local base_id="$id" n=1
    while [[ "$SEEN_IDS" == *"|${id}|"* ]]; do
        n=$(( n + 1 )); id="${base_id}.${n}"
    done
    SEEN_IDS="${SEEN_IDS}${id}|"

    # ── Waivers: documented, accepted deviations (FAIL/WARN only) ───────────
    if [[ -n "$WAIVER_DATA" && ( "$status" == "FAIL" || "$status" == "WARN" ) ]]; then
        local wline wid wreason
        while IFS= read -r wline; do
            wid="${wline%%|*}"; wid="${wid//[[:space:]]/}"
            if [[ -n "$wid" && ( "$wid" == "$id" || "$wid" == "$base_id" ) ]]; then
                wreason="${wline#*|}"
                [[ "$wreason" == "$wline" ]] && wreason="(no reason given)"
                desc="WAIVED (was ${status}): ${wreason# } — ${desc}"
                status="WAIVED"
                break
            fi
        done <<< "$WAIVER_DATA"
    fi

    TOTAL=$(( TOTAL + 1 ))
    case "$status" in
        PASS)   PASS=$(( PASS+1 ));     log_ok   "$id — $title" ;;
        FAIL)   FAIL=$(( FAIL+1 ));     log_fail "$id — $title" ;;
        WARN)   WARN=$(( WARN+1 ));     log_warn "$id — $title" ;;
        INFO)   INFO=$(( INFO+1 ));     log_info "$id — $title" ;;
        SKIP)   SKIP=$(( SKIP+1 ));     log_skip "$id — $title" ;;
        WAIVED) WAIVED=$(( WAIVED+1 )); log_info "$id — $title (waived)" ;;
    esac

    # ── One awk pass renders JSON, HTML and CSV rows with correct escaping ───
    # Values go through ENVIRON (not -v) so backslashes are not re-interpreted.
    # Handles quotes, backslashes, newlines, tabs and control characters —
    # the old sed escaping produced invalid JSON on any multi-line value.
    RG_S="$status" RG_I="$id" RG_T="$title" RG_C="$cat" RG_D="$desc" RG_R="$rem" \
    RG_V="$RHEL_MAJOR" RG_TS="$(date -Iseconds 2>/dev/null || date)" \
    RG_JF="$RESULTS_FILE" RG_HF="$HTML_ROWS_FILE" RG_CF="$CSV_ROWS_FILE" \
    awk 'function j(x){ gsub(/\\/,"\\\\",x); gsub(/"/,"\\\"",x); gsub(/\t/,"\\t",x);
                        gsub(/\r/,"",x); gsub(/\n/,"\\n",x);
                        gsub(/[\001-\010\013\014\016-\037]/,"",x); return x }
         function h(x){ gsub(/&/,"\\&amp;",x); gsub(/</,"\\&lt;",x); gsub(/>/,"\\&gt;",x);
                        gsub(/"/,"\\&quot;",x); gsub(/\047/,"\\&#39;",x);
                        gsub(/\n/,"<br>",x); return x }
         function c(x){ gsub(/"/,"\"\"",x); gsub(/[\r\n]+/," ",x);
                        if (x ~ /^[=+@-]/) x="\047" x;    # CSV/formula injection guard
                        return "\"" x "\"" }
         BEGIN{
           S=ENVIRON["RG_S"]; I=ENVIRON["RG_I"]; T=ENVIRON["RG_T"]; C=ENVIRON["RG_C"]
           D=ENVIRON["RG_D"]; R=ENVIRON["RG_R"]; V=ENVIRON["RG_V"]+0; TS=ENVIRON["RG_TS"]
           printf "{\"id\":\"%s\",\"status\":\"%s\",\"title\":\"%s\",\"category\":\"%s\",\"description\":\"%s\",\"remediation\":\"%s\",\"rhel_ver\":%d,\"ts\":\"%s\"}\n", \
             j(I),j(S),j(T),j(C),j(D),j(R),V,j(TS) >> ENVIRON["RG_JF"]
           rem=""
           if (R != "" && R != "N/A") rem="<div class=\"rem\">&#128295; " h(R) "</div>"
           printf "<tr data-s=\"%s\"><td><span class=\"badge b-%s\">%s</span></td><td class=\"id-cell\">%s</td><td>%s</td><td><strong>%s</strong><br><small class=\"desc\">%s</small>%s</td></tr>\n", \
             h(S),h(S),h(S),h(I),h(C),h(T),h(D),rem >> ENVIRON["RG_HF"]
           printf "%s,%s,%s,%s,%s,%s\n", c(I),c(S),c(C),c(T),c(D),c(R) >> ENVIRON["RG_CF"]
         }' </dev/null
    throttle
}

# ─────────────────────────────────────────────────────────────────────────────
# OS DETECTION
# ─────────────────────────────────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        RHEL_FULL=$(cat /etc/redhat-release)
    elif [[ -f /etc/os-release ]]; then
        RHEL_FULL=$(. /etc/os-release && echo "${PRETTY_NAME:-Unknown}")
    fi

    # Determine family
    case "$RHEL_FULL" in
        *"Red Hat"*)     OS_FAMILY="rhel" ;;
        *"CentOS"*)      OS_FAMILY="centos" ;;
        *"AlmaLinux"*)   OS_FAMILY="alma" ;;
        *"Rocky"*)       OS_FAMILY="rocky" ;;
        *"Fedora"*)      OS_FAMILY="fedora" ;;
        *)               OS_FAMILY="unknown" ;;
    esac

    # Extract major version number
    if [[ -f /etc/os-release ]]; then
        local ver
        ver=$(. /etc/os-release && echo "${VERSION_ID:-0}")
        RHEL_MAJOR=${ver%%.*}
    elif [[ "$RHEL_FULL" =~ release[[:space:]]+([0-9]+) ]]; then
        RHEL_MAJOR="${BASH_REMATCH[1]}"
    fi

    # Validate it's a supported RHEL-family version
    if ! [[ "$RHEL_MAJOR" =~ ^(5|6|7|8|9|10)$ ]]; then
        echo -e "${YELLOW}[WARN] Detected major version: ${RHEL_MAJOR} — best-effort mode (tool targets 5–10)${RESET}"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# VERSION COMPAT HELPERS
# rhel_ge N  → true if running RHEL ≥ N
# rhel_le N  → true if running RHEL ≤ N
# rhel_is N  → true if running exactly RHEL N
# ─────────────────────────────────────────────────────────────────────────────
rhel_ge() { [[ "$RHEL_MAJOR" -ge "$1" ]] 2>/dev/null; }
rhel_le() { [[ "$RHEL_MAJOR" -le "$1" ]] 2>/dev/null; }
rhel_is() { [[ "$RHEL_MAJOR" -eq "$1" ]] 2>/dev/null; }

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    grep "^# USAGE:" -A 45 "$0" | sed "/^# =/q" | grep "^#" | sed 's/^#[[:space:]]\{0,1\}//'
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--mode)       SCAN_MODE="${2:-all}";   shift 2 ;;
            -b|--baseline)   BASELINE_FILE="${2:-}";  shift 2 ;;
            -w|--waivers)    WAIVER_FILE="${2:-}";    shift 2 ;;
            -a|--max-patch-age) MAX_PATCH_AGE="${2:-90}"; shift 2 ;;
            -B|--bundle)     BUNDLE=true;             shift ;;
            --strict)        STRICT=true;             shift ;;
            -o|--output)     OUTPUT_DIR="${2:-$OUTPUT_DIR}"; shift 2 ;;
            -t|--throttle)   THROTTLE_MS="${2:-50}";  shift 2 ;;
            -s|--skip-lynis) shift ;;   # no-op, backward compatibility
            -q|--quiet)      QUIET=true;              shift ;;
            -h|--help)       usage ;;
            *) echo "Unknown option: $1"; usage ;;
        esac
    done
    [[ "$THROTTLE_MS"   =~ ^[0-9]+$ ]] || { echo "Invalid --throttle: $THROTTLE_MS"; exit 1; }
    [[ "$MAX_PATCH_AGE" =~ ^[0-9]+$ ]] || { echo "Invalid --max-patch-age: $MAX_PATCH_AGE"; exit 1; }
    if [[ -n "$BASELINE_FILE" && ! -r "$BASELINE_FILE" ]]; then echo "Baseline not readable: $BASELINE_FILE"; exit 1; fi
    if [[ -n "$WAIVER_FILE"   && ! -r "$WAIVER_FILE"   ]]; then echo "Waiver file not readable: $WAIVER_FILE"; exit 1; fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────
preflight() {
    detect_os
    check_deps
    mkdir -p "$OUTPUT_DIR" || { echo "Cannot create output dir: $OUTPUT_DIR"; exit 1; }

    # Chain of custody: record exactly which script build produced the report
    if command -v sha256sum &>/dev/null && [[ -r "$SCRIPT_PATH" ]]; then
        SCRIPT_SHA256=$(sha256sum "$SCRIPT_PATH" 2>/dev/null | awk '{print $1}')
    fi

    if [[ -n "$WAIVER_FILE" ]]; then
        WAIVER_DATA=$(grep -vE '^[[:space:]]*(#|$)' "$WAIVER_FILE" 2>/dev/null)
        log "Waivers  : $(printf '%s\n' "$WAIVER_DATA" | grep -c . ) loaded from $WAIVER_FILE"
    fi

    if [[ "$IS_ROOT" == false ]]; then
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗"
        echo -e "║  ⚠  Running WITHOUT root — privileged checks will be SKIP'd  ║"
        echo -e "║  Re-run with sudo for complete coverage.                     ║"
        echo -e "╚══════════════════════════════════════════════════════════════╝${RESET}"
    fi

    log "Tool     : ${TOOL_NAME} v${TOOL_VERSION}"
    log "Host     : ${HOSTNAME_VAL}"
    log "OS       : ${RHEL_FULL} (RHEL major: ${RHEL_MAJOR}, family: ${OS_FAMILY})"
    log "Kernel   : $(uname -r)"
    log "Mode     : ${SCAN_MODE}"
    log "Throttle : ${THROTTLE_MS}ms"
    log "As root  : ${IS_ROOT}"
    log "Output   : ${OUTPUT_DIR}"
    log "SHA-256  : ${SCRIPT_SHA256}"
}

# =============================================================================
#  ██████╗██╗███████╗
# ██╔════╝██║██╔════╝
# ██║     ██║███████╗
# ██║     ██║╚════██║
# ╚██████╗██║███████║
#  ╚═════╝╚═╝╚══════╝
#  CIS BENCHMARK CHECKS  (version-aware: RHEL 5–10)
# =============================================================================

run_cis_checks() {

    # ── Kernel Modules ────────────────────────────────────────────────────────
    banner "CIS — Filesystem Kernel Modules"

    # Core modules to disable on all versions
    local modules_all=(cramfs freevxfs hfs hfsplus jffs2 udf)
    # RHEL 8+ additional modules
    local modules_rhel8plus=(squashfs firewire-core usb-storage sctp tipc)
    # RHEL 9+ additional modules (STIG-specific)
    local modules_rhel9plus=(atm can bluetooth)

    local all_mods=("${modules_all[@]}")
    rhel_ge 8 && all_mods+=("${modules_rhel8plus[@]}")
    rhel_ge 9 && all_mods+=("${modules_rhel9plus[@]}")

    for mod in "${all_mods[@]}"; do
        local safe="${mod//-/_}"
        local loaded=false bl=false
        lsmod 2>/dev/null | grep -q "^${safe}[[:space:]]" && loaded=true
        grep -rqE "^\s*(blacklist|install)\s+${mod}" /etc/modprobe.d/ 2>/dev/null && bl=true

        if [[ "$loaded" == false && "$bl" == true ]]; then
            record_result "PASS" "CIS-MOD-$mod" "Kernel module '$mod' disabled and blacklisted" \
                "CONFIGURATION MANAGEMENT" "Module $mod is not loaded and is blacklisted." ""
        elif [[ "$loaded" == false ]]; then
            record_result "WARN" "CIS-MOD-$mod" "Module '$mod' not loaded but not blacklisted" \
                "CONFIGURATION MANAGEMENT" "Module $mod is absent at runtime but not hardened." \
                "echo 'install $mod /bin/false' >> /etc/modprobe.d/hardening.conf && echo 'blacklist $mod' >> /etc/modprobe.d/hardening.conf"
        else
            record_result "FAIL" "CIS-MOD-$mod" "Kernel module '$mod' is loaded/available" \
                "CONFIGURATION MANAGEMENT" "Module $mod is currently loaded." \
                "modprobe -r $mod && echo 'install $mod /bin/false' >> /etc/modprobe.d/hardening.conf"
        fi
    done

    # ── Mount Options ─────────────────────────────────────────────────────────
    banner "CIS — Filesystem Mount Options"

    # Format: "mountpoint:option:check_id"
    local mount_checks=(
        "/tmp:nodev:CIS-MNT-1"
        "/tmp:nosuid:CIS-MNT-2"
        "/tmp:noexec:CIS-MNT-3"
        "/dev/shm:nodev:CIS-MNT-4"
        "/dev/shm:nosuid:CIS-MNT-5"
        "/dev/shm:noexec:CIS-MNT-6"
        "/home:nodev:CIS-MNT-7"
        "/home:nosuid:CIS-MNT-8"
        "/var:nodev:CIS-MNT-9"
        "/var:nosuid:CIS-MNT-10"
        "/var/tmp:nodev:CIS-MNT-11"
        "/var/tmp:nosuid:CIS-MNT-12"
        "/var/tmp:noexec:CIS-MNT-13"
        "/var/log:nodev:CIS-MNT-14"
        "/var/log:nosuid:CIS-MNT-15"
        "/var/log:noexec:CIS-MNT-16"
        "/var/log/audit:nodev:CIS-MNT-17"
        "/var/log/audit:nosuid:CIS-MNT-18"
        "/var/log/audit:noexec:CIS-MNT-19"
    )
    # RHEL 9+ boot mounts
    rhel_ge 9 && mount_checks+=(
        "/boot:nodev:CIS-MNT-20"
        "/boot:nosuid:CIS-MNT-21"
    )

    for item in "${mount_checks[@]}"; do
        IFS=':' read -r mp opt cid <<< "$item"
        if findmnt -n "$mp" &>/dev/null; then
            if findmnt -n -o OPTIONS "$mp" 2>/dev/null | grep -q "$opt"; then
                record_result "PASS" "$cid" "$mp has $opt option" \
                    "MEDIA PROTECTION" "$mp is mounted with $opt." ""
            else
                record_result "FAIL" "$cid" "$mp missing '$opt' mount option" \
                    "MEDIA PROTECTION" "$mp does not have $opt." \
                    "Add $opt to $mp in /etc/fstab and remount: mount -o remount $mp"
            fi
        else
            record_result "WARN" "$cid" "$mp is not a separate partition" \
                "MEDIA PROTECTION" "$mp is not mounted as a separate filesystem." \
                "Consider creating a dedicated partition for $mp"
        fi
    done

    # ── Package / Update Management ───────────────────────────────────────────
    banner "CIS — Software & Package Management"

    # GPG keys
    if rpm -q gpg-pubkey &>/dev/null 2>&1; then
        record_result "PASS" "CIS-PKG-1" "GPG keys are configured" \
            "SYSTEM INTEGRITY" "GPG public keys installed via RPM database." ""
    else
        record_result "FAIL" "CIS-PKG-1" "No GPG keys found in RPM database" \
            "SYSTEM INTEGRITY" "No gpg-pubkey packages found." \
            "Import your organisation's GPG key: rpm --import <keyfile>"
    fi

    # gpgcheck
    local gpg_ok=true
    if grep -rqE "^\s*gpgcheck\s*=\s*0" /etc/yum.conf /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo 2>/dev/null; then
        gpg_ok=false
    fi
    if [[ "$gpg_ok" == true ]]; then
        record_result "PASS" "CIS-PKG-2" "gpgcheck is not disabled in any repo config" \
            "SYSTEM INTEGRITY" "gpgcheck=0 was not found in yum/dnf configuration." ""
    else
        record_result "FAIL" "CIS-PKG-2" "gpgcheck=0 found in at least one repo config" \
            "SYSTEM INTEGRITY" "One or more repos have gpgcheck disabled." \
            "Set gpgcheck=1 in all /etc/yum.repos.d/*.repo files and /etc/dnf/dnf.conf"
    fi

    # RHEL 9: localpkg_gpgcheck
    if rhel_ge 9; then
        local local_gpg
        local_gpg=$(grep -iE "^\s*localpkg_gpgcheck" /etc/dnf/dnf.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "N/A")
        if [[ "$local_gpg" == "1" ]]; then
            record_result "PASS" "CIS-PKG-3" "localpkg_gpgcheck = 1 (RHEL 9+)" \
                "SYSTEM INTEGRITY" "Local package GPG check is enforced." ""
        else
            record_result "FAIL" "CIS-PKG-3" "localpkg_gpgcheck not set to 1 (RHEL 9+)" \
                "SYSTEM INTEGRITY" "Local package installs do not require GPG verification." \
                "Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf"
        fi
    fi

    # Pending updates — cache-only (-C), never touches the network.
    # On air-gapped hosts there is often NO local metadata cache; the old logic
    # reported that as "up to date" (false PASS). Exit codes: 0=none, 100=updates.
    local pkg_mgr="dnf"
    rhel_le 7 && pkg_mgr="yum"
    if command -v "$pkg_mgr" &>/dev/null; then
        local cu_out cu_rc pending
        cu_out=$(run_to 90 "$pkg_mgr" check-update -C --quiet 2>/dev/null); cu_rc=$?
        # count only "name.arch  version  repo" lines, not banner/metadata lines
        pending=$(printf '%s\n' "$cu_out" | grep -cE '^[[:alnum:]_.+-]+\.[[:alnum:]_]+[[:space:]]+[0-9]' || true)
        if [[ $cu_rc -eq 100 ]]; then
            record_result "WARN" "CIS-PKG-4" "$pending pending package update(s) in local metadata" \
                "SYSTEM INTEGRITY" "Local repo metadata lists $pending newer package(s). Freshness depends on when your internal mirror was last synced." \
                "Sync the internal mirror/media, then: $pkg_mgr update"
        elif [[ $cu_rc -eq 0 ]]; then
            record_result "PASS" "CIS-PKG-4" "No pending updates in local repo metadata" \
                "SYSTEM INTEGRITY" "No updates listed in cached metadata. See AIR-PATCH-1 for patch age — metadata may itself be stale." ""
        else
            record_result "SKIP" "CIS-PKG-4" "No usable local repo metadata cache" \
                "SYSTEM INTEGRITY" "$pkg_mgr has no cached metadata (typical on air-gapped hosts). Patch currency is assessed by AIR-PATCH-1 instead." \
                "$pkg_mgr makecache  (against your internal mirror or mounted media)"
        fi
    else
        record_result "SKIP" "CIS-PKG-4" "$pkg_mgr not available" "SYSTEM INTEGRITY" "Package manager not found." ""
    fi

    # ── SELinux ───────────────────────────────────────────────────────────────
    banner "CIS — SELinux / Mandatory Access Control"

    # SELinux available on RHEL 5+
    if rpm -q libselinux &>/dev/null 2>&1; then
        record_result "PASS" "CIS-SEL-1" "SELinux (libselinux) is installed" \
            "ACCESS CONTROL" "libselinux package is present." ""
    else
        record_result "FAIL" "CIS-SEL-1" "SELinux is not installed" \
            "ACCESS CONTROL" "libselinux package is missing." \
            "Install: dnf install libselinux"
    fi

    # Check bootloader for selinux=0
    local grub_cfg=""
    if rhel_ge 7; then grub_cfg="/boot/grub2/grub.cfg"
    else grub_cfg="/boot/grub/grub.conf"; fi

    if grep -qE "selinux=0|enforcing=0" "$grub_cfg" /etc/default/grub 2>/dev/null; then
        record_result "FAIL" "CIS-SEL-2" "SELinux disabled in bootloader configuration" \
            "ACCESS CONTROL" "selinux=0 or enforcing=0 found in bootloader." \
            "Remove selinux=0/enforcing=0 from $grub_cfg and /etc/default/grub, then regenerate grub config."
    else
        record_result "PASS" "CIS-SEL-2" "SELinux is not disabled in bootloader" \
            "ACCESS CONTROL" "No selinux=0 or enforcing=0 in grub config." ""
    fi

    local semode; semode=$(getenforce 2>/dev/null || echo "Unknown")
    case "$semode" in
        Enforcing)
            record_result "PASS" "CIS-SEL-3" "SELinux mode = Enforcing" \
                "ACCESS CONTROL" "SELinux is actively enforcing policy." "" ;;
        Permissive)
            record_result "WARN" "CIS-SEL-3" "SELinux mode = Permissive (should be Enforcing)" \
                "ACCESS CONTROL" "SELinux is permissive — not blocking violations." \
                "setenforce 1 && sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config" ;;
        *)
            record_result "FAIL" "CIS-SEL-3" "SELinux mode = $semode" \
                "ACCESS CONTROL" "SELinux is disabled or status unknown." \
                "Set SELINUX=enforcing in /etc/selinux/config and reboot." ;;
    esac

    local sepol; sepol=$(sestatus 2>/dev/null | awk '/Loaded policy/{print $NF}' || echo "N/A")
    if [[ "$sepol" == "targeted" || "$sepol" == "mls" ]]; then
        record_result "PASS" "CIS-SEL-4" "SELinux policy = $sepol" \
            "ACCESS CONTROL" "SELinux policy type is valid." ""
    else
        record_result "FAIL" "CIS-SEL-4" "SELinux policy = $sepol (expected targeted or mls)" \
            "ACCESS CONTROL" "SELinux policy type is not set to a recommended value." \
            "Set SELINUXTYPE=targeted in /etc/selinux/config"
    fi

    # mcstrans & setroubleshoot (RHEL 7+ only)
    if rhel_ge 7; then
        for pkg in mcstrans setroubleshoot; do
            if rpm -q "$pkg" &>/dev/null 2>&1; then
                record_result "FAIL" "CIS-SEL-5" "Package '$pkg' is installed (should not be)" \
                    "CONFIGURATION MANAGEMENT" "$pkg is installed on this system." \
                    "Remove: dnf remove $pkg"
            else
                record_result "PASS" "CIS-SEL-5" "Package '$pkg' is not installed" \
                    "CONFIGURATION MANAGEMENT" "$pkg is not present." ""
            fi
        done
    fi

    # ── Bootloader ────────────────────────────────────────────────────────────
    banner "CIS — Bootloader"

    local grub_pass_file=""
    rhel_ge 7 && grub_pass_file="/boot/grub2/user.cfg"
    if [[ -n "$grub_pass_file" ]] && grep -qE "^\s*GRUB2_PASSWORD|^\s*password" "$grub_pass_file" "$grub_cfg" 2>/dev/null; then
        record_result "PASS" "CIS-BOOT-1" "Bootloader password is set" \
            "ACCESS CONTROL" "GRUB2 password entry found." ""
    elif rhel_le 6 && grep -qE "^\s*password" /boot/grub/grub.conf 2>/dev/null; then
        record_result "PASS" "CIS-BOOT-1" "Bootloader password is set (GRUB legacy)" \
            "ACCESS CONTROL" "GRUB password entry found in grub.conf." ""
    else
        record_result "FAIL" "CIS-BOOT-1" "Bootloader password is NOT set" \
            "ACCESS CONTROL" "No GRUB password found." \
            "Set bootloader password: grub2-setpassword  (RHEL 7+) or edit /boot/grub/grub.conf (RHEL 5/6)"
    fi

    local grub_perm; grub_perm=$(stat -Lc "%a" "$grub_cfg" 2>/dev/null || echo "N/A")
    if [[ "$grub_perm" == "600" || "$grub_perm" == "400" ]]; then
        record_result "PASS" "CIS-BOOT-2" "Bootloader config permissions = $grub_perm" \
            "ACCESS CONTROL" "$grub_cfg is appropriately restricted." ""
    else
        record_result "FAIL" "CIS-BOOT-2" "Bootloader config permissions = $grub_perm (expected 600)" \
            "ACCESS CONTROL" "$grub_cfg permissions are not restrictive." \
            "chmod og-rwx $grub_cfg"
    fi

    # RHEL 9: grub.cfg ownership
    if rhel_ge 9; then
        local grub_owner; grub_owner=$(stat -Lc "%U:%G" "$grub_cfg" 2>/dev/null || echo "N/A")
        if [[ "$grub_owner" == "root:root" ]]; then
            record_result "PASS" "CIS-BOOT-3" "grub.cfg owned by root:root" \
                "ACCESS CONTROL" "Bootloader config has correct ownership." ""
        else
            record_result "FAIL" "CIS-BOOT-3" "grub.cfg ownership = $grub_owner (expected root:root)" \
                "ACCESS CONTROL" "grub.cfg is not owned by root:root." \
                "chown root:root $grub_cfg"
        fi
    fi

    # ── Kernel Hardening Parameters ───────────────────────────────────────────
    banner "CIS — Kernel Hardening Parameters"

    # Core sysctl checks applicable to all supported versions
    local sysctl_checks=(
        "fs.suid_dumpable:0:CIS-KERN-1"
        "kernel.dmesg_restrict:1:CIS-KERN-2"
        "kernel.kptr_restrict:1:CIS-KERN-3"
        "kernel.randomize_va_space:2:CIS-KERN-4"
        "fs.protected_hardlinks:1:CIS-KERN-5"
        "fs.protected_symlinks:1:CIS-KERN-6"
    )

    # ptrace — value differs by version
    local ptrace_expected=1
    rhel_ge 9 && ptrace_expected=1   # restrict to child processes
    sysctl_checks+=("kernel.yama.ptrace_scope:${ptrace_expected}:CIS-KERN-7")

    # RHEL 8+ kernel params
    if rhel_ge 8; then
        sysctl_checks+=(
            "kernel.perf_event_paranoid:2:CIS-KERN-8"
            "net.core.bpf_jit_harden:2:CIS-KERN-9"
        )
    fi

    # RHEL 9/10: user namespaces
    if rhel_ge 9; then
        sysctl_checks+=("user.max_user_namespaces:0:CIS-KERN-10")
    fi

    for item in "${sysctl_checks[@]}"; do
        IFS=':' read -r param expected cid <<< "$item"
        local actual; actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [[ "$actual" == "$expected" ]]; then
            record_result "PASS" "$cid" "$param = $actual" \
                "CONFIGURATION MANAGEMENT" "Kernel parameter $param is correctly set." ""
        else
            record_result "FAIL" "$cid" "$param = ${actual} (expected: $expected)" \
                "CONFIGURATION MANAGEMENT" "Kernel parameter $param is $actual, expected $expected." \
                "echo '$param = $expected' >> /etc/sysctl.d/99-hardening.conf && sysctl -w $param=$expected"
        fi
    done

    # Core dump checks
    local core_storage; core_storage=$(grep -E "^\s*Storage\s*=" /etc/systemd/coredump.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "N/A")
    if [[ "$core_storage" == "none" ]]; then
        record_result "PASS" "CIS-KERN-11" "systemd-coredump Storage = none" \
            "CONFIGURATION MANAGEMENT" "Core dump storage is disabled." ""
    else
        record_result "FAIL" "CIS-KERN-11" "systemd-coredump Storage = $core_storage (should be none)" \
            "CONFIGURATION MANAGEMENT" "Core dumps may be stored." \
            "Set Storage=none and ProcessSizeMax=0 in /etc/systemd/coredump.conf"
    fi

    # ── Services ──────────────────────────────────────────────────────────────
    banner "CIS — Unnecessary Services"

    # Base unwanted services for all versions
    local svc_checks=(
        "telnet:TELNET"
        "rsh:RSH"
        "rlogin:RLOGIN"
        "rexec:REXEC"
        "ypserv:NIS-server"
        "tftp:TFTP"
        "xinetd:XINETD"
    )

    # Version-conditional services
    rhel_ge 7 && svc_checks+=(
        "avahi-daemon:AVAHI"
        "cups:CUPS"
        "dhcpd:DHCP-server"
        "named:DNS-server"
        "vsftpd:FTP-server"
        "httpd:HTTP-server"
        "dovecot:IMAP/POP3"
        "smb:SAMBA"
        "squid:SQUID-proxy"
        "snmpd:SNMP"
        "nfs-server:NFS-server"
        "rpcbind:RPC-bind"
        "autofs:AUTOFS"
        "kdump:KDUMP"
    )

    rhel_ge 9 && svc_checks+=(
        "gssproxy:GSSPROXY"
        "iprutils:IPRUTILS"
        "tuned:TUNED"
        "quagga:QUAGGA"
    )

    for entry in "${svc_checks[@]}"; do
        IFS=':' read -r svc label <<< "$entry"
        if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
            record_result "FAIL" "CIS-SVC" "Service $svc ($label) is enabled" \
                "CONFIGURATION MANAGEMENT" "$svc is enabled and may be running." \
                "systemctl --now disable $svc"
        else
            record_result "PASS" "CIS-SVC" "Service $svc ($label) is not enabled" \
                "CONFIGURATION MANAGEMENT" "$svc is not enabled." ""
        fi
    done

    # debug-shell (RHEL 8+)
    if rhel_ge 8; then
        if systemctl is-enabled debug-shell &>/dev/null 2>&1; then
            record_result "FAIL" "CIS-SVC-DBG" "debug-shell.service is enabled" \
                "CONFIGURATION MANAGEMENT" "debug-shell provides unauthenticated root access." \
                "systemctl disable debug-shell.service"
        else
            record_result "PASS" "CIS-SVC-DBG" "debug-shell.service is not enabled" \
                "CONFIGURATION MANAGEMENT" "Debug shell is disabled." ""
        fi
    fi

    # ── Network Hardening ─────────────────────────────────────────────────────
    banner "CIS — Network Kernel Parameters"

    local net_checks=(
        "net.ipv4.ip_forward:0:CIS-NET-1"
        "net.ipv4.conf.all.send_redirects:0:CIS-NET-2"
        "net.ipv4.conf.default.send_redirects:0:CIS-NET-3"
        "net.ipv4.conf.all.accept_source_route:0:CIS-NET-4"
        "net.ipv4.conf.default.accept_source_route:0:CIS-NET-5"
        "net.ipv4.conf.all.accept_redirects:0:CIS-NET-6"
        "net.ipv4.conf.default.accept_redirects:0:CIS-NET-7"
        "net.ipv4.conf.all.secure_redirects:0:CIS-NET-8"
        "net.ipv4.conf.default.secure_redirects:0:CIS-NET-9"
        "net.ipv4.conf.all.log_martians:1:CIS-NET-10"
        "net.ipv4.conf.default.log_martians:1:CIS-NET-11"
        "net.ipv4.icmp_echo_ignore_broadcasts:1:CIS-NET-12"
        "net.ipv4.icmp_ignore_bogus_error_responses:1:CIS-NET-13"
        "net.ipv4.conf.all.rp_filter:1:CIS-NET-14"
        "net.ipv4.conf.default.rp_filter:1:CIS-NET-15"
        "net.ipv4.tcp_syncookies:1:CIS-NET-16"
        "net.ipv6.conf.all.accept_ra:0:CIS-NET-17"
        "net.ipv6.conf.default.accept_ra:0:CIS-NET-18"
        "net.ipv6.conf.all.accept_redirects:0:CIS-NET-19"
        "net.ipv6.conf.all.accept_source_route:0:CIS-NET-20"
    )

    # RHEL 9: additional BPF and promiscuous checks
    if rhel_ge 9; then
        net_checks+=(
            "net.core.bpf_jit_harden:2:CIS-NET-21"
            "net.ipv4.conf.default.rp_filter:1:CIS-NET-22"
        )
    fi

    for item in "${net_checks[@]}"; do
        IFS=':' read -r param expected cid <<< "$item"
        local actual; actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [[ "$actual" == "$expected" ]]; then
            record_result "PASS" "$cid" "$param = $actual" \
                "NETWORK CONFIGURATION" "Network parameter $param is correct." ""
        else
            record_result "FAIL" "$cid" "$param = $actual (expected: $expected)" \
                "NETWORK CONFIGURATION" "Network parameter $param is $actual, expected $expected." \
                "echo '$param = $expected' >> /etc/sysctl.d/99-network.conf && sysctl -w $param=$expected"
        fi
    done

    # Firewall
    local fw_active=false
    for fw in firewalld nftables iptables; do
        systemctl is-active "$fw" &>/dev/null && fw_active=true && break
    done
    if [[ "$fw_active" == true ]]; then
        record_result "PASS" "CIS-FW-1" "A firewall service is active" \
            "NETWORK CONFIGURATION" "firewalld/nftables/iptables is running." ""
    else
        record_result "FAIL" "CIS-FW-1" "No firewall service is active" \
            "NETWORK CONFIGURATION" "No active firewall detected." \
            "systemctl --now enable firewalld"
    fi

    # ── Logging & Auditing ────────────────────────────────────────────────────
    banner "CIS — Logging & Auditing"

    # auditd
    if systemctl is-active auditd &>/dev/null 2>&1; then
        record_result "PASS" "CIS-AUD-1" "auditd is active" \
            "AUDIT AND ACCOUNTABILITY" "Audit daemon is running." ""
    else
        record_result "FAIL" "CIS-AUD-1" "auditd is not active" \
            "AUDIT AND ACCOUNTABILITY" "Audit daemon is not running." \
            "systemctl --now enable auditd"
    fi

    # auditd config checks
    if [[ -f /etc/audit/auditd.conf ]]; then
        local max_action; max_action=$(grep -iE "^\s*max_log_file_action" /etc/audit/auditd.conf | awk -F= '{print $2}' | tr -d ' ')
        if echo "$max_action" | grep -qiE "keep_logs|rotate"; then
            record_result "PASS" "CIS-AUD-2" "max_log_file_action = $max_action" \
                "AUDIT AND ACCOUNTABILITY" "Audit log rotation is configured." ""
        else
            record_result "FAIL" "CIS-AUD-2" "max_log_file_action = $max_action" \
                "AUDIT AND ACCOUNTABILITY" "Audit log rotation action is not set correctly." \
                "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf"
        fi

        local sla; sla=$(grep -iE "^\s*space_left_action" /etc/audit/auditd.conf | awk -F= '{print $2}' | tr -d ' ')
        if echo "$sla" | grep -qiE "email|exec|syslog|rotate"; then
            record_result "PASS" "CIS-AUD-3" "space_left_action = $sla" \
                "AUDIT AND ACCOUNTABILITY" "Audit space_left_action notifies administrators." ""
        else
            record_result "FAIL" "CIS-AUD-3" "space_left_action = $sla (expected: email/syslog)" \
                "AUDIT AND ACCOUNTABILITY" "space_left_action is not configured to alert." \
                "Set space_left_action = email in /etc/audit/auditd.conf"
        fi
    fi

    # Audit rules
    local rules_file=""
    for f in /etc/audit/rules.d/audit.rules /etc/audit/audit.rules; do
        [[ -f "$f" ]] && rules_file="$f" && break
    done

    if [[ -n "$rules_file" ]]; then
        local audit_keys=(time-change identity system-locale MAC-policy logins session perm_mod)
        # RHEL 8+: additional keys
        rhel_ge 8 && audit_keys+=(privileged-commands module-load)

        for key in "${audit_keys[@]}"; do
            if grep -q "\-k $key" "$rules_file" 2>/dev/null || auditctl -l 2>/dev/null | grep -q "\-k $key"; then
                record_result "PASS" "CIS-AUD-RULE" "Audit rule key '$key' is configured" \
                    "AUDIT AND ACCOUNTABILITY" "Audit rule for $key found." ""
            else
                record_result "FAIL" "CIS-AUD-RULE" "Audit rule key '$key' is missing" \
                    "AUDIT AND ACCOUNTABILITY" "No audit rule with key '$key' found." \
                    "Add appropriate audit rules with -k $key to $rules_file"
            fi
        done
    else
        record_result "WARN" "CIS-AUD-4" "No audit rules file found" \
            "AUDIT AND ACCOUNTABILITY" "Cannot locate /etc/audit/rules.d/audit.rules." \
            "Create and configure /etc/audit/rules.d/audit.rules"
    fi

    # rsyslog / syslog
    local syslog_active=false
    for svc in rsyslog syslog syslog-ng; do
        systemctl is-active "$svc" &>/dev/null && syslog_active=true && break
    done
    if [[ "$syslog_active" == true ]]; then
        record_result "PASS" "CIS-LOG-1" "A syslog service is active" \
            "AUDIT AND ACCOUNTABILITY" "Logging daemon is running." ""
    else
        record_result "FAIL" "CIS-LOG-1" "No syslog service is active" \
            "AUDIT AND ACCOUNTABILITY" "rsyslog/syslog/syslog-ng is not running." \
            "systemctl --now enable rsyslog"
    fi

    # systemd-journald (RHEL 7+)
    if rhel_ge 7; then
        if systemctl is-active systemd-journald &>/dev/null; then
            record_result "PASS" "CIS-LOG-2" "systemd-journald is active" \
                "AUDIT AND ACCOUNTABILITY" "Journal daemon is running." ""
        else
            record_result "FAIL" "CIS-LOG-2" "systemd-journald is not active" \
                "AUDIT AND ACCOUNTABILITY" "systemd journal is not running." \
                "systemctl --now enable systemd-journald"
        fi
    fi

    # ── SSH Configuration ─────────────────────────────────────────────────────
    banner "CIS — SSH Server Configuration"

    local ssh_conf="/etc/ssh/sshd_config"
    if [[ -f "$ssh_conf" ]]; then
        # Version-conditional expected values
        local max_auth=4
        rhel_le 7 && max_auth=4

        local ssh_checks=(
            "PermitRootLogin:no:CIS-SSH-1"
            "PermitEmptyPasswords:no:CIS-SSH-2"
            "IgnoreRhosts:yes:CIS-SSH-3"
            "HostbasedAuthentication:no:CIS-SSH-4"
            "PermitUserEnvironment:no:CIS-SSH-5"
            "LogLevel:INFO:CIS-SSH-6"
            "X11Forwarding:no:CIS-SSH-7"
            "ClientAliveInterval:300:CIS-SSH-8"
            "ClientAliveCountMax:0:CIS-SSH-9"
            "Banner:/etc/issue.net:CIS-SSH-10"
        )

        # RHEL 8+ SSH checks
        if rhel_ge 8; then
            ssh_checks+=(
                "GSSAPIAuthentication:no:CIS-SSH-11"
                "KerberosAuthentication:no:CIS-SSH-12"
                "StrictModes:yes:CIS-SSH-13"
                "Compression:no:CIS-SSH-14"
            )
        fi

        # RHEL 9: UsePAM required
        if rhel_ge 9; then
            ssh_checks+=(
                "UsePAM:yes:CIS-SSH-15"
                "PrintLastLog:yes:CIS-SSH-16"
                "X11UseLocalhost:yes:CIS-SSH-17"
            )
        fi

        for item in "${ssh_checks[@]}"; do
            IFS=':' read -r directive expected cid <<< "$item"
            local actual; actual=$(sshd -T 2>/dev/null | grep -i "^${directive} " | awk '{print tolower($2)}' || echo "")
            [[ -z "$actual" ]] && actual=$(grep -iE "^\s*${directive}\s+" "$ssh_conf" 2>/dev/null | awk '{print tolower($2)}' || echo "N/A")
            local exp_lc; exp_lc=$(echo "$expected" | tr '[:upper:]' '[:lower:]')

            if [[ "$actual" == "$exp_lc" ]]; then
                record_result "PASS" "$cid" "SSH $directive = $actual" \
                    "ACCESS CONTROL" "SSH directive $directive is correctly set." ""
            else
                record_result "FAIL" "$cid" "SSH $directive = ${actual:-not set} (expected: $expected)" \
                    "ACCESS CONTROL" "SSH directive $directive is not set to recommended value." \
                    "Set '$directive $expected' in $ssh_conf && systemctl restart sshd"
            fi
        done

        # MaxAuthTries (numeric comparison)
        local mat; mat=$(sshd -T 2>/dev/null | grep -i "^maxauthtries " | awk '{print $2}' || grep -iE "MaxAuthTries" "$ssh_conf" | awk '{print $2}' || echo "N/A")
        if [[ "$mat" =~ ^[0-9]+$ ]] && [[ "$mat" -le "$max_auth" ]]; then
            record_result "PASS" "CIS-SSH-MAT" "SSH MaxAuthTries = $mat (≤$max_auth)" \
                "ACCESS CONTROL" "MaxAuthTries is within acceptable range." ""
        else
            record_result "FAIL" "CIS-SSH-MAT" "SSH MaxAuthTries = $mat (expected ≤$max_auth)" \
                "ACCESS CONTROL" "MaxAuthTries is too high or not set." \
                "Set 'MaxAuthTries $max_auth' in $ssh_conf && systemctl restart sshd"
        fi
    else
        record_result "SKIP" "CIS-SSH" "sshd_config not found — SSH checks skipped" \
            "ACCESS CONTROL" "/etc/ssh/sshd_config does not exist." ""
    fi

    # ── Password & Account Policies ───────────────────────────────────────────
    banner "CIS — Password & Account Policies"

    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        # STIG RHEL 9 requires max 60 days; CIS RHEL 8 allows up to 365
        local pass_max_expect=365
        rhel_ge 9 && pass_max_expect=60

        local pw_checks=(
            "PASS_MAX_DAYS:${pass_max_expect}:max:CIS-PW-1"
            "PASS_MIN_DAYS:1:min:CIS-PW-2"
            "PASS_MIN_LEN:14:min:CIS-PW-3"
            "PASS_WARN_AGE:7:min:CIS-PW-4"
        )
        for item in "${pw_checks[@]}"; do
            IFS=':' read -r param expected comp cid <<< "$item"
            local actual; actual=$(grep -E "^\s*${param}\s+" "$login_defs" | awk '{print $2}' || echo "N/A")
            local ok=false
            if [[ "$actual" =~ ^[0-9]+$ ]]; then
                [[ "$comp" == "max" ]] && [[ "$actual" -le "$expected" ]] && ok=true
                [[ "$comp" == "min" ]] && [[ "$actual" -ge "$expected" ]] && ok=true
            fi
            if [[ "$ok" == true ]]; then
                record_result "PASS" "$cid" "$param = $actual (meets ${comp} of $expected)" \
                    "ACCESS CONTROL" "$param meets the required threshold." ""
            else
                record_result "FAIL" "$cid" "$param = $actual (expected ${comp}: $expected)" \
                    "ACCESS CONTROL" "$param does not meet the required threshold." \
                    "Update $param in $login_defs"
            fi
        done

        # SHA512 hashing
        local encrypt; encrypt=$(grep -E "^\s*ENCRYPT_METHOD" "$login_defs" | awk '{print $2}' || echo "N/A")
        if echo "$encrypt" | grep -qiE "SHA512|SHA256"; then
            record_result "PASS" "CIS-PW-5" "ENCRYPT_METHOD = $encrypt" \
                "SYSTEM INTEGRITY" "FIPS-approved password hashing in use." ""
        else
            record_result "FAIL" "CIS-PW-5" "ENCRYPT_METHOD = $encrypt (expected SHA512)" \
                "SYSTEM INTEGRITY" "Password hashing algorithm may not be FIPS-approved." \
                "Set 'ENCRYPT_METHOD SHA512' in $login_defs"
        fi
    fi

    # pwquality (RHEL 7+)
    if rhel_ge 7 && [[ -f /etc/security/pwquality.conf ]]; then
        for opt in minlen dcredit ucredit lcredit ocredit; do
            local val; val=$(grep -E "^\s*${opt}\s*=" /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' ' || echo "N/A")
            if [[ "$opt" == "minlen" ]]; then
                if [[ "$val" =~ ^[0-9]+$ ]] && [[ "$val" -ge 14 ]]; then
                    record_result "PASS" "CIS-PW-PQ" "pwquality $opt = $val (≥14)" \
                        "ACCESS CONTROL" "Password minimum length is configured." ""
                else
                    record_result "FAIL" "CIS-PW-PQ" "pwquality $opt = $val (expected ≥14)" \
                        "ACCESS CONTROL" "Password minimum length is insufficient." \
                        "Set 'minlen = 14' in /etc/security/pwquality.conf"
                fi
            else
                if [[ "$val" =~ ^-?[0-9]+$ ]] && [[ "$val" -lt 0 ]]; then
                    record_result "PASS" "CIS-PW-PQ" "pwquality $opt = $val (complexity enforced)" \
                        "ACCESS CONTROL" "Password complexity for $opt is required." ""
                else
                    record_result "FAIL" "CIS-PW-PQ" "pwquality $opt = $val (expected < 0 e.g. -1)" \
                        "ACCESS CONTROL" "Password complexity $opt is not enforced." \
                        "Set '$opt = -1' in /etc/security/pwquality.conf"
                fi
            fi
        done
    fi

    # PAM faillock / pam_tally2
    if rhel_ge 8; then
        local fconf="/etc/security/faillock.conf"
        if [[ -f "$fconf" ]]; then
            local deny; deny=$(grep -E "^\s*deny\s*=" "$fconf" | awk -F= '{print $2}' | tr -d ' ' || echo "N/A")
            if [[ "$deny" =~ ^[0-9]+$ ]] && [[ "$deny" -le 3 ]] && [[ "$deny" -gt 0 ]]; then
                record_result "PASS" "CIS-PW-FL1" "faillock deny = $deny (≤3)" \
                    "ACCESS CONTROL" "Account lockout threshold is ≤3." ""
            else
                record_result "FAIL" "CIS-PW-FL1" "faillock deny = $deny (expected ≤3)" \
                    "ACCESS CONTROL" "Account lockout threshold is not configured correctly." \
                    "Set 'deny = 3' in /etc/security/faillock.conf"
            fi

            local utime; utime=$(grep -E "^\s*unlock_time\s*=" "$fconf" | awk -F= '{print $2}' | tr -d ' ' || echo "N/A")
            if [[ "$utime" == "0" ]] || ( [[ "$utime" =~ ^[0-9]+$ ]] && [[ "$utime" -ge 900 ]] ); then
                record_result "PASS" "CIS-PW-FL2" "faillock unlock_time = $utime (0 or ≥900s)" \
                    "ACCESS CONTROL" "Account unlock requires admin or ≥15 min." ""
            else
                record_result "FAIL" "CIS-PW-FL2" "faillock unlock_time = $utime (expected 0 or ≥900)" \
                    "ACCESS CONTROL" "Account unlock time is too short." \
                    "Set 'unlock_time = 0' in /etc/security/faillock.conf"
            fi
        else
            record_result "FAIL" "CIS-PW-FL1" "faillock.conf not found" \
                "ACCESS CONTROL" "/etc/security/faillock.conf is missing." \
                "Configure pam_faillock and create /etc/security/faillock.conf"
        fi
    elif rhel_le 7; then
        # Older versions use pam_tally2
        if grep -rqE "pam_tally2" /etc/pam.d/ 2>/dev/null; then
            record_result "PASS" "CIS-PW-FL1" "pam_tally2 is configured (RHEL ≤7)" \
                "ACCESS CONTROL" "Account lockout via pam_tally2 is configured." ""
        else
            record_result "FAIL" "CIS-PW-FL1" "pam_tally2 not configured in /etc/pam.d/ (RHEL ≤7)" \
                "ACCESS CONTROL" "No account lockout mechanism found." \
                "Configure pam_tally2 in /etc/pam.d/system-auth"
        fi
    fi

    # Default umask
    local umask_val; umask_val=$(grep -hE "^\s*umask\s+" /etc/profile /etc/bashrc /etc/profile.d/*.sh 2>/dev/null | awk '{print $2}' | sort -u | head -1 || echo "N/A")
    if [[ "$umask_val" == "027" || "$umask_val" == "077" ]]; then
        record_result "PASS" "CIS-PW-UM" "Default umask = $umask_val" \
            "ACCESS CONTROL" "Default umask is restrictive." ""
    else
        record_result "FAIL" "CIS-PW-UM" "Default umask = $umask_val (expected 027 or 077)" \
            "ACCESS CONTROL" "Default umask may allow excessive file permissions." \
            "Set 'umask 027' in /etc/profile and /etc/bashrc"
    fi

    # TMOUT (session timeout)
    local tmout; tmout=$(grep -hE "^\s*(readonly\s+)?TMOUT" /etc/profile /etc/bashrc /etc/profile.d/*.sh 2>/dev/null | grep -oE "[0-9]+" | head -1 || echo "N/A")
    if [[ "$tmout" =~ ^[0-9]+$ ]] && [[ "$tmout" -le 600 ]]; then
        record_result "PASS" "CIS-PW-TO" "TMOUT = $tmout seconds (≤600)" \
            "ACCESS CONTROL" "Idle session timeout is configured." ""
    else
        record_result "FAIL" "CIS-PW-TO" "TMOUT = $tmout (expected ≤600)" \
            "ACCESS CONTROL" "Idle session timeout is not configured or too long." \
            "Add 'readonly TMOUT=600' to /etc/profile.d/tmout.sh"
    fi

    # ── System File Permissions ───────────────────────────────────────────────
    banner "CIS — Critical File Permissions & Ownership"

    local file_checks=(
        "/etc/passwd:644:root:root:CIS-FILE-1"
        "/etc/group:644:root:root:CIS-FILE-2"
        "/etc/shadow:000:root:root:CIS-FILE-3"   # 000 on RHEL9; 640 acceptable on RHEL<9
        "/etc/gshadow:000:root:root:CIS-FILE-4"
        "/etc/passwd-:644:root:root:CIS-FILE-5"
        "/etc/group-:644:root:root:CIS-FILE-6"
        "/etc/shadow-:000:root:root:CIS-FILE-7"
        "/etc/crontab:600:root:root:CIS-FILE-8"
    )

    for item in "${file_checks[@]}"; do
        IFS=':' read -r filepath perm owner group cid <<< "$item"
        if [[ ! -f "$filepath" ]]; then
            record_result "SKIP" "$cid" "$filepath does not exist — skipping" \
                "CONFIGURATION MANAGEMENT" "File $filepath is not present on this system." ""
            continue
        fi

        local actual_perm; actual_perm=$(stat -Lc "%a" "$filepath" 2>/dev/null || echo "N/A")
        local actual_owner; actual_owner=$(stat -Lc "%U" "$filepath" 2>/dev/null || echo "N/A")
        local actual_group; actual_group=$(stat -Lc "%G" "$filepath" 2>/dev/null || echo "N/A")

        # Shadow files: RHEL < 9 allows 640, RHEL 9+ requires 000
        local expected_perm="$perm"
        if [[ "$filepath" == *"shadow"* ]] && rhel_le 8; then
            expected_perm="640"
        fi

        if [[ "$actual_perm" == "$expected_perm" ]] && [[ "$actual_owner" == "$owner" ]] && [[ "$actual_group" == "$group" ]]; then
            record_result "PASS" "$cid" "$filepath — perm:$actual_perm owner:$actual_owner:$actual_group" \
                "CONFIGURATION MANAGEMENT" "$filepath has correct permissions and ownership." ""
        else
            record_result "FAIL" "$cid" "$filepath — got $actual_perm/$actual_owner:$actual_group (expected $expected_perm/$owner:$group)" \
                "CONFIGURATION MANAGEMENT" "File $filepath permissions or ownership is incorrect." \
                "chmod $expected_perm $filepath && chown $owner:$group $filepath"
        fi
    done

    # ── Account Integrity ─────────────────────────────────────────────────────
    banner "CIS — Account Integrity"

    # Root is only UID-0 account
    local uid0_non_root; uid0_non_root=$(awk -F: '$3==0 && $1!="root"' /etc/passwd 2>/dev/null | wc -l)
    if [[ "$uid0_non_root" -eq 0 ]]; then
        record_result "PASS" "CIS-ACC-1" "Only root has UID 0" \
            "ACCESS CONTROL" "No other accounts have UID 0." ""
    else
        record_result "FAIL" "CIS-ACC-1" "$uid0_non_root non-root account(s) have UID 0" \
            "ACCESS CONTROL" "Accounts other than root have UID 0." \
            "Remove or change UID for non-root accounts with UID 0."
    fi

    # Duplicate UIDs
    local dup_uid; dup_uid=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d | wc -l)
    if [[ "$dup_uid" -eq 0 ]]; then
        record_result "PASS" "CIS-ACC-2" "No duplicate UIDs in /etc/passwd" \
            "ACCESS CONTROL" "All user UIDs are unique." ""
    else
        record_result "FAIL" "CIS-ACC-2" "$dup_uid duplicate UID(s) found" \
            "ACCESS CONTROL" "Duplicate UIDs exist in /etc/passwd." \
            "Investigate and resolve: awk -F: '{print \$3}' /etc/passwd | sort | uniq -d"
    fi

    # Duplicate GIDs
    local dup_gid; dup_gid=$(awk -F: '{print $3}' /etc/group | sort | uniq -d | wc -l)
    if [[ "$dup_gid" -eq 0 ]]; then
        record_result "PASS" "CIS-ACC-3" "No duplicate GIDs in /etc/group" \
            "ACCESS CONTROL" "All group GIDs are unique." ""
    else
        record_result "FAIL" "CIS-ACC-3" "$dup_gid duplicate GID(s) found" \
            "ACCESS CONTROL" "Duplicate GIDs exist in /etc/group." \
            "Investigate and resolve: awk -F: '{print \$3}' /etc/group | sort | uniq -d"
    fi

    # Empty passwords (requires shadow read access)
    if needs_root "CIS-ACC-4" "Check for accounts with empty passwords" "ACCESS CONTROL"; then
        local empty_pw; empty_pw=$(awk -F: '$2==""' /etc/shadow 2>/dev/null | wc -l)
        if [[ "$empty_pw" -eq 0 ]]; then
            record_result "PASS" "CIS-ACC-4" "No accounts with empty passwords" \
                "ACCESS CONTROL" "All shadow entries have a password or lock." ""
        else
            record_result "FAIL" "CIS-ACC-4" "$empty_pw account(s) have empty passwords" \
                "ACCESS CONTROL" "Empty password fields found in /etc/shadow." \
                "Lock or set passwords: passwd -l <user>"
        fi
    fi

    # Inactive account lockout
    local inactive; inactive=$(grep -E "^\s*INACTIVE" /etc/default/useradd 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "N/A")
    local max_inactive=35
    rhel_ge 9 && max_inactive=35
    if [[ "$inactive" =~ ^[0-9]+$ ]] && [[ "$inactive" -le "$max_inactive" ]] && [[ "$inactive" -gt 0 ]]; then
        record_result "PASS" "CIS-ACC-5" "Inactive account lock = $inactive days (≤$max_inactive)" \
            "ACCESS CONTROL" "Inactive account lockout is configured." ""
    else
        record_result "FAIL" "CIS-ACC-5" "Inactive account lock = $inactive (expected 1–$max_inactive)" \
            "ACCESS CONTROL" "Inactive account lockout is not properly configured." \
            "Set 'INACTIVE=$max_inactive' in /etc/default/useradd && useradd -D -f $max_inactive"
    fi

    # NTP / chrony / time sync
    banner "CIS — Time Synchronization"
    local time_active=false
    for svc in chronyd ntpd timesyncd; do
        systemctl is-active "$svc" &>/dev/null && time_active=true && break
    done
    if [[ "$time_active" == true ]]; then
        record_result "PASS" "CIS-TIME-1" "Time synchronization service is active" \
            "AUDIT AND ACCOUNTABILITY" "chronyd/ntpd/timesyncd is running." ""
    else
        record_result "FAIL" "CIS-TIME-1" "No time sync service is active" \
            "AUDIT AND ACCOUNTABILITY" "Time synchronization is not running." \
            "systemctl --now enable chronyd"
    fi
}

# =============================================================================
#  ███████╗████████╗██╗ ██████╗
#  ██╔════╝╚══██╔══╝██║██╔════╝
#  ███████╗   ██║   ██║██║  ███╗
#  ╚════██║   ██║   ██║██║   ██║
#  ███████║   ██║   ██║╚██████╔╝
#  ╚══════╝   ╚═╝   ╚═╝ ╚═════╝
#  DISA STIG CHECKS (RHEL 6–9 version-aware)
# =============================================================================

run_stig_checks() {
    banner "STIG — High Severity (CAT I) Checks"

    # Supported release
    local is_supported=false
    if echo "$RHEL_FULL" | grep -qE "release (6|7|8|9|10)\."; then is_supported=true; fi
    if [[ "$is_supported" == true ]]; then
        record_result "PASS" "STIG-OS-1" "OS is a vendor-supported release: $RHEL_FULL" \
            "SYSTEM INTEGRITY" "Detected OS version is supported." ""
    else
        record_result "WARN" "STIG-OS-1" "OS support status could not be confirmed" \
            "SYSTEM INTEGRITY" "Verify $RHEL_FULL has active vendor support." \
            "Check: https://access.redhat.com/product-life-cycles"
    fi

    # FIPS mode
    local fips_en; fips_en=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo "0")
    if [[ "$fips_en" == "1" ]]; then
        record_result "PASS" "STIG-FIPS-1" "FIPS 140-2/3 mode is enabled" \
            "SYSTEM INTEGRITY" "FIPS mode is active (fips_enabled=1)." ""
    else
        record_result "FAIL" "STIG-FIPS-1" "FIPS mode is NOT enabled (fips_enabled=$fips_en)" \
            "SYSTEM INTEGRITY" "FIPS-validated cryptography is not enforced." \
            "fips-mode-setup --enable && reboot"
    fi

    # RHEL 9: crypto policy must not be overridden
    if rhel_ge 9; then
        local cp; cp=$(update-crypto-policies --show 2>/dev/null || echo "N/A")
        if [[ "$cp" == "FIPS" ]]; then
            record_result "PASS" "STIG-CRYPTO-1" "System crypto policy = FIPS" \
                "SYSTEM INTEGRITY" "System-wide crypto policy is set to FIPS." ""
        else
            record_result "FAIL" "STIG-CRYPTO-1" "System crypto policy = $cp (expected FIPS)" \
                "SYSTEM INTEGRITY" "Crypto policy is not FIPS." \
                "update-crypto-policies --set FIPS && reboot"
        fi
    fi

    # Disk encryption (LUKS)
    if lsblk -o TYPE 2>/dev/null | grep -q "crypt" || blkid 2>/dev/null | grep -qi "LUKS"; then
        record_result "PASS" "STIG-LUKS-1" "Disk encryption (LUKS) detected" \
            "MEDIA PROTECTION" "At least one LUKS encrypted partition found." ""
    else
        record_result "WARN" "STIG-LUKS-1" "No LUKS disk encryption detected" \
            "MEDIA PROTECTION" "No LUKS partitions found — data-at-rest may not be protected." \
            "Implement LUKS encryption on partitions holding sensitive data."
    fi

    # shosts.equiv
    if find /etc -name "shosts.equiv" 2>/dev/null | grep -q .; then
        record_result "FAIL" "STIG-RHOST-1" "shosts.equiv files found" \
            "ACCESS CONTROL" "Host-based auth files exist on this system." \
            "find / -name shosts.equiv -delete"
    else
        record_result "PASS" "STIG-RHOST-1" "No shosts.equiv files found" \
            "ACCESS CONTROL" "No shosts.equiv found." ""
    fi

    # .shosts files
    if find /root /home -name ".shosts" 2>/dev/null | grep -q .; then
        record_result "FAIL" "STIG-RHOST-2" ".shosts files found in home directories" \
            "ACCESS CONTROL" ".shosts files present — host-based auth risk." \
            "find /root /home -name .shosts -delete"
    else
        record_result "PASS" "STIG-RHOST-2" "No .shosts files found" \
            "ACCESS CONTROL" "No .shosts files detected." ""
    fi

    # Dangerous packages
    local dangerous_pkgs=(telnet-server rsh-server tftp-server vsftpd sendmail)
    rhel_ge 8 && dangerous_pkgs+=(abrt abrt-cli libreport)
    rhel_ge 9 && dangerous_pkgs+=(ypserv nfs-utils gssproxy iprutils tuned quagga)

    for pkg in "${dangerous_pkgs[@]}"; do
        if rpm -q "$pkg" &>/dev/null 2>&1; then
            record_result "FAIL" "STIG-PKG-$pkg" "Dangerous package '$pkg' is installed" \
                "CONFIGURATION MANAGEMENT" "$pkg should not be installed on this system." \
                "dnf remove $pkg"
        else
            record_result "PASS" "STIG-PKG-$pkg" "Package '$pkg' is not installed" \
                "CONFIGURATION MANAGEMENT" "$pkg is not present." ""
        fi
    done

    # Required packages (RHEL 9+)
    if rhel_ge 9; then
        local required_pkgs=(openssl-pkcs11 gnutls-utils nss-tools rng-tools s-nail libreswan usbguard)
        for pkg in "${required_pkgs[@]}"; do
            if rpm -q "$pkg" &>/dev/null 2>&1; then
                record_result "PASS" "STIG-REQPKG-$pkg" "Required package '$pkg' is installed" \
                    "SYSTEM INTEGRITY" "$pkg is present as required by STIG." ""
            else
                record_result "FAIL" "STIG-REQPKG-$pkg" "Required package '$pkg' is NOT installed" \
                    "SYSTEM INTEGRITY" "$pkg is required by RHEL 9 STIG but missing." \
                    "dnf install $pkg"
            fi
        done
    fi

    # Ctrl-Alt-Delete
    if systemctl status ctrl-alt-del.target 2>/dev/null | grep -q "masked"; then
        record_result "PASS" "STIG-CAD-1" "Ctrl-Alt-Delete is masked" \
            "CONFIGURATION MANAGEMENT" "ctrl-alt-del.target is masked." ""
    else
        record_result "FAIL" "STIG-CAD-1" "Ctrl-Alt-Delete is NOT masked" \
            "CONFIGURATION MANAGEMENT" "ctrl-alt-del.target is not masked." \
            "systemctl mask ctrl-alt-del.target"
    fi

    banner "STIG — Medium Severity (CAT II) Key Checks"

    # SSH banner
    local banner_file; banner_file=$(sshd -T 2>/dev/null | grep "^banner " | awk '{print $2}' || \
        grep -iE "^\s*Banner\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "none")
    if [[ "$banner_file" != "none" ]] && [[ "$banner_file" != "none" ]] && [[ -f "$banner_file" ]] && grep -qiE "authorized|consent|monitored|government" "$banner_file" 2>/dev/null; then
        record_result "PASS" "STIG-BNR-1" "SSH banner configured with consent language" \
            "ACCESS CONTROL" "SSH banner at $banner_file contains required text." ""
    elif [[ -f "$banner_file" ]]; then
        record_result "WARN" "STIG-BNR-1" "SSH banner exists but may lack required consent text" \
            "ACCESS CONTROL" "Banner at $banner_file may not contain required legal text." \
            "Add mandatory consent/authorized-use text to $banner_file"
    else
        record_result "FAIL" "STIG-BNR-1" "No SSH banner configured" \
            "ACCESS CONTROL" "No SSH login banner found." \
            "Create /etc/issue.net with consent text and set 'Banner /etc/issue.net' in sshd_config"
    fi

    # STIG: no NOPASSWD in sudoers
    if grep -rqE "^\s*[^#].*NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        record_result "FAIL" "STIG-SUDO-1" "NOPASSWD found in sudoers configuration" \
            "ACCESS CONTROL" "Some sudo rules allow passwordless privilege escalation." \
            "Remove NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/"
    else
        record_result "PASS" "STIG-SUDO-1" "No NOPASSWD entries in sudoers" \
            "ACCESS CONTROL" "All sudo rules require password authentication." ""
    fi

    # RHEL 9: USBGuard
    if rhel_ge 9; then
        if rpm -q usbguard &>/dev/null 2>&1 && systemctl is-enabled usbguard &>/dev/null; then
            record_result "PASS" "STIG-USB-1" "USBGuard is installed and enabled" \
                "MEDIA PROTECTION" "USB device authorization policy is active." ""
        else
            record_result "FAIL" "STIG-USB-1" "USBGuard is not installed or not enabled" \
                "MEDIA PROTECTION" "USB peripherals are not being controlled by USBGuard." \
                "dnf install usbguard && systemctl --now enable usbguard"
        fi
    fi

    # SSH key permissions
    local bad_pub; bad_pub=$(find /etc/ssh -name "*.pub" ! -perm 644 2>/dev/null | wc -l)
    if [[ "$bad_pub" -eq 0 ]]; then
        record_result "PASS" "STIG-SSH-KEYS-1" "SSH public host keys have mode 0644" \
            "ACCESS CONTROL" "All /etc/ssh/*.pub files are mode 644." ""
    else
        record_result "FAIL" "STIG-SSH-KEYS-1" "$bad_pub SSH public key file(s) with wrong permissions" \
            "ACCESS CONTROL" "SSH public key file permissions are not 644." \
            "chmod 644 /etc/ssh/*.pub"
    fi

    local bad_priv; bad_priv=$(find /etc/ssh -name "ssh_host_*_key" ! -name "*.pub" \
        \( ! -perm 640 -a ! -perm 600 \) 2>/dev/null | wc -l)
    if [[ "$bad_priv" -eq 0 ]]; then
        record_result "PASS" "STIG-SSH-KEYS-2" "SSH private host keys have mode 640 or 600" \
            "ACCESS CONTROL" "All SSH private host keys have correct permissions." ""
    else
        record_result "FAIL" "STIG-SSH-KEYS-2" "$bad_priv SSH private key file(s) with wrong permissions" \
            "ACCESS CONTROL" "SSH private key permissions are too permissive." \
            "chmod 600 /etc/ssh/ssh_host_*_key"
    fi

    # sshd_config ownership (RHEL 9)
    if rhel_ge 9; then
        local sshd_owner; sshd_owner=$(stat -Lc "%U:%G" /etc/ssh/sshd_config 2>/dev/null || echo "N/A")
        if [[ "$sshd_owner" == "root:root" ]]; then
            record_result "PASS" "STIG-SSH-CFG-1" "sshd_config owned by root:root" \
                "ACCESS CONTROL" "SSH server config has correct ownership." ""
        else
            record_result "FAIL" "STIG-SSH-CFG-1" "sshd_config ownership = $sshd_owner (expected root:root)" \
                "ACCESS CONTROL" "sshd_config is not owned by root:root." \
                "chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config"
        fi
    fi

    # Audit logs permissions
    if needs_root "STIG-AUD-LOG" "Check audit log file permissions" "AUDIT AND ACCOUNTABILITY"; then
        local audit_dir; audit_dir=$(grep -E "^\s*log_file\s*=" /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | xargs dirname 2>/dev/null || echo "/var/log/audit")
        if [[ -d "$audit_dir" ]]; then
            local bad_audit; bad_audit=$(find "$audit_dir" -type f ! -perm 600 2>/dev/null | wc -l)
            if [[ "$bad_audit" -eq 0 ]]; then
                record_result "PASS" "STIG-AUD-LOG" "Audit log files have mode 0600" \
                    "AUDIT AND ACCOUNTABILITY" "All audit logs in $audit_dir are mode 600." ""
            else
                record_result "FAIL" "STIG-AUD-LOG" "$bad_audit audit log file(s) with incorrect permissions" \
                    "AUDIT AND ACCOUNTABILITY" "Audit logs in $audit_dir are not mode 600." \
                    "chmod 600 $audit_dir/*.log"
            fi
        fi
    fi

    # Password aging — STIG requires max 60 days on RHEL 8/9
    if rhel_ge 8; then
        local pass_max; pass_max=$(grep -E "^\s*PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "N/A")
        if [[ "$pass_max" =~ ^[0-9]+$ ]] && [[ "$pass_max" -le 60 ]]; then
            record_result "PASS" "STIG-PW-AGE" "PASS_MAX_DAYS = $pass_max (≤60)" \
                "ACCESS CONTROL" "Password max age meets STIG requirement." ""
        else
            record_result "FAIL" "STIG-PW-AGE" "PASS_MAX_DAYS = $pass_max (STIG requires ≤60)" \
                "ACCESS CONTROL" "Password maximum age exceeds 60 days." \
                "Set 'PASS_MAX_DAYS 60' in /etc/login.defs"
        fi
    fi

    # Password min length 15 (STIG)
    if rhel_ge 8; then
        local pwq_minlen; pwq_minlen=$(grep -E "^\s*minlen\s*=" /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "N/A")
        if [[ "$pwq_minlen" =~ ^[0-9]+$ ]] && [[ "$pwq_minlen" -ge 15 ]]; then
            record_result "PASS" "STIG-PW-LEN" "pwquality minlen = $pwq_minlen (≥15)" \
                "ACCESS CONTROL" "Password minimum length meets STIG requirement." ""
        else
            record_result "FAIL" "STIG-PW-LEN" "pwquality minlen = $pwq_minlen (STIG requires ≥15)" \
                "ACCESS CONTROL" "Password minimum length is below 15 characters." \
                "Set 'minlen = 15' in /etc/security/pwquality.conf"
        fi
    fi

    # NTP check
    if systemctl is-active chronyd &>/dev/null || systemctl is-active ntpd &>/dev/null; then
        record_result "PASS" "STIG-NTP-1" "Time sync service is active" \
            "AUDIT AND ACCOUNTABILITY" "chronyd or ntpd is running." ""
    else
        record_result "FAIL" "STIG-NTP-1" "No time sync service is active" \
            "AUDIT AND ACCOUNTABILITY" "Neither chronyd nor ntpd is running." \
            "systemctl --now enable chronyd"
    fi

    # Wireless interfaces
    if ip link show 2>/dev/null | grep -qiE "wlan|wifi|wireless"; then
        record_result "WARN" "STIG-WIFI-1" "Wireless network interface(s) detected" \
            "NETWORK CONFIGURATION" "Wireless interfaces found. Disable if not required." \
            "nmcli radio wifi off  OR  ip link set <wlan_iface> down"
    else
        record_result "PASS" "STIG-WIFI-1" "No wireless interfaces detected" \
            "NETWORK CONFIGURATION" "No wireless interfaces found." ""
    fi

    # Bluetooth
    if systemctl is-active bluetooth &>/dev/null 2>&1; then
        record_result "FAIL" "STIG-BT-1" "Bluetooth service is active" \
            "CONFIGURATION MANAGEMENT" "Bluetooth is running and should be disabled." \
            "systemctl --now disable bluetooth && echo 'install bluetooth /bin/false' >> /etc/modprobe.d/hardening.conf"
    else
        record_result "PASS" "STIG-BT-1" "Bluetooth service is not active" \
            "CONFIGURATION MANAGEMENT" "Bluetooth is disabled." ""
    fi
}

# =============================================================================
#  ██████╗  ██████╗ ███████╗████████╗██╗   ██╗██████╗ ███████╗
#  ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██║   ██║██╔══██╗██╔════╝
#  ██████╔╝██║   ██║███████╗   ██║   ██║   ██║██████╔╝█████╗
#  ██╔═══╝ ██║   ██║╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝
#  ██║     ╚██████╔╝███████║   ██║   ╚██████╔╝██║  ██║███████╗
#  ╚═╝      ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
#  LYNIS-STYLE POSTURE CHECKS
# =============================================================================

run_posture_checks() {
    banner "POSTURE — File System Integrity"

    # World-writable files in /etc
    local ww_etc; ww_etc=$(find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | wc -l)
    if [[ "$ww_etc" -eq 0 ]]; then
        record_result "PASS" "POS-FS-1" "No world-writable files in /etc" \
            "FILE INTEGRITY" "No world-writable files found in /etc (depth 2)." ""
    else
        record_result "FAIL" "POS-FS-1" "$ww_etc world-writable file(s) in /etc" \
            "FILE INTEGRITY" "World-writable files found in /etc." \
            "find /etc -maxdepth 2 -perm -o+w -type f -exec chmod o-w {} \\;"
    fi

    # Sticky bit on world-writable directories
    # Scoped to key dirs only — avoids full filesystem scan on production
    local no_sticky; no_sticky=$(find /tmp /var /home /srv /opt -maxdepth 3 -xdev -perm -0002 -type d ! -perm -1000 2>/dev/null | wc -l)
    if [[ "$no_sticky" -eq 0 ]]; then
        record_result "PASS" "POS-FS-2" "All world-writable directories have sticky bit set" \
            "FILE INTEGRITY" "No world-writable dirs missing sticky bit." ""
    else
        record_result "FAIL" "POS-FS-2" "$no_sticky world-writable dir(s) missing sticky bit" \
            "FILE INTEGRITY" "Some world-writable directories lack sticky bit." \
            "find / -xdev -perm -0002 -type d ! -perm -1000 -exec chmod +t {} \\;"
    fi

    # SUID/SGID inventory (informational)
    local suid_count; suid_count=$(find /usr/bin /usr/sbin /bin /sbin -perm /6000 2>/dev/null | wc -l)
    record_result "INFO" "POS-FS-3" "$suid_count SUID/SGID files in standard bin dirs" \
        "FILE INTEGRITY" "Review SUID/SGID binaries periodically." \
        "find / -perm /6000 -type f 2>/dev/null"

    # AIDE
    if rpm -q aide &>/dev/null 2>&1 || command -v aide &>/dev/null; then
        record_result "PASS" "POS-FS-4" "AIDE file integrity monitoring is installed" \
            "FILE INTEGRITY" "AIDE package is present." ""
    else
        record_result "WARN" "POS-FS-4" "AIDE is not installed" \
            "FILE INTEGRITY" "No file integrity monitoring tool found." \
            "dnf install aide && aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
    fi

    # RPM integrity (root only — can be slow, limited to quick pass)
    if needs_root "POS-FS-5" "RPM package file integrity check (rpm -Va)" "FILE INTEGRITY"; then
        # rpm -Va can be slow on large installs — capped at 30s with timeout
        local rpm_changed; rpm_changed=$(run_to 30 rpm -Va --nofiledigest 2>/dev/null | grep -cE "^\.M\.|^S\." || true)
        if [[ "$rpm_changed" -eq 0 ]]; then
            record_result "PASS" "POS-FS-5" "No modified RPM-owned files detected" \
                "FILE INTEGRITY" "rpm -Va found no modified package files." ""
        else
            record_result "WARN" "POS-FS-5" "$rpm_changed RPM-owned file(s) may be modified" \
                "FILE INTEGRITY" "rpm -Va detected $rpm_changed potentially modified files." \
                "Review: rpm -Va | grep -E '^.M|^S'"
        fi
    fi

    banner "POSTURE — Account & Authentication Hygiene"

    # Interactive accounts with no expiry
    local no_expiry=0
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$uid" -lt 1000 ]] && continue
        [[ "$shell" == "/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
        local exp; exp=$(chage -l "$user" 2>/dev/null | grep "Account expires" | awk -F: '{print $2}' | tr -d ' ' || echo "")
        [[ "$exp" == "never" ]] && no_expiry=$(( no_expiry + 1 ))
    done < /etc/passwd
    if [[ "$no_expiry" -eq 0 ]]; then
        record_result "PASS" "POS-AUTH-1" "All interactive accounts have expiry set" \
            "ACCESS CONTROL" "No interactive accounts with 'never' expiry." ""
    else
        record_result "WARN" "POS-AUTH-1" "$no_expiry interactive account(s) have no expiry" \
            "ACCESS CONTROL" "Some interactive accounts never expire." \
            "chage -E YYYY-MM-DD <username>"
    fi

    # System accounts with shells
    local sys_with_shell; sys_with_shell=$(awk -F: '$3<1000 && $1!="root" && $7!~/nologin|false/' /etc/passwd 2>/dev/null | wc -l)
    if [[ "$sys_with_shell" -eq 0 ]]; then
        record_result "PASS" "POS-AUTH-2" "No system accounts with interactive shells" \
            "ACCESS CONTROL" "All system accounts use nologin/false shells." ""
    else
        record_result "WARN" "POS-AUTH-2" "$sys_with_shell system account(s) have interactive shells" \
            "ACCESS CONTROL" "System accounts should not have login shells." \
            "usermod -s /sbin/nologin <username>"
    fi

    # Cron access control
    if [[ -f /etc/cron.allow ]]; then
        record_result "PASS" "POS-CRON-1" "/etc/cron.allow exists (restricts cron access)" \
            "ACCESS CONTROL" "cron.allow is configured." ""
    elif [[ -f /etc/cron.deny ]]; then
        record_result "WARN" "POS-CRON-1" "/etc/cron.deny exists but cron.allow is preferred" \
            "ACCESS CONTROL" "cron.deny is less strict than cron.allow." \
            "Create /etc/cron.allow and list permitted users"
    else
        record_result "FAIL" "POS-CRON-1" "No cron access control file (/etc/cron.allow or cron.deny)" \
            "ACCESS CONTROL" "No restriction on who can use cron." \
            "Create /etc/cron.allow with permitted users only"
    fi

    banner "POSTURE — Crypto & System Posture"

    # System crypto policy (RHEL 7+)
    if rhel_ge 7; then
        local cp; cp=$(update-crypto-policies --show 2>/dev/null || echo "N/A")
        case "$cp" in
            FIPS)    record_result "PASS" "POS-CRYPTO-1" "System crypto policy = FIPS" \
                         "SYSTEM INTEGRITY" "FIPS crypto policy is active." "" ;;
            DEFAULT) record_result "WARN" "POS-CRYPTO-1" "System crypto policy = DEFAULT (recommend FIPS)" \
                         "SYSTEM INTEGRITY" "Non-FIPS crypto policy in use." \
                         "update-crypto-policies --set FIPS && reboot" ;;
            *)       record_result "INFO" "POS-CRYPTO-1" "System crypto policy = $cp" \
                         "SYSTEM INTEGRITY" "Crypto policy: $cp." "" ;;
        esac
    fi

    # Secure Boot
    if command -v mokutil &>/dev/null && mokutil --sb-state 2>/dev/null | grep -q "enabled"; then
        record_result "PASS" "POS-BOOT-1" "UEFI Secure Boot is enabled" \
            "SYSTEM INTEGRITY" "Secure Boot is active." ""
    elif [[ -d /sys/firmware/efi ]]; then
        record_result "WARN" "POS-BOOT-1" "UEFI present but Secure Boot status unknown" \
            "SYSTEM INTEGRITY" "UEFI firmware detected — verify Secure Boot in firmware settings." \
            "mokutil --sb-state"
    else
        record_result "INFO" "POS-BOOT-1" "System appears to be BIOS/legacy (no UEFI)" \
            "SYSTEM INTEGRITY" "No UEFI detected — Secure Boot not applicable." ""
    fi

    # NX/DEP
    if grep -qi "nx" /proc/cpuinfo 2>/dev/null; then
        record_result "PASS" "POS-HW-1" "CPU NX/XD (No-Execute) bit supported" \
            "SYSTEM INTEGRITY" "Hardware NX support detected in /proc/cpuinfo." ""
    else
        record_result "INFO" "POS-HW-1" "NX/XD bit status could not be confirmed" \
            "SYSTEM INTEGRITY" "Could not confirm NX hardware feature." ""
    fi

    banner "POSTURE — Network Exposure"

    # Listening services inventory
    local listen_count; listen_count=$(ss -tlnp 2>/dev/null | grep -c "LISTEN" || true)
    record_result "INFO" "POS-NET-1" "$listen_count listening TCP service(s) detected" \
        "NETWORK CONFIGURATION" "Review all listening ports and disable unneeded services." \
        "ss -tlnp"

    # Promiscuous mode interfaces (RHEL 9 STIG)
    local promisc; promisc=$(ip link show 2>/dev/null | grep -c "PROMISC" || true)
    if [[ "$promisc" -eq 0 ]]; then
        record_result "PASS" "POS-NET-2" "No interfaces in promiscuous mode" \
            "NETWORK CONFIGURATION" "No promiscuous mode network interfaces detected." ""
    else
        record_result "FAIL" "POS-NET-2" "$promisc interface(s) in promiscuous mode" \
            "NETWORK CONFIGURATION" "Promiscuous mode allows capture of all network traffic." \
            "ip link set <iface> promisc off"
    fi

    # IPv6 status
    local ipv6; ipv6=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
    if [[ "$ipv6" == "1" ]]; then
        record_result "INFO" "POS-NET-3" "IPv6 is disabled system-wide" \
            "NETWORK CONFIGURATION" "IPv6 is disabled." ""
    else
        record_result "INFO" "POS-NET-3" "IPv6 is enabled" \
            "NETWORK CONFIGURATION" "IPv6 is enabled — ensure it is properly configured." \
            "To disable: echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.d/99-ipv6.conf"
    fi

    banner "POSTURE — Log File Health"

    for logfile in /var/log/messages /var/log/secure /var/log/audit/audit.log; do
        if [[ -f "$logfile" ]]; then
            record_result "PASS" "POS-LOG-1" "Log file present: $logfile" \
                "AUDIT AND ACCOUNTABILITY" "$logfile exists." ""
        else
            record_result "WARN" "POS-LOG-1" "Log file missing: $logfile" \
                "AUDIT AND ACCOUNTABILITY" "$logfile does not exist." \
                "Verify rsyslog/auditd is configured to write $logfile"
        fi
    done
}

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
#  Covers all major Lynis test groups: AUTH BOOT CRYP FILE FIRE HRDN
#  INSE KRNL LOGG MALW NETW PKGS SCHD SHLL STRG TIME TOOL USERS
# =============================================================================

run_hardening_scan() {

    # ── AUTH: Authentication & PAM ────────────────────────────────────────────
    banner "HARDENING [AUTH] — Authentication & PAM"

    # PAM password requisite
    if grep -rqE "pam_pwquality|pam_cracklib" /etc/pam.d/ 2>/dev/null; then
        record_result "PASS" "HRDN-AUTH-1" "PAM password quality module is configured" \
            "AUTHENTICATION" "pam_pwquality or pam_cracklib found in PAM config." ""
    else
        record_result "FAIL" "HRDN-AUTH-1" "PAM password quality module not configured" \
            "AUTHENTICATION" "No pam_pwquality/pam_cracklib in /etc/pam.d/." \
            "authconfig --enablereqpass --update  OR  configure pam_pwquality in /etc/pam.d/system-auth"
    fi

    # PAM nullok — allow empty passwords
    if grep -rqE "nullok" /etc/pam.d/ 2>/dev/null; then
        record_result "FAIL" "HRDN-AUTH-2" "nullok found in PAM config (empty passwords allowed)" \
            "AUTHENTICATION" "PAM nullok option permits passwordless logins." \
            "Remove 'nullok' from all files in /etc/pam.d/"
    else
        record_result "PASS" "HRDN-AUTH-2" "PAM nullok is not present" \
            "AUTHENTICATION" "Empty password logins are not permitted via PAM." ""
    fi

    # /etc/sudoers syntax + NOPASSWD (already in STIG but reinforced here)
    if [[ -f /etc/sudoers ]]; then
        local nopasswd_count; nopasswd_count=$(grep -c "NOPASSWD" /etc/sudoers 2>/dev/null; true)
        if [[ "$nopasswd_count" -eq 0 ]]; then
            record_result "PASS" "HRDN-AUTH-3" "No NOPASSWD entries in /etc/sudoers" \
                "AUTHENTICATION" "All sudo rules require password." ""
        else
            record_result "FAIL" "HRDN-AUTH-3" "$nopasswd_count NOPASSWD entry/entries in sudoers" \
                "AUTHENTICATION" "Passwordless sudo is configured." \
                "Remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/*"
        fi
    fi

    # su restricted to wheel
    if grep -qE "^\s*auth\s+required\s+pam_wheel" /etc/pam.d/su 2>/dev/null; then
        record_result "PASS" "HRDN-AUTH-4" "su access restricted to wheel group via pam_wheel" \
            "AUTHENTICATION" "pam_wheel.so required in /etc/pam.d/su." ""
    else
        record_result "FAIL" "HRDN-AUTH-4" "su is not restricted to wheel group" \
            "AUTHENTICATION" "pam_wheel.so not enforced for su." \
            "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su"
    fi

    # Password history (pam_pwhistory)
    if grep -rqE "pam_pwhistory|remember=" /etc/pam.d/ 2>/dev/null; then
        local rem_val; rem_val=$(grep -rEh "remember=[0-9]+" /etc/pam.d/ 2>/dev/null | grep -oE "remember=[0-9]+" | head -1 | cut -d= -f2 || echo "0")
        if [[ "$rem_val" =~ ^[0-9]+$ ]] && [[ "$rem_val" -ge 5 ]]; then
            record_result "PASS" "HRDN-AUTH-5" "Password history enforcement: remember=$rem_val (≥5)" \
                "AUTHENTICATION" "Password reuse is restricted." ""
        else
            record_result "WARN" "HRDN-AUTH-5" "Password history remember=$rem_val (recommended ≥5)" \
                "AUTHENTICATION" "Password reuse restriction may be insufficient." \
                "Add 'password required pam_pwhistory.so remember=5' to /etc/pam.d/system-auth"
        fi
    else
        record_result "FAIL" "HRDN-AUTH-5" "Password history (pam_pwhistory) not configured" \
            "AUTHENTICATION" "Previous passwords can be immediately reused." \
            "Add 'password required pam_pwhistory.so remember=5' to /etc/pam.d/system-auth"
    fi

    # login.defs SHA512 rounds
    local rounds; rounds=$(grep -E "^\s*SHA_CRYPT_MIN_ROUNDS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "0")
    if [[ "$rounds" =~ ^[0-9]+$ ]] && [[ "$rounds" -ge 5000 ]]; then
        record_result "PASS" "HRDN-AUTH-6" "SHA_CRYPT_MIN_ROUNDS = $rounds (≥5000)" \
            "AUTHENTICATION" "Sufficient password hashing rounds configured." ""
    else
        record_result "FAIL" "HRDN-AUTH-6" "SHA_CRYPT_MIN_ROUNDS = $rounds (expected ≥5000)" \
            "AUTHENTICATION" "Insufficient password hashing rounds." \
            "Set 'SHA_CRYPT_MIN_ROUNDS 5000' in /etc/login.defs"
    fi

    # ── BOOT: Bootloader & Init ───────────────────────────────────────────────
    banner "HARDENING [BOOT] — Bootloader & Init"

    # Single-user mode requires auth
    if grep -qE "ExecStart.*-b|sulogin|sushell" /usr/lib/systemd/system/rescue.service \
       /usr/lib/systemd/system/emergency.service 2>/dev/null; then
        record_result "PASS" "HRDN-BOOT-1" "Rescue/emergency mode requires authentication" \
            "CONFIGURATION MANAGEMENT" "systemd rescue/emergency services use sulogin." ""
    else
        record_result "WARN" "HRDN-BOOT-1" "Rescue/emergency mode authentication unclear" \
            "CONFIGURATION MANAGEMENT" "Verify rescue/emergency services require root password." \
            "Check /usr/lib/systemd/system/rescue.service and emergency.service"
    fi

    # systemd default target (should not be graphical on servers)
    local def_target; def_target=$(systemctl get-default 2>/dev/null || echo "unknown")
    if [[ "$def_target" == "multi-user.target" ]]; then
        record_result "PASS" "HRDN-BOOT-2" "Default systemd target = multi-user (non-graphical)" \
            "CONFIGURATION MANAGEMENT" "System boots to CLI, not graphical environment." ""
    elif [[ "$def_target" == "graphical.target" ]]; then
        record_result "WARN" "HRDN-BOOT-2" "Default target = graphical.target (consider multi-user for servers)" \
            "CONFIGURATION MANAGEMENT" "Graphical environment increases attack surface." \
            "systemctl set-default multi-user.target"
    else
        record_result "INFO" "HRDN-BOOT-2" "Default target = $def_target" \
            "CONFIGURATION MANAGEMENT" "Verify this is the intended boot target." ""
    fi

    # interactive boot disabled
    if grep -qE "^\s*PROMPT\s*=\s*no" /etc/sysconfig/init 2>/dev/null || \
       grep -qE "systemd.confirm_spawn=0\|quiet" /proc/cmdline 2>/dev/null; then
        record_result "PASS" "HRDN-BOOT-3" "Interactive boot is disabled" \
            "CONFIGURATION MANAGEMENT" "System does not allow interactive boot prompts." ""
    else
        record_result "WARN" "HRDN-BOOT-3" "Interactive boot status could not be confirmed" \
            "CONFIGURATION MANAGEMENT" "Verify interactive boot is disabled." \
            "Set PROMPT=no in /etc/sysconfig/init  OR add 'systemd.confirm_spawn=0' to GRUB_CMDLINE_LINUX"
    fi

    # ── CRYP: Cryptography ────────────────────────────────────────────────────
    banner "HARDENING [CRYP] — Cryptography & Certificates"

    # SSL/TLS cert expiry in /etc/pki
    local expired_certs=0 expiring_soon=0
    local now_epoch; now_epoch=$(date +%s)
    while IFS= read -r certfile; do
        local exp_date exp_epoch
        exp_date=$(run_to 3 openssl x509 -noout -enddate -in "$certfile" 2>/dev/null | cut -d= -f2) || continue
        exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null) || continue
        local days_left=$(( (exp_epoch - now_epoch) / 86400 ))
        if [[ "$days_left" -lt 0 ]]; then
            expired_certs=$(( expired_certs + 1 ))
        elif [[ "$days_left" -lt 30 ]]; then
            expiring_soon=$(( expiring_soon + 1 ))
        fi
    done < <(find /etc/pki /etc/ssl -name "*.pem" -o -name "*.crt" 2>/dev/null | head -30)

    if [[ "$expired_certs" -eq 0 && "$expiring_soon" -eq 0 ]]; then
        record_result "PASS" "HRDN-CRYP-1" "No expired or soon-expiring certificates found in /etc/pki" \
            "SYSTEM INTEGRITY" "Checked certificates appear valid." ""
    else
        [[ "$expired_certs" -gt 0 ]] && record_result "FAIL" "HRDN-CRYP-1" "$expired_certs expired certificate(s) in /etc/pki" \
            "SYSTEM INTEGRITY" "Expired certificates found." \
            "Renew expired certificates in /etc/pki"
        [[ "$expiring_soon" -gt 0 ]] && record_result "WARN" "HRDN-CRYP-2" "$expiring_soon certificate(s) expiring within 30 days" \
            "SYSTEM INTEGRITY" "Certificates expiring soon." \
            "Renew certificates expiring within 30 days"
    fi

    # OpenSSL version
    local ossl_ver; ossl_ver=$(openssl version 2>/dev/null | awk '{print $2}' || echo "N/A")
    record_result "INFO" "HRDN-CRYP-3" "OpenSSL version: $ossl_ver" \
        "SYSTEM INTEGRITY" "Installed OpenSSL: $ossl_ver. Ensure it is patched." \
        "dnf update openssl"

    # GnuTLS
    if command -v gnutls-cli &>/dev/null || rpm -q gnutls &>/dev/null 2>&1; then
        record_result "PASS" "HRDN-CRYP-4" "GnuTLS is installed" \
            "SYSTEM INTEGRITY" "GnuTLS package is present." ""
    else
        record_result "WARN" "HRDN-CRYP-4" "GnuTLS not found" \
            "SYSTEM INTEGRITY" "GnuTLS is not installed." \
            "dnf install gnutls gnutls-utils"
    fi

    # ── INSE: Insecure Protocols & Services ───────────────────────────────────
    banner "HARDENING [INSE] — Insecure Protocols"

    # Telnet client installed
    if rpm -q telnet &>/dev/null 2>&1; then
        record_result "WARN" "HRDN-INSE-1" "telnet client is installed" \
            "CONFIGURATION MANAGEMENT" "Telnet transmits credentials in cleartext." \
            "dnf remove telnet"
    else
        record_result "PASS" "HRDN-INSE-1" "telnet client is not installed" \
            "CONFIGURATION MANAGEMENT" "Insecure telnet client is absent." ""
    fi

    # FTP client
    if rpm -q ftp &>/dev/null 2>&1; then
        record_result "WARN" "HRDN-INSE-2" "ftp client is installed" \
            "CONFIGURATION MANAGEMENT" "FTP transmits credentials in cleartext." \
            "dnf remove ftp"
    else
        record_result "PASS" "HRDN-INSE-2" "ftp client is not installed" \
            "CONFIGURATION MANAGEMENT" "Insecure FTP client is absent." ""
    fi

    # rsh client
    if rpm -q rsh &>/dev/null 2>&1; then
        record_result "FAIL" "HRDN-INSE-3" "rsh client is installed" \
            "CONFIGURATION MANAGEMENT" "rsh is an insecure remote shell protocol." \
            "dnf remove rsh"
    else
        record_result "PASS" "HRDN-INSE-3" "rsh client is not installed" \
            "CONFIGURATION MANAGEMENT" "rsh client is absent." ""
    fi

    # LDAP cleartext (check for ldap:// in config, not ldaps://)
    if grep -rqE "^\s*uri\s+ldap://" /etc/nslcd.conf /etc/sssd/sssd.conf /etc/openldap/ldap.conf 2>/dev/null; then
        record_result "WARN" "HRDN-INSE-4" "LDAP cleartext URI found in config (ldap:// not ldaps://)" \
            "NETWORK CONFIGURATION" "LDAP configured without TLS." \
            "Change ldap:// to ldaps:// in LDAP client configuration"
    else
        record_result "PASS" "HRDN-INSE-4" "No cleartext LDAP URIs found" \
            "NETWORK CONFIGURATION" "LDAP is either not configured or uses TLS." ""
    fi

    # ── KRNL: Kernel — extra checks beyond CIS ────────────────────────────────
    banner "HARDENING [KRNL] — Kernel Extra Checks"

    # kernel.sysrq — should be 0 on production
    local sysrq; sysrq=$(sysctl -n kernel.sysrq 2>/dev/null || echo "N/A")
    if [[ "$sysrq" == "0" ]]; then
        record_result "PASS" "HRDN-KRNL-1" "kernel.sysrq = 0 (disabled)" \
            "CONFIGURATION MANAGEMENT" "Magic SysRq key is disabled." ""
    else
        record_result "WARN" "HRDN-KRNL-1" "kernel.sysrq = $sysrq (expected 0)" \
            "CONFIGURATION MANAGEMENT" "SysRq can allow dangerous low-level operations." \
            "echo 'kernel.sysrq = 0' >> /etc/sysctl.d/99-hardening.conf && sysctl -w kernel.sysrq=0"
    fi

    # kernel.core_uses_pid
    local core_pid; core_pid=$(sysctl -n kernel.core_uses_pid 2>/dev/null || echo "N/A")
    if [[ "$core_pid" == "1" ]]; then
        record_result "PASS" "HRDN-KRNL-2" "kernel.core_uses_pid = 1" \
            "CONFIGURATION MANAGEMENT" "Core dumps include PID in filename." ""
    else
        record_result "INFO" "HRDN-KRNL-2" "kernel.core_uses_pid = $core_pid" \
            "CONFIGURATION MANAGEMENT" "Consider enabling core_uses_pid." \
            "echo 'kernel.core_uses_pid = 1' >> /etc/sysctl.d/99-hardening.conf"
    fi

    # Kernel module loading locked (RHEL 8+)
    if rhel_ge 8; then
        local kexec_load; kexec_load=$(sysctl -n kernel.kexec_load_disabled 2>/dev/null || echo "N/A")
        if [[ "$kexec_load" == "1" ]]; then
            record_result "PASS" "HRDN-KRNL-3" "kernel.kexec_load_disabled = 1" \
                "CONFIGURATION MANAGEMENT" "Loading a new kernel for execution is disabled." ""
        else
            record_result "FAIL" "HRDN-KRNL-3" "kernel.kexec_load_disabled = $kexec_load (expected 1)" \
                "CONFIGURATION MANAGEMENT" "kexec allows loading alternate kernels." \
                "echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/99-hardening.conf"
        fi
    fi

    # ── LOGG: Logging extended checks ────────────────────────────────────────
    banner "HARDENING [LOGG] — Logging Configuration"

    # Remote logging configured
    if grep -rqE "^\s*\*\.\*\s+@@|^\s*\*\.\*\s+@[^@]|remote_host" \
       /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null; then
        record_result "PASS" "HRDN-LOGG-1" "Remote syslog forwarding is configured" \
            "AUDIT AND ACCOUNTABILITY" "Logs are forwarded to a remote server." ""
    else
        record_result "WARN" "HRDN-LOGG-1" "Remote syslog forwarding is not configured" \
            "AUDIT AND ACCOUNTABILITY" "Logs are only stored locally." \
            "Configure remote logging in /etc/rsyslog.conf: *.* @@logserver:514"
    fi

    # auditd disk_full_action
    if [[ -f /etc/audit/auditd.conf ]]; then
        local dfa; dfa=$(grep -iE "^\s*disk_full_action" /etc/audit/auditd.conf | awk -F= '{print $2}' | tr -d ' ')
        if echo "$dfa" | grep -qiE "halt|single|syslog"; then
            record_result "PASS" "HRDN-LOGG-2" "auditd disk_full_action = $dfa" \
                "AUDIT AND ACCOUNTABILITY" "System takes action when audit disk is full." ""
        else
            record_result "FAIL" "HRDN-LOGG-2" "auditd disk_full_action = $dfa (expected halt/single/syslog)" \
                "AUDIT AND ACCOUNTABILITY" "No action configured when audit disk fills up." \
                "Set 'disk_full_action = halt' in /etc/audit/auditd.conf"
        fi

        # auditd admin_space_left_action
        local asla; asla=$(grep -iE "^\s*admin_space_left_action" /etc/audit/auditd.conf | awk -F= '{print $2}' | tr -d ' ')
        if echo "$asla" | grep -qiE "halt|single|email|exec"; then
            record_result "PASS" "HRDN-LOGG-3" "auditd admin_space_left_action = $asla" \
                "AUDIT AND ACCOUNTABILITY" "Admin notified when audit space is critically low." ""
        else
            record_result "FAIL" "HRDN-LOGG-3" "auditd admin_space_left_action = $asla" \
                "AUDIT AND ACCOUNTABILITY" "No action for critically low audit disk space." \
                "Set 'admin_space_left_action = halt' in /etc/audit/auditd.conf"
        fi
    fi

    # Logrotate configured
    if [[ -f /etc/logrotate.conf ]] || [[ -d /etc/logrotate.d ]]; then
        record_result "PASS" "HRDN-LOGG-4" "logrotate is configured" \
            "AUDIT AND ACCOUNTABILITY" "/etc/logrotate.conf or /etc/logrotate.d exists." ""
    else
        record_result "WARN" "HRDN-LOGG-4" "logrotate configuration not found" \
            "AUDIT AND ACCOUNTABILITY" "Log rotation may not be configured." \
            "Install logrotate: dnf install logrotate"
    fi

    # ── MALW: Malware & Rootkit Tools ─────────────────────────────────────────
    banner "HARDENING [MALW] — Malware & Integrity Tools"

    local malw_found=false
    for tool in rkhunter chkrootkit aide tripwire samhain; do
        if command -v "$tool" &>/dev/null || rpm -q "$tool" &>/dev/null 2>&1; then
            record_result "PASS" "HRDN-MALW-1" "Malware/integrity scanner '$tool' is installed" \
                "SYSTEM INTEGRITY" "$tool is available for periodic scanning." ""
            malw_found=true
        fi
    done
    if [[ "$malw_found" == false ]]; then
        record_result "WARN" "HRDN-MALW-1" "No malware or rootkit scanner installed" \
            "SYSTEM INTEGRITY" "rkhunter, chkrootkit, aide, tripwire, samhain not found." \
            "Install rkhunter: dnf install rkhunter  OR  aide: dnf install aide"
    fi

    # SELinux denials (recent)
    if command -v aureport &>/dev/null; then
        local avc_count; avc_count=$(run_to 10 aureport --avc 2>/dev/null | tail -n +7 | wc -l || echo "0")
        if [[ "$avc_count" -eq 0 ]]; then
            record_result "PASS" "HRDN-MALW-2" "No recent SELinux AVC denials in audit log" \
                "SYSTEM INTEGRITY" "aureport --avc shows no recent denials." ""
        else
            record_result "INFO" "HRDN-MALW-2" "$avc_count SELinux AVC denial(s) found" \
                "SYSTEM INTEGRITY" "SELinux has logged $avc_count AVC denial(s)." \
                "Review: aureport --avc  and  ausearch -m avc -ts recent"
        fi
    fi

    # ── PKGS: Package Management ──────────────────────────────────────────────
    banner "HARDENING [PKGS] — Package Management"

    # Count installed packages (informational)
    local pkg_count; pkg_count=$(rpm -qa 2>/dev/null | wc -l || echo "N/A")
    record_result "INFO" "HRDN-PKGS-1" "$pkg_count RPM packages installed" \
        "CONFIGURATION MANAGEMENT" "Minimise installed packages to reduce attack surface." \
        "Review: rpm -qa | sort  and remove unneeded packages"

    # Check for development tools on production systems
    local dev_pkgs=0
    for pkg in gcc gcc-c++ make gdb strace ltrace; do
        rpm -q "$pkg" &>/dev/null 2>&1 && dev_pkgs=$(( dev_pkgs + 1 ))
    done
    if [[ "$dev_pkgs" -eq 0 ]]; then
        record_result "PASS" "HRDN-PKGS-2" "No compiler/debug tools installed" \
            "CONFIGURATION MANAGEMENT" "gcc, make, gdb, strace, ltrace not found." ""
    else
        record_result "WARN" "HRDN-PKGS-2" "$dev_pkgs compiler/debug tool(s) installed" \
            "CONFIGURATION MANAGEMENT" "Compilers and debug tools increase attack surface." \
            "Remove: dnf remove gcc gcc-c++ make gdb strace ltrace"
    fi

    # ── SCHD: Scheduled Tasks ─────────────────────────────────────────────────
    banner "HARDENING [SCHD] — Scheduled Jobs"

    # World-writable cron dirs
    local ww_cron; ww_cron=$(find /etc/cron* /var/spool/cron 2>/dev/null -perm -o+w -type f | wc -l)
    if [[ "$ww_cron" -eq 0 ]]; then
        record_result "PASS" "HRDN-SCHD-1" "No world-writable cron files found" \
            "CONFIGURATION MANAGEMENT" "Cron files have appropriate permissions." ""
    else
        record_result "FAIL" "HRDN-SCHD-1" "$ww_cron world-writable cron file(s) found" \
            "CONFIGURATION MANAGEMENT" "World-writable cron files are a security risk." \
            "find /etc/cron* /var/spool/cron -perm -o+w -exec chmod o-w {} \\;"
    fi

    # at.allow / at.deny
    if [[ -f /etc/at.allow ]]; then
        record_result "PASS" "HRDN-SCHD-2" "/etc/at.allow exists (at job access controlled)" \
            "ACCESS CONTROL" "at command access is restricted via at.allow." ""
    else
        record_result "WARN" "HRDN-SCHD-2" "/etc/at.allow not found" \
            "ACCESS CONTROL" "at command access is not explicitly restricted." \
            "Create /etc/at.allow listing only permitted users"
    fi

    # ── SHLL: Shell & Environment ─────────────────────────────────────────────
    banner "HARDENING [SHLL] — Shell Configuration"

    # TMOUT in /etc/profile.d (already checked in CIS but important Lynis check)
    local tmout_set; tmout_set=$(grep -rh "TMOUT" /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null | grep -v "^#" | head -1)
    if [[ -n "$tmout_set" ]]; then
        record_result "PASS" "HRDN-SHLL-1" "TMOUT is set in shell profile" \
            "ACCESS CONTROL" "Idle session timeout configured: $tmout_set" ""
    else
        record_result "FAIL" "HRDN-SHLL-1" "TMOUT not set in any shell profile" \
            "ACCESS CONTROL" "Interactive sessions have no idle timeout." \
            "echo 'readonly TMOUT=600' > /etc/profile.d/tmout.sh && chmod +x /etc/profile.d/tmout.sh"
    fi

    # Dangerous PATH entries
    local bad_path=false
    for f in /etc/profile /etc/profile.d/*.sh /etc/bashrc; do
        grep -qE 'PATH=.*(\.|::|^:|:$)' "$f" 2>/dev/null && bad_path=true && break
    done
    if [[ "$bad_path" == false ]]; then
        record_result "PASS" "HRDN-SHLL-2" "No dangerous PATH entries (. or ::) in shell profiles" \
            "ACCESS CONTROL" "Shell profiles do not include current dir in PATH." ""
    else
        record_result "FAIL" "HRDN-SHLL-2" "Dangerous PATH entry found in shell profile" \
            "ACCESS CONTROL" "PATH includes '.' or empty entry — allows local binary hijacking." \
            "Remove '.' and empty entries from PATH in /etc/profile and /etc/bashrc"
    fi

    # Shell history settings
    local histsize; histsize=$(grep -rh "HISTSIZE" /etc/profile /etc/bashrc /etc/profile.d/*.sh 2>/dev/null | grep -v "^#" | grep -oE "[0-9]+" | sort -n | tail -1 || echo "N/A")
    record_result "INFO" "HRDN-SHLL-3" "HISTSIZE = $histsize" \
        "AUDIT AND ACCOUNTABILITY" "Shell command history size." \
        "Set HISTSIZE=1000 and HISTFILESIZE=2000 in /etc/profile"

    # ── STRG: Storage & USB ───────────────────────────────────────────────────
    banner "HARDENING [STRG] — Storage & USB"

    # USB storage kernel module
    local usb_mod; usb_mod=$(lsmod 2>/dev/null | grep -c "^usb_storage" || true)
    local usb_bl; usb_bl=$(grep -rqE "install usb.storage /bin/(false|true)" /etc/modprobe.d/ 2>/dev/null && echo 1 || echo 0)
    if [[ "$usb_mod" -eq 0 && "$usb_bl" -eq 1 ]]; then
        record_result "PASS" "HRDN-STRG-1" "USB mass storage is disabled and blacklisted" \
            "MEDIA PROTECTION" "usb-storage module is not loaded and is blacklisted." ""
    elif [[ "$usb_mod" -eq 0 ]]; then
        record_result "WARN" "HRDN-STRG-1" "USB storage not loaded but not blacklisted" \
            "MEDIA PROTECTION" "usb-storage is absent but could be loaded." \
            "echo 'install usb-storage /bin/false' >> /etc/modprobe.d/hardening.conf"
    else
        record_result "FAIL" "HRDN-STRG-1" "USB mass storage module is loaded" \
            "MEDIA PROTECTION" "usb-storage is active — USB drives can be mounted." \
            "modprobe -r usb-storage && echo 'install usb-storage /bin/false' >> /etc/modprobe.d/hardening.conf"
    fi

    # Automount
    if systemctl is-active autofs &>/dev/null 2>&1; then
        record_result "FAIL" "HRDN-STRG-2" "autofs automount service is running" \
            "MEDIA PROTECTION" "Automatic media mounting is active." \
            "systemctl --now disable autofs"
    else
        record_result "PASS" "HRDN-STRG-2" "autofs is not running" \
            "MEDIA PROTECTION" "Automatic media mounting is disabled." ""
    fi

    # ── TIME: Time Synchronisation ────────────────────────────────────────────
    banner "HARDENING [TIME] — Time Synchronisation"

    # chrony config — multiple NTP sources
    local ntp_servers=0
    if [[ -f /etc/chrony.conf ]]; then
        ntp_servers=$(grep -cE "^\s*(server|pool)" /etc/chrony.conf 2>/dev/null || echo 0)
    elif [[ -f /etc/ntp.conf ]]; then
        ntp_servers=$(grep -cE "^\s*server" /etc/ntp.conf 2>/dev/null; true)
    fi
    if [[ "$ntp_servers" -ge 2 ]]; then
        record_result "PASS" "HRDN-TIME-1" "$ntp_servers NTP server(s) configured (≥2 for redundancy)" \
            "AUDIT AND ACCOUNTABILITY" "Multiple time sources configured." ""
    elif [[ "$ntp_servers" -eq 1 ]]; then
        record_result "WARN" "HRDN-TIME-1" "Only 1 NTP server configured (recommend ≥2)" \
            "AUDIT AND ACCOUNTABILITY" "Single NTP source is a single point of failure." \
            "Add a second server/pool entry to /etc/chrony.conf"
    else
        record_result "FAIL" "HRDN-TIME-1" "No NTP servers configured in chrony.conf or ntp.conf" \
            "AUDIT AND ACCOUNTABILITY" "Time synchronisation source is not configured." \
            "Add 'pool pool.ntp.org iburst' to /etc/chrony.conf"
    fi

    # chrony tracking — are we actually synced?
    if command -v chronyc &>/dev/null; then
        local tracking; tracking=$(run_to 5 chronyc tracking 2>/dev/null | grep "Leap status" | awk '{print $NF}')
        if [[ "$tracking" == "Normal" ]]; then
            record_result "PASS" "HRDN-TIME-2" "chronyc reports time is synchronised (Leap status: Normal)" \
                "AUDIT AND ACCOUNTABILITY" "System clock is synced to NTP." ""
        else
            record_result "WARN" "HRDN-TIME-2" "chronyc Leap status = $tracking (expected Normal)" \
                "AUDIT AND ACCOUNTABILITY" "System clock may not be properly synchronised." \
                "systemctl restart chronyd && chronyc tracking"
        fi
    fi

    # ── TOOL: Security Tools Inventory ───────────────────────────────────────
    banner "HARDENING [TOOL] — Security Tools"

    local tools_present=() tools_absent=()
    local desired_tools=(
        "aide:File integrity monitoring"
        "rkhunter:Rootkit scanner"
        "auditd:Audit daemon"
        "firewalld:Host firewall"
        "fail2ban:Brute force protection"
        "clamav:Antivirus scanner"
        "openscap:OpenSCAP compliance scanner"
        "oscap:OpenSCAP CLI tool"
        "sssd:System security services daemon"
    )

    for entry in "${desired_tools[@]}"; do
        IFS=':' read -r tool desc <<< "$entry"
        if command -v "$tool" &>/dev/null || rpm -q "$tool" &>/dev/null 2>&1 || \
           systemctl list-units --all 2>/dev/null | grep -q "${tool}"; then
            tools_present+=("$tool")
            record_result "PASS" "HRDN-TOOL" "Security tool '$tool' ($desc) is present" \
                "SYSTEM INTEGRITY" "$tool is installed." ""
        else
            tools_absent+=("$tool")
            record_result "INFO" "HRDN-TOOL" "Security tool '$tool' ($desc) not found" \
                "SYSTEM INTEGRITY" "$tool is not installed — consider adding it." \
                "dnf install $tool"
        fi
    done

    # ── USERS: Extended User Checks ───────────────────────────────────────────
    banner "HARDENING [USERS] — User Account Audit"

    # Users with UID >= 1000 (interactive accounts summary)
    local user_count; user_count=$(awk -F: '$3>=1000 && $3<65534' /etc/passwd 2>/dev/null | wc -l)
    record_result "INFO" "HRDN-USERS-1" "$user_count interactive user account(s) (UID ≥1000)" \
        "ACCESS CONTROL" "Review all interactive accounts periodically." \
        "awk -F: '\$3>=1000' /etc/passwd"

    # Accounts with no password expiry set in shadow (needs root)
    if needs_root "HRDN-USERS-2" "Check shadow password expiry fields" "ACCESS CONTROL"; then
        local no_expiry_shadow=0
        while IFS=: read -r user pw _ _ max _ _ _ _; do
            # Skip system/locked accounts
            [[ "$pw" == "!"* || "$pw" == "*" ]] && continue
            [[ "$max" == "99999" || "$max" == "" || "$max" == "0" ]] && no_expiry_shadow=$(( no_expiry_shadow + 1 ))
        done < /etc/shadow 2>/dev/null
        if [[ "$no_expiry_shadow" -eq 0 ]]; then
            record_result "PASS" "HRDN-USERS-2" "All active accounts have password max-age configured" \
                "ACCESS CONTROL" "No accounts with 99999 or empty max password age." ""
        else
            record_result "WARN" "HRDN-USERS-2" "$no_expiry_shadow account(s) have no password expiry" \
                "ACCESS CONTROL" "Accounts with PASS_MAX_DAYS=99999 or unset found." \
                "chage -M 60 <username>  for each affected user"
        fi
    fi

    # Home directory permissions
    local bad_homes=0
    while IFS=: read -r user _ uid _ _ homedir _; do
        [[ "$uid" -lt 1000 ]] && continue
        [[ ! -d "$homedir" ]] && continue
        local hperm; hperm=$(stat -Lc "%a" "$homedir" 2>/dev/null || echo "000")
        # Should be 700 or 750 — not 755 or more permissive
        if [[ "$hperm" -gt 750 ]] 2>/dev/null; then
            bad_homes=$(( bad_homes + 1 ))
        fi
    done < /etc/passwd 2>/dev/null
    if [[ "$bad_homes" -eq 0 ]]; then
        record_result "PASS" "HRDN-USERS-3" "All home directories have mode 750 or less" \
            "ACCESS CONTROL" "Home directory permissions are appropriately restrictive." ""
    else
        record_result "FAIL" "HRDN-USERS-3" "$bad_homes home director(ies) are too permissive (>750)" \
            "ACCESS CONTROL" "Some home directories are world or group-readable." \
            "chmod 750 <homedir>  for each affected user"
    fi

    # ── HRDN: Hardening Score Summary ────────────────────────────────────────
    banner "HARDENING [HRDN] — System Hardening Features"

    # ExecShield / NX
    if grep -qi " nx" /proc/cpuinfo 2>/dev/null; then
        record_result "PASS" "HRDN-HRDN-1" "CPU NX (No-Execute) bit is supported" \
            "SYSTEM INTEGRITY" "Hardware enforced NX/DEP is available." ""
    fi

    # /proc/sys/kernel/exec-shield (RHEL 6 and earlier)
    if [[ -f /proc/sys/kernel/exec-shield ]]; then
        local es; es=$(cat /proc/sys/kernel/exec-shield 2>/dev/null)
        if [[ "$es" == "1" ]]; then
            record_result "PASS" "HRDN-HRDN-2" "ExecShield is enabled" \
                "SYSTEM INTEGRITY" "kernel.exec-shield = 1" ""
        else
            record_result "FAIL" "HRDN-HRDN-2" "ExecShield is not enabled" \
                "SYSTEM INTEGRITY" "kernel.exec-shield = $es" \
                "echo 'kernel.exec-shield = 1' >> /etc/sysctl.d/99-hardening.conf"
        fi
    fi

    # Compiler restrictions
    if [[ -x /usr/bin/gcc ]] || [[ -x /usr/bin/cc ]]; then
        record_result "WARN" "HRDN-HRDN-3" "Compiler (gcc/cc) is executable by all users" \
            "CONFIGURATION MANAGEMENT" "Compilers should be restricted on production servers." \
            "chmod o-x /usr/bin/gcc /usr/bin/cc 2>/dev/null || dnf remove gcc"
    else
        record_result "PASS" "HRDN-HRDN-3" "No compilers found on system PATH" \
            "CONFIGURATION MANAGEMENT" "Compiler tools are not installed or not accessible." ""
    fi

    # Process accounting
    if systemctl is-active psacct &>/dev/null 2>&1 || systemctl is-active acct &>/dev/null 2>&1; then
        record_result "PASS" "HRDN-HRDN-4" "Process accounting is active (psacct/acct)" \
            "AUDIT AND ACCOUNTABILITY" "Process accounting records commands run by all users." ""
    else
        record_result "WARN" "HRDN-HRDN-4" "Process accounting is not active" \
            "AUDIT AND ACCOUNTABILITY" "User command history is not tracked at OS level." \
            "systemctl --now enable psacct  OR  dnf install psacct && systemctl --now enable psacct"
    fi

    log_ok "Built-in hardening scan complete."
}

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
AIRGAP_PUBLIC_PATTERNS="redhat.com fedoraproject.org centos.org rockylinux.org almalinux.org oracle.com amazonaws.com cloudfront.net github.com githubusercontent.com ntp.org google.com googleapis.com cloudflare.com windows.com microsoft.com apple.com nist.gov quad9.net opendns.com akamaized.net fastly.net"

_is_ip_literal() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$1" == *:*:* ]]; }

_is_private_ip() {
    local ip="$1" o2
    case "$ip" in
        10.*|192.168.*|127.*|169.254.*|0.0.0.0|::1|::|[Ff][Ee]80:*|[Ff][CcDd]*:*) return 0 ;;
        172.*) o2="${ip#172.}"; o2="${o2%%.*}"; [[ "$o2" =~ ^[0-9]+$ ]] && (( o2 >= 16 && o2 <= 31 )) && return 0 ;;
        100.*) o2="${ip#100.}"; o2="${o2%%.*}"; [[ "$o2" =~ ^[0-9]+$ ]] && (( o2 >= 64 && o2 <= 127 )) && return 0 ;;
    esac
    return 1
}

# _host_is_public HOST → 0 if HOST is a public IP literal or a known internet domain
_host_is_public() {
    local h pat
    h=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    h="${h#[}"; h="${h%]}"
    [[ -z "$h" ]] && return 1
    if _is_ip_literal "$h"; then
        _is_private_ip "$h" && return 1
        return 0
    fi
    for pat in $AIRGAP_PUBLIC_PATTERNS; do
        [[ "$h" == "$pat" || "$h" == *".$pat" ]] && return 0
    done
    return 1
}

# _url_host URL → bare host (scheme, creds, port, path stripped)
_url_host() {
    local u="$1"
    u="${u#*://}"; u="${u%%/*}"; u="${u##*@}"
    if [[ "$u" == \[* ]]; then u="${u%%]*}"; u="${u#[}"; else u="${u%%:*}"; fi
    printf '%s' "$u"
}

# _unit_on NAME → 0 if service/timer is enabled or active (systemd or SysV)
_unit_on() {
    local u="$1"
    if command -v systemctl &>/dev/null; then
        systemctl is-active  --quiet "$u" 2>/dev/null && return 0
        [[ "$(systemctl is-enabled "$u" 2>/dev/null)" == "enabled" ]] && return 0
        return 1
    fi
    [[ "$u" == *.timer || "$u" == *.path ]] && return 1
    u="${u%.service}"
    chkconfig --list "$u" 2>/dev/null | grep -q ':on' && return 0
    return 1
}

_mod_loaded() { lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$1"; }

run_airgap_checks() {
    banner "AIR-GAP — Network Egress & Bridging"

    # AIR-NET-1: default route (IPv4 from /proc — works on RHEL 5–10, no `ip` needed)
    local def4=0 def6=0
    [[ -r /proc/net/route ]] && def4=$(awk 'NR>1 && $2=="00000000" && $8=="00000000"' /proc/net/route | wc -l)
    [[ -r /proc/net/ipv6_route ]] && def6=$(awk '$1=="00000000000000000000000000000000" && $2=="00" && $10!="lo"' /proc/net/ipv6_route | wc -l)
    if [[ $def4 -eq 0 && $def6 -eq 0 ]]; then
        record_result "PASS" "AIR-NET-1" "No default route configured" \
            "NETWORK CONFIGURATION" "Host has no default gateway (IPv4/IPv6) — traffic cannot leave the local segments by default." ""
    else
        local gw
        gw=$(awk 'function hx(x,  i,n){n=0; x=toupper(x); for(i=1;i<=length(x);i++) n=n*16+index("0123456789ABCDEF",substr(x,i,1))-1; return n}
                  NR>1 && $2=="00000000" {g=$3; printf "%d.%d.%d.%d (%s) ", hx(substr(g,7,2)), hx(substr(g,5,2)), hx(substr(g,3,2)), hx(substr(g,1,2)), $1}' /proc/net/route 2>/dev/null)
        record_result "WARN" "AIR-NET-1" "Default route present (IPv4: $def4, IPv6: $def6)" \
            "NETWORK CONFIGURATION" "Default gateway(s): ${gw:-see ip route}. In an isolated enclave confirm this gateway cannot forward beyond the enclave boundary." \
            "Verify: ip route show default; remove if not required (nmcli con mod <con> ipv4.never-default yes)"
    fi

    # AIR-NET-2: multi-homed hosts can bridge enclaves
    local ifaces
    ifaces=$(ls /sys/class/net 2>/dev/null | grep -vE '^(lo|virbr[0-9]+-nic|docker[0-9]*|podman[0-9]*|cni.*|veth.*)$' | while read -r i; do
        [[ "$(cat /sys/class/net/$i/operstate 2>/dev/null)" == "up" ]] && printf '%s ' "$i"; done)
    local nif; nif=$(printf '%s' "$ifaces" | wc -w)
    if [[ $nif -le 1 ]]; then
        record_result "PASS" "AIR-NET-2" "Single active network interface (${ifaces% })" \
            "NETWORK CONFIGURATION" "Host is not multi-homed." ""
    else
        record_result "WARN" "AIR-NET-2" "Host is multi-homed: $nif active interfaces (${ifaces% })" \
            "NETWORK CONFIGURATION" "A host on several networks can bridge an enclave to another zone. Confirm each interface is intended and forwarding is off." \
            "sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding  # both must be 0"
    fi

    # AIR-NET-3: IP forwarding (the bridge itself)
    local f4 f6
    f4=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
    f6=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)
    if [[ "$f4" == "0" && "$f6" == "0" ]]; then
        record_result "PASS" "AIR-NET-3" "IPv4 and IPv6 forwarding disabled" \
            "NETWORK CONFIGURATION" "Host will not route packets between networks." ""
    else
        record_result "FAIL" "AIR-NET-3" "Packet forwarding enabled (ipv4=$f4, ipv6=$f6)" \
            "NETWORK CONFIGURATION" "This host can act as a router between the enclave and other networks." \
            "printf 'net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\n' > /etc/sysctl.d/99-airgap.conf && sysctl --system"
    fi

    # AIR-DNS-1: resolvers outside the enclave
    local ns pub_ns="" all_ns=""
    for ns in $(awk '/^[[:space:]]*nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null); do
        all_ns="$all_ns $ns"
        _host_is_public "$ns" && pub_ns="$pub_ns $ns"
    done
    if [[ -n "$pub_ns" ]]; then
        record_result "FAIL" "AIR-DNS-1" "Public DNS resolver(s) configured:${pub_ns}" \
            "NETWORK CONFIGURATION" "Queries to public resolvers leak hostnames and are a classic DNS-tunnel exfiltration path." \
            "Point /etc/resolv.conf (or NetworkManager ipv4.dns) at internal resolvers only"
    elif [[ -z "$all_ns" ]]; then
        record_result "INFO" "AIR-DNS-1" "No DNS resolvers configured" \
            "NETWORK CONFIGURATION" "No nameserver entries in /etc/resolv.conf (common and acceptable in fully isolated hosts)." ""
    else
        record_result "PASS" "AIR-DNS-1" "Only internal DNS resolvers configured:${all_ns}" \
            "NETWORK CONFIGURATION" "All nameservers are private addresses." ""
    fi

    # AIR-NET-4: proxies configured system-wide or for the package manager
    local px
    px=$(grep -hiE '^[[:space:]]*(export[[:space:]]+)?(https?|ftp|all)_proxy[[:space:]]*=|^[[:space:]]*proxy[[:space:]]*=' \
        /etc/environment /etc/profile /etc/profile.d/*.sh /etc/yum.conf /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo 2>/dev/null \
        | sed 's/[[:space:]]\+/ /g; s/\(:\/\/\)[^@/]*@/\1***@/' | sort -u | head -5 | tr '\n' ';')
    if [[ -z "$px" ]]; then
        record_result "PASS" "AIR-NET-4" "No system-wide or package-manager proxy configured" \
            "NETWORK CONFIGURATION" "No *_proxy / proxy= settings found." ""
    else
        record_result "WARN" "AIR-NET-4" "Proxy configuration present" \
            "NETWORK CONFIGURATION" "Proxy settings found (credentials masked): ${px}. Confirm the proxy is an internal, enclave-scoped service." \
            "Review /etc/environment, /etc/profile.d/, /etc/yum.conf, /etc/dnf/dnf.conf"
    fi

    banner "AIR-GAP — Radios & Covert Channels"

    # AIR-RF-1: Wi-Fi hardware/driver
    local wifi_if="" m wifi_mods=""
    for i in /sys/class/net/*; do
        [[ -d "$i/wireless" || -e "$i/phy80211" ]] && wifi_if="$wifi_if ${i##*/}"
    done
    for m in iwlwifi iwlmvm iwldvm ath9k ath10k_pci ath11k_pci ath12k brcmfmac b43 rt2800pci rt2800usb rtw88_pci rtw89_pci mt7921e mt76 cfg80211 mac80211; do
        _mod_loaded "$m" && wifi_mods="$wifi_mods $m"
    done
    if [[ -z "$wifi_if" && -z "$wifi_mods" ]]; then
        record_result "PASS" "AIR-RF-1" "No Wi-Fi interfaces or drivers loaded" \
            "MEDIA PROTECTION" "No 802.11 interfaces and no wireless stack modules loaded." ""
    else
        record_result "FAIL" "AIR-RF-1" "Wi-Fi capability present" \
            "MEDIA PROTECTION" "Interfaces:${wifi_if:- none}; modules:${wifi_mods:- none}. A radio defeats the air gap." \
            "nmcli radio wifi off; blacklist drivers in /etc/modprobe.d/airgap.conf (install <mod> /bin/false); remove hardware where possible"
    fi

    # AIR-RF-2: Bluetooth
    local bt_mods=""
    for m in bluetooth btusb btintel btrtl hci_uart; do _mod_loaded "$m" && bt_mods="$bt_mods $m"; done
    if [[ -z "$bt_mods" ]] && ! ls /sys/class/bluetooth/* &>/dev/null; then
        record_result "PASS" "AIR-RF-2" "No Bluetooth stack loaded" \
            "MEDIA PROTECTION" "No Bluetooth modules or controllers present." ""
    else
        record_result "FAIL" "AIR-RF-2" "Bluetooth stack loaded:${bt_mods:- (controller present)}" \
            "MEDIA PROTECTION" "Bluetooth provides an out-of-band radio channel across the air gap." \
            "systemctl mask --now bluetooth; echo 'install bluetooth /bin/false' >> /etc/modprobe.d/airgap.conf"
    fi

    # AIR-RF-3: cellular / WWAN modems
    local wwan=""
    for m in qmi_wwan cdc_mbim cdc_wdm option sierra sierra_net mhi_wwan_ctrl wwan; do _mod_loaded "$m" && wwan="$wwan $m"; done
    ls /dev/cdc-wdm* /dev/wwan* &>/dev/null && wwan="$wwan (device nodes present)"
    _unit_on ModemManager.service && wwan="$wwan ModemManager"
    if [[ -z "$wwan" ]]; then
        record_result "PASS" "AIR-RF-3" "No cellular/WWAN modem capability" \
            "MEDIA PROTECTION" "No WWAN drivers, device nodes or ModemManager." ""
    else
        record_result "FAIL" "AIR-RF-3" "Cellular/WWAN capability present:$wwan" \
            "MEDIA PROTECTION" "A cellular modem is a direct, unmonitored path to the internet." \
            "systemctl mask --now ModemManager; blacklist WWAN drivers; physically remove the modem"
    fi

    # AIR-RF-4: USB network adapters / phone tethering
    local usbnet=""
    for m in cdc_ether cdc_ncm rndis_host r8152 ax88179_178a asix usbnet ipheth; do _mod_loaded "$m" && usbnet="$usbnet $m"; done
    if [[ -z "$usbnet" ]]; then
        record_result "PASS" "AIR-RF-4" "No USB network / tethering drivers loaded" \
            "MEDIA PROTECTION" "Plugging in a phone or USB NIC has not created a network path." ""
    else
        record_result "WARN" "AIR-RF-4" "USB network/tethering drivers loaded:$usbnet" \
            "MEDIA PROTECTION" "A tethered phone or USB NIC can silently add an internet uplink." \
            "Blacklist: for m in cdc_ether rndis_host ipheth r8152; do echo \"install \$m /bin/false\"; done >> /etc/modprobe.d/airgap.conf; enforce USBGuard"
    fi

    # AIR-DMA-1: Thunderbolt / FireWire DMA
    local dma="" sec
    for d in /sys/bus/thunderbolt/devices/domain*/security; do
        [[ -r "$d" ]] || continue
        sec=$(cat "$d" 2>/dev/null)
        [[ "$sec" == "none" || "$sec" == "dponly" ]] || continue
        dma="$dma thunderbolt(security=$sec)"
    done
    for m in firewire_ohci ohci1394; do _mod_loaded "$m" && dma="$dma $m"; done
    if [[ -z "$dma" ]]; then
        record_result "PASS" "AIR-DMA-1" "No unauthenticated DMA ports (Thunderbolt/FireWire)" \
            "MEDIA PROTECTION" "No FireWire drivers loaded and Thunderbolt (if any) requires authorization." ""
    else
        record_result "WARN" "AIR-DMA-1" "DMA-capable port exposure:$dma" \
            "MEDIA PROTECTION" "Physical DMA attacks can read memory or inject code without any network." \
            "Set Thunderbolt security to 'user'/'secure' in firmware; blacklist firewire_ohci; enable IOMMU (intel_iommu=on / amd_iommu=on)"
    fi

    # AIR-USB-1: desktop automount of removable media
    if _unit_on udisks2.service; then
        record_result "WARN" "AIR-USB-1" "udisks2 is running (removable media automount)" \
            "MEDIA PROTECTION" "Removable media can be mounted by users — the main malware/exfil path into an air-gapped network." \
            "systemctl mask --now udisks2   # and enforce USBGuard allow-list"
    else
        record_result "PASS" "AIR-USB-1" "udisks2 automount not active" \
            "MEDIA PROTECTION" "Removable media is not auto-mounted for users." ""
    fi

    banner "AIR-GAP — Phone-Home & Discovery Services"

    # AIR-SVC-n: services that try to reach the internet or advertise on the LAN
    local entry unit why found=0 k=0
    local svc_list=(
        "rhsmcertd.service|Red Hat subscription cert checks — contacts RHSM/Satellite"
        "insights-client.timer|Red Hat Insights uploads system data"
        "rhcd.service|Remote host configuration daemon (console.redhat.com)"
        "dnf-makecache.timer|Periodic repo metadata refresh — fails noisily or reaches outside"
        "dnf-automatic.timer|Automatic updates — unreviewed change in a controlled enclave"
        "dnf-automatic-install.timer|Automatic updates install without change control"
        "yum-cron.service|Automatic updates (RHEL 7)"
        "packagekit.service|PackageKit background refresh"
        "avahi-daemon.service|mDNS/DNS-SD advertises host and services on the LAN"
        "cups-browsed.service|Printer discovery — network listener (CVE-2024-47176 class)"
        "cloud-init.service|Fetches instance metadata/user-data at boot"
        "geoclue.service|Geolocation service (Wi-Fi/network lookups)"
        "kdump.service|__KDUMP__"
    )
    for entry in "${svc_list[@]}"; do
        unit="${entry%%|*}"; why="${entry#*|}"
        if [[ "$why" == "__KDUMP__" ]]; then
            # kdump is fine locally; only flag when it ships dumps over the network
            _unit_on "$unit" || continue
            grep -qE '^[[:space:]]*(ssh|nfs|net)[[:space:]]' /etc/kdump.conf 2>/dev/null || continue
            why="kdump sends crash dumps (full memory) over the network"
        else
            _unit_on "$unit" || continue
        fi
        found=$(( found + 1 )); k=$(( k + 1 ))
        record_result "WARN" "AIR-SVC-${unit%%.*}" "$unit is enabled/active" \
            "CONFIGURATION MANAGEMENT" "$why." \
            "systemctl disable --now $unit   # or mask, if not required in the enclave"
    done
    if [[ $found -eq 0 ]]; then
        record_result "PASS" "AIR-SVC-0" "No phone-home or LAN discovery services active" \
            "CONFIGURATION MANAGEMENT" "None of the known call-home/discovery services are enabled." ""
    fi

    # AIR-RHSM-1: subscription-manager pointed at the public CDN
    if [[ -r /etc/rhsm/rhsm.conf ]]; then
        local rhsm_host; rhsm_host=$(awk -F'=' '/^\[server\]/{s=1;next} /^\[/{s=0} s && $1~/^[[:space:]]*hostname[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/rhsm/rhsm.conf)
        if [[ -n "$rhsm_host" ]] && _host_is_public "$rhsm_host"; then
            record_result "WARN" "AIR-RHSM-1" "subscription-manager targets public host: $rhsm_host" \
                "CONFIGURATION MANAGEMENT" "Disconnected hosts should register to an internal Satellite or use offline manifests." \
                "subscription-manager config --server.hostname=<internal-satellite>  OR  disable rhsmcertd"
        else
            record_result "PASS" "AIR-RHSM-1" "subscription-manager server is internal (${rhsm_host:-unset})" \
                "CONFIGURATION MANAGEMENT" "RHSM is not configured to reach the public Red Hat CDN." ""
        fi
    fi

    banner "AIR-GAP — Update Sources & Patch Currency"

    # AIR-REPO-1: enabled repositories that point at the internet
    local repo_report
    repo_report=$(awk '
        FNR==1 { sec="" }
        /^[[:space:]]*\[/ { flush(); sec=$0; gsub(/[][[:space:]]/,"",sec); en=1; urls=""; next }
        /^[[:space:]]*enabled[[:space:]]*=/ { v=$0; sub(/.*=[[:space:]]*/,"",v); en=(v=="1"||v=="true"||v=="yes") }
        /^[[:space:]]*(baseurl|mirrorlist|metalink)[[:space:]]*=/ { k=$0; sub(/[[:space:]]*=.*/,"",k); gsub(/[[:space:]]/,"",k)
            v=$0; sub(/^[^=]*=[[:space:]]*/,"",v); urls=urls " " k "=" v }
        function flush() { if (sec!="" && en && urls!="") print sec "\t" urls; sec="" }
        END { flush() }' /etc/yum.repos.d/*.repo 2>/dev/null)
    local pub_repos="" line rname rurls u h
    while IFS=$'\t' read -r rname rurls; do
        [[ -z "$rname" ]] && continue
        for u in $rurls; do
            local key="${u%%=*}" val="${u#*=}"
            h=$(_url_host "$val")
            if [[ "$key" == "mirrorlist" || "$key" == "metalink" ]] || _host_is_public "$h"; then
                pub_repos="$pub_repos $rname(${h:-$key})"; break
            fi
        done
    done <<< "$repo_report"
    if [[ -z "$repo_report" ]]; then
        record_result "INFO" "AIR-REPO-1" "No enabled yum/dnf repositories" \
            "SYSTEM INTEGRITY" "No enabled repos with a baseurl/mirrorlist in /etc/yum.repos.d/." ""
    elif [[ -z "$pub_repos" ]]; then
        record_result "PASS" "AIR-REPO-1" "All enabled repositories are internal or local media" \
            "SYSTEM INTEGRITY" "No enabled repo references a public mirror, mirrorlist or metalink." ""
    else
        record_result "WARN" "AIR-REPO-1" "Enabled repositories point outside the enclave" \
            "SYSTEM INTEGRITY" "Repos:${pub_repos}. These cannot be reached and cause timeouts; some tools may try to fall back to other sources." \
            "dnf config-manager --set-disabled <repo>  and use an internal mirror (baseurl=https://mirror.internal/...) or file:///mnt/media"
    fi

    # AIR-PATCH-1: patch age — the real risk of a disconnected host
    local newest now age_days
    newest=$(rpm -qa --qf '%{INSTALLTIME}\n' 2>/dev/null | sort -n | tail -1)
    now=$(date +%s)
    if [[ "$newest" =~ ^[0-9]+$ ]]; then
        age_days=$(( (now - newest) / 86400 ))
        local last_pkg; last_pkg=$(rpm -qa --last 2>/dev/null | head -1 | awk '{print $1}')
        if [[ $age_days -le $MAX_PATCH_AGE ]]; then
            record_result "PASS" "AIR-PATCH-1" "Last package change ${age_days} day(s) ago" \
                "SYSTEM INTEGRITY" "Most recent install/update: ${last_pkg}. Threshold: ${MAX_PATCH_AGE} days." ""
        elif [[ $age_days -le $(( MAX_PATCH_AGE * 2 )) ]]; then
            record_result "WARN" "AIR-PATCH-1" "No package updates for ${age_days} days (threshold ${MAX_PATCH_AGE})" \
                "SYSTEM INTEGRITY" "Most recent change: ${last_pkg}. Air-gapped hosts silently fall behind on security errata." \
                "Import the latest errata via your internal mirror/transfer media, then patch"
        else
            record_result "FAIL" "AIR-PATCH-1" "No package updates for ${age_days} days (>2x ${MAX_PATCH_AGE}-day threshold)" \
                "SYSTEM INTEGRITY" "Most recent change: ${last_pkg}. The host is likely missing multiple critical errata." \
                "Schedule an offline patch cycle: sync mirror -> transfer -> dnf update"
        fi
    else
        record_result "SKIP" "AIR-PATCH-1" "Could not read package install times" "SYSTEM INTEGRITY" "rpm query failed." ""
    fi

    # AIR-PATCH-2: running kernel older than newest installed kernel
    local run_k newest_k
    run_k=$(uname -r)
    newest_k=$(rpm -q --last kernel kernel-core kernel-uek 2>/dev/null | grep -v 'not installed' | head -1 | awk '{print $1}' | sed -r 's/^kernel(-core|-uek)?-//')
    if [[ -z "$newest_k" ]]; then
        record_result "SKIP" "AIR-PATCH-2" "Could not determine installed kernels" "SYSTEM INTEGRITY" "No kernel package found in rpm DB." ""
    elif [[ "$run_k" == "$newest_k" ]]; then
        record_result "PASS" "AIR-PATCH-2" "Running the newest installed kernel ($run_k)" \
            "SYSTEM INTEGRITY" "No reboot is pending to activate kernel fixes." ""
    else
        record_result "WARN" "AIR-PATCH-2" "Reboot pending: running $run_k, newest installed $newest_k" \
            "SYSTEM INTEGRITY" "Kernel security fixes that were imported are not active until reboot." \
            "Schedule a reboot in the next maintenance window"
    fi

    banner "AIR-GAP — Time, Logging & Tunnels"

    # AIR-TIME-1: time sources that cannot be reached from an enclave
    local tconf srcs="" pub_t=""
    for tconf in /etc/chrony.conf /etc/chrony.d/*.conf /etc/ntp.conf; do
        [[ -r "$tconf" ]] || continue
        srcs="$srcs $(awk '/^[[:space:]]*(server|pool|peer)[[:space:]]/ {print $2}' "$tconf")"
    done
    for h in $srcs; do _host_is_public "$h" && pub_t="$pub_t $h"; done
    if [[ -z "${srcs// /}" ]]; then
        record_result "WARN" "AIR-TIME-1" "No NTP time sources configured" \
            "AUDIT AND ACCOUNTABILITY" "Without a shared internal time source, log correlation and Kerberos break across the enclave." \
            "Configure an internal stratum source (GPS/PTP appliance or an enclave NTP server) in /etc/chrony.conf"
    elif [[ -n "$pub_t" ]]; then
        record_result "WARN" "AIR-TIME-1" "Public/unreachable NTP sources configured:$pub_t" \
            "AUDIT AND ACCOUNTABILITY" "Public time pools are unreachable in an enclave; the clock will drift." \
            "Replace with internal time sources in /etc/chrony.conf"
    else
        record_result "PASS" "AIR-TIME-1" "Time sources are internal:$srcs" \
            "AUDIT AND ACCOUNTABILITY" "No public NTP pools referenced." ""
    fi

    # AIR-LOG-1: remote log forwarding to public destinations
    local tgt pub_log="" any_log=""
    for tgt in $(grep -hvE '^[[:space:]]*#' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null \
                 | grep -oE '(^|[[:space:]])@@?(\([^)]*\))?[^[:space:]:;]+|target="[^"]+"' \
                 | sed -r 's/^[[:space:]]*//; s/^@@?(\([^)]*\))?//; s/^target="//; s/"$//'); do
        [[ -z "$tgt" ]] && continue
        any_log="$any_log $tgt"
        _host_is_public "$tgt" && pub_log="$pub_log $tgt"
    done
    if [[ -n "$pub_log" ]]; then
        record_result "FAIL" "AIR-LOG-1" "Logs forwarded to public destination(s):$pub_log" \
            "AUDIT AND ACCOUNTABILITY" "Log forwarding outside the enclave is both an exfiltration channel and unreachable." \
            "Forward to an internal collector only (rsyslog action target=)"
    else
        record_result "INFO" "AIR-LOG-1" "Remote log destinations:${any_log:- none}" \
            "AUDIT AND ACCOUNTABILITY" "No public log destinations. Local-only logging needs a documented offline collection process." ""
    fi

    # AIR-SSH-1: SSH tunnelling features that can bridge enclaves
    if command -v sshd &>/dev/null || [[ -r /etc/ssh/sshd_config ]]; then
        local sshcfg on_feats="" fk fv
        sshcfg=$(sshd -T 2>/dev/null)
        if [[ -z "$sshcfg" ]]; then
            # fallback: parse config files (first match wins, like sshd) with OpenSSH defaults
            sshcfg=$(cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | awk '
                /^[[:space:]]*[Mm]atch/ {exit} /^[[:space:]]*#/ {next} NF>=2 {k=tolower($1); if(!(k in s)) s[k]=tolower($2)}
                END { d["allowtcpforwarding"]="yes"; d["permittunnel"]="no"; d["gatewayports"]="no";
                      d["x11forwarding"]="no"; d["allowagentforwarding"]="yes"; d["allowstreamlocalforwarding"]="yes"
                      for (k in d) print k, (k in s ? s[k] : d[k]) }')
        fi
        for fk in allowtcpforwarding permittunnel gatewayports x11forwarding allowagentforwarding allowstreamlocalforwarding; do
            fv=$(printf '%s\n' "$sshcfg" | awk -v k="$fk" 'tolower($1)==k {print tolower($2); exit}')
            [[ -n "$fv" && "$fv" != "no" ]] && on_feats="$on_feats $fk=$fv"
        done
        if [[ -z "$on_feats" ]]; then
            record_result "PASS" "AIR-SSH-1" "SSH forwarding/tunnelling disabled" \
                "ACCESS CONTROL" "TCP/agent/stream/X11 forwarding, tunnels and gateway ports are off." ""
        else
            record_result "WARN" "AIR-SSH-1" "SSH forwarding/tunnelling enabled:$on_feats" \
                "ACCESS CONTROL" "SSH port forwarding and tunnels let a single allowed SSH session pivot traffic across enclave boundaries." \
                "In sshd_config: AllowTcpForwarding no, AllowAgentForwarding no, AllowStreamLocalForwarding no, PermitTunnel no, GatewayPorts no, X11Forwarding no"
        fi
    fi

    log_ok "Air-gap isolation checks complete."
}

# ─────────────────────────────────────────────────────────────────────────────
# SCORING — PASS / (PASS + FAIL + WARN)
# INFO, SKIP and WAIVED are excluded. Previously SKIP/INFO counted against the
# score, so a non-root scan looked far worse than the host really was.
# ─────────────────────────────────────────────────────────────────────────────
compliance_pct() {
    local denom=$(( PASS + FAIL + WARN ))
    awk -v p="$PASS" -v d="$denom" 'BEGIN{ if (d>0) printf "%.1f", (p/d)*100; else print "0.0" }'
}

# ─────────────────────────────────────────────────────────────────────────────
# DRIFT vs BASELINE — pure awk over RHELGuard's own one-result-per-line JSON
# ─────────────────────────────────────────────────────────────────────────────
compute_drift() {
    [[ -z "$BASELINE_FILE" ]] && return 0
    awk '
        function field(line,k,   m){ if (match(line, "\"" k "\":\"[^\"]*\"")) { m=substr(line,RSTART,RLENGTH); sub("^\"" k "\":\"","",m); sub("\"$","",m); return m } return "" }
        FNR==NR { if ($0 ~ /"change":/) next; id=field($0,"id"); if (id!="") old[id]=field($0,"status"); next }
        { id=field($0,"id"); if (id=="") next; st=field($0,"status"); t=field($0,"title")
          if (!(id in old)) { if (st=="FAIL"||st=="WARN") print "NEW\t" id "\t-\t" st "\t" t; next }
          o=old[id]
          if (o!=st) {
            if ((st=="FAIL"||st=="WARN") && o!="FAIL" && o!="WARN") k="REGRESSED"
            else if (st=="PASS" && (o=="FAIL"||o=="WARN")) k="FIXED"
            else k="CHANGED"
            print k "\t" id "\t" o "\t" st "\t" t
          } }' "$BASELINE_FILE" "$RESULTS_FILE" > "$DRIFT_FILE"
    DRIFT_NEW_FAIL=$(grep -cE '^(NEW|REGRESSED)' "$DRIFT_FILE" || true)
    DRIFT_FIXED=$(grep -c '^FIXED' "$DRIFT_FILE" || true)
    DRIFT_CHANGED=$(grep -c . "$DRIFT_FILE" || true)
}

_jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037'; }
_h()    { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────
generate_json_report() {
    local jfile="$OUTPUT_DIR/${TOOL_NAME}_${HOSTNAME_VAL}_${REPORT_TS}.json"
    local elapsed=$(( $(date +%s) - START_TS ))
    local cpct; cpct=$(compliance_pct)

    {
        printf '{\n'
        printf '  "tool": "%s",\n'           "$TOOL_NAME"
        printf '  "version": "%s",\n'        "$TOOL_VERSION"
        printf '  "script_sha256": "%s",\n'  "$(_jstr "$SCRIPT_SHA256")"
        printf '  "hostname": "%s",\n'       "$(_jstr "$HOSTNAME_VAL")"
        printf '  "scan_date": "%s",\n'      "$(date -Iseconds 2>/dev/null || date)"
        printf '  "os": "%s",\n'             "$(_jstr "$RHEL_FULL")"
        printf '  "rhel_major": %d,\n'       "$RHEL_MAJOR"
        printf '  "os_family": "%s",\n'      "$OS_FAMILY"
        printf '  "kernel": "%s",\n'         "$(_jstr "$(uname -r)")"
        printf '  "scan_mode": "%s",\n'      "$(_jstr "$SCAN_MODE")"
        printf '  "run_as_root": %s,\n'      "$IS_ROOT"
        printf '  "duration_seconds": %d,\n' "$elapsed"
        printf '  "baseline": "%s",\n'       "$(_jstr "${BASELINE_FILE##*/}")"
        printf '  "waiver_file": "%s",\n'    "$(_jstr "${WAIVER_FILE##*/}")"
        printf '  "summary": {\n'
        printf '    "total": %d,\n'          "$TOTAL"
        printf '    "pass": %d,\n'           "$PASS"
        printf '    "fail": %d,\n'           "$FAIL"
        printf '    "warn": %d,\n'           "$WARN"
        printf '    "info": %d,\n'           "$INFO"
        printf '    "skip": %d,\n'           "$SKIP"
        printf '    "waived": %d,\n'         "$WAIVED"
        printf '    "priv_skip": %d,\n'      "$PRIV_SKIP"
        printf '    "compliance_pct": %s,\n' "$cpct"
        printf '    "compliance_formula": "pass/(pass+fail+warn)",\n'
        printf '    "drift_new_or_regressed": %d,\n' "$DRIFT_NEW_FAIL"
        printf '    "drift_fixed": %d\n'     "$DRIFT_FIXED"
        printf '  },\n'
        printf '  "drift": [\n'
        awk -F'\t' '{ for(i=1;i<=5;i++){ gsub(/\\/,"\\\\",$i); gsub(/"/,"\\\"",$i) }
                      printf "%s{\"change\":\"%s\",\"id\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"title\":\"%s\"}\n", (NR>1?"   ,":"    "), $1,$2,$3,$4,$5 }' "$DRIFT_FILE"
        printf '  ],\n'
        printf '  "results": [\n'
        # one result per line is intentional: grep/awk/baseline friendly
        awk '{ printf "%s%s\n", (NR>1 ? "   ," : "    "), $0 }' "$RESULTS_FILE"
        printf '  ]\n}\n'
    } > "$jfile"
    echo "$jfile"
}

generate_csv_report() {
    local cfile="$OUTPUT_DIR/${TOOL_NAME}_${HOSTNAME_VAL}_${REPORT_TS}.csv"
    { echo '"id","status","category","title","description","remediation"'; cat "$CSV_ROWS_FILE"; } > "$cfile"
    echo "$cfile"
}

generate_html_report() {
    local hfile="$OUTPUT_DIR/${TOOL_NAME}_${HOSTNAME_VAL}_${REPORT_TS}.html"
    local cpct; cpct=$(compliance_pct)
    local elapsed=$(( $(date +%s) - START_TS ))
    local h_host h_os h_kernel h_mode h_sha
    h_host=$(_h "$HOSTNAME_VAL"); h_os=$(_h "$RHEL_FULL"); h_kernel=$(_h "$(uname -r)")
    h_mode=$(_h "$SCAN_MODE");    h_sha=$(_h "$SCRIPT_SHA256")

    local score_color="#e74c3c"
    local _cpct_int="${cpct%%.*}"
    [[ "$_cpct_int" -ge 80 ]] && score_color="#27ae60"
    [[ "$_cpct_int" -ge 60 && "$_cpct_int" -lt 80 ]] && score_color="#f39c12"

    {
    cat << 'CSSEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Air-gap safe: the report can never load or send anything over the network -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
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
CSSEOF
    cat << HTMLEOF
<title>RHELGuard — ${h_host} — ${REPORT_TS}</title>
</head>
<body>

<div class="header">
  <div class="logo">RHELGuard</div>
  <div class="header-meta">
    <div>🖥️ <strong>${h_host}</strong> &nbsp;|&nbsp; 📅 <strong>$(date '+%Y-%m-%d %H:%M:%S %Z')</strong></div>
    <div>🐧 <strong>${h_os}</strong> &nbsp;|&nbsp; 🔧 Kernel <strong>${h_kernel}</strong></div>
    <div>⚙️ Mode: <strong>${h_mode}</strong> &nbsp;|&nbsp; 🔑 Root: <strong>${IS_ROOT}</strong> &nbsp;|&nbsp; ⏱ ${elapsed}s &nbsp;|&nbsp; v${TOOL_VERSION}</div>
    <div class="sha">script sha256: ${h_sha}</div>
  </div>
</div>
HTMLEOF

    if [[ "$IS_ROOT" == false ]]; then
        echo "<div class=\"priv-warn\">⚠️ &nbsp;<strong>Non-root scan</strong> — ${PRIV_SKIP} privileged checks were skipped. Re-run with <code>sudo ./rhelguard.sh</code> for full coverage.</div>"
    fi

    cat << HTMLEOF
<div class="score-row">
  <div class="score-card">
    <div class="score-circle" style="border-color:${score_color};color:${score_color}">${cpct}%</div>
    <div class="score-detail">
      <h2>Compliance Score</h2>
      <p>${PASS} passed · ${FAIL} failed · ${WARN} warnings · ${WAIVED} waived · ${SKIP} skipped</p>
      <p style="margin-top:8px;color:#8b949e">Score = pass ÷ (pass + fail + warn) · ${TOTAL} checks total</p>
    </div>
  </div>
</div>

<div class="prog-bar"><div class="prog-fill" style="width:${cpct}%"></div></div>

<div class="cards">
  <div class="card"><div class="num" style="color:var(--pass)">${PASS}</div><div class="lbl">Pass</div></div>
  <div class="card"><div class="num" style="color:var(--fail)">${FAIL}</div><div class="lbl">Fail</div></div>
  <div class="card"><div class="num" style="color:var(--warn)">${WARN}</div><div class="lbl">Warn</div></div>
  <div class="card"><div class="num" style="color:#8e44ad">${WAIVED}</div><div class="lbl">Waived</div></div>
  <div class="card"><div class="num" style="color:var(--info)">${INFO}</div><div class="lbl">Info</div></div>
  <div class="card"><div class="num" style="color:var(--skip)">${SKIP}</div><div class="lbl">Skip</div></div>
  <div class="card"><div class="num">${TOTAL}</div><div class="lbl">Total</div></div>
</div>
HTMLEOF

    if [[ -n "$BASELINE_FILE" ]]; then
        echo "<div class=\"drift\"><h3>📈 Drift since baseline <code>$(_h "${BASELINE_FILE##*/}")</code> — ${DRIFT_NEW_FAIL} new/regressed · ${DRIFT_FIXED} fixed · ${DRIFT_CHANGED} changed</h3>"
        if [[ -s "$DRIFT_FILE" ]]; then
            echo "<table><thead><tr><th>Change</th><th>Check ID</th><th>From</th><th>To</th><th>Title</th></tr></thead><tbody>"
            awk -F'\t' 'function h(x){gsub(/&/,"\\&amp;",x);gsub(/</,"\\&lt;",x);gsub(/>/,"\\&gt;",x);return x}
                { printf "<tr><td class=\"d-%s\">%s</td><td class=\"id-cell\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", h($1),h($1),h($2),h($3),h($4),h($5) }' "$DRIFT_FILE"
            echo "</tbody></table>"
        else
            echo "<p>No changes.</p>"
        fi
        echo "</div>"
    fi

    cat << HTMLEOF
<div class="controls">
  <input class="search" type="text" id="srch" placeholder="🔍 Search checks..." onkeyup="ft()">
  <button class="filter-btn fb-all active" onclick="sf('all')">All (${TOTAL})</button>
  <button class="filter-btn fb-FAIL" onclick="sf('FAIL')">Fail (${FAIL})</button>
  <button class="filter-btn fb-WARN" onclick="sf('WARN')">Warn (${WARN})</button>
  <button class="filter-btn fb-PASS" onclick="sf('PASS')">Pass (${PASS})</button>
  <button class="filter-btn fb-WAIVED" onclick="sf('WAIVED')">Waived (${WAIVED})</button>
  <button class="filter-btn fb-INFO" onclick="sf('INFO')">Info (${INFO})</button>
  <button class="filter-btn fb-SKIP" onclick="sf('SKIP')">Skip (${SKIP})</button>
</div>

<table id="t">
  <thead><tr>
    <th style="width:70px">Status</th>
    <th style="width:150px">Check ID</th>
    <th style="width:160px">Category</th>
    <th>Finding &amp; Remediation</th>
  </tr></thead>
  <tbody id="tb">
HTMLEOF
    cat "$HTML_ROWS_FILE"
    cat << HTMLEOF
  </tbody>
</table>

<footer>
  ${TOOL_NAME} v${TOOL_VERSION} &nbsp;·&nbsp;
  CIS RHEL 5–10 + DISA STIG (RHEL 6–9) + Built-in Hardening + Air-gap Isolation &nbsp;·&nbsp;
  Generated $(date) &nbsp;·&nbsp;
  For authorised security testing only
</footer>

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
HTMLEOF
    } > "$hfile"
    echo "$hfile"
}

# ─────────────────────────────────────────────────────────────────────────────
# TRANSFER BUNDLE — for carrying results across the air gap (sneakernet)
# Produces <name>.tar.gz with the reports + MANIFEST.txt + SHA256SUMS, and
# prints the bundle's own SHA-256 to record in the media transfer log.
# ─────────────────────────────────────────────────────────────────────────────
generate_bundle() {
    local base="${TOOL_NAME}_${HOSTNAME_VAL}_${REPORT_TS}"
    local stage="$OUTPUT_DIR/.${base}_bundle"
    mkdir -p "$stage/$base" || return 1
    cp "$@" "$stage/$base/" 2>/dev/null
    {
        echo "tool=$TOOL_NAME"
        echo "version=$TOOL_VERSION"
        echo "script_sha256=$SCRIPT_SHA256"
        echo "hostname=$HOSTNAME_VAL"
        echo "os=$RHEL_FULL"
        echo "kernel=$(uname -r)"
        echo "run_as_root=$IS_ROOT"
        echo "operator=$(id -un 2>/dev/null)${SUDO_USER:+ (sudo from $SUDO_USER)}"
        echo "created=$(date -Iseconds 2>/dev/null || date)"
        echo "summary=pass:$PASS fail:$FAIL warn:$WARN waived:$WAIVED info:$INFO skip:$SKIP"
    } > "$stage/$base/MANIFEST.txt"
    if command -v sha256sum &>/dev/null; then
        ( cd "$stage/$base" && sha256sum -- * > SHA256SUMS )
    fi
    ( cd "$stage" && tar czf "../${base}.tar.gz" "$base" ) || { rm -rf "$stage"; return 1; }
    rm -rf "$stage"
    echo "$OUTPUT_DIR/${base}.tar.gz"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    preflight

    if [[ "$QUIET" == false ]]; then
        echo -e "\n${BOLD}${CYAN}"
        echo "  ██████╗ ██╗  ██╗███████╗██╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
        echo "  ██╔══██╗██║  ██║██╔════╝██║     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
        echo "  ██████╔╝███████║█████╗  ██║     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
        echo "  ██╔══██╗██╔══██║██╔══╝  ██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
        echo "  ██║  ██║██║  ██║███████╗███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
        echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝"
        echo -e "${RESET}"
        echo -e "  ${BOLD}v${TOOL_VERSION}${RESET} · RHEL 5–10 · CIS + DISA STIG + Hardening + Air-gap · ${CYAN}${HOSTNAME_VAL}${RESET} (RHEL ${RHEL_MAJOR})\n"
    fi

    case "$SCAN_MODE" in
        cis)     run_cis_checks ;;
        stig)    run_stig_checks ;;
        posture) run_posture_checks; run_hardening_scan ;;
        airgap)  run_airgap_checks ;;
        all)
            run_cis_checks
            run_stig_checks
            run_posture_checks
            run_hardening_scan
            run_airgap_checks
            ;;
        *) echo "Unknown mode: $SCAN_MODE. Use: cis|stig|posture|airgap|all"; exit 1 ;;
    esac

    compute_drift

    # ── Summary (always printed, even with -q) ───────────────────────────────
    local cpct; cpct=$(compliance_pct)
    local elapsed=$(( $(date +%s) - START_TS ))

    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  SCAN COMPLETE  ${elapsed}s  |  RHEL ${RHEL_MAJOR}  |  ${HOSTNAME_VAL}${RESET}"
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    printf "  ${GREEN}%-10s${RESET}%d\n"   "PASS"   "$PASS"
    printf "  ${RED}%-10s${RESET}%d\n"     "FAIL"   "$FAIL"
    printf "  ${YELLOW}%-10s${RESET}%d\n"  "WARN"   "$WARN"
    printf "  ${MAGENTA}%-10s${RESET}%d\n" "WAIVED" "$WAIVED"
    printf "  ${CYAN}%-10s${RESET}%d\n"    "INFO"   "$INFO"
    printf "  %-10s%d\n"                   "SKIP"   "$SKIP"
    [[ "$IS_ROOT" == false ]] && printf "  ${YELLOW}%-10s${RESET}%d  (re-run as root for full coverage)\n" "PRIV-SKIP" "$PRIV_SKIP"
    printf "  %-10s%d\n"                   "TOTAL"  "$TOTAL"
    echo -e "  ${BOLD}Compliance Score : ${cpct}%${RESET}  (pass / (pass+fail+warn))"
    if [[ -n "$BASELINE_FILE" ]]; then
        echo -e "  ${BOLD}Drift            : ${RED}${DRIFT_NEW_FAIL} new/regressed${RESET}${BOLD} · ${GREEN}${DRIFT_FIXED} fixed${RESET}"
        grep -E '^(NEW|REGRESSED)' "$DRIFT_FILE" | head -15 | awk -F'\t' '{printf "      %-10s %-28s %s -> %s\n", $1, $2, $3, $4}'
    fi
    echo ""

    local jout hout cout bout
    log "Generating reports..."
    jout=$(generate_json_report)
    hout=$(generate_html_report)
    cout=$(generate_csv_report)

    echo -e "  📄 JSON   → ${CYAN}$jout${RESET}"
    echo -e "  🌐 HTML   → ${CYAN}$hout${RESET}"
    echo -e "  📊 CSV    → ${CYAN}$cout${RESET}"

    if [[ "$BUNDLE" == true ]]; then
        if command -v tar &>/dev/null && bout=$(generate_bundle "$jout" "$hout" "$cout"); then
            echo -e "  📦 BUNDLE → ${CYAN}$bout${RESET}"
            command -v sha256sum &>/dev/null && \
                echo -e "     sha256: $(sha256sum "$bout" | awk '{print $1}')   <- record this in your media transfer log"
        else
            echo -e "  ${YELLOW}Bundle could not be created (tar missing or write error).${RESET}"
        fi
    fi
    echo ""
    [[ "$QUIET" == false ]] && echo -e "  ${GREEN}${BOLD}Done. Open the HTML report for full details.${RESET}\n"

    if [[ "$STRICT" == true && $FAIL -gt 0 ]]; then exit 2; fi
    exit 0
}

main "$@"
