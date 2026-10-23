#!/usr/bin/env bash
# php2shell-check — read-only exposure check for the "php2shell" PHP
# vulnerabilities CVE-2026-109618 and CVE-2026-109619 (GHSA-w8hw-w9fx-j79w).
#
# https://github.com/EXT-IT/php2shell-check
# Copyright (c) 2026 EXT IT GmbH. MIT License, see LICENSE.
# Provided as is, without warranty and without support.
#
# The script never changes anything and sends no exploit traffic. Local
# checks read package databases, PHP's own configuration and /proc; remote
# checks send one ordinary GET request per URL (following redirects only on
# the same host) and resolve its DNS name.
#
# Compatible with bash 3.2 (macOS) for --remote-only; local checks need Linux.

set -u
export LC_ALL=C

P2S_SCRIPT_VERSION='3.0.0'
P2S_DATA_DATE='2026-10-22'
P2S_ADVISORY='GHSA-w8hw-w9fx-j79w'
P2S_ADVISORY_URL='https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'
P2S_REPO_URL='https://github.com/EXT-IT/php2shell-check'
P2S_INFO_URL='https://ext-it.tech/php2shell/'

# ---------------------------------------------------------------------------
# Vulnerability data. Update these tables when new fixes are published.
# ---------------------------------------------------------------------------

# First fixed upstream release per branch (php.net, 2026-10-21).
# Backports for 7.4, 8.0 and 8.1 are announced but not released.
_p2s_upstream_fixed() {
    case "$1" in
        8.5) echo 8.5.12 ;;
        8.4) echo 8.4.27 ;;
        8.3) echo 8.3.36 ;;
        8.2) echo 8.2.35 ;;
        5.*|7.*|8.0|8.1) echo none ;;
        *)   echo unknown ;;
    esac
}

# Distributions backport fixes and keep the old upstream number (Ubuntu 24.04
# still reports 8.3.6). For those, the package version decides.
# Key: <VERSION_CODENAME>:<source package>. Value: first fixed package
# version, or "unfixed" when the distribution has confirmed it is affected.
_p2s_distro_fixed() {
    case "$1" in
        jammy:php8.1)    echo '8.1.2-1ubuntu2.28' ;;        # Ubuntu 22.04
        noble:php8.3)    echo '8.3.6-0ubuntu0.24.04.13' ;;  # Ubuntu 24.04
        resolute:php8.5) echo '8.5.4-0ubuntu1.5' ;;         # Ubuntu 26.04
        stonking:php8.5) echo '8.5.9-0ubuntu2.1' ;;         # Ubuntu 26.10
        trixie:php8.4)   echo '8.4.27-1~deb13u1' ;;         # Debian 13, DSA-6574-1
        bookworm:php8.2) echo '8.2.35-1~deb12u1' ;;         # Debian 12, DLA-4848-1
        # Ubuntu releases past standard support. These fixes ship through ESM,
        # so they exist only on a host with Ubuntu Pro attached. Without it the
        # package stays below the version named here and the verdict is vuln,
        # which is the truthful answer for that host.
        focal:php7.4)    echo '7.4.3-4ubuntu2.29+esm5' ;;          # 20.04 ESM
        bionic:php7.2)   echo '7.2.24-0ubuntu0.18.04.17+esm14' ;;  # 18.04 ESM
        xenial:php7.0)   echo '7.0.33-0ubuntu0.16.04.16+esm22' ;;  # 16.04 ESM
        trusty:php5)     echo '5.5.9+dfsg-1ubuntu4.29+esm18' ;;    # 14.04 ESM
        *)               echo none ;;
    esac
}

# Upstream numbers that distributions freeze. A remote banner showing one of
# these may belong to a patched backport build, so it cannot be judged.
_p2s_frozen_versions=' 5.5.9 7.0.33 7.2.24 7.4.3 7.4.33 8.1.2 8.3.6 8.5.4 8.5.9 '

# Cloudflare edge ranges, https://www.cloudflare.com/ips/ (2026-10-21).
_p2s_cf_v4='173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
104.24.0.0/14 172.64.0.0/13 131.0.72.0/22'
_p2s_cf_v6='2400:cb00: 2606:4700: 2803:f800: 2405:b500: 2405:8100: 2a06:98c 2c0f:f248:'

# ---------------------------------------------------------------------------
# Argument parsing comes first: --help and --version touch nothing else.
# ---------------------------------------------------------------------------

_p2s_usage() {
    cat <<'EOF'
Usage: php2shell-check.sh [options] [URL ...]

Checks a server and/or websites for exposure to the php2shell vulnerabilities
CVE-2026-109618 and CVE-2026-109619 (GHSA-w8hw-w9fx-j79w). Read-only.

Run it ON THE SERVER (as root) for a definite answer: there it reads the real
versions of every PHP installation and container. Add URLs to also check what
the sites reveal from outside and whether a WAF sits in front. A check from
outside alone can never confirm that a server is patched.

Options:
  -r, --remote-only    only check the given URLs (works without root, on macOS)
                       at most 10 URLs; redirects are followed only within the
                       host you named (and its www. variant)
      --origin IP      also test whether the sites answer directly on IP,
                       bypassing Cloudflare or another proxy
      --no-containers  skip Docker/Podman containers
      --no-logs        skip the memory-limit error count in logs
      --json           machine-readable output on stdout
      --no-color       plain output (also honours NO_COLOR)
  -q, --quiet          print the summary only
  -h, --help           show this help
  -V, --version        show version and data date

Exit codes: 0 nothing vulnerable found, 1 vulnerable, 2 could not decide,
            3 usage error.

Use it only on systems you own or are authorised to check. Provided as is,
without warranty and without support; a clean result is no guarantee.

Examples:
  sudo ./php2shell-check.sh
  sudo ./php2shell-check.sh https://www.example.com
  ./php2shell-check.sh --remote-only https://www.example.com https://shop.example.com
EOF
}

_opt_remote_only=0
_opt_origin=''
_opt_containers=1
_opt_logs=1
_opt_json=0
_opt_color=1
_opt_quiet=0
_p2s_urls=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)       _p2s_usage; exit 0 ;;
        -V|--version)    echo "php2shell-check $P2S_SCRIPT_VERSION (vulnerability data as of $P2S_DATA_DATE)"; exit 0 ;;
        -r|--remote-only) _opt_remote_only=1 ;;
        --origin)        shift; _opt_origin=${1:-}
                         [ -n "$_opt_origin" ] || { echo "php2shell-check: --origin needs an IP address" >&2; exit 3; } ;;
        --origin=*)      _opt_origin=${1#--origin=} ;;
        --no-containers) _opt_containers=0 ;;
        --no-logs)       _opt_logs=0 ;;
        --json)          _opt_json=1 ;;
        --no-color)      _opt_color=0 ;;
        -q|--quiet)      _opt_quiet=1 ;;
        --)              shift; while [ "$#" -gt 0 ]; do _p2s_urls+=("$1"); shift; done; break ;;
        -*)              echo "php2shell-check: unknown option '$1' (see --help)" >&2; exit 3 ;;
        *)               _p2s_urls+=("$1") ;;
    esac
    shift
done

# This is a tool for checking your own sites, not a scanner: a handful of
# URLs per run, no address ranges.
if [ "${#_p2s_urls[@]}" -gt 10 ]; then
    echo "php2shell-check: at most 10 URLs per run (this checks your own sites, it is not a scanner)" >&2
    exit 3
fi
for _u in ${_p2s_urls[@]+"${_p2s_urls[@]}"}; do
    if [[ "$_u" =~ ^[0-9a-fA-F.:]+/[0-9]+$ ]]; then
        echo "php2shell-check: '$_u' looks like an address range; give the URLs of sites you operate" >&2
        exit 3
    fi
done
if [ "$_opt_remote_only" -eq 1 ] && [ "${#_p2s_urls[@]}" -eq 0 ]; then
    echo "php2shell-check: --remote-only needs at least one URL" >&2
    exit 3
fi
[ -n "${NO_COLOR:-}" ] && _opt_color=0
[ -t 1 ] || _opt_color=0
[ "$_opt_json" -eq 1 ] && _opt_color=0

# Test hooks: path prefix for every scanned file, and the proc filesystem to
# read process information from. Not for normal use.
_p2s_root=${P2S_TEST_ROOT:-}
_p2s_proc=${P2S_PROC_ROOT:-/proc}

# Set only while a binary that lives in another mount namespace is judged, by
# _p2s_check_ns_binary. _p2s_ns=1 points every lookup at that root's own data
# and forbids executing anything out of it; _p2s_ns_id is the dedupe identity
# and _p2s_ns_ver the version that was read without running the binary.
_p2s_ns=0
_p2s_ns_id=''
_p2s_ns_mnt=''
_p2s_ns_ver=''

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

if [ "$_opt_color" -eq 1 ]; then
    _c_red=$'\033[1;31m'; _c_yel=$'\033[1;33m'; _c_grn=$'\033[1;32m'
    _c_blu=$'\033[1;34m'; _c_dim=$'\033[2m'; _c_bold=$'\033[1m'; _c_off=$'\033[0m'
else
    _c_red=''; _c_yel=''; _c_grn=''; _c_blu=''; _c_dim=''; _c_bold=''; _c_off=''
fi

# Anything read from a container, a web server or a file is untrusted and may
# carry terminal escape sequences. Keep a conservative character set only.
_p2s_clean() { tr -dc 'A-Za-z0-9_.,:;/@+~=()<>%# -' | head -c "${1:-200}"; }

_p2s_lower() { tr '[:upper:]' '[:lower:]'; }

_p2s_timeout() {   # _p2s_timeout SECONDS cmd ...
    local _s=$1; shift
    if command -v timeout >/dev/null 2>&1; then timeout "$_s" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$_s" "$@"
    else "$@"
    fi
}

# Numeric dotted-version compare. Prints -1, 0 or 1.
_p2s_vercmp() {
    local _a=$1 _b=$2 _x _y
    while [ -n "$_a" ] || [ -n "$_b" ]; do
        _x=${_a%%.*}; _y=${_b%%.*}
        [ "$_a" = "$_x" ] && _a='' || _a=${_a#*.}
        [ "$_b" = "$_y" ] && _b='' || _b=${_b#*.}
        _x=${_x:-0}; _y=${_y:-0}
        if [ "$_x" -lt "$_y" ]; then echo -1; return; fi
        if [ "$_x" -gt "$_y" ]; then echo 1; return; fi
    done
    echo 0
}
_p2s_ver_ge() { [ "$(_p2s_vercmp "$1" "$2")" != "-1" ]; }

# Compare two Debian package versions. dpkg is the authority where it exists;
# without it (a container judged from a non-Debian host, macOS) the fallback
# walks the version in digit and non-digit segments the way dpkg does, with
# "~" sorting before everything. Without this fallback a missing dpkg made
# every comparison fail, which reported a patched package as vulnerable.
_p2s_deb_ge() {
    if command -v dpkg >/dev/null 2>&1; then
        dpkg --compare-versions "$1" ge "$2"
        return
    fi
    [ "$(_p2s_deb_cmp "$1" "$2")" != "-1" ]
}

_p2s_deb_cmp() {
    awk -v a="$1" -v b="$2" '
    function strip(s) { sub(/^[0-9]+:/, "", s); gsub(/~/, "\001", s); return s }
    function tok(s, arr,   n, i, j, L, c) {
        n = 0; i = 1; L = length(s)
        while (i <= L) {
            c = substr(s, i, 1)
            if (c >= "0" && c <= "9") {
                j = i
                while (j <= L && substr(s, j, 1) >= "0" && substr(s, j, 1) <= "9") j++
                n++; arr[n] = "N"; arr[n "v"] = substr(s, i, j - i) + 0
            } else {
                j = i
                while (j <= L && !(substr(s, j, 1) >= "0" && substr(s, j, 1) <= "9")) j++
                n++; arr[n] = "S"; arr[n "v"] = substr(s, i, j - i)
            }
            i = j
        }
        return n
    }
    BEGIN {
        na = tok(strip(a), ta); nb = tok(strip(b), tb)
        m = (na > nb) ? na : nb
        for (k = 1; k <= m; k++) {
            # A version that continues with "~" is older than one that ends
            # here: 8.4.27-1~deb13u1 comes before 8.4.27-1.
            if (k > na) { print (substr(tb[k "v"], 1, 1) == "\001") ? 1 : -1; exit }
            if (k > nb) { print (substr(ta[k "v"], 1, 1) == "\001") ? -1 : 1; exit }
            if (ta[k] == "N" && tb[k] == "N") {
                if (ta[k "v"] + 0 < tb[k "v"] + 0) { print -1; exit }
                if (ta[k "v"] + 0 > tb[k "v"] + 0) { print 1; exit }
            } else {
                if (ta[k "v"] "" < tb[k "v"] "") { print -1; exit }
                if (ta[k "v"] "" > tb[k "v"] "") { print 1; exit }
            }
        }
        print 0
    }'
}

_p2s_is_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# Size strings from php.ini ("64M", "1G", "-1") to bytes.
_p2s_bytes() {
    local _v=$1 _n
    case "$_v" in
        -1|'') echo -1; return ;;
    esac
    _n=${_v%[KkMmGg]}
    [[ "$_n" =~ ^[0-9]+$ ]] || { echo -1; return; }
    case "$_v" in
        *[Kk]) echo $(( _n * 1024 )) ;;
        *[Mm]) echo $(( _n * 1024 * 1024 )) ;;
        *[Gg]) echo $(( _n * 1024 * 1024 * 1024 )) ;;
        *)     echo "$_n" ;;
    esac
}

_p2s_os_field() {
    [ -r "$_p2s_root/etc/os-release" ] || return 0
    # Parsed, never sourced: os-release sets VERSION and friends.
    awk -F= -v k="$1" '$1==k{gsub(/"/,"",$2);print $2;exit}' "$_p2s_root/etc/os-release"
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

_f_status=(); _f_check=(); _f_target=(); _f_detail=()
_p2s_hints_1=''; _p2s_hints_2=''; _p2s_hints_3=''
_p2s_section_open=''

_p2s_section() {
    _p2s_section_open=$1
    [ "$_opt_json" -eq 1 ] || [ "$_opt_quiet" -eq 1 ] && return 0
    printf '\n%s%s%s\n' "$_c_bold" "$1" "$_c_off"
}

# _p2s_add STATUS CHECK TARGET DETAIL [HINT]
#   STATUS: vuln | unknown | warn | ok | info
_p2s_add() {
    local _st=$1 _ck=$2 _tg=$3 _dt=$4 _hn=${5:-} _tag _col
    _f_status+=("$_st"); _f_check+=("$_ck"); _f_target+=("$_tg"); _f_detail+=("$_dt")
    # Hints are collected by severity so the summary lists the urgent ones first.
    if [ -n "$_hn" ]; then
        case "$_st" in
            vuln)         _p2s_hints_1="$_p2s_hints_1|$_hn|" ;;
            warn|unknown) _p2s_hints_2="$_p2s_hints_2|$_hn|" ;;
            *)            _p2s_hints_3="$_p2s_hints_3|$_hn|" ;;
        esac
    fi
    [ "$_opt_json" -eq 1 ] || [ "$_opt_quiet" -eq 1 ] && return 0
    case "$_st" in
        vuln)    _tag='VULN'; _col=$_c_red ;;
        unknown) _tag=' ?? '; _col=$_c_yel ;;
        warn)    _tag='WARN'; _col=$_c_yel ;;
        ok)      _tag=' OK '; _col=$_c_grn ;;
        *)       _tag='INFO'; _col=$_c_blu ;;
    esac
    printf '  %s[%s]%s %-14s %s\n' "$_col" "$_tag" "$_c_off" "$_ck" "$_tg"
    printf '         %s\n' "$_dt"
    [ -n "$_hn" ] && printf '         %s-> %s%s\n' "$_c_dim" "$_hn" "$_c_off"
    return 0
}

_p2s_json_esc() {
    local _s=$1
    _s=${_s//\\/\\\\}; _s=${_s//\"/\\\"}
    printf '%s' "$_s"
}

# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

# Verdict for a plain upstream version (containers, own builds, Alpine, Remi).
# Prints "status|detail|hint".
_p2s_judge_upstream() {
    local _v=$1 _branch _fixed
    _branch=${_v%.*}
    _fixed=$(_p2s_upstream_fixed "$_branch")
    case "$_fixed" in
        none)
            echo "vuln|PHP $_v, branch $_branch has no fixed release yet|Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12; backports for 7.4 to 8.1 are announced but not out" ;;
        unknown)
            echo "unknown|PHP $_v, branch $_branch is not covered by the advisory data of $P2S_DATA_DATE|Compare with $P2S_ADVISORY_URL" ;;
        *)
            if _p2s_ver_ge "$_v" "$_fixed"; then
                echo "ok|PHP $_v (fixed from $_fixed)|"
            else
                echo "vuln|PHP $_v, fixed in $_fixed|Update PHP to $_fixed or later (container: pull the new image and recreate)"
            fi ;;
    esac
}

# Verdict for a Debian/Ubuntu package from data that may come from the host
# or from inside a container: codename, source package, package version, the
# PHP version and a label for the report. Prints "status|detail|hint".
_p2s_judge_deb_data() {
    local _cn=$1 _src=$2 _pv=$3 _v=$4 _pkg=$5 _up _fixed _dfixed
    _up=${_pv#*:}; _up=${_up%%[-+~]*}
    _fixed=$(_p2s_upstream_fixed "${_v%.*}")
    _dfixed=$(_p2s_distro_fixed "$_cn:$_src")
    if [ "$_fixed" != none ] && [ "$_fixed" != unknown ] && _p2s_is_version "$_up" && _p2s_ver_ge "$_up" "$_fixed"; then
        echo "ok|package $_pkg $_pv (upstream $_up)|"
    elif [ "$_dfixed" = unfixed ]; then
        echo "vuln|package $_pkg $_pv, the distribution has not published a fix yet|Apply the temporary mitigations below and watch the distribution's security tracker"
    elif [ "$_dfixed" != none ]; then
        if _p2s_deb_ge "$_pv" "$_dfixed"; then
            echo "ok|package $_pkg $_pv (distribution fix from $_dfixed)|"
        else
            echo "vuln|package $_pkg $_pv, fixed in $_dfixed|apt-get update && apt-get install --only-upgrade $_pkg, then restart PHP-FPM / the web server"
        fi
    else
        echo "unknown|package $_pkg $_pv, no fix data for ${_cn:-this release}|Install security updates and compare with the distribution's advisory for CVE-2026-109618"
    fi
}

# dpkg-query against the package database that belongs to the root under
# examination. --admindir lets this host's own dpkg-query read a container's
# /var/lib/dpkg: no exec into the container, no byte of it executed, and it
# works for every runtime because it is a file read. Judging a container by
# the HOST's database is the mistake v1.4.0 fixed for the Docker path, and the
# process fallback can make it just as easily.
_p2s_dpkg_query() {
    if [ "$_p2s_ns" -eq 1 ] && [ -d "$_p2s_root/var/lib/dpkg" ]; then
        dpkg-query --admindir="$_p2s_root/var/lib/dpkg" "$@"
    else
        dpkg-query "$@"
    fi
}

# The same verdict for a package on this host.
_p2s_judge_deb() {
    local _pkg=$1 _v=$2 _pv _src _cn
    # shellcheck disable=SC2016  # dpkg format string, expanded by dpkg-query
    _pv=$(_p2s_dpkg_query -W -f='${Version}' "$_pkg" 2>/dev/null | _p2s_clean 60)
    # shellcheck disable=SC2016  # dpkg format string, expanded by dpkg-query
    _src=$(_p2s_dpkg_query -W -f='${source:Package}' "$_pkg" 2>/dev/null | _p2s_clean 40)
    _cn=$(_p2s_os_field VERSION_CODENAME)
    _p2s_judge_deb_data "$_cn" "$_src" "$_pv" "$_v" "$_pkg"
}

# An RPM distribution backports the fix at an unchanged upstream number, like
# Debian does — but the deciding part is the release, and every rebuilder sets
# that scheme differently, so a version table cannot be kept correct. The
# changelog of the installed package can: it names the CVE.
#
# Measured on AlmaLinux 9.8 on 2026-10-22, all three with a changelog entry of
# 2026-10-21 naming both CVE IDs:
#   php-cli-8.0.30-8.el9_8.alma.1                      (branch 8.0, no upstream fix at all)
#   php-cli-8.1.32-1.module_el9.8.0+326+528679fc.alma.1 (branch 8.1, likewise)
#   php-cli-8.3.33-1.module_el9.8.0+328+1fdeb728.alma.1 (8.3.33, below the upstream 8.3.36)
# The reverse does not hold, which is why a missing entry decides nothing
# here: the 8.3.36 and 8.2.35 rebases carry the fix through their version and
# never mention a CVE. The plain RHEL build php-cli-8.0.30-8.el9_8 and every
# php-cli in Rocky 9.8 carried no such entry on that day.
_p2s_rpm_changelog_fixed() {   # package name -> 0 when its changelog names a CVE
    [ -n "$1" ] || return 1
    _p2s_timeout 5 rpm -q --changelog "$1" 2>/dev/null \
        | grep -qF -e 'CVE-2026-109618' -e 'CVE-2026-109619'
}

# Verdict for an RPM package. Prints "status|detail|hint".
_p2s_judge_rpm() {
    local _file=$1 _v=$2 _pkg _name _vendor _fixed
    _pkg=$(rpm -qf --qf '%{NAME}-%{VERSION}-%{RELEASE}' "$_file" 2>/dev/null | head -n1 | _p2s_clean 80)
    _name=$(rpm -qf --qf '%{NAME}' "$_file" 2>/dev/null | head -n1 | _p2s_clean 60)
    _vendor=$(rpm -qf --qf '%{VENDOR}' "$_file" 2>/dev/null | head -n1 | _p2s_clean 60)
    _fixed=$(_p2s_upstream_fixed "${_v%.*}")
    if [ "$_fixed" != none ] && [ "$_fixed" != unknown ] && _p2s_ver_ge "$_v" "$_fixed"; then
        echo "ok|package $_pkg|"
    elif _p2s_rpm_changelog_fixed "$_name"; then
        echo "ok|package $_pkg, its changelog names the CVE: a backport at an unchanged upstream number|"
    elif printf '%s' "$_vendor" | grep -qi remi; then
        echo "vuln|package $_pkg (Remi ships upstream versions)|dnf upgrade 'php*' and restart PHP-FPM / the web server"
    else
        echo "unknown|package $_pkg ($_vendor), PHP $_v is below the upstream fix and the package changelog does not name the CVE|dnf upgrade, then compare with the vendor's advisory for CVE-2026-109618"
    fi
}

_p2s_add_verdict() {   # _p2s_add_verdict CHECK TARGET "status|detail|hint"
    local _st _dt _hn _rest
    _st=${3%%|*}; _rest=${3#*|}; _dt=${_rest%%|*}; _hn=${_rest#*|}
    _p2s_add "$_st" "$1" "$2" "$_dt" "$_hn"
}

# ---------------------------------------------------------------------------
# Runtime configuration: the temporary measures from php.net, section
# "If you cannot update immediately" (https://www.php.net/archive/2026.php).
#
# Every judgement below follows that section and nothing else. What it asks
# for, and what this script can read:
#   - memory_limit=-1, "preferably in a way applications can't override, such
#     as php_admin_value in the FPM pool or Apache configuration", and a check
#     "that no pool, directory or application setting puts a finite limit
#     back". This is the first measure in the section.
#   - a low post_max_size: 8M for applications that don't require file
#     uploads, 32M if uploads are necessary, with upload_max_filesize kept
#     below post_max_size.
#   - session.upload_progress.enabled=0 and a restart of every worker, through
#     php.ini, an FPM pool or server configuration that applies before request
#     parsing -- not ini_set() and not an FPM .user.ini.
#   - on PHP 8.5, fatal_error_backtraces=0 and a restart of every worker.
#   - the request limits (decoded size, field count, multipart part count,
#     header count, nesting depth) enforced at the web server or proxy level.
#     The section names no value for max_input_nesting_level, so this script
#     reports that setting as context and never as a missing measure.
#   - no RLIMIT_AS or RLIMIT_DATA as a substitute for a container or cgroup
#     limit, because "these can cause the vulnerable allocation failure".
#
# Settings the section does not name are not reported as its measures:
# expose_php (a disclosure question, its own line below, same as the remote
# check gives it), max_input_vars and pm.max_requests.
#
# And no result here is an "ok", because the section opens with: "while only
# an update is a complete solution, the following measures reduce exposure to
# specific attack paths but do not make an installation safe." Until 1.6.0
# this check answered "[OK] advisory mitigations in place", which said the
# opposite of its own source.
# ---------------------------------------------------------------------------

# The advisory's two absolute numbers for post_max_size, as bytes.
_P2S_POST_NO_UPLOADS=8M
_P2S_POST_UPLOADS=32M

# What php.ini says, kept for the pool and vhost checks further down: a pool
# or vhost that forces another value makes the php.ini line in this report
# untrue for that scope.
_p2s_ini_src=''
_p2s_ini_mem=''
_p2s_ini_post=''
_p2s_ini_upload=''
_p2s_ini_upprog=''

# shellcheck disable=SC2016  # PHP code, $k and $v belong to PHP
_P2S_INI_CODE='foreach (["memory_limit","post_max_size","upload_max_filesize","max_input_nesting_level","session.upload_progress.enabled","expose_php","fatal_error_backtraces"] as $k) { $v = ini_get($k); echo $k, "=", ($v === false ? "n/a" : $v), "\n"; }'

# _p2s_check_ini TARGET cmd... (cmd runs php with -r appended)
_p2s_check_ini() {
    local _tg=$1 _out _k _v _mem='' _post='' _upl='' _expose='' _upprog='' \
          _missing='' _note='' _mb _pb _ub _p8 _p32
    shift
    _out=$(_p2s_timeout 5 "$@" -r "$_P2S_INI_CODE" 2>/dev/null | head -n 20 | _p2s_clean_lines) || return 0
    [ -n "$_out" ] || return 0
    while IFS='=' read -r _k _v; do
        # "=" is the only separator, so a value keeps any padding around it.
        # Several judgements below compare it exactly ("-1", "On"), and a
        # stray space would turn a satisfied measure into a missing one.
        _k=${_k//[[:space:]]/}
        _v=${_v//[[:space:]]/}
        case "$_k" in
            memory_limit)        _mem=$_v ;;
            post_max_size)       _post=$_v ;;
            upload_max_filesize) _upl=$_v ;;
            expose_php)          _expose=$_v ;;
            session.upload_progress.enabled)
                _upprog=$_v
                case "$_v" in 1|On|on) _missing="$_missing session.upload_progress.enabled=0" ;; esac ;;
            fatal_error_backtraces)
                # ini_get answers false below PHP 8.5, which the probe prints
                # as n/a. The advisory asks for this one on 8.5 only, so a
                # host without the setting has nothing to set.
                case "$_v" in 1|On|on) _missing="$_missing fatal_error_backtraces=0" ;; esac ;;
            max_input_nesting_level)
                if [[ "$_v" =~ ^[0-9]+$ ]]; then
                    _note="$_note max_input_nesting_level is $_v; the advisory asks for nesting depth to be limited at the web server or proxy level and names no value for this PHP setting."
                fi ;;
        esac
    done <<EOF
$_out
EOF
    # memory_limit=-1 is the section's first measure: it removes the
    # controllable PHP memory limit failure. A finite value leaves it in
    # place, so it is a missing measure. Until 1.6.0 this value was read and
    # never judged, which is what let a badly configured host come out green.
    _mb=$(_p2s_bytes "$_mem")
    if [ "$_mem" != -1 ] && [ "$_mem" != n/a ] && [ -n "$_mem" ] && [ "$_mb" -ge 0 ]; then
        _missing="$_missing memory_limit=-1 (now $_mem)"
    fi

    # post_max_size against the two numbers the advisory names. This script
    # cannot know whether an installation needs file uploads, so it never
    # picks one of the two for the reader: up to 8M satisfies the section
    # either way, above 32M fails it either way, and in between the value
    # holds only for an installation that does need uploads -- which is said
    # in those words instead of being decided silently.
    _pb=$(_p2s_bytes "$_post")
    _p8=$(_p2s_bytes "$_P2S_POST_NO_UPLOADS")
    _p32=$(_p2s_bytes "$_P2S_POST_UPLOADS")
    case "$_post" in
        0|-1)
            # PHP reads 0 as "do not check the size at all".
            _missing="$_missing a low post_max_size ($_P2S_POST_NO_UPLOADS without file uploads, $_P2S_POST_UPLOADS with; now $_post, no limit)" ;;
        *)
            if [ "$_pb" -gt "$_p32" ]; then
                _missing="$_missing a low post_max_size ($_P2S_POST_NO_UPLOADS without file uploads, $_P2S_POST_UPLOADS with; now $_post)"
            elif [ "$_pb" -gt "$_p8" ]; then
                _note="$_note post_max_size is $_post: the advisory asks for $_P2S_POST_NO_UPLOADS where file uploads are not required and $_P2S_POST_UPLOADS where they are, so this value is low enough only if this installation needs uploads."
            fi ;;
    esac

    # "Keep upload_max_filesize below post_max_size."
    _ub=$(_p2s_bytes "$_upl")
    if [ "$_ub" -gt 0 ] && [ "$_pb" -gt 0 ] && [ "$_ub" -ge "$_pb" ]; then
        _missing="$_missing upload_max_filesize below post_max_size (now $_upl vs $_post)"
    fi

    # expose_php is not one of the advisory's measures. It decides whether the
    # version is in the response headers, not whether the bug can be reached,
    # so it gets the same kind of line the remote check gives it and must not
    # decide the verdict below. Until 1.6.0 it did, and tipped hosts whose
    # real measures were all in place.
    case "$_expose" in
        1|On|on)
            _p2s_add warn disclosure "$_tg" 'expose_php is on, so the PHP version is in the response headers for everyone' \
                'Set expose_php=0 so scanners cannot pick vulnerable targets by header' ;;
        0|Off|off)
            _p2s_add ok disclosure "$_tg" 'expose_php is off, the response headers do not reveal the PHP version' ;;
    esac

    if [ -n "$_missing" ]; then
        _p2s_add warn mitigation "$_tg" "temporary measures from the advisory not set:$_missing.$_note" \
            'Until patched: set memory_limit=-1 and session.upload_progress.enabled=0 where applications cannot override them (php_admin_value in the FPM pool or the Apache configuration), keep post_max_size low, and restart every worker. Only an update is a complete solution'
    else
        # Deliberately info, not ok: info is counted nowhere and changes no
        # exit code, which is the point -- a mitigation is not a patch.
        _p2s_add info mitigation "$_tg" "the temporary measures from the advisory that are readable here are set.$_note Only an update is a complete solution: these measures reduce exposure to specific attack paths but do not make an installation safe."
    fi

    # Remember php.ini for the pool and vhost checks. The FPM php.ini wins
    # when several were probed: that is the one the pools build on.
    case "$_tg" in
        *'(fpm php.ini)'*) : ;;
        *) [ -z "$_p2s_ini_src" ] || return 0 ;;
    esac
    _p2s_ini_src=$_tg
    _p2s_ini_mem=$_mem
    _p2s_ini_post=$_post
    _p2s_ini_upload=$_upl
    _p2s_ini_upprog=$_upprog
}

# php.ini is not the last word. An FPM pool, an Apache section or a
# fastcgi_param can force another value, and the advisory asks explicitly to
# check "that no pool, directory or application setting puts a finite limit
# back" -- that is also where it wants memory_limit=-1 to be set in the first
# place. Read line by line, without a configuration parser: no include is
# followed, no conditional section is evaluated, no precedence between files
# is computed. README says what that misses.
#
# Prints one "name=value" per forced setting.
_p2s_forced_settings() {   # file kind(fpm|apache|nginx)
    case "$2" in
        fpm)
            # php_admin_value[memory_limit] = -1
            grep -E '^[[:space:]]*php_(admin_)?(value|flag)\[[A-Za-z0-9_.]+\][[:space:]]*=' "$1" 2>/dev/null \
                | sed -E 's/^[[:space:]]*php_(admin_)?(value|flag)\[([A-Za-z0-9_.]+)\][[:space:]]*=[[:space:]]*/\3=/' ;;
        apache)
            # php_admin_value memory_limit -1
            grep -E '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+[A-Za-z0-9_.]+[[:space:]]+[^[:space:]]' "$1" 2>/dev/null \
                | sed -E 's/^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+([A-Za-z0-9_.]+)[[:space:]]+"?([^"[:space:]]+)"?.*$/\3=\4/' ;;
        nginx)
            # fastcgi_param PHP_ADMIN_VALUE "memory_limit=-1";
            # Only the single-line form. nginx can carry several settings in
            # one newline-separated quoted string, and that shape is not
            # readable without a parser.
            grep -E 'fastcgi_param[[:space:]]+PHP_(ADMIN_)?VALUE' "$1" 2>/dev/null \
                | grep -oE '[A-Za-z0-9_.]+[[:space:]]*=[[:space:]]*[^";[:space:]]+' \
                | sed -E 's/[[:space:]]*=[[:space:]]*/=/' ;;
    esac | head -n 40 | _p2s_clean_lines
}

# The section header for forced settings, opened only when there is one.
_p2s_forced_pending=''
_p2s_forced_open() {
    [ -n "$_p2s_forced_pending" ] || return 0
    _p2s_section "$_p2s_forced_pending"
    _p2s_forced_pending=''
}

# Judge every setting one file forces, against the same advisory text as
# php.ini, and name the contradiction when php.ini says something else: the
# php.ini line in this report does not describe that scope.
_p2s_check_forced_file() {   # file kind target
    local _f=$1 _kind=$2 _tg=$3 _k _v _diff _b _p32
    _p32=$(_p2s_bytes "$_P2S_POST_UPLOADS")
    while IFS='=' read -r _k _v; do
        _k=${_k//[[:space:]]/}
        _v=${_v//[[:space:]]/}
        [ -n "$_k" ] && [ -n "$_v" ] || continue
        case "$_k" in
            memory_limit)
                _diff=''
                if [ -n "$_p2s_ini_mem" ] && [ "$_p2s_ini_mem" != "$_v" ]; then
                    _diff=" php.ini reads memory_limit = $_p2s_ini_mem, so the php.ini line in this report does not describe this scope."
                fi
                if [ "$_v" = -1 ]; then
                    # This is where the advisory wants the setting to be, so
                    # it is not a warning even when php.ini disagrees.
                    _p2s_forced_open
                    _p2s_add info forced-ini "$_tg" "forces memory_limit = -1 where applications cannot override it, which is what the advisory asks for.$_diff"
                else
                    _p2s_forced_open
                    _p2s_add warn forced-ini "$_tg" "forces memory_limit = $_v, a finite limit; the advisory asks to check that no pool, directory or application setting puts one back.$_diff" \
                        'Set memory_limit=-1 in the pool or vhost as well, or drop the line, then restart every worker'
                fi ;;
            post_max_size)
                _b=$(_p2s_bytes "$_v")
                if [ "$_v" = 0 ] || [ "$_v" = -1 ] || [ "$_b" -gt "$_p32" ]; then
                    _p2s_forced_open
                    _p2s_add warn forced-ini "$_tg" "forces post_max_size = $_v, above both values the advisory names ($_P2S_POST_NO_UPLOADS without file uploads, $_P2S_POST_UPLOADS with)" \
                        'Lower post_max_size in the pool or vhost as well, then restart every worker'
                fi ;;
            session.upload_progress.enabled)
                case "$_v" in
                    1|On|on|true)
                        _diff=''
                        if [ -n "$_p2s_ini_upprog" ] && [ "$_p2s_ini_upprog" != "$_v" ]; then
                            _diff=" php.ini reads $_p2s_ini_upprog, so the php.ini line in this report does not describe this scope."
                        fi
                        _p2s_forced_open
                        _p2s_add warn forced-ini "$_tg" "forces session.upload_progress.enabled = $_v, the setting the advisory asks to turn off.$_diff" \
                            'Set session.upload_progress.enabled=0 in the pool or vhost as well, then restart every worker' ;;
                esac ;;
        esac
    done <<EOF
$(_p2s_forced_settings "$_f" "$_kind")
EOF
}

_p2s_check_vhost_overrides() {
    local _f
    _p2s_forced_pending='PHP settings forced by the web server'
    for _f in "$_p2s_root"/etc/apache2/apache2.conf "$_p2s_root"/etc/apache2/sites-enabled/*.conf \
              "$_p2s_root"/etc/apache2/conf-enabled/*.conf "$_p2s_root"/etc/apache2/vhosts.d/*.conf \
              "$_p2s_root"/etc/httpd/conf/httpd.conf "$_p2s_root"/etc/httpd/conf.d/*.conf; do
        [ -f "$_f" ] && [ -r "$_f" ] || continue
        _p2s_check_forced_file "$_f" apache "${_f#"$_p2s_root"}"
    done
    for _f in "$_p2s_root"/etc/nginx/nginx.conf "$_p2s_root"/etc/nginx/conf.d/*.conf \
              "$_p2s_root"/etc/nginx/sites-enabled/*; do
        [ -f "$_f" ] && [ -r "$_f" ] || continue
        _p2s_check_forced_file "$_f" nginx "${_f#"$_p2s_root"}"
    done
    _p2s_forced_pending=''
}

# The advisory names RLIMIT_AS and RLIMIT_DATA as what NOT to use: it asks for
# "a container or cgroup limit as an availability boundary, preferably with a
# policy that kills only the affected worker" and adds "do not substitute
# RLIMIT_AS or RLIMIT_DATA, as these can cause the vulnerable allocation
# failure". So a finite one on a PHP process, or in the unit that starts it,
# is worth a warning whatever it was set for.
_p2s_check_rlimits() {
    local _p _e _as _data _unit _hit _key _seen=' '
    _p2s_forced_pending='Address-space limits on PHP'
    # /proc, the same test hook the process fallback uses.
    if [ -z "$_p2s_root" ] || [ -n "${P2S_PROC_ROOT:-}" ]; then
        if [ -d "$_p2s_proc" ]; then
            for _p in "$_p2s_proc"/[0-9]*; do
                _e=$(readlink "$_p/exe" 2>/dev/null) || continue
                _e=${_e% (deleted)}
                case "$_e" in
                    */php|*/php[0-9]*|*/php-fpm|*/php-fpm[0-9]*|*/lsphp|*/lsphp[0-9]* \
                    |*/php-cgi|*/php-cgi[0-9]*|*/cgi-bin/php*|*/frankenphp) ;;
                    *) continue ;;
                esac
                [ -r "$_p/limits" ] || continue
                # Both names are three words wide, so the soft limit is field
                # four. Spelled out instead of an awk interval expression:
                # mawk 1.3.4 20200120 does not match those at all.
                _as=$(awk '/^Max address space/ { print $4; exit }' "$_p/limits" 2>/dev/null)
                _data=$(awk '/^Max data size/ { print $4; exit }' "$_p/limits" 2>/dev/null)
                _hit=''
                [[ "$_as" =~ ^[0-9]+$ ]] && _hit="$_hit RLIMIT_AS=$_as"
                [[ "$_data" =~ ^[0-9]+$ ]] && _hit="$_hit RLIMIT_DATA=$_data"
                [ -n "$_hit" ] || continue
                # One line per binary and limit pair: an FPM pool has dozens
                # of children that all carry the same limits.
                _key=$(printf '%s%s' "$_e" "$_hit" | _p2s_clean 160 | tr -d ' ')
                case "$_seen" in *" $_key "*) continue ;; esac
                _seen="$_seen$_key "
                _p2s_forced_open
                _p2s_add warn rlimit "$(printf '%s' "$_e" | _p2s_clean 80)" \
                    "runs with a finite address-space limit ($_hit bytes); the advisory asks not to substitute RLIMIT_AS or RLIMIT_DATA for a container or cgroup limit, because these can cause the vulnerable allocation failure" \
                    'Drop the RLIMIT_AS / RLIMIT_DATA limit and bound memory with a container or cgroup limit that kills only the affected worker'
            done
        fi
    fi
    for _unit in "$_p2s_root"/etc/systemd/system/*php*.service "$_p2s_root"/etc/systemd/system/*php*.service.d/*.conf \
                 "$_p2s_root"/etc/systemd/system/*frankenphp*.service "$_p2s_root"/etc/systemd/system/*frankenphp*.service.d/*.conf \
                 "$_p2s_root"/lib/systemd/system/*php*.service "$_p2s_root"/lib/systemd/system/*frankenphp*.service \
                 "$_p2s_root"/usr/lib/systemd/system/*php*.service "$_p2s_root"/usr/lib/systemd/system/*frankenphp*.service; do
        [ -f "$_unit" ] && [ -r "$_unit" ] || continue
        _hit=$(grep -E '^[[:space:]]*Limit(AS|DATA)[[:space:]]*=' "$_unit" 2>/dev/null \
               | grep -viE '=[[:space:]]*(infinity|unlimited)' | head -n 4 | tr '\n' ' ' | _p2s_clean 120)
        [ -n "$_hit" ] || continue
        _p2s_forced_open
        _p2s_add warn rlimit "${_unit#"$_p2s_root"}" \
            "sets a finite address-space limit ($_hit); the advisory asks not to substitute RLIMIT_AS or RLIMIT_DATA for a container or cgroup limit, because these can cause the vulnerable allocation failure" \
            'Drop the RLIMIT_AS / RLIMIT_DATA limit and bound memory with a container or cgroup limit that kills only the affected worker'
    done
    _p2s_forced_pending=''
}

_p2s_clean_lines() { tr -dc 'A-Za-z0-9_.:/=<>() \n-' | head -c 1000; }

# ---------------------------------------------------------------------------
# Local checks
# ---------------------------------------------------------------------------

_p2s_seen=' '
_p2s_seen_pkg=' '
_p2s_runtime_ns=' '
_p2s_runtime_cmd=0
_p2s_ns_found=0

_p2s_php_version_of() {   # binary -> x.y.z or empty
    local _b=$1 _v
    case "$_b" in
        *frankenphp*)
            # FrankenPHP links PHP into its own binary and answers with
            # "FrankenPHP v1.13.2 PHP 8.5.12 Caddy v2.11.7 h1:...". The first
            # version in that line is FrankenPHP's own, so anchor on "PHP ".
            # "frankenphp php-cli -v" is no alternative: below PHP 8.6 it
            # answers "this functionality is not available".
            _v=$(_p2s_timeout 5 "$_b" version 2>/dev/null | head -n1 \
                 | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -n1)
            _v=${_v#PHP } ;;
        *php-fpm*|*lsphp*|*php-cgi*|*/cgi-bin/php*)
            # php-cgi rejects -r ("option not found r") and prints a usage
            # block instead of a version, so -v is the only probe these share.
            _v=$(_p2s_timeout 5 "$_b" -v 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1) ;;
        *)                 _v=$(_p2s_timeout 5 "$_b" -r 'echo PHP_VERSION;' 2>/dev/null | head -n1 | _p2s_clean 30) ;;
    esac
    _v=${_v%%[-+~]*}
    _p2s_is_version "$_v" && echo "$_v"
}

# Judge one PHP binary. $2 is a note for the report (how it was found).
_p2s_check_one_binary() {
    local _b=$1 _note=${2:-} _real _v='' _pkg _verdict _dir _sapi _qpath
    [ -f "$_b" ] && [ -x "$_b" ] || return 1
    if [ "$_p2s_ns" -eq 1 ]; then
        # readlink -f would walk through the /proc/<pid>/root magic symlink and
        # hand back a path read in the HOST namespace, which both collides with
        # the host's own binaries in the dedupe list and would point the host
        # package database at the wrong file. The mount namespace id plus the
        # path inside it is the identity that is true for every worker of that
        # container and for nothing else.
        _real=$_p2s_ns_id
        _v=$_p2s_ns_ver
    else
        _real=$(readlink -f "$_b" 2>/dev/null || echo "$_b")
    fi
    case "$_p2s_seen" in *" $_real "*) return 1 ;; esac
    _p2s_seen="$_p2s_seen$_real "
    [ -n "$_v" ] || _v=$(_p2s_php_version_of "$_b")
    [ -n "$_v" ] || return 1
    # No test-root guard here: a path that no package owns simply yields an
    # empty answer, and that lets the tests put a dpkg-query stub in PATH and
    # exercise the distribution path end to end instead of as a unit only.
    _pkg=''
    # A foreign root lists its files under the paths they have INSIDE that
    # root, so the /proc/<pid>/root prefix has to come off before the search.
    _qpath=$_real
    [ "$_p2s_ns" -eq 1 ] && _qpath=${_b#"$_p2s_root"}
    if command -v dpkg-query >/dev/null 2>&1; then
        _pkg=$(_p2s_dpkg_query -S "$_qpath" 2>/dev/null | head -n1 | cut -d: -f1)
    fi
    if [ -n "$_pkg" ]; then
        # Debian ships the same cgi build under two paths (/usr/bin/php-cgi8.4
        # and /usr/lib/cgi-bin/php8.4). Same package, same version, same
        # verdict — report it once instead of twice.
        # The mount namespace belongs in the key. php8.3-cli 8.3.6 on the host
        # and php8.3-cli 8.3.6 in a container are the same name at the same
        # upstream number and a different patch state, so collapsing them
        # would hide a vulnerable container behind a patched host, or the
        # other way round.
        case "$_p2s_seen_pkg" in *" $_p2s_ns_mnt$_pkg $_v "*) return 0 ;; esac
        _p2s_seen_pkg="$_p2s_seen_pkg$_p2s_ns_mnt$_pkg $_v "
        _verdict=$(_p2s_judge_deb "$_pkg" "$_v")
    elif [ "$_p2s_ns" -eq 0 ] && command -v rpm >/dev/null 2>&1 && rpm -qf "$_real" >/dev/null 2>&1; then
        _verdict=$(_p2s_judge_rpm "$_real" "$_v")
    else
        # An RPM root is deliberately not read through rpm --dbpath: the
        # database format changed between EL releases (bdb, ndb, sqlite), so
        # the host's rpm can fail on a container's database in a way that looks
        # like "no package" instead of like an error. Without a package the
        # upstream comparison decides, and a version only reaches this point
        # when it came from the image environment, where it is an upstream
        # number — see _p2s_ns_php_version.
        _verdict=$(_p2s_judge_upstream "$_v")
    fi
    _p2s_add_verdict php-binary "${_b#"$_p2s_root"}$_note" "$_verdict"
    # The ini probe below runs the binary with -r. Never do that with a binary
    # out of a foreign root; _p2s_ns_php_version carries the reasoning. The
    # runtime configuration of that root therefore stays unchecked, which is
    # the same limit the README already states for FrankenPHP without a CLI.
    [ "$_p2s_ns" -eq 1 ] && return 0
    case "$_b" in
        # None of these can run the ini probe: -r belongs to the CLI binary
        # alone. On a Debian layout the CLI binary reads the fpm, apache2 and
        # cgi php.ini below anyway; a FrankenPHP host without a php CLI keeps
        # its runtime configuration unchecked, which README states.
        *php-fpm*|*lsphp*|*php-cgi*|*/cgi-bin/php*|*frankenphp*) ;;
        *)
            _p2s_check_ini "${_b#"$_p2s_root"} (CLI)" "$_b"
            # Debian layout: evaluate the FPM / Apache php.ini with this binary.
            _dir="$_p2s_root/etc/php/${_v%.*}"
            for _sapi in fpm apache2 cgi; do
                [ -r "$_dir/$_sapi/php.ini" ] || continue
                PHP_INI_SCAN_DIR="$_dir/$_sapi/conf.d" _p2s_check_ini \
                    "${_b#"$_p2s_root"} ($_sapi php.ini)" "$_b" -c "$_dir/$_sapi/php.ini"
            done ;;
    esac
    return 0
}

# PHP paths taken from the running processes. A build in an unusual place
# (/opt/php-8.3, a vendor bundle) is invisible to the path list below, and
# reporting "no PHP found" on a host that is serving PHP right now is the
# worst mistake this script could make.
#
# The exe link of a containerised process names the path INSIDE that
# container, and that path does not exist in the host's namespace — so the old
# "[ -f $_e ]" filter threw away exactly the finds this fallback exists for.
# Measured on a Docker host on 2026-10-22: php:8.3.35-fpm running as pid
# 581758, [ -f /usr/local/sbin/php-fpm ] false, [ -f
# /proc/581758/root/usr/local/sbin/php-fpm ] true, and the whole run said "no
# PHP installation found" and exited 0. /proc/<pid>/root reaches every runtime
# that gives its payload its own mount namespace — rootless Docker of another
# user, containerd/nerdctl, Kubernetes, LXC/LXD, systemd-nspawn, Snap — with
# one path and without asking any of them.
#
# Prints one record per find: "kind|pid|mount-namespace|path". kind is "host"
# when the process shares our mount namespace and "ns" when it does not.
_p2s_running_php_paths() {
    local _p _e _ns _self _kind _seen=' '
    [ -z "$_p2s_root" ] || [ -n "${P2S_PROC_ROOT:-}" ] || return 0
    [ -d "$_p2s_proc" ] || return 0
    _self=$(readlink "$_p2s_proc/self/ns/mnt" 2>/dev/null | tr -dc '0-9a-z:[]')
    for _p in "$_p2s_proc"/[0-9]*; do
        _e=$(readlink "$_p/exe" 2>/dev/null) || continue
        _e=${_e% (deleted)}
        case "$_e" in
            */php|*/php[0-9]*|*/php-fpm|*/php-fpm[0-9]*|*/lsphp|*/lsphp[0-9]* \
            |*/php-cgi|*/php-cgi[0-9]*|*/cgi-bin/php*|*/frankenphp) ;;
            *) continue ;;
        esac
        # The namespace, not the file test, decides whose binary this is: an
        # LXC container with /usr/bin/php8.3 on a host that also has
        # /usr/bin/php8.3 would otherwise be judged by the host's package and
        # then silently dropped by the dedupe list.
        _ns=$(readlink "$_p/ns/mnt" 2>/dev/null | tr -dc '0-9a-z:[]')
        if [ "$_ns" = "$_self" ]; then _kind=host; else _kind=ns; fi
        # One line per (namespace, path): a busy FPM pool has dozens of
        # workers on the same binary and they are one installation.
        case "$_seen" in *" $_kind$_ns$_e "*) continue ;; esac
        _seen="$_seen $_kind$_ns$_e "
        printf '%s|%s|%s|%s\n' "$_kind" "${_p##*/}" "$_ns" "$_e"
    done | sort -u
}

# The PHP version of a binary in another mount namespace, read from data and
# never by running it.
#
# Running it is the obvious shortcut and measurably tempting: on the Docker
# host of 2026-10-22 /proc/581758/root/usr/local/sbin/php-fpm -v did answer
# "PHP 8.3.35 (fpm-fcgi)". It is still the wrong thing to do here, for two
# reasons that each stand on their own.
#
# It would be foreign code as root. That binary comes out of an image somebody
# else built, and starting it from the host starts it OUTSIDE the container's
# namespaces, cgroups, seccomp filter and AppArmor profile, with full host
# privileges. A tool whose whole promise is "changes nothing, starts nothing"
# must not be the thing that lifts a container payload onto the host. For the
# host's own binaries the trade-off is a different one and the script keeps
# using -v there: those are already running as themselves.
#
# And the answer would not be trustworthy either. The ELF interpreter and
# every library path in that binary are absolute and resolve against the HOST
# root, not the container's: a musl image on a glibc host fails outright, and
# a glibc image of another vintage links against the host's libraries, so what
# it prints is not necessarily what the container runs.
#
# Three sources answer without execution, in this order. All three were
# measured against real containers on a Docker host on 2026-10-22, and the
# order matters more than it looks:
#   1. the container's own dpkg database, which the Debian/Ubuntu verdict needs
#      anyway — a backported 8.3.6 can only be decided from the package
#      version. Measured: dpkg-query --admindir on /proc/<pid>/root answers
#      "php8.3-fpm 8.3.6-0ubuntu0.24.04.13" for an Ubuntu 24.04 container.
#   2. PHP_VERSION in the process environment. The official php, wordpress and
#      FrankenPHP images set it, but only CLI-style processes still carry it:
#      measured, php:8.3.35-cli has PHP_VERSION=8.3.35 in /proc/<pid>/environ
#      while the php-fpm master has overwritten that memory with its process
#      title ("master process (...)"). So this source misses exactly the SAPI
#      that matters most, which is why 3 exists.
#   3. main/php_version.h of a source build, which those images ship with
#      their headers. Measured: this is what answered for php:8.3.35-fpm
#      (#define PHP_VERSION "8.3.35").
# Nothing found means the verdict says so, see _p2s_check_ns_binary.
_p2s_ns_php_version() {   # process-dir root-prefix path-inside-that-root
    local _pd=$1 _r=$2 _e=$3 _v='' _pkg _pv _h
    if command -v dpkg-query >/dev/null 2>&1 && [ -r "$_r/var/lib/dpkg/status" ]; then
        _pkg=$(_p2s_dpkg_query -S "$_e" 2>/dev/null | head -n1 | cut -d: -f1 | _p2s_clean 60)
        if [ -n "$_pkg" ]; then
            # shellcheck disable=SC2016  # dpkg format string, expanded by dpkg-query
            _pv=$(_p2s_dpkg_query -W -f='${Version}' "$_pkg" 2>/dev/null | _p2s_clean 60)
            _v=${_pv#*:}; _v=${_v%%[-+~]*}
        fi
    fi
    if ! _p2s_is_version "$_v" && [ -r "$_pd/environ" ]; then
        _v=$(tr '\0' '\n' < "$_pd/environ" 2>/dev/null \
             | awk -F= '$1=="PHP_VERSION"{print $2;exit}' | _p2s_clean 30)
        _v=${_v%%[-+~]*}
    fi
    if ! _p2s_is_version "$_v"; then
        for _h in "$_r"/usr/local/include/php/main/php_version.h \
                  "$_r"/usr/include/php/main/php_version.h; do
            [ -r "$_h" ] || continue
            _v=$(grep -E '^#define PHP_VERSION ' "$_h" 2>/dev/null | head -n1 | tr -dc '0-9.')
            _p2s_is_version "$_v" && break
        done
    fi
    _p2s_is_version "$_v" && printf '%s' "$_v"
}

# Judge a PHP binary that runs in another mount namespace. Everything the
# verdict needs comes out of THAT root: /etc/os-release for the codename,
# /var/lib/dpkg for the package version, its own php.ini paths. Reusing
# _p2s_root as the prefix is what makes that free — it is already the "look
# below this tree instead of /" switch that P2S_TEST_ROOT uses, and every
# verdict function already reads through it.
_p2s_check_ns_binary() {   # pid mount-namespace path-inside-that-root
    local _pid=$1 _nsid=$2 _e=$3 _hit=1
    local _o_root=$_p2s_root _o_ns=$_p2s_ns _o_id=$_p2s_ns_id _o_ver=$_p2s_ns_ver
    local _o_mnt=$_p2s_ns_mnt
    _p2s_root="$_p2s_proc/$_pid/root"
    _p2s_ns=1
    # No namespace id readable (an unprivileged run) means the pid has to
    # stand in for it: two such finds must not be mistaken for one, and
    # neither must one of them be mistaken for a host path.
    _p2s_ns_mnt="${_nsid:-pid$_pid}:"
    _p2s_ns_id="$_p2s_ns_mnt$_e"
    _p2s_ns_ver=$(_p2s_ns_php_version "$_p2s_proc/$_pid" "$_p2s_root" "$_e")
    if [ -n "$_p2s_ns_ver" ]; then
        _p2s_check_one_binary "$_p2s_root$_e" \
            " (running in a container or other mount namespace, pid $_pid)" || _hit=0
    else
        case "$_p2s_seen" in
            *" $_p2s_ns_id "*) _hit=0 ;;
            *)
                _p2s_seen="$_p2s_seen$_p2s_ns_id "
                _p2s_add unknown php-binary "$_e (running in a container or other mount namespace, pid $_pid)" \
                    'PHP serves requests here, but its version is in neither the package database nor the image environment of that root, and this script does not run a binary out of a foreign root as root on the host' \
                    'Ask it from inside: docker/podman/nerdctl exec <container> php -v, kubectl exec, or lxc-attach' ;;
        esac
    fi
    _p2s_root=$_o_root; _p2s_ns=$_o_ns; _p2s_ns_id=$_o_id; _p2s_ns_ver=$_o_ver
    _p2s_ns_mnt=$_o_mnt
    [ "$_hit" -eq 1 ]
}

# Mount namespaces that the Docker/Podman check below covers anyway. That
# check has more to say about them (runtime configuration, SAPI, container
# log), so it wins and the process fallback stays quiet about those
# namespaces — otherwise the same container PHP appears twice in the report.
# Two read-only queries per runtime, and the namespace id itself is read from
# /proc, not from the runtime.
_p2s_collect_runtime_ns() {
    local _rt _ids _pid _ns
    [ "$_opt_containers" -eq 1 ] || return 0
    [ -z "$_p2s_root" ] || return 0
    for _rt in docker podman; do
        command -v "$_rt" >/dev/null 2>&1 || continue
        _p2s_runtime_cmd=1
        _ids=$(_p2s_timeout 10 "$_rt" ps -q 2>/dev/null | tr -dc '0-9a-f \n') || continue
        [ -n "$_ids" ] || continue
        # One inspect for the whole list, not one per container: a host with
        # fifty containers would otherwise pay fifty process starts before the
        # first line of the report.
        # shellcheck disable=SC2086  # deliberate split, the ids are hex words
        for _pid in $(_p2s_timeout 15 "$_rt" inspect -f '{{.State.Pid}}' $_ids 2>/dev/null | tr -dc '0-9 \n'); do
            [ -n "$_pid" ] && [ "$_pid" != 0 ] || continue
            _ns=$(readlink "$_p2s_proc/$_pid/ns/mnt" 2>/dev/null | tr -dc '0-9a-z:[]')
            [ -n "$_ns" ] && _p2s_runtime_ns="$_p2s_runtime_ns$_ns "
        done
    done
}

# A container runtime is running, nothing could be asked about its containers,
# and no PHP turned up in them either. Saying nothing here is how a green run
# over an unpatched PHP happens — the shape of the 2026-10-22 measurement — so
# this says "I do not know" and costs exit code 2.
#
# Only when no docker or podman command exists at all: where one does,
# _p2s_check_containers reports its own failure to list, and a second line
# about the same gap would just be noise. --no-containers is not covered
# either, because that gap is the caller's own decision.
_p2s_check_unqueried_runtimes() {
    local _p _e _n _rt=''
    [ "$_opt_containers" -eq 1 ] || return 0
    [ "$_p2s_runtime_cmd" -eq 0 ] || return 0
    [ "$_p2s_ns_found" -eq 0 ] || return 0
    [ -z "$_p2s_root" ] || [ -n "${P2S_PROC_ROOT:-}" ] || return 0
    [ -d "$_p2s_proc" ] || return 0
    for _p in "$_p2s_proc"/[0-9]*; do
        _e=$(readlink "$_p/exe" 2>/dev/null) || continue
        _n=${_e##*/}; _n=${_n% (deleted)}
        case "$_n" in
            containerd-shim*) _rt='containerd (nerdctl, Kubernetes)' ;;
            conmon)           _rt='CRI-O or Podman (conmon)' ;;
            crio)             _rt='CRI-O' ;;
            lxc-start)        _rt='LXC or LXD' ;;
            systemd-nspawn)   _rt='systemd-nspawn' ;;
            *) continue ;;
        esac
        break
    done
    [ -n "$_rt" ] || return 0
    _p2s_add unknown container "$_rt" \
        "a $_rt container is running and there is no docker or podman command here to ask about it; no PHP was visible in its mount namespace either, so this says nothing about the PHP inside it" \
        'Run this script inside the container, or ask its runtime: nerdctl/crictl ps, kubectl exec, lxc-attach'
}

_p2s_check_binaries() {
    local _b _found=0 _rk _rp _rn _rb
    _p2s_collect_runtime_ns
    _p2s_section 'PHP installations on this host'
    for _b in "$_p2s_root"/usr/bin/php "$_p2s_root"/usr/bin/php[0-9]* \
              "$_p2s_root"/usr/sbin/php-fpm* "$_p2s_root"/usr/local/bin/php \
              "$_p2s_root"/usr/local/sbin/php-fpm "$_p2s_root"/usr/bin/lsphp* \
              "$_p2s_root"/usr/bin/php-cgi "$_p2s_root"/usr/bin/php-cgi[0-9]* \
              "$_p2s_root"/usr/lib/cgi-bin/php* "$_p2s_root"/usr/local/bin/php-cgi \
              "$_p2s_root"/usr/bin/frankenphp "$_p2s_root"/usr/local/bin/frankenphp \
              "$_p2s_root"/opt/plesk/php/*/bin/php "$_p2s_root"/opt/cpanel/ea-php*/root/usr/bin/php \
              "$_p2s_root"/opt/alt/php*/usr/bin/php "$_p2s_root"/opt/remi/php*/root/usr/bin/php \
              "$_p2s_root"/usr/local/lsws/lsphp*/bin/php; do
        _p2s_check_one_binary "$_b" && _found=1
    done
    # Second pass: whatever is actually running, wherever it lives — in this
    # root or in another one.
    while IFS='|' read -r _rk _rp _rn _rb; do
        [ -n "$_rb" ] || continue
        if [ "$_rk" = host ] && [ -f "$_rb" ]; then
            _p2s_check_one_binary "$_rb" ' (found via a running process)' && _found=1
        elif [ -f "$_p2s_proc/$_rp/root$_rb" ]; then
            # Not when the Docker/Podman check covers that namespace anyway.
            case "$_p2s_runtime_ns" in *" $_rn "*) continue ;; esac
            if _p2s_check_ns_binary "$_rp" "$_rn" "$_rb"; then
                _found=1; _p2s_ns_found=1
            fi
        fi
    done <<EOF
$(_p2s_running_php_paths)
EOF
    _p2s_check_unqueried_runtimes
    if [ "$_found" -eq 0 ]; then
        # Undecided, not clean: this says the known paths and the process list
        # hold nothing, which is not the same as "this host runs no PHP". A
        # build under /opt, a vendor bundle, a launcher under a name this
        # script does not know — all of them end up here. Until 1.6.0 this was
        # an info line, info is counted nowhere, and the run came out green.
        _p2s_add unknown php-binary 'host' 'no PHP installation found in the usual locations and none running, so this run cannot say whether this host serves PHP' \
            'If this host serves PHP from an unusual path, check that path by hand'
    fi
}

_p2s_check_fpm_pools() {
    local _f _v _u _any=0
    for _f in "$_p2s_root"/etc/php/*/fpm/pool.d/*.conf "$_p2s_root"/etc/php-fpm.d/*.conf \
              "$_p2s_root"/etc/opt/remi/php*/php-fpm.d/*.conf "$_p2s_root"/opt/plesk/php/*/etc/php-fpm.d/*.conf \
              "$_p2s_root"/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf "$_p2s_root"/usr/local/etc/php-fpm.d/*.conf; do
        [ -r "$_f" ] || continue
        [ "$_any" -eq 0 ] && _p2s_section 'PHP-FPM pools'
        _any=1
        # A pool running as root turns code execution through this bug into
        # root code execution. Worth its own line, whatever the PHP version is.
        _u=$(grep -E '^[[:space:]]*user[[:space:]]*=' "$_f" 2>/dev/null | tail -n1 | cut -d= -f2 | tr -d '[:space:]' | _p2s_clean 40)
        if [ "$_u" = root ]; then
            _p2s_add warn fpm-pool "${_f#"$_p2s_root"}" 'this pool runs as root, so code execution through this bug would be root code execution' \
                'Run the pool as its own unprivileged user, never as root'
        fi
        _v=$(grep -E '^[[:space:]]*pm\.max_requests[[:space:]]*=' "$_f" 2>/dev/null | tail -n1 | cut -d= -f2 | tr -dc '0-9')
        if [ -z "$_v" ] || [ "$_v" = 0 ]; then
            # Not one of the advisory's measures, and not presented as one:
            # recycling workers only shortens how long one keeps stale state.
            _p2s_add info fpm-pool "${_f#"$_p2s_root"}" 'pm.max_requests is unlimited, workers keep corrupted state for their whole life' \
                'A low pm.max_requests (for example 500) retires workers sooner; it is not one of the advisory measures'
        else
            _p2s_add ok fpm-pool "${_f#"$_p2s_root"}" "pm.max_requests = $_v"
        fi
        # php_admin_value / php_value in this pool. The advisory wants
        # memory_limit=-1 set exactly here, and asks to check that nothing
        # here puts a finite limit back.
        _p2s_check_forced_file "$_f" fpm "${_f#"$_p2s_root"}"
    done
}

# Which SAPI serves requests. How much the version number means depends on
# it: GHSA-6wmf-4rv5-p3rp validated the session lifecycle RCE "against mod_php
# and FPM", so both are demonstrated, and only the startup sequence of the
# first CVE is limited by FPM exiting the child. php.net names php-cgi and
# FrankenPHP under "Who is at risk" without validating either.
_p2s_sapi_note() {   # $1 = sapi, $2 = where
    case "$1" in
        mod_php)    _p2s_add warn sapi "$2" 'served by mod_php: the advisory demonstrates a complete unauthenticated exploit against exactly this setup' \
                        'Treat a vulnerable PHP behind mod_php as the most urgent case' ;;
        fpm)        _p2s_add warn sapi "$2" 'served by PHP-FPM: the advisory validated the session lifecycle RCE against mod_php and FPM alike. FPM exits the child after a failed request startup, which blocks that one sequence, not the bug' \
                        'Treat a vulnerable PHP behind FPM as urgent too, the worker exit is no fix' ;;
        cgi)        _p2s_add warn sapi "$2" 'served by php-cgi: php.net names it under "Who is at risk", the advisories validate no exploit against it' \
                        'A FastCGI process serves many requests, so judge this like FPM, not like one process per request' ;;
        litespeed)  _p2s_add info sapi "$2" 'served by LiteSpeed/LSAPI: named as affected in the advisory, not validated there' ;;
        frankenphp) _p2s_add unknown sapi "$2" 'FrankenPHP: the advisory found no equivalent early configuration consumer in its default configuration, and says explicitly that this does not make it immune' ;;
    esac
}

# Several at once is the normal case, not the exception: a Plesk host carries
# mod_php and FPM, a Debian host FPM and php-cgi. Reporting only the first
# find hid exactly the combination that decides the urgency.
_p2s_sapi_seen() {   # appends $1 to the caller's _found, once
    case " $_found " in *" $1 "*) return 0 ;; esac
    _found="$_found $1"
}

_p2s_check_sapi() {
    local _f _found='' _s
    for _f in "$_p2s_root"/etc/apache2/mods-enabled/php*.load \
              "$_p2s_root"/etc/httpd/conf.modules.d/*php*.conf \
              "$_p2s_root"/usr/local/lib/apache2/modules/libphp*.so \
              "$_p2s_root"/usr/lib/apache2/modules/libphp*.so; do
        [ -e "$_f" ] || continue
        _p2s_sapi_seen mod_php; break
    done
    for _f in "$_p2s_root"/etc/php/*/fpm/php-fpm.conf "$_p2s_root"/etc/php-fpm.conf \
              "$_p2s_root"/usr/local/etc/php-fpm.conf; do
        [ -e "$_f" ] || continue
        _p2s_sapi_seen fpm; break
    done
    # The binary alone proves nothing: on RHEL and AlmaLinux the php-cli
    # package itself installs /usr/bin/php-cgi, so a host with nothing but the
    # command line interpreter claimed to be served through CGI. Evidence is
    # the SAPI's own php.ini (Debian's php*-cgi package) or the cgi-bin wiring
    # of the web server.
    for _f in "$_p2s_root"/etc/php/*/cgi/php.ini "$_p2s_root"/usr/lib/cgi-bin/php* \
              "$_p2s_root"/var/www/cgi-bin/php*; do
        [ -e "$_f" ] || continue
        _p2s_sapi_seen cgi; break
    done
    [ -e "$_p2s_root/usr/local/lsws" ] && _p2s_sapi_seen litespeed
    for _f in "$_p2s_root"/usr/local/bin/frankenphp "$_p2s_root"/usr/bin/frankenphp; do
        [ -e "$_f" ] || continue
        _p2s_sapi_seen frankenphp; break
    done
    if [ -z "$_p2s_root" ] && command -v frankenphp >/dev/null 2>&1; then
        _p2s_sapi_seen frankenphp
    fi
    # Silence is the one answer this script never gives. A host that has PHP
    # but matches none of the patterns above gets told so, because the whole
    # urgency judgement hangs on this section.
    if [ -z "$_found" ]; then
        [ "$_p2s_seen" = ' ' ] && return 0
        _p2s_section 'How PHP is served'
        _p2s_add info sapi 'host' 'cannot tell how PHP is served: no mod_php module, PHP-FPM config, php-cgi, LiteSpeed or FrankenPHP found. A PHP that only runs on the command line is not reachable through this bug' \
            'If this host does serve web requests, judge it by the most urgent case, mod_php'
        return 0
    fi
    _p2s_section 'How PHP is served'
    for _s in $_found; do
        _p2s_sapi_note "$_s" 'host'
    done
}

_p2s_check_containers() {
    local _rt _names _c _v _img _verdict _fpm _cdeb _ccn _cini _csapi _cpkg _csrc _crest _cver _cphp
    for _rt in docker podman; do
        command -v "$_rt" >/dev/null 2>&1 || continue
        if ! _names=$(_p2s_timeout 10 "$_rt" ps --format '{{.Names}}' 2>/dev/null); then
            _p2s_section "$_rt containers"
            _p2s_add unknown container "$_rt" 'cannot list containers (run as root or as a member of the docker group)'
            continue
        fi
        _p2s_section "PHP in $_rt containers"
        _found_ct=0
        for _c in $_names; do
            _c=$(printf '%s' "$_c" | _p2s_clean 80)
            _v=$(_p2s_timeout 5 "$_rt" exec "$_c" php -r 'echo PHP_VERSION;' 2>/dev/null | head -n1 | _p2s_clean 30)
            _v=${_v%%[-+~]*}
            _cphp=1
            # Containers without php answer with an error text here, not a
            # version. A FrankenPHP image built without a php CLI is such a
            # container and still serves PHP, so ask its own binary; the PHP
            # version is the second one in that line, after FrankenPHP's own.
            if ! _p2s_is_version "$_v"; then
                _cphp=0
                _v=$(_p2s_timeout 5 "$_rt" exec "$_c" frankenphp version 2>/dev/null | head -n1 \
                     | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -n1)
                _v=${_v#PHP }
            fi
            _p2s_is_version "$_v" || continue
            _found_ct=1
            _img=$("$_rt" inspect -f '{{.Config.Image}}' "$_c" 2>/dev/null | _p2s_clean 120)
            # A Debian or Ubuntu based image carries backported fixes under an
            # unchanged upstream number, exactly like the host does. Judging
            # such a container by PHP_VERSION alone reports a patched
            # container as vulnerable.
            # Pick the installed php<branch>-common for the PHP version that
            # was just measured. dpkg-query also lists uninstalled
            # placeholders with an empty version, and the php-common meta
            # package belongs to the source php-defaults, which carries no
            # PHP version at all.
            # shellcheck disable=SC2016  # dpkg format string, expanded by dpkg
            _cdeb=$(_p2s_timeout 8 "$_rt" exec "$_c" dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${source:Package} ${Version}\n' 'php*-common' 2>/dev/null \
                    | awk -v want="php${_v%.*}-common" '$1 ~ /^ii/ && $4 != "" && $2 ~ /^php[0-9]/ {
                           if ($2 == want) { print $2, $3, $4; exit }
                           if (!first) first = $2 " " $3 " " $4
                       } END { if (first) print first }' | head -n1 | _p2s_clean 160)
            if [ -n "$_cdeb" ]; then
                _ccn=$(_p2s_timeout 8 "$_rt" exec "$_c" cat /etc/os-release 2>/dev/null \
                       | awk -F= '$1=="VERSION_CODENAME"{gsub(/"/,"",$2);print $2;exit}' | _p2s_clean 40)
                _cpkg=${_cdeb%% *}
                _crest=${_cdeb#* }
                _csrc=${_crest%% *}
                _cver=${_crest#* }
                _verdict=$(_p2s_judge_deb_data "$_ccn" "$_csrc" "$_cver" "$_v" "$_cpkg")
            else
                _verdict=$(_p2s_judge_upstream "$_v")
            fi
            _p2s_add_verdict container "$_c ($_img)" "$_verdict"
            # The ini probe needs the CLI binary. Without it the runtime
            # configuration of that container stays unchecked, and the version
            # verdict above is all this script can say about it.
            if [ "$_cphp" -eq 1 ]; then
                _p2s_check_ini "$_c (CLI)" "$_rt" exec "$_c" php
                # Debian layout inside the container: the SAPI that serves
                # requests has its own php.ini, and that is the one that counts.
                for _cini in $(_p2s_timeout 8 "$_rt" exec "$_c" sh -c 'ls /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php/*/cgi/php.ini 2>/dev/null' 2>/dev/null | _p2s_clean_lines); do
                    case "$_cini" in /etc/php/*/php.ini) ;; *) continue ;; esac
                    _csapi=${_cini%/php.ini}; _csapi=${_csapi##*/}
                    _p2s_check_ini "$_c ($_csapi)" "$_rt" exec -e "PHP_INI_SCAN_DIR=${_cini%/php.ini}/conf.d" "$_c" php -c "$_cini"
                done
            fi
            _fpm=$(_p2s_timeout 5 "$_rt" exec "$_c" sh -c 'command -v php-fpm >/dev/null 2>&1 && grep -hE "^[[:space:]]*pm\.max_requests" /usr/local/etc/php-fpm.d/*.conf 2>/dev/null | tail -n1 | cut -d= -f2' 2>/dev/null | tr -dc '0-9')
            if _p2s_timeout 5 "$_rt" exec "$_c" sh -c 'command -v php-fpm' >/dev/null 2>&1; then
                if [ -z "$_fpm" ] || [ "$_fpm" = 0 ]; then
                    _p2s_add info fpm-pool "$_c" 'pm.max_requests is unlimited' \
                        'Temporary mitigation: set a low pm.max_requests (for example 500) and reload PHP-FPM'
                fi
            fi
            # Each path on its own: "ls a b" fails as soon as one of them is
            # missing, which hid mod_php in every official apache image.
            # Every hit is printed, not just the first: an image can carry
            # mod_php and php-cgi, and the urgency hangs on the whole list.
            # cgi is decided by the SAPI's own php.ini or the cgi-bin wiring,
            # never by "command -v php-cgi": the official FrankenPHP image
            # ships a php-cgi binary that serves nothing, and that probe
            # claimed the whole container was served through it.
            # shellcheck disable=SC2016  # runs inside the container, not here
            for _csapi in $(_p2s_timeout 8 "$_rt" exec "$_c" sh -c 'for f in /etc/apache2/mods-enabled/php*.load /usr/local/lib/apache2/modules/libphp*.so /usr/lib/apache2/modules/libphp*.so /etc/httpd/conf.modules.d/*php*.conf; do
    if [ -e "$f" ]; then echo mod_php; break; fi
done
if command -v php-fpm >/dev/null 2>&1 || command -v php-fpm8 >/dev/null 2>&1; then echo fpm; fi
for f in /etc/php/*/cgi/php.ini /usr/lib/cgi-bin/php*; do
    if [ -e "$f" ]; then echo cgi; break; fi
done
if command -v frankenphp >/dev/null 2>&1; then echo frankenphp; fi' 2>/dev/null | _p2s_clean_lines); do
                _p2s_sapi_note "$_csapi" "$_c"
            done
            if [ "$_opt_logs" -eq 1 ]; then
                _p2s_count_log_hits "$_c (container log, 24 h)" "$_rt" logs --since 24h "$_c"
            fi
        done
        [ "$_found_ct" -eq 1 ] || _p2s_add info container "$_rt" 'no running container with PHP'

        # Stopped containers run no code right now, but they come back with
        # whatever their image ships. The image environment of the official
        # PHP images carries the version, so this costs no exec at all.
        for _c in $(_p2s_timeout 10 "$_rt" ps -a --filter status=exited --filter status=created \
                        --filter status=paused --format '{{.Names}}' 2>/dev/null); do
            _c=$(printf '%s' "$_c" | _p2s_clean 80)
            _img=$("$_rt" inspect -f '{{.Config.Image}}' "$_c" 2>/dev/null | _p2s_clean 120)
            _v=$(_p2s_timeout 8 "$_rt" image inspect "$_img" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
                 | awk -F= '$1=="PHP_VERSION"{print $2;exit}' | _p2s_clean 30)
            _v=${_v%%[-+~]*}
            _p2s_is_version "$_v" || continue
            _verdict=$(_p2s_judge_upstream "$_v")
            case "${_verdict%%|*}" in
                ok) _p2s_add ok container "$_c (stopped, $_img)" "image ships PHP $_v" ;;
                *)  _p2s_add warn container "$_c (stopped, $_img)" \
                        "stopped, but its image ships PHP $_v: it comes back vulnerable on the next start" \
                        'Pull the new image and recreate the container before starting it again' ;;
            esac
        done
    done
}

_p2s_check_stale_processes() {
    local _p _exe _name _comm _state _rc _stale='' _unreadable=0
    [ -d "$_p2s_proc" ] && [ "$(id -u)" -eq 0 ] || return 0
    for _p in "$_p2s_proc"/[0-9]*; do
        [ -d "$_p" ] || continue
        if ! _exe=$(readlink "$_p/exe" 2>/dev/null); then
            # Root inside a container can still lack access to workers owned
            # by another uid. Do not turn an unreadable PHP process into ok.
            _comm=$(cat "$_p/comm" 2>/dev/null | _p2s_clean 40)
            case "$_comm" in
                *php*|apache2|httpd)
                    _state=$(awk '/^State:/{print $2;exit}' "$_p/status" 2>/dev/null)
                    case "$_state" in Z|X|x) continue ;; esac
                    [ -d "$_p" ] && _unreadable=$(( _unreadable + 1 )) ;;
            esac
            continue
        fi
        case "$_exe" in
            *php*' (deleted)')
                _name=$(basename "${_exe% (deleted)}" | _p2s_clean 40) ;;
            *apache2|*httpd)
                grep -q 'libphp.*(deleted)' "$_p/maps" 2>/dev/null
                _rc=$?
                case "$_rc" in
                    0) _name="$(basename "$_exe" | _p2s_clean 40) (mod_php)" ;;
                    1) continue ;;
                    *) [ -d "$_p" ] && _unreadable=$(( _unreadable + 1 )); continue ;;
                esac ;;
            *) continue ;;
        esac
        case "$_stale" in *" $_name"*) ;; *) _stale="$_stale $_name" ;; esac
    done
    _p2s_section 'Running processes'
    if [ -n "$_stale" ]; then
        _p2s_add warn process 'host' "still running the replaced PHP binary:$_stale" \
            'PHP was updated on disk but not restarted: restart PHP-FPM and/or the web server'
    fi
    if [ "$_unreadable" -gt 0 ]; then
        _p2s_add unknown process 'host' "cannot inspect $_unreadable visible PHP/Apache processes; their restart state is unknown" \
            'Check process inspection permissions, or run inside the affected container with permission to read its workers'
    elif [ -z "$_stale" ]; then
        _p2s_add ok process 'host' 'no PHP process runs a replaced binary'
    fi
}

_p2s_check_mac() {
    local _aa _se
    _p2s_section 'Mandatory access control'
    _aa=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null | head -c 1)
    _se=$(getenforce 2>/dev/null | _p2s_clean 20)
    if [ "$_aa" = Y ]; then
        _p2s_add ok mac 'AppArmor' 'enabled (whether PHP runs confined depends on the profiles)'
    elif [ "$_se" = Enforcing ]; then
        _p2s_add ok mac 'SELinux' 'enforcing'
    else
        _p2s_add info mac 'host' 'neither AppArmor nor SELinux is active' \
            'The advisory lists AppArmor/SELinux confinement as a damage limiter, not as a fix'
    fi
}

_p2s_listen_public=0
_p2s_check_exposure() {
    local _l
    command -v ss >/dev/null 2>&1 || return 0
    _p2s_section 'Network exposure'
    _l=$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -E '^(0\.0\.0\.0|\*|\[::\]|::):(80|443)$' | tr '\n' ' ' | _p2s_clean 80)
    if [ -n "$_l" ]; then
        _p2s_listen_public=1
        _p2s_add info exposure 'host' "web ports listen on all interfaces: $_l"
    else
        _p2s_add ok exposure 'host' 'no web port listens on all interfaces (loopback, tunnel or overlay only)'
    fi
    if pgrep -x cloudflared >/dev/null 2>&1; then
        _p2s_add info exposure 'cloudflared' 'Cloudflare Tunnel is running; traffic through it passes the Cloudflare WAF'
    fi
}

# _p2s_count_log_hits TARGET cmd... (cmd prints the log)
_p2s_count_log_hits() {
    local _tg=$1 _n
    shift
    _n=$(_p2s_timeout 15 "$@" 2>&1 | tail -n 200000 | grep -c 'Allowed memory size of')
    _n=${_n:-0}
    if [ "$_n" -ge 20 ]; then
        _p2s_add warn log-indicator "$_tg" "$_n memory-limit fatal errors (this is the trigger condition of CVE-2026-109618)" \
            'Look for bursts of large or deeply nested POST requests from single IPs in the access log'
    elif [ "$_n" -gt 0 ]; then
        _p2s_add info log-indicator "$_tg" "$_n memory-limit fatal errors (usually an application problem, listed for completeness)"
    else
        _p2s_add ok log-indicator "$_tg" 'no memory-limit fatal errors'
    fi
}

_p2s_check_logs() {
    local _f _count=0
    _p2s_section 'Log indicators (memory-limit fatals, current log files only)'
    for _f in "$_p2s_root"/var/log/apache2/error.log "$_p2s_root"/var/log/httpd/error_log \
              "$_p2s_root"/var/log/nginx/error.log "$_p2s_root"/var/log/php*-fpm.log \
              "$_p2s_root"/var/log/php-fpm/*.log "$_p2s_root"/var/www/vhosts/system/*/logs/error_log \
              "$_p2s_root"/usr/local/apache/logs/error_log "$_p2s_root"/usr/local/lsws/logs/error.log; do
        [ -r "$_f" ] || continue
        _count=$(( _count + 1 ))
        [ "$_count" -le 50 ] || break
        _p2s_count_log_hits "${_f#"$_p2s_root"}" cat "$_f"
    done
    [ "$_count" -gt 0 ] || _p2s_add info log-indicator 'host' 'no known PHP or web server error log found'
}

# ---------------------------------------------------------------------------
# Remote checks
# ---------------------------------------------------------------------------

_p2s_ip4_in_cidr() {   # ip cidr
    local _ip=$1 _net=${2%/*} _bits=${2#*/} _a _b _c _d _i _n _mask
    IFS=. read -r _a _b _c _d <<EOF
$_ip
EOF
    _i=$(( (_a << 24) + (_b << 16) + (_c << 8) + _d ))
    IFS=. read -r _a _b _c _d <<EOF
$_net
EOF
    _n=$(( (_a << 24) + (_b << 16) + (_c << 8) + _d ))
    _mask=$(( (0xFFFFFFFF << (32 - _bits)) & 0xFFFFFFFF ))
    [ $(( _i & _mask )) -eq $(( _n & _mask )) ]
}

_p2s_is_cloudflare_ip() {
    local _ip _r
    _ip=$(printf '%s' "$1" | _p2s_lower)
    if [[ "$_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        for _r in $_p2s_cf_v4; do _p2s_ip4_in_cidr "$_ip" "$_r" && return 0; done
    else
        for _r in $_p2s_cf_v6; do
            case "$_r" in
                2a06:98c) [[ "$_ip" =~ ^2a06:98c[0-7] ]] && return 0 ;;
                *) case "$_ip" in "$_r"*) return 0 ;; esac ;;
            esac
        done
    fi
    return 1
}

_p2s_resolve() {   # host -> one IP per line
    local _h=$1
    if [[ "$_h" =~ ^[0-9.]+$ ]] || [[ "$_h" =~ : ]]; then echo "$_h"; return; fi
    {
        if command -v dig >/dev/null 2>&1; then
            dig +short +time=3 +tries=1 A "$_h"; dig +short +time=3 +tries=1 AAAA "$_h"
        elif command -v getent >/dev/null 2>&1; then
            getent ahosts "$_h" | awk '{print $1}'
        elif command -v host >/dev/null 2>&1; then
            host "$_h" | awk '/has (IPv6 )?address/{print $NF}'
        fi
    } 2>/dev/null | grep -E '^[0-9a-fA-F.:]+$' | sort -u | head -n 8
}

# Characters allowed in a URL we pass on to curl (never to a shell).
_p2s_clean_url() { tr -dc 'A-Za-z0-9._~:/?#@!$&()*+,;=%[]-' | head -c "${1:-500}"; }

_p2s_host_of() {   # URL -> lower-case host without port or brackets
    local _h=${1#*://}
    _h=${_h%%/*}; _h=${_h%%\?*}; _h=${_h%%#*}; _h=${_h##*@}
    case "$_h" in \[*) _h=${_h#[}; _h=${_h%%]*} ;; *) _h=${_h%%:*} ;; esac
    printf '%s' "$_h" | _p2s_lower
}

_p2s_same_site() {   # host A, host B: equal or one is the www. variant of the other
    [ "$1" = "$2" ] || [ "www.$1" = "$2" ] || [ "$1" = "www.$2" ]
}

# curl exit code -> short reason for the report.
_p2s_curl_reason() {
    case "$1" in
        6)        echo 'the name does not resolve (DNS)' ;;
        7)        echo 'connection refused' ;;
        28)       echo 'connection timed out' ;;
        35)       echo 'TLS handshake failed (often: no certificate for this name on the server)' ;;
        51|60)    echo 'TLS certificate is not valid for this name' ;;
        52)       echo 'the server closed the connection without an answer' ;;
        56)       echo 'connection reset' ;;
        *)        echo "connection failed (curl exit $1)" ;;
    esac
}

# GET the URL, following redirects only while they stay on the named host.
# Sets _p2s_f_hdr (headers of all hops), _p2s_f_foreign (host of a redirect
# that was not followed), _p2s_f_access (1 if it pointed to Cloudflare
# Access), _p2s_f_err (reason when nothing answered), _p2s_f_badcert (1 when
# the certificate did not match and the headers were read without
# verification), _p2s_f_http (reason when HTTPS failed and plain HTTP was
# used instead; only for URLs given without a scheme), and _p2s_f_last /
# _p2s_f_lasthost (headers and host of the hop that answered last).
_p2s_fetch() {
    local _cur=$1 _host=$2 _ua=$3 _auto=${4:-0} _hop=0 _out _rc _next _nh _k=''
    _p2s_f_hdr=''; _p2s_f_foreign=''; _p2s_f_access=0
    _p2s_f_err=''; _p2s_f_badcert=0; _p2s_f_http=''; _p2s_f_last=''; _p2s_f_lasthost=$_host
    while [ "$_hop" -le 7 ]; do
        _hop=$(( _hop + 1 ))
        _out=$(curl -sS -o /dev/null -D - -w '\n__p2s_next__ %{redirect_url}\n' $_k \
                    --connect-timeout 8 --max-time 15 -A "$_ua" "$_cur" 2>/dev/null)
        _rc=$?
        if [ "$_rc" -ne 0 ] && ! printf '%s\n' "$_out" | grep -qE '^HTTP/'; then
            # A wrong certificate does not stop the check: the headers are
            # read anyway, and the certificate problem is reported.
            if { [ "$_rc" -eq 60 ] || [ "$_rc" -eq 51 ]; } && [ -z "$_k" ]; then
                _k='-k'; _p2s_f_badcert=1; continue
            fi
            # Given without a scheme and HTTPS does not work: try plain HTTP
            # on the same host once.
            if [ "$_auto" -eq 1 ] && [ -z "$_p2s_f_http" ] && [ -z "$_p2s_f_hdr" ]; then
                case "$_cur" in
                    https://*) _p2s_f_http=$(_p2s_curl_reason "$_rc"); _cur="http://${_cur#https://}"; continue ;;
                esac
            fi
            _p2s_f_err=$(_p2s_curl_reason "$_rc")
            break
        fi
        _out=$(printf '%s\n' "$_out" | tr -d '\r')
        _p2s_f_last=$(printf '%s\n' "$_out" | grep -v '^__p2s_next__' | _p2s_lower | _p2s_clean_lines)
        _p2s_f_lasthost=$(_p2s_host_of "$_cur")
        _p2s_f_hdr="$_p2s_f_hdr
$_p2s_f_last"
        _next=$(printf '%s\n' "$_out" | grep '^__p2s_next__' | tail -n1 | cut -d' ' -f2- | _p2s_clean_url)
        [ -n "$_next" ] || break
        _nh=$(_p2s_host_of "$_next")
        case "$_nh" in
            *.cloudflareaccess.com) _p2s_f_access=1; break ;;
        esac
        if _p2s_same_site "$_host" "$_nh"; then
            _cur=$_next
        else
            _p2s_f_foreign=$(printf '%s' "$_nh" | _p2s_clean 120)
            break
        fi
    done
}

_p2s_check_url() {
    local _url=$1 _host _hdr _code _phpv _verdict _edge='' _ips _ip _cf_ip=0 _non_cf=0 _srv _ua _o _auto=0 _blocked=0 _ehdr _ehost _sig
    case "$_url" in http://*|https://*) ;; *) _url="https://$_url"; _auto=1 ;; esac
    _url=$(printf '%s' "$_url" | _p2s_clean_url 300)
    _host=$(_p2s_host_of "$_url")
    _p2s_section "Website $_url"
    _ua="php2shell-check/$P2S_SCRIPT_VERSION (+$P2S_REPO_URL)"

    if ! command -v curl >/dev/null 2>&1; then
        _p2s_add unknown remote "$_url" 'curl is not installed, remote checks skipped'
        return
    fi
    _p2s_fetch "$_url" "$_host" "$_ua" "$_auto"
    _hdr=$_p2s_f_hdr
    _code=$(printf '%s\n' "$_hdr" | grep -E '^http/' | tail -n1 | awk '{print $2}')
    if [ -z "$_code" ]; then
        _p2s_urls_seen=$(( _p2s_urls_seen + 1 )); _p2s_urls_open=$(( _p2s_urls_open + 1 ))
        _p2s_add unknown remote "$_url" "no HTTP answer: ${_p2s_f_err:-unknown error}${_p2s_f_http:+ (HTTPS: $_p2s_f_http)}" \
            'Run this script on the server itself: a site that does not answer cannot be judged from outside'
        return
    fi
    _p2s_add info remote "$_url" "reachable, last HTTP status ${_code:-?}"
    if [ -n "$_p2s_f_http" ]; then
        _p2s_add info tls "$_url" "HTTPS did not work ($_p2s_f_http), checked over plain HTTP"
    fi
    if [ "$_p2s_f_badcert" -eq 1 ]; then
        _p2s_add info tls "$_url" 'the TLS certificate is not valid for this name; headers were read without verification'
    fi
    # Cloudflare (or another edge) answering with a block or challenge page
    # means the application's own headers never reached us.
    case "$_code" in
        403|429|503)
            if printf '%s\n' "$_p2s_f_last" | grep -qE '^cf-mitigated:|^server: *cloudflare' \
               && ! printf '%s\n' "$_p2s_f_last" | grep -qE '^x-powered-by:'; then
                _blocked=1
                _p2s_add info blocked "$_url" "Cloudflare answered with a block or challenge page (HTTP $_code): the site's own headers are not visible, so the PHP banner check says nothing here" \
                    'For sites behind a challenge, run the script on the server itself'
            fi ;;
    esac
    if [ "$_p2s_f_access" -eq 1 ]; then
        _p2s_add ok access "$_url" 'redirects to a Cloudflare Access login: requests without a login stop at Cloudflare, before PHP'
    fi
    if [ -n "$_p2s_f_foreign" ]; then
        _p2s_add info redirect "$_url" "redirects to $_p2s_f_foreign; not followed, only the host you named is checked" \
            'Run the check again with the target URL if that site is yours'
    fi

    # Does the site run PHP at all? Signals that cost no extra request. They
    # say "PHP is here", never which version, so they can only ever turn a
    # silent result into a clearer one.
    _sig=''
    printf '%s\n' "$_hdr" | grep -qE '^set-cookie: *phpsessid=' && _sig="$_sig PHPSESSID cookie,"
    printf '%s\n' "$_hdr" | grep -qE '^x-powered-by: *php' && _sig="$_sig X-Powered-By,"
    printf '%s\n' "$_hdr" | grep -qE '^x-powered-by: *plesklin' && _sig="$_sig Plesk,"
    printf '%s\n' "$_hdr" | grep -qE '^link:.*wp-json|^x-pingback:' && _sig="$_sig WordPress,"
    printf '%s\n' "$_hdr" | grep -qE '^set-cookie: *(laravel_session|xsrf-token)=' && _sig="$_sig Laravel,"
    printf '%s\n' "$_hdr" | grep -qE '^x-drupal-|^x-generator: *drupal' && _sig="$_sig Drupal,"
    printf '%s\n' "$_hdr" | grep -qE '^x-litespeed-cache|^x-turbo-charged-by: *litespeed' && _sig="$_sig LiteSpeed cache,"
    _sig=${_sig%,}

    # PHP version banner (expose_php).
    _phpv=$(printf '%s\n' "$_hdr" | grep -oE 'php/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d/ -f2)
    _p2s_urls_seen=$(( _p2s_urls_seen + 1 ))
    if [ -n "$_phpv" ]; then
        case "$_p2s_frozen_versions" in
            *" $_phpv "*)
                _p2s_urls_open=$(( _p2s_urls_open + 1 ))
                _p2s_add unknown php-banner "$_url" "announces PHP $_phpv, a version number that distributions keep while backporting the fix, so it cannot be judged from outside" \
                    'Run this script on the server itself: there the package version gives a definite answer' ;;
            *)
                _verdict=$(_p2s_judge_upstream "$_phpv")
                case "${_verdict%%|*}" in
                    ok)
                        # A header that announces a fixed version is not a
                        # verdict. X-Powered-By is set by whoever configures
                        # the server: header() in the application, add_header
                        # in nginx, a cache, or a proxy with a different PHP
                        # behind it. Until 1.6.0 this branch answered
                        # "[OK] php-banner" plus "NO VULNERABLE PHP FOUND"
                        # with exit 0, while the prose in the same output said
                        # the run cannot confirm a patch level. The prose was
                        # right and the exit code was wrong, and a pipeline
                        # reads the exit code. A version BELOW the fix stays a
                        # finding: if that header lies, it only costs a look.
                        _p2s_urls_open=$(( _p2s_urls_open + 1 ))
                        _p2s_add unknown php-banner "$_url" "announces PHP $_phpv, which is patched — but a header is self-declared and can be set by the application, a cache or a proxy, so this does not confirm what runs behind it" \
                            'Run this script on the server itself: there the package version gives a definite answer' ;;
                    *)
                        case "${_verdict%%|*}" in unknown) _p2s_urls_open=$(( _p2s_urls_open + 1 )) ;; esac
                        _p2s_add_verdict php-banner "$_url" "${_verdict%%|*}|X-Powered-By: $(printf '%s' "$_verdict" | cut -d'|' -f2-)" ;;
                esac ;;
        esac
        _p2s_add warn disclosure "$_url" "the PHP version is visible to everyone (X-Powered-By: PHP/$_phpv)" \
            'Set expose_php=0 so scanners cannot pick vulnerable targets by header'
    else
        # No version in the headers is not a clean bill of health, and must not
        # look like one: this stays undecided.
        _p2s_urls_open=$(( _p2s_urls_open + 1 ))
        if [ "$_blocked" -eq 1 ]; then
            _p2s_add unknown php-level "$_url" 'the edge answered instead of the site, so no version is visible' \
                'Run this script on the server itself: there the package and container versions give a definite answer'
        elif [ -n "$_sig" ]; then
            _p2s_add unknown php-level "$_url" "runs PHP (signal:$_sig) but does not reveal the version, so the patch level cannot be judged from outside" \
                'Run this script on the server itself: there the package and container versions give a definite answer'
        else
            _p2s_add unknown php-level "$_url" 'no PHP version and no PHP signal in the headers; this says nothing about the patch level' \
                'Run this script on the server itself: there the package and container versions give a definite answer'
        fi
        [ "$_blocked" -eq 1 ] || _p2s_add ok disclosure "$_url" 'the response headers do not reveal the PHP version'
    fi

    # Edge / WAF detection describes the host that answered last: a
    # Cloudflare-proxied apex that redirects to an unproxied www. host must not
    # count as protected (seen in the wild).
    _ehdr=$_p2s_f_last; _ehost=$_p2s_f_lasthost
    if [ "$_ehost" != "$_host" ]; then
        _p2s_add info redirect "$_url" "redirects to $_ehost (same site, followed); the WAF and DNS checks below describe $_ehost"
    fi
    _srv=$(printf '%s\n' "$_ehdr" | grep -E '^server:' | tail -n1 | cut -d: -f2- | _p2s_clean 60)
    printf '%s\n' "$_ehdr" | grep -qE '^cf-ray:|^server: *cloudflare' && _edge='Cloudflare'
    [ -z "$_edge" ] && printf '%s\n' "$_ehdr" | grep -qE '^x-sucuri-id:|^server: *sucuri' && _edge='Sucuri'
    [ -z "$_edge" ] && printf '%s\n' "$_ehdr" | grep -qE '^x-iinfo:|^x-cdn: *imperva' && _edge='Imperva'
    [ -z "$_edge" ] && printf '%s\n' "$_ehdr" | grep -qE '^x-amz-cf-id:' && _edge='Amazon CloudFront'
    [ -z "$_edge" ] && printf '%s\n' "$_ehdr" | grep -qE '^x-azure-ref:' && _edge='Azure Front Door'
    [ -z "$_edge" ] && printf '%s\n' "$_ehdr" | grep -qE '^server: *akamai|^x-akamai' && _edge='Akamai'
    [ -z "$_edge" ] && printf '%s\n' "$_ehdr" | grep -qE '^x-fastly|^x-served-by: *cache-' && _edge='Fastly'
    [ -z "$_edge" ] && printf '%s\n' "$_ehdr" | grep -qE '^server: *bunnycdn' && _edge='BunnyCDN'

    # DNS: do the names point at Cloudflare's edge?
    _ips=$(_p2s_resolve "$_ehost")
    for _ip in $_ips; do
        if _p2s_is_cloudflare_ip "$_ip"; then _cf_ip=1; else _non_cf=1; fi
    done

    case "$_edge" in
        Cloudflare)
            if [ "$_cf_ip" -eq 1 ] && [ "$_non_cf" -eq 0 ]; then
                _p2s_add ok waf "$_url" "proxied through Cloudflare (header and DNS); Cloudflare says it has deployed WAF rules for these CVEs on all plans, Free included" \
                    'Keep the Cloudflare Managed/Free ruleset enabled and make sure the origin only accepts Cloudflare (tunnel or firewall)'
            elif [ "$_non_cf" -eq 1 ] && [ "$_cf_ip" -eq 1 ]; then
                _p2s_add warn waf "$_url" "Cloudflare answered, but $_ehost also resolves to non-Cloudflare addresses ($(printf '%s' "$_ips" | tr '\n' ' ' | _p2s_clean 120))" \
                    'Every DNS record of the site should be proxied (orange cloud), otherwise part of the traffic skips the WAF'
            else
                _p2s_add ok waf "$_url" 'Cloudflare headers present (DNS could not be confirmed from here)' \
                    'Keep the Cloudflare Managed/Free ruleset enabled and make sure the origin only accepts Cloudflare (tunnel or firewall)'
            fi ;;
        '')
            if [ "$_cf_ip" -eq 1 ]; then
                _p2s_add unknown waf "$_url" "$_ehost resolves to Cloudflare, but the response carried no Cloudflare headers"
            else
                _p2s_add info waf "$_url" "no WAF or CDN detected${_srv:+ (server:$_srv)}: requests reach the server unfiltered" \
                    'If you cannot patch today, put the site behind a WAF that has rules for CVE-2026-109618/109619'
            fi ;;
        *)
            _p2s_add info waf "$_url" "behind $_edge. Whether it filters these CVEs is not visible from outside" \
                "Ask $_edge whether rules for CVE-2026-109618/109619 are active for your property" ;;
    esac
    # The first hop came through Cloudflare, the host that actually serves the
    # site did not: protection on the apex only.
    if [ "$_ehost" != "$_host" ] && [ "$_edge" != Cloudflare ] \
       && printf '%s\n' "$_hdr" | grep -qE '^cf-ray:|^server: *cloudflare'; then
        _p2s_add warn waf "$_url" "only $_host goes through Cloudflare; $_ehost, which serves the site, does not" \
            "Proxy the DNS record of $_ehost through Cloudflare as well (orange cloud)"
    fi
    case "$_srv" in
        *litespeed*) _p2s_add info server "$_url" 'LiteSpeed detected: LSAPI is named as affected in the advisory' ;;
        *frankenphp*|*caddy*) _p2s_add info server "$_url" 'Caddy/FrankenPHP detected: the advisory lists FrankenPHP as unclear' ;;
    esac

    # Can the origin be reached directly, past the proxy?
    if [ -n "$_opt_origin" ]; then
        _o=$(printf '%s' "$_opt_origin" | tr -dc '0-9a-fA-F.:')
        if curl -sS -o /dev/null -k --max-time 10 -A "$_ua" \
                --resolve "$_host:443:$_o" --resolve "$_host:80:$_o" "$_url" 2>/dev/null; then
            _p2s_add warn origin "$_url" "the origin $_o answers directly; anyone who knows the address can bypass the proxy and its WAF" \
                'Allow 80/443 on the origin only from the proxy (Cloudflare IP ranges) or publish it through a tunnel'
        else
            _p2s_add ok origin "$_url" "the origin $_o does not answer directly from here"
        fi
    fi
    [ "$_edge" = Cloudflare ] && _p2s_behind_cf=1
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Test hook: tests/run_tests.sh sources the script to call single functions.
if [ "${P2S_SOURCE_ONLY:-0}" = 1 ]; then
    # shellcheck disable=SC2317  # reached when executed instead of sourced
    return 0 2>/dev/null || exit 0
fi

_p2s_behind_cf=0
_p2s_urls_seen=0
_p2s_urls_open=0
_p2s_local_ran=0
_found_ct=0
_p2s_hostname=$( (hostname -f 2>/dev/null || hostname) | _p2s_clean 80)
_p2s_os=$(_p2s_os_field PRETTY_NAME | _p2s_clean 80)
[ -n "$_p2s_os" ] || _p2s_os=$(uname -s 2>/dev/null | _p2s_clean 40)

if [ "$_opt_json" -eq 0 ] && [ "$_opt_quiet" -eq 0 ]; then
    printf '%sphp2shell-check %s%s  CVE-2026-109618 / CVE-2026-109619, data as of %s\n' "$_c_bold" "$P2S_SCRIPT_VERSION" "$_c_off" "$P2S_DATA_DATE"
    printf '%s%s (%s)%s\n' "$_c_dim" "$_p2s_hostname" "$_p2s_os" "$_c_off"
fi

if [ "$_opt_remote_only" -eq 0 ]; then
    if [ "$(uname -s)" != Linux ] && [ -z "$_p2s_root" ]; then
        _p2s_section 'Local checks'
        _p2s_add info local "$_p2s_hostname" 'not a Linux host, local checks skipped (use --remote-only for websites)'
    else
        if [ "$(id -u)" -ne 0 ] && [ -z "$_p2s_root" ]; then
            _p2s_section 'Privileges'
            _p2s_add unknown privileges "$_p2s_hostname" 'not running as root: containers, processes and some logs may be invisible' \
                'Run again with sudo for a complete result'
        fi
        _p2s_local_ran=1
        _p2s_check_binaries
        _p2s_check_sapi
        _p2s_check_fpm_pools
        _p2s_check_vhost_overrides
        _p2s_check_rlimits
        [ "$_opt_containers" -eq 1 ] && [ -z "$_p2s_root" ] && _p2s_check_containers
        if [ -z "$_p2s_root" ]; then
            _p2s_check_stale_processes
            _p2s_check_mac
            _p2s_check_exposure
        fi
        [ "$_opt_logs" -eq 1 ] && _p2s_check_logs
    fi
fi

for _u in ${_p2s_urls[@]+"${_p2s_urls[@]}"}; do
    _p2s_check_url "$_u"
done

if [ "$_p2s_behind_cf" -eq 1 ] && [ "$_p2s_listen_public" -eq 1 ] && [ -z "$_opt_origin" ]; then
    _p2s_section 'Origin'
    # The script cannot tell whether this host is the origin of the URL.
    _p2s_add info origin "$_p2s_hostname" 'if this host is the origin of a Cloudflare site above: it serves 80/443 on all interfaces, so the WAF can be bypassed by anyone who knows its IP' \
        'On a Cloudflare origin, allow 80/443 only from Cloudflare IP ranges, or test with --origin <public IP>'
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

_n_vuln=0; _n_unknown=0; _n_warn=0; _n_ok=0
# How many PHP runtimes this run actually judged. Counting statuses alone
# cannot answer that: a host with no PHP still collects ok lines from the
# AppArmor and process checks and therefore looks examined. Only the three
# checks that judge a PHP runtime count, and only when they reached a verdict.
_n_judged=0
_i=0
while [ "$_i" -lt "${#_f_status[@]}" ]; do
    case "${_f_status[$_i]}" in
        vuln) _n_vuln=$(( _n_vuln + 1 )) ;;
        unknown) _n_unknown=$(( _n_unknown + 1 )) ;;
        warn) _n_warn=$(( _n_warn + 1 )) ;;
        ok) _n_ok=$(( _n_ok + 1 )) ;;
    esac
    case "${_f_check[$_i]}" in
        php-binary|container|php-banner)
            case "${_f_status[$_i]}" in
                vuln|unknown|ok) _n_judged=$(( _n_judged + 1 )) ;;
            esac ;;
    esac
    _i=$(( _i + 1 ))
done
# A run that judged no PHP at all is not a clean run. Until 1.6.0 the lines
# that say "there was nothing here to look at" were info, info is counted
# nowhere, and the result came out "NO VULNERABLE PHP FOUND" with exit 0 —
# measured on a macOS host, where the local checks cannot run in the first
# place: "0 vulnerable, 0 undecided, 0 warnings, 0 ok", exit 0. Silence is not
# a verdict.
if [ "$_n_vuln" -gt 0 ]; then _p2s_result=vulnerable; _p2s_rc=1
elif [ "$_n_unknown" -gt 0 ] || [ "$_n_judged" -eq 0 ]; then _p2s_result=undecided; _p2s_rc=2
else _p2s_result=not-vulnerable; _p2s_rc=0
fi

if [ "$_opt_json" -eq 1 ]; then
    printf '{"tool":"php2shell-check","version":"%s","data_as_of":"%s","advisory":"%s",' "$P2S_SCRIPT_VERSION" "$P2S_DATA_DATE" "$P2S_ADVISORY"
    printf '"host":"%s","os":"%s","result":"%s",' "$(_p2s_json_esc "$_p2s_hostname")" "$(_p2s_json_esc "$_p2s_os")" "$_p2s_result"
    printf '"scope":{"host_checked":%s,"as_root":%s,"urls_checked":%d,"urls_undecided":%d},' \
        "$( [ "$_p2s_local_ran" -eq 1 ] && echo true || echo false )" \
        "$( [ "$(id -u)" -eq 0 ] && echo true || echo false )" "$_p2s_urls_seen" "$_p2s_urls_open"
    printf '"counts":{"vulnerable":%d,"undecided":%d,"warning":%d,"ok":%d},"findings":[' "$_n_vuln" "$_n_unknown" "$_n_warn" "$_n_ok"
    _i=0
    while [ "$_i" -lt "${#_f_status[@]}" ]; do
        [ "$_i" -gt 0 ] && printf ','
        printf '{"status":"%s","check":"%s","target":"%s","detail":"%s"}' \
            "${_f_status[$_i]}" "${_f_check[$_i]}" "$(_p2s_json_esc "${_f_target[$_i]}")" "$(_p2s_json_esc "${_f_detail[$_i]}")"
        _i=$(( _i + 1 ))
    done
    printf ']}\n'
    exit "$_p2s_rc"
fi

printf '\n%sSummary%s  %d vulnerable, %d undecided, %d warnings, %d ok\n' "$_c_bold" "$_c_off" "$_n_vuln" "$_n_unknown" "$_n_warn" "$_n_ok"
case "$_p2s_result" in
    vulnerable)     printf '  %sVULNERABLE%s  at least one PHP runtime needs an update now.\n' "$_c_red" "$_c_off" ;;
    undecided)
        if [ "$_n_judged" -eq 0 ]; then
            printf '  %sUNDECIDED%s   this run judged no PHP runtime at all, so it says nothing\n' "$_c_yel" "$_c_off"
            printf '              about this host. See the lines above for what stopped it.\n'
        else
            printf '  %sUNDECIDED%s   some results could not be judged, see the ?? lines.\n' "$_c_yel" "$_c_off"
        fi ;;
    not-vulnerable) printf '  %sNO VULNERABLE PHP FOUND%s  in what this script can see.\n' "$_c_grn" "$_c_off" ;;
esac

# What the verdict above is worth. A run on the server reads the real
# versions; from outside only what a site chooses to reveal is visible.
printf '\n%sHow reliable this is%s\n' "$_c_bold" "$_c_off"
if [ "$_p2s_local_ran" -eq 1 ]; then
    printf '  Ran on this host: the package and container versions above are read\n'
    printf '  from the system itself. That is the definite answer for this server.\n'
    if [ "$(id -u)" -ne 0 ] && [ -z "$_p2s_root" ]; then
        printf '  %sNot run as root, so containers and other users processes stayed hidden.%s\n' "$_c_yel" "$_c_off"
    fi
else
    printf '  Websites only. From outside, a site shows at most the version it\n'
    printf '  chooses to reveal, so this run cannot confirm a patch level.\n'
    printf '  %sFor a definite answer, run this script on the server that hosts the site:%s\n' "$_c_bold" "$_c_off"
    printf '    sudo bash php2shell-check.sh\n'
fi
if [ "$_p2s_urls_seen" -gt 0 ] && [ "$_p2s_urls_open" -gt 0 ]; then
    printf '  %d of %d websites could not be judged from outside.\n' "$_p2s_urls_open" "$_p2s_urls_seen"
fi
_p2s_hints="$_p2s_hints_1$_p2s_hints_2$_p2s_hints_3"
if [ -n "$_p2s_hints" ]; then
    printf '\n%sNext steps%s\n' "$_c_bold" "$_c_off"
    printf '%s\n' "$_p2s_hints" | tr '|' '\n' | grep -v '^$' | awk '!s[$0]++' | head -n 10 | sed 's/^/  - /'
fi
printf '\n%sAdvisory:   %s\nTool:       %s\nBackground: %s (German)\n            provided as is, without warranty or support (MIT, see LICENSE)%s\n' \
    "$_c_dim" "$P2S_ADVISORY_URL" "$P2S_REPO_URL" "$P2S_INFO_URL" "$_c_off"
exit "$_p2s_rc"
