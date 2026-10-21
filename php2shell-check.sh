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
# checks send one ordinary GET request per URL and resolve its DNS name.
#
# Compatible with bash 3.2 (macOS) for --remote-only; local checks need Linux.

set -u
export LC_ALL=C

P2S_SCRIPT_VERSION='1.0.0'
P2S_DATA_DATE='2026-10-21'
P2S_ADVISORY='GHSA-w8hw-w9fx-j79w'
P2S_ADVISORY_URL='https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'
P2S_REPO_URL='https://github.com/EXT-IT/php2shell-check'

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
        trixie:php8.4)   echo '8.4.27-1~deb13u1' ;;         # Debian 13, DSA-6574-1
        bookworm:php8.2) echo unfixed ;;                    # Debian 12
        *)               echo none ;;
    esac
}

# Upstream numbers that distributions freeze. A remote banner showing one of
# these may belong to a patched backport build, so it cannot be judged.
_p2s_frozen_versions=' 7.4.3 7.4.33 8.1.2 8.3.6 8.5.4 '

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

Run it on the server (as root) to check every PHP installation and container.
Add URLs to also check what the sites reveal and whether a WAF sits in front.

Options:
  -r, --remote-only    only check the given URLs (works without root, on macOS)
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

if [ "$_opt_remote_only" -eq 1 ] && [ "${#_p2s_urls[@]}" -eq 0 ]; then
    echo "php2shell-check: --remote-only needs at least one URL" >&2
    exit 3
fi
[ -n "${NO_COLOR:-}" ] && _opt_color=0
[ -t 1 ] || _opt_color=0
[ "$_opt_json" -eq 1 ] && _opt_color=0

# Test hook: prefix for every scanned path. Not for normal use.
_p2s_root=${P2S_TEST_ROOT:-}

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

# Verdict for a Debian/Ubuntu package. Prints "status|detail|hint".
_p2s_judge_deb() {
    local _pkg=$1 _v=$2 _pv _src _up _fixed _dfixed _cn
    _pv=$(dpkg-query -W -f='${Version}' "$_pkg" 2>/dev/null | _p2s_clean 60)
    _src=$(dpkg-query -W -f='${source:Package}' "$_pkg" 2>/dev/null | _p2s_clean 40)
    _cn=$(_p2s_os_field VERSION_CODENAME)
    _up=${_pv#*:}; _up=${_up%%[-+~]*}
    _fixed=$(_p2s_upstream_fixed "${_v%.*}")
    _dfixed=$(_p2s_distro_fixed "$_cn:$_src")
    if [ "$_fixed" != none ] && [ "$_fixed" != unknown ] && _p2s_is_version "$_up" && _p2s_ver_ge "$_up" "$_fixed"; then
        echo "ok|package $_pkg $_pv (upstream $_up)|"
    elif [ "$_dfixed" = unfixed ]; then
        echo "vuln|package $_pkg $_pv, the distribution has not published a fix yet|Apply the temporary mitigations below and watch the distribution's security tracker"
    elif [ "$_dfixed" != none ]; then
        if dpkg --compare-versions "$_pv" ge "$_dfixed"; then
            echo "ok|package $_pkg $_pv (distribution fix from $_dfixed)|"
        else
            echo "vuln|package $_pkg $_pv, fixed in $_dfixed|apt-get update && apt-get install --only-upgrade $_pkg, then restart PHP-FPM / the web server"
        fi
    else
        echo "unknown|package $_pkg $_pv, no fix data for ${_cn:-this release}|Install security updates and compare with the distribution's advisory for CVE-2026-109618"
    fi
}

# Verdict for an RPM package. Prints "status|detail|hint".
_p2s_judge_rpm() {
    local _file=$1 _v=$2 _pkg _vendor _fixed
    _pkg=$(rpm -qf --qf '%{NAME}-%{VERSION}-%{RELEASE}' "$_file" 2>/dev/null | head -n1 | _p2s_clean 80)
    _vendor=$(rpm -qf --qf '%{VENDOR}' "$_file" 2>/dev/null | head -n1 | _p2s_clean 60)
    _fixed=$(_p2s_upstream_fixed "${_v%.*}")
    if [ "$_fixed" != none ] && [ "$_fixed" != unknown ] && _p2s_ver_ge "$_v" "$_fixed"; then
        echo "ok|package $_pkg|"
    elif printf '%s' "$_vendor" | grep -qi remi; then
        echo "vuln|package $_pkg (Remi ships upstream versions)|dnf upgrade 'php*' and restart PHP-FPM / the web server"
    else
        echo "unknown|package $_pkg ($_vendor), RPM distributions may backport the fix|dnf upgrade, then compare with the vendor's advisory for CVE-2026-109618"
    fi
}

_p2s_add_verdict() {   # _p2s_add_verdict CHECK TARGET "status|detail|hint"
    local _st _dt _hn _rest
    _st=${3%%|*}; _rest=${3#*|}; _dt=${_rest%%|*}; _hn=${_rest#*|}
    _p2s_add "$_st" "$1" "$2" "$_dt" "$_hn"
}

# ---------------------------------------------------------------------------
# Runtime configuration (temporary mitigations from the advisory)
# ---------------------------------------------------------------------------

# shellcheck disable=SC2016  # PHP code, $k and $v belong to PHP
_P2S_INI_CODE='foreach (["memory_limit","post_max_size","max_input_nesting_level","session.upload_progress.enabled","expose_php","fatal_error_backtraces"] as $k) { $v = ini_get($k); echo $k, "=", ($v === false ? "n/a" : $v), "\n"; }'

# _p2s_check_ini TARGET cmd... (cmd runs php with -r appended)
_p2s_check_ini() {
    local _tg=$1 _out _k _v _mem='' _post='' _missing='' _note='' _mb _pb
    shift
    _out=$(_p2s_timeout 5 "$@" -r "$_P2S_INI_CODE" 2>/dev/null | head -n 10 | _p2s_clean_lines) || return 0
    [ -n "$_out" ] || return 0
    while IFS='=' read -r _k _v; do
        case "$_k" in
            memory_limit) _mem=$_v ;;
            post_max_size) _post=$_v ;;
            session.upload_progress.enabled)
                case "$_v" in 1|On|on) _missing="$_missing session.upload_progress.enabled=0" ;; esac ;;
            expose_php)
                case "$_v" in 1|On|on) _missing="$_missing expose_php=0" ;; esac ;;
            fatal_error_backtraces)
                case "$_v" in 1|On|on) _missing="$_missing fatal_error_backtraces=0" ;; esac ;;
            max_input_nesting_level)
                if [[ "$_v" =~ ^[0-9]+$ ]] && [ "$_v" -gt 8 ]; then
                    _note="$_note max_input_nesting_level is $_v (advisory: about 8, test your application first)."
                fi ;;
        esac
    done <<EOF
$_out
EOF
    _mb=$(_p2s_bytes "$_mem"); _pb=$(_p2s_bytes "$_post")
    if [ "$_mb" -gt 0 ] && [ "$_pb" -gt 0 ] && [ "$_pb" -ge $(( _mb / 4 )) ]; then
        _missing="$_missing post_max_size<memory_limit/4 (now $_post vs $_mem)"
    fi
    if [ -n "$_missing" ]; then
        _p2s_add warn mitigation "$_tg" "temporary mitigations not set:$_missing.$_note" \
            "Until patched: set session.upload_progress.enabled=0 and expose_php=0, keep post_max_size below a quarter of memory_limit"
    else
        _p2s_add ok mitigation "$_tg" "advisory mitigations in place.$_note"
    fi
}

_p2s_clean_lines() { tr -dc 'A-Za-z0-9_.:/=<>() \n-' | head -c 1000; }

# ---------------------------------------------------------------------------
# Local checks
# ---------------------------------------------------------------------------

_p2s_seen=' '

_p2s_php_version_of() {   # binary -> x.y.z or empty
    local _b=$1 _v
    case "$_b" in
        *php-fpm*|*lsphp*) _v=$(_p2s_timeout 5 "$_b" -v 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1) ;;
        *)                 _v=$(_p2s_timeout 5 "$_b" -r 'echo PHP_VERSION;' 2>/dev/null | head -n1 | _p2s_clean 30) ;;
    esac
    _v=${_v%%[-+~]*}
    _p2s_is_version "$_v" && echo "$_v"
}

_p2s_check_binaries() {
    local _b _real _v _pkg _verdict _found=0 _dir _sapi
    _p2s_section 'PHP installations on this host'
    for _b in "$_p2s_root"/usr/bin/php "$_p2s_root"/usr/bin/php[0-9]* \
              "$_p2s_root"/usr/sbin/php-fpm* "$_p2s_root"/usr/local/bin/php \
              "$_p2s_root"/usr/local/sbin/php-fpm "$_p2s_root"/usr/bin/lsphp* \
              "$_p2s_root"/opt/plesk/php/*/bin/php "$_p2s_root"/opt/cpanel/ea-php*/root/usr/bin/php \
              "$_p2s_root"/opt/alt/php*/usr/bin/php "$_p2s_root"/opt/remi/php*/root/usr/bin/php \
              "$_p2s_root"/usr/local/lsws/lsphp*/bin/php; do
        [ -f "$_b" ] && [ -x "$_b" ] || continue
        _real=$(readlink -f "$_b" 2>/dev/null || echo "$_b")
        case "$_p2s_seen" in *" $_real "*) continue ;; esac
        _p2s_seen="$_p2s_seen$_real "
        _v=$(_p2s_php_version_of "$_b")
        [ -n "$_v" ] || continue
        _found=1
        _pkg=''
        if [ -z "$_p2s_root" ] && command -v dpkg-query >/dev/null 2>&1; then
            _pkg=$(dpkg-query -S "$_real" 2>/dev/null | head -n1 | cut -d: -f1)
        fi
        if [ -n "$_pkg" ]; then
            _verdict=$(_p2s_judge_deb "$_pkg" "$_v")
        elif [ -z "$_p2s_root" ] && command -v rpm >/dev/null 2>&1 && rpm -qf "$_real" >/dev/null 2>&1; then
            _verdict=$(_p2s_judge_rpm "$_real" "$_v")
        else
            _verdict=$(_p2s_judge_upstream "$_v")
        fi
        _p2s_add_verdict php-binary "${_b#"$_p2s_root"}" "$_verdict"
        case "$_b" in
            *php-fpm*|*lsphp*) ;;
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
    done
    [ "$_found" -eq 1 ] || _p2s_add info php-binary 'host' 'no PHP installation found in the usual locations'
}

_p2s_check_fpm_pools() {
    local _f _v _any=0
    for _f in "$_p2s_root"/etc/php/*/fpm/pool.d/*.conf "$_p2s_root"/etc/php-fpm.d/*.conf \
              "$_p2s_root"/etc/opt/remi/php*/php-fpm.d/*.conf "$_p2s_root"/opt/plesk/php/*/etc/php-fpm.d/*.conf \
              "$_p2s_root"/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf "$_p2s_root"/usr/local/etc/php-fpm.d/*.conf; do
        [ -r "$_f" ] || continue
        [ "$_any" -eq 0 ] && _p2s_section 'PHP-FPM pools'
        _any=1
        _v=$(grep -E '^[[:space:]]*pm\.max_requests[[:space:]]*=' "$_f" 2>/dev/null | tail -n1 | cut -d= -f2 | tr -dc '0-9')
        if [ -z "$_v" ] || [ "$_v" = 0 ]; then
            _p2s_add info fpm-pool "${_f#"$_p2s_root"}" 'pm.max_requests is unlimited, workers keep corrupted state for their whole life' \
                'Temporary mitigation: set a low pm.max_requests (for example 500) and reload PHP-FPM'
        else
            _p2s_add ok fpm-pool "${_f#"$_p2s_root"}" "pm.max_requests = $_v"
        fi
    done
}

_p2s_check_containers() {
    local _rt _names _c _v _img _verdict _fpm
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
            # Containers without php answer with an error text here, not a version.
            _p2s_is_version "$_v" || continue
            _found_ct=1
            _img=$("$_rt" inspect -f '{{.Config.Image}}' "$_c" 2>/dev/null | _p2s_clean 120)
            _verdict=$(_p2s_judge_upstream "$_v")
            _p2s_add_verdict container "$_c ($_img)" "$_verdict"
            _p2s_check_ini "$_c" "$_rt" exec "$_c" php
            _fpm=$(_p2s_timeout 5 "$_rt" exec "$_c" sh -c 'command -v php-fpm >/dev/null 2>&1 && grep -hE "^[[:space:]]*pm\.max_requests" /usr/local/etc/php-fpm.d/*.conf 2>/dev/null | tail -n1 | cut -d= -f2' 2>/dev/null | tr -dc '0-9')
            if _p2s_timeout 5 "$_rt" exec "$_c" sh -c 'command -v php-fpm' >/dev/null 2>&1; then
                if [ -z "$_fpm" ] || [ "$_fpm" = 0 ]; then
                    _p2s_add info fpm-pool "$_c" 'pm.max_requests is unlimited' \
                        'Temporary mitigation: set a low pm.max_requests (for example 500) and reload PHP-FPM'
                fi
            fi
            if [ "$_opt_logs" -eq 1 ]; then
                _p2s_count_log_hits "$_c (container log, 24 h)" "$_rt" logs --since 24h "$_c"
            fi
        done
        [ "$_found_ct" -eq 1 ] || _p2s_add info container "$_rt" 'no running container with PHP'
    done
}

_p2s_check_stale_processes() {
    local _p _exe _name _stale=''
    [ -d /proc ] && [ "$(id -u)" -eq 0 ] || return 0
    for _p in /proc/[0-9]*; do
        _exe=$(readlink "$_p/exe" 2>/dev/null) || continue
        case "$_exe" in
            *php*' (deleted)')
                _name=$(basename "${_exe% (deleted)}" | _p2s_clean 40) ;;
            *apache2|*httpd)
                grep -q 'libphp.*(deleted)' "$_p/maps" 2>/dev/null || continue
                _name="$(basename "$_exe" | _p2s_clean 40) (mod_php)" ;;
            *) continue ;;
        esac
        case "$_stale" in *" $_name"*) ;; *) _stale="$_stale $_name" ;; esac
    done
    _p2s_section 'Running processes'
    if [ -n "$_stale" ]; then
        _p2s_add warn process 'host' "still running the replaced PHP binary:$_stale" \
            'PHP was updated on disk but not restarted: restart PHP-FPM and/or the web server'
    else
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

_p2s_check_url() {
    local _url=$1 _host _hdr _code _phpv _verdict _edge='' _ips _ip _cf_ip=0 _non_cf=0 _srv _ua _o
    case "$_url" in http://*|https://*) ;; *) _url="https://$_url" ;; esac
    _url=$(printf '%s' "$_url" | _p2s_clean 300)
    _host=${_url#*://}; _host=${_host%%/*}; _host=${_host##*@}
    case "$_host" in \[*) _host=${_host#[}; _host=${_host%%]*} ;; *) _host=${_host%%:*} ;; esac
    _p2s_section "Website $_url"
    _ua="php2shell-check/$P2S_SCRIPT_VERSION (+$P2S_REPO_URL)"

    if ! command -v curl >/dev/null 2>&1; then
        _p2s_add unknown remote "$_url" 'curl is not installed, remote checks skipped'
        return
    fi
    _hdr=$(curl -sS -o /dev/null -D - -L --max-redirs 5 --max-time 15 -A "$_ua" "$_url" 2>/dev/null | tr -d '\r' | _p2s_lower | _p2s_clean_lines)
    _code=$(printf '%s\n' "$_hdr" | grep -E '^http/' | tail -n1 | awk '{print $2}')
    if [ -z "$_hdr" ]; then
        _p2s_add unknown remote "$_url" 'no HTTP response (DNS, TLS or connection failure)'
        return
    fi
    _p2s_add info remote "$_url" "reachable, final HTTP status ${_code:-?}"

    # PHP version banner (expose_php).
    _phpv=$(printf '%s\n' "$_hdr" | grep -oE 'php/[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d/ -f2)
    if [ -n "$_phpv" ]; then
        case "$_p2s_frozen_versions" in
            *" $_phpv "*)
                _p2s_add unknown php-banner "$_url" "announces PHP $_phpv, a distribution build that may contain the backported fix" \
                    'Run this script on the server to check the package version' ;;
            *)
                _verdict=$(_p2s_judge_upstream "$_phpv")
                _p2s_add_verdict php-banner "$_url" "${_verdict%%|*}|X-Powered-By: $(printf '%s' "$_verdict" | cut -d'|' -f2-)" ;;
        esac
        _p2s_add warn disclosure "$_url" "the PHP version is visible to everyone (X-Powered-By: PHP/$_phpv)" \
            'Set expose_php=0 so scanners cannot pick vulnerable targets by header'
    else
        _p2s_add ok disclosure "$_url" 'no PHP version in the response headers (this alone says nothing about the patch level)'
    fi

    # Edge / WAF detection by headers.
    _srv=$(printf '%s\n' "$_hdr" | grep -E '^server:' | tail -n1 | cut -d: -f2- | _p2s_clean 60)
    printf '%s\n' "$_hdr" | grep -qE '^cf-ray:|^server: *cloudflare' && _edge='Cloudflare'
    [ -z "$_edge" ] && printf '%s\n' "$_hdr" | grep -qE '^x-sucuri-id:|^server: *sucuri' && _edge='Sucuri'
    [ -z "$_edge" ] && printf '%s\n' "$_hdr" | grep -qE '^x-iinfo:|^x-cdn: *imperva' && _edge='Imperva'
    [ -z "$_edge" ] && printf '%s\n' "$_hdr" | grep -qE '^x-amz-cf-id:' && _edge='Amazon CloudFront'
    [ -z "$_edge" ] && printf '%s\n' "$_hdr" | grep -qE '^x-azure-ref:' && _edge='Azure Front Door'
    [ -z "$_edge" ] && printf '%s\n' "$_hdr" | grep -qE '^server: *akamai|^x-akamai' && _edge='Akamai'
    [ -z "$_edge" ] && printf '%s\n' "$_hdr" | grep -qE '^x-fastly|^x-served-by: *cache-' && _edge='Fastly'
    [ -z "$_edge" ] && printf '%s\n' "$_hdr" | grep -qE '^server: *bunnycdn' && _edge='BunnyCDN'

    # DNS: do the names point at Cloudflare's edge?
    _ips=$(_p2s_resolve "$_host")
    for _ip in $_ips; do
        if _p2s_is_cloudflare_ip "$_ip"; then _cf_ip=1; else _non_cf=1; fi
    done

    case "$_edge" in
        Cloudflare)
            if [ "$_cf_ip" -eq 1 ] && [ "$_non_cf" -eq 0 ]; then
                _p2s_add ok waf "$_url" "proxied through Cloudflare (header and DNS); Cloudflare says it has deployed WAF rules for these CVEs on all plans, Free included" \
                    'Keep the Cloudflare Managed/Free ruleset enabled and make sure the origin only accepts Cloudflare (tunnel or firewall)'
            elif [ "$_non_cf" -eq 1 ] && [ "$_cf_ip" -eq 1 ]; then
                _p2s_add warn waf "$_url" "Cloudflare answered, but $_host also resolves to non-Cloudflare addresses ($(printf '%s' "$_ips" | tr '\n' ' ' | _p2s_clean 120))" \
                    'Every DNS record of the site should be proxied (orange cloud), otherwise part of the traffic skips the WAF'
            else
                _p2s_add ok waf "$_url" 'Cloudflare headers present (DNS could not be confirmed from here)' \
                    'Keep the Cloudflare Managed/Free ruleset enabled and make sure the origin only accepts Cloudflare (tunnel or firewall)'
            fi ;;
        '')
            if [ "$_cf_ip" -eq 1 ]; then
                _p2s_add unknown waf "$_url" "$_host resolves to Cloudflare, but the response carried no Cloudflare headers"
            else
                _p2s_add info waf "$_url" "no WAF or CDN detected${_srv:+ (server:$_srv)}: requests reach PHP unfiltered" \
                    'If you cannot patch today, put the site behind a WAF that has rules for CVE-2026-109618/109619'
            fi ;;
        *)
            _p2s_add info waf "$_url" "behind $_edge. Whether it filters these CVEs is not visible from outside" \
                "Ask $_edge whether rules for CVE-2026-109618/109619 are active for your property" ;;
    esac
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
        _p2s_check_binaries
        _p2s_check_fpm_pools
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
_i=0
while [ "$_i" -lt "${#_f_status[@]}" ]; do
    case "${_f_status[$_i]}" in
        vuln) _n_vuln=$(( _n_vuln + 1 )) ;;
        unknown) _n_unknown=$(( _n_unknown + 1 )) ;;
        warn) _n_warn=$(( _n_warn + 1 )) ;;
        ok) _n_ok=$(( _n_ok + 1 )) ;;
    esac
    _i=$(( _i + 1 ))
done
if [ "$_n_vuln" -gt 0 ]; then _p2s_result=vulnerable; _p2s_rc=1
elif [ "$_n_unknown" -gt 0 ]; then _p2s_result=undecided; _p2s_rc=2
else _p2s_result=not-vulnerable; _p2s_rc=0
fi

if [ "$_opt_json" -eq 1 ]; then
    printf '{"tool":"php2shell-check","version":"%s","data_as_of":"%s","advisory":"%s",' "$P2S_SCRIPT_VERSION" "$P2S_DATA_DATE" "$P2S_ADVISORY"
    printf '"host":"%s","os":"%s","result":"%s",' "$(_p2s_json_esc "$_p2s_hostname")" "$(_p2s_json_esc "$_p2s_os")" "$_p2s_result"
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
    undecided)      printf '  %sUNDECIDED%s   some results could not be judged, see the ?? lines.\n' "$_c_yel" "$_c_off" ;;
    not-vulnerable) printf '  %sNO VULNERABLE PHP FOUND%s  in what this script can see.\n' "$_c_grn" "$_c_off" ;;
esac
_p2s_hints="$_p2s_hints_1$_p2s_hints_2$_p2s_hints_3"
if [ -n "$_p2s_hints" ]; then
    printf '\n%sNext steps%s\n' "$_c_bold" "$_c_off"
    printf '%s\n' "$_p2s_hints" | tr '|' '\n' | grep -v '^$' | awk '!s[$0]++' | head -n 10 | sed 's/^/  - /'
fi
printf '\n%sAdvisory: %s\nTool:     %s\n          provided as is, without warranty or support (MIT, see LICENSE)%s\n' \
    "$_c_dim" "$P2S_ADVISORY_URL" "$P2S_REPO_URL" "$_c_off"
exit "$_p2s_rc"
