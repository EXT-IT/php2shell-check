#!/usr/bin/env bash
# Regression tests for php2shell-check.sh. No root, no network, no Docker.
# Runs on bash 3.2 (macOS) and bash 5 (Linux CI).

set -u
_t_dir=$(cd "$(dirname "$0")" && pwd)
_t_script="$_t_dir/../php2shell-check.sh"
_t_tmp=$(mktemp -d)
_t_pass=0
_t_fail=0
_t_server_pid=''

_t_cleanup() {
    [ -n "$_t_server_pid" ] && { kill "$_t_server_pid" 2>/dev/null; wait "$_t_server_pid" 2>/dev/null; }
    rm -rf "$_t_tmp"
}
trap _t_cleanup EXIT

_t_ok()   { _t_pass=$(( _t_pass + 1 )); printf '  ok    %s\n' "$1"; }
_t_bad()  { _t_fail=$(( _t_fail + 1 )); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }

# _t_run NAME EXPECTED_RC EXPECTED_TEXT cmd...
_t_run() {
    local _name=$1 _rc=$2 _text=$3 _out _got
    shift 3
    _out=$("$@" 2>&1); _got=$?
    if [ "$_got" -ne "$_rc" ]; then
        _t_bad "$_name (exit $_got, expected $_rc)" "$_out"
    elif [ -n "$_text" ] && ! printf '%s' "$_out" | grep -qE -- "$_text"; then
        _t_bad "$_name (output lacks /$_text/)" "$_out"
    else
        _t_ok "$_name"
    fi
}

# A fake php binary: prints $FAKE_PHP_VERSION and a fixed ini set.
_t_fake_root() {   # dir version
    local _root=$1
    mkdir -p "$_root/usr/bin" "$_root/etc/php/8.3/fpm/pool.d" "$_root/var/log/nginx"
    cat > "$_root/usr/bin/php8.3" <<EOF
#!/bin/sh
case "\$*" in
    *PHP_VERSION*) printf '%s' '$2' ;;
    *ini_get*) printf 'memory_limit=256M\npost_max_size=64M\nmax_input_nesting_level=64\nsession.upload_progress.enabled=1\nexpose_php=1\nfatal_error_backtraces=n/a\n' ;;
esac
EOF
    chmod +x "$_root/usr/bin/php8.3"
    printf '[www]\npm = dynamic\n' > "$_root/etc/php/8.3/fpm/pool.d/www.conf"
    : > "$_root/var/log/nginx/error.log"
}

echo "Informational flags"
_t_run '--version exits 0'                0 '^php2shell-check [0-9]' bash "$_t_script" --version
_t_run '--help exits 0'                   0 'Usage:'                 bash "$_t_script" --help
_t_run 'unknown option exits 3'           3 'unknown option'         bash "$_t_script" --bogus
_t_run '--remote-only without URL exits 3' 3 'needs at least one URL' bash "$_t_script" --remote-only
_t_run '--origin without value exits 3'   3 'needs an IP'            bash "$_t_script" --origin

echo "Helper functions"
# shellcheck source=/dev/null
P2S_SOURCE_ONLY=1 . "$_t_script"
_t_cmp() { if [ "$(_p2s_vercmp "$1" "$2")" = "$3" ]; then _t_ok "vercmp $1 $2 = $3"; else _t_bad "vercmp $1 $2 = $3"; fi; }
_t_cmp 8.3.36 8.3.36 0
_t_cmp 8.3.35 8.3.36 -1
_t_cmp 8.3.100 8.3.36 1
_t_cmp 8.4.27 8.4.3 1
_t_cf() { if _p2s_is_cloudflare_ip "$1"; then _r=yes; else _r=no; fi; if [ "$_r" = "$2" ]; then _t_ok "cloudflare ip $1 = $2"; else _t_bad "cloudflare ip $1 = $2"; fi; }
_t_cf 104.16.123.96 yes
_t_cf 172.67.1.1 yes
_t_cf 131.0.72.5 yes
_t_cf 203.0.113.42 no
_t_cf 8.8.8.8 no
_t_cf 2606:4700:3030::6815:1 yes
_t_cf 2a06:98c1:3120::3 yes
_t_cf 2a06:98c8::1 no
_t_cf 2001:db8::1 no
_t_by() { if [ "$(_p2s_bytes "$1")" = "$2" ]; then _t_ok "bytes $1 = $2"; else _t_bad "bytes $1 = $2 (got $(_p2s_bytes "$1"))"; fi; }
_t_by 64M 67108864
_t_by 1G 1073741824
_t_by 512K 524288
_t_by -1 -1
_t_up() { _r=$(_p2s_judge_upstream "$1"); if [ "${_r%%|*}" = "$2" ]; then _t_ok "upstream $1 = $2"; else _t_bad "upstream $1 = $2 (got ${_r%%|*})"; fi; }
_t_up 8.5.12 ok
_t_up 8.5.11 vuln
_t_up 8.4.27 ok
_t_up 8.4.26 vuln
_t_up 8.3.36 ok
_t_up 8.2.34 vuln
_t_up 8.1.33 vuln
_t_up 7.4.33 vuln
_t_up 8.6.0 unknown

echo "Local checks (fake root)"
_t_fake_root "$_t_tmp/vuln" 8.3.35
_t_run 'vulnerable PHP binary exits 1'   1 'VULN\] php-binary +/usr/bin/php8.3' env P2S_TEST_ROOT="$_t_tmp/vuln" bash "$_t_script" --no-color
_t_run 'missing mitigations are listed' 1 'session.upload_progress.enabled=0' env P2S_TEST_ROOT="$_t_tmp/vuln" bash "$_t_script" --no-color
_t_run 'FPM pool without max_requests'  1 'pm.max_requests is unlimited'     env P2S_TEST_ROOT="$_t_tmp/vuln" bash "$_t_script" --no-color
_t_fake_root "$_t_tmp/fixed" 8.3.36
_t_run 'fixed PHP binary exits 0'       0 'OK \] php-binary'                  env P2S_TEST_ROOT="$_t_tmp/fixed" bash "$_t_script" --no-color
_t_fake_root "$_t_tmp/future" 8.6.0
_t_run 'unknown branch exits 2'         2 'not covered'                       env P2S_TEST_ROOT="$_t_tmp/future" bash "$_t_script" --no-color
_t_fake_root "$_t_tmp/logs" 8.3.36
for _i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21; do
    echo "PHP Fatal error:  Allowed memory size of 268435456 bytes exhausted" >> "$_t_tmp/logs/var/log/nginx/error.log"
done
_t_run 'log burst is flagged'           0 'WARN\] log-indicator'             env P2S_TEST_ROOT="$_t_tmp/logs" bash "$_t_script" --no-color
_t_run '--no-logs skips the log check'  0 ''                                  env P2S_TEST_ROOT="$_t_tmp/logs" bash "$_t_script" --no-logs --no-color
if env P2S_TEST_ROOT="$_t_tmp/logs" bash "$_t_script" --no-logs --no-color | grep -q log-indicator; then
    _t_bad '--no-logs output has no log lines'
else
    _t_ok '--no-logs output has no log lines'
fi
_t_mkempty=$(mktemp -d "$_t_tmp/empty.XXXX")
# Exit 2, not 0: the known paths and the process list holding nothing is not
# the same as this host running no PHP, and a run that judged no PHP runtime
# says nothing about the host. The old expectation (0) was how a run that
# examined nothing came out green.
_t_run 'host without PHP is undecided'  2 'no PHP installation found'         env P2S_TEST_ROOT="$_t_mkempty" bash "$_t_script" --no-color

echo "JSON output"
if command -v python3 >/dev/null 2>&1; then
    if env P2S_TEST_ROOT="$_t_tmp/vuln" bash "$_t_script" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["result"]=="vulnerable"; assert any(f["check"]=="php-binary" for f in d["findings"])'; then
        _t_ok 'JSON parses and reports vulnerable'
    else
        _t_bad 'JSON parses and reports vulnerable'
    fi
else
    echo "  skip  python3 not installed"
fi

echo "Remote checks (local fixture server)"
if command -v python3 >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
    python3 "$_t_dir/fixture_server.py" "$_t_tmp/port" &
    _t_server_pid=$!
    _i=0
    while [ ! -s "$_t_tmp/port" ] && [ "$_i" -lt 50 ]; do _i=$(( _i + 1 )); sleep 0.1; done
    _t_base="http://127.0.0.1:$(cat "$_t_tmp/port")"
    _t_run 'banner 8.3.35 is vulnerable'   1 'VULN\] php-banner'   bash "$_t_script" -r --no-color "$_t_base/vulnerable"
    # Undecided, not ok: X-Powered-By is self-declared. The old expectation
    # let a run whose only input was a header exit 0 as "no vulnerable PHP
    # found", while the same output said it cannot confirm a patch level.
    _t_run 'banner 8.3.36 is undecided'    2 '\?\? \] php-banner'  bash "$_t_script" -r --no-color "$_t_base/fixed"
    _t_run 'and says a header is self-declared' 2 'self-declared' bash "$_t_script" -r --no-color "$_t_base/fixed"
    _t_run 'frozen distro banner is undecided' 2 'cannot be judged' bash "$_t_script" -r --no-color "$_t_base/distro"
    _t_run 'EOL banner is vulnerable'      1 'no fixed release'    bash "$_t_script" -r --no-color "$_t_base/eol"
    _t_run 'version disclosure warns'      1 'WARN\] disclosure'   bash "$_t_script" -r --no-color "$_t_base/vulnerable"
    _t_run 'Cloudflare headers detected'   2 'OK \] waf'           bash "$_t_script" -r --no-color "$_t_base/cloudflare"
    _t_run 'Sucuri detected'               2 'behind Sucuri'       bash "$_t_script" -r --no-color "$_t_base/sucuri"
    _t_run 'LiteSpeed noted'               2 'LSAPI'               bash "$_t_script" -r --no-color "$_t_base/litespeed"
    _t_run 'no WAF reported'               2 'no WAF or CDN'       bash "$_t_script" -r --no-color "$_t_base/plain"
    _t_run 'unreachable site is undecided' 2 'no HTTP answer'    bash "$_t_script" -r --no-color "http://127.0.0.1:9/"
    _t_run 'origin reachable warns'        2 'WARN\] origin'       bash "$_t_script" -r --no-color --origin 127.0.0.1 "$_t_base/plain"
    if bash "$_t_script" -r --no-color "$_t_base/escape" | LC_ALL=C grep -q "$(printf '\033')"; then
        _t_bad 'escape sequences from headers are stripped'
    else
        _t_ok 'escape sequences from headers are stripped'
    fi
else
    echo "  skip  python3 or curl not installed"
    _t_base=''
fi

# Further cases live in tests/cases/*.sh. They are sourced here and can use
# _t_run, _t_ok, _t_bad, _t_fake_root, $_t_script, $_t_tmp and $_t_base
# (empty when the fixture server is not available; skip remote cases then).
for _t_case in "$_t_dir"/cases/*.sh; do
    [ -f "$_t_case" ] || continue
    echo "Cases from $(basename "$_t_case")"
    # shellcheck source=/dev/null
    . "$_t_case"
done

echo
echo "$_t_pass passed, $_t_fail failed"
[ "$_t_fail" -eq 0 ]
