# shellcheck shell=bash
# Sourced by tests/run_tests.sh. The promises about how reliable a verdict is.
# shellcheck disable=SC2154  # _t_script, _t_base and _t_tmp come from run_tests.sh

# The core promise: a website that does not show its version is never reported
# as clean, and the output says where a definite answer comes from.
if [ -n "${_t_base:-}" ]; then
    _t_run 'silent site is undecided, not clean' 2 'php-level' bash "$_t_script" -r --no-color "$_t_base/plain"
    _t_run 'remote run points at the server'     2 'run this script on the server' bash "$_t_script" -r --no-color "$_t_base/plain"
    if bash "$_t_script" -r --no-color "$_t_base/plain" | grep -q 'NO VULNERABLE PHP FOUND'; then
        _t_bad 'silent site is not called "no vulnerable PHP found"'
    else
        _t_ok 'silent site is not called "no vulnerable PHP found"'
    fi
    _t_run 'PHPSESSID shows PHP is present'  2 'signal: PHPSESSID cookie' bash "$_t_script" -r --no-color "$_t_base/phpsess"
    _t_run 'wp-json shows PHP is present'    2 'signal: WordPress'        bash "$_t_script" -r --no-color "$_t_base/wordpress"
    # A visible fixed version is the weakest kind of good news: the header
    # can be set by the application, a cache or a proxy with another PHP
    # behind it. It is undecided, in line with the promise this file tests
    # everywhere else -- a check from outside never confirms a patch.
    _t_run 'a visible fixed version is undecided' 2 '\?\? \] php-banner'  bash "$_t_script" -r --no-color "$_t_base/fixed"
else
    echo "  skip  fixture server not available"
fi

# A local run says so, and a host serving no PHP says that too.
_t_fake_root "$_t_tmp/rel" 8.3.36
_t_run 'local run reports its own scope' 0 'Ran on this host'  env P2S_TEST_ROOT="$_t_tmp/rel" bash "$_t_script" --no-color
_t_empty=$(mktemp -d "$_t_tmp/relempty.XXXX")
# Exit 2 for the same reason as the case above: nothing was judged here.
_t_run 'no PHP found mentions none running' 2 'none running' env P2S_TEST_ROOT="$_t_empty" bash "$_t_script" --no-color

# PHP in an unusual path is found through the process list, not the path globs.
_t_proc="$_t_tmp/proc/4242"
mkdir -p "$_t_proc" "$_t_tmp/weird/opt/php-8.3/bin"
cat > "$_t_tmp/weird/opt/php-8.3/bin/php" <<'INNER'
#!/bin/sh
case "$*" in
    *PHP_VERSION*) printf '%s' '8.3.35' ;;
    *ini_get*) printf 'memory_limit=256M\npost_max_size=8M\nmax_input_nesting_level=8\nsession.upload_progress.enabled=0\nexpose_php=0\nfatal_error_backtraces=n/a\n' ;;
esac
INNER
chmod +x "$_t_tmp/weird/opt/php-8.3/bin/php"
ln -sf "$_t_tmp/weird/opt/php-8.3/bin/php" "$_t_proc/exe"
_t_run 'running PHP outside the known paths is found' 1 'found via a running process' \
    env P2S_TEST_ROOT="$_t_tmp/weird" P2S_PROC_ROOT="$_t_tmp/proc" bash "$_t_script" --no-color
_t_run 'and it is judged, not just listed' 1 'PHP 8.3.35, fixed in 8.3.36' \
    env P2S_TEST_ROOT="$_t_tmp/weird" P2S_PROC_ROOT="$_t_tmp/proc" bash "$_t_script" --no-color

# A container judged by its package database: same upstream number, different
# patch state. This is the unit behind the container check.
_t_deb() { _r=$(_p2s_judge_deb_data "$1" "$2" "$3" "$4" "$2"); if [ "${_r%%|*}" = "$5" ]; then _t_ok "deb $1 $2 $3 = $5"; else _t_bad "deb $1 $2 $3 = $5 (got ${_r%%|*})"; fi; }
_t_deb noble php8.3 8.3.6-0ubuntu0.24.04.13 8.3.6 ok
_t_deb noble php8.3 8.3.6-0ubuntu0.24.04.12 8.3.6 vuln
_t_deb trixie php8.4 8.4.27-1~deb13u1 8.4.27 ok
_t_deb trixie php8.4 8.4.24-1~deb13u1 8.4.24 vuln
_t_deb bookworm php8.2 8.2.34-1~deb12u1 8.2.34 vuln
_t_deb plucky php8.4 8.4.5-1ubuntu1 8.4.5 unknown

# The version comparison must also work where dpkg does not exist.
_t_cmpdeb() { if [ "$(_p2s_deb_cmp "$1" "$2")" = "$3" ]; then _t_ok "deb_cmp $1 $2 = $3"; else _t_bad "deb_cmp $1 $2 = $3 (got $(_p2s_deb_cmp "$1" "$2"))"; fi; }
_t_cmpdeb 8.3.6-0ubuntu0.24.04.13 8.3.6-0ubuntu0.24.04.13 0
_t_cmpdeb 8.3.6-0ubuntu0.24.04.13 8.3.6-0ubuntu0.24.04.12 1
_t_cmpdeb 8.3.6-0ubuntu0.24.04.9  8.3.6-0ubuntu0.24.04.13 -1
_t_cmpdeb 8.4.27-1~deb13u1 8.4.24-1~deb13u1 1
_t_cmpdeb 8.4.27-1~deb13u1 8.4.27-1 -1
_t_cmpdeb 2:8.1.2-1ubuntu2.28 8.1.2-1ubuntu2.27 1

# Where dpkg exists, the fallback must agree with it.
if command -v dpkg >/dev/null 2>&1; then
    _t_pairs="8.3.6-0ubuntu0.24.04.13:8.3.6-0ubuntu0.24.04.12
8.3.6-0ubuntu0.24.04.9:8.3.6-0ubuntu0.24.04.13
8.4.27-1~deb13u1:8.4.27-1
8.4.27-1~deb13u1:8.4.24-1~deb13u1
8.2.34-1~deb12u1:8.2.34-1~deb12u1
2:8.1.2-1ubuntu2.28:8.1.2-1ubuntu2.27
8.1.2-1ubuntu2.28:8.1.2-1ubuntu2.9"
    _t_agree=1
    for _t_pair in $_t_pairs; do
        _t_a=${_t_pair%:*}; _t_b=${_t_pair##*:}
        if dpkg --compare-versions "$_t_a" ge "$_t_b"; then _t_want=yes; else _t_want=no; fi
        if [ "$(_p2s_deb_cmp "$_t_a" "$_t_b")" != "-1" ]; then _t_got=yes; else _t_got=no; fi
        [ "$_t_want" = "$_t_got" ] || { _t_agree=0; echo "        disagreement on $_t_a / $_t_b (dpkg $_t_want, fallback $_t_got)"; }
    done
    if [ "$_t_agree" -eq 1 ]; then _t_ok 'fallback agrees with dpkg'; else _t_bad 'fallback agrees with dpkg'; fi
else
    echo "  skip  dpkg not installed, cross-check skipped"
fi
