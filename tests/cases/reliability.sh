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
    _t_run 'a visible fixed version is ok'   0 'OK \] php-banner'         bash "$_t_script" -r --no-color "$_t_base/fixed"
else
    echo "  skip  fixture server not available"
fi

# A local run says so, and a host serving no PHP says that too.
_t_fake_root "$_t_tmp/rel" 8.3.36
_t_run 'local run reports its own scope' 0 'Ran on this host'  env P2S_TEST_ROOT="$_t_tmp/rel" bash "$_t_script" --no-color
_t_empty=$(mktemp -d "$_t_tmp/relempty.XXXX")
_t_run 'no PHP found mentions none running' 0 'none running' env P2S_TEST_ROOT="$_t_empty" bash "$_t_script" --no-color

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
