# shellcheck shell=bash
# Sourced by tests/run_tests.sh. An effective uid of zero does not guarantee
# access to another user's /proc/<pid>/exe or maps in a container.
# shellcheck disable=SC2154  # _t_script and _t_tmp come from run_tests.sh

_sp_dir="${_t_tmp:?}/stale-processes"
mkdir -p "$_sp_dir"

_sp_process() {   # case pid comm exe (empty means readlink fails)
    local _p="$_sp_dir/$1/$2"
    mkdir -p "$_p"
    printf '%s\n' "$3" > "$_p/comm"
    if [ -n "$4" ]; then
        ln -s "$4" "$_p/exe"
    else
        # A regular file produces the same readlink failure even as root.
        : > "$_p/exe"
    fi
}

_sp_states() {
    # shellcheck disable=SC2016  # Expand these variables in the child shell.
    env P2S_SOURCE_ONLY=1 P2S_PROC_ROOT="$_sp_dir/$1" bash -c '
        . "$1"
        id() { if [ "${1:-}" = -u ]; then printf "0\n"; else command id "$@"; fi; }
        _opt_json=1
        _p2s_check_stale_processes
        printf "%s\n" "${_f_status[@]}"
    ' _ "$_t_script"
}

_sp_expect() {   # name case exact states
    local _got
    _got=$(_sp_states "$2")
    if [ "$_got" = "$3" ]; then
        _t_ok "$1"
    else
        _t_bad "$1 (expected '$3', got '$_got')"
    fi
}

_sp_process current 101 php-fpm8.3 /usr/sbin/php-fpm8.3
_sp_expect 'current FPM process retains its ok finding' current ok

_sp_process deleted 102 php-fpm8.3 '/usr/sbin/php-fpm8.3 (deleted)'
_sp_expect 'deleted FPM executable retains its restart warning' deleted warn

_sp_process denied 103 php-fpm8.3 ''
_sp_expect 'unreadable FPM exe is unknown, never ok' denied unknown

_sp_process mixed 104 php-fpm8.3 '/usr/sbin/php-fpm8.3 (deleted)'
_sp_process mixed 105 php-fpm8.3 ''
_sp_expect 'stale and unreadable workers preserve both findings' mixed $'warn\nunknown'

_sp_process unrelated 106 sleep ''
_sp_expect 'unreadable unrelated process does not imply a PHP gap' unrelated ok

_sp_process apache-current 107 apache2 /usr/sbin/apache2
printf '%s\n' '00400000-00500000 r-xp 00000000 00:01 1 /usr/lib/apache2/modules/libphp8.3.so' \
    > "$_sp_dir/apache-current/107/maps"
_sp_expect 'readable current Apache mapping retains ok' apache-current ok

_sp_process apache-deleted 108 apache2 /usr/sbin/apache2
printf '%s\n' '00400000-00500000 r-xp 00000000 00:01 1 /usr/lib/apache2/modules/libphp8.3.so (deleted)' \
    > "$_sp_dir/apache-deleted/108/maps"
_sp_expect 'deleted Apache PHP mapping retains its restart warning' apache-deleted warn

_sp_process apache-denied 109 apache2 /usr/sbin/apache2
mkdir "$_sp_dir/apache-denied/109/maps"
_sp_expect 'Apache maps read failure is unknown, never ok' apache-denied unknown

_sp_process apache-exe-denied 110 httpd ''
_sp_expect 'unreadable httpd exe is unknown, never ok' apache-exe-denied unknown

mkdir -p "$_sp_dir/exited"
_sp_expect 'an already vanished process does not create a read failure' exited ok

_sp_process zombie 111 php-fpm8.3 ''
printf 'Name:\tphp-fpm8.3\nState:\tZ (zombie)\n' > "$_sp_dir/zombie/111/status"
_sp_expect 'a zombie PHP process has no running executable to inspect' zombie ok
