# shellcheck shell=bash
# Sourced by tests/run_tests.sh. PHP-FPM pool settings that change the blast
# radius of this bug.
# shellcheck disable=SC2154  # _t_script and _t_tmp come from run_tests.sh

_t_pool_root="$_t_tmp/poolroot"
_t_fake_root "$_t_pool_root" 8.3.36
printf '[www]\nuser = root\ngroup = root\npm = dynamic\n' > "$_t_pool_root/etc/php/8.3/fpm/pool.d/www.conf"
_t_run 'FPM pool running as root is a warning' 0 'runs as root' \
    env P2S_TEST_ROOT="$_t_pool_root" bash "$_t_script" --no-color
_t_run 'and it says why that matters'          0 'root code execution' \
    env P2S_TEST_ROOT="$_t_pool_root" bash "$_t_script" --no-color

_t_pool_user="$_t_tmp/pooluser"
_t_fake_root "$_t_pool_user" 8.3.36
printf '[www]\nuser = www-data\ngroup = www-data\npm.max_requests = 500\n' > "$_t_pool_user/etc/php/8.3/fpm/pool.d/www.conf"
if env P2S_TEST_ROOT="$_t_pool_user" bash "$_t_script" --no-color | grep -q 'runs as root'; then
    _t_bad 'an unprivileged pool is not flagged'
else
    _t_ok 'an unprivileged pool is not flagged'
fi
_t_run 'a pool with pm.max_requests is fine' 0 'pm.max_requests = 500' \
    env P2S_TEST_ROOT="$_t_pool_user" bash "$_t_script" --no-color

# The distribution table, checked against the security advisories.
_t_tbl() { if [ "$(_p2s_distro_fixed "$1")" = "$2" ]; then _t_ok "table $1 = $2"; else _t_bad "table $1 = $2 (got $(_p2s_distro_fixed "$1"))"; fi; }
_t_tbl noble:php8.3    8.3.6-0ubuntu0.24.04.13
_t_tbl jammy:php8.1    8.1.2-1ubuntu2.28
_t_tbl resolute:php8.5 8.5.4-0ubuntu1.5
_t_tbl trixie:php8.4   8.4.27-1~deb13u1
_t_tbl bookworm:php8.2 8.2.35-1~deb12u1
_t_tbl noble:php8.9    none

# Which SAPI serves requests decides how urgent a vulnerable PHP is.
_t_modphp="$_t_tmp/modphp"
_t_fake_root "$_t_modphp" 8.3.35
mkdir -p "$_t_modphp/etc/apache2/mods-enabled"
: > "$_t_modphp/etc/apache2/mods-enabled/php8.3.load"
_t_run 'mod_php is called out as the demonstrated case' 1 'WARN\] sapi' \
    env P2S_TEST_ROOT="$_t_modphp" bash "$_t_script" --no-color
_t_run 'and names the advisory finding'                 1 'demonstrates a complete unauthenticated exploit' \
    env P2S_TEST_ROOT="$_t_modphp" bash "$_t_script" --no-color

_t_fpmonly="$_t_tmp/fpmonly"
_t_fake_root "$_t_fpmonly" 8.3.35
: > "$_t_fpmonly/etc/php/8.3/fpm/php-fpm.conf"
_t_run 'FPM gets the advisory caveat, not a warning' 1 'no complete exploit for FPM' \
    env P2S_TEST_ROOT="$_t_fpmonly" bash "$_t_script" --no-color
if env P2S_TEST_ROOT="$_t_fpmonly" bash "$_t_script" --no-color | grep -q 'WARN\] sapi'; then
    _t_bad 'FPM is not warned about like mod_php'
else
    _t_ok 'FPM is not warned about like mod_php'
fi
