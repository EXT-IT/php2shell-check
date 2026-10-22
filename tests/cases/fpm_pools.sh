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
_t_tbl stonking:php8.5 8.5.9-0ubuntu2.1
_t_tbl trixie:php8.4   8.4.27-1~deb13u1
_t_tbl bookworm:php8.2 8.2.35-1~deb12u1
_t_tbl focal:php7.4    7.4.3-4ubuntu2.29+esm5
_t_tbl bionic:php7.2   7.2.24-0ubuntu0.18.04.17+esm14
_t_tbl xenial:php7.0   7.0.33-0ubuntu0.16.04.16+esm22
_t_tbl trusty:php5     5.5.9+dfsg-1ubuntu4.29+esm18
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

# GHSA-6wmf-4rv5-p3rp validated the session lifecycle RCE "against mod_php
# and FPM". The earlier wording here ("no complete exploit for FPM") came from
# the first CVE alone and read as an all-clear for FPM, which it is not.
_t_fpmonly="$_t_tmp/fpmonly"
_t_fake_root "$_t_fpmonly" 8.3.35
: > "$_t_fpmonly/etc/php/8.3/fpm/php-fpm.conf"
_t_run 'FPM carries the validated session RCE' 1 'validated the session lifecycle RCE against mod_php and FPM' \
    env P2S_TEST_ROOT="$_t_fpmonly" bash "$_t_script" --no-color
_t_run 'and the worker exit is named as no fix' 1 'worker exit is no fix' \
    env P2S_TEST_ROOT="$_t_fpmonly" bash "$_t_script" --no-color
if env P2S_TEST_ROOT="$_t_fpmonly" bash "$_t_script" --no-color | grep -q 'no complete exploit for FPM'; then
    _t_bad 'the old FPM all-clear is gone'
else
    _t_ok 'the old FPM all-clear is gone'
fi

# php-cgi, named in php.net's "Who is at risk". Debian's php8.3-cgi depends on
# php8.3-cli, so the version verdict arrives through the CLI binary either
# way; what was missing without this line is how the host serves requests.
_t_cgi="$_t_tmp/cgionly"
_t_fake_root "$_t_cgi" 8.3.35
mkdir -p "$_t_cgi/etc/php/8.3/cgi"
: > "$_t_cgi/etc/php/8.3/cgi/php.ini"
_t_run 'php-cgi is reported as a SAPI' 1 'served by php-cgi' \
    env P2S_TEST_ROOT="$_t_cgi" bash "$_t_script" --no-color
_t_run 'and is judged like FPM, not per request' 1 'FastCGI process serves many requests' \
    env P2S_TEST_ROOT="$_t_cgi" bash "$_t_script" --no-color

# FrankenPHP links PHP into its own binary. The trap is the version line:
# "FrankenPHP v1.13.2 PHP 8.3.35 ..." - the first number is FrankenPHP's own.
_t_franken="$_t_tmp/franken"
mkdir -p "$_t_franken/usr/local/bin" "$_t_franken/etc"
printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=trixie\n' \
    > "$_t_franken/etc/os-release"
cat > "$_t_franken/usr/local/bin/frankenphp" <<'EOF'
#!/bin/sh
[ "$1" = version ] && echo 'FrankenPHP v1.13.2 PHP 8.3.35 Caddy v2.11.7 h1:yj0Y4fYZ='
exit 0
EOF
chmod +x "$_t_franken/usr/local/bin/frankenphp"
_t_run 'FrankenPHP is judged by its embedded PHP version' 1 'PHP 8\.3\.35, fixed in 8\.3\.36' \
    env P2S_TEST_ROOT="$_t_franken" bash "$_t_script" --no-color
if env P2S_TEST_ROOT="$_t_franken" bash "$_t_script" --no-color | grep -q '1\.13\.2'; then
    _t_bad "FrankenPHP's own version stays out of the verdict"
else
    _t_ok "FrankenPHP's own version stays out of the verdict"
fi
_t_run 'FrankenPHP keeps the advisory wording' 1 'does not make it immune' \
    env P2S_TEST_ROOT="$_t_franken" bash "$_t_script" --no-color

# Two SAPIs at once is the normal case on a control-panel host. Reporting only
# the first find hid exactly the combination that decides the urgency.
_t_both="$_t_tmp/bothsapi"
_t_fake_root "$_t_both" 8.3.35
mkdir -p "$_t_both/etc/apache2/mods-enabled"
: > "$_t_both/etc/apache2/mods-enabled/php8.3.load"
: > "$_t_both/etc/php/8.3/fpm/php-fpm.conf"
_t_both_out=$(env P2S_TEST_ROOT="$_t_both" bash "$_t_script" --no-color 2>&1)
if printf '%s' "$_t_both_out" | grep -q 'served by mod_php' \
   && printf '%s' "$_t_both_out" | grep -q 'served by PHP-FPM'; then
    _t_ok 'mod_php and FPM side by side are both reported'
else
    _t_bad 'mod_php and FPM side by side are both reported' "$_t_both_out"
fi

# A PHP that matches no SAPI pattern gets said out loud. Silence in this
# section would leave the reader to guess the urgency.
_t_nosapi="$_t_tmp/nosapi"
_t_fake_root "$_t_nosapi" 8.3.35
_t_run 'a host with no detectable SAPI is told so' 1 'cannot tell how PHP is served' \
    env P2S_TEST_ROOT="$_t_nosapi" bash "$_t_script" --no-color
