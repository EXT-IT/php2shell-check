# shellcheck shell=bash
# Sourced by tests/run_tests.sh. The temporary measures from php.net, section
# "If you cannot update immediately", and nothing besides them.
#
# Up to 1.6.0 this check contradicted that section in five places: it read
# memory_limit and never judged it, measured post_max_size against a quarter
# of memory_limit (a rule from no source, and dead code at memory_limit=-1),
# counted expose_php as one of the measures, attributed a value of "about 8"
# to the advisory for max_input_nesting_level, and summed all of it up as
# "[OK] advisory mitigations in place" although the section itself says these
# measures "do not make an installation safe". The cases below pin each of
# those down from the other side.
#
# Every host here runs PHP 8.4.27, which is fixed, so the exit code stays 0
# and nothing but the mitigation lines is under test.
# shellcheck disable=SC2154  # _t_script and _t_tmp come from run_tests.sh

# _mit_php PATH VERSION MEMORY POST UPLOAD UPLOAD_PROGRESS EXPOSE
_mit_php() {
    local _dst=$1
    mkdir -p "${_dst%/*}"
    cat > "$_dst" <<EOF
#!/bin/sh
# Prefixed variables so none of them shadows a standard environment variable.
case " \$* " in
    *PHP_VERSION*) printf '%s' '$2'; exit 0 ;;
    *ini_get*) ;;
    *) exit 0 ;;
esac
printf 'memory_limit=$3\npost_max_size=$4\nupload_max_filesize=$5\n'
printf 'max_input_nesting_level=64\n'
printf 'session.upload_progress.enabled=$6\nexpose_php=$7\nfatal_error_backtraces=n/a\n'
EOF
    chmod +x "$_dst"
}

# _mit_host NAME MEMORY POST UPLOAD UPLOAD_PROGRESS EXPOSE -> prints the root
_mit_host() {
    # ${_t_tmp:?} so an unset temp dir cannot turn this into rm -rf /mit-*
    local _root="${_t_tmp:?}/mit-$1"
    rm -rf "$_root"
    mkdir -p "$_root/etc"
    printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=trixie\n' \
        > "$_root/etc/os-release"
    _mit_php "$_root/usr/bin/php" 8.4.27 "$2" "$3" "$4" "$5" "$6"
    printf '%s' "$_root"
}

# ---------------------------------------------------------------------------
# M1: memory_limit=-1 with a huge post_max_size. The measured case that made
# this work necessary: the old quarter-rule required memory_limit > 0, so at
# -1 it never fired and 2048M came out as "[OK] advisory mitigations in
# place". The advisory names 8M and 32M as absolute values, so this is a
# missing measure.
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host unlimited-mem -1 2048M 2M 0 0)
_t_run 'M1 memory_limit=-1 does not excuse post_max_size=2048M' 0 \
    'WARN\] mitigation' env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M1 and it names both of the advisory values' 0 \
    'post_max_size \(8M without file uploads, 32M with; now 2048M\)' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs | grep -q 'OK \] mitigation'; then
    _t_bad 'M1 no mitigation line is ever an ok'
else
    _t_ok 'M1 no mitigation line is ever an ok'
fi
# The quarter-rule is gone, so its wording must be gone from the output too.
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs | grep -q 'quarter'; then
    _t_bad 'M1 the invented quarter-of-memory_limit rule is gone'
else
    _t_ok 'M1 the invented quarter-of-memory_limit rule is gone'
fi

# ---------------------------------------------------------------------------
# M2: a finite memory_limit. The advisory's first measure is memory_limit=-1,
# so a finite value is a missing measure, not a detail to print.
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host finite-mem 256M 8M 2M 0 0)
_t_run 'M2 a finite memory_limit is a missing measure' 0 \
    'memory_limit=-1 \(now 256M\)' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M2 and the hint says where to set it so applications cannot override' 0 \
    'php_admin_value in the FPM pool' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M2 and the hint says to restart every worker' 0 \
    'restart every worker' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# ---------------------------------------------------------------------------
# M3: "Keep upload_max_filesize below post_max_size."
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host upload-above-post -1 16M 32M 0 0)
_t_run 'M3 upload_max_filesize above post_max_size is a missing measure' 0 \
    'upload_max_filesize below post_max_size \(now 32M vs 16M\)' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

_mit_root=$(_mit_host upload-below-post -1 8M 2M 0 0)
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs | grep -q 'upload_max_filesize'; then
    _t_bad 'M3 upload_max_filesize below post_max_size is not flagged'
else
    _t_ok 'M3 upload_max_filesize below post_max_size is not flagged'
fi

# ---------------------------------------------------------------------------
# M4: all readable measures set. Info, never ok, and it carries the sentence
# the advisory opens that section with.
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host all-set -1 8M 2M 0 0)
_t_run 'M4 all measures set is info, not ok' 0 'INFO\] mitigation' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M4 and it says only an update is a complete solution' 0 \
    'nly an update is a complete solution' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M4 and that the measures do not make an installation safe' 0 \
    'do not make an installation safe' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
# info is counted nowhere and changes no exit code. That is the point: a
# mitigation is not a patch, and must not read like one in the summary.
_t_run 'M4 and info is counted nowhere' 0 '0 vulnerable, 0 undecided, 0 warnings' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# ---------------------------------------------------------------------------
# M5: expose_php. Not one of the advisory's measures, so it gets its own
# disclosure line (the shape the remote check already used) and must not tip
# the verdict of a host whose real measures are in place.
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host expose-on -1 8M 2M 0 1)
_t_run 'M5 expose_php=On is its own disclosure line' 0 'WARN\] disclosure' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M5 and the mitigation verdict stays info' 0 'INFO\] mitigation' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs \
    | grep -E 'mitigation|measures from the advisory' | grep -q 'expose_php'; then
    _t_bad 'M5 expose_php is not listed among the advisory measures'
else
    _t_ok 'M5 expose_php is not listed among the advisory measures'
fi

# ---------------------------------------------------------------------------
# M6: max_input_nesting_level. The advisory names nesting depth among the
# limits to enforce at the web server or proxy and gives no number for this
# PHP setting, so the "about 8" the script used to print was invented.
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host nesting -1 8M 2M 0 0)
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs | grep -q 'about 8'; then
    _t_bad 'M6 the invented "about 8" is gone'
else
    _t_ok 'M6 the invented "about 8" is gone'
fi
_t_run 'M6 and it says where the advisory wants nesting depth limited' 0 \
    'nesting depth to be limited at the web server or proxy level' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# ---------------------------------------------------------------------------
# M7: post_max_size between the two values. The script cannot know whether an
# installation needs file uploads, so it states both numbers instead of
# picking one, and this is context, not a missing measure.
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host post-between -1 16M 2M 0 0)
_t_run 'M7 a value between 8M and 32M is reported with both numbers' 0 \
    'only if this installation needs uploads' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M7 and it is not counted as a missing measure' 0 'INFO\] mitigation' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# ---------------------------------------------------------------------------
# M8: php.ini against the FPM pool. The advisory asks to "check that no pool,
# directory or application setting puts a finite limit back", and the ini
# probe alone cannot see a pool.
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host pool-contradiction -1 8M 2M 0 0)
mkdir -p "$_mit_root/etc/php/8.4/fpm/pool.d"
printf '[www]\nuser = www-data\npm.max_requests = 500\nphp_admin_value[memory_limit] = 256M\n' \
    > "$_mit_root/etc/php/8.4/fpm/pool.d/www.conf"
_t_run 'M8 a pool that puts a finite memory_limit back is a warning' 0 \
    'WARN\] forced-ini' env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M8 and the contradiction with php.ini is named' 0 \
    'php.ini reads memory_limit = -1, so the php.ini line in this report does not describe this scope' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# The other direction is the shape the advisory recommends -- php.ini finite,
# the pool forcing -1 where applications cannot override it. Naming it is
# right, warning about it would not be.
_mit_root=$(_mit_host pool-fixes-ini 256M 8M 2M 0 0)
mkdir -p "$_mit_root/etc/php/8.4/fpm/pool.d"
printf '[www]\nuser = www-data\npm.max_requests = 500\nphp_admin_value[memory_limit] = -1\n' \
    > "$_mit_root/etc/php/8.4/fpm/pool.d/www.conf"
_t_run 'M8 a pool that forces -1 is reported as the advisory shape' 0 \
    'INFO\] forced-ini' env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# A pool that switches session.upload_progress back on.
_mit_root=$(_mit_host pool-upprog -1 8M 2M 0 0)
mkdir -p "$_mit_root/etc/php/8.4/fpm/pool.d"
printf '[www]\nuser = www-data\npm.max_requests = 500\nphp_value[session.upload_progress.enabled] = 1\n' \
    > "$_mit_root/etc/php/8.4/fpm/pool.d/www.conf"
_t_run 'M8 a pool that re-enables session.upload_progress is a warning' 0 \
    'forces session.upload_progress.enabled = 1' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# An Apache vhost can do the same with php_admin_value.
_mit_root=$(_mit_host vhost-contradiction -1 8M 2M 0 0)
mkdir -p "$_mit_root/etc/apache2/sites-enabled"
printf '<VirtualHost *:80>\n  ServerName www.example.com\n  php_admin_value memory_limit 512M\n</VirtualHost>\n' \
    > "$_mit_root/etc/apache2/sites-enabled/000-default.conf"
_t_run 'M8 an Apache vhost that puts a finite memory_limit back is a warning' 0 \
    'forces memory_limit = 512M' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# nginx passes settings as a fastcgi_param, single-line form only.
_mit_root=$(_mit_host nginx-contradiction -1 8M 2M 0 0)
mkdir -p "$_mit_root/etc/nginx/conf.d"
printf 'server {\n  location ~ \\.php$ {\n    fastcgi_param PHP_ADMIN_VALUE "memory_limit=512M";\n  }\n}\n' \
    > "$_mit_root/etc/nginx/conf.d/site.conf"
_t_run 'M8 an nginx fastcgi_param that forces a finite memory_limit is a warning' 0 \
    'forces memory_limit = 512M' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

# A pool that forces nothing must stay silent.
_mit_root=$(_mit_host pool-clean -1 8M 2M 0 0)
mkdir -p "$_mit_root/etc/php/8.4/fpm/pool.d"
printf '[www]\nuser = www-data\npm.max_requests = 500\n' \
    > "$_mit_root/etc/php/8.4/fpm/pool.d/www.conf"
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs | grep -q 'forced-ini'; then
    _t_bad 'M8 a pool that forces nothing is not reported'
else
    _t_ok 'M8 a pool that forces nothing is not reported'
fi

# ---------------------------------------------------------------------------
# M10: padded values. "=" is the only separator in the probe output, so a
# value keeps any space around it, and three of the judgements compare it
# exactly. A padded "-1" must not come out as a finite limit.
# ---------------------------------------------------------------------------

_mit_root="${_t_tmp:?}/mit-padded"
rm -rf "$_mit_root"
mkdir -p "$_mit_root/etc" "$_mit_root/usr/bin"
printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=trixie\n' \
    > "$_mit_root/etc/os-release"
cat > "$_mit_root/usr/bin/php" <<'EOF'
#!/bin/sh
case " $* " in
    *PHP_VERSION*) printf '%s' '8.4.27'; exit 0 ;;
    *ini_get*) ;;
    *) exit 0 ;;
esac
printf 'memory_limit = -1 \npost_max_size = 8M \nupload_max_filesize = 2M \n'
printf 'max_input_nesting_level = 64 \nsession.upload_progress.enabled = 0 \n'
printf 'expose_php = 0 \nfatal_error_backtraces = n/a \n'
EOF
chmod +x "$_mit_root/usr/bin/php"
_t_run 'M10 a padded memory_limit=-1 still satisfies the measure' 0 'INFO\] mitigation' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs | grep -q 'memory_limit=-1 (now'; then
    _t_bad 'M10 a padded -1 is not reported as a finite limit'
else
    _t_ok 'M10 a padded -1 is not reported as a finite limit'
fi

# ---------------------------------------------------------------------------
# M9: RLIMIT_AS / RLIMIT_DATA. The advisory asks for a container or cgroup
# limit and says not to substitute these two, "as these can cause the
# vulnerable allocation failure".
# ---------------------------------------------------------------------------

_mit_root=$(_mit_host rlimit-unit -1 8M 2M 0 0)
mkdir -p "$_mit_root/etc/systemd/system/php8.4-fpm.service.d"
printf '[Service]\nLimitAS=2147483648\n' \
    > "$_mit_root/etc/systemd/system/php8.4-fpm.service.d/limits.conf"
_t_run 'M9 LimitAS in a systemd drop-in is a warning' 0 'WARN\] rlimit' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs
_t_run 'M9 and it quotes why the advisory rejects it' 0 \
    'can cause the vulnerable allocation failure' \
    env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs

_mit_root=$(_mit_host rlimit-infinity -1 8M 2M 0 0)
mkdir -p "$_mit_root/etc/systemd/system/php8.4-fpm.service.d"
printf '[Service]\nLimitAS=infinity\nLimitDATA=infinity\n' \
    > "$_mit_root/etc/systemd/system/php8.4-fpm.service.d/limits.conf"
if env P2S_TEST_ROOT="$_mit_root" bash "$_t_script" --no-color --no-logs | grep -q 'rlimit'; then
    _t_bad 'M9 LimitAS=infinity is not flagged'
else
    _t_ok 'M9 LimitAS=infinity is not flagged'
fi

# A running PHP process with a finite address-space limit, read from a fake
# /proc the way the process fallback is tested elsewhere.
_mit_root=$(_mit_host rlimit-proc -1 8M 2M 0 0)
_mit_proc="${_t_tmp:?}/mit-proc"
rm -rf "$_mit_proc"
mkdir -p "$_mit_proc/4711"
ln -s /usr/sbin/php-fpm8.4 "$_mit_proc/4711/exe"
{
    printf 'Limit                     Soft Limit           Hard Limit           Units\n'
    printf 'Max cpu time              unlimited            unlimited            seconds\n'
    printf 'Max address space         2147483648           2147483648           bytes\n'
    printf 'Max data size             unlimited            unlimited            bytes\n'
} > "$_mit_proc/4711/limits"
_t_run 'M9 a running PHP with a finite RLIMIT_AS is a warning' 0 'RLIMIT_AS=2147483648' \
    env P2S_TEST_ROOT="$_mit_root" P2S_PROC_ROOT="$_mit_proc" bash "$_t_script" --no-color --no-logs

printf 'Limit                     Soft Limit           Hard Limit           Units\nMax address space         unlimited            unlimited            bytes\nMax data size             unlimited            unlimited            bytes\n' \
    > "$_mit_proc/4711/limits"
if env P2S_TEST_ROOT="$_mit_root" P2S_PROC_ROOT="$_mit_proc" bash "$_t_script" --no-color --no-logs \
    | grep -q 'WARN\] rlimit'; then
    _t_bad 'M9 an unlimited PHP process is not flagged'
else
    _t_ok 'M9 an unlimited PHP process is not flagged'
fi
