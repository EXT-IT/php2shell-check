# shellcheck shell=bash
# Sourced by tests/run_tests.sh. The flagship case end to end: an Ubuntu host
# whose php -v says 8.3.6 before and after the fix, judged by package version.
# A dpkg-query stub in PATH stands in for the package database.
# shellcheck disable=SC2154  # _t_script and _t_tmp come from run_tests.sh

# _t_deb_host DIR PKGVERSION -> fake noble host plus a dpkg stub
_t_deb_host() {
    local _root=$1 _pkgver=$2 _bin
    mkdir -p "$_root/usr/bin" "$_root/etc" "$_root/stub"
    printf 'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nVERSION_CODENAME=noble\nID=ubuntu\n' > "$_root/etc/os-release"
    _bin="$_root/usr/bin/php8.3"
    cat > "$_bin" <<'INNER'
#!/bin/sh
case "$*" in
    *PHP_VERSION*) printf '%s' '8.3.6' ;;
    *ini_get*) printf 'memory_limit=256M\npost_max_size=8M\nmax_input_nesting_level=8\nsession.upload_progress.enabled=0\nexpose_php=0\nfatal_error_backtraces=n/a\n' ;;
esac
INNER
    chmod +x "$_bin"
    cat > "$_root/stub/dpkg-query" <<INNER
#!/bin/sh
# Stands in for the package database of a noble host.
case "\$*" in
    *-S*)  echo "php8.3-cli: \$3" ;;
    *source:Package*) printf '%s' 'php8.3' ;;
    *Version*) printf '%s' '$_pkgver' ;;
esac
INNER
    chmod +x "$_root/stub/dpkg-query"
    cp "$_root/stub/dpkg-query" "$_root/stub/dpkg" 2>/dev/null
    # dpkg itself is only used for comparing; the built-in fallback is tested
    # separately, so the stub must not pretend to be dpkg.
    rm -f "$_root/stub/dpkg"
}

_t_deb_host "$_t_tmp/noble-ok" 8.3.6-0ubuntu0.24.04.13
_t_run 'patched Ubuntu package is ok although php -v says 8.3.6' 0 'OK \] php-binary' \
    env PATH="$_t_tmp/noble-ok/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/noble-ok" bash "$_t_script" --no-color
_t_run 'and it names the distribution fix' 0 'distribution fix from 8.3.6-0ubuntu0.24.04.13' \
    env PATH="$_t_tmp/noble-ok/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/noble-ok" bash "$_t_script" --no-color

_t_deb_host "$_t_tmp/noble-old" 8.3.6-0ubuntu0.24.04.12
_t_run 'the package before the fix is vulnerable' 1 'VULN\] php-binary' \
    env PATH="$_t_tmp/noble-old/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/noble-old" bash "$_t_script" --no-color
_t_run 'and it names the version to install' 1 'fixed in 8.3.6-0ubuntu0.24.04.13' \
    env PATH="$_t_tmp/noble-old/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/noble-old" bash "$_t_script" --no-color

# Without the package database the same host falls back to the upstream
# number, and 8.3.6 is below 8.3.36, so it must not come out clean.
_t_run 'without a package database it is not called clean' 1 'VULN\] php-binary' \
    env P2S_TEST_ROOT="$_t_tmp/noble-ok" bash "$_t_script" --no-color
