# shellcheck shell=bash
# Sourced by tests/run_tests.sh. Host layouts: where PHP lives on a real
# server, and which of the two verdict paths has to judge it.
#
# The split that matters: Debian and Ubuntu backport the fix and keep the
# upstream number, so there the PACKAGE version decides
# (_p2s_judge_deb_data / _p2s_distro_fixed). Everything else — source build,
# Plesk, cPanel, CloudLinux — carries real upstream numbers and is judged by
# _p2s_judge_upstream.
#
# A fake host has no package database of its own: dpkg-query, if it exists at
# all, knows nothing about a path under the fake root and answers empty, so
# these hosts travel the upstream path. The package table is therefore tested
# as a unit against _p2s_judge_deb_data here, and end to end with a
# dpkg-query stub in tests/cases/deb_endtoend.sh.
#
# shellcheck disable=SC2154  # _t_script and _t_tmp come from run_tests.sh

# ---------------------------------------------------------------------------
# Fake host builders
# ---------------------------------------------------------------------------

# _hl_os_release ROOT CODENAME PRETTY_NAME
_hl_os_release() {
    mkdir -p "$1/etc"
    printf 'PRETTY_NAME="%s"\nID=debian\nVERSION_ID="1"\nVERSION_CODENAME=%s\n' \
        "$3" "$2" > "$1/etc/os-release"
}

# _hl_php PATH VERSION [CLI_INI]
# A fake php binary. It answers the version probe and the advisory's ini_get
# probe, and it takes the ini values from the file named with -c, or from
# CLI_INI when no -c is given. That is what lets one host have a different
# mitigation state per SAPI.
_hl_php() {
    local _dst=$1 _ver=$2 _cli_ini=${3:-}
    mkdir -p "${_dst%/*}"
    cat > "$_dst" <<EOF
#!/bin/sh
# Variables are prefixed so none of them shadows a standard environment
# variable that the shell or gettext already owns.
_fake_ini='$_cli_ini'
_fake_prev=''
for _fake_arg in "\$@"; do
    [ "\$_fake_prev" = '-c' ] && _fake_ini=\$_fake_arg
    _fake_prev=\$_fake_arg
done
case " \$* " in
    *PHP_VERSION*) printf '%s' '$_ver'; exit 0 ;;
    *ini_get*) ;;
    *) exit 0 ;;
esac
_fake_upload=0
_fake_expose=0
if [ -n "\$_fake_ini" ] && [ -r "\$_fake_ini" ]; then
    _fake_v=\$(sed -n 's/^[[:space:]]*session.upload_progress.enabled[[:space:]]*=[[:space:]]*//p' "\$_fake_ini" | tail -n1)
    [ -n "\$_fake_v" ] && _fake_upload=\$_fake_v
    _fake_v=\$(sed -n 's/^[[:space:]]*expose_php[[:space:]]*=[[:space:]]*//p' "\$_fake_ini" | tail -n1)
    [ -n "\$_fake_v" ] && _fake_expose=\$_fake_v
fi
printf 'memory_limit=256M\npost_max_size=8M\nmax_input_nesting_level=8\n'
printf 'session.upload_progress.enabled=%s\nexpose_php=%s\nfatal_error_backtraces=n/a\n' \\
    "\$_fake_upload" "\$_fake_expose"
EOF
    chmod +x "$_dst"
}

# _hl_host NAME CODENAME PRETTY -> prints the root it created
_hl_host() {
    # ${_t_tmp:?} so a run with an unset temp dir cannot turn this into rm -rf /hl-*
    local _root="${_t_tmp:?}/hl-$1"
    rm -rf "$_root"
    mkdir -p "$_root"
    _hl_os_release "$_root" "$2" "$3"
    printf '%s' "$_root"
}

# ---------------------------------------------------------------------------
# A1-A6: the distribution package table (unit, see the header)
# ---------------------------------------------------------------------------

# _hl_deb CASE CODENAME SRCPKG PKGVERSION PHPVERSION EXPECTED
_hl_deb() {
    local _r
    _r=$(_p2s_judge_deb_data "$2" "$3" "$4" "$5" "$3")
    if [ "${_r%%|*}" = "$6" ]; then
        _t_ok "$1 $2 $3 $4 = $6"
    else
        _t_bad "$1 $2 $3 $4 = $6 (got ${_r%%|*}: ${_r#*|})"
    fi
}

_hl_deb A1 noble    php8.3 8.3.6-0ubuntu0.24.04.13 8.3.6   ok
_hl_deb A2 noble    php8.3 8.3.6-0ubuntu0.24.04.12 8.3.6   vuln
_hl_deb A3 jammy    php8.1 8.1.2-1ubuntu2.28       8.1.2   ok
# A3b: the release before the fix on the same branch must not come out ok.
_hl_deb A3b jammy   php8.1 8.1.2-1ubuntu2.27       8.1.2   vuln
_hl_deb A4 bookworm php8.2 8.2.34-1~deb12u1        8.2.34  vuln
_hl_deb A5 trixie   php8.4 8.4.27-1~deb13u1        8.4.27  ok
# A6: a release the data does not know, and a host whose os-release carries
# no codename at all. Neither may be answered with ok or vuln.
_hl_deb A6 questing php8.3 8.3.6-0ubuntu0.25.10.2  8.3.6   unknown
_hl_deb A6b ''      php8.3 8.3.6-1                 8.3.6   unknown
# A6c-A6f: releases past standard support, plus 26.10. On the ESM releases the
# same host is vuln without Ubuntu Pro and ok with it, at an unchanged
# upstream number — and branch 7.4 and older has no upstream fix at all, so
# only the package version can decide these rows.
_hl_deb A6c focal    php7.4 7.4.3-4ubuntu2.29      7.4.3   vuln
_hl_deb A6d focal    php7.4 7.4.3-4ubuntu2.29+esm5 7.4.3   ok
_hl_deb A6e trusty   php5   5.5.9+dfsg-1ubuntu4.29+esm18 5.5.9 ok
_hl_deb A6f stonking php8.5 8.5.9-0ubuntu2         8.5.9   vuln

# ---------------------------------------------------------------------------
# A7/A8: a source build in /usr/local
# ---------------------------------------------------------------------------

_hl_root=$(_hl_host src-vuln trixie 'Debian GNU/Linux 13 (trixie)')
_hl_php "$_hl_root/usr/local/bin/php" 8.3.35
_t_run 'A7 source build 8.3.35 is vulnerable' 1 'VULN\] php-binary +/usr/local/bin/php' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color
_t_run 'A7 and names the fixed release' 1 'PHP 8\.3\.35, fixed in 8\.3\.36' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color

_hl_root=$(_hl_host src-fixed trixie 'Debian GNU/Linux 13 (trixie)')
_hl_php "$_hl_root/usr/local/bin/php" 8.3.36
_t_run 'A8 source build 8.3.36 is clean' 0 'OK \] php-binary +/usr/local/bin/php' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color

# ---------------------------------------------------------------------------
# A9-A11: the control-panel layouts
# ---------------------------------------------------------------------------

_hl_root=$(_hl_host plesk bookworm 'Debian GNU/Linux 12 (bookworm)')
_hl_php "$_hl_root/opt/plesk/php/8.2/bin/php" 8.2.34
_t_run 'A9 Plesk php 8.2.34 is vulnerable' 1 'VULN\] php-binary +/opt/plesk/php/8\.2/bin/php' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color

_hl_root=$(_hl_host cpanel '' 'AlmaLinux 9.4 (Seafoam Ocelot)')
_hl_php "$_hl_root/opt/cpanel/ea-php83/root/usr/bin/php" 8.3.35
_t_run 'A10 cPanel ea-php83 8.3.35 is vulnerable' 1 'VULN\] php-binary +/opt/cpanel/ea-php83/root/usr/bin/php' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color

_hl_root=$(_hl_host cloudlinux '' 'CloudLinux 8.10 (Anatoly Levchenko)')
_hl_php "$_hl_root/opt/alt/php83/usr/bin/php" 8.3.36
_t_run 'A11 CloudLinux alt-php83 8.3.36 is clean' 0 'OK \] php-binary +/opt/alt/php83/usr/bin/php' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color

# ---------------------------------------------------------------------------
# A12: two branches side by side. One verdict per installation, and the worst
# one decides the exit code — a fixed 8.3 must not cover a vulnerable 8.1.
# ---------------------------------------------------------------------------

_hl_root=$(_hl_host multi jammy 'Ubuntu 22.04.5 LTS')
_hl_php "$_hl_root/usr/bin/php8.1" 8.1.33
_hl_php "$_hl_root/usr/bin/php8.3" 8.3.36
_t_run 'A12 the 8.1 installation is reported vulnerable' 1 'VULN\] php-binary +/usr/bin/php8\.1' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color
_t_run 'A12 the 8.3 installation is reported ok' 1 'OK \] php-binary +/usr/bin/php8\.3' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color
_t_run 'A12 summary counts both' 1 'Summary.*1 vulnerable' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color

# ---------------------------------------------------------------------------
# A17: CLI and FPM disagree about session.upload_progress.enabled. The SAPI
# that serves requests is the one that matters, so both must be reported
# separately — a clean CLI must never hide a warning FPM pool.
# ---------------------------------------------------------------------------

_hl_root=$(_hl_host sapi noble 'Ubuntu 24.04.3 LTS')
mkdir -p "$_hl_root/etc/php/8.3/cli" "$_hl_root/etc/php/8.3/fpm"
printf '[PHP]\nsession.upload_progress.enabled = 0\nexpose_php = 0\n' \
    > "$_hl_root/etc/php/8.3/cli/php.ini"
printf '[PHP]\nsession.upload_progress.enabled = 1\nexpose_php = 0\n' \
    > "$_hl_root/etc/php/8.3/fpm/php.ini"
_hl_php "$_hl_root/usr/bin/php8.3" 8.3.36 "$_hl_root/etc/php/8.3/cli/php.ini"
_t_run 'A17 the CLI ini is reported ok' 0 'OK \] mitigation +/usr/bin/php8\.3 \(CLI\)' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color
_t_run 'A17 the fpm ini is reported as a warning' 0 'WARN\] mitigation +/usr/bin/php8\.3 \(fpm php\.ini\)' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color
_t_run 'A17 and the warning names the missing setting' 0 'session\.upload_progress\.enabled=0' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color

# ---------------------------------------------------------------------------
# A18: branches that have no fixed release at all. "Up to date" is no help
# here, so the verdict must say that no fix exists rather than pointing at a
# version number that cannot be installed.
# ---------------------------------------------------------------------------

_hl_root=$(_hl_host eol bookworm 'Debian GNU/Linux 12 (bookworm)')
_hl_php "$_hl_root/usr/bin/php7.4" 7.4.33
_hl_php "$_hl_root/usr/bin/php8.0" 8.0.30
_hl_php "$_hl_root/usr/bin/php8.1" 8.1.33
for _hl_eol in 7.4.33:7\\.4 8.0.30:8\\.0 8.1.33:8\\.1; do
    _hl_v=${_hl_eol%%:*}
    _hl_b=${_hl_eol##*:}
    _t_run "A18 $_hl_v is vulnerable with a no-fix hint" 1 \
        "PHP $(printf '%s' "$_hl_v" | sed 's/\./\\./g'), branch $_hl_b has no fixed release yet" \
        env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color
done
_t_run 'A18 the hint says the backports are not out' 1 \
    'backports for 7\.4 to 8\.1 are announced but not out' \
    env P2S_TEST_ROOT="$_hl_root" bash "$_t_script" --no-color
