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

# ---------------------------------------------------------------------------
# The RPM counterpart, with an rpm stub in PATH. An RPM distribution backports
# at an unchanged upstream number too, but there the deciding part is the
# release, whose scheme every rebuilder sets differently — so below the
# upstream fix the changelog of the installed package decides. Modelled on
# AlmaLinux 9.8 and Rocky 9.8 as measured on 2026-10-22.
# ---------------------------------------------------------------------------

# _t_rpm_host DIR PHPVERSION RELEASE VENDOR CHANGELOG_NAMES_CVE(yes|no)
_t_rpm_host() {
    local _root=$1 _v=$2 _rel=$3 _vendor=$4 _cve=$5 _bin
    mkdir -p "$_root/usr/bin" "$_root/etc" "$_root/stub"
    printf 'PRETTY_NAME="AlmaLinux 9.8 (Olive Jaguar)"\nID=almalinux\n' > "$_root/etc/os-release"
    _bin="$_root/usr/bin/php"
    cat > "$_bin" <<INNER
#!/bin/sh
case "\$*" in
    *PHP_VERSION*) printf '%s' '$_v' ;;
    *ini_get*) printf 'memory_limit=256M\npost_max_size=8M\nmax_input_nesting_level=8\nsession.upload_progress.enabled=0\nexpose_php=0\nfatal_error_backtraces=n/a\n' ;;
esac
INNER
    chmod +x "$_bin"
    cat > "$_root/stub/rpm" <<INNER
#!/bin/sh
# Stands in for the rpm database. -qf answers for a path, -q --changelog for a
# package name, exactly as the script calls them.
_cve='$_cve'
case "\$*" in
    *--changelog*)
        echo "* Thu Aug 06 2026 Remi Collet <rcollet\@redhat.com> - $_v-1"
        echo "- rebase to $_v"
        if [ "\$_cve" = yes ]; then
            echo "* Wed Oct 21 2026 Andrew Lukoshko <alukoshko\@almalinux.org> - $_v-$_rel"
            echo "- Fix state corruption via bailout"
            echo "  CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)"
            echo "  CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)"
        fi ;;
    *NAME*VERSION*RELEASE*) printf '%s' 'php-cli-$_v-$_rel' ;;
    *NAME*)                 printf '%s' 'php-cli' ;;
    *VENDOR*)               printf '%s' '$_vendor' ;;
    *-qf*)                  exit 0 ;;
esac
INNER
    chmod +x "$_root/stub/rpm"
}

# An AlmaLinux build below the upstream fix whose changelog names the CVE.
_t_rpm_host "$_t_tmp/alma-backport" 8.3.33 '1.module_el9.8.0+328+1fdeb728.alma.1' AlmaLinux yes
_t_run 'a patched RPM below the upstream fix is ok' 0 'OK \] php-binary' \
    env PATH="$_t_tmp/alma-backport/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/alma-backport" bash "$_t_script" --no-color
_t_run 'and it says the changelog decided it' 0 'changelog names the CVE' \
    env PATH="$_t_tmp/alma-backport/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/alma-backport" bash "$_t_script" --no-color

# The same version without that entry, as Rocky 9.8 shipped it: undecided, and
# above all never ok.
_t_rpm_host "$_t_tmp/rocky-plain" 8.3.33 '1.module+el9.8.0+40285+1bc4c2b4' 'Rocky Enterprise Software Foundation' no
_t_run 'the same version without the entry stays undecided' 2 '\?\? \] php-binary' \
    env PATH="$_t_tmp/rocky-plain/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/rocky-plain" bash "$_t_script" --no-color
_t_run 'and it says why it could not decide' 2 'changelog does not name the CVE' \
    env PATH="$_t_tmp/rocky-plain/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/rocky-plain" bash "$_t_script" --no-color

# A branch upstream never fixed (8.0) is decidable this way and only this way.
_t_rpm_host "$_t_tmp/alma-eol" 8.0.30 '8.el9_8.alma.1' AlmaLinux yes
_t_run 'a backport on the EOL branch 8.0 is ok' 0 'OK \] php-binary' \
    env PATH="$_t_tmp/alma-eol/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/alma-eol" bash "$_t_script" --no-color

# A rebase to the upstream fix carries no CVE line and must still be ok.
_t_rpm_host "$_t_tmp/alma-rebase" 8.3.36 '1.module_el9.8.0+330+fdc30075' AlmaLinux no
_t_run 'a rebase to the upstream fix is ok without a changelog entry' 0 'OK \] php-binary' \
    env PATH="$_t_tmp/alma-rebase/stub:$PATH" P2S_TEST_ROOT="$_t_tmp/alma-rebase" bash "$_t_script" --no-color
