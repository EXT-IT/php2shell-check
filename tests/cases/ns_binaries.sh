# shellcheck shell=bash
# Sourced by tests/run_tests.sh. PHP that runs in another mount namespace:
# a container, and only reachable through /proc/<pid>/root.
#
# The incident behind this file, measured on a Docker host on 2026-10-22:
# php:8.3.35-fpm was serving as pid 581758, readlink /proc/581758/exe gave
# /usr/local/sbin/php-fpm, that path does not exist in the host namespace, and
# the run reported "no PHP installation found in the usual locations and none
# running" with exit 0. Every case below is built so that a verdict taken from
# the HOST instead of from the container's own data comes out differently, and
# so that executing the container's binary would be visible: each fake binary
# writes a marker file when it runs, and the tests assert that it did not.
#
# shellcheck disable=SC2154  # _t_script and _t_tmp come from run_tests.sh

_ns_dir="${_t_tmp:?}/ns"
rm -rf "$_ns_dir"
mkdir -p "$_ns_dir"

# _ns_host NAME CODENAME -> prints a host root that has no PHP of its own
_ns_host() {
    local _r="$_ns_dir/$1-host"
    mkdir -p "$_r/etc"
    printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=%s\n' "$2" \
        > "$_r/etc/os-release"
    printf '%s' "$_r"
}

# _ns_bin PATH MARKER
# A binary that must never be executed by the script. It writes the marker
# file when it runs and answers every version probe with 9.9.9, so running it
# would be visible twice over: in the marker and in the verdict.
_ns_bin() {
    mkdir -p "${1%/*}"
    cat > "$1" <<EOF
#!/bin/sh
echo ran > '$2'
printf 'PHP 9.9.9 (cli)\n'
EOF
    chmod +x "$1"
}

# _ns_proc PROCROOT PID NSID CONTAINERROOT EXE
# One fake process: its exe link names the path inside the container, its
# ns/mnt link identifies the mount namespace, its root link is the container.
_ns_proc() {
    mkdir -p "$1/$2/ns"
    ln -sf "$5" "$1/$2/exe"
    ln -sf "mnt:[$3]" "$1/$2/ns/mnt"
    ln -sfn "$4" "$1/$2/root"
}

# _ns_environ PROCROOT PID VERSION   (the official images set PHP_VERSION)
_ns_environ() {
    printf 'PATH=/usr/local/bin\000PHP_VERSION=%s\000' "$3" > "$1/$2/environ"
}

# _ns_count NAME EXPECTED PATTERN ROOT PROC [PATH]
# How many report lines match. Used where the question is "once, not twice".
_ns_count() {
    local _got
    _got=$(env PATH="${6:-$PATH}" P2S_TEST_ROOT="$4" P2S_PROC_ROOT="$5" \
               bash "$_t_script" --no-color 2>&1 | grep -cE -- "$3")
    if [ "$_got" = "$2" ]; then
        _t_ok "$1"
    else
        _t_bad "$1 (found $_got, expected $2)"
    fi
}

# _ns_no_marker NAME MARKER
_ns_no_marker() {
    if [ -e "$2" ]; then
        _t_bad "$2 was executed: $1"
    else
        _t_ok "$1"
    fi
}

# ---------------------------------------------------------------------------
# N1/N2: the measured case. An official php image: source build under
# /usr/local, no package database, PHP_VERSION in the image environment.
# ---------------------------------------------------------------------------

_ns_mk_image() {   # NAME PHP_VERSION -> host root; proc is <name>-proc
    local _h _c _p
    _h=$(_ns_host "$1" trixie)
    _c="$_ns_dir/$1-ctr"; _p="$_ns_dir/$1-proc"
    mkdir -p "$_c/etc"
    printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_CODENAME=trixie\n' \
        > "$_c/etc/os-release"
    _ns_bin "$_c/usr/local/sbin/php-fpm" "$_ns_dir/$1-ran"
    _ns_proc "$_p" 581758 4026532701 "$_c" /usr/local/sbin/php-fpm
    _ns_environ "$_p" 581758 "$2"
    printf '%s' "$_h"
}

_ns_r=$(_ns_mk_image vuln 8.3.35)
_t_run 'N1 a container PHP reachable only through /proc/<pid>/root is found' 1 \
    'VULN\] php-binary +/usr/local/sbin/php-fpm' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/vuln-proc" bash "$_t_script" --no-color
_t_run 'N1 and the report says the find is from another namespace' 1 \
    'running in a container or other mount namespace, pid 581758' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/vuln-proc" bash "$_t_script" --no-color
_t_run 'N1 and it is judged, not just listed' 1 'PHP 8\.3\.35, fixed in 8\.3\.36' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/vuln-proc" bash "$_t_script" --no-color
if env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/vuln-proc" bash "$_t_script" --no-color \
   | grep -q 'no PHP installation found'; then
    _t_bad 'N1 the old "no PHP installation found" line is gone'
else
    _t_ok 'N1 the old "no PHP installation found" line is gone'
fi
_ns_no_marker 'N1 the container binary was not executed' "$_ns_dir/vuln-ran"

_ns_r=$(_ns_mk_image fixed 8.3.36)
_t_run 'N2 a patched container comes out clean' 0 'OK \] php-binary +/usr/local/sbin/php-fpm' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/fixed-proc" bash "$_t_script" --no-color
_ns_no_marker 'N2 the container binary was not executed' "$_ns_dir/fixed-ran"

# ---------------------------------------------------------------------------
# N3: the version from the headers of a source build, which the official
# images ship, when the process environment carries nothing.
# ---------------------------------------------------------------------------

_ns_r=$(_ns_host hdr trixie)
_ns_c="$_ns_dir/hdr-ctr"
mkdir -p "$_ns_c/usr/local/include/php/main"
printf '#define PHP_VERSION "8.4.26"\n#define PHP_VERSION_ID 80426\n' \
    > "$_ns_c/usr/local/include/php/main/php_version.h"
_ns_bin "$_ns_c/usr/local/sbin/php-fpm" "$_ns_dir/hdr-ran"
_ns_proc "$_ns_dir/hdr-proc" 4711 4026532702 "$_ns_c" /usr/local/sbin/php-fpm
_t_run 'N3 the version comes from the php headers of that root' 1 'PHP 8\.4\.26, fixed in 8\.4\.27' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/hdr-proc" bash "$_t_script" --no-color
_ns_no_marker 'N3 the container binary was not executed' "$_ns_dir/hdr-ran"

# ---------------------------------------------------------------------------
# N4: the container's own package database decides, not the host's. The
# container is Ubuntu noble with a backported 8.3.6; the host root is Debian
# trixie and the dpkg stub answers a DIFFERENT, unpatched version when it is
# asked without --admindir. So a verdict built on the host's data cannot come
# out ok here, and a verdict that ignores the container's codename cannot
# either (trixie:php8.3 has no fix data at all and would be "unknown").
# ---------------------------------------------------------------------------

_ns_mk_deb() {   # NAME PACKAGE_VERSION -> host root
    local _h _c _p
    _h=$(_ns_host "$1" trixie)
    _c="$_ns_dir/$1-ctr"; _p="$_ns_dir/$1-proc"
    mkdir -p "$_c/etc" "$_c/var/lib/dpkg" "$_ns_dir/stub"
    printf 'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nID=ubuntu\nVERSION_CODENAME=noble\n' \
        > "$_c/etc/os-release"
    : > "$_c/var/lib/dpkg/status"
    printf '%s' "$2" > "$_c/var/lib/dpkg/fake-version"
    _ns_bin "$_c/usr/bin/php8.3" "$_ns_dir/$1-ran"
    _ns_proc "$_p" 2024 4026532703 "$_c" /usr/bin/php8.3
    printf '%s' "$_h"
}

mkdir -p "$_ns_dir/stub"
cat > "$_ns_dir/stub/dpkg-query" <<'STUB'
#!/bin/sh
# Stands in for dpkg-query. With --admindir it answers from THAT database,
# which is the container's; without it from the host's, with an unpatched
# version. A verdict built on the wrong database is therefore visible.
_stub_admin=''
_stub_mode=''
for _stub_a in "$@"; do
    case "$_stub_a" in
        --admindir=*)     _stub_admin=${_stub_a#--admindir=} ;;
        -S)               _stub_mode=search ;;
        *source:Package*) _stub_mode=source ;;
        *Version*)        _stub_mode=version ;;
    esac
done
if [ -n "$_stub_admin" ] && [ -r "$_stub_admin/fake-version" ]; then
    _stub_ver=$(cat "$_stub_admin/fake-version")
else
    _stub_ver='8.3.6-0ubuntu0.24.04.1'
fi
case "$_stub_mode" in
    search)  echo 'php8.3-cli: /usr/bin/php8.3' ;;
    source)  printf '%s' 'php8.3' ;;
    version) printf '%s' "$_stub_ver" ;;
esac
STUB
chmod +x "$_ns_dir/stub/dpkg-query"

_ns_r=$(_ns_mk_deb debok 8.3.6-0ubuntu0.24.04.13)
_t_run 'N4 the container package database decides and says ok' 0 'OK \] php-binary +/usr/bin/php8\.3' \
    env PATH="$_ns_dir/stub:$PATH" P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/debok-proc" \
    bash "$_t_script" --no-color
_t_run 'N4 and it names the distribution fix of the container' 0 \
    'distribution fix from 8\.3\.6-0ubuntu0\.24\.04\.13' \
    env PATH="$_ns_dir/stub:$PATH" P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/debok-proc" \
    bash "$_t_script" --no-color
_ns_no_marker 'N4 the container binary was not executed' "$_ns_dir/debok-ran"

_ns_r=$(_ns_mk_deb debold 8.3.6-0ubuntu0.24.04.12)
_t_run 'N4b the package before the fix is vulnerable' 1 'VULN\] php-binary +/usr/bin/php8\.3' \
    env PATH="$_ns_dir/stub:$PATH" P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/debold-proc" \
    bash "$_t_script" --no-color
_t_run 'N4b and it names the version to install' 1 'fixed in 8\.3\.6-0ubuntu0\.24\.04\.13' \
    env PATH="$_ns_dir/stub:$PATH" P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/debold-proc" \
    bash "$_t_script" --no-color

# N4c: the host and the container carry the same package name at the same
# upstream number in a different patch state — php8.3-cli 8.3.6 is exactly
# that case on Ubuntu 24.04. Both verdicts have to appear: a dedupe that keys
# only on package plus PHP version would hide one behind the other.
_ns_r=$(_ns_mk_deb mixed 8.3.6-0ubuntu0.24.04.13)
mkdir -p "$_ns_r/usr/bin"
printf 'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nID=ubuntu\nVERSION_CODENAME=noble\n' \
    > "$_ns_r/etc/os-release"
cat > "$_ns_r/usr/bin/php8.3" <<'HOSTBIN'
#!/bin/sh
case "$*" in
    *PHP_VERSION*) printf '%s' '8.3.6' ;;
    *ini_get*) printf 'memory_limit=256M\npost_max_size=8M\nmax_input_nesting_level=8\nsession.upload_progress.enabled=0\nexpose_php=0\nfatal_error_backtraces=n/a\n' ;;
esac
HOSTBIN
chmod +x "$_ns_r/usr/bin/php8.3"
_ns_count 'N4c host and container package are both reported' 2 \
    'php-binary +/usr/bin/php8\.3' "$_ns_r" "$_ns_dir/mixed-proc" "$_ns_dir/stub:$PATH"
_t_run 'N4c the unpatched host package is vulnerable' 1 'VULN\] php-binary +/usr/bin/php8\.3$' \
    env PATH="$_ns_dir/stub:$PATH" P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/mixed-proc" \
    bash "$_t_script" --no-color
_t_run 'N4c the patched container package is ok' 1 \
    'OK \] php-binary +/usr/bin/php8\.3 \(running in a container' \
    env PATH="$_ns_dir/stub:$PATH" P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/mixed-proc" \
    bash "$_t_script" --no-color

# ---------------------------------------------------------------------------
# N5: no version anywhere in that root. "I do not know" (exit 2), not silence
# and not a guess — and above all not a run of the foreign binary.
# ---------------------------------------------------------------------------

_ns_r=$(_ns_host blind trixie)
_ns_c="$_ns_dir/blind-ctr"
mkdir -p "$_ns_c/etc"
_ns_bin "$_ns_c/usr/local/sbin/php-fpm" "$_ns_dir/blind-ran"
_ns_proc "$_ns_dir/blind-proc" 3131 4026532704 "$_ns_c" /usr/local/sbin/php-fpm
_t_run 'N5 a container whose version is unreadable is undecided' 2 '\?\? \] php-binary' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/blind-proc" bash "$_t_script" --no-color
_t_run 'N5 and it says why it did not ask the binary' 2 'does not run a binary out of a foreign root' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/blind-proc" bash "$_t_script" --no-color
_ns_no_marker 'N5 the container binary was not executed' "$_ns_dir/blind-ran"

# ---------------------------------------------------------------------------
# N6: no double reporting.
#   a) a busy FPM pool: many workers, one namespace, one binary -> one line
#   b) two different containers on the same path -> two lines, because they
#      are two installations and may be patched differently
#   c) a namespace the Docker/Podman check covers -> not reported here at all
# ---------------------------------------------------------------------------

_ns_r=$(_ns_mk_image pool 8.3.35)
for _ns_p in 581759 581760 581761; do
    _ns_proc "$_ns_dir/pool-proc" "$_ns_p" 4026532701 "$_ns_dir/pool-ctr" /usr/local/sbin/php-fpm
    _ns_environ "$_ns_dir/pool-proc" "$_ns_p" 8.3.35
done
_ns_count 'N6a four workers of one container are reported once' 1 \
    'php-binary +/usr/local/sbin/php-fpm' "$_ns_r" "$_ns_dir/pool-proc"

_ns_r=$(_ns_mk_image two 8.3.35)
mkdir -p "$_ns_dir/two-ctr2/etc"
cp "$_ns_dir/two-ctr/etc/os-release" "$_ns_dir/two-ctr2/etc/os-release"
_ns_bin "$_ns_dir/two-ctr2/usr/local/sbin/php-fpm" "$_ns_dir/two-ran2"
_ns_proc "$_ns_dir/two-proc" 777 4026532799 "$_ns_dir/two-ctr2" /usr/local/sbin/php-fpm
_ns_environ "$_ns_dir/two-proc" 777 8.3.36
_ns_count 'N6b two containers on the same path are reported twice' 2 \
    'php-binary +/usr/local/sbin/php-fpm' "$_ns_r" "$_ns_dir/two-proc"
_t_run 'N6b and each gets its own verdict' 1 'OK \] php-binary +/usr/local/sbin/php-fpm' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/two-proc" bash "$_t_script" --no-color

# N6c is a unit: _p2s_collect_runtime_ns only talks to a real runtime, so the
# list it fills is set by hand here and _p2s_check_binaries called directly.
# The functions come from the P2S_SOURCE_ONLY source in run_tests.sh.
_ns_r=$(_ns_mk_image covered 8.3.35)
_ns_out=$(
    _p2s_root=$_ns_r
    _p2s_proc="$_ns_dir/covered-proc"
    _p2s_runtime_ns=' mnt:[4026532701] '
    _p2s_check_binaries 2>&1
)
if printf '%s' "$_ns_out" | grep -q 'php-binary +/usr/local/sbin/php-fpm'; then
    _t_bad 'N6c a namespace the container check covers is not reported twice' "$_ns_out"
else
    _t_ok 'N6c a namespace the container check covers is not reported twice'
fi
if printf '%s' "$_ns_out" | grep -q 'no PHP installation found'; then
    _t_ok 'N6c and the host itself is still reported as having no PHP'
else
    _t_bad 'N6c and the host itself is still reported as having no PHP' "$_ns_out"
fi

# ---------------------------------------------------------------------------
# N7: neither the path list nor /proc shows anything. This case must stay
# exactly as it was: info, no counter, exit 0.
# ---------------------------------------------------------------------------

_ns_r=$(_ns_host quiet trixie)
mkdir -p "$_ns_dir/quiet-proc/12/ns"
ln -sf /usr/sbin/nginx "$_ns_dir/quiet-proc/12/exe"
_t_run 'N7 a host with no PHP anywhere is unchanged' 0 'no PHP installation found' \
    env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/quiet-proc" bash "$_t_script" --no-color

# ---------------------------------------------------------------------------
# N8: a container runtime runs, nothing could be asked about it, and no PHP
# turned up in its namespaces. Silence is what made the measured run green, so
# this is an unknown (exit 2), not an info.
# ---------------------------------------------------------------------------

for _ns_case in containerd-shim-runc-v2:containerd conmon:conmon crio:CRI-O \
                lxc-start:LXC systemd-nspawn:nspawn; do
    _ns_exe=${_ns_case%%:*}
    _ns_r=$(_ns_host "shim-$_ns_exe" trixie)
    mkdir -p "$_ns_dir/shim-$_ns_exe-proc/9/ns"
    ln -sf "/usr/bin/$_ns_exe" "$_ns_dir/shim-$_ns_exe-proc/9/exe"
    _t_run "N8 $_ns_exe without a queryable runtime is undecided" 2 '\?\? \] container' \
        env P2S_TEST_ROOT="$_ns_r" P2S_PROC_ROOT="$_ns_dir/shim-$_ns_exe-proc" \
        bash "$_t_script" --no-color
done
_t_run 'N8 and the line says what to do instead' 2 'lxc-attach' \
    env P2S_TEST_ROOT="$_ns_dir/shim-lxc-start-host" P2S_PROC_ROOT="$_ns_dir/shim-lxc-start-proc" \
    bash "$_t_script" --no-color
# A shim next to a container PHP that WAS judged needs no such line: the gap
# it warns about is not there.
_t_run 'N8 no such line when the PHP in that namespace was judged' 1 'VULN\] php-binary' \
    env P2S_TEST_ROOT="$_ns_dir/vuln-host" P2S_PROC_ROOT="$_ns_dir/vuln-proc" \
    bash "$_t_script" --no-color
mkdir -p "$_ns_dir/vuln-proc/9/ns"
ln -sf /usr/bin/containerd-shim-runc-v2 "$_ns_dir/vuln-proc/9/exe"
if env P2S_TEST_ROOT="$_ns_dir/vuln-host" P2S_PROC_ROOT="$_ns_dir/vuln-proc" \
       bash "$_t_script" --no-color | grep -q '?? \] container'; then
    _t_bad 'N8 a shim beside a judged container PHP adds no unknown line'
else
    _t_ok 'N8 a shim beside a judged container PHP adds no unknown line'
fi
