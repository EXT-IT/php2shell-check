# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/).

Changes to the vulnerability data (fixed versions, distribution packages) are
listed separately from code changes, because they change verdicts without
changing behaviour.

## [3.0.1] - 2026-10-23

### Fixed

- **On every busybox host, an unreadable Apache `maps` file fell back to
  `ok`** — the case 3.0.0 was released to close. The check told "no match"
  from "could not read" by grep's exit code, and that code is not portable:
  measured on `alpine:3.20`, busybox grep answers 1 for an unreadable path
  where GNU grep answers 2. Readability is now decided before grep runs, with
  `head -c 1`, which fails for an unreadable file and for a directory alike.
  Caught by the Alpine job of the test matrix.

## [3.0.0] - 2026-10-23

One contributed fix, and it changes an exit code the same way 2.0.0 did, which
is what makes this a major release. Thanks to Artifex Ignotvs
([#1](https://github.com/EXT-IT/php2shell-check/pull/1)).

### Breaking

- **A process whose executable cannot be inspected is reported as undecided
  (exit 2), where the check used to answer `ok`.** The stale-worker check reads
  `/proc/<pid>/exe` and silently skipped every process it could not read. Root
  inside a container does not mean access to a worker owned by another user:
  measured in an unmodified `php:8.3-fpm` container, the master runs as root
  and is readable, both workers run as `www-data` and are not, because Docker's
  default capability set has no `SYS_PTRACE`. The published 2.1.1 answered
  `[ OK ] process host`, "no PHP process runs a replaced binary", exit 0 —
  about two workers it had never looked at. It now answers `[ ?? ] process`,
  names how many processes it could not inspect, and the run is undecided.

  A run inside a container is therefore undecided unless the capability is
  granted. That is the truthful answer to "does the running code have the fix",
  and it is the same reasoning as 2.0.0: a pipeline that treats `0` as all
  clear will see `2` where it used to see `0`. The PowerShell edition has
  reported an uninspectable process as undecided since 2.1.0, so the two
  editions now agree.

- Zombies and processes that disappear mid-scan are ignored rather than counted
  as uninspectable, and an unreadable Apache `maps` file is told apart from one
  that simply has no PHP mapping (`grep` exit 2 versus 1).

### Added

- `tests/cases/stale_processes.sh`, eleven cases over the existing
  `P2S_PROC_ROOT` hook: current and deleted FPM executables, unreadable FPM and
  Apache evidence, both findings at once, an unrelated unreadable process, a
  vanished process and a zombie. The stale-process check reads its proc root
  through that hook now, which is what makes it testable at all.

## [2.1.1] - 2026-10-23

Everything in this release was found by the pipeline and the two Windows
branches of its matrix minutes after 2.1.0 went out, which is what they are
for. No verdict changes.

### Fixed

- **The file list of an installation came out in a different order depending on
  which PowerShell ran the check.** `Sort-Object` compares culture-aware, and
  the collation tables of Windows PowerShell (NLS) and PowerShell 7 (ICU) order
  punctuation differently: 5.1 printed `php.exe, php-cgi.exe`, 7 printed
  `php-cgi.exe, php.exe`. A report that reads differently depending on the
  interpreter cannot be compared between two runs. All five lists sort
  ordinally now.
- **Usage errors were wrapped in PowerShell's error decoration.**
  `Write-Error` breaks the line at the console width and adds a
  "powershell.EXE : ... + CategoryInfo" block, which on a narrow console cut
  the sentence in half. They are one line on stderr now, prefixed with the tool
  name, the way the shell edition answers.
- **The 2.1.0 release did not carry the PowerShell edition at all.** The
  release workflow predates it and attached only the shell script, while
  `SHA256SUMS` listed both -- so the permanent download link for
  `php2shell-check.ps1` answered 404 and the checksum file pointed at a file
  that was not there. Both are attached, and an existing release has its assets
  synced instead of being skipped.
- The CI workflow was invalid as a whole: a step's `shell` key is not a place
  where an expression may be used, so `shell: ${{ matrix.shell }}` stopped
  every job in the file from starting. Neither a YAML parse nor yamllint can
  see this.

### Changed

- The README leads with one line to copy per platform, for a server and for a
  website alone, and keeps 129 of its 492 lines open; the rest is folded. The
  Windows line writes the script to the temp directory, runs it and deletes it,
  because the usual `iex "& { $(irm ...) }"` form ends the whole session when
  the script exits -- measured, which costs an administrator the console window
  and the result with it.
- A red Windows job used to report nothing but "failure": the log needs a token
  and the jobs API gives only step names. Every failing case is repeated as an
  annotation now, which is served without a token.

## [2.1.0] - 2026-10-23

### Added

- `php2shell-check.ps1`, a PowerShell edition for Windows servers. Windows is
  the one platform where the version number decides on its own: the php.net
  builds carry the real upstream version, so the backport trap that the whole
  shell edition is built around does not exist there. Everything else does not
  carry over at all — there is no package database to ask, and `applicationHost.config`
  decides which of several installed binaries actually answers a request. That
  is why this is a second script and not a flag on the first one. Checks:
  installations under the paths the Windows installers use, judged by the
  version resource in the file; the IIS FastCGI entries and handler mappings,
  including the pipe-separated `scriptProcessor` form; running processes, read
  from the file on disk so an application pool still serving the old binary is
  visible; a renamed but still loaded DLL and a rename queued in
  `PendingFileRenameOperations`; the ini settings and the advisory's temporary
  measures; and the same URL checks as the shell edition, with the same options
  and the same exit codes. It never starts a PHP binary: versions come out of
  the version resource, settings out of the ini files on disk. Both option
  spellings work, the PowerShell one and the shell one, so a fleet script does
  not have to know which host it is talking to; `--origin` is refused with a
  usage error instead of being dropped, because dropping it would turn the
  address into another target.
- `tests/run_tests.ps1`, and a CI job that runs it on Windows under both
  Windows PowerShell 5.1 and PowerShell 7. 5.1 is the target, because that is
  what a Windows Server has before anyone installs anything.
- `tests/data_parity.py`, which compares the vulnerability data of the two
  editions and fails on the first number that drifts. Two files carrying the
  same table is the one thing no run of either can catch: a Linux run never
  reads the PowerShell table, a Windows run never reads the shell one, and both
  would pass their own tests while giving different verdicts for the same PHP.

### Changed

- The shell edition is 2.1.0 with no change to its behaviour. A release ships
  both files, and a pair of version numbers that drift apart makes it
  impossible to say afterwards which combination was measured.

### Measured, and the limits that came out of it

Windows Server 2022, IIS 10, PHP 8.3.35 and 8.3.36 side by side, 2026-10-22
and 2026-10-23. Two of these only showed up once the tests ran on the real
thing, and both were wrong in the direction that matters:

- **A host with no `php.ini` at all came out undecided although it was fully
  patched.** The missing file was reported as "the measures could not be
  read", and any undecided line sets exit 2. But the absence of every
  candidate file is itself a measurement: PHP then runs on its compiled
  defaults, so the measures are simply not set. That is a warning, the same as
  on Linux, and it leaves the patch verdict alone.
- **The measures were reported per php.ini, not per installation.** On the
  test server `C:\php\8.3.36` served every request without an ini of its own
  while `C:\php\8.3.35` had one, and the report printed the settings of the
  installation that was not serving while saying nothing about the one that
  was. The missing file is now named per installation, and the host-wide line
  is gone.
- **A file without a version resource does not answer with empty properties,
  it answers `0.0.0.0`.** The verdict stayed undecided either way, but for the
  wrong reason — "branch 0.0 is not covered by the advisory data" instead of
  "no readable version resource". A zero version now reads as nothing there.

The limits that stand:

- NTFS tunneling is on by default and hands a replaced file the creation time
  of the file it replaced. So a timestamp is not evidence that an update
  happened, and the script judges by the version resource alone. The version
  resource is present in `php.exe`, `php-cgi.exe` and `php8.dll` alike; a build
  without one is *undecided*.
- `applicationHost.config` is readable by SYSTEM and Administrators only. An
  unelevated run reports the gap rather than skipping the IIS part silently.
- Pointing IIS at the new PHP leaves the running worker on the old binary until
  the pool recycles, which is what the process check is for.
- Apache and nginx on Windows are not parsed. Their binaries are found and
  judged; the link from a site to a binary is missing.

## [2.0.0] - 2026-10-22

Three ways to a green result that said nothing, found by checking the script
against its own sources and measuring the cases on a test host. Every one of
them is a changed exit code, which is what makes this a major release: a
pipeline that treats `0` as "all clear" will now see `2` where it used to see
`0`. Nothing about a *vulnerable* verdict changed.

### Breaking

- A run that judged no PHP runtime is *undecided* (exit 2), not clean.
  Measured before the change on a macOS host, where the local checks cannot
  run at all: "Summary 0 vulnerable, 0 undecided, 0 warnings, 0 ok / NO
  VULNERABLE PHP FOUND", exit 0. The lines that say "there was nothing here to
  look at" were `info`, and `info` is counted nowhere. The summary now counts
  judged runtimes separately from statuses, because a host with no PHP still
  collects `ok` lines from the AppArmor and process checks and therefore
  looked examined.
- "No PHP installation found in the usual locations and none running" is
  *undecided*, not informational. It means the known paths hold nothing, which
  is not the same as this host running no PHP.
- A website whose header announces a patched version is *undecided*, not `ok`.
  `X-Powered-By` is self-declared: the application, a cache or a proxy with a
  different PHP behind it can set it. The prose in the same output already
  said the run "cannot confirm a patch level" while the exit code said clean —
  the prose was right. A version below the fix is still a finding, from a
  header too: if that header lies, it only costs a look.
- The `mitigation` check no longer answers `ok`. See the entry below.

### Fixed

- A PHP that runs in a container was invisible to the process fallback, and
  that fallback is the last line against a "no PHP found" on a host that is
  serving PHP right now. `readlink /proc/<pid>/exe` returns the path inside
  the container, the old `[ -f "$path" ]` test fails in the host namespace, and
  the find was thrown away. Measured on a Docker host on 2026-10-22:
  `php:8.3.35-fpm` serving as pid 581758, `php2shell-check.sh --no-containers`
  answered "no PHP installation found in the usual locations and none running"
  and exited 0. The binary is now read through `/proc/<pid>/root`, which
  reaches every runtime that gives its payload a mount namespace — rootless
  Docker of another user, containerd and nerdctl, Kubernetes, LXC and LXD,
  systemd-nspawn, Snap, a chroot — with one path and without asking any of
  them. The report marks such a find as coming from another mount namespace.
- The verdict for such a find is built from that root's own data: its
  `/etc/os-release` for the codename and its `/var/lib/dpkg` for the package
  version, read with the host's `dpkg-query --admindir`. Judging a container by
  the host's package database is the mistake 1.4.0 fixed for the Docker path,
  and the process fallback could make it just as easily.
- Which process belongs to the host and which to a container is decided by the
  mount namespace, not by a file test. An LXC container with `/usr/bin/php8.3`
  on a host that also has `/usr/bin/php8.3` was otherwise judged by the host's
  package and then dropped by the dedupe list.

### Changed

- The `mitigation` check follows php.net, section "If you cannot update
  immediately", instead of contradicting it in five places. Measured before
  the change: a host with `memory_limit=-1` and `post_max_size=2048M` was
  reported as `[OK] advisory mitigations in place`.
  - `memory_limit` is judged. It is the first measure in that section
    (`-1`, "preferably in a way applications can't override"), and the check
    read the value and never looked at it. `-1` satisfies the measure, a
    finite value is a missing one.
  - `post_max_size` is measured against the two absolute values the section
    names: 8M for applications that don't require file uploads, 32M if uploads
    are necessary. The old rule — below a quarter of `memory_limit` — stood in
    no source and was dead code at `memory_limit=-1`, because its condition
    required a positive limit. Up to 8M satisfies the section either way,
    above 32M fails it either way, and a value in between is reported with
    both numbers: the script cannot know whether an installation needs
    uploads, so it does not decide that silently.
  - `upload_max_filesize` is read and checked against `post_max_size`, which
    the section asks for and the probe did not even collect.
  - `expose_php` is no longer counted as one of the advisory's measures. It is
    not in that section, it decides whether the version is in the response
    headers rather than whether the bug can be reached, and counting it tipped
    the verdict of hosts whose real measures were all in place. It now gets
    its own `disclosure` line, the same shape the remote check already used.
  - `max_input_nesting_level` no longer claims the advisory asks for "about
    8". The section names no value for that setting; it asks for nesting depth
    to be limited at the web server or proxy level, and that is what the line
    now says.
  - The verdict for a host with every readable measure in place is `info`, not
    `ok`. The section opens with "while only an update is a complete solution,
    the following measures reduce exposure to specific attack paths but do not
    make an installation safe", and that sentence is now in the output.
    `info` is counted nowhere and changes no exit code, which is the point.
  - The hints name where the section wants each setting applied
    (`php_admin_value` in the FPM pool or the Apache configuration) and say to
    restart every worker, which no hint said before.
- `pm.max_requests` is no longer presented as a temporary mitigation. It is
  not in the advisory; the line stays, the wording says so.

### Added

- `php_admin_value` / `php_value` in FPM pools, in the Apache configuration
  and as a single-line `fastcgi_param PHP_VALUE` / `PHP_ADMIN_VALUE` in the
  nginx configuration. The ini probe reads `php.ini` and `PHP_INI_SCAN_DIR`
  and was blind to exactly the place the advisory asks for the setting to be
  made. A pool or vhost that contradicts `php.ini` is reported as a warning
  naming both values, so the `php.ini` line in the report cannot be read as
  covering that scope. A pool that forces `memory_limit=-1` while `php.ini` is
  finite is the shape the advisory recommends and is reported as info.
  Read line by line, no configuration parser — README lists what that misses.
- `RLIMIT_AS` / `RLIMIT_DATA` on PHP, read from `/proc/<pid>/limits` of a
  running PHP process and from `LimitAS=` / `LimitDATA=` in the systemd units
  and drop-ins that start PHP. The advisory asks for a container or cgroup
  limit and says not to substitute these two, "as these can cause the
  vulnerable allocation failure", so a finite one is a warning.
- A container runtime that is running while no `docker` or `podman` command
  exists to ask about it (`containerd-shim*`, `conmon`, `crio`, `lxc-start`,
  `systemd-nspawn`) gets an *undecided* line of its own instead of silence —
  but only when no PHP turned up in those namespaces either.

### Security

- Nothing out of a foreign root is executed. The version of a containerised
  PHP is read from data only: the container's package database, `PHP_VERSION`
  in the process environment (which the official `php`, `wordpress` and
  FrankenPHP images set), or `main/php_version.h` of a source build. Running
  the container's own binary would have been one line shorter and did answer
  on the measured host, but it means starting someone else's image payload as
  root *outside* that container's namespaces, cgroups, seccomp filter and
  AppArmor profile — and the answer would not even be trustworthy, because the
  ELF interpreter and library paths in that binary resolve against the host
  root. Where no version can be read, the line is *undecided*. The
  `mitigation` check, which needs `php -r`, is therefore skipped for these
  finds; the README states that limit.


## [1.6.0] - 2026-10-22

Built from two measured runs on a test host: an Ubuntu 26.04 matrix (mod_php
and FPM, patched and unpatched, with and without a restart, a root pool) and a
`php-cgi` plus FrankenPHP matrix. Both the Ubuntu 24.04 and the Ubuntu 22.04
before/after state were re-measured for this release.

### Added

- `php-cgi` and FrankenPHP are found and judged. php.net names both under
  "Who is at risk" and the script ignored them. `php-cgi` rejects `-r`, so its
  version comes from `-v`; FrankenPHP links PHP into its own binary, so the
  version comes from `frankenphp version` — anchored on `PHP `, because the
  first number in that line is FrankenPHP's own. `/usr/lib/cgi-bin/php*` and
  both binaries are in the path list and in the process list.
- `sapi` reports every way a host serves PHP, not just the first one found. A
  control-panel host carries mod_php and FPM side by side, and that
  combination is what decides the urgency.
- `sapi` says so when it cannot tell how PHP is served, instead of leaving the
  section out. Silence in that section left the reader to guess.
- A FrankenPHP container without a `php` CLI is judged through its own binary
  instead of being skipped.
- RPM systems get a second way to a definite verdict: if the version is below
  the upstream fix, the changelog of the installed package decides. An RPM
  distribution backports at an unchanged upstream number just like Debian
  does, but there the deciding part is the release, and every rebuilder sets
  that scheme differently, so a version table cannot be kept correct.
  Measured on AlmaLinux 9.8: `php-cli-8.3.33-1.module_el9.8.0+328+1fdeb728.alma.1`
  is patched while `8.3.33` is below the upstream `8.3.36`, and the same holds
  for branches 8.0 and 8.1, which have no upstream fix at all. A missing entry
  decides nothing, because the 8.3.36 and 8.2.35 rebases are fixed through
  their version and name no CVE.

### Changed

- The FPM wording was wrong and is corrected. GHSA-6wmf-4rv5-p3rp validated
  the session-lifecycle RCE "against mod_php and FPM"; only the startup
  sequence of CVE-2026-109618 is limited by FPM exiting the child. The line
  was an informational note that read as an all-clear and is now a warning.
- FrankenPHP's note follows the advisory: no equivalent early configuration
  consumer in its default configuration, which the advisory explicitly does
  not call immune.
- The same package in two paths (Debian ships the cgi build as
  `/usr/bin/php-cgi8.4` and `/usr/lib/cgi-bin/php8.4`) is reported once.
- The `cgi` SAPI is decided by the SAPI's own `php.ini` or the cgi-bin wiring,
  never by the presence of a `php-cgi` binary. On RHEL and AlmaLinux the
  `php-cli` package installs `/usr/bin/php-cgi`, and the official FrankenPHP
  image ships one as well, so a host or container with nothing but the command
  line interpreter was reported as served through CGI.

### Vulnerability data

- Ubuntu 26.10 (php8.5): `8.5.9-0ubuntu2.1`.
- The four ESM releases, verified against the Ubuntu CVE page: 20.04
  `7.4.3-4ubuntu2.29+esm5`, 18.04 `7.2.24-0ubuntu0.18.04.17+esm14`, 16.04
  `7.0.33-0ubuntu0.16.04.16+esm22`, 14.04 `5.5.9+dfsg-1ubuntu4.29+esm18`. They
  need Ubuntu Pro; without it the host stays below them and is reported
  vulnerable, which is the truthful answer.
- `5.5.9`, `7.0.33`, `7.2.24`, `7.4.3` and `8.5.9` added to the frozen numbers
  a remote banner cannot be judged by.

## [1.5.0] - 2026-10-21

Built from a container case matrix on a test host: official Debian-based and
Alpine images, `wordpress:latest`, Ubuntu and Debian with distribution PHP, a
stopped container, a container without PHP and one without a shell.

### Added

- `sapi`: how PHP is served, on the host and inside every container. The
  advisory demonstrates a complete unauthenticated exploit against mod_php
  and reports none for PHP-FPM, which is what decides the order of patching.
  mod_php is a warning, FPM an informational line with that caveat.
- Stopped containers whose image ships a vulnerable PHP are reported as a
  warning: they come back on the next start. The version is read from the
  image environment, so this costs no exec.
- `fpm-pool` flags a pool running as `root`: code execution through this bug
  would then be root code execution.

### Changed

- Debian 12 (php8.2) is no longer listed as unfixed: the fix shipped as
  `8.2.35-1~deb12u1` (DLA-4848-1).
- README states that Podman shares the Docker code path but is unverified.

## [1.4.0] - 2026-10-21

Found by building a test environment with three containers: a vulnerable
`php:8.3.35-apache`, a patched Debian 13 with php8.4 and an Ubuntu 24.04 with
php8.3-fpm, whose `php -v` prints 8.3.6 before and after the fix.

### Fixed

- A Debian or Ubuntu based container was judged by `PHP_VERSION` alone, so a
  container carrying the backported fix (`8.3.6-0ubuntu0.24.04.13`) was
  reported as vulnerable. Containers are now judged by the package database
  inside them, the same way the host is.
- The Debian version comparison no longer depends on `dpkg` being installed.
  Without it every comparison failed and reported a patched package as
  vulnerable, which happens on any non-Debian host running Debian containers.
  The fallback walks the version in digit and non-digit segments with `~`
  sorting first, and is cross-checked against `dpkg` wherever dpkg exists.
- Inside a container only the CLI `php.ini` was read. The SAPI that serves
  requests has its own, and that is the one that decides whether the advisory
  mitigations are in place.

## [1.3.0] - 2026-10-21

The theme of this release is not claiming more than the script can know.

### Changed

- A website whose patch level cannot be determined is now **undecided**
  (exit 2), not "no vulnerable PHP found" (exit 0). That covers a site
  without a version header, an edge that answers with a block page, and a
  version number that distributions freeze while backporting. Hiding
  `X-Powered-By` no longer produces a green result.
- Every run ends with a "How reliable this is" block: a run on the host
  states that the versions were read from the system itself, a run against
  websites states that it cannot confirm a patch level and names the command
  to run on the server.
- `--help` and the README say up front that a definite answer comes from
  running the script on the server.

### Added

- `php-binary` also covers every PHP that is currently running, taken from
  the process list. A build in an unusual path (`/opt/php-8.3/bin/php`, a
  vendor bundle) used to end up as "no PHP installation found".
- `php-level`: states why a site could not be judged from outside.
- PHP is now recognised without a version from PHPSESSID, WordPress,
  Laravel, Drupal, Plesk and LiteSpeed signals, so "nothing visible" and
  "PHP is here but silent" are no longer the same result.
- `--json` carries a `scope` object: host checked, run as root, URLs checked
  and how many of them stayed undecided.

### Fixed

- A blocked edge response no longer counts as "the headers do not reveal the
  version": the site was never reached.

## [1.2.1] - 2026-10-21

### Fixed

- The WAF and DNS checks now describe the host that answers last. Before, a
  Cloudflare-proxied apex that redirects to an unproxied `www.` host was
  reported as "proxied through Cloudflare", although the page itself came
  straight from the origin. That case is now a warning of its own, and the
  followed redirect is listed.

## [1.2.0] - 2026-10-21

From testing against real-world sites (shared hosting, Cloudflare, sites
without a certificate): most "no answer" results in 1.1.0 were TLS problems,
not dead sites.

### Added

- `tls`: a URL given without a scheme falls back to plain HTTP on the same
  host when HTTPS fails (common on shared hosting without a certificate for
  the name). A certificate that does not match the name no longer stops the
  check; the headers are read without verification and the problem is
  reported.
- `blocked`: a Cloudflare block or challenge page (HTTP 403/429/503) is
  reported as such and no longer counted as "no PHP version in the headers".

### Changed

- "No HTTP answer" now names the reason: DNS, connection refused, timeout,
  TLS handshake or certificate.
- Connect timeout of 8 s per request.

## [1.1.0] - 2026-10-21

### Changed

- Redirects are followed only while they stay on the host you named or its
  `www.` variant. A redirect to another host is reported and not followed, so
  the script never sends a request to a system you did not name.
- At most 10 URLs per run; arguments that look like address ranges
  (`203.0.113.0/24`) are refused. The tool checks your own sites and is not a
  scanner.

### Added

- `access`: a redirect to a Cloudflare Access login is recognised.
- `redirect`: redirects to other hosts are listed.

## [1.0.0] - 2026-10-21

### Added

- Local checks: PHP binaries from distribution packages (dpkg, rpm), Plesk,
  cPanel EasyApache, CloudLinux alt-php, Remi, LiteSpeed and `/usr/local`
  builds; PHP inside running Docker and Podman containers.
- Backport-aware verdicts for Debian and Ubuntu packages.
- Temporary mitigations from the advisory, read from the CLI and, on Debian
  layouts, from the FPM and Apache `php.ini`; `pm.max_requests` in FPM pools.
- PHP processes still running a replaced binary after an update.
- AppArmor / SELinux status, web ports listening on all interfaces,
  Cloudflare Tunnel.
- Count of memory-limit fatal errors in current web server and container logs.
- Remote checks: PHP version disclosure via `X-Powered-By`, WAF/CDN detection
  (Cloudflare by header and IP range, Sucuri, Imperva, CloudFront, Azure Front
  Door, Akamai, Fastly, BunnyCDN), DNS records outside Cloudflare, optional
  direct-origin test with `--origin`.
- `--json` output, exit codes 0/1/2/3, `--remote-only` on macOS (bash 3.2).

### Vulnerability data as of 2026-10-21

- Upstream fixes: 8.2.35, 8.3.36, 8.4.27, 8.5.12. No release yet for 7.4 to 8.1.
- Ubuntu 22.04 `8.1.2-1ubuntu2.28`, Ubuntu 24.04 `8.3.6-0ubuntu0.24.04.13`,
  Ubuntu 26.04 `8.5.4-0ubuntu1.5`, Debian 13 `8.4.27-1~deb13u1` (DSA-6574-1).
- Debian 12 (php8.2): marked vulnerable, no fix published yet.

[1.5.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.5.0
[1.4.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.4.0
[1.3.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.3.0
[1.2.1]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.2.1
[1.2.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.2.0
[1.1.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.1.0
[1.0.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.0.0
