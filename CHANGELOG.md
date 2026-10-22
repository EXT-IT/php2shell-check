# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/).

Changes to the vulnerability data (fixed versions, distribution packages) are
listed separately from code changes, because they change verdicts without
changing behaviour.

## [Unreleased]

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

### Added

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
