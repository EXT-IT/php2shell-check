# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/).

Changes to the vulnerability data (fixed versions, distribution packages) are
listed separately from code changes, because they change verdicts without
changing behaviour.

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
