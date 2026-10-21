# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/).

Changes to the vulnerability data (fixed versions, distribution packages) are
listed separately from code changes, because they change verdicts without
changing behaviour.

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

[1.2.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.2.0
[1.1.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.1.0
[1.0.0]: https://github.com/EXT-IT/php2shell-check/releases/tag/v1.0.0
