<div align="center">

# php2shell-check

**Is this server still exposed to php2shell (CVE-2026-109618, CVE-2026-109619)?**

[![CI](https://img.shields.io/github/actions/workflow/status/EXT-IT/php2shell-check/ci.yml?branch=main&label=CI)](https://github.com/EXT-IT/php2shell-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.6.0-green.svg)](CHANGELOG.md)
[![Data](https://img.shields.io/badge/vulnerability%20data-2026--10--21-orange.svg)](#keeping-the-data-current)
[![Maintained by EXT IT GmbH](https://img.shields.io/badge/maintained%20by-EXT%20IT%20GmbH-0a4f7a.svg)](https://ext-it.tech)

</div>

On Ubuntu 24.04, `php -v` prints `PHP 8.3.6` before the fix and after it.
Canonical backports security patches and keeps the version number, so the
number that every quick check looks at tells you nothing. The patched package
is `8.3.6-0ubuntu0.24.04.13`, and only the package database knows whether you
have it. Your WordPress container, meanwhile, ships its own PHP that `apt`
never sees.

`php2shell-check.sh` looks in both places, plus Plesk, cPanel, CloudLinux and
hand-built PHP, and gives one verdict per PHP runtime. It is read-only: it
reads package databases, asks each PHP binary for its version and settings,
and sends one ordinary GET request to each URL you give it, following
redirects only on that same host. No exploit traffic, nothing written to
disk.

> **Run it on the server.** That is the only way to get a definite answer.
> There the script reads the real versions of every PHP installation, every
> container and every FPM pool. A check from outside sees only what a site
> chooses to put in its headers, which on most sites is nothing at all. The
> script never turns that silence into a clean result: a website whose patch
> level it cannot determine comes back as **undecided**, with a pointer to
> run it on the server, and never as "not vulnerable". Every run ends with a
> "How reliable this is" block that says which of the two it was.

```console
$ sudo ./php2shell-check.sh https://www.example.com

PHP installations on this host
  [ OK ] php-binary     /usr/sbin/php-fpm8.3
         package php8.3-fpm 8.3.6-0ubuntu0.24.04.13 (distribution fix from 8.3.6-0ubuntu0.24.04.13)

PHP in docker containers
  [VULN] container      shop-wordpress-1 (wordpress:latest)
         PHP 8.3.35, fixed in 8.3.36
         -> Update PHP to 8.3.36 or later (container: pull the new image and recreate)
  [WARN] mitigation     shop-wordpress-1
         temporary mitigations not set: session.upload_progress.enabled=0 expose_php=0.

Website https://www.example.com
  [WARN] disclosure     https://www.example.com
         the PHP version is visible to everyone (X-Powered-By: PHP/8.3.35)
  [ OK ] waf            https://www.example.com
         proxied through Cloudflare (header and DNS); Cloudflare says it has deployed
         WAF rules for these CVEs on all plans, Free included

Summary  1 vulnerable, 0 undecided, 2 warnings, 2 ok
  VULNERABLE  at least one PHP runtime needs an update now.

How reliable this is
  Ran on this host: the package and container versions above are read
  from the system itself. That is the definite answer for this server.
```

## Run it

On your server:

```sh
sudo bash -c "$(curl -fsSL https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.sh)" - https://your-site.example
```

Replace `https://your-site.example` with your website. Several sites go one
after the other, separated by spaces. Leave the URL out to check only the
server.

Only a website, from any computer including a Mac (no `sudo` needed):

```sh
bash -c "$(curl -fsSL https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.sh)" - --remote-only https://your-site.example
```

The command downloads the script completely before it runs and leaves no
file behind. The link always points to the latest release, so it never
changes.

Want to read the script first, or check it against its SHA-256 sum? Download
the latest release and run it step by step:

```sh
curl -fsSLO https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.sh
curl -fsSLO https://github.com/EXT-IT/php2shell-check/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS          # macOS: shasum -a 256 -c SHA256SUMS
less php2shell-check.sh
sudo bash php2shell-check.sh https://your-site.example
```

Without root it still runs, but it cannot see containers or other users'
processes and says so in the output. Checking only websites is useful for a
quick overview of a fleet, but it never replaces a run on each server.

| Option | Effect |
|---|---|
| `-r`, `--remote-only` | only check the URLs; no root needed, works on macOS. At most 10 URLs per run, no address ranges |
| `--origin IP` | also try to reach each site directly at `IP`, past the proxy |
| `--no-containers` | skip Docker and Podman |
| `--no-logs` | skip the log scan |
| `--json` | one JSON object on stdout, for monitoring and fleet runs |
| `--no-color`, `-q` | plain output; summary only |

Exit codes: `0` nothing vulnerable found, `1` vulnerable, `2` could not decide,
`3` usage error. Warnings (missing mitigations, version disclosure) do not
change the exit code.

## What it checks

On the server:

| Check | What it looks at |
|---|---|
| `php-binary` | every PHP in `/usr/bin`, `/usr/sbin`, `/usr/local`, Plesk (`/opt/plesk/php`), cPanel EasyApache (`/opt/cpanel/ea-php*`), CloudLinux alt-php, Remi, LiteSpeed, `php-cgi` including `/usr/lib/cgi-bin`, FrankenPHP (read out of `frankenphp version`, which carries the embedded PHP version), **plus every PHP that is currently running**, taken from the process list, so a build in an unusual path is not missed. Debian and Ubuntu packages are judged by package version against the distribution's fix, RPM packages below the upstream fix by whether their changelog names the CVE; everything else by upstream version |
| `sapi` | how PHP is served, and every way at once when a host has several. The advisory validated the session-lifecycle RCE against **mod_php and PHP-FPM** alike, names `php-cgi`, LiteSpeed and FrankenPHP as at risk without validating them, and this is what decides the order of patching. Detected on the host and inside each container. A host where none of them matches is told so rather than passed over in silence |
| `container` | PHP inside every running Docker or Podman container, plus stopped containers whose image ships a vulnerable PHP and would bring it back on the next start. A Debian or Ubuntu based image is judged by the package database inside the container, for the same reason as the host: the upstream number stays unchanged when the fix is backported |
| `mitigation` | the temporary settings from the advisory: `session.upload_progress.enabled`, `expose_php`, `post_max_size` against `memory_limit`, `max_input_nesting_level`, `fatal_error_backtraces`. On Debian layouts it reads the FPM and Apache `php.ini`, on the host and inside containers, not just the CLI one, because they differ |
| `fpm-pool` | `pm.max_requests` in every PHP-FPM pool, and whether a pool runs as `root`, which would turn this bug into root code execution |
| `process` | PHP-FPM, `lsphp` or Apache with `mod_php` still running the old binary after an update. A patched package is not a patched server until the service restarts |
| `mac` | whether AppArmor or SELinux is active |
| `exposure` | web ports listening on all interfaces; a running Cloudflare Tunnel |
| `log-indicator` | memory-limit fatal errors in current web server, PHP-FPM and container logs. The first CVE triggers at exactly that point. A count is a hint, never proof |

For each URL:

| Check | What it looks at |
|---|---|
| `remote` | whether the site answers; if not, why: DNS, connection refused, timeout or TLS |
| `tls` | HTTPS that does not work (a URL given without `https://` is then checked over plain HTTP) or a certificate that does not match the name. The headers are read either way |
| `blocked` | Cloudflare answering with a block or challenge page instead of the site. The banner check cannot say anything then, and the script says so instead of reporting a clean result |
| `php-banner` | a PHP version in `X-Powered-By`, judged like a local version. A distribution's frozen number such as `8.3.6` comes back as *undecided*, for the reason in the first paragraph |
| `disclosure` | whether the site announces its PHP version at all. Hiding the version makes this check quiet; it patches nothing |
| `waf` | Cloudflare (by `cf-ray` header and by checking every DNS record against Cloudflare's published IP ranges), Sucuri, Imperva, CloudFront, Azure Front Door, Akamai, Fastly, BunnyCDN. A record that points past Cloudflare is flagged, because that traffic skips the WAF |
| `php-level` | the patch level could not be determined from outside: no version in the headers, the edge answered instead of the site, or a version number that distributions freeze. Keeps the result undecided instead of clean, and says where the definite answer comes from |
| `access` | a redirect to a Cloudflare Access login, which stops requests without a login before they reach PHP |
| `redirect` | a redirect to another host. It is reported and not followed, so the script only ever talks to the host you named (or its `www.` variant) |
| `origin` | with `--origin`, whether the server answers directly. If it does, anyone who finds the IP can go around the WAF |

## What it cannot tell you

Read this section even if you skip the rest.

Podman goes through the same code path as Docker, but has only been verified
against Docker.

A green result covers what the script can see. PHP in a chroot, a
FreeBSD jail, a VM on the same host or an appliance with a web interface stays
invisible. The heise article lists pfSense, OPNsense, Synology, QNAP, Citrix,
Ivanti and F5 BIG-IP among the products that embed PHP, and none of them can
run this script. Check them with their vendors.

The fix table goes stale. Distributions publish fixes over days. The
script knows the packages that existed on 2026-10-21:

| Release | Fixed package |
|---|---|
| Ubuntu 22.04 (php8.1) | `8.1.2-1ubuntu2.28` |
| Ubuntu 24.04 (php8.3) | `8.3.6-0ubuntu0.24.04.13` |
| Ubuntu 26.04 (php8.5) | `8.5.4-0ubuntu1.5` |
| Ubuntu 26.10 (php8.5) | `8.5.9-0ubuntu2.1` |
| Ubuntu 20.04 (php7.4) | `7.4.3-4ubuntu2.29+esm5`, needs Ubuntu Pro |
| Ubuntu 18.04 (php7.2) | `7.2.24-0ubuntu0.18.04.17+esm14`, needs Ubuntu Pro |
| Ubuntu 16.04 (php7.0) | `7.0.33-0ubuntu0.16.04.16+esm22`, Pro with Legacy Support |
| Ubuntu 14.04 (php5) | `5.5.9+dfsg-1ubuntu4.29+esm18`, Pro with Legacy Support |
| Debian 13 (php8.4) | `8.4.27-1~deb13u1`, [DSA-6574-1](https://security-tracker.debian.org/tracker/CVE-2026-109618) |
| Debian 12 (php8.2) | `8.2.35-1~deb12u1`, [DLA-4848-1](https://security-tracker.debian.org/tracker/CVE-2026-109618) |
| RHEL, AlmaLinux, Rocky | not in the table, reported as *undecided* |

On the four ESM rows the fix exists only on a host with Ubuntu Pro attached.
Without it the package stays below the version above and the verdict is
*vulnerable*, which is the truthful answer for such a host.

**RHEL and its rebuilds are not in that table on purpose.** They backport at an
unchanged upstream number too, but there the deciding part is the RPM release,
and every rebuilder sets that scheme differently — `-8.el9_8.1` at Red Hat,
`-8.el9_8.alma.1` at AlmaLinux, `+328+1fdeb728` inside a module build. A table
of those would be wrong within days. So when the version is below the upstream
fix, the changelog of the installed package decides: it either names
CVE-2026-109618 / CVE-2026-109619 or it does not. Measured on AlmaLinux 9.8 on
2026-10-22, `php-cli-8.3.33-1.module_el9.8.0+328+1fdeb728.alma.1` is patched
while `8.3.33` is below `8.3.36`, and the branches 8.0 and 8.1 carry fixes that
upstream does not have at all. A package whose changelog says nothing is left
*undecided*, not called clean: the 8.3.36 and 8.2.35 rebases are fixed through
their version and name no CVE either.

**Alpine's stable branches are a dead end, not a slow one.** Measured on
2026-10-22: `alpine:3.24` and edge carry `php83 8.3.36-r0`, `php84 8.4.27-r0`
and `php85 8.5.12-r0`, while 3.21, 3.22 and 3.23 sit at 8.3.19, 8.3.29 and
8.3.31, and Alpine's own security database lists the fix for 3.24 and edge
only. An image built on `alpine:3.22` cannot be patched with `apk upgrade`; the
base image has to move. The official `php:*-alpine` images are not affected by
this, they compile PHP themselves.

Run an old copy a week from now and a fixed Debian 12 server can still come
out *vulnerable*. Use the latest release.

Upstream branches 7.4, 8.0 and 8.1 have no fix. The PHP team announced
backports but had not released them when this version shipped. A source build
of those branches therefore always comes out vulnerable, even if a vendor has
patched it privately. Distribution packages are the exception: the ESM rows
above are judged by package version like any other, so a focal host with Pro
attached comes out clean at an unchanged `7.4.3`.

Not every PHP runtime can be read. The script knows `php`, `php-fpm`,
`php-cgi`, `lsphp` and `frankenphp`, by path and in the process list. A
runtime that embeds PHP under another name — Swoole, RoadRunner, `ngx_php`, a
vendor bundle, a statically linked launcher of your own — is found only if it
happens to run from one of those names. FrankenPHP built without a `php` CLI
is judged by version, but its runtime configuration (the `mitigation` check)
stays unchecked, because the ini probe needs that binary.

The WAF check sees that a proxy is there, not what it blocks. Cloudflare
said on 2026-10-21 that its managed rules cover the known attack paths on
every plan, and its CTO called them a stopgap. The script cannot see whether
those rules are switched on for your zone. Nor can it see whether your origin
is reachable unless you pass `--origin`.

Remote banners are hints. Hiding `X-Powered-By` makes the remote check
quiet. It does not patch anything.

## Keeping the data current

Everything that decides a verdict sits in three short functions at the top of
the script: `_p2s_upstream_fixed`, `_p2s_distro_fixed` and the list of frozen
versions. When a distribution publishes a fix, that is a two-line change plus a
test in `tests/run_tests.sh`. If you keep your own copy current, link the
distribution's advisory next to each entry.

```sh
bash tests/run_tests.sh      # no root, no network, no Docker needed
```

CI runs the tests on Ubuntu 22.04 and 24.04, Debian 12 and 13, Rocky Linux 9,
Alpine and macOS (bash 3.2), and checks `SHA256SUMS` against the script.

## Background

- Why `php -v` is not enough, the fixed versions per distribution and the four
  steps to fix it, in German:
  [ext-it.tech/php2shell](https://ext-it.tech/php2shell/)
- PHP advisory: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- heise online, 21.10.2026: [php2shell: Kritische Sicherheitslücken erlauben Codeeinschleusung in PHP](https://www.heise.de/news/php2shell-Kritische-Sicherheitsluecken-erlauben-Codeeinschleusung-in-PHP-11492938.html)
- Cloudflare IP ranges: <https://www.cloudflare.com/ips/>

## Disclaimer

This script is for administrators checking systems they own or are
authorised to check. Use it on anything else and that is your decision and
your responsibility, not ours.

It is provided as is, free of charge, without warranty and without support.
A result of "not vulnerable" is no guarantee: if in doubt, patch. EXT IT GmbH
does not answer questions about the script or its results, does not help with
installing or running it, and has no obligation to fix errors or keep the
vulnerability data current. Issues and pull requests may stay unanswered.

To the extent permitted by law, EXT IT GmbH is not liable for any damage
resulting from using this script or relying on its output. This does not limit
liability where the law does not allow it to be limited, in particular for
intent and gross negligence.

## License

MIT, see [LICENSE](LICENSE). Copyright 2026 EXT IT GmbH, Hannover.
[ext-it.tech](https://ext-it.tech) · [Impressum](https://ext-it.tech/impressum/)
