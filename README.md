<div align="center">

# php2shell-check

**Is this server still exposed to php2shell (CVE-2026-109618, CVE-2026-109619)?**

[![CI](https://img.shields.io/github/actions/workflow/status/EXT-IT/php2shell-check/ci.yml?branch=main&label=CI)](https://github.com/EXT-IT/php2shell-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.1.0-green.svg)](CHANGELOG.md)
[![Data](https://img.shields.io/badge/vulnerability%20data-2026--10--22-orange.svg)](#keeping-the-data-current)
[![Maintained by EXT IT GmbH](https://img.shields.io/badge/maintained%20by-EXT%20IT%20GmbH-0a4f7a.svg)](https://ext-it.tech)

</div>

On Ubuntu 24.04, `php -v` prints `PHP 8.3.6` before the fix and after it.
Canonical backports the patch and keeps the version number, so the number every
quick check looks at tells you nothing — only the package database knows. Your
WordPress container, meanwhile, ships its own PHP that `apt` never sees. On
Windows it is the other way round: there the version number is the whole
answer, and the IIS configuration decides which of several installed binaries
answers a request.

Two scripts, one verdict per PHP runtime. Both are read-only: they read package
databases and version resources, ask each PHP for its settings, and send one
ordinary GET request to each URL you name. No exploit traffic, nothing written
to disk.

## Run it

On a Linux server:

```sh
sudo bash -c "$(curl -fsSL https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.sh)" - https://your-site.example
```

On a Windows server, in an elevated PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $f = "$env:TEMP\p2s.ps1"; irm https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.ps1 -OutFile $f; & $f https://your-site.example; del $f
```

Replace `https://your-site.example` with your website, several separated by
spaces, or leave it out to check only the server. Both commands download the
whole script first, run it, and leave no file behind. The link always points at
the latest release, so it never changes.

Without root it still runs, but it cannot see containers or other users'
processes and says so in the output. Checking only websites is useful for a
quick overview of a fleet, but it never replaces a run on each server.

## Or take the repository

The one-liner is the short way. Clone the repository when you want to read the
script first, keep it on a jump host, or run it again next month:

```sh
git clone https://github.com/EXT-IT/php2shell-check.git
cd php2shell-check
sudo bash php2shell-check.sh https://your-site.example
```

```powershell
git clone https://github.com/EXT-IT/php2shell-check.git
cd php2shell-check
.\php2shell-check.ps1 https://your-site.example
```

Without git, take the two files from the latest release and check them against
their SHA-256 sums before running anything:

```sh
curl -fsSLO https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.sh
curl -fsSLO https://github.com/EXT-IT/php2shell-check/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
less php2shell-check.sh
sudo bash php2shell-check.sh https://your-site.example
```

```powershell
irm https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.ps1 -OutFile php2shell-check.ps1
irm https://github.com/EXT-IT/php2shell-check/releases/latest/download/SHA256SUMS -OutFile SHA256SUMS
$want = (Get-Content ./SHA256SUMS | Select-String 'php2shell-check\.ps1').ToString().Split()[0]
$got = (Get-FileHash ./php2shell-check.ps1 -Algorithm SHA256).Hash.ToLower()
if ($want -eq $got) { 'checksum ok' } else { 'MISMATCH' }
.\php2shell-check.ps1 https://your-site.example
```

`SHA256SUMS` lists both editions, hence `--ignore-missing` when you took only
one of them. If PowerShell's execution policy refuses the script, run it as
`powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1`.


Only a website, from any computer and without root:

```sh
bash -c "$(curl -fsSL https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.sh)" - --remote-only https://your-site.example
```

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; $f = "$env:TEMP\p2s.ps1"; irm https://github.com/EXT-IT/php2shell-check/releases/latest/download/php2shell-check.ps1 -OutFile $f; & $f -RemoteOnly https://your-site.example; del $f
```

## What the answer is worth

**Run it on the server.** That is the only way to get a definite answer. There
it reads the real versions of every installation, every container and every FPM
pool. From outside it sees only what a site puts in its headers, which on most
sites is nothing — and the script never turns that silence into a clean result.
A site whose patch level it cannot determine comes back **undecided**, never as
"not vulnerable". Every run ends with a block that says which of the two it
was.

Exit codes: `0` nothing vulnerable found, `1` vulnerable, `2` could not decide,
`3` usage error. Warnings (missing mitigations, version disclosure) do not
change the exit code.

A verdict covers what the script can see. The folded sections below have the
details; the short version is that silence is never counted as clean, a
distribution fix table goes stale within days, and a mitigation is not a patch.

<details>
<summary>Why a run can end in 2 where it used to end in 0</summary>

`0` is reserved for a run that actually judged a PHP runtime and found all of
them patched. Three cases that used to end in `0` now end in `2`, because
"nothing to report" and "nothing examined" are not the same answer:

- a run that judged no PHP at all — no PHP in the known paths, none in the
  process list, or the local checks could not run on this platform
- a website whose header announces a patched version: `X-Powered-By` is
  self-declared and can be set by the application, a cache or a proxy with a
  different PHP behind it
- a package below the upstream fix on an RPM distribution whose changelog does
  not name the CVE

A version *below* the fix is still `1`, from a header too: if that header
lies, it only costs a look.

</details>

| Option | Effect |
|---|---|
| `-r`, `--remote-only` | only check the URLs; no root needed, works on macOS. At most 10 URLs per run, no address ranges |
| `--origin IP` | also try to reach each site directly at `IP`, past the proxy |
| `--no-containers` | skip Docker and Podman |
| `--no-logs` | skip the log scan |
| `--json` | one JSON object on stdout, for monitoring and fleet runs |
| `--no-color`, `-q` | plain output; summary only |

## Help with the patching

Knowing where you stand is the easy half. The other half is an end-of-life
Ubuntu that needs ESM attached, an image nobody has rebuilt in two years, or a
container whose base distribution has no fix at all and never will.

EXT IT GmbH does that as paid work:
[ext-it.tech/kontakt](https://ext-it.tech/kontakt/). That is a service for your
servers, not support for this script — the script stays as it is, free of
charge and without warranty, and the disclaimer at the bottom of this page is
unchanged.

<details>
<summary><b>Example output</b> — one Linux host, one Windows host</summary>

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

A Windows server with both versions unpacked and IIS pointing at the new one,
with the website check left out. Two sites are configured there, which is why
the `sapi` check answers twice and three FastCGI pools show up — one line per
handler, not one per host:

```console
php2shell-check 2.1.0  CVE-2026-109618 / CVE-2026-109619, data as of 2026-10-22
WEB01 (Microsoft Windows Server 2022 Standard)

PHP installations on this host
  [VULN] php-binary     C:\php\8.3.35
         PHP 8.3.35, fixed in 8.3.36 (php.exe, php-cgi.exe, phpdbg.exe, php-win.exe)
         -> Update PHP to 8.3.36 or later, then recycle the FastCGI application or the application pool
  [ OK ] php-binary     C:\php\8.3.36
         PHP 8.3.36 (fixed from 8.3.36) (php.exe, php-cgi.exe, phpdbg.exe, php-win.exe)

How PHP is served
  [WARN] sapi           PHP_site2 (*.php2)
         served by php-cgi through IIS FastCGI: C:\php\8.3.36\php-cgi.exe. php.net names php-cgi under 'Who is at risk', the advisories validate no exploit against it
         -> A FastCGI process serves many requests, so judge this like PHP-FPM, not like one process per request
  [WARN] sapi           PHP_via_FastCGI (*.php)
         served by php-cgi through IIS FastCGI: C:\php\8.3.36\php-cgi.exe. php.net names php-cgi under 'Who is at risk', the advisories validate no exploit against it
         -> A FastCGI process serves many requests, so judge this like PHP-FPM, not like one process per request
  [INFO] fastcgi-pool   C:\php\8.3.35\php-cgi.exe
         instanceMaxRequests = 10000
         -> A low instanceMaxRequests retires workers sooner; it is not one of the advisory measures
  [INFO] fastcgi-pool   C:\php\8.3.36\php-cgi.exe
         instanceMaxRequests = 10000
         -> A low instanceMaxRequests retires workers sooner; it is not one of the advisory measures
  [INFO] fastcgi-pool   C:\php\8.3.36\php-cgi.exe
         instanceMaxRequests = 200, arguments '-d open_basedir=C:\inetpub\wwwroot'
         -> A low instanceMaxRequests retires workers sooner; it is not one of the advisory measures

Runtime configuration
  [WARN] disclosure     C:\php\8.3.35\php.ini
         expose_php is on, so the PHP version is in the response headers for everyone
         -> Set expose_php=0 so scanners cannot pick vulnerable targets by header
  [WARN] mitigation     C:\php\8.3.35\php.ini
         temporary measures from the advisory not set: memory_limit=-1 (now 128M) a low post_max_size (8M without file uploads, 32M with; now 64M) session.upload_progress.enabled=0.
         -> Until patched: set memory_limit=-1 and session.upload_progress.enabled=0 where applications cannot override them, keep post_max_size low, and recycle every worker. Only an update is a complete solution
  [WARN] mitigation     C:\php\8.3.36
         no php.ini next to these binaries, and none in the registry, in PHPRC or in the Windows directory, so this installation runs on PHP's compiled defaults and none of the temporary measures is set
         -> Copy php.ini-production next to php.exe and set the measures from the advisory, or confirm with "php --ini" which file is really in use
  [WARN] forced-ini     C:\php\8.3.36\php-cgi.exe
         the FastCGI pool forces settings through its arguments: '-d open_basedir=C:\inetpub\wwwroot', so the php.ini lines in this report do not describe that pool
         -> Check the forced values against the advisory measures, then recycle the FastCGI application

Summary  1 vulnerable, 0 undecided, 6 warnings, 1 ok
  VULNERABLE  at least one PHP runtime needs an update now.

How reliable this is
  Ran on this host: the versions above are read out of the files
  themselves, which is the definite answer for what is installed.
  What no check can prove on Windows is which code a running worker
  already executes, so recycle the FastCGI application or the
  application pool after every PHP update.
```

</details>

<details>
<summary><b>What it checks</b> — every check, on the server and for each URL</summary>

On the server:

| Check | What it looks at |
|---|---|
| `php-binary` | every PHP in `/usr/bin`, `/usr/sbin`, `/usr/local`, Plesk (`/opt/plesk/php`), cPanel EasyApache (`/opt/cpanel/ea-php*`), CloudLinux alt-php, Remi, LiteSpeed, `php-cgi` including `/usr/lib/cgi-bin`, FrankenPHP (read out of `frankenphp version`, which carries the embedded PHP version), **plus every PHP that is currently running**, taken from the process list, so a build in an unusual path is not missed. Debian and Ubuntu packages are judged by package version against the distribution's fix, RPM packages below the upstream fix by whether their changelog names the CVE; everything else by upstream version |
| `sapi` | how PHP is served, and every way at once when a host has several. The advisory validated the session-lifecycle RCE against **mod_php and PHP-FPM** alike, names `php-cgi`, LiteSpeed and FrankenPHP as at risk without validating them, and this is what decides the order of patching. Detected on the host and inside each container. A host where none of them matches is told so rather than passed over in silence |
| `container` | PHP inside every running Docker or Podman container, plus stopped containers whose image ships a vulnerable PHP and would bring it back on the next start. A Debian or Ubuntu based image is judged by the package database inside the container, for the same reason as the host: the upstream number stays unchanged when the fix is backported |
| `mitigation` | the temporary measures from the advisory's own section: `memory_limit=-1`, `post_max_size` against the 8M / 32M the advisory names, `upload_max_filesize` below it, `session.upload_progress.enabled`, `fatal_error_backtraces` on 8.5, and `max_input_nesting_level` as context. On Debian layouts it reads the FPM, Apache and CGI `php.ini`, on the host and inside containers, not just the CLI one, because they differ. `php_admin_value` / `php_value` in FPM pools and vhosts is read as well — that is where the advisory asks for the setting. `expose_php` is not one of these measures and has its own `disclosure` line |
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

### Windows servers

The Windows edition is a separate script, `php2shell-check.ps1`, because none
of the package-database machinery applies there and all of the IIS machinery
has no counterpart on Linux. It needs Windows PowerShell 5.1, which every
Windows Server since 2016 has without an installation, and runs under
PowerShell 7 as well. The exit codes are the same, and the options come in both
spellings — `-RemoteOnly` and `--remote-only` do the same thing — so one fleet
script can call either. `--no-containers` and `--no-logs` are accepted and do
nothing; `--origin` does not exist there and ends in a usage error rather than
being treated as another website to check.

| Check | What it looks at |
|---|---|
| `php-binary` | every `php.exe`, `php-cgi.exe` and `php*.dll` under the paths the Windows installers use: Chocolatey (`C:\tools\php*`), Scoop, WinGet, XAMPP, WampServer, Laragon, EasyPHP, Plesk, Zend Server, plus a scan of every fixed drive. Judged by the version resource in the file, not by its path or its name |
| `iis` | which binary actually serves `.php`, read out of `applicationHost.config`: the FastCGI entries, the handler mappings including the `scriptProcessor` form that packs two paths into one pipe-separated string, and `instanceMaxRequests` |
| `process` | PHP that is running now. The version comes from the file on disk, so an application pool still serving the old `php-cgi.exe` after an update is visible — which is the usual state of a Windows server an hour after someone unpacked the new PHP |
| `stale-evidence` | a PHP DLL that was renamed out of the way but is still loaded, and a rename queued in `PendingFileRenameOperations`, meaning the update finishes at the next reboot and not before |
| `ini`, `mitigation` | the temporary measures from the advisory, read out of every `php.ini` it can find: next to each binary (`php-cgi.ini` before `php.ini`, because that is the order PHP itself uses), `phpForApache.ini` for WampServer, the path in `HKLM\SOFTWARE\PHP`, `PHPRC`, and the Windows directory |
| `remote` | the URL checks, identical to the shell version |

</details>

<details>
<summary><b>What it cannot tell you</b> — read this before trusting a green result</summary>

Read this section even if you skip the rest.

Podman goes through the same code path as Docker, but has only been verified
against Docker.

**A container no runtime answers for is found, but judged less deeply.** Where
no Docker or Podman command can be asked — rootless Docker belonging to another
user, containerd or nerdctl, Kubernetes, LXC and LXD, systemd-nspawn, Snap, a
chroot, or simply a run with `--no-containers` — the running process is read
through `/proc/<pid>/root` instead. The verdict then comes from that root's own
`/etc/os-release` and package database, which is what a version and a patch
state need. What it does not get is the runtime configuration: the `mitigation`
check has to run `php -r`, and this script does not start a binary out of a
foreign root as root on the host. Where no version can be read from data at
all, the line is *undecided* — never clean. And where a container runtime is
running that nothing could be asked about, that is its own *undecided* line
rather than silence.

**Inside a container, root cannot inspect workers that belong to another
user.** Measured in an unmodified `php:8.3-fpm` container: the master runs as
root and is readable, the two workers run as `www-data` and their
`/proc/<pid>/exe` is not, because Docker's default capability set does not
include `SYS_PTRACE`. The restart state of those workers is therefore unknown,
the run says so, and the result is *undecided* — that is the normal outcome of
a run inside a container, not a sign of trouble. Run it on the host, where root
reads every process, or grant `--cap-add=SYS_PTRACE` for the check.

A green result covers what the script can see. A FreeBSD jail, a VM on the
same host or an appliance with a web interface stays invisible. The heise
article lists pfSense, OPNsense, Synology, QNAP, Citrix, Ivanti and F5 BIG-IP
among the products that embed PHP, and none of them can run this script. Check
them with their vendors.

The fix table goes stale. Distributions publish fixes over days. The
script knows the packages that existed on 2026-10-22:

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

PHP on Windows is a separate script with separate limits, see
[Windows servers](#windows-servers). The shell version does not run there and
does not pretend to: a `--remote-only` run from a Mac or a Linux box judges a
Windows site by its headers like any other, which is the same thin answer.

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

Forced PHP settings are read line by line, not parsed. The advisory asks
to check "that no pool, directory or application setting puts a finite limit
back", so the script reads `php_admin_value` / `php_value` in FPM pools, in
the Apache configuration under `sites-enabled`, `conf-enabled`, `vhosts.d`
and `httpd/conf.d`, and single-line `fastcgi_param PHP_VALUE` /
`PHP_ADMIN_VALUE` in the nginx configuration. It does not follow `include`
directives, does not evaluate `<Directory>`, `<Files>` or `<IfModule>`
sections, does not work out which file wins when two set the same value, and
does not read the newline-separated nginx form that carries several settings
in one quoted string. `.htaccess`, `.user.ini` and anything an application
sets at runtime stay invisible. A pool or vhost it does report is a real
finding; silence here is not a clean bill of health.

No result in the `mitigation` check is an *ok*. php.net opens the
section these checks follow with "while only an update is a complete solution,
the following measures reduce exposure to specific attack paths but do not
make an installation safe", so a host with every readable measure in place is
reported as *info*: counted nowhere, no effect on the exit code. A mitigation
is not a patch.

### On Windows

What it does not do, measured on Windows Server 2022 with IIS 10 on
2026-10-22:

- **File timestamps are not evidence on NTFS and are not used.** NTFS tunneling
  hands a replaced file the creation time of the one it replaced, so a `php.exe`
  put there ten minutes ago can carry a creation date from last year. The
  verdict comes from the version resource only. A build whose resource is empty
  — a self-compiled binary, a repacked bundle — is *undecided*, never clean.
- **Without Administrator rights the IIS part is missing.** `applicationHost.config`
  is readable by SYSTEM and the Administrators group, nothing else, so an
  unelevated run finds the installations but cannot say which one answers a
  request. It says so instead of leaving the gap open.
- **Only IIS is read.** Apache and nginx on Windows serve PHP through their own
  configuration, and the script does not parse it. Their binaries are still
  found and judged; what is missing is the link from a site to a binary.
- **It never starts a PHP binary.** Every version comes out of the file's
  version resource and every setting out of an ini file on disk. That keeps the
  script harmless on a production server, and it means a setting that only the
  running process knows — a compiled-in default, something an application sets
  at runtime — stays invisible. `php --ini` on the host is the way to see which
  file actually wins.
- Windows Server 2022 and IIS 10 are what this was measured against. 2016,
  2019 and 2025 use the same interfaces and are expected to work; nobody has
  run it there yet.

The two scripts carry the same table of fixed versions, and that is the one
thing neither of them can check by running: a Windows run never reads the
shell table, a Linux run never reads the PowerShell one. So `tests/data_parity.py`
compares them and fails on the first number that drifts apart.

</details>

<details>
<summary><b>Keeping the data current, and the tests</b></summary>

### Keeping the data current

Everything that decides a verdict sits in three short functions at the top of
the script: `_p2s_upstream_fixed`, `_p2s_distro_fixed` and the list of frozen
versions. When a distribution publishes a fix, that is a two-line change plus a
test in `tests/run_tests.sh`. If you keep your own copy current, link the
distribution's advisory next to each entry.

```sh
bash tests/run_tests.sh        # no root, no network, no Docker needed
python3 tests/data_parity.py   # both editions carry the same numbers
```

```console
PS> .\tests\run_tests.ps1
```

Windows PowerShell 5.1 runs all of those. PowerShell 7 cannot build the fake
`php.exe` they need — it refuses to emit an executable assembly — so there it
falls back to the C# compiler that Windows ships with .NET Framework, and
where neither exists the host checks are skipped with the reason printed. On a
Mac that leaves the option, version and remote cases, which do run.

CI runs the shell tests on Ubuntu 22.04 and 24.04, Debian 12 and 13, Rocky
Linux 9, Alpine and macOS (bash 3.2), the PowerShell tests on Windows in both
5.1 and 7, the parity check on every push, and verifies `SHA256SUMS` against
both scripts.

</details>

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
