#Requires -Version 5.1
<#
Regression tests for php2shell-check.ps1. No admin rights, no network, no PHP
installation needed, nothing is changed outside the temporary directory.

    powershell -NoProfile -ExecutionPolicy Bypass -File tests\run_tests.ps1

The fixtures are the interesting part. The script reads a PHP version out of a
file's version resource, so a fake PHP cannot be a text file the way it can on
Linux -- it needs a real PE with a real version resource. Add-Type compiles
one at test time with the in-box C# compiler, which keeps binaries out of the
repository and still exercises the real reader:

    [assembly: AssemblyFileVersion("8.3.35.0")] -> VersionInfo.FileMajorPart ...

A fixture built that way is a managed executable rather than a C build, which
does not matter here: the script only ever reads the resource and never runs
the file.
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$script:Pass = 0
$script:Fail = 0
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'php2shell-check.ps1'
# Re-invoke the very PowerShell that runs these tests. Hardcoding
# powershell.exe would make the PowerShell 7 CI job test 5.1 instead, and it
# keeps the harness runnable on a Mac for everything that needs no PE fixture.
$psExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("p2s-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

function T-Ok([string] $Name) { $script:Pass++; Write-Host ("  ok    " + $Name) }
function T-Bad([string] $Name, [string] $Detail) {
    $script:Fail++
    Write-Host ("  FAIL  " + $Name) -ForegroundColor Red
    if ($Detail) { ($Detail -split "`n" | Select-Object -First 25) | ForEach-Object { Write-Host ("        " + $_) } }
}

# T-Absent NAME EXPECTED_RC PATTERN ARGS: the pattern must NOT appear.
function T-Absent {
    param([string] $Name, [int] $Rc, [string] $Pattern, [string[]] $ScriptArgs)
    $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $target @ScriptArgs 2>&1 | Out-String
    $got = $LASTEXITCODE
    if ($got -ne $Rc) { T-Bad ("$Name (exit $got, expected $Rc)") $out }
    elseif ($out -match $Pattern) { T-Bad ("$Name (output still has /$Pattern/)") $out }
    else { T-Ok $Name }
}

# T-Run NAME EXPECTED_RC PATTERN ARGS
function T-Run {
    param([string] $Name, [int] $Rc, [string] $Pattern, [string[]] $ScriptArgs)
    $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $target @ScriptArgs 2>&1 | Out-String
    $got = $LASTEXITCODE
    if ($got -ne $Rc) {
        T-Bad ("$Name (exit $got, expected $Rc)") $out
    } elseif ($Pattern -and $out -notmatch $Pattern) {
        T-Bad ("$Name (output lacks /$Pattern/)") $out
    } else {
        T-Ok $Name
    }
}

# New-FakePhp DIR VERSION [NAMES] -> a directory holding PE files whose
# version resource says VERSION.
function New-FakePhp {
    param([string] $Dir, [string] $PhpVersion, [string[]] $Names = @('php.exe', 'php-cgi.exe'))
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $four = if ($PhpVersion -match '^\d+\.\d+\.\d+$') { "$PhpVersion.0" } else { $PhpVersion }
    $src = @"
using System.Reflection;
[assembly: AssemblyFileVersion("$four")]
[assembly: AssemblyInformationalVersion("$PhpVersion")]
[assembly: AssemblyCompanyAttribute("The PHP Group")]
public static class FakePhp$($PhpVersion -replace '\D','') { public static void Main() { } }
"@
    $first = $null
    foreach ($n in $Names) {
        $out = Join-Path $Dir $n
        if ($first) {
            Copy-Item $first $out -Force
        } else {
            New-FixtureExe -Source $src -OutFile $out
            $first = $out
        }
    }
}

# Add-Type writes an executable only in Windows PowerShell: PowerShell 7
# answers "Both the assembly types 'ConsoleApplication' and
# 'WindowsApplication' are not currently supported" -- measured on PowerShell
# 7.5.4. Falling back to the .NET Framework compiler that Windows itself
# ships keeps the host checks running under 7 as well; where neither exists,
# the caller skips those tests.
function New-FixtureExe {
    param([string] $Source, [string] $OutFile)
    try {
        Add-Type -TypeDefinition $Source -OutputAssembly $OutFile -OutputType ConsoleApplication -ErrorAction Stop
        return
    } catch {
        if (-not $env:windir) { throw }
        $csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        if (-not (Test-Path -LiteralPath $csc)) { throw }
        $cs = [IO.Path]::ChangeExtension($OutFile, '.cs')
        Set-Content -LiteralPath $cs -Value $Source -Encoding UTF8
        $log = & $csc /nologo /target:exe ('/out:' + $OutFile) $cs 2>&1 | Out-String
        Remove-Item -LiteralPath $cs -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $OutFile)) { throw ("csc.exe did not produce the fixture: " + $log) }
    }
}

function New-FakeRoot {
    param([string] $Name)
    $r = Join-Path $tmp $Name
    Remove-Item $r -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path (Join-Path $r 'Windows\system32\inetsrv\config') | Out-Null
    return $r
}

# Write-IisConfig ROOT ENTRIES: one applicationHost.config with a FastCGI
# application and a handler per entry. ScriptProcessor may carry the
# pipe-separated argument form that per-site setups use.
function Write-IisConfig {
    param([string] $Root, [hashtable[]] $Entries)
    $apps = ''
    $handlers = ''
    $i = 0
    foreach ($e in $Entries) {
        $i++
        # Not $args: that is an automatic variable in every function.
        $argAttr = if ($e.Arguments) { " arguments=`"$($e.Arguments)`"" } else { '' }
        $imr = if ($e.InstanceMaxRequests) { " instanceMaxRequests=`"$($e.InstanceMaxRequests)`"" } else { '' }
        $apps += "      <application fullPath=`"$($e.FullPath)`"$argAttr$imr />`r`n"
        $proc = if ($e.Arguments) { "$($e.FullPath)|$($e.Arguments)" } else { $e.FullPath }
        $handlers += "      <add name=`"PHP_$i`" path=`"*.php`" verb=`"*`" modules=`"FastCgiModule`" scriptProcessor=`"$proc`" resourceType=`"Either`" />`r`n"
    }
    $xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <fastCgi>
$apps    </fastCgi>
    <handlers>
$handlers    </handlers>
  </system.webServer>
</configuration>
"@
    Set-Content -Path (Join-Path $Root 'Windows\system32\inetsrv\config\applicationHost.config') -Value $xml -Encoding UTF8
}

Write-Host "php2shell-check.ps1 tests"
Write-Host ("  target: " + $target)
Write-Host ("  temp:   " + $tmp)

# ---------------------------------------------------------------------------
Write-Host 'Informational flags'
T-Run '-Version exits 0' 0 'php2shell-check \d+\.\d+\.\d+' @('-Version')
T-Run '-Help exits 0' 0 'Usage:' @('-Help')
T-Run '-RemoteOnly without a URL exits 3' 3 'need at least one URL' @('-RemoteOnly')

# The shell edition's spellings have to survive PowerShell's own parameter
# binding: everything it does not recognise lands in $Url, where an untranslated
# "--json" would be checked as if it were a website.
T-Run '--version works like -Version' 0 'php2shell-check \d+\.\d+\.\d+' @('--version')
T-Run '--help works like -Help' 0 'Usage:' @('--help')
T-Run '--remote-only without a URL exits 3' 3 'need at least one URL' @('--remote-only')
# Against an empty fake root, so the verdict does not depend on whether the
# machine running the tests has PHP installed -- a hosted CI runner does.
$optRoot = New-FakeRoot 'options'
T-Run '--quiet is accepted' 2 '' @('--quiet', '--no-remote', '-TestRoot', $optRoot)
T-Run '--no-color is accepted' 2 '' @('--no-color', '--no-remote', '-TestRoot', $optRoot)
T-Run '--no-containers and --no-logs do nothing here' 2 '' @('--no-remote', '--no-containers', '--no-logs', '-TestRoot', $optRoot)
T-Run 'an unknown option is a usage error' 3 'unknown option: --nope' @('--nope')
T-Run '--origin is refused instead of being dropped' 3 'not part of the Windows edition' @('--origin', '203.0.113.42')

# ---------------------------------------------------------------------------
Write-Host 'Judging a version (unit, dot-sourced)'
$env:P2S_SOURCE_ONLY = '1'
. $target
$env:P2S_SOURCE_ONLY = $null

function T-Verdict([string] $Version, [string] $Expected) {
    $v = Get-UpstreamVerdict $Version
    if ($v.Status -eq $Expected) { T-Ok "verdict $Version = $Expected" }
    else { T-Bad "verdict $Version = $Expected" "got $($v.Status): $($v.Detail)" }
}
T-Verdict '8.3.36' 'ok'
T-Verdict '8.3.37' 'ok'
T-Verdict '8.3.35' 'vuln'
T-Verdict '8.5.12' 'ok'
T-Verdict '8.5.11' 'vuln'
T-Verdict '8.2.35' 'ok'
T-Verdict '8.4.26' 'vuln'
# The branches whose fix never raised a version number. Neither ok nor vuln
# would be honest: a patched source build of 8.1.34 reads exactly like an
# unpatched one.
T-Verdict '8.1.34' 'unknown'
T-Verdict '8.0.30' 'unknown'
T-Verdict '7.4.33' 'unknown'
T-Verdict '7.2.24' 'unknown'
T-Verdict '5.6.40' 'unknown'
T-Verdict '9.0.1' 'unknown'
T-Verdict 'garbage' 'unknown'

# Compare-PhpVersion refuses junk instead of guessing. The shell edition's
# comparison was fail-open on non-numeric input, which would turn a garbled
# version into "ok".
if ($null -eq (Compare-PhpVersion '8.x.y' '8.3.36')) { T-Ok 'version comparison refuses junk' }
else { T-Bad 'version comparison refuses junk' 'it returned a verdict' }
if ((Compare-PhpVersion '8.3.36' '8.3.36') -eq 0) { T-Ok 'equal versions compare equal' }
else { T-Bad 'equal versions compare equal' '' }
if ((Compare-PhpVersion '8.3.9' '8.3.10') -lt 0) { T-Ok '8.3.9 sorts below 8.3.10' }
else { T-Bad '8.3.9 sorts below 8.3.10' 'string comparison would get this wrong' }

# Byte sizes from php.ini values.
function T-Bytes([string] $In, [int64] $Expected) {
    $got = Convert-IniBytes $In
    if ($got -eq $Expected) { T-Ok "ini bytes '$In' = $Expected" } else { T-Bad "ini bytes '$In' = $Expected" "got $got" }
}
T-Bytes '8M' 8388608
T-Bytes '32M' 33554432
T-Bytes '128M' 134217728
T-Bytes '-1' -1
T-Bytes '1G' 1073741824

# Reading a value out of php.ini lines: the last assignment wins, comments do
# not, and padding is ignored.
$iniLines = @('memory_limit = 128M', '; memory_limit = -1', 'post_max_size=64M', 'memory_limit = -1  ; later wins')
if ((Get-IniValue $iniLines 'memory_limit') -eq '-1') { T-Ok 'the last uncommented ini assignment wins' }
else { T-Bad 'the last uncommented ini assignment wins' (Get-IniValue $iniLines 'memory_limit') }
if ((Get-IniValue $iniLines 'post_max_size') -eq '64M') { T-Ok 'an ini value without spaces is read' }
else { T-Bad 'an ini value without spaces is read' '' }

# ---------------------------------------------------------------------------
Write-Host 'Remote checks'

# A local listener instead of the internet: one header is all these cases need.
$listener = New-Object System.Net.HttpListener
$port = 0
foreach ($try in 1..20) {
    $candidate = Get-Random -Minimum 20000 -Maximum 60000
    try {
        $listener.Prefixes.Clear()
        $listener.Prefixes.Add("http://127.0.0.1:$candidate/")
        $listener.Start()
        $port = $candidate
        break
    } catch { }
}
if ($port -eq 0) {
    T-Bad 'remote checks' 'no free port for the test listener'
} else {
    $job = Start-Job -ScriptBlock {
        param($prefix)
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add($prefix)
        $l.Start()
        for ($i = 0; $i -lt 8; $i++) {
            $ctx = $l.GetContext()
            $path = $ctx.Request.Url.AbsolutePath
            switch ($path) {
                '/fixed'      { $ctx.Response.Headers.Add('X-Powered-By', 'PHP/8.3.36') }
                '/vulnerable' { $ctx.Response.Headers.Add('X-Powered-By', 'PHP/8.3.35') }
                '/distro'     { $ctx.Response.Headers.Add('X-Powered-By', 'PHP/8.3.6') }
                '/silent'     { }
                default       { }
            }
            $buf = [Text.Encoding]::ASCII.GetBytes('ok')
            $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
            $ctx.Response.Close()
        }
        $l.Stop()
    } -ArgumentList "http://127.0.0.1:$port/"
    $listener.Stop()
    Start-Sleep -Seconds 2

    $base = "http://127.0.0.1:$port"
    T-Run 'a vulnerable banner is a finding' 1 'VULN\]\s+php-banner' @('-RemoteOnly', "$base/vulnerable")
    # Patched-looking is undecided, not ok: the header is self-declared.
    T-Run 'a patched banner is undecided, not ok' 2 '\?\? \]\s+php-banner' @('-RemoteOnly', "$base/fixed")
    T-Run 'and says a header is self-declared' 2 'self-declared' @('-RemoteOnly', "$base/fixed")
    T-Run 'a frozen distribution number cannot be judged' 2 'distributions keep while backporting' @('-RemoteOnly', "$base/distro")
    T-Run 'a site without a version is undecided' 2 '\?\? \]\s+php-level' @('-RemoteOnly', "$base/silent")
    Stop-Job $job -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $job -Force -ErrorAction SilentlyContinue | Out-Null
}

# Everything below needs a PE file with a real version resource, which needs
# the in-box C# compiler. Where that is missing -- PowerShell 7 on a Mac, a
# locked-down host -- the remaining cases are skipped rather than failed: they
# would be testing the compiler, not the script.
$fixtureProbe = ''
try {
    New-FakePhp (Join-Path $tmp 'probe') '8.3.35' @('php.exe')
} catch {
    $fixtureProbe = $_.Exception.Message.Split([Environment]::NewLine)[0]
}
if ($fixtureProbe) {
    Write-Host ''
    Write-Host ("  skip  the host checks need a PE fixture: " + $fixtureProbe)
    Write-Host ("        run these on Windows: " + $target)
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host ("{0} passed, {1} failed" -f $script:Pass, $script:Fail)
    if ($script:Fail -gt 0) { exit 1 }
    exit 0
}

# ---------------------------------------------------------------------------
Write-Host 'Installations on a fake host'

$r = New-FakeRoot 'vuln'
New-FakePhp (Join-Path $r 'PHP') '8.3.35'
T-Run 'a vulnerable installation is reported' 1 'VULN\]\s+php-binary' @('-NoRemote', '-TestRoot', $r)
T-Run 'and it names the fixed release' 1 'fixed in 8\.3\.36' @('-NoRemote', '-TestRoot', $r)
T-Run 'and one line covers the whole directory' 1 'php\.exe, php-cgi\.exe' @('-NoRemote', '-TestRoot', $r)

$r = New-FakeRoot 'fixed'
New-FakePhp (Join-Path $r 'PHP') '8.3.36'
T-Run 'a patched installation is clean' 0 'OK \]\s+php-binary' @('-NoRemote', '-TestRoot', $r)

$r = New-FakeRoot 'eol'
New-FakePhp (Join-Path $r 'PHP') '8.1.34'
T-Run 'an end-of-life branch is undecided, not clean' 2 '\?\? \]\s+php-binary' @('-NoRemote', '-TestRoot', $r)
T-Run 'and says why it cannot be read' 2 'does not raise the version number' @('-NoRemote', '-TestRoot', $r)

$r = New-FakeRoot 'two'
New-FakePhp (Join-Path $r 'PHP\8.3.35') '8.3.35'
New-FakePhp (Join-Path $r 'PHP\8.3.36') '8.3.36'
T-Run 'two installations side by side are both judged' 1 'VULN\]\s+php-binary' @('-NoRemote', '-TestRoot', $r)
T-Run 'and the summary counts both' 1 'Summary\s+1 vulnerable, 0 undecided, \d+ warnings, 1 ok' @('-NoRemote', '-TestRoot', $r)

$r = New-FakeRoot 'empty'
T-Run 'a host without PHP is undecided, never clean' 2 'no PHP found' @('-NoRemote', '-TestRoot', $r)
T-Absent 'and it is never called clean' 2 'NO VULNERABLE PHP FOUND' @('-NoRemote', '-TestRoot', $r)
# "nothing was judged" is a different state from "something came back
# undecided", and on a host run the php-binary line always answers, so this
# wording needs a run that judges nothing at all: a URL that refuses the
# connection. Expecting it on the empty-host case was my own mistake -- the
# script was right there and said "some results could not be judged".
T-Run 'a run that judged nothing says exactly that' 2 'judged no PHP runtime at all' @('-RemoteOnly', 'http://127.0.0.1:1/')

# A file without a version resource: unknown, because the patch level cannot
# be read -- not ok and not vuln.
# An installation without any php.ini: PHP falls back to its compiled
# defaults, so the measures are missing (warning), and the host stays clean.
$r = New-FakeRoot 'noini'
New-FakePhp (Join-Path $r 'PHP') '8.3.36'
T-Run 'a host without any php.ini is still clean' 0 'WARN\]\s+mitigation' @('-NoRemote', '-TestRoot', $r)
T-Run 'and says PHP runs on its compiled defaults' 0 'compiled defaults' @('-NoRemote', '-TestRoot', $r)

# The shape measured on the real server: two installations, only one of them
# with an ini. The file of the one that is NOT serving must not stand in for
# the other -- that was reported per host once and said nothing about the
# installation IIS actually used.
$r = New-FakeRoot 'mixedini'
New-FakePhp (Join-Path $r 'php\8.3.35') '8.3.35'
New-FakePhp (Join-Path $r 'php\8.3.36') '8.3.36'
Set-Content -Path (Join-Path $r 'php\8.3.35\php.ini') -Value @('memory_limit = -1', 'post_max_size = 8M',
    'session.upload_progress.enabled = 0', 'expose_php = 0') -Encoding Ascii
T-Run 'an installation without its own ini is named' 1 'mitigation\s+\S*8\.3\.36' @('-NoRemote', '-TestRoot', $r)
T-Run 'and the other ini is still read' 1 'INFO\]\s+mitigation' @('-NoRemote', '-TestRoot', $r)

$r = New-FakeRoot 'noresource'
New-Item -ItemType Directory -Force -Path (Join-Path $r 'PHP') | Out-Null
Set-Content -Path (Join-Path $r 'PHP\php.exe') -Value 'not a PE file' -Encoding Ascii
T-Run 'a file without a version resource is undecided' 2 'no readable version resource' @('-NoRemote', '-TestRoot', $r)

# ---------------------------------------------------------------------------
Write-Host 'How PHP is served (IIS configuration)'

$r = New-FakeRoot 'iis'
New-FakePhp (Join-Path $r 'PHP') '8.3.35'
Write-IisConfig $r @(@{ FullPath = 'C:\PHP\php-cgi.exe'; InstanceMaxRequests = '10000' })
T-Run 'a FastCGI handler is reported' 1 'WARN\]\s+sapi' @('-NoRemote', '-TestRoot', $r)
T-Run 'and php-cgi is judged like FPM' 1 'judge this like PHP-FPM' @('-NoRemote', '-TestRoot', $r)
T-Run 'instanceMaxRequests is reported as measured' 1 'instanceMaxRequests = 10000' @('-NoRemote', '-TestRoot', $r)

# The pipe form. scriptProcessor is not a path: with per-site arguments it
# reads "C:\PHP\php-cgi.exe|-d open_basedir=...", and reading it as a path
# loses every multi-site host, which is the normal shared-hosting shape.
$r = New-FakeRoot 'iis-args'
New-FakePhp (Join-Path $r 'PHP') '8.3.35'
Write-IisConfig $r @(@{ FullPath = 'C:\PHP\php-cgi.exe'; Arguments = '-d open_basedir=C:\sites\one'; InstanceMaxRequests = '200' })
T-Run 'the pipe form of scriptProcessor is split at the pipe' 1 'php-cgi\.exe\. php\.net names php-cgi' @('-NoRemote', '-TestRoot', $r)
T-Run 'forced settings in the pool arguments are reported' 1 'forces settings through its arguments' @('-NoRemote', '-TestRoot', $r)

# An unreadable applicationHost.config has to be said out loud. Its ACL grants
# SYSTEM and Administrators only, so this is the normal case without
# elevation, and a run that silently skips IIS would look clean.
$r = New-FakeRoot 'iis-broken'
New-FakePhp (Join-Path $r 'PHP') '8.3.36'
Set-Content -Path (Join-Path $r 'Windows\system32\inetsrv\config\applicationHost.config') -Value '<configuration><not-closed>' -Encoding UTF8
T-Run 'an unreadable IIS configuration is reported, not skipped' 2 'could not be read' @('-NoRemote', '-TestRoot', $r)

# ---------------------------------------------------------------------------
Write-Host 'Runtime configuration'

$r = New-FakeRoot 'mitig-missing'
New-FakePhp (Join-Path $r 'PHP') '8.3.36'
Set-Content -Path (Join-Path $r 'PHP\php.ini') -Encoding Ascii -Value @(
    'memory_limit = 128M', 'post_max_size = 64M', 'upload_max_filesize = 32M',
    'session.upload_progress.enabled = On', 'expose_php = On')
T-Run 'a finite memory_limit is a missing measure' 0 'memory_limit=-1 \(now 128M\)' @('-NoRemote', '-TestRoot', $r)
T-Run 'post_max_size is judged against the advisory numbers' 0 '8M without file uploads, 32M with' @('-NoRemote', '-TestRoot', $r)
T-Run 'expose_php has its own line and is not an advisory measure' 0 'WARN\]\s+disclosure' @('-NoRemote', '-TestRoot', $r)

$r = New-FakeRoot 'mitig-set'
New-FakePhp (Join-Path $r 'PHP') '8.3.36'
Set-Content -Path (Join-Path $r 'PHP\php.ini') -Encoding Ascii -Value @(
    'memory_limit = -1', 'post_max_size = 8M', 'upload_max_filesize = 2M',
    'session.upload_progress.enabled = 0', 'expose_php = 0')
T-Run 'every readable measure set is info, never ok' 0 'INFO\]\s+mitigation' @('-NoRemote', '-TestRoot', $r)
T-Run 'and it quotes that this is not safety' 0 'do not make an installation safe' @('-NoRemote', '-TestRoot', $r)
T-Run 'expose_php off is reported as ok' 0 'OK \]\s+disclosure' @('-NoRemote', '-TestRoot', $r)

$r = New-FakeRoot 'mitig-upload'
New-FakePhp (Join-Path $r 'PHP') '8.3.36'
Set-Content -Path (Join-Path $r 'PHP\php.ini') -Encoding Ascii -Value @(
    'memory_limit = -1', 'post_max_size = 8M', 'upload_max_filesize = 16M',
    'session.upload_progress.enabled = 0', 'expose_php = 0')
T-Run 'upload_max_filesize above post_max_size is a missing measure' 0 'upload_max_filesize below post_max_size' @('-NoRemote', '-TestRoot', $r)

# The invented number is gone: the advisory names no value for this setting.
$r = New-FakeRoot 'nesting'
New-FakePhp (Join-Path $r 'PHP') '8.3.36'
Set-Content -Path (Join-Path $r 'PHP\php.ini') -Encoding Ascii -Value @(
    'memory_limit = -1', 'post_max_size = 8M', 'session.upload_progress.enabled = 0',
    'expose_php = 0', 'max_input_nesting_level = 64')
T-Run 'max_input_nesting_level is context, not a verdict' 0 'names no value for this PHP setting' @('-NoRemote', '-TestRoot', $r)
$out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $target '-NoRemote' '-TestRoot' $r 2>&1 | Out-String
if ($out -match 'about 8') { T-Bad 'the invented "about 8" is gone' $out } else { T-Ok 'the invented "about 8" is gone' }

# ---------------------------------------------------------------------------
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 }
exit 0
