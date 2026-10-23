#Requires -Version 5.1
<#
php2shell-check.ps1 - read-only exposure check for the "php2shell" PHP
vulnerabilities CVE-2026-109618 and CVE-2026-109619 (GHSA-w8hw-w9fx-j79w),
for Windows hosts and for websites checked from a Windows host.

https://github.com/EXT-IT/php2shell-check
Copyright (c) 2026 EXT IT GmbH. MIT License, see LICENSE.
Provided as is, without warranty and without support.

The script never changes anything and sends no exploit traffic. Local checks
read files, the registry, the IIS configuration and the process list; remote
checks send one ordinary GET request per URL and resolve its DNS name.

It never executes a PHP binary. On Windows that is not a limitation: every
official build carries its version in the file's version resource, so the
version is read out of the file (measured on 8.3.36 and 8.5.12: php.exe,
php-cgi.exe, php8.dll, php8ts.dll and php8apache2_4.dll all report it).

Windows differs from Linux in three ways that shape this script:

  * No backports. The php.net builds carry real upstream versions, so there
    is no distribution table here - the upstream comparison is the whole
    verdict. The exception is 7.4, 8.0 and 8.1: the fixes for those branches
    exist only as source backports that do not raise the version number, and
    there are no Windows binaries at all. A patched self-build of 8.1.34 is
    indistinguishable from an unpatched one, so those branches are reported
    as undecided, never as ok.
  * PHP does not run inside w3wp.exe. Under FastCGI it runs in its own
    php-cgi.exe processes, so the IIS worker carries no PHP to inspect.
  * A running process cannot be proven to run current code. A loaded DLL
    cannot be overwritten (measured: "The process cannot access the file
    because it is being used by another process"), so an update means a new
    directory or the documented rename trick. After a rename,
    ProcessModule.FileVersionInfo reports the NEW version for a process that
    still runs the old code, because that property reads the file on disk and
    not the image in memory. Timestamps do not close the gap either:
    Expand-Archive takes LastWriteTime from the zip entry (the 8.3.36 files
    carry 2026-10-20, the release is from 2026-10-21), and CreationTime can
    be restored by NTFS tunneling (measured on Windows Server 2022: delete
    and recreate under the same name brought the old CreationTime back).
    So this script collects evidence that an in-place swap happened and says
    plainly that a worker may serve older code than its file shows. It never
    reports freshness it cannot prove.
#>

[CmdletBinding()]
param(
    # Websites to check from here. Same contract as the bash version.
    # Position 0 as well as ValueFromRemainingArguments: without the position,
    # "-File script.ps1 -RemoteOnly https://example.com" left $Url empty.
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]] $Url,

    [switch] $RemoteOnly,
    [switch] $NoRemote,
    [switch] $Json,
    [switch] $Quiet,
    [switch] $NoColor,
    [switch] $Version,
    [switch] $Help,

    # Test hook: treat this directory as the root of the system to inspect.
    # The bash version calls it P2S_TEST_ROOT and the tests use it the same way.
    [string] $TestRoot = $env:P2S_TEST_ROOT
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Off

$script:P2sScriptVersion = '3.1.1'
$script:P2sDataDate = '2026-10-22'
$script:P2sAdvisory = 'GHSA-w8hw-w9fx-j79w'
$script:P2sAdvisoryUrl = 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'
$script:P2sRepoUrl = 'https://github.com/EXT-IT/php2shell-check'
$script:P2sInfoUrl = 'https://ext-it.tech/php2shell/'
$script:P2sCve1 = 'CVE-2026-109618'
$script:P2sCve2 = 'CVE-2026-109619'

# ---------------------------------------------------------------------------
# Vulnerability data. Keep in step with php2shell-check.sh - ci/data_parity.py
# compares both files and fails the build when they drift.
# ---------------------------------------------------------------------------

# First fixed upstream release per branch (php.net, 2026-10-21).
$script:P2sUpstreamFixed = @{
    '8.5' = '8.5.12'
    '8.4' = '8.4.27'
    '8.3' = '8.3.36'
    '8.2' = '8.2.35'
}

# Branches with no released upstream fix. The PHP team published source
# backports for 7.4, 8.0 and 8.1; those do not raise the version number and
# there are no Windows binaries for them, so the patch level of such a build
# cannot be read from the file at all. Everything older never got a fix.
# The patterns are the ones php2shell-check.sh uses, so the two files can be
# compared literally by tests/data_parity.py.
$script:P2sNoFixBranchPatterns = @('5.*', '7.*', '8.0', '8.1')

# Upstream numbers that Linux distributions freeze while backporting. A remote
# banner showing one of these cannot be judged, whatever host answers.
$script:P2sFrozenVersions = @(
    '5.5.9', '7.0.33', '7.2.24', '7.4.3', '7.4.33', '8.1.2', '8.3.6', '8.5.4', '8.5.9'
)

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

$script:Findings = New-Object System.Collections.ArrayList
$script:Hints1 = New-Object System.Collections.ArrayList
$script:Hints2 = New-Object System.Collections.ArrayList
$script:Hints3 = New-Object System.Collections.ArrayList
$script:UrlsSeen = 0
$script:UrlsOpen = 0
$script:LocalRan = $false
$script:SectionShown = @{}

# One place that decides whether a line is tinted. Write-Host refuses $null as
# a colour, so -NoColor cannot be done by blanking the variable; it has to pick
# a different call. Everything that colours output goes through here.
$script:NoColour = $false

# COMPUTERNAME is set on every Windows session, but it is an environment
# variable and therefore droppable: a service started with a scrubbed
# environment reports an empty host, which lands in the JSON output as null.
# MachineName comes from the API.
$script:HostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }

function Write-Tinted {
    param([string] $Text, [string] $Colour, [switch] $NoNewline)
    if ($script:NoColour -or -not $Colour) {
        if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
        return
    }
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Colour -NoNewline }
    else { Write-Host $Text -ForegroundColor $Colour }
}

function Sort-Ordinal {
    param([Parameter(ValueFromPipeline = $true)] [string[]] $Value)
    begin { $all = New-Object System.Collections.ArrayList }
    process { foreach ($v in $Value) { if ($null -ne $v -and -not $all.Contains($v)) { $null = $all.Add($v) } } }
    end {
        $arr = [string[]] $all.ToArray()
        [Array]::Sort($arr, [StringComparer]::OrdinalIgnoreCase)
        return $arr
    }
}

function Add-Finding {
    param(
        [ValidateSet('vuln', 'unknown', 'warn', 'ok', 'info')] [string] $Status,
        [string] $Check,
        [string] $Target,
        [string] $Detail,
        [string] $Hint
    )
    $null = $script:Findings.Add([pscustomobject]@{
        Status = $Status; Check = $Check; Target = $Target; Detail = $Detail; Hint = $Hint
    })
    if ($Hint) {
        switch ($Status) {
            'vuln' { if (-not $script:Hints1.Contains($Hint)) { $null = $script:Hints1.Add($Hint) } }
            'warn' { if (-not $script:Hints2.Contains($Hint)) { $null = $script:Hints2.Add($Hint) } }
            'unknown' { if (-not $script:Hints2.Contains($Hint)) { $null = $script:Hints2.Add($Hint) } }
            default { if (-not $script:Hints3.Contains($Hint)) { $null = $script:Hints3.Add($Hint) } }
        }
    }
    if ($Json -or $Quiet) { return }

    $tag = switch ($Status) {
        'vuln'    { '[VULN]' }
        'unknown' { '[ ?? ]' }
        'warn'    { '[WARN]' }
        'ok'      { '[ OK ]' }
        default   { '[INFO]' }
    }
    $colour = switch ($Status) {
        'vuln'    { 'Red' }
        'unknown' { 'Yellow' }
        'warn'    { 'Yellow' }
        'ok'      { 'Green' }
        default   { 'Cyan' }
    }
    Write-Host '  ' -NoNewline
    Write-Tinted $tag -Colour $colour -NoNewline
    Write-Host (' {0,-14} {1}' -f $Check, $Target)
    Write-Host ('         {0}' -f $Detail)
    if ($Hint) { Write-Tinted ('         -> {0}' -f $Hint) -Colour 'DarkGray' }
}

function Write-Section {
    param([string] $Title)
    if ($Json -or $Quiet) { return }
    if ($script:SectionShown[$Title]) { return }
    $script:SectionShown[$Title] = $true
    Write-Host ''
    Write-Tinted $Title -Colour 'White'
}

# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

function Get-PhpBranch {
    param([string] $VersionString)
    if ($VersionString -match '^(\d+\.\d+)\.') { return $Matches[1] }
    return ''
}

# Compare two dotted versions numerically. Returns -1, 0 or 1, or $null when
# either side is not a plain x.y.z - the caller must treat $null as "cannot
# decide" and never as "ok". The bash version's _p2s_ver_ge was fail-open on
# junk input; this one refuses instead.
function Compare-PhpVersion {
    param([string] $A, [string] $B)
    if ($A -notmatch '^\d+(\.\d+){0,3}$' -or $B -notmatch '^\d+(\.\d+){0,3}$') { return $null }
    $pa = @($A -split '\.' | ForEach-Object { [int] $_ })
    $pb = @($B -split '\.' | ForEach-Object { [int] $_ })
    for ($i = 0; $i -lt 4; $i++) {
        $x = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}

# Verdict for a plain upstream version. Returns a hashtable with Status,
# Detail and Hint, mirroring _p2s_judge_upstream in the bash version.
function Get-UpstreamVerdict {
    param([string] $PhpVersion)
    $branch = Get-PhpBranch $PhpVersion
    if (-not $branch) {
        return @{ Status = 'unknown'
                  Detail = "PHP version '$PhpVersion' could not be read as x.y.z"
                  Hint   = "Compare with $script:P2sAdvisoryUrl" }
    }
    $noFix = $false
    foreach ($pat in $script:P2sNoFixBranchPatterns) { if ($branch -like $pat) { $noFix = $true; break } }
    if ($noFix) {
        # The decisive Windows case. The fix for these branches exists only as
        # a source backport that leaves the version number untouched, and
        # php.net ships no Windows binary for them at all. So a file reading
        # 8.1.34 may be patched or unpatched, and this script cannot tell.
        return @{ Status = 'unknown'
                  Detail = "PHP $PhpVersion, branch $branch is end of life: its fix exists only as a source backport that does not raise the version number, so the patch level cannot be read from the file"
                  Hint   = 'Move this host to a supported branch (8.2.35, 8.3.36, 8.4.27 or 8.5.12); if you built the backport yourself, track that build outside this script' }
    }
    $fixed = $script:P2sUpstreamFixed[$branch]
    if (-not $fixed) {
        return @{ Status = 'unknown'
                  Detail = "PHP $PhpVersion, branch $branch is not covered by the advisory data of $script:P2sDataDate"
                  Hint   = "Compare with $script:P2sAdvisoryUrl" }
    }
    $cmp = Compare-PhpVersion $PhpVersion $fixed
    if ($null -eq $cmp) {
        return @{ Status = 'unknown'
                  Detail = "PHP $PhpVersion could not be compared with $fixed"
                  Hint   = "Compare with $script:P2sAdvisoryUrl" }
    }
    if ($cmp -ge 0) {
        return @{ Status = 'ok'; Detail = "PHP $PhpVersion (fixed from $fixed)"; Hint = '' }
    }
    return @{ Status = 'vuln'
              Detail = "PHP $PhpVersion, fixed in $fixed"
              Hint   = "Update PHP to $fixed or later, then recycle the FastCGI application or the application pool" }
}

# ---------------------------------------------------------------------------
# Reading a PHP version out of a file, without executing it
# ---------------------------------------------------------------------------

# The binary FILEVERSION fields are the reliable source. The ProductVersion
# string carries pre-release suffixes (8.5.0RC1, 8.7.0-dev) that no version
# cast survives, so the string is only displayed, never compared.
function Get-PhpFileVersion {
    param([string] $Path)
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch { return $null }
    $vi = $item.VersionInfo
    if (-not $vi) { return $null }
    # A file without a version resource answers with empty properties rather
    # than throwing, which is documented behaviour.
    if ($null -eq $vi.FileMajorPart -and -not $vi.ProductVersion) { return $null }
    $numeric = '{0}.{1}.{2}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart
    if ($numeric -eq '0.0.0') {
        # Measured on Windows Server 2022: a PE without a version resource does
        # not answer with empty properties, it answers 0.0.0.0. A zero version
        # has to read as "nothing there" -- otherwise the report explains that
        # "branch 0.0 is not covered by the advisory data" instead of saying
        # the file carries no readable version.
        if ($vi.ProductVersion -match '^(\d+\.\d+\.\d+)' -and $Matches[1] -ne '0.0.0') {
            $numeric = $Matches[1]
        } else {
            return $null
        }
    }
    return [pscustomobject]@{
        Path           = $item.FullName
        Numeric        = $numeric
        ProductVersion = $vi.ProductVersion
        FileDescription = $vi.FileDescription
        IsDebug        = [bool] $vi.IsDebug
        CreationTime   = $item.CreationTime
        LastWriteTime  = $item.LastWriteTime
    }
}

function Resolve-UnderRoot {
    param([string] $Path)
    if (-not $TestRoot) { return $Path }
    if ($Path -match '^[A-Za-z]:\\(.*)$') { return (Join-Path $TestRoot $Matches[1]) }
    return (Join-Path $TestRoot $Path.TrimStart('\'))
}

function Show-PathForReport {
    param([string] $Path)
    if ($TestRoot -and $Path.StartsWith($TestRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($TestRoot.Length)
    }
    return $Path
}

# Windows paths are case-insensitive, and the same directory reaches this
# script in different spellings: C:\PHP\8.3.35 from the directory list,
# C:\php\8.3.35 out of the IIS configuration. Neither Get-Item nor GetFullPath
# fixes the case, so the real spelling is read from the filesystem segment by
# segment. Without it the same installation appears twice in one report.
function Get-RealCasePath {
    param([string] $Path)
    try {
        $full = [IO.Path]::GetFullPath($Path)
    } catch { return $Path }
    $parts = $full.Split([IO.Path]::DirectorySeparatorChar)
    if ($parts.Count -lt 2) { return $full }
    $current = $parts[0].ToUpperInvariant()     # drive letter
    if (-not $current.EndsWith(':')) { return $full }
    $built = $current + [IO.Path]::DirectorySeparatorChar
    for ($i = 1; $i -lt $parts.Count; $i++) {
        if (-not $parts[$i]) { continue }
        try {
            $child = Get-ChildItem -LiteralPath $built -Force -ErrorAction Stop |
                     Where-Object { $_.Name -eq $parts[$i] } | Select-Object -First 1
        } catch { $child = $null }
        $name = if ($child) { $child.Name } else { $parts[$i] }
        $built = Join-Path $built $name
    }
    return $built
}

# ---------------------------------------------------------------------------
# Where PHP lives. Every entry is a layout that exists in the wild; the IIS
# configuration and the process list are the reliable sources, these globs
# only catch an installation that nothing currently references.
# Never -Recurse: XAMPP ships a second complete copy under
# php\windowsXamppPhp, and C:\inetpub holds customer data.
# ---------------------------------------------------------------------------

function Get-PhpDirectoryCandidates {
    $pf = ${env:ProgramFiles}
    $pf86 = ${env:ProgramFiles(x86)}
    $pd = $env:ProgramData
    $up = $env:USERPROFILE
    $lad = $env:LOCALAPPDATA

    $globs = New-Object System.Collections.ArrayList
    foreach ($g in @(
        'C:\PHP', 'C:\PHP\*', 'C:\inetpub\php\*',
        "$pf\PHP", "$pf\PHP\v*", "$pf86\PHP\v*",
        # Chocolatey installs NTS by default, so php8.dll and no php8ts.dll.
        'C:\tools\php[0-9][0-9]', "$env:ChocolateyToolsLocation\php[0-9][0-9]",
        # Scoop keeps the active php.ini under ...\cli\php.ini.
        "$up\scoop\apps\php\*", "$up\scoop\apps\php-nts\*", "$up\scoop\apps\php[0-9][0-9]\*",
        "$pd\scoop\apps\php*\*", "$env:SCOOP\apps\php*\*", "$env:SCOOP_GLOBAL\apps\php*\*",
        "$lad\Microsoft\WinGet\Packages\PHP.PHP.*", "$pf\WinGet\Packages\PHP.PHP.*",
        "$pf86\WinGet\Packages\PHP.PHP.*",
        'C:\xampp\php',
        'C:\wamp64\bin\php\php*', 'C:\wamp\bin\php\php*',
        'C:\laragon\bin\php\*',
        "$pf86\EasyPHP-Devserver-*\eds-binaries\php\php*", 'C:\EasyPHP-Devserver-*\eds-binaries\php\php*',
        # Plesk for Windows. Documented only in vendor support notes, so the
        # IIS configuration stays the stronger source for such a host.
        "$pf86\Plesk\Additional\PleskPHP*", "$pf86\Plesk\Additional\php*",
        "$pf86\Parallels\Plesk\Additional\PleskPHP*", "$pf86\Parallels\Plesk\Additional\php*",
        "$pf\Zend\ZendPHP\*", "$pf\Zend\*", "$pf86\Zend\*"
    )) {
        if ($g -and $g -notmatch '^\\\\' -and $g -notmatch '^\$') { $null = $globs.Add($g) }
    }

    # Drive-letter wildcards are not expanded by PowerShell, so the drives are
    # enumerated instead. A second XAMPP or WampServer on D: is common.
    $extra = @('xampp\php', 'wamp64\bin\php\php*', 'wamp\bin\php\php*', 'laragon\bin\php\*')
    try {
        $drives = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
                  Select-Object -ExpandProperty DeviceID
    } catch { $drives = @('C:') }
    foreach ($d in $drives) {
        if ($d -eq 'C:') { continue }
        foreach ($e in $extra) { $null = $globs.Add((Join-Path "$d\" $e)) }
    }

    $dirs = New-Object System.Collections.ArrayList
    foreach ($g in $globs) {
        $probe = Resolve-UnderRoot $g
        try {
            foreach ($p in (Resolve-Path -Path $probe -ErrorAction SilentlyContinue)) {
                if (Test-Path -LiteralPath $p.Path -PathType Container) { $null = $dirs.Add($p.Path) }
            }
        } catch { }
    }
    return ($dirs | Sort-Ordinal)
}

$script:PhpFileNames = @('php.exe', 'php-cgi.exe', 'php-win.exe', 'phpdbg.exe')
$script:PhpDllPatterns = @('php[0-9].dll', 'php[0-9]ts.dll', 'php[0-9]apache2_4.dll')

# ---------------------------------------------------------------------------
# The IIS configuration: the reliable source for what actually serves PHP
# ---------------------------------------------------------------------------

function Get-IisPhpConfiguration {
    $result = [pscustomobject]@{
        Readable      = $false
        Reason        = ''
        Applications  = New-Object System.Collections.ArrayList   # fullPath, arguments, instanceMaxRequests
        Handlers      = New-Object System.Collections.ArrayList   # name, path, processor, module
    }
    $cfg = Resolve-UnderRoot "$env:windir\system32\inetsrv\config\applicationHost.config"
    if (-not (Test-Path -LiteralPath $cfg)) {
        $result.Reason = 'no applicationHost.config, so IIS is not installed on this host'
        return $result
    }
    try {
        [xml] $x = Get-Content -LiteralPath $cfg -ErrorAction Stop
    } catch {
        # Measured on Windows Server 2022: the ACL of that file grants
        # TrustedInstaller, SYSTEM and Administrators only. Without elevation
        # this is the normal outcome, and it has to be said out loud.
        $result.Reason = "applicationHost.config exists but could not be read ($($_.Exception.Message.Split([Environment]::NewLine)[0]))"
        return $result
    }
    $result.Readable = $true
    $ws = $x.configuration.'system.webServer'
    if ($ws -and $ws.fastCgi) {
        foreach ($a in @($ws.fastCgi.application)) {
            if (-not $a -or -not $a.fullPath) { continue }
            $null = $result.Applications.Add([pscustomobject]@{
                FullPath = $a.fullPath
                Arguments = [string] $a.arguments
                # Default is 200 when the attribute is absent, but every
                # example from Microsoft and php.net sets 10000, so the actual
                # value is what gets reported.
                InstanceMaxRequests = if ($a.instanceMaxRequests) { [string] $a.instanceMaxRequests } else { '200 (default)' }
                EnvironmentVariables = @(if ($a.environmentVariables) { $a.environmentVariables.environmentVariable } else { @() })
            })
        }
    }
    foreach ($node in @('handlers')) {
        if (-not $ws -or -not $ws.$node) { continue }
        foreach ($h in @($ws.$node.add)) {
            if (-not $h -or -not $h.scriptProcessor) { continue }
            # scriptProcessor is not a path: with per-site arguments it reads
            # "C:\PHP\php-cgi.exe|-d open_basedir=C:\Websites\Site1" and that
            # whole string is the key of the FastCGI application. Measured on
            # the test host. Reading it as a path loses every multi-site
            # setup, which is the normal shared-hosting and Plesk shape.
            $processor = ($h.scriptProcessor -split '\|', 2)[0]
            $null = $result.Handlers.Add([pscustomobject]@{
                Name = [string] $h.name
                Path = [string] $h.path
                Processor = $processor
                Module = [string] $h.modules
                Raw = [string] $h.scriptProcessor
            })
        }
    }
    return $result
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

function Test-Elevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-PrivilegeCheck {
    if ($TestRoot) { return }
    if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
        # EnumProcessModules fails with ERROR_PARTIAL_COPY across bitness, so
        # a 32-bit PowerShell would silently see no PHP in 64-bit workers.
        Write-Section 'Privileges'
        Add-Finding -Status unknown -Check bitness -Target 'this PowerShell' `
            -Detail '32-bit PowerShell on a 64-bit Windows: the module list of 64-bit processes cannot be read, so a PHP loaded there stays invisible' `
            -Hint 'Run this script from the 64-bit PowerShell at %windir%\System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    if (-not (Test-Elevated)) {
        Write-Section 'Privileges'
        Add-Finding -Status unknown -Check privileges -Target $script:HostName `
            -Detail 'not running as administrator: the IIS configuration is not readable (its ACL grants SYSTEM and Administrators only) and the processes of other users stay hidden' `
            -Hint 'Run this script in an elevated PowerShell for a complete answer'
    }
}

function Invoke-BinaryCheck {
    param([System.Collections.ArrayList] $Judged)

    Write-Section 'PHP installations on this host'
    $seen = @{}
    $found = 0

    # Every path the IIS configuration points at, then the directory globs.
    # Configuration first: it is the one source that knows about a PHP in a
    # place nobody would guess.
    $paths = New-Object System.Collections.ArrayList
    $iis = $script:Iis
    if ($iis.Readable) {
        foreach ($a in $iis.Applications) { $null = $paths.Add((Resolve-UnderRoot $a.FullPath)) }
        foreach ($h in $iis.Handlers) { $null = $paths.Add((Resolve-UnderRoot $h.Processor)) }
    }
    foreach ($d in (Get-PhpDirectoryCandidates)) {
        foreach ($n in $script:PhpFileNames) {
            $p = Join-Path $d $n
            if (Test-Path -LiteralPath $p -PathType Leaf) { $null = $paths.Add($p) }
        }
        foreach ($pat in $script:PhpDllPatterns) {
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $d -Filter $pat -File -ErrorAction SilentlyContinue)) {
                    $null = $paths.Add($f.FullName)
                }
            } catch { }
        }
    }

    # One verdict per installation, not per executable. A php.net build ships
    # php.exe, php-cgi.exe, php-win.exe, phpdbg.exe and the core DLL in one
    # directory, all carrying the same version resource, and reporting each of
    # them turned a host with two installations into eight findings that said
    # the same thing. Grouped by directory AND version, so a directory that
    # really holds two versions still shows both.
    $groups = @{}
    foreach ($p in ($paths | Sort-Ordinal)) {
        if (-not $p -or $seen[$p.ToLowerInvariant()]) { continue }
        $seen[$p.ToLowerInvariant()] = $true
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $info = Get-PhpFileVersion $p
        $dir = Split-Path -Parent $p
        $key = '{0}|{1}' -f $dir.ToLowerInvariant(), $(if ($info) { $info.Numeric } else { 'unreadable' })
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [pscustomobject]@{
                Dir = $dir
                Info = $info
                Files = (New-Object System.Collections.ArrayList)
            }
        }
        $null = $groups[$key].Files.Add((Split-Path -Leaf $p))
        $null = $Judged.Add($p)
    }

    foreach ($g in ($groups.Values | Sort-Object { $_.Dir.ToLowerInvariant() })) {
        $found++
        $target = Show-PathForReport (Get-RealCasePath $g.Dir)
        $files = (($g.Files | Sort-Ordinal) -join ', ')
        if (-not $g.Info) {
            Add-Finding -Status unknown -Check php-binary -Target $target `
                -Detail ('the files here carry no readable version resource, so the patch level cannot be read ({0})' -f $files) `
                -Hint 'Check this installation by hand, or replace it with an official build from php.net'
            continue
        }
        $verdict = Get-UpstreamVerdict $g.Info.Numeric
        $detail = '{0} ({1})' -f $verdict.Detail, $files
        if ($g.Info.ProductVersion -and $g.Info.ProductVersion -ne $g.Info.Numeric) {
            $detail += ", version resource says $($g.Info.ProductVersion)"
        }
        if ($g.Info.IsDebug) { $detail += ', debug build' }
        Add-Finding -Status $verdict.Status -Check php-binary -Target $target `
            -Detail $detail -Hint $verdict.Hint
    }

    if ($found -eq 0) {
        Add-Finding -Status unknown -Check php-binary -Target $script:HostName `
            -Detail 'no PHP found in the known locations, in the IIS configuration or in the process list, so this run cannot say whether this host serves PHP' `
            -Hint 'If PHP lives somewhere unusual on this host, check that path by hand'
    }
}

function Invoke-SapiCheck {
    $iis = $script:Iis
    if (-not $iis.Readable) {
        if ($iis.Reason -and $iis.Reason -notlike 'no applicationHost.config*') {
            Write-Section 'How PHP is served'
            Add-Finding -Status unknown -Check sapi -Target $script:HostName `
                -Detail $iis.Reason -Hint 'Run this script elevated so it can read how IIS serves PHP'
        }
        return
    }
    if ($iis.Handlers.Count -eq 0 -and $iis.Applications.Count -eq 0) { return }

    Write-Section 'How PHP is served'
    foreach ($h in $iis.Handlers) {
        if ($h.Module -eq 'FastCgiModule') {
            Add-Finding -Status warn -Check sapi -Target ('{0} ({1})' -f $h.Name, $h.Path) `
                -Detail ("served by php-cgi through IIS FastCGI: {0}. php.net names php-cgi under 'Who is at risk', the advisories validate no exploit against it" -f $h.Processor) `
                -Hint 'A FastCGI process serves many requests, so judge this like PHP-FPM, not like one process per request'
        } elseif ($h.Module -eq 'IsapiModule') {
            Add-Finding -Status warn -Check sapi -Target ('{0} ({1})' -f $h.Name, $h.Path) `
                -Detail ("served through the ISAPI module: {0}. That SAPI was dropped upstream after PHP 5.3, so this installation is far beyond any fix" -f $h.Processor) `
                -Hint 'Move this site to php-cgi behind FastCGI on a supported PHP branch'
        }
    }
    foreach ($a in $iis.Applications) {
        # The FastCGI counterpart of pm.max_requests. Not an advisory measure,
        # and not presented as one.
        Add-Finding -Status info -Check fastcgi-pool -Target $a.FullPath `
            -Detail ('instanceMaxRequests = {0}{1}' -f $a.InstanceMaxRequests, $(if ($a.Arguments) { ", arguments '$($a.Arguments)'" } else { '' })) `
            -Hint 'A low instanceMaxRequests retires workers sooner; it is not one of the advisory measures'
    }
}

function Invoke-ProcessCheck {
    param([System.Collections.ArrayList] $Judged)
    if ($TestRoot) { return }

    $names = @('php-cgi', 'php', 'php-win', 'httpd', 'frankenphp')
    $procs = @()
    foreach ($n in $names) {
        try { $procs += @(Get-Process -Name $n -ErrorAction SilentlyContinue) } catch { }
    }
    if ($procs.Count -eq 0) { return }

    Write-Section 'PHP processes running right now'
    $seen = @{}
    foreach ($p in $procs) {
        $exe = $null
        try { $exe = $p.Path } catch { }
        if (-not $exe) {
            Add-Finding -Status unknown -Check process -Target ('{0} pid {1}' -f $p.ProcessName, $p.Id) `
                -Detail 'the executable path of this process is not readable, so its PHP version cannot be judged' `
                -Hint 'Run this script elevated'
            continue
        }
        $key = $exe.ToLowerInvariant()
        if ($seen[$key]) { continue }
        $seen[$key] = $true

        $info = Get-PhpFileVersion $exe
        if (-not $info) { continue }
        $verdict = Get-UpstreamVerdict $info.Numeric
        $already = $Judged -contains $exe
        $detail = '{0}, serving requests right now' -f $verdict.Detail
        if ($verdict.Status -eq 'ok') {
            # The honest limit: this says the FILE is patched, not that the
            # running image is. A replaced-by-rename DLL would report the new
            # version for an old process, and no timestamp closes that gap.
            Add-Finding -Status info -Check process -Target (Show-PathForReport (Get-RealCasePath $exe)) `
                -Detail ("{0}. The file is patched; whether this worker already runs that code cannot be read from outside the process" -f $verdict.Detail) `
                -Hint 'After updating PHP, recycle the FastCGI application or the application pool so no worker keeps the old code'
        } else {
            Add-Finding -Status $verdict.Status -Check process -Target (Show-PathForReport (Get-RealCasePath $exe)) `
                -Detail $detail -Hint $verdict.Hint
        }
        if (-not $already) { $null = $Judged.Add($exe) }
    }
}

# Positive evidence that someone replaced a loaded DLL in place: the old file
# left behind under another name, or a rename queued for the next boot.
function Invoke-StaleEvidenceCheck {
    $hits = New-Object System.Collections.ArrayList
    foreach ($d in (Get-PhpDirectoryCandidates)) {
        foreach ($pat in @('php[0-9]ts.dll.*', 'php[0-9].dll.*', 'php*.dll.old', 'php*.dll.bak')) {
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $d -Filter $pat -File -ErrorAction SilentlyContinue)) {
                    $null = $hits.Add($f.FullName)
                }
            } catch { }
        }
    }
    if (-not $TestRoot) {
        try {
            $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                        -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
            foreach ($entry in @($pending)) {
                if ($entry -and $entry -match '(?i)php') { $null = $hits.Add("pending rename: $entry") }
            }
        } catch { }
    }
    if ($hits.Count -eq 0) { return }

    Write-Section 'Traces of an in-place replacement'
    foreach ($h in ($hits | Sort-Ordinal)) {
        Add-Finding -Status warn -Check stale-trace -Target (Show-PathForReport $h) `
            -Detail 'a PHP library was replaced under a new name, which is how a loaded DLL is swapped on Windows: processes started before that still run the old code' `
            -Hint 'Recycle every FastCGI application and application pool, then remove the leftover file'
    }
}

# ---------------------------------------------------------------------------
# Runtime configuration. The measures php.net lists under "If you cannot
# update immediately", read out of php.ini and out of the places that
# override it. Nothing here is an "ok": that section opens with "while only
# an update is a complete solution, the following measures reduce exposure to
# specific attack paths but do not make an installation safe".
# ---------------------------------------------------------------------------

function Get-IniValue {
    param([string[]] $Lines, [string] $Key)
    $value = $null
    foreach ($l in $Lines) {
        if ($l -match ('^\s*' + [regex]::Escape($Key) + '\s*=\s*(.*?)\s*(;.*)?$')) {
            $value = $Matches[1].Trim('"').Trim()
        }
    }
    return $value
}

function Convert-IniBytes {
    param([string] $Value)
    if (-not $Value) { return -1 }
    if ($Value -eq '-1') { return -1 }
    if ($Value -match '^(\d+)\s*([KMG])?$') {
        $n = [int64] $Matches[1]
        switch ($Matches[2]) {
            'K' { return $n * 1KB }
            'M' { return $n * 1MB }
            'G' { return $n * 1GB }
            default { return $n }
        }
    }
    return -1
}

function Invoke-IniCheck {
    param([string] $IniPath, [string] $Label)
    try { $lines = Get-Content -LiteralPath $IniPath -ErrorAction Stop } catch { return }

    $missing = New-Object System.Collections.ArrayList
    $notes = New-Object System.Collections.ArrayList

    $mem = Get-IniValue $lines 'memory_limit'
    $post = Get-IniValue $lines 'post_max_size'
    $upload = Get-IniValue $lines 'upload_max_filesize'
    $upprog = Get-IniValue $lines 'session.upload_progress.enabled'
    $backtr = Get-IniValue $lines 'fatal_error_backtraces'
    $expose = Get-IniValue $lines 'expose_php'
    $nesting = Get-IniValue $lines 'max_input_nesting_level'

    # memory_limit=-1 is the first measure of that section.
    if ($mem -and $mem -ne '-1') { $null = $missing.Add("memory_limit=-1 (now $mem)") }

    # The two absolute numbers the advisory names: 8M without uploads, 32M
    # with. This script cannot know whether the application needs uploads, so
    # it never picks one of them for the reader.
    if ($post) {
        $pb = Convert-IniBytes $post
        if ($post -eq '0' -or $pb -lt 0) {
            $null = $missing.Add("a low post_max_size (8M without file uploads, 32M with; now $post, no limit)")
        } elseif ($pb -gt 32MB) {
            $null = $missing.Add("a low post_max_size (8M without file uploads, 32M with; now $post)")
        } elseif ($pb -gt 8MB) {
            # ${post} and not $post: PowerShell reads "$post:" as a
            # drive-qualified variable and refuses to parse the file.
            $null = $notes.Add("post_max_size is ${post}: the advisory asks for 8M where file uploads are not required and 32M where they are, so this value is low enough only if this installation needs uploads.")
        }
        if ($upload) {
            $ub = Convert-IniBytes $upload
            if ($ub -ge 0 -and $pb -ge 0 -and $ub -ge $pb) {
                $null = $missing.Add("upload_max_filesize below post_max_size (now $upload vs $post)")
            }
        }
    }

    # session.upload_progress.enabled defaults to 1 and php.ini-production
    # leaves it commented out, so a stock server has this measure off.
    if (-not $upprog -or $upprog -match '^(1|on|true)$') {
        $null = $missing.Add('session.upload_progress.enabled=0')
    }
    if ($backtr -match '^(1|on|true)$') { $null = $missing.Add('fatal_error_backtraces=0') }
    if ($nesting -match '^\d+$') {
        $null = $notes.Add("max_input_nesting_level is $nesting; the advisory asks for nesting depth to be limited at the web server or proxy level and names no value for this PHP setting.")
    }

    # expose_php is not one of the advisory's measures. It decides whether the
    # version is in the response headers, not whether the bug can be reached.
    if ($expose -match '^(1|on|true)$') {
        Add-Finding -Status warn -Check disclosure -Target $Label `
            -Detail 'expose_php is on, so the PHP version is in the response headers for everyone' `
            -Hint 'Set expose_php=0 so scanners cannot pick vulnerable targets by header'
    } elseif ($expose -match '^(0|off|false)$') {
        Add-Finding -Status ok -Check disclosure -Target $Label `
            -Detail 'expose_php is off, the response headers do not reveal the PHP version'
    }

    $noteText = if ($notes.Count) { ' ' + ($notes -join ' ') } else { '' }
    if ($missing.Count) {
        Add-Finding -Status warn -Check mitigation -Target $Label `
            -Detail ('temporary measures from the advisory not set: {0}.{1}' -f ($missing -join ' '), $noteText) `
            -Hint 'Until patched: set memory_limit=-1 and session.upload_progress.enabled=0 where applications cannot override them, keep post_max_size low, and recycle every worker. Only an update is a complete solution'
    } else {
        Add-Finding -Status info -Check mitigation -Target $Label `
            -Detail ('the temporary measures from the advisory that are readable here are set.{0} Only an update is a complete solution: these measures reduce exposure to specific attack paths but do not make an installation safe.' -f $noteText)
    }
}

# Which php.ini applies. Measured on a php.net installation: PHPRC is empty
# and HKLM\SOFTWARE\PHP does not exist, so the file next to the binary is the
# one that counts. The other sources are checked because each of them wins
# over that file when present.
function Invoke-ConfigurationCheck {
    param([System.Collections.ArrayList] $Judged)
    if ($Judged.Count -eq 0) { return }

    Write-Section 'Runtime configuration'
    $inis = New-Object System.Collections.ArrayList

    foreach ($key in @('HKLM:\SOFTWARE\PHP', 'HKLM:\SOFTWARE\WOW6432Node\PHP')) {
        if ($TestRoot) { break }
        try {
            $p = (Get-ItemProperty -Path $key -Name IniFilePath -ErrorAction SilentlyContinue).IniFilePath
            if ($p) {
                $cand = if (Test-Path -LiteralPath $p -PathType Container) { Join-Path $p 'php.ini' } else { $p }
                $null = $inis.Add([pscustomobject]@{ Path = $cand; Label = "$cand (from registry $key)" })
            }
        } catch { }
    }
    if (-not $TestRoot -and $env:PHPRC) {
        $p = $env:PHPRC
        $cand = if (Test-Path -LiteralPath $p -PathType Container) { Join-Path $p 'php.ini' } else { $p }
        $null = $inis.Add([pscustomobject]@{ Path = $cand; Label = "$cand (from PHPRC)" })
    }
    # An ini from the registry, PHPRC or the Windows directory applies to every
    # installation on the host; one next to a binary applies to that
    # installation only. The difference decides who is left without a file.
    $globalIni = $inis.Count -gt 0
    $dirsWithIni = @{}
    $judgedDirs = New-Object System.Collections.ArrayList

    foreach ($bin in $Judged) {
        $dir = Split-Path -Parent $bin
        if (-not $dir) { continue }
        if (-not $judgedDirs.Contains($dir)) { $null = $judgedDirs.Add($dir) }
        # php-SAPI.ini wins over php.ini for that SAPI, which is why the
        # per-SAPI name is checked first.
        $leaf = [IO.Path]::GetFileNameWithoutExtension($bin)
        foreach ($n in @("$leaf.ini", 'php.ini')) {
            $c = Join-Path $dir $n
            if (Test-Path -LiteralPath $c -PathType Leaf) {
                $null = $inis.Add([pscustomobject]@{ Path = $c; Label = (Show-PathForReport (Get-RealCasePath $c)) })
                $dirsWithIni[$dir.ToLowerInvariant()] = $true
            }
        }
        # WampServer serves Apache from a different file than the CLI.
        $apacheIni = Join-Path $dir 'phpForApache.ini'
        if (Test-Path -LiteralPath $apacheIni -PathType Leaf) {
            $null = $inis.Add([pscustomobject]@{ Path = $apacheIni; Label = (Show-PathForReport (Get-RealCasePath $apacheIni)) + ' (Apache)' })
            $dirsWithIni[$dir.ToLowerInvariant()] = $true
        }
    }
    foreach ($n in @('php-cgi.ini', 'php.ini')) {
        $c = Resolve-UnderRoot (Join-Path $env:windir $n)
        if (Test-Path -LiteralPath $c -PathType Leaf) {
            $null = $inis.Add([pscustomobject]@{ Path = $c; Label = (Show-PathForReport (Get-RealCasePath $c)) })
            $globalIni = $true
        }
    }

    $done = @{}
    foreach ($i in $inis) {
        $k = $i.Path.ToLowerInvariant()
        if ($done[$k]) { continue }
        $done[$k] = $true
        Invoke-IniCheck -IniPath $i.Path -Label $i.Label
    }
    # An installation without a file of its own, on a host where no global one
    # applies either, runs on PHP's compiled defaults -- memory_limit 128M,
    # post_max_size 8M, expose_php on -- so none of the advisory's measures is
    # in place. That is a measurement, not an open question: reporting it as
    # undecided used to drag a fully patched host to exit 2, and a missing
    # measure is a warning in the shell edition too.
    #
    # It is reported per installation, not once for the host. Measured on
    # Windows Server 2022, where C:\php\8.3.36 served every request without an
    # ini of its own while C:\php\8.3.35 had one: a single host-level line
    # fires only when nothing is found anywhere, so the report carried the
    # settings of the installation that was not even serving and said nothing
    # about the one that was.
    if (-not $globalIni) {
        foreach ($dir in $judgedDirs) {
            if ($dirsWithIni[$dir.ToLowerInvariant()]) { continue }
            Add-Finding -Status warn -Check mitigation -Target (Show-PathForReport (Get-RealCasePath $dir)) `
                -Detail "no php.ini next to these binaries, and none in the registry, in PHPRC or in the Windows directory, so this installation runs on PHP's compiled defaults and none of the temporary measures is set" `
                -Hint 'Copy php.ini-production next to php.exe and set the measures from the advisory, or confirm with "php --ini" which file is really in use'
        }
    }

    # The FastCGI pool can force settings through arguments, which is the
    # Windows counterpart of php_admin_value: under FastCGI there is no
    # php_admin_value at all.
    if ($script:Iis.Readable) {
        foreach ($a in $script:Iis.Applications) {
            if (-not $a.Arguments) { continue }
            if ($a.Arguments -match '-d\s*([A-Za-z0-9_.]+)\s*=\s*([^\s"]+)') {
                Add-Finding -Status warn -Check forced-ini -Target $a.FullPath `
                    -Detail ("the FastCGI pool forces settings through its arguments: '{0}', so the php.ini lines in this report do not describe that pool" -f $a.Arguments) `
                    -Hint 'Check the forced values against the advisory measures, then recycle the FastCGI application'
            }
        }
        foreach ($a in $script:Iis.Applications) {
            foreach ($e in @($a.EnvironmentVariables)) {
                if ($e -and $e.name -eq 'PHPRC') {
                    Add-Finding -Status info -Check forced-ini -Target $a.FullPath `
                        -Detail ("this pool sets PHPRC to '{0}', so it reads a php.ini that may not be the one above" -f $e.value)
                }
            }
        }
    }

    # .user.ini is read by the CGI/FastCGI SAPI, and the advisory says
    # explicitly not to rely on it, so a measure found there does not count.
    $userInis = New-Object System.Collections.ArrayList
    foreach ($root in @('C:\inetpub\wwwroot')) {
        $probe = Resolve-UnderRoot (Join-Path $root '.user.ini')
        if (Test-Path -LiteralPath $probe -PathType Leaf) { $null = $userInis.Add($probe) }
    }
    foreach ($u in $userInis) {
        try { $lines = Get-Content -LiteralPath $u -ErrorAction Stop } catch { continue }
        if ((Get-IniValue $lines 'session.upload_progress.enabled') -or (Get-IniValue $lines 'memory_limit')) {
            Add-Finding -Status warn -Check forced-ini -Target (Show-PathForReport $u) `
                -Detail 'this .user.ini sets one of the advisory measures, and the advisory says not to rely on .user.ini for them' `
                -Hint 'Move the setting into php.ini or the FastCGI pool arguments, then recycle every worker'
        }
    }
}

# ---------------------------------------------------------------------------
# Remote checks. Same contract as the bash version, including the rule that a
# header announcing a patched version is undecided and never ok.
# ---------------------------------------------------------------------------

function Invoke-RemoteCheck {
    param([string] $Target)

    $u = $Target
    if ($u -notmatch '^[a-zA-Z]+://') { $u = "https://$u" }
    try { $parsed = [uri] $u } catch {
        Add-Finding -Status unknown -Check remote -Target $Target -Detail 'not a usable URL'
        return
    }
    if ($parsed.Scheme -notin @('http', 'https')) {
        Add-Finding -Status unknown -Check remote -Target $Target -Detail 'only http and https are checked'
        return
    }

    Write-Section ('Website {0}' -f $parsed.AbsoluteUri)
    $script:UrlsSeen++

    $resp = $null
    $err = ''
    try {
        $resp = Invoke-WebRequest -Uri $parsed.AbsoluteUri -Method Get -UseBasicParsing `
                    -MaximumRedirection 0 -TimeoutSec 20 -ErrorAction Stop
    } catch {
        $r = $_.Exception.Response
        if ($r) { $resp = $r } else { $err = $_.Exception.Message.Split([Environment]::NewLine)[0] }
    }
    if (-not $resp) {
        $script:UrlsOpen++
        Add-Finding -Status unknown -Check remote -Target $parsed.AbsoluteUri `
            -Detail ('the site did not answer: {0}' -f $err) `
            -Hint 'Run this script on the server that hosts the site'
        return
    }

    $headers = @{}
    try {
        foreach ($k in $resp.Headers.Keys) { $headers[$k.ToLowerInvariant()] = [string] $resp.Headers[$k] }
    } catch { }
    $status = 0
    try { $status = [int] $resp.StatusCode } catch { }
    Add-Finding -Status info -Check remote -Target $parsed.AbsoluteUri `
        -Detail ('reachable, last HTTP status {0}' -f $status)

    $powered = ''
    if ($headers.ContainsKey('x-powered-by')) { $powered = $headers['x-powered-by'] }
    $server = ''
    if ($headers.ContainsKey('server')) { $server = $headers['server'] }

    $phpv = ''
    foreach ($h in @($powered, $server)) {
        if ($h -match '(?i)php/(\d+\.\d+\.\d+)') { $phpv = $Matches[1]; break }
    }

    if ($phpv) {
        if ($script:P2sFrozenVersions -contains $phpv) {
            $script:UrlsOpen++
            Add-Finding -Status unknown -Check php-banner -Target $parsed.AbsoluteUri `
                -Detail ("announces PHP {0}, a version number that distributions keep while backporting the fix, so it cannot be judged from outside" -f $phpv) `
                -Hint 'Run this script on the server itself: there the package version gives a definite answer'
        } else {
            $verdict = Get-UpstreamVerdict $phpv
            if ($verdict.Status -eq 'ok') {
                # Deliberately not ok: X-Powered-By is self-declared and can
                # be set by the application, a cache or a proxy with a
                # different PHP behind it.
                $script:UrlsOpen++
                Add-Finding -Status unknown -Check php-banner -Target $parsed.AbsoluteUri `
                    -Detail ("announces PHP {0}, which is patched - but a header is self-declared and can be set by the application, a cache or a proxy, so this does not confirm what runs behind it" -f $phpv) `
                    -Hint 'Run this script on the server itself: there the file version gives a definite answer'
            } else {
                if ($verdict.Status -eq 'unknown') { $script:UrlsOpen++ }
                Add-Finding -Status $verdict.Status -Check php-banner -Target $parsed.AbsoluteUri `
                    -Detail ('X-Powered-By: {0}' -f $verdict.Detail) -Hint $verdict.Hint
            }
        }
        Add-Finding -Status warn -Check disclosure -Target $parsed.AbsoluteUri `
            -Detail ('the PHP version is visible to everyone (PHP/{0})' -f $phpv) `
            -Hint 'Set expose_php=0 so scanners cannot pick vulnerable targets by header'
        return
    }

    # No version in the headers is not a clean bill of health.
    $script:UrlsOpen++
    $signals = New-Object System.Collections.ArrayList
    if ($headers.ContainsKey('set-cookie') -and $headers['set-cookie'] -match '(?i)phpsessid') { $null = $signals.Add('PHPSESSID cookie') }
    if ($headers.ContainsKey('link') -and $headers['link'] -match '(?i)wp-json') { $null = $signals.Add('WordPress') }
    if ($headers.ContainsKey('x-redirect-by') -and $headers['x-redirect-by'] -match '(?i)wordpress') { $null = $signals.Add('WordPress') }
    if ($server -match '(?i)microsoft-iis') { $null = $signals.Add("Server: $server") }

    if ($signals.Count) {
        Add-Finding -Status unknown -Check php-level -Target $parsed.AbsoluteUri `
            -Detail ('runs PHP (signal: {0}) but does not reveal the version, so the patch level cannot be judged from outside' -f ($signals -join ', ')) `
            -Hint 'Run this script on the server itself: there the file version gives a definite answer'
    } else {
        Add-Finding -Status unknown -Check php-level -Target $parsed.AbsoluteUri `
            -Detail 'no PHP version and no PHP signal in the response, so this check cannot say anything about the patch level' `
            -Hint 'Run this script on the server itself: there the file version gives a definite answer'
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

function Write-UsageError {
    param([string] $Message)
    # Deliberately not the Write-Error cmdlet: it wraps at the console width
    # and wraps the message in a "powershell.EXE : ... + CategoryInfo" block.
    # Measured on a GitHub runner, where that wrap cut the sentence in half. A
    # command line tool says one line on stderr, like the shell edition.
    [Console]::Error.WriteLine('php2shell-check: ' + $Message)
}

function Show-Help {
    @"
php2shell-check $script:P2sScriptVersion - read-only exposure check for
$script:P2sCve1 and $script:P2sCve2 ($script:P2sAdvisory). Windows edition.

Usage:
  .\php2shell-check.ps1                      check this host
  .\php2shell-check.ps1 https://example.com  check this host and one website
  .\php2shell-check.ps1 -RemoteOnly https://example.com
  .\php2shell-check.ps1 -NoRemote
  .\php2shell-check.ps1 -Json

  -Quiet      summary only
  -Json       one JSON object on stdout, for monitoring and fleet runs
  -NoColor    plain output
  -Version    print the version and exit
  -Help       this text

The spellings of the shell edition work as well, so one fleet script can call
both: --remote-only, -r, --no-remote, --json, --quiet, -q, --no-color,
--version, --help. --no-containers and --no-logs are accepted and do nothing
here; --origin does not exist on Windows and ends in exit 3 rather than being
dropped.

Exit codes: 0 nothing vulnerable found, 1 vulnerable, 2 could not decide,
3 usage error. 0 is reserved for a run that judged a PHP runtime and found
all of them patched.

This script changes nothing and sends no exploit traffic. It never executes a
PHP binary: versions are read from the files' version resources.

Tool:       $script:P2sRepoUrl
Background: $script:P2sInfoUrl (German)
            provided as is, without warranty or support (MIT, see LICENSE)
"@
}

# Test hook: tests/run_tests.ps1 dot-sources this file to call single
# functions. Same contract and the same variable name as the shell edition,
# where tests/run_tests.sh does "P2S_SOURCE_ONLY=1 . php2shell-check.sh".
if ($env:P2S_SOURCE_ONLY -eq '1') { return }

# A fleet script that calls the shell edition on Linux and this one on Windows
# should not have to rewrite its options. PowerShell puts every token it does
# not recognise into $Url, so a GNU-style spelling would otherwise be checked
# as if it were a website. Translated here, before anything is evaluated.
$targets = New-Object System.Collections.ArrayList
foreach ($a in @($Url)) {
    if ([string]::IsNullOrWhiteSpace($a)) { continue }
    switch -Regex ($a) {
        '^(--remote-only|-r)$' { $RemoteOnly = $true; continue }
        '^--no-remote$'        { $NoRemote = $true; continue }
        '^--json$'             { $Json = $true; continue }
        '^(--quiet|-q)$'       { $Quiet = $true; continue }
        '^--no-color$'         { $NoColor = $true; continue }
        '^--version$'          { $Version = $true; continue }
        '^(--help|-h|/\?)$'    { $Help = $true; continue }
        # Windows has no containers and no log scan, so these two are accepted
        # and do nothing. A fleet script may pass them to every host.
        '^(--no-containers|--no-logs)$' { continue }
        # --origin needs a value, and silently dropping it would turn the
        # address into a target. The check does not exist here, so say so.
        '^--origin$' {
            Write-UsageError 'the --origin check is not part of the Windows edition'
            exit 3
        }
        '^-' {
            Write-UsageError ('unknown option: {0}' -f $a)
            exit 3
        }
        default { $null = $targets.Add($a) }
    }
}
$Url = [string[]] $targets.ToArray()
if ($NoColor) { $script:NoColour = $true }

if ($Help) { Show-Help; exit 0 }
if ($Version) { "php2shell-check $script:P2sScriptVersion (vulnerability data as of $script:P2sDataDate)"; exit 0 }
if ($RemoteOnly -and -not $Url) {
    Write-UsageError 'need at least one URL with -RemoteOnly'
    exit 3
}

if (-not ($Json -or $Quiet)) {
    Write-Tinted ('php2shell-check {0}' -f $script:P2sScriptVersion) -Colour 'White' -NoNewline
    Write-Host ('  {0} / {1}, data as of {2}' -f $script:P2sCve1, $script:P2sCve2, $script:P2sDataDate)
    $os = ''
    try { $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { $os = 'Windows' }
    Write-Tinted ('{0} ({1})' -f $script:HostName, $os) -Colour 'DarkGray'
}

$judged = New-Object System.Collections.ArrayList

if (-not $RemoteOnly) {
    $script:LocalRan = $true
    $script:Iis = Get-IisPhpConfiguration
    Invoke-PrivilegeCheck
    Invoke-BinaryCheck -Judged $judged
    Invoke-SapiCheck
    Invoke-ProcessCheck -Judged $judged
    Invoke-StaleEvidenceCheck
    Invoke-ConfigurationCheck -Judged $judged
}

if (-not $NoRemote) {
    foreach ($u in @($Url)) {
        if ($u) { Invoke-RemoteCheck -Target $u }
    }
}

# ---------------------------------------------------------------------------
# Summary. Counting statuses alone cannot say whether anything was examined,
# because a host with no PHP still collects ok lines elsewhere. Only the
# checks that judge a PHP runtime count, and only when they reached a verdict.
# ---------------------------------------------------------------------------

$nVuln = @($script:Findings | Where-Object { $_.Status -eq 'vuln' }).Count
$nUnknown = @($script:Findings | Where-Object { $_.Status -eq 'unknown' }).Count
$nWarn = @($script:Findings | Where-Object { $_.Status -eq 'warn' }).Count
$nOk = @($script:Findings | Where-Object { $_.Status -eq 'ok' }).Count
$nJudged = @($script:Findings | Where-Object {
    $_.Check -in @('php-binary', 'process', 'php-banner') -and $_.Status -in @('vuln', 'unknown', 'ok')
}).Count

if ($nVuln -gt 0) { $result = 'vulnerable'; $rc = 1 }
elseif ($nUnknown -gt 0 -or $nJudged -eq 0) { $result = 'undecided'; $rc = 2 }
else { $result = 'not-vulnerable'; $rc = 0 }

if ($Json) {
    $payload = [ordered]@{
        tool = 'php2shell-check'
        edition = 'windows'
        version = $script:P2sScriptVersion
        data_as_of = $script:P2sDataDate
        advisory = $script:P2sAdvisory
        host = $script:HostName
        result = $result
        scope = [ordered]@{
            host_checked = $script:LocalRan
            elevated = (Test-Elevated)
            urls_checked = $script:UrlsSeen
            urls_undecided = $script:UrlsOpen
        }
        counts = [ordered]@{ vulnerable = $nVuln; undecided = $nUnknown; warning = $nWarn; ok = $nOk }
        findings = @($script:Findings | ForEach-Object {
            [ordered]@{ status = $_.Status; check = $_.Check; target = $_.Target; detail = $_.Detail }
        })
    }
    $payload | ConvertTo-Json -Depth 6 -Compress
    exit $rc
}

Write-Host ''
Write-Tinted 'Summary' -Colour 'White' -NoNewline
Write-Host ('  {0} vulnerable, {1} undecided, {2} warnings, {3} ok' -f $nVuln, $nUnknown, $nWarn, $nOk)
switch ($result) {
    'vulnerable' {
        Write-Tinted '  VULNERABLE' -Colour 'Red' -NoNewline
        Write-Host '  at least one PHP runtime needs an update now.'
    }
    'undecided' {
        Write-Tinted '  UNDECIDED' -Colour 'Yellow' -NoNewline
        if ($nJudged -eq 0) {
            Write-Host '   this run judged no PHP runtime at all, so it says nothing'
            Write-Host '              about this host. See the lines above for what stopped it.'
        } else {
            Write-Host '   some results could not be judged, see the ?? lines.'
        }
    }
    'not-vulnerable' {
        Write-Tinted '  NO VULNERABLE PHP FOUND' -Colour 'Green' -NoNewline
        Write-Host '  in what this script can see.'
    }
}

if (-not $Quiet) {
    Write-Host ''
    Write-Tinted 'How reliable this is' -Colour 'White'
    if ($script:LocalRan) {
        Write-Host '  Ran on this host: the versions above are read out of the files'
        Write-Host '  themselves, which is the definite answer for what is installed.'
        Write-Host '  What no check can prove on Windows is which code a running worker'
        Write-Host '  already executes, so recycle the FastCGI application or the'
        Write-Host '  application pool after every PHP update.'
        if (-not (Test-Elevated)) {
            Write-Tinted '  Not elevated, so the IIS configuration and the processes of other users stayed hidden.' -Colour 'Yellow'
        }
    }
    if ($script:UrlsSeen -gt 0) {
        Write-Host ('  {0} of {1} websites could not be judged from outside: a check from' -f $script:UrlsOpen, $script:UrlsSeen)
        Write-Host '  outside never confirms a patch level.'
    }

    $hints = @($script:Hints1) + @($script:Hints2) + @($script:Hints3)
    if ($hints.Count) {
        Write-Host ''
        Write-Tinted 'Next steps' -Colour 'White'
        foreach ($h in $hints) { Write-Host ('  - {0}' -f $h) }
    }

    Write-Host ''
    Write-Tinted ('Advisory:   {0}' -f $script:P2sAdvisoryUrl) -Colour 'DarkGray'
    Write-Tinted ('Tool:       {0}' -f $script:P2sRepoUrl) -Colour 'DarkGray'
    Write-Tinted ('Background: {0} (German)' -f $script:P2sInfoUrl) -Colour 'DarkGray'
    Write-Tinted '            provided as is, without warranty or support (MIT, see LICENSE)' -Colour 'DarkGray'
}

exit $rc
