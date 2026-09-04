# ============================================================
# Script: admxupdate.ps1
# Purpose:
#   Import the current ADMX/ADML administrative templates into the domain's
#   Group Policy Central Store, so every admin machine editing GPOs sees the
#   same policy definitions without any per-machine installation.
#
#   - Windows 11 client templates (Microsoft Download Center .msi)
#   - Microsoft 365 Apps / Office templates (Download Center .exe)
#   - Microsoft Edge templates (edgeupdates API .cab)
#   - Google Chrome templates (dl.google.com .zip)
#
# Assumption: this runs on a domain controller, interactively, by an account with
# write access to SYSVOL. Unlike dcconfig.ps1 it is meant to be re-run - whenever a
# new Windows feature update ships, or a browser/Office template refresh is wanted -
# and on any DC in the domain, since the Central Store is a single replicated path
# rather than per-DC state. It touches no GPO, no OU and no AD object: it only ever
# adds or overwrites files under the Central Store, and never deletes any.
#
# Runs two ways, and standalone is the primary one: on its own it prompts, logs and
# reports for itself, so it can simply be copied to any DC and run. dcconfig.ps1 also
# calls it as its last step with -Embedded, which suppresses only that ceremony (see
# the -Embedded parameter) and never changes what gets imported.
#
# Coding: ClaudeCode
# Mastermind: sp
#
# Version History:
#   1.0: Initial version. Seeds the Central Store from the local PolicyDefinitions folder when it does not yet exist, then overlays the Windows 11, Office, Edge and Chrome templates, each downloaded at run time. Supports -SourceDir for DCs with no outbound internet access, and -WhatIf, which resolves and prints every download URL without fetching anything. Adds -Embedded, used by dcconfig.ps1 to call this script as its final step without a second prompt, a second transcript or a competing completion banner, taking back the failure count to fold into its own.
# ============================================================


##################################################
###        Group Policy Central Store          ###
##################################################

# Fail up front with a clear message rather than deep into the run with an obscure
# access-denied error. ActiveDirectory is needed only to resolve the domain's DNS
# name, from which the Central Store's UNC path is derived.
#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param (
    # Language of the .adml files to import. Only this one is copied - the source
    # packages carry dozens, and every one of them replicates to every DC forever.
    [string]$Language = "en-US",

    # Folder holding pre-staged installers, for a DC with no outbound internet
    # access. Nothing is downloaded when this is set; each block looks for its own
    # file by name in here instead. Populate it by running this script once on a
    # connected machine with -KeepDownloads and copying the resulting folder over.
    [string]$SourceDir,

    # Keep the downloaded installers instead of deleting them at the end.
    [switch]$KeepDownloads,

    # Re-copy the local (Windows Server) PolicyDefinitions set over the Central
    # Store even though it already exists. Off by default: the server's templates
    # are a subset of the Windows 11 client ones, so an unnecessary re-seed on a
    # run that also has -SkipWindows would quietly downgrade the store.
    [switch]$SeedFromLocal,

    [switch]$SkipWindows,
    [switch]$SkipOffice,
    [switch]$SkipEdge,
    [switch]$SkipChrome,

    # Set by dcconfig.ps1 when it calls this script as its last step. The caller has
    # already asked its one confirmation, is already writing a transcript, and prints
    # its own banners - so in this mode we prompt for nothing, start no second
    # transcript (a nested Start-Transcript fails, and worse, an unguarded
    # Stop-Transcript here would close the CALLER's log), print no banner of our own,
    # and return the failure count for the caller to fold into its completion banner.
    # Everything else behaves identically, which is what keeps this script honest as
    # a standalone tool: -Embedded removes ceremony, never work.
    [switch]$Embedded
)

Import-Module ActiveDirectory

# ============================================================
# Script Version
# ============================================================
# The header's Version History block is the only place a version number is
# maintained (see CLAUDE.md) - read the most recent entry from it rather than
# keeping a second copy here that could drift out of sync.
function Get-ClkScriptVersion {
    param ([string]$Path)

    if (-not $Path -or -not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        return $null
    }

    try {
        # @() matters: with a single Version History entry the pipeline returns a bare
        # string, and [-1] on a string is its last character - so this would report
        # "v0" for a 1.0 header rather than "v1.0". The optional third group is what
        # lets a patch release (1.0.1) be read; without it the pattern stopped at the
        # minor and demanded a colon, so a X.Y.Z entry matched nothing and the banner
        # silently reported the previous X.Y version instead.
        $versions = @(Select-String -LiteralPath $Path -Pattern '^#\s+(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9]+)?):' -ErrorAction Stop |
            ForEach-Object { $_.Matches[0].Groups[1].Value })
        if ($versions) { return "v$($versions[-1])" }
    }
    catch { }

    return $null
}

# $PSCommandPath is empty when the script is dot-sourced or run from a pasted
# selection - fall back gracefully rather than failing the whole run over a banner.
$ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$ScriptVersion = Get-ClkScriptVersion -Path $ScriptPath
if (-not $ScriptVersion) { $ScriptVersion = "(version unknown)" }

# ============================================================
# Configuration
# ============================================================
# The one value here that needs hand-maintaining. Edge and Chrome publish a
# machine-readable "latest" (an API and a permanent URL respectively), and the
# Office page id is stable because Microsoft refreshes that download in place every
# month. The Windows client templates do neither: each feature update - and each
# revision of one - gets a brand new Download Center page whose id is not derivable
# from anything. Bump this when a new Windows 11 release ships, roughly yearly.
#
#   23H2      = 105667
#   24H2      = 106254      24H2 V2.0 = 108293
#   25H2      = 108394      25H2 V2.0 = 108428  <- current
$WindowsAdmxPageId = 108428

# Stable page id, refreshed in place monthly by Microsoft. Serves both the x86 and
# x64 self-extractors; they carry identical templates, so either would do.
$OfficeAdmxPageId = 49030

# Enterprise release feed. The "Policy" product's newest release has exactly one
# artifact, a .cab, which in turn contains a single .zip.
$EdgeApiUrl = "https://edgeupdates.microsoft.com/api/products?view=enterprise"

# Permanent URL, re-published continuously. ~120 MB, because it carries every
# platform and every locale - of which about 2 MB is actually imported.
$ChromeZipUrl = "https://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip"

# ============================================================
# Transcript Logging
# ============================================================
# $PSScriptRoot is empty when the script is dot-sourced or run from an editor
# selection, which would make Join-Path throw - fall back to the current location.
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# $script:TranscriptStarted gates every Stop-Transcript below. Without it, an
# embedded run would close the caller's transcript on its way out and leave the rest
# of that run unlogged.
$script:TranscriptStarted = $false
$LogFile = "(the caller's log)"

if (-not $Embedded) {
    $LogDir = Join-Path $ScriptRoot "Logs"
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir | Out-Null
    }
    $LogFile = Join-Path $LogDir ("admxupdate_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

    try {
        Start-Transcript -Path $LogFile -ErrorAction Stop | Out-Null
        $script:TranscriptStarted = $true
    }
    catch {
        Write-Host "Warning: could not start transcript ($($_.Exception.Message)). Continuing without a log file." -ForegroundColor Yellow
    }
}

# Any terminating error below would otherwise leave the transcript running in the
# session, so that the next run fails at Start-Transcript. Close it and re-throw.
trap {
    Write-Host ""
    Write-Host "Unhandled error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The run stopped early - the Central Store may hold a partial import." -ForegroundColor Red
    if ($script:TranscriptStarted) { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null }
    break
}

Write-Host ""
if ($Embedded) {
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "Central Store import (admxupdate $ScriptVersion)" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
}
else {
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "Starting admxupdate $ScriptVersion" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
}
Write-Host ""

# ============================================================
# Helper Functions
# ============================================================
# Per-source failure tally, keyed by source name. The final banner reports the
# total, so a run that could not reach one vendor never announces success.
$script:AdmxFailures = @{}

function Add-ClkAdmxFailure {
    param ([string]$Label, [string]$Message)

    $script:AdmxFailures[$Label] = 1 + [int]$script:AdmxFailures[$Label]
    Write-Host "  FAILED: [$Label] $Message" -ForegroundColor Red
}

# Every exit path goes through here, so that closing the transcript and handing a
# result back to an embedded caller can never be forgotten on one of them. It cannot
# return on the caller's behalf - each call site still needs its own `return`.
function Exit-ClkAdmxUpdate {
    param ([int]$Failures = 0)

    if ($script:TranscriptStarted) { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null }
    if ($Embedded) {
        [PSCustomObject]@{ Failures = $Failures; Sources = $script:AdmxFailures }
    }
}

function Confirm-Action {
    param ([string]$Message)

    Write-Host ""
    Write-Host "$Message [Y/N]:" -NoNewline
    while ($true) {
        $key = [System.Console]::ReadKey($true).Key
        if ($key -eq "Y") { Write-Host " Y"; return $true }
        if ($key -eq "N") { Write-Host " N"; return $false }
    }
}

# Scrape a Download Center page for its direct download link. There is no public
# search or details API any more (the old /download/api/details/<id> endpoint now
# 404s), but the page itself needs no session and the download.microsoft.com links
# in it are direct, so a regex over the HTML is the whole mechanism.
function Get-ClkDownloadUrl {
    param ([int]$PageId, [string]$Pattern, [string]$Label)

    $page = "https://www.microsoft.com/en-us/download/details.aspx?id=$PageId"

    try {
        $html = (Invoke-WebRequest -Uri $page -UseBasicParsing -ErrorAction Stop).Content
    }
    catch {
        Add-ClkAdmxFailure $Label "could not read $page - $($_.Exception.Message)"
        return $null
    }

    $url = [regex]::Matches($html, 'https://download\.microsoft\.com/[^"]+') |
        ForEach-Object { $_.Value } |
        Where-Object { $_ -match $Pattern } |
        Select-Object -Unique -First 1

    if (-not $url) {
        Add-ClkAdmxFailure $Label "no download link matching '$Pattern' on $page - the page layout or its file names may have changed"
        return $null
    }

    return $url
}

function Invoke-ClkDownload {
    param ([string]$Url, [string]$Destination, [string]$Label)

    Write-Host "  Downloading $Url"

    # Some of these URLs contain spaces; [uri] percent-escapes the path for us.
    # Invoke-WebRequest's progress bar costs more time than the transfer itself on
    # a file the size of the Chrome package, hence suppressing it.
    $previousProgress = $ProgressPreference
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri ([uri]$Url).AbsoluteUri -OutFile $Destination -UseBasicParsing -ErrorAction Stop
        return $true
    }
    catch {
        Add-ClkAdmxFailure $Label "download failed - $($_.Exception.Message)"
        return $false
    }
    finally {
        $ProgressPreference = $previousProgress
    }
}

# With -SourceDir, take the pre-staged file instead of downloading. Returns the
# local path to work from, or $null if the source is unusable.
function Get-ClkPackage {
    param ([string]$Url, [string]$FileName, [string]$Label)

    if ($SourceDir) {
        $staged = Join-Path $SourceDir $FileName
        if (Test-Path -LiteralPath $staged) {
            Write-Host "  Using pre-staged $staged"
            return $staged
        }
        Add-ClkAdmxFailure $Label "no pre-staged $FileName in $SourceDir"
        return $null
    }

    $target = Join-Path $WorkDir $FileName
    if (Invoke-ClkDownload -Url $Url -Destination $target -Label $Label) { return $target }
    return $null
}

# Extract only the entries we actually import. The Chrome package holds some 15,000
# files across every platform and locale; expanding all of them to disk to copy four
# of them out would dominate the runtime.
function Expand-ClkZipEntry {
    param ([string]$ZipPath, [string]$Destination, [string]$Include)

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $zip = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $zip.Entries) {
            # A directory entry has an empty Name; skip those rather than trying to
            # extract them as files.
            if (-not $entry.Name) { continue }
            if ($entry.FullName -notmatch $Include) { continue }

            $target = Join-Path $Destination ($entry.FullName -replace '/', '\')
            $parent = Split-Path $target -Parent
            if (-not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
    }
    finally {
        $zip.Dispose()
    }
}

# The four packages each lay their templates out differently (and the Office one
# even lowercases its locale folder), so rather than hardcoding four paths, find the
# folder holding the most .admx files and treat that as the PolicyDefinitions root.
function Find-ClkAdmxRoot {
    param ([string]$Path)

    Get-ChildItem -LiteralPath $Path -Recurse -Filter *.admx -File -ErrorAction SilentlyContinue |
        Group-Object DirectoryName |
        Sort-Object Count -Descending |
        Select-Object -First 1 -ExpandProperty Name
}

# The only step that writes to SYSVOL. Copies the .admx files and the one language's
# .adml files, overwriting in place and never deleting, then reports this source's
# result - green only if nothing failed.
function Copy-ClkAdmx {
    param ([string]$SourceRoot, [string]$Label)

    if (-not $SourceRoot -or -not (Test-Path -LiteralPath $SourceRoot)) {
        Add-ClkAdmxFailure $Label "no PolicyDefinitions folder found in the extracted package"
        return
    }

    $admxFiles = @(Get-ChildItem -LiteralPath $SourceRoot -Filter *.admx -File -ErrorAction SilentlyContinue)
    if (-not $admxFiles) {
        Add-ClkAdmxFailure $Label "no .admx files in $SourceRoot"
        return
    }

    # Locale folder names are matched case-insensitively by the filesystem, so the
    # Office package's "en-us" resolves here and still lands in the store under the
    # canonical "en-US" spelling of $Language.
    $admlSource = Join-Path $SourceRoot $Language
    $admlFiles = @(Get-ChildItem -LiteralPath $admlSource -Filter *.adml -File -ErrorAction SilentlyContinue)
    if (-not $admlFiles) {
        Add-ClkAdmxFailure $Label "no $Language .adml files under $SourceRoot - the package may not carry that language"
    }

    $admlTarget = Join-Path $CentralStore $Language
    foreach ($dir in @($CentralStore, $admlTarget)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    $copied = 0
    foreach ($file in ($admxFiles + $admlFiles)) {
        $target = if ($file.Extension -eq ".admx") { $CentralStore } else { $admlTarget }
        try {
            Copy-Item -LiteralPath $file.FullName -Destination $target -Force -ErrorAction Stop
            $copied++
        }
        catch {
            Add-ClkAdmxFailure $Label "$($file.Name) - $($_.Exception.Message)"
        }
    }

    if ($script:AdmxFailures[$Label]) {
        Write-Host "  $Label : $copied file(s) imported, $($script:AdmxFailures[$Label]) failure(s)" -ForegroundColor Red
    }
    else {
        Write-Host "  $Label : $copied file(s) imported ($($admxFiles.Count) .admx, $($admlFiles.Count) .adml)" -ForegroundColor Green
    }
}

# ============================================================
# Central Store Path
# ============================================================
# A single replicated path rather than per-DC state, which is why this script can be
# run from any DC in the domain and why it is written to be re-run.
$DomainDns = (Get-ADDomain).DNSRoot
$CentralStore = "\\$DomainDns\SYSVOL\$DomainDns\Policies\PolicyDefinitions"
$CentralStoreExists = Test-Path -LiteralPath $CentralStore

$LocalPolicyDefinitions = Join-Path $env:SystemRoot "PolicyDefinitions"
$SeedNeeded = (-not $CentralStoreExists) -or $SeedFromLocal

# Kept deliberately short. The Windows package's administrative install lays its
# payload out under "Microsoft Group Policy\Windows 11 Oct 2025 Update (25H2)\
# PolicyDefinitions\<locale>\", which is about 90 characters before the file name -
# so a work folder more than ~140 characters deep pushes the longest .adml past
# MAX_PATH and msiexec fails the whole extraction with a bare 1603.
$WorkDir = Join-Path $env:TEMP ("admx_{0}" -f (Get-Date -Format "HHmmss"))

# ============================================================
# Confirmation
# ============================================================
Write-Host "Central Store: $CentralStore" -ForegroundColor Cyan
Write-Host "Language:      $Language" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will import the following into the Central Store:" -ForegroundColor Cyan

if ($SeedNeeded) {
    Write-Host "  - Base Windows templates from $LocalPolicyDefinitions" -NoNewline
    if (-not $CentralStoreExists) { Write-Host " (creating the Central Store)" } else { Write-Host " (-SeedFromLocal)" }
}
if (-not $SkipWindows) { Write-Host "  - Windows 11 client templates (Download Center page $WindowsAdmxPageId)" }
if (-not $SkipOffice)  { Write-Host "  - Microsoft 365 Apps / Office templates (Download Center page $OfficeAdmxPageId)" }
if (-not $SkipEdge)    { Write-Host "  - Microsoft Edge templates (edgeupdates enterprise feed)" }
if (-not $SkipChrome)  { Write-Host "  - Google Chrome templates (~120 MB download, ~2 MB imported)" }

Write-Host ""

# Once a Central Store exists, GPMC and gpedit stop reading the local
# PolicyDefinitions folder on every machine entirely, so a store that holds only
# some vendor's templates leaves every Windows policy showing as unknown. That is
# what the seed step above prevents, and it is the one thing worth understanding
# before answering Y.
if (-not $CentralStoreExists) {
    Write-Host "No Central Store exists yet. Creating one makes every GPO editor in the domain ignore its own" -ForegroundColor Yellow
    Write-Host "local PolicyDefinitions folder, so the full Windows set is copied up first - without it, every" -ForegroundColor Yellow
    Write-Host "Windows policy would show as unknown in GPMC." -ForegroundColor Yellow
    Write-Host ""
}

if ($SeedNeeded -and -not (Test-Path -LiteralPath $LocalPolicyDefinitions)) {
    Write-Host "$LocalPolicyDefinitions does not exist - cannot seed the Central Store. Exiting." -ForegroundColor Red
    Exit-ClkAdmxUpdate -Failures 1
    return
}

if ($WhatIfPreference) {
    Write-Host "Running with -WhatIf: nothing is downloaded and nothing is written. Each source's current" -ForegroundColor Yellow
    Write-Host "download URL is resolved and printed, so this doubles as a check that all four are still reachable." -ForegroundColor Yellow
    Write-Host ""
}

# The caller has already taken its own single confirmation, which announced this
# step - asking again here would be a second prompt in a script that has exactly one.
if (-not $Embedded -and -not (Confirm-Action "Proceed?")) {
    Write-Host "Aborted by user." -ForegroundColor Red
    Exit-ClkAdmxUpdate
    return
}

# ============================================================
# -WhatIf: resolve and report, change nothing
# ============================================================
# Downloading 150 MB and extracting it only to skip every copy would be a strange
# reading of -WhatIf, so the run stops here instead. Resolving the URLs is free and
# read-only, and is the part most likely to have rotted since the last run.
if ($WhatIfPreference) {
    Write-Host ""
    Write-Host "--- Would import into $CentralStore ---" -ForegroundColor Cyan

    if ($SeedNeeded) {
        Write-Host "Base Windows: $LocalPolicyDefinitions"
    }
    if (-not $SkipWindows) {
        Write-Host "Windows 11:   $(Get-ClkDownloadUrl -PageId $WindowsAdmxPageId -Pattern '\.msi$' -Label 'Windows 11')"
    }
    if (-not $SkipOffice) {
        Write-Host "Office:       $(Get-ClkDownloadUrl -PageId $OfficeAdmxPageId -Pattern 'admintemplates_x64.*\.exe$' -Label 'Office')"
    }
    if (-not $SkipEdge) {
        try {
            $feed = Invoke-RestMethod -Uri $EdgeApiUrl -UseBasicParsing -ErrorAction Stop
            $release = ($feed | Where-Object { $_.Product -eq "Policy" }).Releases |
                Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
            Write-Host "Edge:         $(($release.Artifacts | Where-Object { $_.ArtifactName -eq 'cab' }).Location) ($($release.ProductVersion))"
        }
        catch {
            Add-ClkAdmxFailure "Edge" "could not read $EdgeApiUrl - $($_.Exception.Message)"
        }
    }
    if (-not $SkipChrome) {
        Write-Host "Chrome:       $ChromeZipUrl"
    }

    Write-Host ""
    Write-Host "-WhatIf complete - nothing was downloaded or written." -ForegroundColor Yellow
    Exit-ClkAdmxUpdate -Failures ($script:AdmxFailures.Values | Measure-Object -Sum).Sum
    return
}

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

# ============================================================
# Base Windows Templates (Central Store seed)
# ============================================================
# Ordered first deliberately: the server's own templates are the baseline, and the
# Windows 11 client set below is a superset that must land on top of them, not under.
if ($SeedNeeded) {
    Write-Host ""
    Write-Host "--- Base Windows templates ---" -ForegroundColor Cyan
    Copy-ClkAdmx -SourceRoot $LocalPolicyDefinitions -Label "Base Windows"
}

# ============================================================
# Windows 11 Client Templates
# ============================================================
# msiexec /a is an administrative install: it lays the payload out under TARGETDIR
# without installing or registering anything, which is all we want from the package.
if (-not $SkipWindows) {
    Write-Host ""
    Write-Host "--- Windows 11 client templates ---" -ForegroundColor Cyan

    $url = if ($SourceDir) { $null } else { Get-ClkDownloadUrl -PageId $WindowsAdmxPageId -Pattern '\.msi$' -Label "Windows 11" }
    if ($url -or $SourceDir) {
        $msi = Get-ClkPackage -Url $url -FileName "windows-admx.msi" -Label "Windows 11"
        if ($msi) {
            $extract = Join-Path $WorkDir "win"
            $process = Start-Process msiexec.exe -ArgumentList @("/a", "`"$msi`"", "/qn", "TARGETDIR=`"$extract`"") -Wait -PassThru
            if ($process.ExitCode -ne 0) {
                $hint = if ($process.ExitCode -eq 1603) { " - 1603 here almost always means a path longer than MAX_PATH; check that `$env:TEMP is not deeply nested" } else { "" }
                Add-ClkAdmxFailure "Windows 11" "msiexec /a exited with $($process.ExitCode)$hint"
            }
            else {
                Copy-ClkAdmx -SourceRoot (Find-ClkAdmxRoot -Path $extract) -Label "Windows 11"
            }
        }
    }
}

# ============================================================
# Microsoft 365 Apps / Office Templates
# ============================================================
# A self-extracting IExpress package: /extract: unpacks it without running the
# bundled setup. Its layout is admx\*.admx plus admx\<locale>\*.adml.
if (-not $SkipOffice) {
    Write-Host ""
    Write-Host "--- Office templates ---" -ForegroundColor Cyan

    $url = if ($SourceDir) { $null } else { Get-ClkDownloadUrl -PageId $OfficeAdmxPageId -Pattern 'admintemplates_x64.*\.exe$' -Label "Office" }
    if ($url -or $SourceDir) {
        $exe = Get-ClkPackage -Url $url -FileName "office-admx.exe" -Label "Office"
        if ($exe) {
            $extract = Join-Path $WorkDir "office"
            New-Item -ItemType Directory -Path $extract -Force | Out-Null
            $process = Start-Process $exe -ArgumentList @("/extract:`"$extract`"", "/quiet") -Wait -PassThru
            if ($process.ExitCode -ne 0) {
                Add-ClkAdmxFailure "Office" "extractor exited with $($process.ExitCode)"
            }
            else {
                Copy-ClkAdmx -SourceRoot (Find-ClkAdmxRoot -Path $extract) -Label "Office"
            }
        }
    }
}

# ============================================================
# Microsoft Edge Templates
# ============================================================
# The enterprise feed's "Policy" product is versioned in step with Edge itself. Its
# single .cab contains exactly one file - a .zip - which is where the templates
# actually live, so this unwraps two layers.
if (-not $SkipEdge) {
    Write-Host ""
    Write-Host "--- Edge templates ---" -ForegroundColor Cyan

    $url = $null
    if (-not $SourceDir) {
        try {
            $feed = Invoke-RestMethod -Uri $EdgeApiUrl -UseBasicParsing -ErrorAction Stop
            $release = ($feed | Where-Object { $_.Product -eq "Policy" }).Releases |
                Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
            $url = ($release.Artifacts | Where-Object { $_.ArtifactName -eq "cab" }).Location
            if ($url) { Write-Host "  Edge policy templates $($release.ProductVersion)" }
            else { Add-ClkAdmxFailure "Edge" "no cab artifact in the newest Policy release" }
        }
        catch {
            Add-ClkAdmxFailure "Edge" "could not read $EdgeApiUrl - $($_.Exception.Message)"
        }
    }

    if ($url -or $SourceDir) {
        $cab = Get-ClkPackage -Url $url -FileName "MicrosoftEdgePolicyTemplates.cab" -Label "Edge"
        if ($cab) {
            $extract = Join-Path $WorkDir "edge"
            New-Item -ItemType Directory -Path $extract -Force | Out-Null
            $zip = Join-Path $extract "MicrosoftEdgePolicyTemplates.zip"

            $expand = Start-Process expand.exe -ArgumentList @("`"$cab`"", "-F:MicrosoftEdgePolicyTemplates.zip", "`"$zip`"") -Wait -PassThru -NoNewWindow
            if ($expand.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $zip)) {
                Add-ClkAdmxFailure "Edge" "expand.exe could not extract the zip from the cab (exit $($expand.ExitCode))"
            }
            else {
                $pattern = "^windows/admx/(?:[^/]+\.admx|$([regex]::Escape($Language))/[^/]+\.adml)$"
                Expand-ClkZipEntry -ZipPath $zip -Destination $extract -Include $pattern
                Copy-ClkAdmx -SourceRoot (Join-Path $extract "windows\admx") -Label "Edge"
            }
        }
    }
}

# ============================================================
# Google Chrome Templates
# ============================================================
# Same windows/admx layout as Edge, one layer shallower. chrome.admx carries the
# browser policies and google.admx only the parent category both it and Google
# Update hang off, so both are needed for the tree to render.
if (-not $SkipChrome) {
    Write-Host ""
    Write-Host "--- Chrome templates ---" -ForegroundColor Cyan

    $zip = Get-ClkPackage -Url $ChromeZipUrl -FileName "policy_templates.zip" -Label "Chrome"
    if ($zip) {
        $extract = Join-Path $WorkDir "chrome"
        New-Item -ItemType Directory -Path $extract -Force | Out-Null

        $pattern = "^windows/admx/(?:[^/]+\.admx|$([regex]::Escape($Language))/[^/]+\.adml)$"
        Expand-ClkZipEntry -ZipPath $zip -Destination $extract -Include $pattern
        Copy-ClkAdmx -SourceRoot (Join-Path $extract "windows\admx") -Label "Chrome"
    }
}

# ============================================================
# Cleanup
# ============================================================
if (Test-Path -LiteralPath $WorkDir) {
    if ($KeepDownloads) {
        Write-Host ""
        Write-Host "Downloads kept in $WorkDir" -ForegroundColor Yellow
        Write-Host "Copy that folder to an offline DC and re-run there with -SourceDir to import the same versions." -ForegroundColor Yellow
    }
    else {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

##########################################
###          Script completed          ###
##########################################

$TotalFailures = ($script:AdmxFailures.Values | Measure-Object -Sum).Sum

Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
if ($TotalFailures) {
    Write-Host "Central Store import completed with errors" -ForegroundColor Red
    Write-Host "$TotalFailures failure(s) across $($script:AdmxFailures.Count) source(s):" -ForegroundColor Red
    foreach ($entry in $script:AdmxFailures.GetEnumerator()) {
        Write-Host "  - $($entry.Key): $($entry.Value) failure(s)" -ForegroundColor Red
    }
    Write-Host "Review the log at $LogFile and re-run once the cause is fixed." -ForegroundColor Red
    Write-Host "Anything that did import is already in the Central Store - a re-run only overwrites it." -ForegroundColor Red
}
else {
    Write-Host "Central Store import completed successfully" -ForegroundColor Cyan
    Write-Host "Open GPMC and edit any GPO to confirm the new templates load from $CentralStore" -ForegroundColor Cyan
}

# Standalone, this is the script's own final word; embedded, the caller prints the
# run's verdict and this line would contradict it on a run where the AD baseline
# succeeded and only the import failed.
if (-not $Embedded) {
    Write-Host ""
    if ($TotalFailures) {
        Write-Host "admxupdate $ScriptVersion completed with errors" -ForegroundColor Red
    }
    else {
        Write-Host "admxupdate $ScriptVersion completed successfully" -ForegroundColor Cyan
    }
}

Exit-ClkAdmxUpdate -Failures $TotalFailures



# Future feature plan:
#
# - $WindowsAdmxPageId is the only value here that rots. There is no public search
#   API on the Download Center any more, so nothing can discover the current page id
#   for a new Windows release automatically - it has to be looked up by hand once per
#   feature update. Running with -WhatIf prints every resolved URL, which is the
#   cheapest way to notice that a page id or a file-name pattern has gone stale.
#
# - Nothing here is ever deleted from the Central Store, so a template retired by a
#   vendor lingers. Harmless (an unreferenced .admx renders nothing) but it means the
#   store only grows. A -Prune mode would need a manifest of what this script put
#   there, since the store may also hold templates imported by hand.
#
# - The .adml side is single-language by design. Passing -Language ro-RO would import
#   only that one; importing several would mean running once per language, which
#   works today because the .admx copy is idempotent. A -Language accepting an array
#   would be the tidier form if that is ever actually wanted.
#
# - dcconfig.ps1's "Settings: EDGE Policies" GPO writes values that render as Extra
#   Registry Settings until msedge.admx is in the Central Store. After the first run
#   of this script, open that GPO once: anything still listed under Extra Registry
#   Settings is a value name or type that does not match its policy, and needs
#   correcting in dcconfig.ps1 rather than here.
