# ============================================================
# Script: dcconfig.ps1
# Purpose:
#   Domain controller baseline configuration (STRUCTURE ONLY)
#
#   - OU structure creation
#   - Admin group (Janitors)
#   - User placement
#   - Fine-Grained Password Policies
#   - GPO object creation and linking
#   - GPO Settings
#   - ADMX Central Store import (delegated to admxupdate.ps1, which also stands alone)
#
# Assumption: this runs once, interactively, on a freshly promoted DC that is the
# only DC in the domain at that point. AD/GPO cmdlets below are therefore not pinned
# to a specific -Server - there is nothing else for them to land on, so no cross-DC
# replication lag is possible at run time. If this script is ever run against a
# domain that already has multiple DCs, add -Server $DC pinning throughout first.
#
# Coding: (bad)Copilot until v2.1, ClaudeCode since v3.0
# Mastermind: sp
#
# Version History:
#   2.0-gold: Initial version. Creates the Active Directory baseline: OU structure, administrative groups, FGPPs, and GPO objects with linking only. No policy settings are applied.
#   2.1: Populates all baseline GPOs with security, firewall, Defender, SMB, RDP, Windows Update, and startup reliability settings, forming the complete domain hardening configuration.
#   3.0: Adds transcript logging, a tunables block for the FGPP values, -WhatIf support, a single up-front confirmation prompt, and consolidates GPO identity/target/link state into the $GPOs array as the single source of truth.
#   3.1: Correctness and robustness pass. The User Policy FGPP now sets explicit lockout values (it previously inherited a threshold of 0, disabling lockout for every domain user). -WhatIf no longer errors on objects it did not create. GPO settings writes go through Set-ClkGPOValue, which catches failures so a partial run is reported as such instead of announcing success. Janitors is resolved domain-wide, DC IP resolution is guarded against an empty result, the root OU name is validated, and the transcript is closed on unhandled errors. Adds a #Requires preamble (elevation, PS 5.1, both modules), caches Get-GPInheritance per OU, and batches registry values that share a key and a type into single writes. Restores the "Starting dcconfig" / "dcconfig completed successfully" banners, both (plus the -WhatIf and failure banners) printing the running script's version, read at runtime from this Version History block so it can never drift out of sync with the one place a version is maintained.
#   3.2: Redirects the default computer/user containers via redircmp/redirusr so objects created without an explicit OU (a domain-joined computer, a bare net user) land in the Workstations and Users OUs instead of the invisible-to-GPO CN=Computers/CN=Users containers. Adds a "Settings: GP Refresh" GPO, linked to the Servers and Computers OUs, setting the Group Policy refresh interval to 15 minutes.
#   3.3: Adds a "Deploy: ESMC" GPO, linked (disabled) to the Computers and Servers OUs, as an empty placeholder for future ESET ESMC deployment settings. New-ClkGPOLink now reconciles an existing link's enabled state instead of only checking that the link exists, so changing a $GPOs entry's Disabled flag takes effect on a re-run rather than being silently ignored on a domain the script has already configured. Populates and enables three GPOs that were previously created empty with their links disabled: "Firewall: Allow from DC" and "Firewall: Allow from Clickwork HQ" (192.168.10.5/32) now get inbound allow-any rules written into their Windows Defender Firewall with Advanced Security store via the new Set-ClkGPOFirewallRule helper - the legacy WindowsFirewall ADMX used by the other firewall GPOs cannot express an all-ports rule scoped to an address - and "Settings: NoSleep" gets the plugged-in sleep and hibernate timeouts set to never. "Settings: EDGE Policies" is populated and enabled too, as user-configuration values under HKCU\Software\Policies\Microsoft\Edge; these render as Extra Registry Settings until msedge.admx is imported into the Central Store, after which the same values start displaying as named policies with no rewrite. Adds NetSecurity to the #Requires module list.
#   3.4: Adds admxupdate.ps1, a second script that imports the current Windows 11, Office, Edge and Chrome ADMX/ADML templates into the domain's Group Policy Central Store, so the policies this script writes render as named policies in GPMC rather than as Extra Registry Settings. It stands alone - it is the one to re-run on other DCs, or when a new Windows release ships, since the Central Store is a single replicated path rather than per-DC state - and dcconfig.ps1 also calls it as its final step with -Embedded, which suppresses its prompt, transcript and banners and hands back a failure count for the completion banner to report separately from the GPO tally. Placed last because nothing above depends on it: registry.pol records no reference to any ADMX, so the Central Store only decides how already-correct settings display. New -SkipCentralStore switch leaves it out, and a missing admxupdate.ps1 is a warning rather than a failure, so dcconfig.ps1 still works when it is the only file copied to a DC.
#   3.4.1: Set-ClkDefaultContainer now checks redircmp/redirusr's exit code instead of discarding it and printing the green success line unconditionally, so a default container redirection that did not happen is reported rather than silent. Its failures, and any later non-GPO baseline failure, are tallied in $script:ADFailures and reported by the completion banner, which previously could announce a fully successful run while that step had failed. Get-ClkScriptVersion's pattern now accepts a three-part version, without which this very entry would have matched nothing and the banner would have kept reporting v3.4.
# ============================================================


##################################################
###   AD Structure, Groups, FGPPs, GPO Objects ###
##################################################

# Fail up front with a clear message rather than deep into the run with an obscure
# access-denied or "term not recognized" error. -Modules also imports both modules,
# so the Import-Module calls below are belt-and-braces for readability.
#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy, NetSecurity

[CmdletBinding(SupportsShouldProcess)]
param (
    # Skip the ADMX Central Store import at the end of the run. For a DC with no
    # outbound internet access, or when the templates are being managed separately -
    # admxupdate.ps1 can always be run on its own later.
    [switch]$SkipCentralStore
)

Import-Module ActiveDirectory
Import-Module GroupPolicy

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
        # "v0" for a 1.0 header rather than "v1.0". Latent here (this header has had
        # several entries since the helper was written), real in admxupdate.ps1.
        # The optional third group is what lets a patch release (3.4.1) be read; without
        # it the pattern stopped at "3.4" and demanded a colon, so a X.Y.Z entry matched
        # nothing and the banner silently reported the previous X.Y version instead.
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
# Transcript Logging
# ============================================================
# $PSScriptRoot is empty when the script is dot-sourced or run from an editor
# selection, which would make Join-Path throw - fall back to the current location.
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$LogDir = Join-Path $ScriptRoot "Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
$LogFile = Join-Path $LogDir ("dcconfig_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

try {
    Start-Transcript -Path $LogFile -ErrorAction Stop | Out-Null
}
catch {
    Write-Host "Warning: could not start transcript ($($_.Exception.Message)). Continuing without a log file." -ForegroundColor Yellow
}

# Any terminating error below would otherwise leave the transcript running in the
# session, so that the next run fails at Start-Transcript. Close it and re-throw.
trap {
    Write-Host ""
    Write-Host "Unhandled error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The run stopped early - the baseline is only partially applied." -ForegroundColor Red
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    break
}

Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Starting dcconfig $ScriptVersion" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Configuration
# ============================================================
# Fine-Grained Password Policy tunables - adjust here for org-specific requirements.
# MinPasswordLength values are sp's deliberate call, not an oversight - leave as-is
# unless he says otherwise.
$DomainAdminPasswordMinLength         = 8
$DomainAdminPasswordHistoryCount      = 16
$DomainAdminMaxPasswordAgeDays        = 365
$DomainAdminLockoutThreshold          = 10
$DomainAdminLockoutDurationMinutes    = 60
$DomainAdminLockoutObservationMinutes = 60

$UserPasswordMinLength    = 8
$UserPasswordHistoryCount = 16
$UserMaxPasswordAgeDays   = 120

# An FGPP replaces the Default Domain Policy password AND lockout settings wholesale
# for its subjects - it is not an overlay. Leaving these unset would create the policy
# with LockoutThreshold 0, i.e. no account lockout at all for every member of
# Domain Users. Always set them explicitly.
$UserLockoutThreshold          = 10
$UserLockoutDurationMinutes    = 30
$UserLockoutObservationMinutes = 30

# ============================================================
# Helper Functions
# ============================================================
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

function New-OU {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$Name,
        [string]$Path
    )

    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess("OU=$Name,$Path", "Create organizational unit")) {
            New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
            Write-Host "Created OU: $Name" -ForegroundColor Green
        }
    }
    else {
        Write-Host "OU already exists: $Name" -ForegroundColor Gray
    }
}

# Failures in the AD baseline steps that are not GPO registry writes. Tallied
# separately from $script:GPOFailures because the completion banner describes that
# one as "GPO setting(s)", which a container redirection is not.
$script:ADFailures = 0

# redircmp.exe/redirusr.exe are OS-shipped binaries (not PowerShell cmdlets) that set
# the domain's default computer/user container - there is no AD cmdlet for this, so
# idempotency is checked via Get-ADDomain's ComputersContainer/UsersContainer instead
# of a Get-* existence check like the other New-Clk* helpers use.
function Set-ClkDefaultContainer {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$ContainerType,
        [string]$CurrentContainer,
        [string]$TargetOU,
        [string]$Command
    )

    if ($CurrentContainer -eq $TargetOU) {
        Write-Host "Default $ContainerType container already set to: $TargetOU" -ForegroundColor Gray
        return
    }

    if (-not $PSCmdlet.ShouldProcess($TargetOU, "Set default $ContainerType container ($Command)")) {
        return
    }

    # A native exe has no -ErrorAction to lean on: its only failure signal is the exit
    # code, and this previously discarded both that and the tool's output, then printed
    # the green success line unconditionally. A redirection that did not happen was
    # invisible in the log and left the run announcing success - the one baseline step
    # with no second signal anywhere to contradict it.
    #
    # 2>&1 folds the tool's own error text into $Output rather than letting PowerShell
    # surface it as a NativeCommandError record, and the try/catch is for the exe being
    # missing entirely: that throws CommandNotFoundException, which the script-level
    # trap would turn into an aborted run over a step the rest of the baseline does not
    # depend on.
    try {
        $Output = & $Command $TargetOU 2>&1
    }
    catch {
        $script:ADFailures++
        Write-Host "FAILED: could not run $Command - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Default $ContainerType container NOT set - it is still $CurrentContainer" -ForegroundColor Red
        return
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Set default ${ContainerType} container: $TargetOU" -ForegroundColor Green
        return
    }

    $script:ADFailures++
    Write-Host "FAILED: $Command exited with $LASTEXITCODE" -ForegroundColor Red
    Write-Host "  Default $ContainerType container NOT set to $TargetOU - it is still $CurrentContainer" -ForegroundColor Red
    if ($Output) { Write-Host "  $(($Output | Out-String).Trim())" -ForegroundColor Red }
}

function New-ClkGPO {
    [CmdletBinding(SupportsShouldProcess)]
    param ([string]$Name)

    if (-not (Get-GPO -Name $Name -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($Name, "Create GPO")) {
            New-GPO -Name $Name | Out-Null
            Write-Host "Created GPO: $Name" -ForegroundColor Green
        }
    }
    else {
        Write-Host "GPO already exists: $Name" -ForegroundColor Gray
    }
}

# Get-GPInheritance is a round-trip per call, and the link loop asks about the same
# handful of OUs once per GPO. Cache each OU's links on first use as a
# name -> enabled map; there are ~23 links across 6 distinct OUs, so this turns 23
# queries into 6. The enabled state is cached alongside the name because
# New-ClkGPOLink reconciles it, not just the link's existence.
$script:GPLinkCache = @{}

function Get-ClkGPOLinkState {
    param ([string]$TargetOU)

    if (-not $script:GPLinkCache.ContainsKey($TargetOU)) {
        $state = @{}
        foreach ($link in (Get-GPInheritance -Target $TargetOU).GpoLinks) {
            $state[$link.DisplayName] = $link.Enabled
        }
        $script:GPLinkCache[$TargetOU] = $state
    }

    return $script:GPLinkCache[$TargetOU]
}

function New-ClkGPOLink {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$GPOName,
        [string]$TargetOU,
        [bool]$Disabled = $false
    )

    # Returned by reference, so the writes below keep the cache current.
    $Links       = Get-ClkGPOLinkState $TargetOU
    $WantEnabled = -not $Disabled
    $LinkEnabled = if ($WantEnabled) { "Yes" } else { "No" }

    if (-not $Links.ContainsKey($GPOName)) {
        if ($PSCmdlet.ShouldProcess("$GPOName -> $TargetOU", "Link GPO (enabled: $LinkEnabled)")) {
            New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled $LinkEnabled | Out-Null
            $Links[$GPOName] = $WantEnabled

            if ($WantEnabled) {
                Write-Host "Linked: $GPOName -> $TargetOU" -ForegroundColor Green
            }
            else {
                Write-Host "Linked (disabled): $GPOName -> $TargetOU" -ForegroundColor Yellow
            }
        }
        return
    }

    # The link exists, so creation is a no-op - but its enabled state can still be
    # wrong. Flipping Disabled in $GPOs was otherwise silently ignored on any domain
    # the script had already been run against: the link was found, reported as
    # "already exists", and left in whatever state the earlier run gave it.
    if ($Links[$GPOName] -eq $WantEnabled) {
        Write-Host "Link already exists: $GPOName -> $TargetOU" -ForegroundColor Gray
        return
    }

    if ($PSCmdlet.ShouldProcess("$GPOName -> $TargetOU", "Set link enabled: $LinkEnabled")) {
        Set-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled $LinkEnabled | Out-Null
        $Links[$GPOName] = $WantEnabled

        if ($WantEnabled) {
            Write-Host "Link enabled: $GPOName -> $TargetOU" -ForegroundColor Green
        }
        else {
            Write-Host "Link disabled: $GPOName -> $TargetOU" -ForegroundColor Yellow
        }
    }
}

# Records how many registry writes failed, per GPO, so a partial run is reported
# as a failure instead of printing a green "Populated" line regardless of outcome.
$script:GPOFailures = @{}

# -ValueName and -Value accept arrays, and each call is one open/commit of the GPO's
# registry.pol. Values sharing a key AND a type can therefore be written in a single
# call. -Type is singular, so a DWord and a String under the same key still need two.
function Set-ClkGPOValue {
    param (
        [string]$Name,
        [string]$Key,
        [string[]]$ValueName,
        [Microsoft.Win32.RegistryValueKind]$Type,
        [object[]]$Value
    )

    try {
        Set-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop | Out-Null
    }
    catch {
        $script:GPOFailures[$Name] = $ValueName.Count + [int]$script:GPOFailures[$Name]
        Write-Host "  FAILED: [$Name] $Key\$($ValueName -join ', ') - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# A "permit every port from this address" rule has no expression in the legacy
# WindowsFirewall ADMX the blocks above use - that schema only scopes per-service and
# per-port exceptions - so these rules are written into the GPO's Windows Defender
# Firewall with Advanced Security store instead, where GPMC shows them as ordinary
# inbound rules rather than as registry settings. Not being a registry write, it
# cannot go through Set-ClkGPOValue, so it mirrors that helper's contract instead:
# failures are tallied per GPO in $script:GPOFailures and Confirm-GPOPopulated still
# reports the block accurately.
function Set-ClkGPOFirewallRule {
    param (
        [string]$Name,
        [string]$PolicyStore,
        [string]$RuleName,
        [string]$DisplayName,
        [string[]]$RemoteAddress
    )

    try {
        $Existing = Get-NetFirewallRule -PolicyStore $PolicyStore -Name $RuleName -ErrorAction SilentlyContinue

        # DC addresses can differ from the run that first created the rule. Correct
        # the scope rather than skipping it, so a re-run converges the same way an
        # overwriting Set-ClkGPOValue call does.
        if ($Existing) {
            Set-NetFirewallRule -PolicyStore $PolicyStore -Name $RuleName `
                -RemoteAddress $RemoteAddress -ErrorAction Stop
            Write-Host "  Rule scope updated: $DisplayName ($($RemoteAddress -join ', '))" -ForegroundColor Gray
        }
        else {
            New-NetFirewallRule -PolicyStore $PolicyStore -Name $RuleName `
                -DisplayName $DisplayName -Direction Inbound -Action Allow `
                -Profile Any -RemoteAddress $RemoteAddress -ErrorAction Stop | Out-Null
            Write-Host "  Rule created: $DisplayName ($($RemoteAddress -join ', '))" -ForegroundColor Gray
        }
    }
    catch {
        $script:GPOFailures[$Name] = 1 + [int]$script:GPOFailures[$Name]
        Write-Host "  FAILED: [$Name] $DisplayName - $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Confirm-GPOPopulated {
    param ([string]$Name)

    $failed = [int]$script:GPOFailures[$Name]
    if ($failed -eq 0) {
        Write-Host "Populated GPO: $Name" -ForegroundColor Green
    }
    else {
        Write-Host "INCOMPLETE GPO: $Name ($failed setting(s) failed)" -ForegroundColor Red
    }
}

# ============================================================
# Root OU Input
# ============================================================
$RootOUName = Read-Host "Enter the root OU name (e.g. CONTOSO, ACME)"

if ([string]::IsNullOrWhiteSpace($RootOUName)) {
    Write-Host "Root OU name cannot be empty. Exiting." -ForegroundColor Red
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    return
}

# The name is interpolated into both an LDAP filter and a distinguished name, so
# characters that are special to either (' , = + \ # < > ;) must be rejected up
# front rather than producing a broken filter or a malformed DN that every
# derived path below would silently inherit.
if ($RootOUName -notmatch '^[A-Za-z0-9][A-Za-z0-9 _-]{0,62}$') {
    Write-Host "Root OU name must start with a letter or digit and contain only letters, digits, spaces, hyphens and underscores (max 63 characters). Exiting." -ForegroundColor Red
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    return
}

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName

$BaseOU         = "OU=$RootOUName,$DomainDN"
$AdminsOU       = "OU=Admins,$BaseOU"
$UsersOU        = "OU=Users,$BaseOU"
$GroupsOU       = "OU=Groups,$BaseOU"
$ComputersOU    = "OU=Computers,$BaseOU"
$ServersOU      = "OU=Servers,$ComputersOU"
$WorkstationsOU = "OU=Workstations,$ComputersOU"

# ============================================================
# Confirmation
# ============================================================
Write-Host ""
Write-Host "This will configure the following baseline under '$BaseOU':" -ForegroundColor Cyan
Write-Host "  - OU structure (Admins, Users, Groups, Computers, Servers, Workstations, !SrvcAccts)"
Write-Host "  - Default computer/user containers redirected to Workstations/Users (redircmp/redirusr)"
Write-Host "  - 'Janitors' admin group, with the current user added as a member"
Write-Host "  - Current user moved to the Admins OU"
Write-Host "  - Fine-Grained Password Policies for admins and users"
Write-Host "  - Baseline GPOs, created, linked to their target OUs, and populated with security/firewall/Defender/SMB/RDP/Update settings"
if (-not $SkipCentralStore) {
    Write-Host "  - Current Windows 11 / Office / Edge / Chrome ADMX templates imported into the domain's Group Policy Central Store"
    Write-Host "    (via admxupdate.ps1, as the last step - downloads roughly 170 MB; pass -SkipCentralStore to leave it out)"
}
Write-Host ""

if ($WhatIfPreference) {
    Write-Host "Running with -WhatIf: no changes will actually be made. Each action will report what it would have done." -ForegroundColor Yellow
    Write-Host "GPO linking and GPO settings population are skipped entirely, since both operate on objects that -WhatIf did not create." -ForegroundColor Yellow
    Write-Host "The Central Store import is skipped with them - run admxupdate.ps1 -WhatIf directly to see what it would fetch." -ForegroundColor Yellow
    Write-Host ""
}

if (-not (Confirm-Action "Proceed?")) {
    Write-Host "Aborted by user." -ForegroundColor Red
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    return
}

# ============================================================
# OU Structure
# ============================================================
New-OU $RootOUName $DomainDN
New-OU "Admins" $BaseOU
New-OU "Users" $BaseOU
New-OU "Groups" $BaseOU
New-OU "Computers" $BaseOU
New-OU "!SrvcAccts" $BaseOU

New-OU "Security" $GroupsOU
New-OU "Distribution" $GroupsOU
New-OU "Contacts" $GroupsOU

New-OU "Servers" $ComputersOU
New-OU "Workstations" $ComputersOU

Write-Host ""

# ============================================================
# Default Computer/User Containers (redircmp / redirusr)
# ============================================================
# Without this, a computer joining the domain (or a user created without an explicit
# -Path) lands in the CN=Computers/CN=Users containers rather than the OU structure
# above, invisible to every GPO linked above since GPOs don't link to containers.
Set-ClkDefaultContainer -ContainerType "Computer" -CurrentContainer $Domain.ComputersContainer -TargetOU $WorkstationsOU -Command "redircmp.exe"
Set-ClkDefaultContainer -ContainerType "User"     -CurrentContainer $Domain.UsersContainer     -TargetOU $UsersOU        -Command "redirusr.exe"

Write-Host ""

# ============================================================
# Janitors Group
# ============================================================
$JanitorsOU = "OU=Security,$GroupsOU"
$JanitorsGroup = "Janitors"

# sAMAccountName is unique domain-wide, so an OU-scoped existence check would miss a
# Janitors group living elsewhere and then fail on the duplicate name. Search the whole
# domain, and carry the resolved object forward so every later call targets that exact
# group rather than re-resolving an ambiguous name.
$Janitors = Get-ADGroup -Filter "Name -eq '$JanitorsGroup'" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $Janitors) {
    New-ADGroup -Name $JanitorsGroup -GroupScope Global -GroupCategory Security -Path $JanitorsOU
    $Janitors = Get-ADGroup -Filter "Name -eq '$JanitorsGroup'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    Write-Host "Created group: Janitors" -ForegroundColor Green
}
elseif ($Janitors.DistinguishedName -notlike "*,$JanitorsOU") {
    Write-Host "Group 'Janitors' already exists outside the expected OU: $($Janitors.DistinguishedName)" -ForegroundColor Yellow
    Write-Host "Using the existing group. Move it to $JanitorsOU manually if that is not intended." -ForegroundColor Yellow
}
else {
    Write-Host "Group already exists: Janitors" -ForegroundColor Gray
}

try {
    $CurrentUser = Get-ADUser ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -ErrorAction Stop
}
catch {
    Write-Host "Could not resolve the current user as a domain account. This script must be run while logged on as a domain user. Exiting." -ForegroundColor Red
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    return
}

# Under -WhatIf the group was never created, so there is nothing to enumerate.
if (-not $Janitors) {
    Write-Host "What if: Adding current user to Janitors" -ForegroundColor Gray
}
elseif (-not (Get-ADGroupMember -Identity $Janitors | Where-Object { $_.SID.Value -eq $CurrentUser.SID.Value })) {
    Add-ADGroupMember -Identity $Janitors -Members $CurrentUser
    Write-Host "Added current user to Janitors" -ForegroundColor Green
}
else {
    Write-Host "Current user already a member of Janitors" -ForegroundColor Gray
}

# ============================================================
# Move User to Admins OU
# ============================================================
# Match the Admins OU under this root specifically - "*OU=Admins,*" would also match
# an Admins OU under some other root and skip the move.
if ($CurrentUser.DistinguishedName -notlike "*,$AdminsOU") {
    Move-ADObject -Identity $CurrentUser.DistinguishedName -TargetPath $AdminsOU
    Write-Host "Moved user to Admins OU" -ForegroundColor Green
}
else {
    Write-Host "User already in Admins OU" -ForegroundColor Gray
}

# ============================================================
# FGPPs
# ============================================================
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'Domain Admin Policy'")) {
    New-ADFineGrainedPasswordPolicy `
        -Name "Domain Admin Policy" `
        -Precedence 1 `
        -MinPasswordLength $DomainAdminPasswordMinLength `
        -PasswordHistoryCount $DomainAdminPasswordHistoryCount `
        -ComplexityEnabled $true `
        -MaxPasswordAge (New-TimeSpan -Days $DomainAdminMaxPasswordAgeDays) `
        -LockoutThreshold $DomainAdminLockoutThreshold `
        -LockoutDuration (New-TimeSpan -Minutes $DomainAdminLockoutDurationMinutes) `
        -LockoutObservationWindow (New-TimeSpan -Minutes $DomainAdminLockoutObservationMinutes)
    Write-Host "Created FGPP: Domain Admin Policy" -ForegroundColor Green
}
else {
    Write-Host "FGPP already exists: Domain Admin Policy" -ForegroundColor Gray
}

# Guarded on the policy existing: under -WhatIf it was never created, and querying
# subjects of a missing policy is a terminating error.
if (-not $Janitors -or -not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'Domain Admin Policy'")) {
    Write-Host "What if: Adding Janitors as subject of Domain Admin Policy" -ForegroundColor Gray
}
elseif (-not (Get-ADFineGrainedPasswordPolicySubject -Identity "Domain Admin Policy" | Where-Object { $_.SID.Value -eq $Janitors.SID.Value })) {
    Add-ADFineGrainedPasswordPolicySubject -Identity "Domain Admin Policy" -Subjects $Janitors
    Write-Host "Added Janitors as subject of Domain Admin Policy" -ForegroundColor Green
}
else {
    Write-Host "Janitors already a subject of Domain Admin Policy" -ForegroundColor Gray
}

if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'User Policy'")) {
    New-ADFineGrainedPasswordPolicy `
        -Name "User Policy" `
        -Precedence 10 `
        -MinPasswordLength $UserPasswordMinLength `
        -PasswordHistoryCount $UserPasswordHistoryCount `
        -ComplexityEnabled $true `
        -MaxPasswordAge (New-TimeSpan -Days $UserMaxPasswordAgeDays) `
        -LockoutThreshold $UserLockoutThreshold `
        -LockoutDuration (New-TimeSpan -Minutes $UserLockoutDurationMinutes) `
        -LockoutObservationWindow (New-TimeSpan -Minutes $UserLockoutObservationMinutes)
    Write-Host "Created FGPP: User Policy" -ForegroundColor Green
}
else {
    Write-Host "FGPP already exists: User Policy" -ForegroundColor Gray
}

if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'User Policy'")) {
    Write-Host "What if: Adding Domain Users as subject of User Policy" -ForegroundColor Gray
}
elseif (-not (Get-ADFineGrainedPasswordPolicySubject -Identity "User Policy" | Where-Object { $_.Name -eq "Domain Users" })) {
    Add-ADFineGrainedPasswordPolicySubject -Identity "User Policy" -Subjects "Domain Users"
    Write-Host "Added Domain Users as subject of User Policy" -ForegroundColor Green
}
else {
    Write-Host "Domain Users already a subject of User Policy" -ForegroundColor Gray
}

# ============================================================
# GPO Creation
# ============================================================
# Each GPO carries its name, target OU(s), and link state together,
# so adding a GPO here is the only step needed - there is no separate
# lookup table to fall out of sync with.
$GPOs = @(
    [PSCustomObject]@{ Name = "Security: Enable Firewall";           TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Firewall: Default Server Rules";      TargetOU = @($ServersOU);          Disabled = $false }
    [PSCustomObject]@{ Name = "Firewall: Default Workstation Rules"; TargetOU = @($WorkstationsOU);     Disabled = $false }
    [PSCustomObject]@{ Name = "Firewall: Allow from DC";             TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Firewall: Allow from Clickwork HQ";   TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Firewall: Allow ESMC";                TargetOU = @($ComputersOU);        Disabled = $true  }
    [PSCustomObject]@{ Name = "Security: Enable Defender";           TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Security: Ctrl+Alt+Del";              TargetOU = @($ComputersOU);        Disabled = $true  }
    [PSCustomObject]@{ Name = "Security: Disable AutoPlay";          TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Security: SMB Hardening";             TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Settings: Wait for network";          TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Settings: GP Refresh";                TargetOU = @($ServersOU, $ComputersOU); Disabled = $false }
    # Intentionally at the Computers OU: RDP is enabled on workstations as well as
    # servers, and who may actually reach it is controlled by the firewall GPOs below.
    [PSCustomObject]@{ Name = "Settings: Enable RDP";                TargetOU = @($ComputersOU);        Disabled = $false }
    [PSCustomObject]@{ Name = "Settings: NoSleep";                   TargetOU = @($WorkstationsOU);     Disabled = $false }
    [PSCustomObject]@{ Name = "Settings: Workstation Updates";       TargetOU = @($WorkstationsOU);     Disabled = $false }
    [PSCustomObject]@{ Name = "Printers: Remove garbage";            TargetOU = @($WorkstationsOU);     Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Lock Screen";          TargetOU = @($WorkstationsOU);     Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Wallpaper";            TargetOU = @($WorkstationsOU);     Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Regional";             TargetOU = @($UsersOU);            Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Explorer";             TargetOU = @($UsersOU);            Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: NoCloud content";      TargetOU = @($UsersOU);            Disabled = $true  }
    [PSCustomObject]@{ Name = "Settings: EDGE Policies";             TargetOU = @($UsersOU, $AdminsOU); Disabled = $false }
    [PSCustomObject]@{ Name = "Deploy: ESMC";                        TargetOU = @($ComputersOU, $ServersOU); Disabled = $true  }
)

foreach ($gpo in $GPOs) {
    New-ClkGPO $gpo.Name
}

# ============================================================
# -WhatIf stops here
# ============================================================
# Everything below reads or writes the GPOs and OUs created above:
# Get-GPInheritance needs the target OU to exist, and Set-GPRegistryValue needs the
# GPO to exist. Under -WhatIf neither does, so continuing would only produce a wall
# of errors while still printing success lines.
if ($WhatIfPreference) {
    Write-Host ""
    Write-Host "-WhatIf: skipping GPO linking and settings population (both require the objects above to exist)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "dcconfig $ScriptVersion -WhatIf ended" -ForegroundColor Cyan
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    return
}

# ============================================================
# GPO Linking (NO SETTINGS)
# ============================================================
Write-Host ""
Write-Host "Linking GPOs to OUs ..."
foreach ($gpo in $GPOs) {
    foreach ($ou in $gpo.TargetOU) {
        New-ClkGPOLink $gpo.Name $ou $gpo.Disabled
    }
}




#########################################
###       GPO Settings Population     ###
#########################################

Write-Host ""
Write-Host "Populating GPO settings ..."

###
# GPO: Security: Enable Firewall
# Administrative Template: "Windows Defender Firewall: Protect all network connections"
# (Domain, Private, and Public Profiles)
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$FirewallEnableGPO = "Security: Enable Firewall"

# ------------------------------------------------------------
# Enable firewall engine for all profiles
# ------------------------------------------------------------
$Profiles = @("DomainProfile", "PrivateProfile", "PublicProfile")

foreach ($FWProfile in $Profiles) {
    Set-ClkGPOValue `
        -Name $FirewallEnableGPO `
        -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\$FWProfile" `
        -ValueName "EnableFirewall" `
        -Type DWord `
        -Value 1
}

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $FirewallEnableGPO


# ------------------------------------------------------------
# Resolve DC IPv4 addresses (static snapshot, matches .pol/ADMX behavior)
# Shared by the Server and Workstation firewall rule blocks below,
# which both scope their exceptions to these same DC IPs.
#
# This is the intended state for a fresh domain: remote administration, file sharing
# and RDP are reachable only from a DC. Admin workstation IPs are to be added to
# $DCIPString (or to the RemoteAddresses scopes directly) later, at which point those
# machines can manage and RDP into servers and workstations too.
# ------------------------------------------------------------
$DCIPs = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty IPv4Address |
    Where-Object { $_ }

# An empty scope here would be written into the remote administration, file sharing
# and Remote Desktop exceptions below. Combined with EnableFirewall above, that can
# leave every server and workstation in the tree unreachable for management, so stop
# rather than apply it.
if (-not $DCIPs) {
    throw "Could not resolve any domain controller IPv4 address. Refusing to write empty RemoteAddresses scopes into the firewall GPOs."
}

$DCIPString = ($DCIPs -join ",")

$DomainProfileKey = "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"

###
# GPO: Firewall: Default Server Rules
# Path: Administrative Templates > Network > Network Connections > Windows Defender Firewall > Domain Profile
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$ServerFirewallGPO = "Firewall: Default Server Rules"

# ------------------------------------------------------------
# Allow ICMP exceptions → Allow inbound echo request
# (.pol: DomainProfile\IcmpSettings)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\IcmpSettings" `
    -ValueName "AllowInboundEchoRequest" `
    -Type DWord `
    -Value 1

# ------------------------------------------------------------
# Allow inbound remote administration exception (DC IP only)
# (.pol: DomainProfile\RemoteAdminSettings)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1

Set-ClkGPOValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString

# ------------------------------------------------------------
# Allow inbound file and printer sharing (DC IP only)
# (.pol: DomainProfile\Services\FileAndPrint)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1

Set-ClkGPOValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString

# ------------------------------------------------------------
# Allow inbound Remote Desktop exceptions (DC IP only)
# (.pol: DomainProfile\Services\RemoteDesktop)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1

Set-ClkGPOValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $ServerFirewallGPO


###
# GPO: Firewall: Default Workstation Rules
# Path: Administrative Templates > Network > Network Connections > Windows Defender Firewall > Domain Profile
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$WorkstationFirewallGPO = "Firewall: Default Workstation Rules"

# ------------------------------------------------------------
# Allow ICMP exceptions → Allow inbound echo request
# (uses $DCIPString/$DomainProfileKey resolved above, shared with the Server Rules block)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\IcmpSettings" `
    -ValueName "AllowInboundEchoRequest" `
    -Type DWord `
    -Value 1

# ------------------------------------------------------------
# Allow inbound remote administration exception (DC IP only)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1

Set-ClkGPOValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString

# ------------------------------------------------------------
# Allow inbound file and printer sharing (DC IP only)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1

Set-ClkGPOValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString

# ------------------------------------------------------------
# Allow inbound Remote Desktop exceptions (DC IP only)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1

Set-ClkGPOValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $WorkstationFirewallGPO


###
# GPO: Firewall: Allow from DC
# Path: Windows Settings > Security Settings > Windows Defender Firewall with
#       Advanced Security > Inbound Rules
#
# Unlike the two blocks above, this is a WFAS rule rather than a legacy ADMX
# registry setting - "allow every port and protocol from this address" has no
# equivalent in that ADMX schema, which only exposes per-service and per-port
# exceptions. The two models coexist: a packet is permitted if either allows it.
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$AllowFromDCGPO = "Firewall: Allow from DC"

# ------------------------------------------------------------
# Allow all inbound traffic from the domain controllers
#
# Scoped to the same $DCIPs snapshot the server and workstation rules above use.
# This is the broad counterpart to those narrow per-service exceptions: it makes a
# DC reachable on any port, so anything managed from a DC keeps working without a
# new exception per service. It also means DC compromise grants unrestricted
# inbound reach into every machine in the tree - the accepted trade for a tree
# whose management all originates from the DC.
# ------------------------------------------------------------
Set-ClkGPOFirewallRule `
    -Name $AllowFromDCGPO `
    -PolicyStore "$($Domain.DNSRoot)\$AllowFromDCGPO" `
    -RuleName "CLK-AllowInboundFromDC" `
    -DisplayName "Allow all inbound from domain controllers" `
    -RemoteAddress $DCIPs

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $AllowFromDCGPO


###
# GPO: Firewall: Allow from Clickwork HQ
# Path: Windows Settings > Security Settings > Windows Defender Firewall with
#       Advanced Security > Inbound Rules
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$AllowFromHQGPO = "Firewall: Allow from Clickwork HQ"

# ------------------------------------------------------------
# Allow all inbound traffic from the Clickwork HQ management address
#
# A single host, not the surrounding /24: the intent is to reach machines from
# that one management box, so widening it to the subnet would grant every device
# on that network the same unrestricted access.
# ------------------------------------------------------------
$HQAddress = "192.168.10.5/32"

Set-ClkGPOFirewallRule `
    -Name $AllowFromHQGPO `
    -PolicyStore "$($Domain.DNSRoot)\$AllowFromHQGPO" `
    -RuleName "CLK-AllowInboundFromHQ" `
    -DisplayName "Allow all inbound from Clickwork HQ" `
    -RemoteAddress $HQAddress

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $AllowFromHQGPO


###
# GPO: Security: Enable Defender
# Path: Administrative Templates > Windows Components > Microsoft Defender Antivirus
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$DefenderGPO = "Security: Enable Defender"

$BaseKey = "HKLM\Software\Policies\Microsoft\Windows Defender"

# ------------------------------------------------------------
# Turn on Microsoft Defender Antivirus
# Policy: Turn off Microsoft Defender Antivirus = Disabled
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $DefenderGPO `
    -Key $BaseKey `
    -ValueName "DisableAntiSpyware" `
    -Type DWord `
    -Value 0

# ------------------------------------------------------------
# Enable real-time protection
# Policy: Turn on real-time protection = Enabled
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $DefenderGPO `
    -Key "$BaseKey\Real-Time Protection" `
    -ValueName "DisableRealtimeMonitoring" `
    -Type DWord `
    -Value 0

# ------------------------------------------------------------
# MAPS / cloud protection (same key, same type - written in one call)
# Policy: Turn on cloud-delivered protection = Enabled  (SpynetReporting = 2)
# Policy: Send file samples when further analysis is required (SubmitSamplesConsent = 1)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $DefenderGPO `
    -Key "$BaseKey\Spynet" `
    -ValueName "SpynetReporting", "SubmitSamplesConsent" `
    -Type DWord `
    -Value 2, 1

# ------------------------------------------------------------
# Enable Potentially Unwanted Application (PUA) protection
# Policy: Configure detection for potentially unwanted applications = Enabled (Block)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $DefenderGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows Defender" `
    -ValueName "PUAProtection" `
    -Type DWord `
    -Value 1

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $DefenderGPO


###
# GPO: Security: Disable AutoPlay
# Path: Administrative Templates > Windows Components > AutoPlay Policies

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$AutoPlayGPO = "Security: Disable AutoPlay"

# ------------------------------------------------------------
# Explorer AutoRun policies (same key, same type - written in one call)
# Policy: Set the default behavior for AutoRun = Enabled
#         Default AutoRun Behavior: Do not execute any autorun commands (NoAutorun = 1)
# Policy: Turn off AutoPlay = Enabled
#         Turn off AutoPlay on: All drives (NoDriveTypeAutoRun = 255)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $AutoPlayGPO `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoAutorun", "NoDriveTypeAutoRun" `
    -Type DWord `
    -Value 1, 255

# ------------------------------------------------------------
# Disallow AutoPlay for non-volume devices = Enabled
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $AutoPlayGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\Explorer" `
    -ValueName "NoAutoplayfornonVolume" `
    -Type DWord `
    -Value 1

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $AutoPlayGPO


###
# GPO: Security: SMB Hardening
# Policies:
# - Disable Computer Browser service
# - Disable SMBv1
# - Disable insecure guest logons
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$SmbHardeningGPO = "Security: SMB Hardening"

# ------------------------------------------------------------
# Disable Computer Browser service
# System Services → Computer Browser → Startup Mode: Disabled
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $SmbHardeningGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\Browser" `
    -ValueName "Start" `
    -Type DWord `
    -Value 4

# ------------------------------------------------------------
# Disable SMBv1 protocol (Lanman Server)
# Administrative Templates → Network → Lanman Server
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $SmbHardeningGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "SMB1" `
    -Type DWord `
    -Value 0

# ------------------------------------------------------------
# Disable insecure guest logons (Lanman Workstation)
# Administrative Templates → Network → Lanman Workstation
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $SmbHardeningGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
    -ValueName "AllowInsecureGuestAuth" `
    -Type DWord `
    -Value 0

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $SmbHardeningGPO


###
# GPO: Settings: Wait for network
# ADMX Policy: System\Logon\Always wait for the network at computer startup and logon = Enabled
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$WaitForNetworkGPO = "Settings: Wait for network"

# ------------------------------------------------------------
# Always wait for the network at computer startup and logon
# SyncForegroundPolicy IS the registry backing for that ADMX policy - there is no
# separate "AlwaysWaitForNetworkAtStartupAndLogon" value to set.
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $WaitForNetworkGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -ValueName "SyncForegroundPolicy" `
    -Type DWord `
    -Value 1

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $WaitForNetworkGPO


###
# GPO: Settings: GP Refresh
# ADMX Policy: System\Group Policy\Set Group Policy refresh interval for computers = Enabled
# Group Policy Refresh Interval: 15 minutes, Random offset: 2 minutes
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$GPRefreshGPO = "Settings: GP Refresh"

# ------------------------------------------------------------
# Group Policy refresh interval (same key, same type - written in one call)
# GroupPolicyRefreshTime = 15 (minutes)
# GroupPolicyRefreshTimeOffset = 2 (random offset, minutes)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $GPRefreshGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\Group Policy" `
    -ValueName "GroupPolicyRefreshTime", "GroupPolicyRefreshTimeOffset" `
    -Type DWord `
    -Value 15, 2

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $GPRefreshGPO


###
# GPO: Settings: Enable RDP
# ADMX Policies:
# - Allow users to connect remotely by using Remote Desktop Services
# - Require user authentication for remote connections by using Network Level Authentication
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$EnableRdpGPO = "Settings: Enable RDP"

# ------------------------------------------------------------
# Terminal Services policies (same key, same type - written in one call)
# Policy: Allow users to connect remotely using Remote Desktop Services
#         (fDenyTSConnections = 0)
# Policy: Require Network Level Authentication (UserAuthentication = 1)
#
# This GPO is linked at the Computers OU, so RDP is enabled on workstations as well
# as servers. Reachability is deliberately controlled by the firewall GPOs rather
# than here: the RemoteDesktop exception is scoped to the DC IPs resolved at run
# time, so only a DC can currently connect. Admin workstation IPs are to be added
# to that scope later.
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $EnableRdpGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "fDenyTSConnections", "UserAuthentication" `
    -Type DWord `
    -Value 0, 1

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $EnableRdpGPO


###
# GPO: Settings: Workstation Updates
# ADMX Policy: Windows Update → Configure Automatic Updates
# Option: Auto download and schedule the install
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$WorkstationUpdatesGPO = "Settings: Workstation Updates"

# ------------------------------------------------------------
# Automatic Updates policies (same key, same type - written in one call)
# Policy: Enable Automatic Updates (NoAutoUpdate = 0)
# Policy: Configure Automatic Updates: Option 4 (AUOptions = 4)
#         Auto download and schedule the install
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $WorkstationUpdatesGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "NoAutoUpdate", "AUOptions" `
    -Type DWord `
    -Value 0, 4

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $WorkstationUpdatesGPO


###
# GPO: Settings: NoSleep
# ADMX Policy: System > Power Management > Sleep Settings
#   "Specify the system sleep timeout (plugged in)"     = Enabled, 0
#   "Specify the system hibernate timeout (plugged in)" = Enabled, 0
#
# Each power setting is keyed by its own GUID under PowerSettings, so these are two
# keys and therefore two calls. ACSettingIndex is the plugged-in value; the DC
# counterpart (on battery) is deliberately left alone, so a laptop still sleeps on
# battery. 0 means never.
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$NoSleepGPO = "Settings: NoSleep"

$PowerSettingsKey = "HKLM\Software\Policies\Microsoft\Power\PowerSettings"

# ------------------------------------------------------------
# Never sleep while plugged in (STANDBYIDLE)
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $NoSleepGPO `
    -Key "$PowerSettingsKey\29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA" `
    -ValueName "ACSettingIndex" `
    -Type DWord `
    -Value 0

# ------------------------------------------------------------
# Never hibernate while plugged in (HIBERNATEIDLE)
# Without this, the sleep timeout above only defers the machine to hibernation.
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $NoSleepGPO `
    -Key "$PowerSettingsKey\9D7815A6-7EE4-497E-8888-515A05F02364" `
    -ValueName "ACSettingIndex" `
    -Type DWord `
    -Value 0

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $NoSleepGPO


###
# GPO: Settings: EDGE Policies
# ADMX Policy: Administrative Templates > Microsoft Edge
#
# User configuration (HKCU), because this GPO is linked to the Users and Admins OUs
# rather than to a computer OU. Edge reads policy from both hives, HKLM winning.
#
# msedge.admx/.adml ships separately from Windows and is usually not installed when
# this script first runs, in which case GPMC shows these as Extra Registry Settings
# until it is. That is a display concern only: registry.pol records no reference to
# any ADMX, so once the definitions are in the Central Store the same bytes start
# rendering as named policies with no rewrite and no re-run. Two consequences worth
# knowing: creating a Central Store makes GPMC ignore C:\Windows\PolicyDefinitions
# entirely, so the full Windows ADMX set has to be copied there alongside msedge.admx
# or every other policy in the tree goes unknown; and because the names below were
# written without an ADMX on hand to check them against, a value whose name or type
# does not match its policy exactly will stay unknown forever rather than fail loudly.
# After importing the ADMX, open this GPO once - anything still listed under Extra
# Registry Settings is a mismatch to correct here.
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$EdgeGPO = "Settings: EDGE Policies"

$EdgeKey = "HKCU\Software\Policies\Microsoft\Edge"

# ------------------------------------------------------------
# Edge policies stored as DWords (same key, same type - one call)
# Policy: Force synchronization of browser data and do not show the sync consent
#         prompt = Enabled (ForceSync = 1)
# Policy: Hide the First-run experience and splash screen = Enabled
#         (HideFirstRunExperience = 1)
# Policy: Show Hubs Sidebar = Disabled (HubsSidebarEnabled = 0)
# Policy: Show Microsoft Rewards experiences = Disabled (ShowMicrosoftRewards = 0)
# Policy: Automatically import another browser's data and settings at first run
#         = Disables automatic import, and the import section of the first-run
#         experience is skipped (AutoImportAtFirstRun = 4)
# Policy: Allow Microsoft News content on the new tab page = Disabled
#         (NewTabPageContentEnabled = 0)
# Policy: Hide the default top sites from the new tab page = Enabled
#         (NewTabPageHideDefaultTopSites = 1)
# Policy: Enable the default search provider = Enabled
#         (DefaultSearchProviderEnabled = 1). Not in gpos.xlsx, but the whole
#         DefaultSearchProvider* family below is ignored without it.
# ------------------------------------------------------------
Set-ClkGPOValue `
    -Name $EdgeGPO `
    -Key $EdgeKey `
    -ValueName "ForceSync", "HideFirstRunExperience", "HubsSidebarEnabled", "ShowMicrosoftRewards", "AutoImportAtFirstRun", "NewTabPageContentEnabled", "NewTabPageHideDefaultTopSites", "DefaultSearchProviderEnabled" `
    -Type DWord `
    -Value 1, 1, 0, 0, 4, 0, 1, 1

# ------------------------------------------------------------
# Edge policies stored as strings (same key, same type - one call)
# Policy: Manage Search Engines = Enabled, carrying its search engine list as JSON
#         (ManagedSearchEngines)
# Policy: New tab page search box experience = Address bar
#         (NewTabPageSearchBox = "redirect"; "bing" would be the search box)
# Policy: Default search provider name / keyword / search URL / URL for suggestions
#
# ManagedSearchEngines takes precedence over the DefaultSearchProvider* values when
# both are set, so the effective default is the JSON list's Google RO entry. Both are
# written because gpos.xlsx specifies both.
# ------------------------------------------------------------
$ManagedSearchEngines = '[{"allow_search_engine_discovery":true},{"is_default":true,"search_url":"https://www.google.ro/search?q={searchTerms}","name":"Google RO","keyword":"google.ro"}]'
$SearchURL            = '{google:baseURL}search?q=%s&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:iOSSearchLanguage}{google:searchClient}{google:sourceId}{google:contextualSearchVersion}ie={inputEncoding}'
$SuggestURL           = '{google:baseURL}complete/search?output=chrome&q={searchTerms}'

Set-ClkGPOValue `
    -Name $EdgeGPO `
    -Key $EdgeKey `
    -ValueName "ManagedSearchEngines", "NewTabPageSearchBox", "DefaultSearchProviderName", "DefaultSearchProviderKeyword", "DefaultSearchProviderSearchURL", "DefaultSearchProviderSuggestURL" `
    -Type String `
    -Value $ManagedSearchEngines, "redirect", "Google", "google.ro", $SearchURL, $SuggestURL

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Confirm-GPOPopulated $EdgeGPO


# ============================================================
# Group Policy Central Store
# ============================================================
# Deliberately last. Nothing above depends on it - a registry.pol records no
# reference to any ADMX, so the settings written above are already correct and the
# Central Store only decides how they display in GPMC. Running it here means the
# whole AD baseline is already in place before the run spends several minutes on
# ~170 MB of downloads, and a DC with no outbound internet ends with a warning
# rather than a baseline that never got applied.
#
# admxupdate.ps1 is a standalone script in its own right (it is the one to re-run on
# other DCs, or when a new Windows release ships) - -Embedded only tells it that this
# script has already prompted, is already transcribing, and will report the outcome.
# It is called rather than dot-sourced on purpose: dot-sourcing would overwrite
# $ScriptVersion, $ScriptRoot and $LogFile in this scope with its own.
#
# -Language is left at its en-US default here. To import a different one, run
# admxupdate.ps1 directly - the .admx copy is idempotent, so it can be run once per
# language without undoing the previous pass.
$AdmxFailures = 0

if ($SkipCentralStore) {
    Write-Host ""
    Write-Host "Skipping the Central Store import (-SkipCentralStore)." -ForegroundColor Yellow
}
else {
    $AdmxScript = Join-Path $ScriptRoot "admxupdate.ps1"

    if (-not (Test-Path -LiteralPath $AdmxScript)) {
        # This script has to keep working when it is the only file copied to a DC,
        # so a missing admxupdate.ps1 is a warning, not a failure.
        Write-Host ""
        Write-Host "admxupdate.ps1 not found next to this script - skipping the Central Store import." -ForegroundColor Yellow
        Write-Host "Copy it alongside dcconfig.ps1 and run it separately to import the ADMX templates." -ForegroundColor Yellow
    }
    else {
        # Caught here rather than left to the trap at the top of this script. An
        # unhandled error inside admxupdate.ps1 rethrows out of its own trap, which
        # would take this script down with it - ending the run with no completion
        # banner at all, even though every AD and GPO step above already succeeded.
        # The whole point of tallying the import separately is that it cannot make a
        # good baseline look broken, and that has to hold when it crashes too.
        try {
            # Select the result object rather than trusting the call to emit exactly
            # one thing, so a stray line of pipeline output inside admxupdate.ps1
            # could never be mistaken for its verdict.
            $AdmxResult = & $AdmxScript -Embedded |
                Where-Object { $_.PSObject.Properties.Name -contains "Failures" } |
                Select-Object -Last 1

            $AdmxFailures = [int]$AdmxResult.Failures
        }
        catch {
            Write-Host ""
            Write-Host "The Central Store import stopped on an unhandled error: $($_.Exception.Message)" -ForegroundColor Red
            $AdmxFailures = 1
        }
    }
}


##########################################
###          Script completed          ###
##########################################

$TotalFailures = ($script:GPOFailures.Values | Measure-Object -Sum).Sum

Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
if ($TotalFailures -or $AdmxFailures -or $script:ADFailures) {
    Write-Host "dcconfig $ScriptVersion completed with errors" -ForegroundColor Red

    # Reported before the GPO tally because these are the steps the rest of the
    # baseline is built on - a container redirection that did not take is a different
    # class of problem from a registry value that did not write.
    if ($script:ADFailures) {
        Write-Host "$($script:ADFailures) AD baseline step(s) failed - see the FAILED lines above." -ForegroundColor Red
    }

    if ($TotalFailures) {
        Write-Host "$TotalFailures GPO setting(s) failed to apply across $($script:GPOFailures.Count) GPO(s):" -ForegroundColor Red
        foreach ($entry in $script:GPOFailures.GetEnumerator()) {
            Write-Host "  - $($entry.Key): $($entry.Value) failure(s)" -ForegroundColor Red
        }
    }

    # Tallied separately from the GPO failures on purpose: the two fail for unrelated
    # reasons, and an ADMX import that could not reach the internet says nothing about
    # whether the domain itself was configured correctly.
    if ($AdmxFailures) {
        Write-Host "$AdmxFailures Central Store failure(s) - the AD baseline above is unaffected." -ForegroundColor Red
        Write-Host "Re-run admxupdate.ps1 on its own once the cause is fixed; it overwrites what did import." -ForegroundColor Red
    }

    Write-Host "Review the log at $LogFile and re-run once the cause is fixed." -ForegroundColor Red
}
else {
    Write-Host "dcconfig $ScriptVersion completed successfully" -ForegroundColor Cyan
}

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null



# Future feature plan:
#
# Nine GPOs are still created empty with their links disabled, to be filled in by
# hand per deployment. Each is blocked on something specific, not merely unwritten -
# the constraint is that every setting must render in GPMC/gpedit as a named policy,
# never as "Extra Registry Settings", and that nothing may be hand-edited in SYSVOL.
# A registry.pol value renders as a named policy if and only if a loaded ADMX defines
# that exact key and value name, so that test decides where each of these can go.
#
# - Settings: EDGE Policies is populated but still owes a verification pass. The
#   Central Store step above now imports msedge.admx/.adml, so the pass is just:
#   after a run, open that GPO once. Anything left under Extra Registry Settings is
#   a name or type that does not match its policy and needs correcting in the block
#   above.
#
# - Security: Ctrl+Alt+Del and Customization: Regional / Explorer. No ADMX exists for
#   any of these values. DisableCAD is a Security Option (GptTmpl.inf); the Explorer
#   and Control Panel\International values are preferences, whose only GUI-native home
#   is Preferences > Registry (Registry.xml). Both are SYSVOL files and the
#   GroupPolicy module has no API for either - Set-GPRegistryValue writes registry.pol
#   and nothing else. The one route that satisfies both constraints is to configure
#   each once by hand on a reference DC, Backup-GPO it into this repo, and Import-GPO
#   it here: the cmdlets do the SYSVOL writing, and the result is GUI-native. Note
#   Import-GPO replaces a GPO's entire contents, so a backup must be complete rather
#   than incremental.
#
# - Customization: NoCloud content is a mix: "Turn off Microsoft consumer experiences"
#   is ADMX-backed, while the ContentDeliveryManager values are preferences. Check
#   each value against the ADMX before deciding which half goes where.
#
# - Printers: Remove garbage, Customization: Lock Screen / Wallpaper, Deploy: ESMC and
#   Firewall: Allow ESMC are unspecified beyond their names in gpos.xlsx.
#
# - Security: SMB Hardening writes SMB1 and the Browser service's Start value under
#   HKLM\SYSTEM\CurrentControlSet\Services, which no ADMX covers and which is outside
#   any managed policy branch: they show as Extra Registry Settings and they tattoo.
#   The comments above them name GUI locations the values do not actually reach. The
#   GUI-native equivalents are System Services (Import-GPO again) for the Browser
#   service, and for SMBv1 removing the feature outright via DISM rather than a GPO.
#
# Validation still owed on a lab DC, both from the v3.3 firewall work: that
# -PolicyStore tolerates the colon in GPO names such as "Firewall: Allow from DC",
# and that Set-ClkGPOFirewallRule's update path behaves on a second run.
