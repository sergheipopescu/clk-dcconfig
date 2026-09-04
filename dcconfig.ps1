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
# ============================================================


##################################################
###   AD Structure, Groups, FGPPs, GPO Objects ###
##################################################

# Fail up front with a clear message rather than deep into the run with an obscure
# access-denied or "term not recognized" error. -Modules also imports both modules,
# so the Import-Module calls below are belt-and-braces for readability.
#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding(SupportsShouldProcess)]
param()

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
        $versions = Select-String -LiteralPath $Path -Pattern '^#\s+(\d+\.\d+(?:-[A-Za-z0-9]+)?):' -ErrorAction Stop |
            ForEach-Object { $_.Matches[0].Groups[1].Value }
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

    if ($PSCmdlet.ShouldProcess($TargetOU, "Set default $ContainerType container ($Command)")) {
        & $Command $TargetOU | Out-Null
        Write-Host "Set default ${ContainerType} container: $TargetOU" -ForegroundColor Green
    }
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
# handful of OUs once per GPO. Cache the linked-GPO names per OU on first use; there
# are ~22 links across 6 distinct OUs, so this turns 22 queries into 6.
$script:GPLinkCache = @{}

function Get-ClkGPOLinkNames {
    param ([string]$TargetOU)

    if (-not $script:GPLinkCache.ContainsKey($TargetOU)) {
        $script:GPLinkCache[$TargetOU] = @(
            (Get-GPInheritance -Target $TargetOU).GpoLinks |
                Select-Object -ExpandProperty DisplayName
        )
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

    $existing = (Get-ClkGPOLinkNames $TargetOU) -contains $GPOName

    if (-not $existing) {
        if ($Disabled) {
            if ($PSCmdlet.ShouldProcess("$GPOName -> $TargetOU", "Link GPO (disabled)")) {
                New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled No | Out-Null
                $script:GPLinkCache[$TargetOU] += $GPOName
                Write-Host "Linked (disabled): $GPOName -> $TargetOU" -ForegroundColor Yellow
            }
        }
        elseif ($PSCmdlet.ShouldProcess("$GPOName -> $TargetOU", "Link GPO")) {
            New-GPLink -Name $GPOName -Target $TargetOU | Out-Null
            $script:GPLinkCache[$TargetOU] += $GPOName
            Write-Host "Linked: $GPOName -> $TargetOU" -ForegroundColor Green
        }
    }
    else {
        Write-Host "Link already exists: $GPOName -> $TargetOU" -ForegroundColor Gray
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
Write-Host ""

if ($WhatIfPreference) {
    Write-Host "Running with -WhatIf: no changes will actually be made. Each action will report what it would have done." -ForegroundColor Yellow
    Write-Host "GPO linking and GPO settings population are skipped entirely, since both operate on objects that -WhatIf did not create." -ForegroundColor Yellow
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
    [PSCustomObject]@{ Name = "Firewall: Allow from DC";             TargetOU = @($ComputersOU);        Disabled = $true  }
    [PSCustomObject]@{ Name = "Firewall: Allow from Clickwork HQ";   TargetOU = @($ComputersOU);        Disabled = $true  }
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
    [PSCustomObject]@{ Name = "Settings: NoSleep";                   TargetOU = @($WorkstationsOU);     Disabled = $true  }
    [PSCustomObject]@{ Name = "Settings: Workstation Updates";       TargetOU = @($WorkstationsOU);     Disabled = $false }
    [PSCustomObject]@{ Name = "Printers: Remove garbage";            TargetOU = @($WorkstationsOU);     Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Lock Screen";          TargetOU = @($WorkstationsOU);     Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Wallpaper";            TargetOU = @($WorkstationsOU);     Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Regional";             TargetOU = @($UsersOU);            Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: Explorer";             TargetOU = @($UsersOU);            Disabled = $true  }
    [PSCustomObject]@{ Name = "Customization: NoCloud content";      TargetOU = @($UsersOU);            Disabled = $true  }
    [PSCustomObject]@{ Name = "Settings: EDGE Policies";             TargetOU = @($UsersOU, $AdminsOU); Disabled = $true  }
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


##########################################
###          Script completed          ###
##########################################

$TotalFailures = ($script:GPOFailures.Values | Measure-Object -Sum).Sum

Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
if ($TotalFailures) {
    Write-Host "dcconfig $ScriptVersion completed with errors" -ForegroundColor Red
    Write-Host "$TotalFailures GPO setting(s) failed to apply across $($script:GPOFailures.Count) GPO(s):" -ForegroundColor Red
    foreach ($entry in $script:GPOFailures.GetEnumerator()) {
        Write-Host "  - $($entry.Key): $($entry.Value) failure(s)" -ForegroundColor Red
    }
    Write-Host "Review the log at $LogFile and re-run once the cause is fixed." -ForegroundColor Red
}
else {
    Write-Host "dcconfig $ScriptVersion completed successfully" -ForegroundColor Cyan
}

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null



# Future feature plan:
# - Add more GPO settings to fully implement the baseline hardening configuration.