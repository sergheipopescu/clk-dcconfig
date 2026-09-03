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
# Coding: (bad)Copilot unti v2.1, ClaudeCode since v3.0
# Mastermind: sp
#
# Version History:
#   2.0-gold: Initial version. Creates the Active Directory baseline: OU structure, administrative groups, FGPPs, and GPO objects with linking only. No policy settings are applied.
#   2.1: Populates all baseline GPOs with security, firewall, Defender, SMB, RDP, Windows Update, and startup reliability settings, forming the complete domain hardening configuration.
# ============================================================


##############################################
###            Version 2.0-gold            ###
##############################################

[CmdletBinding(SupportsShouldProcess)]
param()

Import-Module ActiveDirectory
Import-Module GroupPolicy

# ============================================================
# Transcript Logging
# ============================================================
$LogDir = Join-Path $PSScriptRoot "Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
$LogFile = Join-Path $LogDir ("dcconfig_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Start-Transcript -Path $LogFile | Out-Null

Write-Host ""
Write-Host "===        dcconfig        ===" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Configuration
# ============================================================
# Fine-Grained Password Policy tunables - adjust here for org-specific requirements.
$DomainAdminPasswordMinLength         = 8
$DomainAdminPasswordHistoryCount      = 16
$DomainAdminMaxPasswordAgeDays        = 365
$DomainAdminLockoutThreshold          = 10
$DomainAdminLockoutDurationMinutes    = 60
$DomainAdminLockoutObservationMinutes = 60

$UserPasswordMinLength    = 8
$UserPasswordHistoryCount = 16
$UserMaxPasswordAgeDays   = 120

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

function New-ClkGPOLink {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$GPOName,
        [string]$TargetOU,
        [bool]$Disabled = $false
    )

    $existing = (Get-GPInheritance -Target $TargetOU).GpoLinks |
        Where-Object { $_.DisplayName -eq $GPOName }

    if (-not $existing) {
        if ($Disabled) {
            if ($PSCmdlet.ShouldProcess("$GPOName -> $TargetOU", "Link GPO (disabled)")) {
                New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled No | Out-Null
                Write-Host "Linked (disabled): $GPOName -> $TargetOU" -ForegroundColor Yellow
            }
        }
        elseif ($PSCmdlet.ShouldProcess("$GPOName -> $TargetOU", "Link GPO")) {
            New-GPLink -Name $GPOName -Target $TargetOU | Out-Null
            Write-Host "Linked: $GPOName -> $TargetOU" -ForegroundColor Green
        }
    }
    else {
        Write-Host "Link already exists: $GPOName -> $TargetOU" -ForegroundColor Gray
    }
}

# ============================================================
# Root OU Input
# ============================================================
$RootOUName = Read-Host "Enter the root OU name (e.g. CONTOSO, ACME)"

if ([string]::IsNullOrWhiteSpace($RootOUName)) {
    Write-Host "Root OU name cannot be empty. Exiting." -ForegroundColor Red
    Stop-Transcript | Out-Null
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
Write-Host "  - 'Janitors' admin group, with the current user added as a member"
Write-Host "  - Current user moved to the Admins OU"
Write-Host "  - Fine-Grained Password Policies for admins and users"
Write-Host "  - Baseline GPOs, created, linked to their target OUs, and populated with security/firewall/Defender/SMB/RDP/Update settings"
Write-Host ""

if ($WhatIfPreference) {
    Write-Host "Running with -WhatIf: no changes will actually be made. Each action will report what it would have done." -ForegroundColor Yellow
    Write-Host ""
}

if (-not (Confirm-Action "Proceed?")) {
    Write-Host "Aborted by user." -ForegroundColor Red
    Stop-Transcript | Out-Null
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
# Janitors Group
# ============================================================
$JanitorsOU = "OU=Security,$GroupsOU"
$JanitorsGroup = "Janitors"

if (-not (Get-ADGroup -Filter "Name -eq '$JanitorsGroup'" -SearchBase $JanitorsOU -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $JanitorsGroup -GroupScope Global -GroupCategory Security -Path $JanitorsOU
    Write-Host "Created group: Janitors" -ForegroundColor Green
}
else {
    Write-Host "Group already exists: Janitors" -ForegroundColor Gray
}

try {
    $CurrentUser = Get-ADUser ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -ErrorAction Stop
}
catch {
    Write-Host "Could not resolve the current user as a domain account. This script must be run while logged on as a domain user. Exiting." -ForegroundColor Red
    Stop-Transcript | Out-Null
    return
}

if (-not (Get-ADGroupMember -Identity $JanitorsGroup | Where-Object { $_.SID.Value -eq $CurrentUser.SID.Value })) {
    Add-ADGroupMember -Identity $JanitorsGroup -Members $CurrentUser
    Write-Host "Added current user to Janitors" -ForegroundColor Green
}
else {
    Write-Host "Current user already a member of Janitors" -ForegroundColor Gray
}

# ============================================================
# Move User to Admins OU
# ============================================================
if ($CurrentUser.DistinguishedName -notlike "*OU=Admins,*") {
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

if (-not (Get-ADFineGrainedPasswordPolicySubject -Identity "Domain Admin Policy" | Where-Object { $_.Name -eq "Janitors" })) {
    Add-ADFineGrainedPasswordPolicySubject -Identity "Domain Admin Policy" -Subjects "Janitors"
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
        -MaxPasswordAge (New-TimeSpan -Days $UserMaxPasswordAgeDays)
    Write-Host "Created FGPP: User Policy" -ForegroundColor Green
}
else {
    Write-Host "FGPP already exists: User Policy" -ForegroundColor Gray
}

if (-not (Get-ADFineGrainedPasswordPolicySubject -Identity "User Policy" | Where-Object { $_.Name -eq "Domain Users" })) {
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
###            Version 2.1            ###
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
    Set-GPRegistryValue `
        -Name $FirewallEnableGPO `
        -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\$FWProfile" `
        -ValueName "EnableFirewall" `
        -Type DWord `
        -Value 1 | Out-Null
}

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $FirewallEnableGPO" -ForegroundColor Green


# ------------------------------------------------------------
# Resolve DC IPv4 addresses (static snapshot, matches .pol/ADMX behavior)
# Shared by the Server and Workstation firewall rule blocks below,
# which both scope their exceptions to these same DC IPs.
# ------------------------------------------------------------
$DCIPs = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty IPv4Address |
    Where-Object { $_ }

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
Set-GPRegistryValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\IcmpSettings" `
    -ValueName "AllowInboundEchoRequest" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Allow inbound remote administration exception (DC IP only)
# (.pol: DomainProfile\RemoteAdminSettings)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1 | Out-Null

Set-GPRegistryValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString | Out-Null

# ------------------------------------------------------------
# Allow inbound file and printer sharing (DC IP only)
# (.pol: DomainProfile\Services\FileAndPrint)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1 | Out-Null

Set-GPRegistryValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString | Out-Null

# ------------------------------------------------------------
# Allow inbound Remote Desktop exceptions (DC IP only)
# (.pol: DomainProfile\Services\RemoteDesktop)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1 | Out-Null

Set-GPRegistryValue `
    -Name $ServerFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $ServerFirewallGPO" -ForegroundColor Green


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
Set-GPRegistryValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\IcmpSettings" `
    -ValueName "AllowInboundEchoRequest" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Allow inbound remote administration exception (DC IP only)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1 | Out-Null

Set-GPRegistryValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\RemoteAdminSettings" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString | Out-Null

# ------------------------------------------------------------
# Allow inbound file and printer sharing (DC IP only)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1 | Out-Null

Set-GPRegistryValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\FileAndPrint" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString | Out-Null

# ------------------------------------------------------------
# Allow inbound Remote Desktop exceptions (DC IP only)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "Enabled" `
    -Type DWord `
    -Value 1 | Out-Null

Set-GPRegistryValue `
    -Name $WorkstationFirewallGPO `
    -Key "$DomainProfileKey\Services\RemoteDesktop" `
    -ValueName "RemoteAddresses" `
    -Type String `
    -Value $DCIPString | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $WorkstationFirewallGPO" -ForegroundColor Green


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
Set-GPRegistryValue `
    -Name $DefenderGPO `
    -Key $BaseKey `
    -ValueName "DisableAntiSpyware" `
    -Type DWord `
    -Value 0 | Out-Null

# ------------------------------------------------------------
# Enable real-time protection
# Policy: Turn on real-time protection = Enabled
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $DefenderGPO `
    -Key "$BaseKey\Real-Time Protection" `
    -ValueName "DisableRealtimeMonitoring" `
    -Type DWord `
    -Value 0 | Out-Null

# ------------------------------------------------------------
# Enable cloud-delivered protection
# Policy: Turn on cloud-delivered protection = Enabled
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $DefenderGPO `
    -Key "$BaseKey\Spynet" `
    -ValueName "SpynetReporting" `
    -Type DWord `
    -Value 2 | Out-Null

# ------------------------------------------------------------
# Enable automatic sample submission
# Policy: Send file samples when further analysis is required
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $DefenderGPO `
    -Key "$BaseKey\Spynet" `
    -ValueName "SubmitSamplesConsent" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Enable Potentially Unwanted Application (PUA) protection
# Policy: Configure detection for potentially unwanted applications = Enabled (Block)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $DefenderGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows Defender" `
    -ValueName "PUAProtection" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $DefenderGPO" -ForegroundColor Green


###
# GPO: Security: Disable AutoPlay
# Path: Administrative Templates > Windows Components > AutoPlay Policies

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$AutoPlayGPO = "Security: Disable AutoPlay"

# ------------------------------------------------------------
# Set the default behavior for AutoRun = Enabled
# Default AutoRun Behavior: Do not execute any autorun commands
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $AutoPlayGPO `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoAutorun" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Turn off AutoPlay = Enabled
# Turn off AutoPlay on: All drives
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $AutoPlayGPO `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoDriveTypeAutoRun" `
    -Type DWord `
    -Value 255 | Out-Null

# ------------------------------------------------------------
# Disallow AutoPlay for non-volume devices = Enabled
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $AutoPlayGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\Explorer" `
    -ValueName "NoAutoplayfornonVolume" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $AutoPlayGPO" -ForegroundColor Green


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
Set-GPRegistryValue `
    -Name $SmbHardeningGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\Browser" `
    -ValueName "Start" `
    -Type DWord `
    -Value 4 | Out-Null

# ------------------------------------------------------------
# Disable SMBv1 protocol (Lanman Server)
# Administrative Templates → Network → Lanman Server
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $SmbHardeningGPO `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "SMB1" `
    -Type DWord `
    -Value 0 | Out-Null

# ------------------------------------------------------------
# Disable insecure guest logons (Lanman Workstation)
# Administrative Templates → Network → Lanman Workstation
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $SmbHardeningGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" `
    -ValueName "AllowInsecureGuestAuth" `
    -Type DWord `
    -Value 0 | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $SmbHardeningGPO" -ForegroundColor Green


###
# GPO: Settings: Wait for network
# ADMX Policy: System\Logon\Always wait for the network at computer startup and logon = Enabled
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$WaitForNetworkGPO = "Settings: Wait for network"

# ------------------------------------------------------------
# Always wait for the network at startup and logon
# ------------------------------------------------------------
#Set-GPRegistryValue `
#   -Name $WaitForNetworkGPO `
#    -Key "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" `
#    -ValueName "AlwaysWaitForNetworkAtStartupAndLogon" `
#    -Type DWord `
#    -Value 1

# ------------------------------------------------------------
# Synchronous foreground policy processing (required by ADMX)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $WaitForNetworkGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -ValueName "SyncForegroundPolicy" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $WaitForNetworkGPO" -ForegroundColor Green


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
# Allow users to connect remotely using Remote Desktop Services
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $EnableRdpGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "fDenyTSConnections" `
    -Type DWord `
    -Value 0 | Out-Null

# ------------------------------------------------------------
# Require Network Level Authentication (NLA)
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $EnableRdpGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" `
    -ValueName "UserAuthentication" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $EnableRdpGPO" -ForegroundColor Green


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
# Enable Automatic Updates
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $WorkstationUpdatesGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "NoAutoUpdate" `
    -Type DWord `
    -Value 0 | Out-Null

# ------------------------------------------------------------
# Configure Automatic Updates: Option 4
# Auto download and schedule the install
# ------------------------------------------------------------
Set-GPRegistryValue `
    -Name $WorkstationUpdatesGPO `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "AUOptions" `
    -Type DWord `
    -Value 4 | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $WorkstationUpdatesGPO" -ForegroundColor Green


##########################################
###          Script completed          ###
##########################################

Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "=== dcconfig 2.1 completed ===" -ForegroundColor Cyan

Stop-Transcript | Out-Null



# Future feature plan:
# - Add more GPO settings to fully implement the baseline hardening configuration.
# redircmp "OU=Workstations,OU=Computers,OU=<RootOU>,DC=example,DC=com"
# redirusr "OU=Users,OU=<RootOU>,DC=example,DC=com"