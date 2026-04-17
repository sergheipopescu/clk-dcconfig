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
# Coding: (bad)Copilot
# Mastermind: sp
#
# Version History:
#   2.0-gold: Initial version. Creates the Active Directory baseline: OU structure, administrative groups, FGPPs, and GPO objects with linking only. No policy settings are applied.
#   2.1: Populates all baseline GPOs with security, firewall, Defender, SMB, RDP, Windows Update, and startup reliability settings, forming the complete domain hardening configuration.
# ============================================================


##############################################
###            Version 2.0-gold            ###
##############################################

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host ""
Write-Host "===        dcconfig        ===" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

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
    param (
        [string]$Name,
        [string]$Path
    )

    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
        Write-Host "Created OU: $Name" -ForegroundColor Green
    }
    else {
        Write-Host "OU already exists: $Name" -ForegroundColor Gray
    }
}

function New-ClkGPO {
    param ([string]$Name)

    if (-not (Get-GPO -Name $Name -ErrorAction SilentlyContinue)) {
        New-GPO -Name $Name | Out-Null
        Write-Host "Created GPO: $Name" -ForegroundColor Green
    }
    else {
        Write-Host "GPO already exists: $Name" -ForegroundColor Gray
    }
}

function New-ClkGPOLink {
    param (
        [string]$GPOName,
        [string]$TargetOU,
        [bool]$Disabled = $false
    )

    $existing = (Get-GPInheritance -Target $TargetOU).GpoLinks |
        Where-Object { $_.DisplayName -eq $GPOName }

    if (-not $existing) {
        if ($Disabled) {
            New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled No | Out-Null
            Write-Host "Linked (disabled): $GPOName -> $TargetOU" -ForegroundColor Yellow
        }
        else {
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
# OU Structure
# ============================================================
if (Confirm-Action "Create baseline OU structure?") {

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
}

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

$CurrentUser = Get-ADUser ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)

Add-ADGroupMember -Identity $JanitorsGroup -Members $CurrentUser -ErrorAction SilentlyContinue
Write-Host "Ensured current user is member of Janitors" -ForegroundColor Green

# ============================================================
# Move User to Admins OU
# ============================================================
if (Confirm-Action "Move current user '$($CurrentUser.SamAccountName)' to Admins OU?") {
    if ($CurrentUser.DistinguishedName -notlike "*OU=Admins,*") {
        Move-ADObject -Identity $CurrentUser.DistinguishedName -TargetPath $AdminsOU
        Write-Host "Moved user to Admins OU" -ForegroundColor Green
    }
    else {
        Write-Host "User already in Admins OU" -ForegroundColor Gray
    }
}

# ============================================================
# FGPPs
# ============================================================
if (Confirm-Action "Create Fine-Grained Password Policies?") {

    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'Domain Admin Policy'")) {
        New-ADFineGrainedPasswordPolicy `
            -Name "Domain Admin Policy" `
            -Precedence 1 `
            -MinPasswordLength 8 `
            -PasswordHistoryCount 16 `
            -ComplexityEnabled $true `
            -MaxPasswordAge (New-TimeSpan -Days 365) `
            -LockoutThreshold 10 `
            -LockoutDuration (New-TimeSpan -Minutes 60) `
            -LockoutObservationWindow (New-TimeSpan -Minutes 60)
        Write-Host "Created FGPP: Domain Admin Policy" -ForegroundColor Green
    }
    else {
        Write-Host "FGPP already exists: Domain Admin Policy" -ForegroundColor Gray
    }

    Add-ADFineGrainedPasswordPolicySubject -Identity "Domain Admin Policy" -Subjects "Janitors" -ErrorAction SilentlyContinue

    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'User Policy'")) {
        New-ADFineGrainedPasswordPolicy `
            -Name "User Policy" `
            -Precedence 10 `
            -MinPasswordLength 8 `
            -PasswordHistoryCount 16 `
            -ComplexityEnabled $true `
            -MaxPasswordAge (New-TimeSpan -Days 120)
        Write-Host "Created FGPP: User Policy" -ForegroundColor Green
    }
    else {
        Write-Host "FGPP already exists: User Policy" -ForegroundColor Gray
    }

    Add-ADFineGrainedPasswordPolicySubject -Identity "User Policy" -Subjects "Domain Users" -ErrorAction SilentlyContinue
}

# ============================================================
# GPO Creation
# ============================================================
$GPOs = @(
    "Security: Enable Firewall",
    "Firewall: Default Server Rules",
    "Firewall: Default Workstation Rules",
    "Firewall: Allow from DC",
    "Firewall: Allow from Clickwork HQ",
    "Firewall: Allow ESMC",
    "Security: Enable Defender",
    "Security: Ctrl+Alt+Del",
    "Security: Disable AutoPlay",
    "Security: SMB Hardening",
    "Settings: Wait for network",
    "Settings: Enable RDP",
    "Settings: NoSleep",
    "Settings: Workstation Updates",
    "Printers: Remove garbage",
    "Customization: Lock Screen",
    "Customization: Wallpaper",
    "Customization: Regional",
    "Customization: Explorer",
    "Customization: NoCloud content",
    "Settings: EDGE Policies"
)

if (Confirm-Action "Create baseline GPO objects?") {
    foreach ($gpo in $GPOs) {
        New-ClkGPO $gpo
    }
}

# ============================================================
# GPO Linking (NO SETTINGS)
# ============================================================
Write-Host ""
Write-Host "Linking GPOs to OUs ..."
foreach ($gpo in $GPOs) {
    switch ($gpo) {
	"Security: Disable AutoPlay"		 { New-ClkGPOLink $gpo $ComputersOU }
	"Security: SMB Hardening"		 { New-ClkGPOLink $gpo $ComputersOU }
	"Security: Enable Firewall"		 { New-ClkGPOLink $gpo $ComputersOU }
	"Security: Enable Defender"		 { New-ClkGPOLink $gpo $ComputersOU }
        "Firewall: Default Server Rules"         { New-ClkGPOLink $gpo $ServersOU }
        "Firewall: Default Workstation Rules"    { New-ClkGPOLink $gpo $WorkstationsOU }
	"Settings: Wait for network"		 { New-ClkGPOLink $gpo $ComputersOU }
	"Settings: Enable RDP"			 { New-ClkGPOLink $gpo $ComputersOU }
	"Settings: Workstation Updates"          { New-ClkGPOLink $gpo $WorkstationsOU }
	"Security: Ctrl+Alt+Del"		 { New-ClkGPOLink $gpo $ComputersOU $true }
	"Firewall: Allow from DC"		 { New-ClkGPOLink $gpo $ComputersOU $true }
	"Firewall: Allow from Clickwork HQ"	 { New-ClkGPOLink $gpo $ComputersOU $true }
	"Firewall: Allow ESMC"			 { New-ClkGPOLink $gpo $ComputersOU $true }
        "Printers: Remove garbage"               { New-ClkGPOLink $gpo $WorkstationsOU $true }
        "Customization: Lock Screen"             { New-ClkGPOLink $gpo $WorkstationsOU $true }
        "Customization: Wallpaper"               { New-ClkGPOLink $gpo $WorkstationsOU $true }
	"Customization: Regional"                { New-ClkGPOLink $gpo $UsersOU $true }
        "Customization: Explorer"                { New-ClkGPOLink $gpo $UsersOU $true }
        "Customization: NoCloud content"         { New-ClkGPOLink $gpo $UsersOU $true }
	"Settings: NoSleep"                      { New-ClkGPOLink $gpo $WorkstationsOU $true }
        "Settings: EDGE Policies"                {
                                                    New-ClkGPOLink $gpo $UsersOU $true
                                                    New-ClkGPOLink $gpo $AdminsOU $true
                                                  }
        default                                  { New-ClkGPOLink $gpo $ComputersOU }
    }
}




#########################################
###            Version 2.1            ###
#########################################

Write-Host ""
Write-Host "Populating GPO settings ..."

###
# GPO: Security: Enable Firewall
# Including Administrative Template: "Protect all network connections" (Standard Profile)
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

Set-GPRegistryValue `
    -Name $FirewallEnableGPO `
    -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" `
    -ValueName "EnableFirewall" `
    -Type DWord `
    -Value 1 | Out-Null

# ------------------------------------------------------------
# Confirm settings population
# ------------------------------------------------------------
Write-Host "Populated GPO: $FirewallEnableGPO" -ForegroundColor Green


###
# GPO: Firewall: Default Server Rules
# Path: Administrative Templates > Network > Network Connections > Windows Defender Firewall > Domain Profile
###

# ------------------------------------------------------------
# Target GPO
# ------------------------------------------------------------
$ServerFirewallGPO = "Firewall: Default Server Rules"

# ------------------------------------------------------------
# Resolve DC IPv4 addresses (static snapshot, matches .pol behavior)
# ------------------------------------------------------------
$DCIPs = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty IPv4Address |
    Where-Object { $_ }

$DCIPString = ($DCIPs -join ",")

$DomainProfileKey = "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"

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
# Resolve DC IPv4 addresses (static snapshot, matches ADMX behavior)
# ------------------------------------------------------------
$DCIPs = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty IPv4Address |
    Where-Object { $_ }

$DCIPString = ($DCIPs -join ",")

$DomainProfileKey = "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"

# ------------------------------------------------------------
# Allow ICMP exceptions → Allow inbound echo request
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