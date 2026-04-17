# ============================================================
# Script: dc_config.ps1
# Version: 2.0-gold
#
# Purpose:
#   Domain controller baseline configuration (STRUCTURE ONLY)
#
#   - OU structure creation
#   - Admin group (Janitors)
#   - User placement
#   - Fine-Grained Password Policies
#   - GPO object creation and linking
#
# Coding: (bad)Copilot
# Mastermind: sp
# ============================================================

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host ""
Write-Host "=== dc_config.ps1 2.0-gold ===" -ForegroundColor White
Write-Host "=== STRUCTURE-ONLY BOOTSTRAP ===" -ForegroundColor Cyan
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

function New-GPO {
    param ([string]$Name)

    if (-not (Get-GPO -Name $Name -ErrorAction SilentlyContinue)) {
        New-GPO -Name $Name | Out-Null
        Write-Host "Created GPO: $Name" -ForegroundColor Green
    }
    else {
        Write-Host "GPO already exists: $Name" -ForegroundColor Gray
    }
}

function New-GPOLink {
    param (
        [string]$GPOName,
        [string]$TargetOU,
        [bool]$Disabled = $false
    )

    $existing = (Get-GPInheritance -Target $TargetOU).GpoLinks |
        Where-Object { $_.DisplayName -eq $GPOName }

    if (-not $existing) {
        if ($Disabled) {
            New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled No
            Write-Host "Linked (disabled): $GPOName -> $TargetOU" -ForegroundColor Yellow
        }
        else {
            New-GPLink -Name $GPOName -Target $TargetOU
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
        New-GPO $gpo
    }
}

# ============================================================
# GPO Linking (NO SETTINGS)
# ============================================================

foreach ($gpo in $GPOs) {
    switch ($gpo) {
	"Security: Enable Firewall"		 { New-GPOLink $gpo $ComputersOU }
        "Firewall: Default Server Rules"         { New-GPOLink $gpo $ServersOU }
        "Firewall: Default Workstation Rules"    { New-GPOLink $gpo $WorkstationsOU }
	"Firewall: Allow from DC"		 { New-GPOLink $gpo $ComputersOU $true }
	"Firewall: Allow from Clickwork HQ"	 { New-GPOLink $gpo $ComputersOU $true }
	"Firewall: Allow ESMC"			 { New-GPOLink $gpo $ComputersOU $true }
	"Security: Enable Defender"		 { New-GPOLink $gpo $ComputersOU }
	"Security: Ctrl+Alt+Del"		 { New-GPOLink $gpo $ComputersOU }
	"Security: Disable AutoPlay"		 { New-GPOLink $gpo $ComputersOU }
	"Security: SMB Hardening"		 { New-GPOLink $gpo $ComputersOU }
	"Settings: Wait for network"		 { New-GPOLink $gpo $ComputersOU }
	"Settings: Enable RDP"			 { New-GPOLink $gpo $ComputersOU }
        "Settings: NoSleep"                      { New-GPOLink $gpo $WorkstationsOU $true }
        "Settings: Workstation Updates"          { New-GPOLink $gpo $WorkstationsOU }
        "Printers: Remove garbage"               { New-GPOLink $gpo $WorkstationsOU $true }
        "Customization: Regional"                { New-GPOLink $gpo $UsersOU $true }
        "Customization: Explorer"                { New-GPOLink $gpo $UsersOU $true }
        "Customization: NoCloud content"         { New-GPOLink $gpo $UsersOU $true }
        "Customization: Lock Screen"             { New-GPOLink $gpo $WorkstationsOU $true }
        "Customization: Wallpaper"               { New-GPOLink $gpo $WorkstationsOU $true }
        "Settings: EDGE Policies"                {
                                                    New-GPOLink $gpo $UsersOU $true
                                                    New-GPOLink $gpo $AdminsOU $true
                                                  }
        default                                  { New-GPOLink $gpo $ComputersOU }
    }
}

Write-Host ""
Write-Host "=== dc_config.ps1 2.0-gold completed ===" -ForegroundColor White