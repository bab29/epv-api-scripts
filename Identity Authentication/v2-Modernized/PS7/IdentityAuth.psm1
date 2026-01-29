#Requires -Version 7.0
<#
.SYNOPSIS
    Identity Authentication Module for CyberArk Privilege Cloud (PowerShell 7+)

.DESCRIPTION
    Provides authentication to CyberArk Identity for Privilege Cloud environments.
    Supports OAuth, Username/Password, MFA, and OOBAUTHPIN authentication flows.
    Returns hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers for PCloud APIs.

    This version uses PowerShell 7+ features including classes and enums for better type safety.

.NOTES
    PowerShell Version: 7.0+
    Module Version: 2.0.0
    Author: CyberArk
    Last Updated: 2026-01-28
#>

# Module script initialization
using namespace System
using namespace System.Collections.Generic
using namespace System.Management.Automation

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Import enums first (required before classes)
$EnumFiles = @(Get-ChildItem -Path $PSScriptRoot\Enums\*.ps1 -ErrorAction SilentlyContinue)
foreach ($import in $EnumFiles) {
    try {
        . $import.FullName
    } catch {
        Write-Error "Failed to import enum $($import.FullName): $_"
    }
}

# Import classes
$ClassFiles = @(Get-ChildItem -Path $PSScriptRoot\Classes\*.ps1 -ErrorAction SilentlyContinue)
foreach ($import in $ClassFiles) {
    try {
        . $import.FullName
    } catch {
        Write-Error "Failed to import class $($import.FullName): $_"
    }
}

# Script-level variables for session state
$script:CurrentSession = $null
$script:OAuthTokenCache = $null
$script:TokenExpiry = $null

# Import private functions
$PrivateFunctions = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
foreach ($import in $PrivateFunctions) {
    try {
        . $import.FullName
    } catch {
        Write-Error "Failed to import private function $($import.FullName): $_"
    }
}

# Import public functions
$PublicFunctions = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)
foreach ($import in $PublicFunctions) {
    try {
        . $import.FullName
    } catch {
        Write-Error "Failed to import public function $($import.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $PublicFunctions.BaseName
