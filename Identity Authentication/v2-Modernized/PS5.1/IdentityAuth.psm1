#Requires -Version 5.1
<#
.SYNOPSIS
    Identity Authentication Module for CyberArk Privilege Cloud (PowerShell 5.1)

.DESCRIPTION
    Provides authentication to CyberArk Identity for Privilege Cloud environments.
    Supports OAuth, Username/Password, MFA, and OOBAUTHPIN authentication flows.
    Returns hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers for PCloud APIs.

.NOTES
    PowerShell Version: 5.1+
    Module Version: 2.0.0
    Author: CyberArk
    Last Updated: 2026-01-28
#>

# Module script initialization
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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
