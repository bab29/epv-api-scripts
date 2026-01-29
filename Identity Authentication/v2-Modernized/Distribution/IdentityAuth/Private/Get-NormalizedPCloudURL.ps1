#Requires -Version 5.1
<#
.SYNOPSIS
    Validates and normalizes PCloud URL

.DESCRIPTION
    Ensures PCloud URL is in correct format with /PasswordVault/ suffix.
    Handles various input formats and adds missing components.
#>

function Get-NormalizedPCloudURL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PCloudURL
    )
    
    Write-Verbose "Original PCloud URL: $PCloudURL"
    
    # Remove trailing slashes
    $url = $PCloudURL.TrimEnd('/')
    
    # Ensure HTTPS
    if (-not $url.StartsWith('http')) {
        $url = "https://$url"
        Write-Verbose "Added HTTPS scheme: $url"
    }
    
    # Add /PasswordVault if missing
    if (-not $url.EndsWith('/PasswordVault')) {
        $url = "$url/PasswordVault"
        Write-Verbose "Added /PasswordVault suffix: $url"
    }
    
    Write-Verbose "Normalized PCloud URL: $url"
    
    return $url
}
