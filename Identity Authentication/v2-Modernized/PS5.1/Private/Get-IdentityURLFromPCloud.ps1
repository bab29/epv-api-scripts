#Requires -Version 5.1
<#
.SYNOPSIS
    Derives Identity URL from PCloud URL using HTTP redirect discovery

.DESCRIPTION
    Constructs the base CyberArk URL and makes an HTTP request to discover
    the actual Identity URL through redirect. Falls back to string replacement
    if HTTP discovery fails.
    
    This matches the v1 behavior which uses HTTP redirects to find the correct
    Identity URL, handling cases where subdomain doesn't match
    (e.g., serviceslab.privilegecloud → abi4738.id)
#>

function Get-IdentityURLFromPCloud {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PCloudURL
    )

    Write-Verbose "Deriving Identity URL from PCloud URL: $PCloudURL"

    # Extract subdomain and TLD from PCloud URL
    if ($PCloudURL -match '^(?:https?:\/\/)?(?<sub>[^.]+)(?:\.privilegecloud)?\.cyberark\.(?<top>cloud|com)') {
        $subdomain = $Matches['sub']
        $topLevel = $Matches['top']
        $baseUrl = "https://$subdomain.cyberark.$topLevel"
        
        Write-Verbose "Attempting HTTP redirect discovery from: $baseUrl"
        
        try {
            # Make HTTP request and follow redirects to discover Identity URL
            $response = Invoke-WebRequest -Uri $baseUrl -Method Get -MaximumRedirection 5 -ErrorAction Stop
            
            # Extract Identity URL from response
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                # PowerShell 7+
                $identityHost = $response.BaseResponse.RequestMessage.RequestUri.Host
            } else {
                # PowerShell 5.1
                $identityHost = $response.BaseResponse.ResponseUri.Host
            }
            
            if ($identityHost -and $identityHost -like '*.id.cyberark.*') {
                $identityURL = "https://$identityHost"
                Write-Verbose "Identity URL discovered via HTTP redirect: $identityURL"
                return $identityURL
            } else {
                Write-Verbose "HTTP response did not contain valid Identity URL, using fallback"
            }
        } catch {
            Write-Verbose "HTTP redirect discovery failed: $($_.Exception.Message), using fallback"
        }
    }
    
    # Fallback: Simple string replacement (works for most tenants)
    Write-Verbose "Using string replacement fallback method"
    if ($PCloudURL -match 'https?://([^.]+)\.(?:privilegecloud\.)?cyberark\.cloud') {
        $subdomain = $Matches[1]
        $identityURL = "https://$subdomain.id.cyberark.cloud"
        Write-Verbose "Derived Identity URL: $identityURL"
        return $identityURL
    } else {
        throw "Unable to derive Identity URL from PCloud URL: $PCloudURL. Expected format: https://subdomain.privilegecloud.cyberark.cloud"
    }
}

