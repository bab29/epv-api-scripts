#Requires -Version 5.1
<#
.SYNOPSIS
    Derives Identity tenant URL from PCloud URL

.DESCRIPTION
    Extracts subdomain from PCloud URL and constructs Identity tenant URL.
    Handles both privilegecloud.cyberark.cloud and cyberark.cloud formats.
#>

function Get-IdentityURLFromPCloud {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PCloudURL
    )

    Write-Verbose "Deriving Identity URL from PCloud URL: $PCloudURL"

    # Extract subdomain
    if ($PCloudURL -match 'https?://([^.]+)\.(?:privilegecloud\.)?cyberark\.cloud') {
        $subdomain = $Matches[1]

        # Build Identity URL
        $identityURL = "https://$subdomain.id.cyberark.cloud"

        Write-Verbose "Derived Identity URL: $identityURL"
        return $identityURL
    } else {
        throw "Unable to derive Identity URL from PCloud URL: $PCloudURL. Expected format: https://subdomain.privilegecloud.cyberark.cloud"
    }
}
