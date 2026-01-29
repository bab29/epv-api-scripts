#Requires -Version 5.1
<#
.SYNOPSIS
    Formats authentication token into PCloud-compatible headers

.DESCRIPTION
    Creates hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers
    required for Privilege Cloud API authentication.
#>

function Format-IdentityHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    Write-Verbose "Formatting Identity headers"

    # Create headers hashtable
    $headers = @{
        Authorization           = "Bearer $AccessToken"
        'X-IDAP-NATIVE-CLIENT' = 'true'
    }

    Write-Verbose "Headers created with Authorization and X-IDAP-NATIVE-CLIENT"

    return $headers
}
