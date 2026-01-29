#Requires -Version 5.1
<#
.SYNOPSIS
    Convert session hashtable to authorization headers

.DESCRIPTION
    Extracts token from session hashtable and constructs authorization headers
    with X-IDAP-NATIVE-CLIENT header for Privilege Cloud APIs.

.PARAMETER Session
    Session hashtable containing Token and other metadata

.OUTPUTS
    Hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers

.EXAMPLE
    $headers = ConvertFrom-SessionToHeaders -Session $script:CurrentSession

.NOTES
    Private function - Internal use only
#>
function ConvertFrom-SessionToHeaders {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Session
    )

    Write-Verbose "Converting session to headers"

    # PS5.1: Check expiry manually (no IsExpired() method)
    if ($Session.TokenExpiry -and ((Get-Date) -gt $Session.TokenExpiry)) {
        throw "Session token has expired. Please re-authenticate."
    }

    return @{
        'Authorization'        = "Bearer $($Session.Token)"
        'X-IDAP-NATIVE-CLIENT' = 'true'
    }
}
