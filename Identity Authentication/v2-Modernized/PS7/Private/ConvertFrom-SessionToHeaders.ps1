#Requires -Version 7.0
<#
.SYNOPSIS
    Convert IdentitySession object to authorization headers

.DESCRIPTION
    Extracts token from IdentitySession class instance and constructs authorization headers
    with X-IDAP-NATIVE-CLIENT header for Privilege Cloud APIs.

.PARAMETER Session
    IdentitySession object containing Token and other metadata

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
        [IdentitySession]$Session
    )

    Write-Verbose "Converting session to headers"

    if ($Session.IsExpired()) {
        throw "Session token has expired. Please re-authenticate."
    }

    return $Session.GetAuthHeader()
}
