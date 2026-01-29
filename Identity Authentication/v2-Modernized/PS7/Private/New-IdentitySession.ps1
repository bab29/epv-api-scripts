#Requires -Version 7.0
<#
.SYNOPSIS
    Create new IdentitySession object

.DESCRIPTION
    Creates a new IdentitySession class instance with all required properties.
    Used after successful authentication to store session data.

.PARAMETER Properties
    Hashtable containing session properties (Token, TokenExpiry, IdentityURL, etc.)

.OUTPUTS
    IdentitySession object

.EXAMPLE
    $session = New-IdentitySession -Properties @{
        Token = $token
        TokenExpiry = (Get-Date).AddSeconds(3600)
        IdentityURL = $identityUrl
        PCloudURL = $pcloudUrl
        Username = $username
        AuthMethod = [AuthenticationMechanism]::OAuth
    }

.NOTES
    Private function - Internal use only
#>
function New-IdentitySession {
    [CmdletBinding()]
    [OutputType([IdentitySession])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Properties
    )

    Write-Verbose "Creating new IdentitySession for user: $($Properties.Username)"

    $session = [IdentitySession]::new($Properties)

    $session.Metadata.CreatedAt = Get-Date
    $session.Metadata.LastRefreshed = Get-Date
    $session.Metadata.RefreshCount = 0

    Write-Verbose "Session created. Expires: $($session.TokenExpiry)"

    return $session
}
