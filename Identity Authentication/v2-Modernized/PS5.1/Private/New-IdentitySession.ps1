#Requires -Version 5.1
<#
.SYNOPSIS
    Create new Identity session hashtable

.DESCRIPTION
    Creates a new session hashtable with all required properties for session state management.
    Used after successful authentication to store session data.

.PARAMETER Properties
    Hashtable containing session properties (Token, TokenExpiry, IdentityURL, etc.)

.OUTPUTS
    Hashtable with complete session structure

.EXAMPLE
    $session = New-IdentitySession -Properties @{
        Token = $token
        TokenExpiry = (Get-Date).AddSeconds(3600)
        IdentityURL = $identityUrl
        PCloudURL = $pcloudUrl
        Username = $username
        AuthMethod = 'OAuth'
    }

.NOTES
    Private function - Internal use only
#>
function New-IdentitySession {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Properties
    )

    Write-Verbose "Creating new Identity session for user: $($Properties.Username)"

    # PS5.1: Use hashtable instead of class
    $session = @{
        Token             = $Properties.Token
        TokenExpiry       = $Properties.TokenExpiry
        IdentityURL       = $Properties.IdentityURL
        PCloudURL         = $Properties.PCloudURL
        Username          = $Properties.Username
        SessionId         = $Properties.SessionId
        AuthMethod        = $Properties.AuthMethod
        StoredCredentials = $Properties.StoredCredentials
        Metadata          = @{
            CreatedAt     = Get-Date
            LastRefreshed = Get-Date
            RefreshCount  = 0
            RefreshToken  = $null
        }
    }

    Write-Verbose "Session created. Expires: $($session.TokenExpiry)"

    return $session
}
