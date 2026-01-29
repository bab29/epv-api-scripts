#Requires -Version 7.0
<#
.SYNOPSIS
    Update IdentitySession with refreshed token

.DESCRIPTION
    Updates an existing IdentitySession object with new token and expiry.
    Used for OAuth token refresh to extend session lifetime.

.PARAMETER Session
    IdentitySession object to update

.EXAMPLE
    Update-IdentitySession -Session $script:CurrentSession

.NOTES
    Private function - Internal use only
    Used by: OAuth token refresh logic
#>
function Update-IdentitySession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [IdentitySession]$Session
    )

    Write-Verbose "Updating session with refreshed token"

    if ($Session.AuthMethod -ne [AuthenticationMechanism]::OAuth) {
        throw "Cannot auto-refresh: Only OAuth sessions support automatic refresh"
    }

    try {
        $Session.Refresh()
        Write-Verbose "Session refreshed successfully. New expiry: $($Session.TokenExpiry)"
    }
    catch {
        Write-Verbose "Session refresh failed: $($_.Exception.Message)"
        throw
    }
}
