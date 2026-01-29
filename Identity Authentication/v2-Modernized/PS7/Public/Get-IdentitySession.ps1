#Requires -Version 7.0
<#
.SYNOPSIS
    Retrieves current Identity session details

.DESCRIPTION
    Returns current IdentitySession object with token expiry, authentication method,
    and other metadata.

.OUTPUTS
    IdentitySession - Current session object

.EXAMPLE
    $session = Get-IdentitySession

.NOTES
    Public function - Exported
#>
function Get-IdentitySession {
    [CmdletBinding()]
    [OutputType([IdentitySession])]
    param()

    if (-not $script:CurrentSession) {
        Write-Verbose "No active session"
        return $null
    }

    Write-Verbose "Returning current session"
    Write-Verbose "User: $($script:CurrentSession.Username)"
    Write-Verbose "Expires: $($script:CurrentSession.TokenExpiry)"
    Write-Verbose "Is Expired: $($script:CurrentSession.IsExpired())"

    return $script:CurrentSession
}
