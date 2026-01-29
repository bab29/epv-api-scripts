#Requires -Version 7.0
<#
.SYNOPSIS
    Clears current Identity session

.DESCRIPTION
    Clears the current session from memory and optionally calls logout endpoint
    to invalidate token on server. Uses SessionManager class for lifecycle management.

.PARAMETER NoLogout
    Skip calling logout endpoint (only clear local session)

.EXAMPLE
    Clear-IdentitySession

.EXAMPLE
    Clear-IdentitySession -NoLogout

.NOTES
    Public function - Exported
#>
function Clear-IdentitySession {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$NoLogout
    )

    if (-not $script:CurrentSession) {
        Write-Verbose "No active session to clear"
        return
    }

    Write-Verbose "Clearing Identity session"

    if (-not $NoLogout -and $script:CurrentSession.IdentityURL) {
        try {
            $logoutUrl = "$($script:CurrentSession.IdentityURL)/Security/logout"
            $headers = $script:CurrentSession.GetAuthHeader()

            Write-Verbose "Calling logout endpoint"
            Invoke-RestMethod -Uri $logoutUrl -Method Post -Headers $headers -ErrorAction SilentlyContinue | Out-Null
            Write-Verbose "Logout successful"
        }
        catch {
            Write-Verbose "Logout call failed (continuing with local cleanup): $($_.Exception.Message)"
        }
    }

    # Clear the session
    $script:CurrentSession.Dispose()
    $script:CurrentSession = $null

    Write-Verbose "Session cleared"
}
