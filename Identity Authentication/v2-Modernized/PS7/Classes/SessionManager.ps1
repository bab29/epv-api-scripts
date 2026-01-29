#Requires -Version 7.0
<#
.SYNOPSIS
    Session manager class

.DESCRIPTION
    Manages the current Identity session lifecycle
#>

class SessionManager {
    hidden [IdentitySession]$CurrentSession

    # Get current session
    [IdentitySession] GetSession() {
        return $this.CurrentSession
    }

    # Set current session
    [void] SetSession([IdentitySession]$Session) {
        $this.CurrentSession = $Session
        Write-Verbose "Session set for user: $($Session.Username)"
    }

    # Clear current session
    [void] ClearSession([bool]$Logout = $true) {
        if ($this.HasActiveSession()) {
            if ($Logout) {
                $this.CurrentSession.Dispose()
            }
            $this.CurrentSession = $null
            Write-Verbose "Session cleared"
        }
    }

    # Check if there's an active session
    [bool] HasActiveSession() {
        return $null -ne $this.CurrentSession -and -not $this.CurrentSession.IsExpired()
    }

    # Refresh token if needed
    [bool] RefreshIfNeeded() {
        if ($this.HasActiveSession() -and $this.CurrentSession.IsExpiringSoon()) {
            try {
                $this.CurrentSession.Refresh()
                return $true
            } catch {
                Write-Verbose "Failed to refresh session: $($_.Exception.Message)"
                return $false
            }
        }
        return $false
    }
}
