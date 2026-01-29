#Requires -Version 7.0
<#
.SYNOPSIS
    Authentication session class

.DESCRIPTION
    Represents an active authentication session with Identity.
    Stores session ID, token, and expiry information.
#>

class IdentitySession {
    [string]$SessionId
    [string]$AccessToken
    [datetime]$ExpiresAt
    [string]$Username
    [AuthenticationMethod]$AuthMethod
    [hashtable]$Headers

    IdentitySession([string]$sessionId, [string]$token, [datetime]$expiry, [string]$username, [AuthenticationMethod]$method) {
        $this.SessionId = $sessionId
        $this.AccessToken = $token
        $this.ExpiresAt = $expiry
        $this.Username = $username
        $this.AuthMethod = $method
        $this.Headers = @{
            Authorization           = "Bearer $token"
            'X-IDAP-NATIVE-CLIENT' = 'true'
        }
    }

    [bool] IsExpired() {
        return $this.IsExpired(300)  # 5-minute buffer
    }

    [bool] IsExpired([int]$bufferSeconds) {
        $now = [datetime]::Now
        $expiryWithBuffer = $this.ExpiresAt.AddSeconds(-$bufferSeconds)
        return $now -ge $expiryWithBuffer
    }

    [hashtable] GetHeaders() {
        if ($this.IsExpired()) {
            throw "Session token has expired"
        }
        return $this.Headers
    }
}
