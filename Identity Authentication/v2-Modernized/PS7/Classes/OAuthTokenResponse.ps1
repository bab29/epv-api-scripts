#Requires -Version 7.0
<#
.SYNOPSIS
    OAuth token response class

.DESCRIPTION
    Represents OAuth token response from Identity.
#>

class OAuthTokenResponse {
    [string]$AccessToken
    [string]$TokenType
    [int]$ExpiresIn
    [datetime]$ExpiresAt
    [datetime]$IssuedAt
    
    OAuthTokenResponse([string]$token, [string]$type, [int]$expires) {
        $this.AccessToken = $token
        $this.TokenType = $type
        $this.ExpiresIn = $expires
        $this.IssuedAt = [datetime]::Now
        $this.ExpiresAt = $this.IssuedAt.AddSeconds($expires)
    }
    
    [bool] IsValid() {
        return -not $this.IsExpired()
    }
    
    [bool] IsExpired() {
        return $this.IsExpired(300)
    }
    
    [bool] IsExpired([int]$bufferSeconds) {
        $now = [datetime]::Now
        $expiryWithBuffer = $this.ExpiresAt.AddSeconds(-$bufferSeconds)
        return $now -ge $expiryWithBuffer
    }
    
    [int] GetRemainingSeconds() {
        if ($this.IsExpired(0)) {
            return 0
        }
        return [int]($this.ExpiresAt - [datetime]::Now).TotalSeconds
    }
}
