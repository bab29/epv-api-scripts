#Requires -Version 7.0
<#
.SYNOPSIS
    Identity session class

.DESCRIPTION
    Represents an active Identity authentication session with full lifecycle management
#>

class IdentitySession {
    # Core authentication data
    [string]$Token
    [datetime]$TokenExpiry
    [string]$IdentityURL
    [string]$PCloudURL

    # User and session metadata
    [string]$Username
    [string]$SessionId
    [AuthenticationMechanism]$AuthMethod

    # Optional stored credentials (OAuth only for auto-refresh)
    [PSCredential]$StoredCredentials

    # Additional metadata
    [hashtable]$Metadata = @{
        CreatedAt = [datetime]::Now
        LastRefreshed = [datetime]::Now
        RefreshCount = 0
        PCloudVersion = $null
        TenantId = $null
        RefreshToken = $null
    }

    # Default constructor
    IdentitySession() { }

    # Constructor from hashtable
    IdentitySession([hashtable]$Properties) {
        $this.Token = $Properties.Token
        $this.TokenExpiry = $Properties.TokenExpiry
        $this.IdentityURL = $Properties.IdentityURL
        $this.PCloudURL = $Properties.PCloudURL ?? ''
        $this.Username = $Properties.Username
        $this.SessionId = $Properties.SessionId ?? ''
        $this.AuthMethod = $Properties.AuthMethod
        $this.StoredCredentials = $Properties.StoredCredentials ?? $null
    }

    # Check if token is expired
    [bool] IsExpired() {
        return (Get-Date) -gt $this.TokenExpiry
    }

    # Check if token is expiring soon
    [bool] IsExpiringSoon([int]$ThresholdSeconds = 60) {
        $expiryThreshold = (Get-Date).AddSeconds($ThresholdSeconds)
        return $this.TokenExpiry -lt $expiryThreshold
    }

    # Refresh OAuth token
    [void] Refresh() {
        if ($this.AuthMethod -eq [AuthenticationMechanism]::OAuth) {
            if ($null -ne $this.StoredCredentials) {
                Write-Verbose "Auto-refreshing OAuth token"

                $ClientId = $this.StoredCredentials.UserName
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.StoredCredentials.Password)
                $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

                try {
                    $body = "grant_type=client_credentials&client_id=$ClientId&client_secret=$ClientSecret"
                    $oauthParams = @{
                        Uri = "$($this.IdentityURL)/OAuth2/Token/$ClientId"
                        Method = 'Post'
                        ContentType = 'application/x-www-form-urlencoded'
                        Body = $body
                        ErrorAction = 'Stop'
                    }
                    $response = Invoke-RestMethod @oauthParams

                    $this.Token = $response.access_token
                    $this.TokenExpiry = (Get-Date).AddSeconds($response.expires_in)
                    $this.Metadata.LastRefreshed = Get-Date
                    $this.Metadata.RefreshCount++

                    Write-Verbose "OAuth token refreshed successfully (Refresh count: $($this.Metadata.RefreshCount))"
                } catch {
                    throw "Failed to refresh OAuth token: $($_.Exception.Message)"
                } finally {
                    if ($bstr) {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    }
                    $ClientSecret = $null
                }
            } else {
                throw "Cannot refresh: OAuth credentials not stored in session"
            }
        } else {
            throw "Cannot auto-refresh: AuthMethod '$($this.AuthMethod)' requires manual user interaction"
        }
    }

    # Get authorization header
    [hashtable] GetAuthHeader() {
        if ($this.IsExpired()) {
            throw "Token expired. Re-authentication required."
        }
        return @{
            'Authorization' = "Bearer $($this.Token)"
            'X-IDAP-NATIVE-CLIENT' = 'true'
        }
    }

    # Dispose and logout
    [void] Dispose() {
        Write-Verbose "Disposing Identity session for user: $($this.Username)"

        # Call logout endpoint
        try {
            $logoutUrl = "$($this.IdentityURL)/Security/logout"
            $logoutParams = @{
                Uri = $logoutUrl
                Method = 'Post'
                Headers = $this.GetAuthHeader()
                ErrorAction = 'SilentlyContinue'
            }
            Invoke-RestMethod @logoutParams | Out-Null
            Write-Verbose "Logout API call successful"
        } catch {
            Write-Verbose "Logout API call failed: $($_.Exception.Message)"
        }

        # Clear sensitive data
        $this.Token = $null
        $this.StoredCredentials = $null
        $this.SessionId = $null
        Write-Verbose "Session disposed"
    }
}
