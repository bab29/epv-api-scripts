#Requires -Version 5.1
<#
.SYNOPSIS
    OAuth authentication implementation for CyberArk Identity

.DESCRIPTION
    Handles OAuth client credentials flow for Privilege Cloud authentication.
    Returns access token for API authentication.
#>

function Get-OAuthToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCredential]$OAuthCreds,
        
        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )
    
    Write-Verbose "Initiating OAuth authentication to $IdentityTenantURL"
    
    # Extract client ID and secret from credential
    $clientId = $OAuthCreds.UserName
    $clientSecret = $OAuthCreds.GetNetworkCredential().Password
    
    # Build OAuth token request
    $tokenUrl = "$IdentityTenantURL/oauth2/platformtoken/"
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $clientId
        client_secret = $clientSecret
    }
    
    try {
        Write-Verbose "Requesting OAuth token..."
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        
        if ($response.access_token) {
            Write-Verbose "OAuth token received successfully"
            
            # Calculate expiry time
            $expiresIn = if ($response.expires_in) { $response.expires_in } else { 3600 }
            $expiry = (Get-Date).AddSeconds($expiresIn)
            
            return @{
                AccessToken = $response.access_token
                TokenType   = $response.token_type
                ExpiresIn   = $expiresIn
                ExpiresAt   = $expiry
            }
        } else {
            throw "OAuth response did not contain access_token"
        }
    } catch {
        Write-Error "OAuth authentication failed: $($_.Exception.Message)"
        throw
    }
}
