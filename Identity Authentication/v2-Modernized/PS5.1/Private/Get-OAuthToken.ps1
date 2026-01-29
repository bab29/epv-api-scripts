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
    
    Write-IdentityLog -Message "Initiating OAuth authentication" -Level Verbose -Component 'OAuth' -AdditionalData @{URL = $IdentityTenantURL}
    
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
        Write-IdentityLog -Message "Requesting OAuth token from Identity" -Level Verbose -Component 'OAuth'
        
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        
        # Validate response
        $null = Test-AuthenticationResponse -Response $response -AuthMethod 'OAuth'
        
        if ($response.access_token) {
            $tokenPreview = Hide-SensitiveData -Text "Bearer $($response.access_token)" -DataType Token
            Write-IdentityLog -Message "OAuth token received: $tokenPreview" -Level Verbose -Component 'OAuth'
            
            # Calculate expiry time
            $expiresIn = if ($response.expires_in) { $response.expires_in } else { 3600 }
            $expiry = (Get-Date).AddSeconds($expiresIn)
            
            Write-IdentityLog -Message "Token expires in $expiresIn seconds" -Level Verbose -Component 'OAuth' -AdditionalData @{ExpiresAt = $expiry}
            
            return @{
                AccessToken = $response.access_token
                TokenType   = $response.token_type
                ExpiresIn   = $expiresIn
                ExpiresAt   = $expiry
            }
        } else {
            $errorRecord = New-IdentityErrorRecord `
                -Message "OAuth response did not contain access_token" `
                -ErrorId 'OAuthNoToken' `
                -Category InvalidResult `
                -RecommendedAction "Verify OAuth client credentials and permissions"
            throw $errorRecord
        }
    } catch {
        $safeMessage = Get-SafeErrorMessage -ErrorRecord $_
        Write-IdentityLog -Message "OAuth authentication failed: $safeMessage" -Level Error -Component 'OAuth'
        throw
    }
}
