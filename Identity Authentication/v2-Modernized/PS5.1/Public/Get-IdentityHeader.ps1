#Requires -Version 5.1
<#
.SYNOPSIS
    Main authentication entry point for CyberArk Identity

.DESCRIPTION
    Authenticates to CyberArk Identity and returns Bearer token for Privilege Cloud APIs.
    Supports multiple authentication methods:
    - OAuth client credentials
    - Username/Password
    - MFA (OTP, Push, etc.)
    - OOBAUTHPIN (SAML with PIN)

.PARAMETER IdentityUserName
    Username for interactive authentication

.PARAMETER UPCreds
    PSCredential for Username/Password authentication

.PARAMETER OAuthCreds
    PSCredential containing OAuth Client ID (username) and Client Secret (password)

.PARAMETER PCloudURL
    Privilege Cloud URL (e.g., https://subdomain.cyberark.cloud)

.PARAMETER IdentityTenantURL
    Identity tenant URL (optional, derived from PCloudURL if not provided)

.PARAMETER ForceNewSession
    Forces new authentication even if valid cached session exists

.OUTPUTS
    String - Bearer token for use with Privilege Cloud APIs

.EXAMPLE
    # OAuth authentication
    $token = Get-IdentityHeader -OAuthCreds $creds -PCloudURL 'https://subdomain.cyberark.cloud'

.EXAMPLE
    # Interactive authentication
    $token = Get-IdentityHeader -IdentityUserName 'user@company.com' -PCloudURL 'https://subdomain.cyberark.cloud'

.NOTES
    Public function - Exported
    Returns: Bearer token string (compatible with Accounts_Onboard_Utility.ps1 -logonToken parameter)
#>
function Get-IdentityHeader {
    [CmdletBinding(DefaultParameterSetName = 'IdentityUserName')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'IdentityUserName')]
        [string]$IdentityUserName,

        [Parameter(Mandatory, ParameterSetName = 'UPCreds')]
        [PSCredential]$UPCreds,

        [Parameter(Mandatory, ParameterSetName = 'OAuthCreds')]
        [PSCredential]$OAuthCreds,

        [Parameter()]
        [string]$PIN,

        [Parameter(Mandatory)]
        [string]$PCloudURL,

        [Parameter()]
        [string]$IdentityTenantURL,

        [Parameter()]
        [switch]$ForceNewSession
    )

    # Check for existing session
    if (-not $ForceNewSession -and $script:CurrentSession) {
        $isExpired = $script:CurrentSession.TokenExpiry -and ((Get-Date) -gt $script:CurrentSession.TokenExpiry)
        if (-not $isExpired) {
            Write-Verbose 'Using existing session token'
            $headers = ConvertFrom-SessionToHeaders -Session $script:CurrentSession
            return $headers.Authorization
        }
        else {
            Write-Verbose 'Session expired, re-authenticating'
        }
    }

    # Get Identity URL
    if (-not $IdentityTenantURL) {
        $IdentityTenantURL = Get-IdentityURL -PCloudURL $PCloudURL
    }

    # PS5.1: No ternary operator
    if ($IdentityTenantURL -match '^https://') {
        $identityBaseUrl = $IdentityTenantURL
    }
    else {
        $identityBaseUrl = "https://$IdentityTenantURL"
    }
    Write-Verbose "Identity URL: $identityBaseUrl"

    # OAuth flow
    if ($PSCmdlet.ParameterSetName -eq 'OAuthCreds') {
        Write-Verbose 'Using OAuth authentication'

        $clientId = $OAuthCreds.UserName
        $clientSecret = $OAuthCreds.GetNetworkCredential().Password

        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $clientId
            client_secret = $clientSecret
        }

        $tokenUrl = "$identityBaseUrl/oauth2/platformtoken"
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'

        $token = $response.access_token
        # PS5.1: No null coalescing
        if ($response.expires_in) {
            $expiresIn = $response.expires_in
        }
        else {
            $expiresIn = 3600
        }

        # Create session - OAuth has no SessionId
        $session = New-IdentitySession -Properties @{
            Token             = $token
            TokenExpiry       = (Get-Date).AddSeconds($expiresIn)
            IdentityURL       = $identityBaseUrl
            PCloudURL         = $PCloudURL
            Username          = $clientId
            AuthMethod        = 'OAuth'
            StoredCredentials = $OAuthCreds
            SessionId         = $null
        }

        # Safe property check for refresh token
        if ($response.PSObject.Properties['refresh_token']) {
            $session.Metadata.RefreshToken = $response.refresh_token
        }

        $script:CurrentSession = $session
        $headers = Format-Token -Token $token
        return $headers
    }

    # Interactive authentication
    # PS5.1: No ternary operator
    if ($PSCmdlet.ParameterSetName -eq 'UPCreds') {
        $username = $UPCreds.UserName
    }
    else {
        $username = $IdentityUserName
    }
    Write-Verbose "Authenticating user: $username"

    $startAuthUrl = "$identityBaseUrl/Security/StartAuthentication"
    $startAuthBody = @{
        User    = $username
        Version = '1.0'
    }
    $requestHeaders = @{
        'Content-Type'         = 'application/json'
        'X-IDAP-NATIVE-CLIENT' = 'true'
        OobIdPAuth             = 'true'
    }

    $idaptiveResponse = Invoke-Rest -Uri $startAuthUrl -Method Post -Body $startAuthBody -Headers $requestHeaders

    # Check for SAML/OOBAUTHPIN flow (property may not exist in all responses)
    $hasIdpRedirect = $null -ne $idaptiveResponse.Result.PSObject.Properties['IdpRedirectShortUrl']

    if ($hasIdpRedirect -and -not [string]::IsNullOrEmpty($idaptiveResponse.Result.IdpRedirectShortUrl)) {
        Write-Verbose 'OOBAUTHPIN flow detected'

        $oobParams = @{
            IdaptiveResponse = $idaptiveResponse
            IdentityURL      = $identityBaseUrl
            PIN              = $PIN
        }
        $answerResponse = Invoke-OOBAUTHPIN @oobParams

        if ($answerResponse.success -and $answerResponse.Result.Token) {
            $token = $answerResponse.Result.Token
            # PS5.1: No ternary operator
            if ($answerResponse.Result.PSObject.Properties['TokenLifetime']) {
                $tokenLifetime = $answerResponse.Result.TokenLifetime
            }
            else {
                $tokenLifetime = 3600
            }

            # Create session
            $session = New-IdentitySession -Properties @{
                Token             = $token
                TokenExpiry       = (Get-Date).AddSeconds($tokenLifetime)
                IdentityURL       = $identityBaseUrl
                PCloudURL         = $PCloudURL
                Username          = $username
                SessionId         = $idaptiveResponse.Result.SessionId
                AuthMethod        = 'OOBAUTHPIN'
                StoredCredentials = $null
            }

            if ($answerResponse.Result.PSObject.Properties['RefreshToken']) {
                $session.Metadata.RefreshToken = $answerResponse.Result.RefreshToken
            }
            $script:CurrentSession = $session
            $headers = Format-Token -Token $token
            return $headers
        }
        else {
            $errorMsg = if ($answerResponse.PSObject.Properties['Message']) { $answerResponse.Message } else { 'Unknown error' }
            throw "OOBAUTHPIN authentication failed: $errorMsg"
        }
    }

    $sessionId = $idaptiveResponse.Result.SessionId
    Write-Verbose "Session ID: $sessionId"

    # Standard challenge flow
    $challengeParams = @{
        IdaptiveResponse = $idaptiveResponse
        IdentityURL      = $identityBaseUrl
        UPCreds          = $UPCreds
    }
    $answerResponse = Invoke-Challenge @challengeParams

    Write-Verbose "Response properties: $($answerResponse.PSObject.Properties.Name -join ', ')"
    Write-Verbose "Response JSON: $($answerResponse | ConvertTo-Json -Depth 5 -Compress)"

    if ($answerResponse.PSObject.Properties['success'] -and $answerResponse.success -and $answerResponse.Result.Token) {
        $token = $answerResponse.Result.Token
        # PS5.1: No ternary operator
        if ($answerResponse.Result.PSObject.Properties['TokenLifetime']) {
            $tokenLifetime = $answerResponse.Result.TokenLifetime
        }
        else {
            $tokenLifetime = 3600
        }

        # Create session
        $session = New-IdentitySession -Properties @{
            Token             = $token
            TokenExpiry       = (Get-Date).AddSeconds($tokenLifetime)
            IdentityURL       = $identityBaseUrl
            PCloudURL         = $PCloudURL
            Username          = $username
            SessionId         = $sessionId
            AuthMethod        = 'UP'
            StoredCredentials = $null
        }

        $script:CurrentSession = $session
        $headers = Format-Token -Token $token
        return $headers
    }
    else {
        # Gather error details - safely check properties
        $hasSuccess = $null -ne $answerResponse.PSObject.Properties['success']
        $successValue = if ($hasSuccess) { $answerResponse.success } else { 'Property missing' }

        $hasResult = $null -ne $answerResponse.PSObject.Properties['Result']
        $hasToken = if ($hasResult -and $answerResponse.Result) {
            $null -ne $answerResponse.Result.PSObject.Properties['Token'] -and $answerResponse.Result.Token
        } else {
            $false
        }

        # Try to extract error message
        if ($answerResponse.PSObject.Properties['Message']) {
            $errorMsg = $answerResponse.Message
        } elseif ($hasResult -and $answerResponse.Result.PSObject.Properties['Message']) {
            $errorMsg = $answerResponse.Result.Message
        } else {
            $errorMsg = "Success=$successValue, HasToken=$hasToken. Use -Verbose to see full response."
        }
        throw "Authentication failed: $errorMsg"
    }
}
