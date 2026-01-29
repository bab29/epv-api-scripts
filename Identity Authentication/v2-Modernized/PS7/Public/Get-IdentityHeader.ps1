#Requires -Version 7.0
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

    PS7 version utilizes classes and enums for enhanced type safety.

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

    $InformationPreference = 'Continue'
    # Check for existing session
    if (-not $ForceNewSession -and $script:CurrentSession) {
        if (-not $script:CurrentSession.IsExpired()) {
            Write-Verbose 'Using existing session token'
            $headers = $script:CurrentSession.GetAuthHeader()
            return $headers.Authorization
        } else {
            Write-Verbose 'Session expired, re-authenticating'
        }
    }

    # Get Identity URL
    if (-not $IdentityTenantURL) {
        $IdentityTenantURL = Get-IdentityURL -PCloudURL $PCloudURL
    }

    $identityBaseUrl = $IdentityTenantURL -match '^https://' ? $IdentityTenantURL : "https://$IdentityTenantURL"
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
        $expiresIn = $response.expires_in ?? 3600

        # Create session - OAuth has no SessionId
        $session = New-IdentitySession -Properties @{
            Token             = $token
            TokenExpiry       = (Get-Date).AddSeconds($expiresIn)
            IdentityURL       = $identityBaseUrl
            PCloudURL         = $PCloudURL
            Username          = $clientId
            AuthMethod        = [AuthenticationMechanism]::OAuth
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
    $username = $PSCmdlet.ParameterSetName -eq 'UPCreds' ? $UPCreds.UserName : $IdentityUserName
    Write-Verbose "Authenticating user: $username"

    $startAuthUrl = "$identityBaseUrl/Security/StartAuthentication"
    $startAuthBody = @{
        User    = $username
        Version = '1.0'
    }
    $Headers = @{
        'Content-Type'         = 'application/json'
        'X-IDAP-NATIVE-CLIENT' = 'true'
        OobIdPAuth             = 'true'
    }

    $idaptiveResponse = Invoke-Rest -Uri $startAuthUrl -Method Post -Body $startAuthBody -headers $headers

    # Check for SAML/OOBAUTHPIN flow (property may not exist in all responses)
    if ($idaptiveResponse.Result.PSObject.Properties['IdpRedirectShortUrl'] -and
        -not [string]::IsNullOrEmpty($idaptiveResponse.Result.IdpRedirectShortUrl)) {
        Write-Verbose 'OOBAUTHPIN flow detected'

        $oobParams = @{
            IdaptiveResponse = $idaptiveResponse
            IdentityURL      = $identityBaseUrl
            PIN              = $PIN
        }
        $answerResponse = Invoke-OOBAUTHPIN @oobParams

        if ($answerResponse.success -and $answerResponse.Result.Token) {
            $token = $answerResponse.Result.Token
            $tokenLifetime = ($answerResponse.Result.PSObject.Properties['TokenLifetime']) ? $answerResponse.Result.TokenLifetime : 3600


            # Create session
            $session = New-IdentitySession -Properties @{
                Token             = $token
                TokenExpiry       = (Get-Date).AddSeconds($tokenLifetime)
                IdentityURL       = $identityBaseUrl
                PCloudURL         = $PCloudURL
                Username          = $username
                SessionId         = $idaptiveResponse.Result.SessionId
                AuthMethod        = [AuthenticationMechanism]::OOBAUTHPIN
                StoredCredentials = $null
            }

            $session.Metadata.RefreshToken = ($answerResponse.Result.PSObject.Properties['RefreshToken']) ? $answerResponse.Result.RefreshToken : $null
            $script:CurrentSession = $session
            $headers = Format-Token -Token $token
            return $headers
        } else {
            $errorMsg = $answerResponse.PSObject.Properties['Message'] ? $answerResponse.Message : 'Unknown error'
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

    if ($answerResponse.PSObject.Properties['success'] -and $answerResponse.success -and $answerResponse.Result.Token) {
        $token = $answerResponse.Result.Token
        $tokenLifetime = ($answerResponse.Result.PSObject.Properties['TokenLifetime']) ? $answerResponse.Result.TokenLifetime : 3600

        # Create session
        $session = New-IdentitySession -Properties @{
            Token       = $token
            TokenExpiry = (Get-Date).AddSeconds($tokenLifetime)
            IdentityURL = $identityBaseUrl
            PCloudURL   = $PCloudURL
            Username    = $username
            SessionId   = $sessionId
            AuthMethod  = [AuthenticationMechanism]::UP
            StoredCredentials = $null
        }
        $session.Metadata.RefreshToken = ($answerResponse.Result.PSObject.Properties['RefreshToken']) ? $answerResponse.Result.RefreshToken : $null
        $script:CurrentSession = $session
        $headers = Format-Token -Token $token
        return $headers
    } else {
        $errorMsg = $answerResponse.PSObject.Properties['Message'] ? $answerResponse.Message : 'Unknown error'
        throw "Authentication failed: $errorMsg"
    }
}
